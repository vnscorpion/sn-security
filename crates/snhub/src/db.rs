//! SQLite persistence for the hub. One connection guarded by a mutex in the
//! shared state; all queries are tiny (≤50 agents), so they run inline in the
//! handlers without awaiting while locked. A connection pool / `spawn_blocking`
//! is a v1.1 upgrade if the fleet grows.

use std::net::{IpAddr, Ipv6Addr};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use snsec_common::schema::{DesiredBody, ReportBody};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_seen INTEGER NOT NULL DEFAULT 0,
    last_report_seq INTEGER NOT NULL DEFAULT 0,
    version TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'observe',
    host_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    received INTEGER NOT NULL,
    body_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_agent ON reports(agent_id, seq DESC);
CREATE TABLE IF NOT EXISTS desired (
    agent_id TEXT PRIMARY KEY,
    epoch INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    body_json TEXT NOT NULL,
    updated INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT 'system'
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
    token TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    who TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    ts INTEGER NOT NULL
);
"#;

pub struct Db {
    pub(crate) conn: Connection,
    /// Per-agent report budget, `(tokens, last refill)`: see `take_report_token`.
    report_budget: std::cell::RefCell<std::collections::HashMap<String, (f64, i64)>>,
}

/// Reports a VPS may send back to back: a queue flushed after the hub was
/// unreachable is up to 50 at once.
const REPORT_BURST: f64 = 60.0;
/// After that, one report per this many seconds on average. A VPS reports every
/// 5–15 minutes, plus one now and then when an incident is being handled.
const REPORT_REFILL_SECS: f64 = 10.0;
/// Reports kept per agent. The UI reads only the latest one.
const REPORTS_KEPT: i64 = 10;

/// One row of the decisions log: `(agent_id, who, action, detail, ts)`.
pub type Decision = (String, String, String, String, i64);

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub name: String,
    pub last_seen: i64,
    pub last_report_seq: u64,
    pub version: String,
    pub mode: String,
}

/// This process's effective uid, from `/proc/self/status` (the owner of
/// `/proc/self` reads as root for a process that is not dumpable). `None` where
/// there is no procfs.
#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    // Real, effective, saved, filesystem.
    line.split_whitespace().nth(1)?.parse().ok()
}

/// The database holds AI API keys, the TOTP secret and enrollment tokens: create
/// it readable by its owner only (SQLite gives its `-wal`/`-shm` files the same
/// mode), and tighten one that an older version left readable, if it is ours.
#[cfg(unix)]
fn private_db_file(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating db {}", path.display()))?;
    let me = effective_uid();
    let mut files = vec![path.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        files.push(p.into());
    }
    for f in files {
        let Ok(meta) = std::fs::metadata(&f) else {
            continue;
        };
        if meta.mode() & 0o077 != 0 && me.is_none_or(|uid| uid == meta.uid()) {
            let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(())
}

impl Db {
    pub fn open(path: &std::path::Path) -> Result<Db> {
        #[cfg(unix)]
        private_db_file(path)?;
        let conn =
            Connection::open(path).with_context(|| format!("opening db {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        conn.execute_batch(SCHEMA).context("applying schema")?;
        conn.execute_batch(crate::db_ai::SCHEMA_AI)
            .context("applying AI schema")?;
        conn.execute_batch(crate::db_auth::SCHEMA_AUTH)
            .context("applying auth schema")?;
        crate::db_auth::migrate_auth(&conn).context("migrating auth schema")?;
        conn.execute_batch(crate::db_mcp::SCHEMA_MCP)
            .context("applying MCP schema")?;
        // Not fatal: `get_desired` leaves such entries out anyway.
        if let Err(e) = scrub_desired(&conn) {
            tracing::error!("checking stored ban orders: {e:#}");
        }
        Ok(Db {
            conn,
            report_budget: std::cell::RefCell::default(),
        })
    }

    // ---- enrollment -------------------------------------------------------

    pub fn create_enroll_token(&self, name: &str, now: i64, ttl: i64) -> Result<String> {
        let token = random_token();
        self.conn.execute(
            "INSERT INTO enroll_tokens (token, name, created, expires, used) VALUES (?1, ?2, ?3, ?4, 0)",
            params![token, name, now, now + ttl],
        )?;
        Ok(token)
    }

    /// Consume a single-use token; returns the VPS name if valid & unexpired.
    pub fn consume_token(&self, token: &str, now: i64) -> Result<Option<String>> {
        let row: Option<(String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT name, expires, used FROM enroll_tokens WHERE token = ?1",
                params![token],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            Some((name, expires, used)) if used == 0 && expires >= now => {
                self.conn.execute(
                    "UPDATE enroll_tokens SET used = 1 WHERE token = ?1",
                    params![token],
                )?;
                Ok(Some(name))
            }
            _ => Ok(None),
        }
    }

    pub fn enroll_agent(&self, name: &str, pubkey: &str, now: i64) -> Result<String> {
        let id = agent_id(name);
        self.conn.execute(
            "INSERT INTO agents (id, name, pubkey, created) VALUES (?1, ?2, ?3, ?4)",
            params![id, name, pubkey, now],
        )?;
        // Seed an initial observe desired-state.
        let body = serde_json::to_string(&DesiredBody::default())?;
        self.conn.execute(
            "INSERT INTO desired (agent_id, epoch, version, body_json, updated, updated_by) \
             VALUES (?1, 1, 1, ?2, ?3, 'system')",
            params![id, body, now],
        )?;
        Ok(id)
    }

    pub fn agent_pubkey(&self, agent_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT pubkey FROM agents WHERE id = ?1",
                params![agent_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    // ---- reports ----------------------------------------------------------

    pub fn last_report_seq(&self, agent_id: &str) -> Result<u64> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_report_seq FROM agents WHERE id = ?1",
                params![agent_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.unwrap_or(0) as u64)
    }

    pub fn record_report(
        &self,
        agent_id: &str,
        seq: u64,
        now: i64,
        body: &ReportBody,
        body_json: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO reports (agent_id, seq, received, body_json) VALUES (?1, ?2, ?3, ?4)",
            params![agent_id, seq as i64, now, body_json],
        )?;
        let host_json = serde_json::to_string(&body.host).unwrap_or_else(|_| "{}".into());
        self.conn.execute(
            "UPDATE agents SET last_seen = ?1, last_report_seq = ?2, version = ?3, host_json = ?4 WHERE id = ?5",
            params![now, seq as i64, body.agent_version, host_json, agent_id],
        )?;
        // Keep only the most recent reports per agent. The UI only ever reads the
        // latest one, and a report with a long ban list can be ~50 KB, so a deep
        // history would only grow the database.
        self.conn.execute(
            "DELETE FROM reports WHERE agent_id = ?1 AND id NOT IN \
             (SELECT id FROM reports WHERE agent_id = ?1 ORDER BY id DESC LIMIT ?2)",
            params![agent_id, REPORTS_KEPT],
        )?;
        Ok(())
    }

    /// May this agent's report be stored now? A token bucket per agent: a burst
    /// of [`REPORT_BURST`], then one per [`REPORT_REFILL_SECS`], so an enrolled
    /// VPS cannot flood the hub with reports while a queue flushed after an
    /// outage still goes through. Only for a report whose signature checked out.
    pub fn take_report_token(&self, agent_id: &str, now: i64) -> bool {
        let mut m = self.report_budget.borrow_mut();
        let (tokens, at) = m.entry(agent_id.to_string()).or_insert((REPORT_BURST, now));
        let refill = (now - *at).max(0) as f64 / REPORT_REFILL_SECS;
        *tokens = (*tokens + refill).min(REPORT_BURST);
        *at = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }

    pub fn latest_report(&self, agent_id: &str) -> Result<Option<ReportBody>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT body_json FROM reports WHERE agent_id = ?1 ORDER BY seq DESC LIMIT 1",
                params![agent_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    // ---- agents -----------------------------------------------------------

    pub fn list_agents(&self) -> Result<Vec<AgentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, last_seen, last_report_seq, version, mode FROM agents ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AgentRow {
                id: r.get(0)?,
                name: r.get(1)?,
                last_seen: r.get(2)?,
                last_report_seq: r.get::<_, i64>(3)? as u64,
                version: r.get(4)?,
                mode: r.get(5)?,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Remove a VPS from the hub: its key (so it can neither report nor pull
    /// orders any more), its reports, orders, evidence and AI proposals. The
    /// decisions log keeps its lines, with a last one saying who removed it.
    /// Returns the removed VPS's name, or `None` if there was no such VPS.
    ///
    /// # Errors
    /// A database error (nothing is removed then).
    pub fn remove_agent(&self, agent_id: &str, who: &str, now: i64) -> Result<Option<String>> {
        let Some(a) = self.agent(agent_id)? else {
            return Ok(None);
        };
        let tx = self.conn.unchecked_transaction()?;
        for table in ["reports", "desired", "evidence", "ai_state", "proposals"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE agent_id = ?1"),
                params![agent_id],
            )?;
        }
        // Created by the desired-pull handler the first time it is needed.
        let _ = tx.execute(
            "DELETE FROM desired_pulls WHERE agent_id = ?1",
            params![agent_id],
        );
        tx.execute("DELETE FROM agents WHERE id = ?1", params![agent_id])?;
        tx.execute(
            "INSERT INTO decisions (agent_id, who, action, detail, ts) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                agent_id,
                who,
                "remove_vps",
                format!("xoá VPS {} khỏi hub", a.name),
                now
            ],
        )?;
        tx.commit()?;
        self.report_budget.borrow_mut().remove(agent_id);
        Ok(Some(a.name))
    }

    pub fn agent(&self, agent_id: &str) -> Result<Option<AgentRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, last_seen, last_report_seq, version, mode FROM agents WHERE id = ?1",
                params![agent_id],
                |r| {
                    Ok(AgentRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        last_seen: r.get(2)?,
                        last_report_seq: r.get::<_, i64>(3)? as u64,
                        version: r.get(4)?,
                        mode: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    // ---- desired ----------------------------------------------------------

    /// The desired state as it is signed for the agent and edited by the hub.
    /// Ban and unban entries that are not one address (or an IPv6 /64) are left
    /// out, whoever wrote them: the agent puts them into a root nftables script.
    pub fn get_desired(&self, agent_id: &str) -> Result<Option<(u64, u64, DesiredBody)>> {
        let row: Option<(i64, i64, String)> = self
            .conn
            .query_row(
                "SELECT epoch, version, body_json FROM desired WHERE agent_id = ?1",
                params![agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.and_then(|(e, v, j)| {
            let mut body: DesiredBody = serde_json::from_str(&j).ok()?;
            warn_dropped(agent_id, &keep_valid_orders(&mut body));
            Some((e as u64, v as u64, body))
        }))
    }

    /// Mutate the desired body and bump its version. The closure receives the
    /// current body and edits it in place.
    pub fn update_desired(
        &self,
        agent_id: &str,
        now: i64,
        who: &str,
        action: &str,
        detail: &str,
        edit: impl FnOnce(&mut DesiredBody),
    ) -> Result<()> {
        let (epoch, version, mut body) =
            self.get_desired(agent_id)?
                .unwrap_or((1, 0, DesiredBody::default()));
        // A job the agent has already run need not ride along in every later
        // desired-state. Dropping it keeps a rolled-back (older) agent from
        // meeting a job kind it cannot parse. `jobs_seq` stays, so the agent's
        // run-once logic is unchanged.
        if !body.jobs.is_empty() {
            let applied = self
                .latest_report(agent_id)
                .ok()
                .flatten()
                .map_or(0, |r| r.applied_desired.seq);
            if job_already_applied(&body, applied) {
                body.jobs.clear();
            }
        }
        edit(&mut body);
        warn_dropped(agent_id, &keep_valid_orders(&mut body));
        bound_orders(&mut body);
        let json = serde_json::to_string(&body)?;
        self.conn.execute(
            "INSERT INTO desired (agent_id, epoch, version, body_json, updated, updated_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(agent_id) DO UPDATE SET epoch=?2, version=?3, body_json=?4, updated=?5, updated_by=?6",
            params![agent_id, epoch as i64, (version + 1) as i64, json, now, who],
        )?;
        // Reflect the mode on the agent row for the overview.
        self.conn.execute(
            "UPDATE agents SET mode = ?1 WHERE id = ?2",
            params![body.mode.as_str(), agent_id],
        )?;
        self.record_decision(agent_id, who, action, detail, now)?;
        Ok(())
    }

    /// Queue a single one-shot job for the agent. Replaces any pending job and
    /// stamps `jobs_seq` with the new version so the agent runs it exactly once.
    /// Lift every ban on a VPS: the hub's own orders are dropped and the VPS is
    /// told (by `unban_all_seq`) to empty its ban sets and forget its offence
    /// counts. An agent too old to know the marker gets the addresses its last
    /// report listed as unbans instead. With `observe`, the VPS also stops
    /// banning by itself until switched back.
    ///
    /// # Errors
    /// A database error.
    pub fn unban_all(&self, agent_id: &str, now: i64, who: &str, observe: bool) -> Result<()> {
        let report = self.latest_report(agent_id)?;
        let knows = report
            .as_ref()
            .is_some_and(|r| r.capabilities.iter().any(|c| c == "unban_all"));
        let listed: Vec<String> = if knows {
            Vec::new()
        } else {
            report
                .map(|r| r.active_bans.into_iter().map(|b| b.ip).collect())
                .unwrap_or_default()
        };
        let detail = if observe {
            "gỡ toàn bộ lệnh chặn, chuyển sang chỉ theo dõi"
        } else {
            "gỡ toàn bộ lệnh chặn"
        };
        self.update_desired(agent_id, now, who, "unban_all", detail, |d| {
            let hub_bans: Vec<String> = d.bans.drain(..).map(|b| b.ip).collect();
            d.unbans.clear();
            if !knows {
                d.unbans = hub_bans.into_iter().chain(listed).collect();
                d.unbans.dedup();
            }
            d.unban_all_seq = (d.unban_all_seq + 1).max(u64::try_from(now).unwrap_or(0));
            if observe {
                d.mode = snsec_common::schema::Mode::Observe;
            }
        })
    }

    pub fn queue_job(
        &self,
        agent_id: &str,
        now: i64,
        who: &str,
        job: snsec_common::schema::Job,
        detail: &str,
    ) -> Result<()> {
        let (epoch, version, mut body) =
            self.get_desired(agent_id)?
                .unwrap_or((1, 0, DesiredBody::default()));
        // There is one job slot per VPS. Replacing a job the VPS has not run yet
        // would drop it silently (an operator's ban order, an incident-response
        // order), so refuse and say so; the caller can try again shortly.
        if !body.jobs.is_empty() {
            let applied = self
                .latest_report(agent_id)
                .ok()
                .flatten()
                .map_or(0, |r| r.applied_desired.seq);
            if !job_already_applied(&body, applied) {
                anyhow::bail!(
                    "VPS còn một lệnh chưa chạy (đang chờ báo cáo kế tiếp, tối đa ~15 phút); thử lại sau"
                );
            }
        }
        let new_version = version + 1;
        body.jobs = vec![job];
        body.jobs_seq = new_version;
        let json = serde_json::to_string(&body)?;
        self.conn.execute(
            "INSERT INTO desired (agent_id, epoch, version, body_json, updated, updated_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(agent_id) DO UPDATE SET epoch=?2, version=?3, body_json=?4, updated=?5, updated_by=?6",
            params![agent_id, epoch as i64, new_version as i64, json, now, who],
        )?;
        self.record_decision(agent_id, who, "job", detail, now)?;
        Ok(())
    }

    pub fn record_decision(
        &self,
        agent_id: &str,
        who: &str,
        action: &str,
        detail: &str,
        now: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO decisions (agent_id, who, action, detail, ts) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![agent_id, who, action, detail, now],
        )?;
        Ok(())
    }

    pub fn recent_decisions(&self, limit: i64) -> Result<Vec<Decision>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_id, who, action, detail, ts FROM decisions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }
}

fn random_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn agent_id(name: &str) -> String {
    use rand::RngCore;
    let slug: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-');
    // 128 random bits: the id is all an outsider needs to ask for this VPS's
    // desired state. Ids given out earlier (3 bytes) keep working.
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    format!(
        "{}-{}",
        if slug.is_empty() { "vps" } else { slug },
        hex::encode(buf)
    )
}

/// Has the agent applied the desired-state that carried this body's jobs?
fn job_already_applied(body: &DesiredBody, agent_applied_seq: u64) -> bool {
    body.jobs_seq > 0 && agent_applied_seq >= body.jobs_seq
}

// ---- what a ban order may name ---------------------------------------------

/// One address a ban may name: not this machine, not "every address", not a
/// group address.
fn banable(ip: IpAddr) -> bool {
    match snsec_common::net::normalize(ip) {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast())
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()),
    }
}

/// The canonical text of a single address, or `None`.
fn one_address(input: &str) -> Option<String> {
    let ip = snsec_common::net::normalize(input.trim().parse::<IpAddr>().ok()?);
    banable(ip).then(|| ip.to_string())
}

/// An IPv6 /64, the form the VPS keys and reports its IPv6 clients and bans in
/// (`net::ban_key`), rebuilt from the parsed network; `None` for anything else.
fn canonical_v6_64(input: &str) -> Option<String> {
    let (addr, len) = input.trim().split_once('/')?;
    let v6 = addr.parse::<Ipv6Addr>().ok()?;
    if len != "64" || v6.to_ipv4_mapped().is_some() {
        return None;
    }
    let key = snsec_common::net::ban_key(IpAddr::V6(v6));
    let net: Ipv6Addr = key.strip_suffix("/64")?.parse().ok()?;
    banable(IpAddr::V6(net)).then_some(key)
}

/// What a ban or unban order may carry: the canonical text of one address, or
/// of an IPv6 /64 (the agent turns a single IPv6 ban into its /64 anyway). The
/// agent writes it into an nftables script as root, so free text never goes in.
pub(crate) fn ban_target(input: &str) -> Option<String> {
    one_address(input).or_else(|| canonical_v6_64(input))
}

/// Hub bans and unbans a VPS keeps, at most. Every desired-state carries them and
/// the agent reads it whole: an unbounded list (a looping client, a leaked token)
/// would one day be too big to read, and the VPS would stop taking hub orders.
pub(crate) const MAX_HUB_BANS: usize = 1_000;
pub(crate) const MAX_UNBANS: usize = 500;

/// Keep the newest bans and the most recent unbans within those limits.
fn bound_orders(body: &mut DesiredBody) {
    if body.bans.len() > MAX_HUB_BANS {
        body.bans.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        body.bans.truncate(MAX_HUB_BANS);
    }
    if body.unbans.len() > MAX_UNBANS {
        let extra = body.unbans.len() - MAX_UNBANS;
        body.unbans.drain(..extra);
    }
}

/// Rewrite every ban and unban of `body` in its canonical form and drop the
/// ones that name no single address or /64. Returns what was dropped.
fn keep_valid_orders(body: &mut DesiredBody) -> Vec<String> {
    let mut dropped = Vec::new();
    body.bans.retain_mut(|b| match ban_target(&b.ip) {
        Some(ip) => {
            b.ip = ip;
            true
        }
        None => {
            dropped.push(std::mem::take(&mut b.ip));
            false
        }
    });
    body.unbans = std::mem::take(&mut body.unbans)
        .into_iter()
        .filter_map(|u| {
            let ok = ban_target(&u);
            if ok.is_none() {
                dropped.push(u);
            }
            ok
        })
        .collect();
    dropped
}

/// The dropped entries for a log line or the decisions log: escaped and short.
fn shown(dropped: &[String]) -> String {
    let all = format!("{dropped:?}");
    if all.chars().count() > 300 {
        all.chars().take(300).chain("…".chars()).collect()
    } else {
        all
    }
}

fn warn_dropped(agent_id: &str, dropped: &[String]) {
    if !dropped.is_empty() {
        tracing::warn!(
            "desired state of {agent_id}: left out {} ban/unban entr(ies) that are not an IP address: {}",
            dropped.len(),
            shown(dropped)
        );
    }
}

/// Once per open: take out of the stored desired states any ban or unban that
/// is not an address (free text an older hub accepted), so it is neither sent
/// to a VPS again nor kept forever among the unbans. The version stays: what a
/// VPS may still need from the order is unchanged.
fn scrub_desired(conn: &Connection) -> Result<()> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT agent_id, body_json FROM desired")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(Result::ok)
            .collect()
    };
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    for (agent_id, json) in rows {
        let Ok(mut body) = serde_json::from_str::<DesiredBody>(&json) else {
            continue;
        };
        let dropped = keep_valid_orders(&mut body);
        if dropped.is_empty() {
            continue;
        }
        warn_dropped(&agent_id, &dropped);
        conn.execute(
            "UPDATE desired SET body_json = ?1 WHERE agent_id = ?2",
            params![serde_json::to_string(&body)?, agent_id],
        )?;
        conn.execute(
            "INSERT INTO decisions (agent_id, who, action, detail, ts) VALUES (?1, 'system', 'drop', ?2, ?3)",
            params![
                agent_id,
                format!("lệnh chặn/gỡ chặn không phải địa chỉ IP: {}", shown(&dropped)),
                at
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(jobs_seq: u64) -> DesiredBody {
        DesiredBody {
            jobs_seq,
            ..DesiredBody::default()
        }
    }

    #[test]
    fn reports_get_a_burst_then_a_steady_rate_per_agent() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        let burst = REPORT_BURST as usize;
        let ok = (0..burst + 5)
            .filter(|_| db.take_report_token("a", 1_000))
            .count();
        assert_eq!(ok, burst);
        // Another agent has its own budget.
        assert!(db.take_report_token("b", 1_000));
        // It refills slowly, up to the burst.
        assert!(!db.take_report_token("a", 1_000 + REPORT_REFILL_SECS as i64 - 1));
        assert!(db.take_report_token("a", 1_000 + REPORT_REFILL_SECS as i64));
        assert!(!db.take_report_token("a", 1_000 + REPORT_REFILL_SECS as i64));
        let later = 1_000_000;
        let ok = (0..burst + 5)
            .filter(|_| db.take_report_token("a", later))
            .count();
        assert_eq!(ok, burst);
    }

    #[test]
    fn new_agent_ids_are_long_random_and_keep_the_name() {
        let a = agent_id("Web 01!");
        let b = agent_id("Web 01!");
        assert_ne!(a, b);
        let (slug, rand) = a.rsplit_once('-').unwrap();
        assert_eq!(slug, "web-01");
        assert_eq!(rand.len(), 32);
        assert!(rand.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(agent_id("!!!").starts_with("vps-"));
    }

    #[test]
    fn a_job_is_dropped_only_once_the_agent_has_applied_it() {
        // Queued at version 7: not yet applied while the agent is at 6.
        assert!(!job_already_applied(&body(7), 6));
        assert!(job_already_applied(&body(7), 7));
        assert!(job_already_applied(&body(7), 9));
        // No job ever queued: nothing to drop.
        assert!(!job_already_applied(&body(0), 5));
    }

    #[test]
    fn a_ban_order_carries_only_the_canonical_text_of_one_address_or_64() {
        for (input, want) in [
            (" 203.0.113.7 ", "203.0.113.7"),
            ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
            // A private address is the admin's call; it is only flagged elsewhere.
            ("10.0.0.5", "10.0.0.5"),
            // The form the VPS lists its IPv6 clients and bans in.
            ("2001:db8:1:2::/64", "2001:db8:1:2::/64"),
            // Rebuilt from the parsed network, never passed through as typed.
            (" 2001:DB8:1:2:aa::5/64 ", "2001:db8:1:2::/64"),
        ] {
            assert_eq!(ban_target(input).as_deref(), Some(want), "{input}");
        }
        for bad in [
            "",
            "hunt 1 ngày",
            "1.2.3.4 }; flush ruleset; add element inet sn sn_ban4 { 5.6.7.8",
            "1.2.3.4\n5.6.7.8",
            "0.0.0.0/0",
            "::/0",
            "2001:db8::/32",
            "2001:db8::/48",
            "2001:db8::/0",
            "203.0.113.0/24",
            "203.0.113.0/64",
            "::ffff:1.2.3.4/64",
            "::/64",
            "::1/64",
            "ff02::/64",
            "2001:db8::/64 ; flush ruleset",
            "2001:db8::/064",
            "x/64",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "::",
            "255.255.255.255",
            "224.0.0.1",
            "ff02::1",
        ] {
            assert_eq!(ban_target(bad), None, "{bad}");
        }
    }

    fn seed_desired(db: &Db, id: &str, json: &str) {
        db.conn
            .execute(
                "UPDATE desired SET body_json = ?1 WHERE agent_id = ?2",
                params![json, id],
            )
            .unwrap();
    }

    const JUNK: &str = r#"{"mode":"observe","k":5.0,
        "bans":[{"ip":"1.2.3.4 }; flush ruleset","ttl_secs":60,"reason":"admin","created_at":1},
                {"ip":"2001:DB8::9","ttl_secs":60,"reason":"admin","created_at":1}],
        "unbans":["1.2.3.4 }; flush ruleset","203.0.113.7","2001:db8:1:2::/64"]}"#;

    #[test]
    fn stored_free_text_orders_are_never_handed_out_and_are_scrubbed_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let db = Db::open(&path).unwrap();
        let id = db.enroll_agent("web", "pk", 1).unwrap();
        seed_desired(&db, &id, JUNK);
        let raw = |db: &Db| -> (i64, String) {
            db.conn
                .query_row(
                    "SELECT version, body_json FROM desired WHERE agent_id = ?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        // What is signed for the agent leaves it out, and keeps the rest canonical.
        let (_, _, d) = db.get_desired(&id).unwrap().unwrap();
        let bans: Vec<&str> = d.bans.iter().map(|b| b.ip.as_str()).collect();
        assert_eq!(bans, ["2001:db8::9"]);
        assert_eq!(d.unbans, ["203.0.113.7", "2001:db8:1:2::/64"]);
        drop(db);
        // The next open takes it out of the database, keeps the version, and says so.
        let db = Db::open(&path).unwrap();
        let (version, json) = raw(&db);
        assert_eq!(version, 1);
        assert!(!json.contains("flush"), "{json}");
        assert!(json.contains("203.0.113.7") && json.contains("2001:db8::9"));
        let log = db.recent_decisions(5).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!((log[0].1.as_str(), log[0].2.as_str()), ("system", "drop"));
        assert!(log[0].3.contains("flush ruleset"), "{}", log[0].3);
        // Nothing left to drop: a later open logs nothing more.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.recent_decisions(5).unwrap().len(), 1);
    }

    #[test]
    fn an_edit_cannot_store_an_order_that_is_not_an_address() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        let id = db.enroll_agent("web", "pk", 1).unwrap();
        db.update_desired(&id, 2, "admin", "unban", "x", |d| {
            d.unbans.push("1.2.3.4 }; flush ruleset".into());
            d.unbans.push("::ffff:198.51.100.4".into());
        })
        .unwrap();
        let json: String = db
            .conn
            .query_row(
                "SELECT body_json FROM desired WHERE agent_id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!json.contains("flush"), "{json}");
        assert_eq!(
            db.get_desired(&id).unwrap().unwrap().2.unbans,
            ["198.51.100.4"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_effective_uid_is_the_owner_of_a_file_this_process_creates() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("mine");
        std::fs::write(&f, b"x").unwrap();
        let owner = std::fs::metadata(&f).unwrap().uid();
        assert_eq!(effective_uid(), Some(owner));
    }
}
