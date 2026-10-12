//! SQLite persistence for the hub. One connection guarded by a mutex in the
//! shared state; all queries are tiny (≤50 agents), so they run inline in the
//! handlers without awaiting while locked. A connection pool / `spawn_blocking`
//! is a v1.1 upgrade if the fleet grows.

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
}

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

impl Db {
    pub fn open(path: &std::path::Path) -> Result<Db> {
        let conn =
            Connection::open(path).with_context(|| format!("opening db {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        conn.execute_batch(SCHEMA).context("applying schema")?;
        conn.execute_batch(crate::db_ai::SCHEMA_AI)
            .context("applying AI schema")?;
        conn.execute_batch(crate::db_auth::SCHEMA_AUTH)
            .context("applying auth schema")?;
        Ok(Db { conn })
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
             (SELECT id FROM reports WHERE agent_id = ?1 ORDER BY id DESC LIMIT 100)",
            params![agent_id],
        )?;
        Ok(())
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
            serde_json::from_str(&j)
                .ok()
                .map(|b| (e as u64, v as u64, b))
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
    let mut buf = [0u8; 3];
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
    fn a_job_is_dropped_only_once_the_agent_has_applied_it() {
        // Queued at version 7: not yet applied while the agent is at 6.
        assert!(!job_already_applied(&body(7), 6));
        assert!(job_already_applied(&body(7), 7));
        assert!(job_already_applied(&body(7), 9));
        // No job ever queued: nothing to drop.
        assert!(!job_already_applied(&body(0), 5));
    }
}
