//! ModSecurity rules the hub orders onto the VPSes, and what they matched.
//!
//! A rule is data (kind + value, see [`snsec_common::waf::WafRule`]); the agent
//! renders it into its own rules file. Every rule starts as log-only: the
//! request goes through and the web server writes a line, which the agent
//! counts and reports. An admin looks at those hits and only then lets the rule
//! block (403). Rules apply to every VPS or to one.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use snsec_common::waf::{self, MANAGED_ID_MAX, MANAGED_ID_MIN, MAX_WAF_RULES, WafKind, WafRule};

use crate::db::Db;

pub const SCHEMA_WAF: &str = r#"
CREATE TABLE IF NOT EXISTS waf_rules (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    agent_id TEXT NOT NULL DEFAULT '',
    block INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    UNIQUE(kind, value, agent_id)
);
CREATE TABLE IF NOT EXISTS waf_seq (
    k INTEGER PRIMARY KEY CHECK (k = 1),
    next INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS waf_hits (
    agent_id TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    last_at INTEGER NOT NULL DEFAULT 0,
    samples TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (agent_id, rule_id)
);
"#;

/// Examples kept per rule and VPS.
const SAMPLES_KEPT: usize = 5;
const SAMPLE_MAX: usize = 200;
/// Hit lines one report may carry; anything past that is ignored.
const HITS_PER_REPORT: usize = MAX_WAF_RULES;
/// A note is a short reminder, not a document.
const NOTE_MAX: usize = 200;

/// Probes for files no site serves, and the User-Agent words of common
/// vulnerability scanners: the starter set the hub offers (log-only at first).
pub const STARTER_PATHS: &[&str] = &[
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.env.production",
    "/.git/",
    "/.svn/",
    "/.aws/",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php~",
    "/.vscode/sftp.json",
];
pub const STARTER_TOKENS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nuclei",
    "masscan",
    "zgrab",
    "wpscan",
    "acunetix",
    "netsparker",
    "dirbuster",
    "gobuster",
    "nmap",
];

#[derive(Debug, Clone)]
pub struct WafRuleRow {
    pub id: u32,
    pub kind: WafKind,
    pub value: String,
    /// Empty: every VPS.
    pub agent_id: String,
    pub block: bool,
    pub note: String,
    pub created_at: i64,
    pub created_by: String,
    pub updated_at: i64,
    pub updated_by: String,
}

impl WafRuleRow {
    #[must_use]
    pub fn rule(&self) -> WafRule {
        WafRule {
            id: self.id,
            kind: self.kind,
            value: self.value.clone(),
            block: self.block,
        }
    }
}

/// Hits of one rule, summed over the VPSes (or for one VPS).
#[derive(Debug, Clone, Default)]
pub struct WafHits {
    pub count: u64,
    /// Of those, answered 403.
    pub blocked: u64,
    pub last_at: i64,
    pub samples: Vec<String>,
    /// VPSes (agent ids) where it matched.
    pub agents: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Added(u32),
    /// The same rule already exists for that scope (its id).
    Exists(u32),
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<WafRuleRow>> {
    let kind: String = r.get(1)?;
    let Some(kind) = WafKind::parse(&kind) else {
        return Ok(None);
    };
    Ok(Some(WafRuleRow {
        id: r.get::<_, i64>(0)? as u32,
        kind,
        value: r.get(2)?,
        agent_id: r.get(3)?,
        block: r.get::<_, i64>(4)? != 0,
        note: r.get(5)?,
        created_at: r.get(6)?,
        created_by: r.get(7)?,
        updated_at: r.get(8)?,
        updated_by: r.get(9)?,
    }))
}

const COLS: &str =
    "id, kind, value, agent_id, block, note, created_at, created_by, updated_at, updated_by";

impl Db {
    /// Every rule, fleet-wide ones first, then by id.
    pub fn list_waf_rules(&self) -> Result<Vec<WafRuleRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLS} FROM waf_rules ORDER BY agent_id <> '', agent_id, id"
        ))?;
        let rows = stmt.query_map([], row)?;
        Ok(rows.filter_map(Result::ok).flatten().collect())
    }

    pub fn waf_rule(&self, id: u32) -> Result<Option<WafRuleRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM waf_rules WHERE id = ?1"),
                params![i64::from(id)],
                row,
            )
            .optional()?
            .flatten())
    }

    /// The rules in force on one VPS: fleet-wide ones and its own.
    pub fn waf_rules_for(&self, agent_id: &str) -> Result<Vec<WafRule>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLS} FROM waf_rules WHERE agent_id = '' OR agent_id = ?1 ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![agent_id], row)?;
        Ok(rows
            .filter_map(Result::ok)
            .flatten()
            .map(|r| r.rule())
            .take(MAX_WAF_RULES)
            .collect())
    }

    fn waf_count(&self, agent_id: &str) -> Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM waf_rules WHERE agent_id = '' OR agent_id = ?1",
            params![agent_id],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    /// The most rules any one VPS would carry if one more fleet-wide rule came.
    fn waf_max_load(&self) -> Result<usize> {
        let fleet: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM waf_rules WHERE agent_id = ''",
            [],
            |r| r.get(0),
        )?;
        let own: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(n), 0) FROM \
             (SELECT COUNT(*) AS n FROM waf_rules WHERE agent_id <> '' GROUP BY agent_id)",
            [],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(fleet + own).unwrap_or(usize::MAX))
    }

    /// A fresh id. Ids are not handed out again soon after a rule is removed,
    /// so a hit the VPS counted for the old rule is not credited to a new one.
    fn next_waf_id(&self) -> Result<u32> {
        let stored: Option<i64> = self
            .conn
            .query_row("SELECT next FROM waf_seq WHERE k = 1", [], |r| r.get(0))
            .optional()?;
        let (lo, hi) = (i64::from(MANAGED_ID_MIN), i64::from(MANAGED_ID_MAX));
        let mut stmt = self.conn.prepare("SELECT id FROM waf_rules")?;
        let used: HashSet<i64> = stmt
            .query_map([], |r| r.get(0))?
            .filter_map(Result::ok)
            .collect();
        // The first free id from where the last one was handed out, wrapping
        // round once: an id just freed is the last to be used again.
        let start = stored.filter(|s| (lo..=hi).contains(s)).unwrap_or(lo);
        let span = hi - lo + 1;
        let Some(next) = (0..span)
            .map(|k| lo + (start - lo + k) % span)
            .find(|id| !used.contains(id))
        else {
            bail!("no free WAF rule id");
        };
        self.conn.execute(
            "INSERT INTO waf_seq (k, next) VALUES (1, ?1) ON CONFLICT(k) DO UPDATE SET next = ?1",
            params![next + 1],
        )?;
        Ok(u32::try_from(next)?)
    }

    /// Add a log-only rule for every VPS (`agent_id` empty) or one VPS, and
    /// send it out.
    ///
    /// # Errors
    /// A value the agent would refuse, an unknown VPS, too many rules, or a
    /// database error.
    pub fn add_waf_rule(
        &self,
        kind: WafKind,
        value: &str,
        agent_id: &str,
        note: &str,
        who: &str,
        now: i64,
    ) -> Result<AddOutcome> {
        let value = value.trim();
        if !waf::valid_value(kind, value) {
            bail!("giá trị không dùng được cho loại luật này");
        }
        if !agent_id.is_empty() && self.agent(agent_id)?.is_none() {
            bail!("không có VPS này");
        }
        let existing: Option<i64> = self
            .conn
            .query_row(
                // The same rule for every VPS already covers this one.
                "SELECT id FROM waf_rules WHERE kind = ?1 AND value = ?2 \
                 AND (agent_id = ?3 OR agent_id = '') ORDER BY agent_id = '' DESC LIMIT 1",
                params![kind.as_str(), value, agent_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok(AddOutcome::Exists(u32::try_from(id)?));
        }
        let load = if agent_id.is_empty() {
            self.waf_max_load()?
        } else {
            self.waf_count(agent_id)?
        };
        if load >= MAX_WAF_RULES {
            bail!("đã đủ {MAX_WAF_RULES} luật cho một VPS");
        }
        let note: String = note.trim().chars().take(NOTE_MAX).collect();
        let tx = self.conn.unchecked_transaction()?;
        let id = self.next_waf_id()?;
        self.conn.execute(
            "INSERT INTO waf_rules (id, kind, value, agent_id, block, note, created_at, created_by, updated_at, updated_by) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?6, ?7)",
            params![i64::from(id), kind.as_str(), value, agent_id, note, now, who],
        )?;
        self.record_decision(
            scope_label(agent_id),
            who,
            "waf_add",
            &format!("luật WAF #{id} ({}): {value} — chỉ ghi nhận", kind_vi(kind)),
            now,
        )?;
        self.sync_waf_scope(agent_id, now, who)?;
        tx.commit()?;
        Ok(AddOutcome::Added(id))
    }

    /// Let a rule block (403) or put it back to log-only.
    ///
    /// # Errors
    /// A database error. `Ok(false)` when there is no such rule.
    pub fn set_waf_block(&self, id: u32, block: bool, who: &str, now: i64) -> Result<bool> {
        let Some(r) = self.waf_rule(id)? else {
            return Ok(false);
        };
        if r.block == block {
            return Ok(true);
        }
        let tx = self.conn.unchecked_transaction()?;
        self.conn.execute(
            "UPDATE waf_rules SET block = ?1, updated_at = ?2, updated_by = ?3 WHERE id = ?4",
            params![i64::from(block), now, who, i64::from(id)],
        )?;
        let what = if block {
            "bật chặn"
        } else {
            "chỉ ghi nhận"
        };
        self.record_decision(
            scope_label(&r.agent_id),
            who,
            if block { "waf_block" } else { "waf_log" },
            &format!("luật WAF #{id} ({}): {} — {what}", kind_vi(r.kind), r.value),
            now,
        )?;
        self.sync_waf_scope(&r.agent_id, now, who)?;
        tx.commit()?;
        Ok(true)
    }

    /// Remove a rule from the hub and from the VPSes.
    ///
    /// # Errors
    /// A database error. `Ok(false)` when there is no such rule.
    pub fn remove_waf_rule(&self, id: u32, who: &str, now: i64) -> Result<bool> {
        let Some(r) = self.waf_rule(id)? else {
            return Ok(false);
        };
        let tx = self.conn.unchecked_transaction()?;
        self.conn.execute(
            "DELETE FROM waf_rules WHERE id = ?1",
            params![i64::from(id)],
        )?;
        self.conn.execute(
            "DELETE FROM waf_hits WHERE rule_id = ?1",
            params![i64::from(id)],
        )?;
        self.record_decision(
            scope_label(&r.agent_id),
            who,
            "waf_remove",
            &format!("xoá luật WAF #{id} ({}): {}", kind_vi(r.kind), r.value),
            now,
        )?;
        self.sync_waf_scope(&r.agent_id, now, who)?;
        tx.commit()?;
        Ok(true)
    }

    /// Add the starter set (probe paths, scanner words) for every VPS, log-only.
    /// Returns how many were new.
    ///
    /// # Errors
    /// A database error or too many rules.
    pub fn add_waf_starter(&self, who: &str, now: i64) -> Result<usize> {
        let mut added = 0;
        let items = STARTER_PATHS
            .iter()
            .map(|v| (WafKind::Path, *v))
            .chain(STARTER_TOKENS.iter().map(|v| (WafKind::UaToken, *v)));
        for (kind, value) in items {
            if let AddOutcome::Added(_) =
                self.add_waf_rule(kind, value, "", "gói cơ bản", who, now)?
            {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Bring the desired state of the VPSes a scope covers up to date.
    fn sync_waf_scope(&self, agent_id: &str, now: i64, who: &str) -> Result<()> {
        if agent_id.is_empty() {
            for a in self.list_agents()? {
                self.sync_waf(&a.id, now, who)?;
            }
            Ok(())
        } else {
            self.sync_waf(agent_id, now, who)
        }
    }

    /// Put the VPS's current rules into its desired state, if they differ from
    /// what is there. A VPS that never had rules and has none gets nothing, so
    /// its agent does not start managing a WAF file for no reason.
    ///
    /// # Errors
    /// A database error.
    pub fn sync_waf(&self, agent_id: &str, now: i64, who: &str) -> Result<()> {
        let rules = self.waf_rules_for(agent_id)?;
        let current = self.get_desired(agent_id)?.and_then(|(_, _, d)| d.waf);
        let unchanged = match &current {
            Some(have) => *have == rules,
            None => rules.is_empty(),
        };
        if unchanged {
            return Ok(());
        }
        self.update_desired_quiet(agent_id, now, who, |d| d.waf = Some(rules))
    }

    /// Add the hits a VPS reported to the running totals. Hits for ids the hub
    /// no longer has are dropped.
    ///
    /// # Errors
    /// A database error.
    pub fn record_waf_hits(
        &self,
        agent_id: &str,
        hits: &[snsec_common::schema::WafHit],
    ) -> Result<()> {
        if hits.is_empty() {
            return Ok(());
        }
        let known: std::collections::HashSet<u32> = self
            .waf_rules_for(agent_id)?
            .into_iter()
            .map(|r| r.id)
            .collect();
        let tx = self.conn.unchecked_transaction()?;
        for h in hits.iter().take(HITS_PER_REPORT) {
            if h.count == 0 || !known.contains(&h.id) {
                continue;
            }
            let old: Option<String> = self
                .conn
                .query_row(
                    "SELECT samples FROM waf_hits WHERE agent_id = ?1 AND rule_id = ?2",
                    params![agent_id, i64::from(h.id)],
                    |r| r.get(0),
                )
                .optional()?;
            let mut samples: Vec<String> = old
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for s in h.samples.iter().take(SAMPLES_KEPT) {
                let s: String = s.chars().take(SAMPLE_MAX).collect();
                samples.retain(|x| *x != s);
                samples.insert(0, s);
            }
            samples.truncate(SAMPLES_KEPT);
            let count = i64::try_from(h.count).unwrap_or(i64::MAX);
            let blocked = i64::try_from(h.blocked.min(h.count)).unwrap_or(i64::MAX);
            self.conn.execute(
                "INSERT INTO waf_hits (agent_id, rule_id, count, blocked, last_at, samples) \
                 VALUES (?1, ?2, ?3, ?6, ?4, ?5) \
                 ON CONFLICT(agent_id, rule_id) DO UPDATE SET \
                 count = MIN(count + ?3, 9000000000000000000), \
                 blocked = MIN(blocked + ?6, 9000000000000000000), \
                 last_at = MAX(last_at, ?4), samples = ?5",
                params![
                    agent_id,
                    i64::from(h.id),
                    count,
                    h.last_at,
                    serde_json::to_string(&samples)?,
                    blocked
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Hits per rule id, summed over the VPSes, or for one VPS.
    pub fn waf_hits(&self, agent_id: Option<&str>) -> Result<HashMap<u32, WafHits>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_id, rule_id, count, last_at, samples, blocked FROM waf_hits \
             WHERE ?1 IS NULL OR agent_id = ?1",
        )?;
        let rows = stmt.query_map(params![agent_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut out: HashMap<u32, WafHits> = HashMap::new();
        for (agent, id, count, last_at, samples, blocked) in rows.filter_map(Result::ok) {
            let Ok(id) = u32::try_from(id) else { continue };
            let e = out.entry(id).or_default();
            e.count = e.count.saturating_add(u64::try_from(count).unwrap_or(0));
            e.blocked = e
                .blocked
                .saturating_add(u64::try_from(blocked).unwrap_or(0));
            e.last_at = e.last_at.max(last_at);
            e.agents.push(agent);
            let s: Vec<String> = serde_json::from_str(&samples).unwrap_or_default();
            for x in s {
                if e.samples.len() < SAMPLES_KEPT && !e.samples.contains(&x) {
                    e.samples.push(x);
                }
            }
        }
        Ok(out)
    }

    /// Forget everything WAF-related about a VPS that is being removed.
    pub(crate) fn forget_waf_agent(tx: &rusqlite::Transaction<'_>, agent_id: &str) -> Result<()> {
        tx.execute(
            "DELETE FROM waf_rules WHERE agent_id = ?1",
            params![agent_id],
        )?;
        tx.execute(
            "DELETE FROM waf_hits WHERE agent_id = ?1",
            params![agent_id],
        )?;
        Ok(())
    }
}

/// The decisions-log VPS column for a scope.
fn scope_label(agent_id: &str) -> &str {
    if agent_id.is_empty() { "*" } else { agent_id }
}

#[must_use]
pub fn kind_vi(kind: WafKind) -> &'static str {
    match kind {
        WafKind::UserAgent => "User-Agent",
        WafKind::Shape => "kiểu request",
        WafKind::Path => "đường dẫn dò quét",
        WafKind::UaToken => "công cụ quét",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snsec_common::schema::WafHit;

    fn db_with(agents: &[&str]) -> Db {
        let db = Db::open(std::path::Path::new(":memory:")).unwrap();
        for a in agents {
            db.conn
                .execute(
                    "INSERT INTO agents (id, name, pubkey, created, last_seen, last_report_seq, version, mode) \
                     VALUES (?1, ?1, '', 0, 0, 0, '', 'observe')",
                    params![a],
                )
                .unwrap();
        }
        db
    }

    fn desired_waf(db: &Db, agent: &str) -> Option<Vec<WafRule>> {
        db.get_desired(agent).unwrap().and_then(|(_, _, d)| d.waf)
    }

    #[test]
    fn a_new_rule_logs_only_and_reaches_every_vps() {
        let db = db_with(&["a", "b"]);
        let AddOutcome::Added(id) = db
            .add_waf_rule(WafKind::Path, "/.env", "", "", "admin", 100)
            .unwrap()
        else {
            panic!("not added")
        };
        assert_eq!(id, MANAGED_ID_MIN);
        for a in ["a", "b"] {
            let rules = desired_waf(&db, a).unwrap();
            assert_eq!(rules.len(), 1);
            assert!(!rules[0].block);
            assert_eq!(rules[0].value, "/.env");
        }
        // The same rule again is not a second rule.
        assert_eq!(
            db.add_waf_rule(WafKind::Path, "/.env", "", "", "admin", 101)
                .unwrap(),
            AddOutcome::Exists(id)
        );
        // One log line for the fleet, not one per VPS.
        let log = db.recent_decisions(10).unwrap();
        assert_eq!(log.iter().filter(|d| d.2 == "waf_add").count(), 1);
    }

    #[test]
    fn a_rule_for_one_vps_stays_on_it() {
        let db = db_with(&["a", "b"]);
        db.add_waf_rule(WafKind::UaToken, "sqlmap", "a", "", "admin", 100)
            .unwrap();
        assert_eq!(desired_waf(&db, "a").unwrap().len(), 1);
        // b never had rules and has none: its desired state is untouched.
        assert!(db.get_desired("b").unwrap().is_none());
        assert!(
            db.add_waf_rule(WafKind::UaToken, "sqlmap", "nope", "", "admin", 100)
                .is_err()
        );
    }

    #[test]
    fn values_the_agent_would_refuse_are_refused_here() {
        let db = db_with(&["a"]);
        assert!(
            db.add_waf_rule(WafKind::UaToken, "chrome", "", "", "admin", 1)
                .is_err()
        );
        assert!(
            db.add_waf_rule(WafKind::Path, "/x%{TX.a}", "", "", "admin", 1)
                .is_err()
        );
        assert!(db.list_waf_rules().unwrap().is_empty());
    }

    #[test]
    fn blocking_and_removing_update_the_vps_and_ids_are_not_reused_at_once() {
        let db = db_with(&["a"]);
        let AddOutcome::Added(id) = db
            .add_waf_rule(WafKind::Path, "/.git/", "", "", "admin", 1)
            .unwrap()
        else {
            panic!()
        };
        let v0 = db.get_desired("a").unwrap().unwrap().1;
        assert!(db.set_waf_block(id, true, "admin", 2).unwrap());
        let (_, v1, d) = db.get_desired("a").unwrap().unwrap();
        assert!(v1 > v0);
        assert!(d.waf.unwrap()[0].block);
        // Same state again: no new version.
        assert!(db.set_waf_block(id, true, "admin", 3).unwrap());
        assert_eq!(db.get_desired("a").unwrap().unwrap().1, v1);

        db.record_waf_hits(
            "a",
            &[WafHit {
                id,
                count: 3,
                blocked: 1,
                last_at: 5,
                samples: vec!["a.example /.git/config".into()],
            }],
        )
        .unwrap();
        assert_eq!(db.waf_hits(None).unwrap()[&id].count, 3);
        assert_eq!(db.waf_hits(None).unwrap()[&id].blocked, 1);

        assert!(db.remove_waf_rule(id, "admin", 4).unwrap());
        assert_eq!(desired_waf(&db, "a").unwrap(), Vec::<WafRule>::new());
        assert!(db.waf_hits(None).unwrap().is_empty());
        assert!(!db.remove_waf_rule(id, "admin", 4).unwrap());

        let AddOutcome::Added(next) = db
            .add_waf_rule(WafKind::Path, "/.svn/", "", "", "admin", 5)
            .unwrap()
        else {
            panic!()
        };
        assert_ne!(next, id);
    }

    #[test]
    fn hits_add_up_and_unknown_ids_are_dropped() {
        let db = db_with(&["a", "b"]);
        let AddOutcome::Added(id) = db
            .add_waf_rule(WafKind::UaToken, "nikto", "", "", "admin", 1)
            .unwrap()
        else {
            panic!()
        };
        let hit = |count, last_at, s: &str| WafHit {
            id,
            count,
            blocked: 0,
            last_at,
            samples: vec![s.into()],
        };
        db.record_waf_hits("a", &[hit(2, 10, "x /a")]).unwrap();
        db.record_waf_hits("a", &[hit(3, 20, "x /b")]).unwrap();
        db.record_waf_hits("b", &[hit(1, 15, "y /c")]).unwrap();
        db.record_waf_hits(
            "a",
            &[WafHit {
                id: id + 1000,
                count: 99,
                blocked: 0,
                last_at: 30,
                samples: vec![],
            }],
        )
        .unwrap();
        let all = db.waf_hits(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[&id].count, 6);
        assert_eq!(all[&id].last_at, 20);
        assert_eq!(all[&id].agents.len(), 2);
        let a = db.waf_hits(Some("a")).unwrap();
        assert_eq!(a[&id].count, 5);
        assert_eq!(a[&id].samples[0], "x /b");
    }

    #[test]
    fn a_rule_every_vps_has_is_not_added_again_for_one() {
        let db = db_with(&["a"]);
        let AddOutcome::Added(id) = db
            .add_waf_rule(WafKind::Path, "/.env", "", "", "admin", 1)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            db.add_waf_rule(WafKind::Path, "/.env", "a", "", "admin", 2)
                .unwrap(),
            AddOutcome::Exists(id)
        );
        assert_eq!(db.list_waf_rules().unwrap().len(), 1);
    }

    #[test]
    fn after_the_last_id_a_just_freed_id_is_the_last_to_come_back() {
        let db = db_with(&["a"]);
        // Pretend the counter is at the top of the range.
        db.conn
            .execute(
                "INSERT INTO waf_seq (k, next) VALUES (1, ?1)",
                params![i64::from(MANAGED_ID_MAX)],
            )
            .unwrap();
        let add = |v: &str| match db
            .add_waf_rule(WafKind::Path, v, "", "", "admin", 1)
            .unwrap()
        {
            AddOutcome::Added(id) => id,
            AddOutcome::Exists(_) => panic!(),
        };
        let top = add("/.one");
        assert_eq!(top, MANAGED_ID_MAX);
        let first = add("/.two");
        assert_eq!(first, MANAGED_ID_MIN);
        assert!(db.remove_waf_rule(first, "admin", 2).unwrap());
        // Not handed out again at once.
        assert_eq!(add("/.three"), MANAGED_ID_MIN + 1);
    }

    #[test]
    fn the_starter_set_is_valid_and_added_once() {
        let db = db_with(&["a"]);
        let n = db.add_waf_starter("admin", 1).unwrap();
        assert_eq!(n, STARTER_PATHS.len() + STARTER_TOKENS.len());
        assert_eq!(db.add_waf_starter("admin", 2).unwrap(), 0);
        let rules = desired_waf(&db, "a").unwrap();
        assert_eq!(rules.len(), n);
        assert!(rules.iter().all(|r| r.is_valid() && !r.block));
    }
}
