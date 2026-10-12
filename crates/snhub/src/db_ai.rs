//! Storage for the AI-assisted incident response: the providers the operator
//! configured, the latest evidence per VPS, per-VPS autonomy, and the proposals
//! the model made with what became of them.
//!
//! API keys are stored as written, in the hub's own SQLite file (readable only by
//! the hub's user), because the hub must send them. They are never put back into
//! a page: the UI shows only the last four characters.

use anyhow::Result;
use rusqlite::{OptionalExtension, Row, params};
use snsec_common::ai::{self, Plan};
use snsec_common::schema::{Evidence, RemediationReport};

use crate::ai_client::Provider;
use crate::db::Db;

pub const SCHEMA_AI: &str = r#"
CREATE TABLE IF NOT EXISTS ai_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL,
    api_key TEXT NOT NULL DEFAULT '',
    is_default INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    agent_id TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    body_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_state (
    agent_id TEXT PRIMARY KEY,
    autonomy TEXT NOT NULL DEFAULT 'approve',
    pending INTEGER NOT NULL DEFAULT 0,
    pending_since INTEGER NOT NULL DEFAULT 0,
    last_analysis INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    created INTEGER NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    diagnosis TEXT NOT NULL DEFAULT '',
    plan_json TEXT NOT NULL DEFAULT '{}',
    note TEXT NOT NULL DEFAULT '',
    job_id TEXT NOT NULL DEFAULT '',
    applied_json TEXT NOT NULL DEFAULT '[]',
    result_json TEXT NOT NULL DEFAULT '',
    auto INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_proposals_agent ON proposals(agent_id, id DESC);
"#;

/// A pending analysis older than this is given up on (the agent never answered).
pub const PENDING_TIMEOUT_SECS: i64 = 20 * 60;

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
    pub is_default: bool,
}

impl ProviderRow {
    #[must_use]
    pub fn to_provider(&self) -> Provider {
        Provider {
            id: self.id,
            name: self.name.clone(),
            kind: self.kind.clone(),
            endpoint: self.endpoint.clone(),
            model: self.model.clone(),
            api_key: self.api_key.clone(),
        }
    }
}

fn provider_row(r: &Row<'_>) -> rusqlite::Result<ProviderRow> {
    Ok(ProviderRow {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        endpoint: r.get(3)?,
        model: r.get(4)?,
        api_key: r.get(5)?,
        is_default: r.get::<_, i64>(6)? != 0,
    })
}

/// What the operator typed for a provider.
#[derive(Debug, Clone, Copy)]
pub struct ProviderInput<'a> {
    pub name: &'a str,
    pub kind: &'a str,
    pub endpoint: &'a str,
    pub model: &'a str,
    pub api_key: &'a str,
}

/// A proposal to store.
#[derive(Debug, Clone, Copy)]
pub struct NewProposal<'a> {
    pub agent_id: &'a str,
    pub provider: &'a str,
    pub status: &'a str,
    pub plan: &'a Plan,
    pub note: &'a str,
    pub auto: bool,
}

const PROVIDER_COLS: &str = "id, name, kind, endpoint, model, api_key, is_default";

#[derive(Debug, Clone)]
pub struct AiState {
    pub autonomy: String,
    pub pending: bool,
    pub pending_since: i64,
    pub last_analysis: i64,
}

impl Default for AiState {
    fn default() -> Self {
        AiState {
            autonomy: ai::AUTONOMY_APPROVE.to_string(),
            pending: false,
            pending_since: 0,
            last_analysis: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProposalRow {
    pub id: i64,
    pub agent_id: String,
    pub created: i64,
    pub provider: String,
    /// `proposed`, `executing`, `done`, `rejected` or `error`.
    pub status: String,
    pub diagnosis: String,
    pub plan: Plan,
    pub note: String,
    pub job_id: String,
    /// Indices of the plan's actions already ordered.
    pub applied: Vec<usize>,
    pub result: Option<RemediationReport>,
    pub auto: bool,
}

const PROPOSAL_COLS: &str = "id, agent_id, created, provider, status, diagnosis, plan_json, note, job_id, applied_json, result_json, auto";

fn proposal_row(r: &Row<'_>) -> rusqlite::Result<ProposalRow> {
    let plan_json: String = r.get(6)?;
    let applied_json: String = r.get(9)?;
    let result_json: String = r.get(10)?;
    Ok(ProposalRow {
        id: r.get(0)?,
        agent_id: r.get(1)?,
        created: r.get(2)?,
        provider: r.get(3)?,
        status: r.get(4)?,
        diagnosis: r.get(5)?,
        plan: serde_json::from_str(&plan_json).unwrap_or_default(),
        note: r.get(7)?,
        job_id: r.get(8)?,
        applied: serde_json::from_str(&applied_json).unwrap_or_default(),
        result: serde_json::from_str(&result_json).ok(),
        auto: r.get::<_, i64>(11)? != 0,
    })
}

impl Db {
    // ---- providers --------------------------------------------------------

    pub fn list_providers(&self) -> Result<Vec<ProviderRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {PROVIDER_COLS} FROM ai_providers ORDER BY is_default DESC, id"
        ))?;
        let rows = stmt.query_map([], provider_row)?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn get_provider(&self, id: i64) -> Result<Option<ProviderRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {PROVIDER_COLS} FROM ai_providers WHERE id = ?1"),
                params![id],
                provider_row,
            )
            .optional()?)
    }

    /// The provider analyses use: the one marked default, else the first.
    pub fn default_provider(&self) -> Result<Option<ProviderRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {PROVIDER_COLS} FROM ai_providers ORDER BY is_default DESC, id LIMIT 1"
                ),
                [],
                provider_row,
            )
            .optional()?)
    }

    /// Add (`id = None`) or change a provider. An empty `api_key` on a change
    /// keeps the stored one, so editing a name does not require re-typing it.
    pub fn save_provider(&self, id: Option<i64>, p: &ProviderInput<'_>, now: i64) -> Result<i64> {
        let ProviderInput {
            name,
            kind,
            endpoint,
            model,
            api_key,
        } = *p;
        match id {
            Some(id) => {
                if api_key.is_empty() {
                    self.conn.execute(
                        "UPDATE ai_providers SET name=?1, kind=?2, endpoint=?3, model=?4 WHERE id=?5",
                        params![name, kind, endpoint, model, id],
                    )?;
                } else {
                    self.conn.execute(
                        "UPDATE ai_providers SET name=?1, kind=?2, endpoint=?3, model=?4, api_key=?5 WHERE id=?6",
                        params![name, kind, endpoint, model, api_key, id],
                    )?;
                }
                Ok(id)
            }
            None => {
                let first: i64 =
                    self.conn
                        .query_row("SELECT COUNT(*) FROM ai_providers", [], |r| r.get(0))?;
                self.conn.execute(
                    "INSERT INTO ai_providers (name, kind, endpoint, model, api_key, is_default, created) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![name, kind, endpoint, model, api_key, i64::from(first == 0), now],
                )?;
                Ok(self.conn.last_insert_rowid())
            }
        }
    }

    pub fn set_default_provider(&self, id: i64) -> Result<()> {
        self.conn
            .execute("UPDATE ai_providers SET is_default = 0", [])?;
        self.conn.execute(
            "UPDATE ai_providers SET is_default = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn delete_provider(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM ai_providers WHERE id = ?1", params![id])?;
        // Keep exactly one default if any provider is left.
        self.conn.execute(
            "UPDATE ai_providers SET is_default = 1 WHERE id = \
             (SELECT id FROM ai_providers ORDER BY id LIMIT 1) \
             AND NOT EXISTS (SELECT 1 FROM ai_providers WHERE is_default = 1)",
            [],
        )?;
        Ok(())
    }

    // ---- evidence ---------------------------------------------------------

    pub fn save_evidence(&self, agent_id: &str, ev: &Evidence) -> Result<()> {
        self.conn.execute(
            "INSERT INTO evidence (agent_id, at, body_json) VALUES (?1, ?2, ?3) \
             ON CONFLICT(agent_id) DO UPDATE SET at=?2, body_json=?3",
            params![agent_id, ev.at, serde_json::to_string(ev)?],
        )?;
        Ok(())
    }

    pub fn latest_evidence(&self, agent_id: &str) -> Result<Option<Evidence>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT body_json FROM evidence WHERE agent_id = ?1",
                params![agent_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    // ---- per-VPS AI state -------------------------------------------------

    pub fn ai_state(&self, agent_id: &str) -> Result<AiState> {
        let row = self
            .conn
            .query_row(
                "SELECT autonomy, pending, pending_since, last_analysis FROM ai_state WHERE agent_id = ?1",
                params![agent_id],
                |r| {
                    Ok(AiState {
                        autonomy: r.get(0)?,
                        pending: r.get::<_, i64>(1)? != 0,
                        pending_since: r.get(2)?,
                        last_analysis: r.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_default())
    }

    fn ensure_ai_state(&self, agent_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO ai_state (agent_id) VALUES (?1)",
            params![agent_id],
        )?;
        Ok(())
    }

    pub fn set_autonomy(&self, agent_id: &str, autonomy: &str) -> Result<()> {
        self.ensure_ai_state(agent_id)?;
        self.conn.execute(
            "UPDATE ai_state SET autonomy = ?1 WHERE agent_id = ?2",
            params![autonomy, agent_id],
        )?;
        Ok(())
    }

    pub fn set_pending(&self, agent_id: &str, pending: bool, now: i64) -> Result<()> {
        self.ensure_ai_state(agent_id)?;
        self.conn.execute(
            "UPDATE ai_state SET pending = ?1, pending_since = ?2 WHERE agent_id = ?3",
            params![i64::from(pending), if pending { now } else { 0 }, agent_id],
        )?;
        Ok(())
    }

    pub fn touch_analysis(&self, agent_id: &str, now: i64) -> Result<()> {
        self.ensure_ai_state(agent_id)?;
        self.conn.execute(
            "UPDATE ai_state SET last_analysis = ?1 WHERE agent_id = ?2",
            params![now, agent_id],
        )?;
        Ok(())
    }

    // ---- proposals --------------------------------------------------------

    pub fn create_proposal(&self, now: i64, n: &NewProposal<'_>) -> Result<i64> {
        let NewProposal {
            agent_id,
            provider,
            status,
            plan,
            note,
            auto,
        } = *n;
        self.conn.execute(
            "INSERT INTO proposals (agent_id, created, provider, status, diagnosis, plan_json, note, auto) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                agent_id,
                now,
                provider,
                status,
                plan.diagnosis,
                serde_json::to_string(plan)?,
                note,
                i64::from(auto)
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn latest_proposal(&self, agent_id: &str) -> Result<Option<ProposalRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {PROPOSAL_COLS} FROM proposals WHERE agent_id = ?1 ORDER BY id DESC LIMIT 1"
                ),
                params![agent_id],
                proposal_row,
            )
            .optional()?)
    }

    pub fn get_proposal(&self, id: i64) -> Result<Option<ProposalRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {PROPOSAL_COLS} FROM proposals WHERE id = ?1"),
                params![id],
                proposal_row,
            )
            .optional()?)
    }

    /// Record that actions were ordered: the new status, the job id and every
    /// index ordered so far.
    pub fn mark_proposal_ordered(&self, id: i64, job_id: &str, applied: &[usize]) -> Result<()> {
        self.conn.execute(
            "UPDATE proposals SET status = 'executing', job_id = ?1, applied_json = ?2 WHERE id = ?3",
            params![job_id, serde_json::to_string(applied)?, id],
        )?;
        Ok(())
    }

    pub fn set_proposal_status(&self, id: i64, status: &str, note: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE proposals SET status = ?1, note = ?2 WHERE id = ?3",
            params![status, note, id],
        )?;
        Ok(())
    }

    /// Attach the agent's report on a job to the proposal that ordered it. The
    /// proposal is `done` only when every one of its actions has been ordered;
    /// otherwise it stays open for the rest.
    pub fn attach_remediation(&self, agent_id: &str, rep: &RemediationReport) -> Result<bool> {
        let row: Option<(i64, String, String)> = self
            .conn
            .query_row(
                "SELECT id, plan_json, applied_json FROM proposals WHERE agent_id = ?1 AND job_id = ?2",
                params![agent_id, rep.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, plan_json, applied_json)) = row else {
            return Ok(false);
        };
        let total = serde_json::from_str::<Plan>(&plan_json)
            .map(|p| p.proposed.len())
            .unwrap_or(0);
        let applied = serde_json::from_str::<Vec<usize>>(&applied_json)
            .map(|a| a.len())
            .unwrap_or(0);
        let status = if applied >= total { "done" } else { "proposed" };
        self.conn.execute(
            "UPDATE proposals SET status = ?1, result_json = ?2 WHERE id = ?3",
            params![status, serde_json::to_string(rep)?, id],
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snsec_common::ai::Proposed;
    use snsec_common::schema::Action;

    fn pi<'a>(
        name: &'a str,
        kind: &'a str,
        endpoint: &'a str,
        model: &'a str,
        key: &'a str,
    ) -> ProviderInput<'a> {
        ProviderInput {
            name,
            kind,
            endpoint,
            model,
            api_key: key,
        }
    }

    fn db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn the_first_provider_becomes_the_default_and_a_key_survives_edits() {
        let (db, _d) = db();
        let a = db
            .save_provider(
                None,
                &pi(
                    "Hermes",
                    "openai",
                    "https://h/v1",
                    "hermes-4",
                    "sk-secret-1234",
                ),
                1,
            )
            .unwrap();
        let b = db
            .save_provider(
                None,
                &pi("Claude", "anthropic", "", "claude-x", "key-b-5678"),
                2,
            )
            .unwrap();
        assert_eq!(db.default_provider().unwrap().unwrap().id, a);
        db.set_default_provider(b).unwrap();
        assert_eq!(db.default_provider().unwrap().unwrap().id, b);
        // Editing without a key keeps the old one; with a key replaces it.
        db.save_provider(
            Some(a),
            &pi("Hermes 4", "openai", "https://h/v1", "hermes-4", ""),
            3,
        )
        .unwrap();
        assert_eq!(
            db.get_provider(a).unwrap().unwrap().api_key,
            "sk-secret-1234"
        );
        db.save_provider(
            Some(a),
            &pi(
                "Hermes 4",
                "openai",
                "https://h/v1",
                "hermes-4",
                "new-key-9999",
            ),
            3,
        )
        .unwrap();
        assert_eq!(db.get_provider(a).unwrap().unwrap().api_key, "new-key-9999");
    }

    #[test]
    fn deleting_the_default_promotes_another() {
        let (db, _d) = db();
        let a = db
            .save_provider(None, &pi("A", "openai", "https://a/v1", "m", "k"), 1)
            .unwrap();
        let b = db
            .save_provider(None, &pi("B", "openai", "https://b/v1", "m", "k"), 2)
            .unwrap();
        db.delete_provider(a).unwrap();
        let d = db.default_provider().unwrap().unwrap();
        assert_eq!(d.id, b);
        assert!(d.is_default);
        db.delete_provider(b).unwrap();
        assert!(db.default_provider().unwrap().is_none());
    }

    #[test]
    fn autonomy_defaults_to_approve_and_pending_is_tracked() {
        let (db, _d) = db();
        let s = db.ai_state("a1").unwrap();
        assert_eq!(s.autonomy, "approve");
        assert!(!s.pending);
        db.set_autonomy("a1", "auto_safe").unwrap();
        db.set_pending("a1", true, 100).unwrap();
        let s = db.ai_state("a1").unwrap();
        assert_eq!(
            (s.autonomy.as_str(), s.pending, s.pending_since),
            ("auto_safe", true, 100)
        );
        db.set_pending("a1", false, 200).unwrap();
        assert!(!db.ai_state("a1").unwrap().pending);
    }

    #[test]
    fn a_proposal_goes_from_proposed_to_ordered_to_done() {
        let (db, _d) = db();
        let plan = Plan {
            diagnosis: "miner".into(),
            proposed: vec![Proposed {
                action: Action::DisableService {
                    unit: "rpcbind.service".into(),
                },
                reason: "port 111".into(),
                risk: "medium".into(),
            }],
            rejected: vec![],
        };
        let id = db
            .create_proposal(
                10,
                &NewProposal {
                    agent_id: "a1",
                    provider: "Hermes",
                    status: "proposed",
                    plan: &plan,
                    note: "",
                    auto: false,
                },
            )
            .unwrap();
        let p = db.latest_proposal("a1").unwrap().unwrap();
        assert_eq!(
            (p.id, p.status.as_str(), p.plan.proposed.len()),
            (id, "proposed", 1)
        );
        db.mark_proposal_ordered(id, "p1-10", &[0]).unwrap();
        let p = db.get_proposal(id).unwrap().unwrap();
        assert_eq!(
            (p.status.as_str(), p.job_id.as_str(), p.applied.clone()),
            ("executing", "p1-10", vec![0])
        );
        let rep = RemediationReport {
            id: "p1-10".into(),
            at: 20,
            results: vec![snsec_common::schema::ActionResult {
                index: 0,
                ok: true,
                message: "ok".into(),
            }],
        };
        assert!(db.attach_remediation("a1", &rep).unwrap());
        let p = db.get_proposal(id).unwrap().unwrap();
        assert_eq!(p.status, "done");
        assert!(p.result.unwrap().results[0].ok);
        // A report for a job nobody ordered attaches to nothing.
        let other = RemediationReport {
            id: "zzz".into(),
            at: 1,
            results: vec![],
        };
        assert!(!db.attach_remediation("a1", &other).unwrap());
    }

    #[test]
    fn evidence_is_kept_per_vps_and_replaced() {
        let (db, _d) = db();
        assert!(db.latest_evidence("a1").unwrap().is_none());
        db.save_evidence(
            "a1",
            &Evidence {
                at: 5,
                label: "miner".into(),
                ..Evidence::default()
            },
        )
        .unwrap();
        db.save_evidence(
            "a1",
            &Evidence {
                at: 9,
                label: "unknown".into(),
                ..Evidence::default()
            },
        )
        .unwrap();
        let e = db.latest_evidence("a1").unwrap().unwrap();
        assert_eq!((e.at, e.label.as_str()), (9, "unknown"));
    }
}
