//! Storage for the AI's reading of a VPS's traffic: what it found and what it
//! proposed (WAF rules, short bans), and what became of each proposal.
//!
//! Apart from the incident proposals (`proposals`): those carry jobs for the
//! agent checked against its evidence, these carry orders the hub itself carries
//! out (a WAF rule, a ban in the desired state).

use anyhow::Result;
use rusqlite::{OptionalExtension, Row, params};

use crate::db::Db;
use crate::traffic_ai::TrafficItem;

pub const SCHEMA_TRAFFIC: &str = r#"
CREATE TABLE IF NOT EXISTS traffic_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    created INTEGER NOT NULL,
    provider TEXT NOT NULL,
    -- proposed (waiting for a click), done, rejected, error
    status TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    items_json TEXT NOT NULL DEFAULT '[]',
    applied_json TEXT NOT NULL DEFAULT '[]',
    rejected_json TEXT NOT NULL DEFAULT '[]',
    note TEXT NOT NULL DEFAULT '',
    auto INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_agent ON traffic_proposals(agent_id, id DESC);
"#;

/// A traffic proposal as stored.
#[derive(Debug, Clone)]
pub struct TrafficRow {
    pub id: i64,
    pub agent_id: String,
    pub created: i64,
    pub provider: String,
    pub status: String,
    pub summary: String,
    pub items: Vec<TrafficItem>,
    /// Indices into `items` already carried out.
    pub applied: Vec<usize>,
    /// What the hub dropped from the model's answer, and why.
    pub rejected: Vec<String>,
    pub note: String,
    pub auto: bool,
}

/// A proposal to store.
#[derive(Debug, Clone, Copy)]
pub struct NewTraffic<'a> {
    pub agent_id: &'a str,
    pub provider: &'a str,
    pub status: &'a str,
    pub summary: &'a str,
    pub items: &'a [TrafficItem],
    pub rejected: &'a [String],
    pub note: &'a str,
    pub auto: bool,
}

const COLS: &str = "id, agent_id, created, provider, status, summary, items_json, applied_json, rejected_json, note, auto";

fn traffic_row(r: &Row<'_>) -> rusqlite::Result<TrafficRow> {
    let json = |i: usize| -> rusqlite::Result<String> { r.get(i) };
    Ok(TrafficRow {
        id: r.get(0)?,
        agent_id: r.get(1)?,
        created: r.get(2)?,
        provider: r.get(3)?,
        status: r.get(4)?,
        summary: r.get(5)?,
        items: serde_json::from_str(&json(6)?).unwrap_or_default(),
        applied: serde_json::from_str(&json(7)?).unwrap_or_default(),
        rejected: serde_json::from_str(&json(8)?).unwrap_or_default(),
        note: r.get(9)?,
        auto: r.get::<_, i64>(10)? != 0,
    })
}

impl Db {
    pub fn create_traffic(&self, now: i64, n: &NewTraffic<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO traffic_proposals \
             (agent_id, created, provider, status, summary, items_json, rejected_json, note, auto) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                n.agent_id,
                now,
                n.provider,
                n.status,
                n.summary,
                serde_json::to_string(n.items)?,
                serde_json::to_string(n.rejected)?,
                n.note,
                i64::from(n.auto),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn latest_traffic(&self, agent_id: &str) -> Result<Option<TrafficRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {COLS} FROM traffic_proposals WHERE agent_id = ?1 ORDER BY id DESC LIMIT 1"
                ),
                params![agent_id],
                traffic_row,
            )
            .optional()?)
    }

    pub fn get_traffic(&self, id: i64) -> Result<Option<TrafficRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM traffic_proposals WHERE id = ?1"),
                params![id],
                traffic_row,
            )
            .optional()?)
    }

    /// Record what was carried out: the indices, the new status, a note.
    pub fn update_traffic(
        &self,
        id: i64,
        status: &str,
        applied: &[usize],
        note: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE traffic_proposals SET status = ?1, applied_json = ?2, note = ?3 WHERE id = ?4",
            params![status, serde_json::to_string(applied)?, note, id],
        )?;
        Ok(())
    }
}
