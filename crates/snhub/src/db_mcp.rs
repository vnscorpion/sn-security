//! Access tokens for the MCP endpoint (`/mcp`), through which an outside agent
//! such as Hermes reads the fleet and, if allowed, acts on it.
//!
//! A token is shown once when it is made; only its SHA-256 is stored (it is 256
//! random bits, so a plain hash is enough). Each token carries one scope:
//! * `read`    — look only: VPS list, status, evidence, proposals, the log.
//! * `propose` — also submit incident-response plans; they wait for an admin's
//!   approval on the VPS page, exactly like the built-in AI's proposals.
//! * `act`     — also carry out plans (after the same checks against the VPS's
//!   own evidence), ban/unban addresses, change mode and send scans.

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::db::Db;

pub const SCHEMA_MCP: &str = r#"
CREATE TABLE IF NOT EXISTS mcp_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_used INTEGER NOT NULL DEFAULT 0,
    last_ip TEXT NOT NULL DEFAULT '',
    revoked INTEGER NOT NULL DEFAULT 0
);
"#;

pub const SCOPE_READ: &str = "read";
pub const SCOPE_PROPOSE: &str = "propose";
pub const SCOPE_ACT: &str = "act";
/// Live tokens at most; an admin who needs more should revoke old ones.
pub const MAX_TOKENS: i64 = 20;
const TOKEN_PREFIX: &str = "snmcp_";

/// Rank of a scope, so `act` includes `propose` includes `read`.
#[must_use]
pub fn scope_rank(scope: &str) -> u8 {
    match scope {
        SCOPE_ACT => 3,
        SCOPE_PROPOSE => 2,
        SCOPE_READ => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone)]
pub struct McpToken {
    pub id: i64,
    pub name: String,
    pub scope: String,
    pub created: i64,
    pub last_used: i64,
    pub last_ip: String,
}

impl McpToken {
    /// May this token do what `needed` requires?
    #[must_use]
    pub fn allows(&self, needed: &str) -> bool {
        let need = scope_rank(needed);
        need > 0 && scope_rank(&self.scope) >= need
    }
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(format!("snhub-mcp|{token}").as_bytes()))
}

fn new_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{TOKEN_PREFIX}{}", hex::encode(b))
}

/// A name shown in the UI and the decisions log: printable, short.
fn clean_name(name: &str) -> String {
    let n: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
        .take(40)
        .collect();
    let n = n.trim().to_string();
    if n.is_empty() { "hermes".into() } else { n }
}

impl Db {
    /// Make a token; returns `(id, token)`. The token is not stored and cannot be
    /// shown again.
    ///
    /// # Errors
    /// Unknown scope, too many live tokens, or a database error.
    pub fn create_mcp_token(&self, name: &str, scope: &str, now: i64) -> Result<(i64, String)> {
        if scope_rank(scope) == 0 {
            bail!("phạm vi không hợp lệ");
        }
        let live: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM mcp_tokens WHERE revoked = 0",
            [],
            |r| r.get(0),
        )?;
        if live >= MAX_TOKENS {
            bail!("đã có {MAX_TOKENS} token: thu hồi bớt token cũ trước");
        }
        let token = new_token();
        self.conn.execute(
            "INSERT INTO mcp_tokens (name, hash, scope, created) VALUES (?1, ?2, ?3, ?4)",
            params![clean_name(name), hash_token(&token), scope, now],
        )?;
        Ok((self.conn.last_insert_rowid(), token))
    }

    /// The live token matching what a client presented, if any.
    #[must_use]
    pub fn mcp_token(&self, presented: &str) -> Option<McpToken> {
        // Cheap shape check first; anything else cannot be one of ours.
        if !presented.starts_with(TOKEN_PREFIX) || presented.len() != TOKEN_PREFIX.len() + 64 {
            return None;
        }
        self.conn
            .query_row(
                "SELECT id, name, scope, created, last_used, last_ip FROM mcp_tokens \
                 WHERE hash = ?1 AND revoked = 0",
                params![hash_token(presented)],
                |r| {
                    Ok(McpToken {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        scope: r.get(2)?,
                        created: r.get(3)?,
                        last_used: r.get(4)?,
                        last_ip: r.get(5)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn touch_mcp_token(&self, id: i64, now: i64, ip: &str) {
        let _ = self.conn.execute(
            "UPDATE mcp_tokens SET last_used = ?1, last_ip = ?2 WHERE id = ?3",
            params![now, ip.chars().take(45).collect::<String>(), id],
        );
    }

    #[must_use]
    pub fn list_mcp_tokens(&self) -> Vec<McpToken> {
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT id, name, scope, created, last_used, last_ip FROM mcp_tokens \
             WHERE revoked = 0 ORDER BY id",
        ) else {
            return Vec::new();
        };
        stmt.query_map([], |r| {
            Ok(McpToken {
                id: r.get(0)?,
                name: r.get(1)?,
                scope: r.get(2)?,
                created: r.get(3)?,
                last_used: r.get(4)?,
                last_ip: r.get(5)?,
            })
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    /// Revoke every live token; returns how many. Done whenever the admin's
    /// credentials are reset: whoever had the old password could have made one.
    ///
    /// # Errors
    /// A database error.
    pub fn revoke_all_mcp_tokens(&self) -> Result<usize> {
        Ok(self
            .conn
            .execute("UPDATE mcp_tokens SET revoked = 1 WHERE revoked = 0", [])?)
    }

    /// Is a name already used by a live token?
    #[must_use]
    pub fn mcp_name_taken(&self, name: &str) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM mcp_tokens WHERE revoked = 0 AND name = ?1",
                params![clean_name(name)],
                |r| r.get::<_, i64>(0),
            )
            .is_ok_and(|n| n > 0)
    }

    /// Revoke a token; `true` if one was live.
    ///
    /// # Errors
    /// A database error.
    pub fn revoke_mcp_token(&self, id: i64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 AND revoked = 0",
            params![id],
        )? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (Db, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("t.db")).unwrap();
        (db, d)
    }

    #[test]
    fn a_token_is_shown_once_stored_hashed_and_found_again() {
        let (db, _d) = db();
        let (id, tok) = db.create_mcp_token("Hermes <b>", SCOPE_ACT, 10).unwrap();
        assert!(tok.starts_with("snmcp_") && tok.len() == 6 + 64);
        let stored: String = db
            .conn
            .query_row("SELECT hash FROM mcp_tokens WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!stored.contains(&tok[6..]), "only the hash is kept");
        let t = db.mcp_token(&tok).unwrap();
        assert_eq!(
            (t.id, t.scope.as_str(), t.name.as_str()),
            (id, "act", "Hermes b")
        );
        assert!(db.mcp_token("snmcp_nope").is_none());
        let mut wrong = tok.clone();
        wrong.pop();
        wrong.push('0');
        if wrong != tok {
            assert!(db.mcp_token(&wrong).is_none());
        }
    }

    #[test]
    fn scopes_nest_and_unknown_ones_are_refused() {
        let (db, _d) = db();
        assert!(db.create_mcp_token("x", "root", 1).is_err());
        let (_, tok) = db.create_mcp_token("x", SCOPE_PROPOSE, 1).unwrap();
        let t = db.mcp_token(&tok).unwrap();
        assert!(t.allows(SCOPE_READ) && t.allows(SCOPE_PROPOSE) && !t.allows(SCOPE_ACT));
        assert!(!t.allows("bogus"));
    }

    #[test]
    fn a_revoked_token_stops_working_and_the_count_is_capped() {
        let (db, _d) = db();
        let (id, tok) = db.create_mcp_token("x", SCOPE_READ, 1).unwrap();
        assert!(db.revoke_mcp_token(id).unwrap());
        assert!(db.mcp_token(&tok).is_none());
        assert!(!db.revoke_mcp_token(id).unwrap());
        for i in 0..MAX_TOKENS {
            db.create_mcp_token(&format!("t{i}"), SCOPE_READ, 1)
                .unwrap();
        }
        assert!(db.create_mcp_token("one too many", SCOPE_READ, 1).is_err());
        assert_eq!(db.list_mcp_tokens().len() as i64, MAX_TOKENS);
    }
}
