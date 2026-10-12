//! Storage for the admin's sign-in: the password override set from the web UI,
//! the second factors (an authenticator-app secret, passkeys, one-time recovery
//! codes) and a log of sign-in attempts.
//!
//! The password itself lives in the config file as before (set with
//! `snhub set-admin-password`); a password changed in the web UI is kept here,
//! because the service cannot write its own config. When both exist, this wins.
//! Recovery codes are stored only as hashes and each works once.

use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::webauthn::{Credential, b64d, b64e};

pub const SCHEMA_AUTH: &str = r#"
CREATE TABLE IF NOT EXISTS admin_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    pw_hash TEXT NOT NULL DEFAULT '',
    pw_updated INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    webauthn_user TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL UNIQUE,
    x TEXT NOT NULL,
    y TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    hash TEXT PRIMARY KEY,
    created INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    ip TEXT NOT NULL,
    ok INTEGER NOT NULL,
    method TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
"#;

/// Recovery codes issued at a time.
pub const RECOVERY_CODES: usize = 8;
const LOGIN_LOG_KEEP: i64 = 200;
/// Letters and digits that cannot be misread (no 0/o, 1/l/i).
const CODE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

#[derive(Debug, Clone)]
pub struct TotpState {
    pub secret: String,
    pub enabled: bool,
    pub last_step: u64,
}

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: i64,
    pub name: String,
    pub created: i64,
    pub last_used: i64,
}

#[derive(Debug, Clone)]
pub struct LoginRow {
    pub ts: i64,
    pub ip: String,
    pub ok: bool,
    pub method: String,
    pub note: String,
}

/// Normalise what a person typed: lower case, no dashes or spaces.
fn normalise_code(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The stored form of a recovery code.
#[must_use]
pub fn hash_recovery(code: &str) -> String {
    hex::encode(Sha256::digest(
        format!("snhub-recovery|{}", normalise_code(code)).as_bytes(),
    ))
}

/// `RECOVERY_CODES` fresh codes as `(shown to the admin, stored)`.
#[must_use]
pub fn new_recovery_codes() -> Vec<(String, String)> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut pick = |n: usize| -> String {
                (0..n)
                    .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
                    .collect()
            };
            let code = format!("{}-{}-{}", pick(5), pick(5), pick(5));
            let hash = hash_recovery(&code);
            (code, hash)
        })
        .collect()
}

impl Db {
    fn ensure_auth_row(&self) -> Result<()> {
        self.conn
            .execute("INSERT OR IGNORE INTO admin_auth (id) VALUES (1)", [])?;
        Ok(())
    }

    // ---- password override ------------------------------------------------

    pub fn admin_pw_hash(&self) -> Option<String> {
        self.conn
            .query_row("SELECT pw_hash FROM admin_auth WHERE id = 1", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .filter(|h| !h.is_empty())
    }

    pub fn set_admin_pw_hash(&self, phc: &str, now: i64) -> Result<()> {
        self.ensure_auth_row()?;
        self.conn.execute(
            "UPDATE admin_auth SET pw_hash = ?1, pw_updated = ?2 WHERE id = 1",
            params![phc, now],
        )?;
        Ok(())
    }

    // ---- authenticator app (TOTP) -----------------------------------------

    pub fn totp(&self) -> Option<TotpState> {
        self.conn
            .query_row(
                "SELECT totp_secret, totp_enabled, totp_last_step FROM admin_auth WHERE id = 1",
                [],
                |r| {
                    Ok(TotpState {
                        secret: r.get(0)?,
                        enabled: r.get::<_, i64>(1)? != 0,
                        last_step: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
            .filter(|t| !t.secret.is_empty())
    }

    /// Store a new secret, not yet active: it only counts after a code from it
    /// has been entered correctly.
    pub fn start_totp(&self, secret: &str) -> Result<()> {
        self.ensure_auth_row()?;
        self.conn.execute(
            "UPDATE admin_auth SET totp_secret = ?1, totp_enabled = 0, totp_last_step = 0 WHERE id = 1",
            params![secret],
        )?;
        Ok(())
    }

    pub fn enable_totp(&self, step: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE admin_auth SET totp_enabled = 1, totp_last_step = ?1 WHERE id = 1",
            params![i64::try_from(step).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }

    /// Claim a time step for a sign-in: `true` only for the one caller that
    /// moves the stored step forward, so a code cannot be used twice even by two
    /// requests at the same moment.
    pub fn claim_totp_step(&self, step: u64) -> bool {
        self.conn
            .execute(
                "UPDATE admin_auth SET totp_last_step = ?1 \
                 WHERE id = 1 AND totp_enabled = 1 AND totp_last_step < ?1",
                params![i64::try_from(step).unwrap_or(i64::MAX)],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    pub fn disable_totp(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE admin_auth SET totp_secret = '', totp_enabled = 0, totp_last_step = 0 WHERE id = 1",
            [],
        )?;
        Ok(())
    }

    // ---- passkeys ---------------------------------------------------------

    /// The stable user handle WebAuthn wants (random, not the user name).
    pub fn webauthn_user(&self) -> Result<String> {
        self.ensure_auth_row()?;
        let cur: String = self.conn.query_row(
            "SELECT webauthn_user FROM admin_auth WHERE id = 1",
            [],
            |r| r.get(0),
        )?;
        if !cur.is_empty() {
            return Ok(cur);
        }
        use rand::RngCore;
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let id = b64e(&buf);
        self.conn.execute(
            "UPDATE admin_auth SET webauthn_user = ?1 WHERE id = 1",
            params![id],
        )?;
        Ok(id)
    }

    pub fn add_passkey(&self, c: &Credential, name: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO passkeys (cred_id, x, y, sign_count, name, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![c.id, b64e(&c.x), b64e(&c.y), i64::from(c.sign_count), name, now],
        )?;
        Ok(())
    }

    pub fn list_passkeys(&self) -> Vec<PasskeyRow> {
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT id, name, created, last_used FROM passkeys ORDER BY id")
        else {
            return Vec::new();
        };
        stmt.query_map([], |r| {
            Ok(PasskeyRow {
                id: r.get(0)?,
                name: r.get(1)?,
                created: r.get(2)?,
                last_used: r.get(3)?,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    /// Credential ids of every passkey (for `allowCredentials` / `excludeCredentials`).
    pub fn passkey_ids(&self) -> Vec<String> {
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT cred_id FROM passkeys ORDER BY id")
        else {
            return Vec::new();
        };
        stmt.query_map([], |r| r.get::<_, String>(0))
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    pub fn get_passkey(&self, cred_id: &str) -> Option<Credential> {
        self.conn
            .query_row(
                "SELECT cred_id, x, y, sign_count FROM passkeys WHERE cred_id = ?1",
                params![cred_id],
                |r| {
                    let (x, y): (String, String) = (r.get(1)?, r.get(2)?);
                    Ok((r.get::<_, String>(0)?, x, y, r.get::<_, i64>(3)?))
                },
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|(id, x, y, n)| {
                let (x, y) = (b64d(&x)?, b64d(&y)?);
                Some(Credential {
                    id,
                    x: x.try_into().ok()?,
                    y: y.try_into().ok()?,
                    sign_count: u32::try_from(n).unwrap_or(0),
                })
            })
    }

    pub fn touch_passkey(&self, cred_id: &str, sign_count: u32, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE passkeys SET sign_count = ?1, last_used = ?2 WHERE cred_id = ?3",
            params![i64::from(sign_count), now, cred_id],
        )?;
        Ok(())
    }

    pub fn delete_passkey(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM passkeys WHERE id = ?1", params![id])?
            > 0)
    }

    // ---- recovery codes ---------------------------------------------------

    /// Replace all recovery codes with these hashes.
    pub fn replace_recovery_codes(&self, hashes: &[String], now: i64) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM recovery_codes", [])?;
        for h in hashes {
            tx.execute(
                "INSERT INTO recovery_codes (hash, created) VALUES (?1, ?2)",
                params![h, now],
            )?;
        }
        Ok(tx.commit()?)
    }

    /// Use a code: `true` once, then never again.
    pub fn use_recovery_code(&self, hash: &str) -> bool {
        self.conn
            .execute(
                "UPDATE recovery_codes SET used = 1 WHERE hash = ?1 AND used = 0",
                params![hash],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    pub fn recovery_codes_left(&self) -> u32 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE used = 0",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_or(0, |n| u32::try_from(n).unwrap_or(0))
    }

    // ---- overview ---------------------------------------------------------

    /// Is a second factor required to sign in?
    pub fn second_factor_enrolled(&self) -> bool {
        self.totp().is_some_and(|t| t.enabled) || !self.list_passkeys().is_empty()
    }

    /// Remove every second factor and recovery code (lock-out recovery, and
    /// turning 2FA off).
    pub fn reset_2fa(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE admin_auth SET totp_secret = '', totp_enabled = 0, totp_last_step = 0 WHERE id = 1",
            [],
        )?;
        tx.execute("DELETE FROM passkeys", [])?;
        tx.execute("DELETE FROM recovery_codes", [])?;
        Ok(tx.commit()?)
    }

    // ---- sign-in log ------------------------------------------------------

    pub fn log_login(&self, ts: i64, ip: &str, ok: bool, method: &str, note: &str) {
        let _ = self.conn.execute(
            "INSERT INTO login_log (ts, ip, ok, method, note) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ts,
                ip.chars().take(45).collect::<String>(),
                i64::from(ok),
                method,
                note.chars().take(120).collect::<String>()
            ],
        );
        // Failures and successes are trimmed separately: a flood of wrong
        // guesses must not push out the record of who signed in or what changed.
        for (ok, keep) in [(0_i64, LOGIN_LOG_KEEP / 2), (1_i64, LOGIN_LOG_KEEP)] {
            let _ = self.conn.execute(
                "DELETE FROM login_log WHERE ok = ?1 AND id NOT IN \
                 (SELECT id FROM login_log WHERE ok = ?1 ORDER BY id DESC LIMIT ?2)",
                params![ok, keep],
            );
        }
    }

    pub fn recent_logins(&self, n: i64) -> Vec<LoginRow> {
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT ts, ip, ok, method, note FROM login_log ORDER BY id DESC LIMIT ?1")
        else {
            return Vec::new();
        };
        stmt.query_map(params![n], |r| {
            Ok(LoginRow {
                ts: r.get(0)?,
                ip: r.get(1)?,
                ok: r.get::<_, i64>(2)? != 0,
                method: r.get(3)?,
                note: r.get(4)?,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        (db, dir)
    }

    #[test]
    fn no_second_factor_until_one_is_confirmed() {
        let (db, _d) = db();
        assert!(!db.second_factor_enrolled());
        db.start_totp("ABCDEF234567").unwrap();
        // A secret that was shown but never confirmed does not turn 2FA on.
        assert!(!db.second_factor_enrolled());
        assert!(!db.totp().unwrap().enabled);
        db.enable_totp(42).unwrap();
        assert!(db.second_factor_enrolled());
        let t = db.totp().unwrap();
        assert_eq!((t.enabled, t.last_step), (true, 42));
        assert!(db.claim_totp_step(43));
        assert_eq!(db.totp().unwrap().last_step, 43);
        // The same step (or an older one) cannot be claimed again.
        assert!(!db.claim_totp_step(43) && !db.claim_totp_step(40));
        assert!(db.claim_totp_step(44));
        db.disable_totp().unwrap();
        assert!(db.totp().is_none() && !db.second_factor_enrolled());
    }

    #[test]
    fn passkeys_are_stored_listed_counted_and_removed() {
        let (db, _d) = db();
        let c = Credential {
            id: "credA".into(),
            x: [1; 32],
            y: [2; 32],
            sign_count: 3,
        };
        db.add_passkey(&c, "Laptop", 10).unwrap();
        assert!(db.second_factor_enrolled());
        assert_eq!(db.passkey_ids(), ["credA"]);
        assert_eq!(db.get_passkey("credA").unwrap(), c);
        assert!(db.get_passkey("nope").is_none());
        db.touch_passkey("credA", 9, 20).unwrap();
        assert_eq!(db.get_passkey("credA").unwrap().sign_count, 9);
        let l = db.list_passkeys();
        assert_eq!(
            (l.len(), l[0].name.as_str(), l[0].last_used),
            (1, "Laptop", 20)
        );
        // The same credential twice is refused.
        assert!(db.add_passkey(&c, "Dup", 11).is_err());
        assert!(db.delete_passkey(l[0].id).unwrap());
        assert!(!db.second_factor_enrolled());
    }

    #[test]
    fn a_recovery_code_works_once_and_only_as_typed_loosely() {
        let (db, _d) = db();
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        // Distinct, well formed, and what is stored is not what is shown.
        let shown: std::collections::HashSet<&str> =
            codes.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(shown.len(), RECOVERY_CODES);
        for (code, hash) in &codes {
            assert_eq!(code.len(), 17);
            assert_eq!((code.as_bytes()[5], code.as_bytes()[11]), (b'-', b'-'));
            assert_ne!(code, hash);
        }
        let hashes: Vec<String> = codes.iter().map(|(_, h)| h.clone()).collect();
        db.replace_recovery_codes(&hashes, 1).unwrap();
        assert_eq!(db.recovery_codes_left(), RECOVERY_CODES as u32);
        let typed = codes[0].0.to_uppercase().replace('-', " ");
        assert!(db.use_recovery_code(&hash_recovery(&typed)));
        assert!(!db.use_recovery_code(&hash_recovery(&typed)), "single use");
        assert!(!db.use_recovery_code(&hash_recovery("zzzzz-zzzzz")));
        assert_eq!(db.recovery_codes_left(), RECOVERY_CODES as u32 - 1);
        // Issuing new codes invalidates the old ones.
        db.replace_recovery_codes(&["x".into()], 2).unwrap();
        assert!(!db.use_recovery_code(&hashes[1]));
    }

    #[test]
    fn resetting_clears_every_factor_but_keeps_the_password() {
        let (db, _d) = db();
        db.set_admin_pw_hash("$argon2id$fake", 5).unwrap();
        db.start_totp("AAAA").unwrap();
        db.enable_totp(1).unwrap();
        db.add_passkey(
            &Credential {
                id: "c".into(),
                x: [0; 32],
                y: [0; 32],
                sign_count: 0,
            },
            "k",
            1,
        )
        .unwrap();
        db.replace_recovery_codes(&["h".into()], 1).unwrap();
        db.reset_2fa().unwrap();
        assert!(!db.second_factor_enrolled());
        assert_eq!(db.recovery_codes_left(), 0);
        assert_eq!(db.admin_pw_hash().as_deref(), Some("$argon2id$fake"));
    }

    #[test]
    fn the_webauthn_user_handle_is_stable_and_random() {
        let (db, _d) = db();
        let a = db.webauthn_user().unwrap();
        assert_eq!(a, db.webauthn_user().unwrap());
        assert!(a.len() >= 20);
    }

    #[test]
    fn the_sign_in_log_is_bounded_newest_first_and_failures_cannot_push_out_successes() {
        let (db, _d) = db();
        db.log_login(1, "1.2.3.4", true, "tắt 2FA", "an event worth keeping");
        for i in 0..(LOGIN_LOG_KEEP * 3) {
            db.log_login(10 + i, "9.9.9.9", false, "password", "sai");
        }
        let all = db.recent_logins(10_000);
        // Failures are capped at half the budget; the early success survived.
        assert_eq!(
            all.iter().filter(|r| !r.ok).count() as i64,
            LOGIN_LOG_KEEP / 2
        );
        assert!(all.iter().any(|r| r.ok && r.method == "tắt 2FA"));
        assert_eq!(all[0].ts, 10 + LOGIN_LOG_KEEP * 3 - 1, "newest first");
        assert_eq!(db.recent_logins(5).len(), 5);
        for i in 0..(LOGIN_LOG_KEEP + 30) {
            db.log_login(100_000 + i, "1.2.3.4", true, "password", "x");
        }
        let ok = db.recent_logins(10_000).iter().filter(|r| r.ok).count() as i64;
        assert_eq!(ok, LOGIN_LOG_KEEP);
    }
}
