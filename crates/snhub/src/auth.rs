//! Minimal admin authentication: a single password (salted SHA-256) and an
//! in-memory session set keyed by a random cookie. This is intentionally small;
//! bind the hub to localhost and front it with a VPN or IP allow-list. TOTP and
//! per-user roles are a v1.1 upgrade (review RM-9).

use std::collections::HashSet;
use std::sync::Mutex;

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

pub const COOKIE: &str = "snhub_session";

#[derive(Default)]
pub struct Sessions {
    live: Mutex<HashSet<String>>,
}

impl Sessions {
    pub fn insert(&self, token: String) {
        if let Ok(mut s) = self.live.lock() {
            s.insert(token);
        }
    }

    pub fn valid(&self, token: &str) -> bool {
        self.live.lock().map(|s| s.contains(token)).unwrap_or(false)
    }

    pub fn remove(&self, token: &str) {
        if let Ok(mut s) = self.live.lock() {
            s.remove(token);
        }
    }
}

/// Salted hash of a password, hex-encoded.
#[must_use]
pub fn hash_password(salt: &str, password: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"|");
    h.update(password.as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time comparison of two hex strings of equal expected length.
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Extract the session cookie value from request headers.
#[must_use]
pub fn session_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(&format!("{COOKIE}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// Generate a random session token.
#[must_use]
pub fn new_session_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_salted() {
        let a = hash_password("s1", "pw");
        let b = hash_password("s1", "pw");
        let c = hash_password("s2", "pw");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
    }
}
