//! Admin authentication: password (Argon2id), an optional second factor (TOTP or
//! a passkey, see `totp` and `webauthn`), server-side sessions that expire, and a
//! limiter that slows down guessing.
//!
//! Sessions, half-finished logins and the limiter live in memory: a restart signs
//! everyone out, which is the right failure. Nothing here is persisted except what
//! the caller stores (the password hash, the second factors).

use std::collections::HashMap;
use std::sync::Mutex;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

pub const COOKIE: &str = "snhub_session";
/// Cookie that carries a login whose password was right but whose second factor
/// is still to come.
pub const PENDING_COOKIE: &str = "snhub_2fa";

/// A session ends this long after sign-in, whatever happens.
const SESSION_ABS_SECS: i64 = 24 * 3600;
/// ...and this long after its last request.
const SESSION_IDLE_SECS: i64 = 8 * 3600;
const MAX_SESSIONS: usize = 50;
/// A password-correct login must finish its second factor within this long.
const PENDING_TTL_SECS: i64 = 5 * 60;
/// Wrong second-factor attempts allowed per half-finished login.
const PENDING_MAX_TRIES: u32 = 5;
/// A passkey challenge is good for this long.
const CHALLENGE_TTL_SECS: i64 = 2 * 60;

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

/// A new Argon2id hash (PHC string, random salt) of `password`.
///
/// # Panics
/// Never in practice; hashing with the default parameters cannot fail.
#[must_use]
pub fn hash_password_argon2(password: &str) -> String {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

/// Check `password` against an Argon2 PHC string. A malformed hash never matches.
#[must_use]
pub fn verify_password_argon2(phc: &str, password: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

/// The old salted SHA-256, kept only to read hashes written by earlier versions.
#[must_use]
pub fn hash_password(salt: &str, password: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"|");
    h.update(password.as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time comparison of two strings.
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

/// Is a password acceptable for the admin? Length, not composition rules: a long
/// passphrase beats `Aa1!aaaa`.
#[must_use]
pub fn password_problem(pw: &str) -> Option<&'static str> {
    if pw.chars().count() < 10 {
        Some("Mật khẩu cần ít nhất 10 ký tự (nên dùng một câu dài).")
    } else if pw.chars().count() > 200 {
        Some("Mật khẩu quá dài (tối đa 200 ký tự).")
    } else if pw.chars().all(|c| c == pw.chars().next().unwrap_or(' ')) {
        Some("Mật khẩu không được chỉ gồm một ký tự lặp lại.")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Cookies and tokens
// ---------------------------------------------------------------------------

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        if let Some(val) = part.trim().strip_prefix(&format!("{name}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// The session cookie's value.
#[must_use]
pub fn session_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, COOKIE)
}

/// The half-finished-login cookie's value.
#[must_use]
pub fn pending_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, PENDING_COOKIE)
}

/// A random 192-bit token, hex.
#[must_use]
pub fn new_session_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// A `Set-Cookie` value. `Secure` when the hub is served over HTTPS.
#[must_use]
pub fn cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{name}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// The client address behind the reverse proxy: the *last* `X-Forwarded-For`
/// entry (the one the proxy itself added, whether it appends to or replaces what
/// the client sent), else `X-Real-IP`. Only meaningful when the hub is reached
/// through one such proxy (the documented setup binds the hub to 127.0.0.1); the
/// limiter does not rely on it alone.
#[must_use]
pub fn client_ip(headers: &HeaderMap) -> String {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    let raw = h("x-forwarded-for")
        .and_then(|v| v.rsplit(',').next())
        .or_else(|| h("x-real-ip"))
        .unwrap_or("")
        .trim();
    // Only something that is an address: it ends up in a map key and a page.
    raw.parse::<std::net::IpAddr>()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into())
}

fn short_id(token: &str) -> String {
    hex::encode(&Sha256::digest(token.as_bytes())[..6])
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Public handle (a hash of the token) so a page can name a session without
    /// exposing it.
    pub id: String,
    pub created: i64,
    pub last_seen: i64,
    pub ip: String,
    pub agent: String,
    /// How it was opened: `password`, `password+totp`, `password+passkey`,
    /// `password+recovery`.
    pub method: String,
}

#[derive(Default)]
pub struct Sessions {
    live: Mutex<HashMap<String, SessionInfo>>,
}

fn expired(s: &SessionInfo, now: i64) -> bool {
    now - s.created > SESSION_ABS_SECS || now - s.last_seen > SESSION_IDLE_SECS
}

impl Sessions {
    pub fn insert(&self, token: String, ip: &str, agent: &str, method: &str, now: i64) {
        let Ok(mut m) = self.live.lock() else {
            return;
        };
        m.retain(|_, s| !expired(s, now));
        // Bounded: if somehow full, the oldest goes.
        while m.len() >= MAX_SESSIONS {
            let Some(oldest) = m
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            m.remove(&oldest);
        }
        let id = short_id(&token);
        m.insert(
            token,
            SessionInfo {
                id,
                created: now,
                last_seen: now,
                ip: ip.chars().take(45).collect(),
                agent: agent
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(120)
                    .collect(),
                method: method.into(),
            },
        );
    }

    /// Is this a live session? A request counts as activity.
    pub fn valid(&self, token: &str, now: i64) -> bool {
        let Ok(mut m) = self.live.lock() else {
            return false;
        };
        match m.get_mut(token) {
            Some(s) if !expired(s, now) => {
                s.last_seen = now;
                true
            }
            Some(_) => {
                m.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn remove(&self, token: &str) {
        if let Ok(mut m) = self.live.lock() {
            m.remove(token);
        }
    }

    /// Every live session, newest first.
    pub fn list(&self, now: i64) -> Vec<SessionInfo> {
        let Ok(m) = self.live.lock() else {
            return Vec::new();
        };
        let mut v: Vec<SessionInfo> = m.values().filter(|s| !expired(s, now)).cloned().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.created));
        v
    }

    /// Sign out every session except `keep` (a password or factor change). Returns
    /// how many were ended.
    pub fn remove_all_except(&self, keep: &str) -> usize {
        let Ok(mut m) = self.live.lock() else {
            return 0;
        };
        let before = m.len();
        m.retain(|t, _| t == keep);
        before - m.len()
    }

    /// End one session by its public id.
    pub fn remove_by_id(&self, id: &str) -> bool {
        let Ok(mut m) = self.live.lock() else {
            return false;
        };
        let target = m.iter().find(|(_, s)| s.id == id).map(|(t, _)| t.clone());
        target.is_some_and(|t| m.remove(&t).is_some())
    }

    /// The public id of a token's session.
    pub fn id_of(&self, token: &str) -> Option<String> {
        self.live.lock().ok()?.get(token).map(|s| s.id.clone())
    }
}

// ---------------------------------------------------------------------------
// Logins waiting for their second factor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub created: i64,
    pub tries: u32,
    pub ip: String,
    pub agent: String,
    /// The passkey challenge issued to this login, with when.
    pub challenge: Option<(String, i64)>,
}

#[derive(Default)]
pub struct Pending {
    m: Mutex<HashMap<String, PendingLogin>>,
}

impl Pending {
    const MAX: usize = 200;

    /// Drop expired entries; if it is still full, drop the oldest one, so a
    /// flood cannot throw out logins that are in progress all at once.
    fn make_room(m: &mut HashMap<String, PendingLogin>, now: i64) {
        m.retain(|_, p| now - p.created <= PENDING_TTL_SECS);
        while m.len() >= Self::MAX {
            let Some(oldest) = m
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            m.remove(&oldest);
        }
    }

    /// Start a half-finished login after the password was right.
    pub fn create(&self, ip: &str, agent: &str, now: i64) -> String {
        let token = new_session_token();
        if let Ok(mut m) = self.m.lock() {
            Self::make_room(&mut m, now);
            m.insert(
                token.clone(),
                PendingLogin {
                    created: now,
                    tries: 0,
                    ip: ip.chars().take(45).collect(),
                    agent: agent
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(120)
                        .collect(),
                    challenge: None,
                },
            );
        }
        token
    }

    /// The login, if it is still open.
    pub fn get(&self, token: &str, now: i64) -> Option<PendingLogin> {
        let m = self.m.lock().ok()?;
        m.get(token)
            .filter(|p| now - p.created <= PENDING_TTL_SECS && p.tries < PENDING_MAX_TRIES)
            .cloned()
    }

    /// A wrong second factor. Returns attempts left; at 0 the login is gone.
    pub fn fail(&self, token: &str) -> u32 {
        let Ok(mut m) = self.m.lock() else {
            return 0;
        };
        let left = match m.get_mut(token) {
            Some(p) => {
                p.tries += 1;
                PENDING_MAX_TRIES.saturating_sub(p.tries)
            }
            None => 0,
        };
        if left == 0 {
            m.remove(token);
        }
        left
    }

    /// Remember the passkey challenge issued to this login.
    pub fn set_challenge(&self, token: &str, challenge: &str, now: i64) {
        if let Ok(mut m) = self.m.lock()
            && let Some(p) = m.get_mut(token)
        {
            p.challenge = Some((challenge.to_string(), now));
        }
    }

    /// Hold a challenge under a caller-chosen key (a passkey being added from a
    /// signed-in session). It expires like a login and is taken once.
    pub fn issue(&self, key: &str, challenge: &str, now: i64) {
        if let Ok(mut m) = self.m.lock() {
            Self::make_room(&mut m, now);
            m.insert(
                key.to_string(),
                PendingLogin {
                    created: now,
                    tries: 0,
                    ip: String::new(),
                    agent: String::new(),
                    challenge: Some((challenge.to_string(), now)),
                },
            );
        }
    }

    /// Take the challenge (once): a response can only answer it one time.
    pub fn take_challenge(&self, token: &str, now: i64) -> Option<String> {
        let mut m = self.m.lock().ok()?;
        let p = m.get_mut(token)?;
        let (c, at) = p.challenge.take()?;
        (now - at <= CHALLENGE_TTL_SECS).then_some(c)
    }

    pub fn remove(&self, token: &str) {
        if let Ok(mut m) = self.m.lock() {
            m.remove(token);
        }
    }
}

/// The limiter key for an address: IPv6 clients are grouped by their /64 (one
/// subscriber usually controls a whole /64, so per-address keys would be free to
/// rotate).
#[must_use]
pub fn limiter_key(kind: &str, ip: &str) -> String {
    let addr = match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(a)) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        _ => ip.to_string(),
    };
    format!("{kind}:{addr}")
}

// ---------------------------------------------------------------------------
// Guessing limiter
// ---------------------------------------------------------------------------

/// Wrong attempts allowed per key before it is locked out.
const FREE_FAILS: u32 = 5;
/// First lock-out; it doubles with every further failure, up to the cap.
const LOCK_BASE_SECS: i64 = 30;
const LOCK_MAX_SECS: i64 = 15 * 60;
/// Failures are forgotten after this long without one.
const FORGET_SECS: i64 = 3600;
/// Across all keys: this many failures in `GLOBAL_WINDOW` pauses every login.
const GLOBAL_FAILS: u32 = 40;
const GLOBAL_WINDOW_SECS: i64 = 10 * 60;
const GLOBAL_LOCK_SECS: i64 = 5 * 60;
const MAX_KEYS: usize = 5_000;

#[derive(Default)]
struct LimiterInner {
    keys: HashMap<String, (u32, i64, i64)>, // fails, last_fail, locked_until
    global: Vec<i64>,
    global_locked_until: i64,
}

#[derive(Default)]
pub struct Limiter {
    inner: Mutex<LimiterInner>,
}

impl Limiter {
    /// May this key try now? `Err(seconds)` when it must wait. Checked before the
    /// password is even hashed, so a flood costs the attacker, not the hub.
    ///
    /// # Errors
    /// The seconds left until the lock lifts.
    pub fn check(&self, key: &str, now: i64) -> Result<(), i64> {
        let Ok(i) = self.inner.lock() else {
            return Ok(());
        };
        if i.global_locked_until > now {
            return Err(i.global_locked_until - now);
        }
        match i.keys.get(key) {
            Some(&(_, _, locked)) if locked > now => Err(locked - now),
            _ => Ok(()),
        }
    }

    /// Count one attempt against this key (and lock it when it has had too many).
    fn count_key(i: &mut LimiterInner, key: &str, now: i64) {
        if i.keys.len() >= MAX_KEYS {
            i.keys
                .retain(|_, &mut (_, last, _)| now - last < FORGET_SECS);
        }
        let e = i.keys.entry(key.to_string()).or_insert((0, now, 0));
        if now - e.1 > FORGET_SECS {
            *e = (0, now, 0);
        }
        e.0 += 1;
        e.1 = now;
        if e.0 >= FREE_FAILS {
            let doublings = (e.0 - FREE_FAILS).min(10);
            e.2 = now + (LOCK_BASE_SECS << doublings).min(LOCK_MAX_SECS);
        }
    }

    /// One wrong guess, for the all-keys flood guard.
    fn count_global(i: &mut LimiterInner, now: i64) {
        i.global.retain(|t| now - t <= GLOBAL_WINDOW_SECS);
        i.global.push(now);
        if i.global.len() as u32 >= GLOBAL_FAILS {
            i.global_locked_until = now + GLOBAL_LOCK_SECS;
            i.global.clear();
        }
    }

    /// Start a guess: refuse if the key is locked, otherwise count it *now*, before
    /// the slow hash, so a burst of parallel guesses cannot all pass the check
    /// before any is counted. A right answer clears the key with `success`.
    /// The all-keys pause applies to `ip:` keys only (the password step, which
    /// anyone can reach); steps behind a right password are bounded per key, so
    /// a flood of bad passwords cannot also lock the admin out of finishing a
    /// login that is already half done.
    ///
    /// # Errors
    /// The seconds left until the lock lifts.
    pub fn begin(&self, key: &str, now: i64) -> Result<(), i64> {
        let Ok(mut i) = self.inner.lock() else {
            return Err(LOCK_BASE_SECS);
        };
        if key.starts_with("ip:") && i.global_locked_until > now {
            return Err(i.global_locked_until - now);
        }
        if let Some(&(_, _, locked)) = i.keys.get(key)
            && locked > now
        {
            return Err(locked - now);
        }
        Self::count_key(&mut i, key, now);
        Ok(())
    }

    /// A guess that turned out wrong (it was already counted by `begin`).
    pub fn wrong(&self, now: i64) {
        if let Ok(mut i) = self.inner.lock() {
            Self::count_global(&mut i, now);
        }
    }

    /// Record a failed attempt (counted here, not by `begin`).
    pub fn fail(&self, key: &str, now: i64) {
        let Ok(mut i) = self.inner.lock() else {
            return;
        };
        Self::count_key(&mut i, key, now);
        Self::count_global(&mut i, now);
    }

    /// A successful sign-in clears that key's failures.
    pub fn success(&self, key: &str) {
        if let Ok(mut i) = self.inner.lock() {
            i.keys.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_hash_is_stable_and_salted() {
        let a = hash_password("s1", "pw");
        assert_eq!(a, hash_password("s1", "pw"));
        assert_ne!(a, hash_password("s2", "pw"));
        assert!(ct_eq(&a, &hash_password("s1", "pw")));
        assert!(!ct_eq(&a, &hash_password("s2", "pw")));
    }

    #[test]
    fn argon2_hashes_verify_and_are_salted() {
        let h = hash_password_argon2("correct horse battery staple");
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password_argon2(&h, "correct horse battery staple"));
        assert!(!verify_password_argon2(&h, "correct horse battery stapl"));
        assert_ne!(h, hash_password_argon2("correct horse battery staple"));
        // A malformed or legacy value never matches.
        assert!(!verify_password_argon2("", "x"));
        assert!(!verify_password_argon2("deadbeef", "x"));
    }

    #[test]
    fn password_rules_ask_for_length_not_symbols() {
        assert!(password_problem("short").is_some());
        assert!(password_problem("aaaaaaaaaaaa").is_some());
        assert!(password_problem(&"x".repeat(201)).is_some());
        assert!(password_problem("mot cau mat khau dai").is_none());
    }

    #[test]
    fn a_session_ends_when_idle_or_old_and_activity_extends_it() {
        let s = Sessions::default();
        s.insert("t1".into(), "1.2.3.4", "UA", "password", 1000);
        assert!(s.valid("t1", 1000 + 3600));
        // Activity at +1h keeps it past the 8h idle limit counted from sign-in.
        assert!(s.valid("t1", 1000 + 3600 + SESSION_IDLE_SECS - 1));
        // Idle too long.
        assert!(!s.valid(
            "t1",
            1000 + 3600 + SESSION_IDLE_SECS - 1 + SESSION_IDLE_SECS + 1
        ));
        // Absolute limit even with constant activity.
        s.insert("t2".into(), "1.2.3.4", "UA", "password", 0);
        let mut t = 0;
        while t < SESSION_ABS_SECS {
            t += 3600;
            assert!(s.valid("t2", t) || t > SESSION_ABS_SECS);
        }
        assert!(!s.valid("t2", SESSION_ABS_SECS + 1));
        assert!(!s.valid("nope", 5));
    }

    #[test]
    fn sessions_can_be_listed_ended_by_id_and_bulk_ended() {
        let s = Sessions::default();
        for (t, at) in [("a", 10), ("b", 20), ("c", 30)] {
            s.insert(t.into(), "9.9.9.9", "UA\u{1b}[2J", "password+totp", at);
        }
        let l = s.list(40);
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].created, 30); // newest first
        assert!(!l[0].agent.contains('\u{1b}'));
        let id_b = s.id_of("b").unwrap();
        assert!(s.remove_by_id(&id_b));
        assert!(!s.valid("b", 41));
        assert_eq!(s.remove_all_except("c"), 1);
        assert!(s.valid("c", 42) && !s.valid("a", 42));
        assert!(!s.remove_by_id("nonexistent"));
    }

    #[test]
    fn the_session_table_is_bounded() {
        let s = Sessions::default();
        for i in 0..(MAX_SESSIONS + 20) {
            s.insert(format!("t{i}"), "1.1.1.1", "UA", "password", i as i64);
        }
        assert!(s.list(1000).len() <= MAX_SESSIONS);
        // The newest survived.
        assert!(s.valid(&format!("t{}", MAX_SESSIONS + 19), 1000));
    }

    #[test]
    fn a_pending_login_allows_a_few_tries_and_a_short_time() {
        let p = Pending::default();
        let t = p.create("1.2.3.4", "UA", 100);
        assert!(p.get(&t, 150).is_some());
        for left in (0..PENDING_MAX_TRIES).rev() {
            assert_eq!(p.fail(&t), left);
        }
        assert!(p.get(&t, 150).is_none(), "gone after too many tries");
        let t2 = p.create("1.2.3.4", "UA", 100);
        assert!(p.get(&t2, 100 + PENDING_TTL_SECS + 1).is_none(), "expired");
        assert!(p.get("unknown", 100).is_none());
    }

    #[test]
    fn a_passkey_challenge_answers_once_and_expires() {
        let p = Pending::default();
        let t = p.create("1.2.3.4", "UA", 0);
        p.set_challenge(&t, "abc", 10);
        assert_eq!(p.take_challenge(&t, 20).as_deref(), Some("abc"));
        assert_eq!(p.take_challenge(&t, 21), None, "single use");
        p.set_challenge(&t, "def", 30);
        assert_eq!(
            p.take_challenge(&t, 30 + CHALLENGE_TTL_SECS + 1),
            None,
            "expired"
        );
    }

    #[test]
    fn a_burst_of_guesses_is_counted_before_any_is_answered() {
        let l = Limiter::default();
        // Ten requests arrive together: none has been judged yet, but each was
        // counted on the way in, so the sixth onwards is turned away.
        let passed = (0..10)
            .filter(|_| l.begin("ip:1.1.1.1", 100).is_ok())
            .count();
        assert_eq!(passed, FREE_FAILS as usize);
        // A right answer clears the key.
        l.success("ip:1.1.1.1");
        assert!(l.begin("ip:1.1.1.1", 101).is_ok());
    }

    #[test]
    fn the_all_keys_pause_stops_the_password_step_but_not_a_half_done_login() {
        let l = Limiter::default();
        for _ in 0..GLOBAL_FAILS {
            l.wrong(1000);
        }
        assert!(l.begin("ip:2.2.2.2", 1001).is_err(), "password step paused");
        assert!(
            l.begin("2fa:2.2.2.2", 1001).is_ok(),
            "second step still reachable"
        );
        assert!(l.begin("pw:2.2.2.2", 1001).is_ok());
    }

    #[test]
    fn ipv6_clients_share_a_key_per_64() {
        assert_eq!(
            limiter_key("ip", "2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            limiter_key("ip", "2001:db8:1:2:1::9")
        );
        assert_ne!(
            limiter_key("ip", "2001:db8:1:2::1"),
            limiter_key("ip", "2001:db8:1:3::1")
        );
        assert_eq!(limiter_key("2fa", "203.0.113.9"), "2fa:203.0.113.9");
    }

    #[test]
    fn a_flood_of_logins_evicts_the_oldest_not_everyone() {
        let p = Pending::default();
        let first = p.create("1.1.1.1", "UA", 1);
        for i in 0..Pending::MAX + 20 {
            p.create("2.2.2.2", "UA", 2 + i as i64);
        }
        assert!(p.get(&first, 3).is_none(), "the oldest went first");
        let last = p.create("3.3.3.3", "UA", 5000);
        assert!(p.get(&last, 5000).is_some());
        // Recent ones are still there.
        let recent = p.create("4.4.4.4", "UA", 5001);
        assert!(p.get(&recent, 5001).is_some() && p.get(&last, 5001).is_some());
    }

    #[test]
    fn a_challenge_issued_under_a_key_is_taken_once_and_is_not_a_login() {
        let p = Pending::default();
        p.issue("reg:tok", "chal", 10);
        // Not a half-finished login: nothing to sign in with.
        assert_eq!(p.take_challenge("reg:tok", 12).as_deref(), Some("chal"));
        assert_eq!(p.take_challenge("reg:tok", 13), None, "single use");
        p.issue("reg:tok", "again", 20);
        assert_eq!(p.take_challenge("reg:other", 21), None, "bound to its key");
        assert_eq!(
            p.take_challenge("reg:tok", 20 + CHALLENGE_TTL_SECS + 1),
            None
        );
    }

    #[test]
    fn guessing_is_slowed_down_per_key_and_forgiven_on_success() {
        let l = Limiter::default();
        for i in 0..FREE_FAILS {
            assert!(l.check("ip:1", 100 + i64::from(i)).is_ok());
            l.fail("ip:1", 100 + i64::from(i));
        }
        let wait = l.check("ip:1", 105).unwrap_err();
        assert!(wait > 0 && wait <= LOCK_BASE_SECS);
        // Another address is unaffected.
        assert!(l.check("ip:2", 105).is_ok());
        // It lifts, and further failures lock for longer (doubling, capped).
        assert!(l.check("ip:1", 100 + LOCK_BASE_SECS + 10).is_ok());
        for i in 0..20 {
            l.fail("ip:1", 200 + i);
        }
        assert!(l.check("ip:1", 220).unwrap_err() <= LOCK_MAX_SECS);
        l.success("ip:1");
        assert!(l.check("ip:1", 221).is_ok());
    }

    #[test]
    fn a_flood_from_many_addresses_pauses_everyone_briefly() {
        let l = Limiter::default();
        for i in 0..GLOBAL_FAILS {
            l.fail(&format!("ip:{i}"), 1000);
        }
        let wait = l.check("ip:brand-new", 1001).unwrap_err();
        assert!(wait > 0 && wait <= GLOBAL_LOCK_SECS);
        assert!(l.check("ip:brand-new", 1000 + GLOBAL_LOCK_SECS + 1).is_ok());
    }

    #[test]
    fn client_addresses_must_be_addresses() {
        let mut h = HeaderMap::new();
        // A client-supplied entry in front of the proxy's own is ignored.
        h.insert(
            "x-forwarded-for",
            "198.51.100.7, 203.0.113.9".parse().unwrap(),
        );
        assert_eq!(client_ip(&h), "203.0.113.9");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "<script>".parse().unwrap());
        assert_eq!(client_ip(&h), "?");
        assert_eq!(client_ip(&HeaderMap::new()), "?");
    }

    #[test]
    fn cookies_are_strict_and_secure_over_https() {
        let c = cookie("s", "v", 60, true);
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Secure"));
        assert!(!cookie("s", "v", 60, false).contains("Secure"));
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            "a=1; snhub_session=tok; snhub_2fa=p".parse().unwrap(),
        );
        assert_eq!(session_from_headers(&h).as_deref(), Some("tok"));
        assert_eq!(pending_from_headers(&h).as_deref(), Some("p"));
    }
}
