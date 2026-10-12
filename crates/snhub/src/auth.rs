//! Admin authentication: password (Argon2id), an optional second factor (TOTP or
//! a passkey, see `totp` and `webauthn`), server-side sessions that expire, and a
//! limiter that slows down guessing.
//!
//! Sessions, half-finished logins and the limiter live in memory: a restart signs
//! everyone out, which is the right failure. Nothing here is persisted except what
//! the caller stores (the password hash, the second factors, and the time of a
//! sign-out of every session ordered from the command line).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const COOKIE: &str = "snhub_session";
/// Cookie that carries a login whose password was right but whose second factor
/// is still to come.
pub const PENDING_COOKIE: &str = "snhub_2fa";
/// Cookie that marks a browser which has signed in before (see [`device_cookie`]).
pub const DEVICE_COOKIE: &str = "snhub_device";
/// How long a browser stays "known" after its last sign-in.
pub const DEVICE_TTL_SECS: i64 = 30 * 86_400;

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

fn device_mac(secret: &[u8], issued: i64) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(format!("snhub-device-v1|{issued}").as_bytes());
    mac
}

/// The value of the "known device" cookie a browser gets when it signs in:
/// the time, signed with a hub secret. It only lets that browser past the
/// all-keys pause of the password step (an outsider's flood of wrong passwords
/// must not lock the admin out); every per-address limit still applies.
#[must_use]
pub fn device_cookie(secret: &[u8], issued: i64) -> String {
    let tag = device_mac(secret, issued).finalize().into_bytes();
    format!("{issued}.{}", hex::encode(tag))
}

/// Is this a known-device cookie this hub signed, younger than
/// [`DEVICE_TTL_SECS`] and issued after `not_before` (the last sign-out of every
/// session from the command line)?
#[must_use]
pub fn device_cookie_ok(secret: &[u8], value: &str, now: i64, not_before: i64) -> bool {
    let Some((issued, tag)) = value.split_once('.') else {
        return false;
    };
    let (Ok(issued), Ok(tag)) = (issued.parse::<i64>(), hex::decode(tag)) else {
        return false;
    };
    issued > not_before
        && issued <= now.saturating_add(60)
        && now.saturating_sub(issued) <= DEVICE_TTL_SECS
        && device_mac(secret, issued).verify_slice(&tag).is_ok()
}

/// The known-device cookie's value.
#[must_use]
pub fn device_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, DEVICE_COOKIE)
}

// ---------------------------------------------------------------------------
// Password hashing queue
// ---------------------------------------------------------------------------

/// Hashes allowed to wait for a free slot; past this a request is turned away
/// at once, so a burst of guesses cannot queue the admin's own sign-in behind
/// thousands of them.
pub const MAX_HASH_WAITERS: usize = 16;

/// How many password checks are waiting for a hashing slot.
#[derive(Default)]
pub struct HashQueue {
    waiting: AtomicUsize,
}

/// A place in the [`HashQueue`], given back when dropped (once the hash has a
/// slot, or the request is gone).
pub struct HashTicket<'a>(&'a HashQueue);

impl HashQueue {
    #[must_use]
    pub const fn new() -> Self {
        HashQueue {
            waiting: AtomicUsize::new(0),
        }
    }

    /// A place in the queue, unless it is already long.
    pub fn try_join(&self) -> Option<HashTicket<'_>> {
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= MAX_HASH_WAITERS {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(HashTicket(self))
    }

    /// A place in the queue however long it is: for a known device or a
    /// signed-in session, whose attempts the limiter already bounds.
    pub fn join(&self) -> HashTicket<'_> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        HashTicket(self)
    }
}

impl Drop for HashTicket<'_> {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::SeqCst);
    }
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
    /// Every session opened at or before this time is over: the password or the
    /// second factors were reset from the command line, which writes the time to
    /// the database (see `web_auth::session_valid`).
    revoked_at: AtomicI64,
    /// When `revoked_at` was last read from the database.
    revoked_read: AtomicI64,
}

/// How often the sign-out time written by the command line is read again.
pub const REVOKED_REFRESH_SECS: i64 = 5;

fn expired(s: &SessionInfo, now: i64) -> bool {
    now - s.created > SESSION_ABS_SECS || now - s.last_seen > SESSION_IDLE_SECS
}

/// Opened at or before a sign-out of every session (0: there never was one).
fn revoked(s: &SessionInfo, revoked_at: i64) -> bool {
    revoked_at > 0 && s.created <= revoked_at
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
        let revoked_at = self.revoked_at();
        let Ok(mut m) = self.live.lock() else {
            return false;
        };
        match m.get_mut(token) {
            Some(s) if !expired(s, now) && !revoked(s, revoked_at) => {
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

    /// The time before which (inclusive) every session is over.
    pub fn revoked_at(&self) -> i64 {
        self.revoked_at.load(Ordering::SeqCst)
    }

    /// End every session opened at or before `at`. Returns how many were ended.
    pub fn revoke_through(&self, at: i64) -> usize {
        self.revoked_at.fetch_max(at, Ordering::SeqCst);
        let Ok(mut m) = self.live.lock() else {
            return 0;
        };
        let before = m.len();
        m.retain(|_, s| !revoked(s, at));
        before - m.len()
    }

    /// Time to read the command line's sign-out time from the database again?
    /// `true` for one caller at most every [`REVOKED_REFRESH_SECS`].
    pub fn revocation_due(&self, now: i64) -> bool {
        let last = self.revoked_read.load(Ordering::SeqCst);
        if (0..REVOKED_REFRESH_SECS).contains(&(now - last)) {
            return false;
        }
        self.revoked_read
            .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Read the sign-out time again on the next request (tests that cannot
    /// wait [`REVOKED_REFRESH_SECS`]).
    #[cfg(test)]
    pub fn recheck_revocation(&self) {
        self.revoked_read.store(0, Ordering::SeqCst);
    }

    pub fn remove(&self, token: &str) {
        if let Ok(mut m) = self.live.lock() {
            m.remove(token);
        }
    }

    /// Every live session, newest first.
    pub fn list(&self, now: i64) -> Vec<SessionInfo> {
        let revoked_at = self.revoked_at();
        let Ok(m) = self.live.lock() else {
            return Vec::new();
        };
        let mut v: Vec<SessionInfo> = m
            .values()
            .filter(|s| !expired(s, now) && !revoked(s, revoked_at))
            .cloned()
            .collect();
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

    /// Drop everything started at or before `at` (every half-finished login
    /// and held challenge, for `i64::MAX`). Returns how many were dropped.
    pub fn drop_through(&self, at: i64) -> usize {
        let Ok(mut m) = self.m.lock() else {
            return 0;
        };
        let before = m.len();
        m.retain(|_, p| p.created > at);
        before - m.len()
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
/// Across all keys, failures *behind* a right password (a wrong second factor,
/// a wrong current password on a signed-in page): this many in
/// `FACTOR_WINDOW_SECS` pause those steps for everyone. Only someone who has the
/// password or a session can cause them, so this cannot lock the admin out on
/// an outsider's say-so; per-address keys alone would let such a person guess
/// codes from as many addresses as they hold.
const FACTOR_FAILS: usize = 10;
const FACTOR_WINDOW_SECS: i64 = 3600;
/// The pause, doubled at each further trip (up to `FACTOR_MAX_DOUBLINGS`) until
/// a day passes without one.
const FACTOR_LOCK_SECS: i64 = 3600;
const FACTOR_MAX_DOUBLINGS: u32 = 5;
const FACTOR_FORGET_SECS: i64 = 24 * 3600;
/// Password-correct sign-ins that may start waiting for a second factor per
/// hour, across all addresses.
const PENDING_PER_HOUR: usize = 20;

#[derive(Default)]
struct LimiterInner {
    keys: HashMap<String, (u32, i64, i64)>, // fails, last_fail, locked_until
    global: Vec<i64>,
    global_locked_until: i64,
    factor: Vec<i64>,
    factor_locked_until: i64,
    factor_trips: u32,
    factor_last_trip: i64,
    pending_starts: Vec<i64>,
}

/// Keys of the steps behind a right password: the second factor at sign-in and
/// the current password asked again on a signed-in page.
fn behind_password(key: &str) -> bool {
    key.starts_with("2fa:") || key.starts_with("pw:")
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
    /// anyone can reach); steps behind a right password (`2fa:`, `pw:`) have
    /// their own all-keys pause (see `wrong_factor`), so a flood of bad
    /// passwords cannot also lock the admin out of finishing a login that is
    /// already half done.
    ///
    /// # Errors
    /// The seconds left until the lock lifts.
    pub fn begin(&self, key: &str, now: i64) -> Result<(), i64> {
        self.start(key, now, false)
    }

    /// `begin` for a browser with a valid known-device cookie: it skips the
    /// all-keys pause of the password step, so an outsider's flood cannot keep
    /// the admin out. Its own per-address limit still applies.
    ///
    /// # Errors
    /// The seconds left until the lock lifts.
    pub fn begin_known_device(&self, key: &str, now: i64) -> Result<(), i64> {
        self.start(key, now, true)
    }

    fn start(&self, key: &str, now: i64, known_device: bool) -> Result<(), i64> {
        let Ok(mut i) = self.inner.lock() else {
            return Err(LOCK_BASE_SECS);
        };
        if key.starts_with("ip:") && !known_device && i.global_locked_until > now {
            return Err(i.global_locked_until - now);
        }
        if behind_password(key) && i.factor_locked_until > now {
            return Err(i.factor_locked_until - now);
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

    /// A wrong answer behind a right password (a second factor, or the current
    /// password asked again), already counted per key by `begin`. Returns the
    /// pause in seconds when this one tripped the all-keys lock; the caller then
    /// drops every half-finished login.
    pub fn wrong_factor(&self, now: i64) -> Option<i64> {
        let Ok(mut i) = self.inner.lock() else {
            return None;
        };
        i.factor.retain(|t| now - t <= FACTOR_WINDOW_SECS);
        i.factor.push(now);
        if i.factor.len() < FACTOR_FAILS {
            return None;
        }
        if now - i.factor_last_trip > FACTOR_FORGET_SECS {
            i.factor_trips = 0;
        }
        let secs = FACTOR_LOCK_SECS << i.factor_trips.min(FACTOR_MAX_DOUBLINGS);
        i.factor_trips = i.factor_trips.saturating_add(1);
        i.factor_last_trip = now;
        i.factor_locked_until = now + secs;
        i.factor.clear();
        Some(secs)
    }

    /// Seconds left of the all-keys pause behind the password, if it is on.
    pub fn factor_paused(&self, now: i64) -> Option<i64> {
        let i = self.inner.lock().ok()?;
        (i.factor_locked_until > now).then(|| i.factor_locked_until - now)
    }

    /// A new admin password was set from the command line: whatever the guesser
    /// knew is worthless, so lift the pause behind the password, its counts and
    /// the per-address locks of those steps. The trip count stays, so guessing
    /// again with the new password pauses for longer. Returns whether a pause
    /// was on.
    pub fn clear_factor_pause(&self, now: i64) -> bool {
        let Ok(mut i) = self.inner.lock() else {
            return false;
        };
        let was = i.factor_locked_until > now;
        i.factor.clear();
        i.factor_locked_until = 0;
        i.pending_starts.clear();
        i.keys.retain(|k, _| !behind_password(k));
        was
    }

    /// May a password-correct sign-in start waiting for its second factor? Not
    /// while that step is paused, and not more than `PENDING_PER_HOUR` an hour:
    /// someone who has the password cannot stockpile half-finished logins.
    ///
    /// # Errors
    /// The seconds to wait.
    pub fn begin_pending(&self, now: i64) -> Result<(), i64> {
        let Ok(mut i) = self.inner.lock() else {
            return Err(LOCK_BASE_SECS);
        };
        if i.factor_locked_until > now {
            return Err(i.factor_locked_until - now);
        }
        i.pending_starts.retain(|t| now - t < 3600);
        if i.pending_starts.len() >= PENDING_PER_HOUR {
            let oldest = i.pending_starts.iter().min().copied().unwrap_or(now);
            return Err((oldest + 3600 - now).max(1));
        }
        i.pending_starts.push(now);
        Ok(())
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
    fn wrong_second_factors_from_many_addresses_pause_that_step_for_everyone() {
        let l = Limiter::default();
        let t = 10_000;
        // One guess from each of many addresses: no per-address key ever locks.
        for n in 0..FACTOR_FAILS - 1 {
            let key = format!("2fa:10.0.0.{n}");
            assert!(l.begin(&key, t).is_ok());
            assert_eq!(l.wrong_factor(t), None);
        }
        assert!(l.begin("2fa:10.0.1.1", t).is_ok());
        let secs = l.wrong_factor(t).expect("tripped");
        assert_eq!(secs, FACTOR_LOCK_SECS);
        // Every second factor and password re-check is refused, from anywhere,
        // and no new half-finished login can start.
        assert!(l.begin("2fa:192.0.2.1", t + 1).is_err());
        assert!(l.begin("pw:192.0.2.1", t + 1).is_err());
        assert!(l.begin_pending(t + 1).is_err());
        assert_eq!(l.factor_paused(t + 1), Some(FACTOR_LOCK_SECS - 1));
        // The password step is not part of it.
        assert!(l.begin("ip:192.0.2.1", t + 1).is_ok());
        // After the pause, a second trip pauses twice as long.
        let t2 = t + FACTOR_LOCK_SECS + 1;
        assert!(l.begin("2fa:192.0.2.1", t2).is_ok());
        for _ in 0..FACTOR_FAILS - 1 {
            assert_eq!(l.wrong_factor(t2), None);
        }
        assert_eq!(l.wrong_factor(t2), Some(2 * FACTOR_LOCK_SECS));
        // A day without a trip forgets the doubling.
        let t3 = t2 + 2 * FACTOR_LOCK_SECS + FACTOR_FORGET_SECS + 1;
        for _ in 0..FACTOR_FAILS - 1 {
            assert_eq!(l.wrong_factor(t3), None);
        }
        assert_eq!(l.wrong_factor(t3), Some(FACTOR_LOCK_SECS));
    }

    #[test]
    fn a_new_password_lifts_the_pause_behind_it_but_a_new_trip_still_doubles() {
        let l = Limiter::default();
        let t = 10_000;
        for _ in 0..PENDING_PER_HOUR {
            assert!(l.begin_pending(t).is_ok());
        }
        for n in 0..FREE_FAILS {
            assert!(l.begin("2fa:198.51.100.1", t + i64::from(n)).is_ok());
        }
        assert!(l.begin("ip:203.0.113.1", t).is_ok());
        for _ in 0..FACTOR_FAILS {
            l.wrong_factor(t);
        }
        assert!(l.factor_paused(t + 1).is_some());
        assert!(l.clear_factor_pause(t + 1), "it was on");
        assert_eq!(l.factor_paused(t + 1), None);
        assert!(
            l.begin_pending(t + 1).is_ok(),
            "the hourly count starts over"
        );
        assert!(
            l.begin("2fa:198.51.100.1", t + 1).is_ok(),
            "its own lock too"
        );
        assert!(l.begin("pw:198.51.100.1", t + 1).is_ok());
        assert!(!l.clear_factor_pause(t + 1), "nothing left to lift");
        // The password step's own counts are not touched.
        assert!(l.inner.lock().unwrap().keys.contains_key("ip:203.0.113.1"));
        // Guessing on: the next trip pauses twice as long as the first.
        for _ in 0..FACTOR_FAILS - 1 {
            assert_eq!(l.wrong_factor(t + 2), None);
        }
        assert_eq!(l.wrong_factor(t + 2), Some(2 * FACTOR_LOCK_SECS));
    }

    #[test]
    fn wrong_second_factors_spread_over_hours_do_not_add_up() {
        let l = Limiter::default();
        for n in 0..(FACTOR_FAILS as i64 * 3) {
            assert_eq!(l.wrong_factor(1_000 + n * (FACTOR_WINDOW_SECS / 5)), None);
        }
        assert_eq!(l.factor_paused(1_000 + FACTOR_WINDOW_SECS * 10), None);
    }

    #[test]
    fn half_finished_logins_are_capped_per_hour() {
        let l = Limiter::default();
        for n in 0..PENDING_PER_HOUR as i64 {
            assert!(l.begin_pending(100 + n).is_ok());
        }
        let wait = l.begin_pending(200).unwrap_err();
        assert!(wait > 0 && wait <= 3600, "{wait}");
        assert!(l.begin_pending(100 + 3600).is_ok(), "the oldest aged out");
    }

    #[test]
    fn a_known_device_is_not_held_by_the_all_keys_pause_but_by_its_own_limit() {
        let l = Limiter::default();
        for _ in 0..GLOBAL_FAILS {
            l.wrong(1000);
        }
        assert!(l.begin("ip:198.51.100.1", 1001).is_err());
        assert!(l.begin_known_device("ip:198.51.100.1", 1001).is_ok());
        for _ in 1..FREE_FAILS {
            assert!(l.begin_known_device("ip:198.51.100.1", 1001).is_ok());
        }
        assert!(
            l.begin_known_device("ip:198.51.100.1", 1001).is_err(),
            "per-address limit"
        );
    }

    #[test]
    fn the_known_device_cookie_is_signed_bound_to_this_hub_and_expires() {
        let secret = [7u8; 32];
        let v = device_cookie(&secret, 5_000);
        assert!(device_cookie_ok(&secret, &v, 5_000, 0));
        assert!(device_cookie_ok(&secret, &v, 5_000 + DEVICE_TTL_SECS, 0));
        assert!(!device_cookie_ok(&secret, &v, 5_001 + DEVICE_TTL_SECS, 0));
        // Another hub's secret, a changed time, junk.
        assert!(!device_cookie_ok(&[8u8; 32], &v, 5_000, 0));
        let forged = v.replacen("5000", "9000", 1);
        assert!(!device_cookie_ok(&secret, &forged, 9_000, 0));
        for junk in ["", "5000", "5000.", "x.y", "5000.zz"] {
            assert!(!device_cookie_ok(&secret, junk, 5_000, 0), "{junk}");
        }
        // Issued before a sign-out of every session: no longer known.
        assert!(!device_cookie_ok(&secret, &v, 6_000, 5_000));
        assert!(device_cookie_ok(&secret, &v, 6_000, 4_999));
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            format!("snhub_session=t; {DEVICE_COOKIE}={v}")
                .parse()
                .unwrap(),
        );
        assert_eq!(device_from_headers(&h), Some(v));
    }

    #[test]
    fn the_hash_queue_turns_away_a_burst_but_not_a_known_device() {
        let q = HashQueue::new();
        let held: Vec<HashTicket<'_>> = (0..MAX_HASH_WAITERS)
            .map(|_| q.try_join().expect("room"))
            .collect();
        assert!(q.try_join().is_none(), "full");
        let priority = q.join();
        assert!(q.try_join().is_none());
        drop(priority);
        drop(held);
        assert!(q.try_join().is_some(), "places are given back");
    }

    #[test]
    fn a_command_line_sign_out_ends_the_sessions_opened_before_it() {
        let s = Sessions::default();
        s.insert("old".into(), "1.1.1.1", "UA", "password", 100);
        s.insert("same".into(), "1.1.1.1", "UA", "password", 200);
        s.insert("new".into(), "1.1.1.1", "UA", "password", 201);
        assert_eq!(s.revoked_at(), 0);
        assert_eq!(s.revoke_through(200), 2);
        assert!(!s.valid("old", 300) && !s.valid("same", 300));
        assert!(s.valid("new", 300));
        assert_eq!(s.list(300).len(), 1);
        // It never moves back.
        s.revoke_through(50);
        assert_eq!(s.revoked_at(), 200);
        // A session opened later (a fresh sign-in) is fine.
        s.insert("later".into(), "1.1.1.1", "UA", "password", 400);
        assert!(s.valid("later", 401));
    }

    #[test]
    fn the_sign_out_time_is_read_again_only_every_few_seconds() {
        let s = Sessions::default();
        assert!(s.revocation_due(1_000));
        assert!(!s.revocation_due(1_000));
        assert!(!s.revocation_due(1_000 + REVOKED_REFRESH_SECS - 1));
        assert!(s.revocation_due(1_000 + REVOKED_REFRESH_SECS));
        // A clock that went back does not stop it.
        assert!(s.revocation_due(10));
    }

    #[test]
    fn half_finished_logins_can_be_dropped_all_at_once() {
        let p = Pending::default();
        let a = p.create("1.1.1.1", "UA", 100);
        let b = p.create("1.1.1.1", "UA", 200);
        assert_eq!(p.drop_through(150), 1);
        assert!(p.get(&a, 210).is_none() && p.get(&b, 210).is_some());
        assert_eq!(p.drop_through(i64::MAX), 1);
        assert!(p.get(&b, 210).is_none());
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
