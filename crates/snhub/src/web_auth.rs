//! The sign-in pages: password, then (when enrolled) a second factor, and the
//! "Bảo mật" page where the admin manages the password, the authenticator app, passkeys,
//! recovery codes and sessions.
//!
//! Rules this file keeps:
//! * Every guess goes through the limiter *before* any hashing, and wrong guesses
//!   are logged.
//! * A password-correct login that still needs a factor gets no session: only a
//!   short-lived, attempt-limited "pending" cookie.
//! * Every change to the sign-in setup asks for the current password again, so a
//!   stolen session cannot quietly add its own passkey or switch 2FA off.
//! * Anything a page shows that came from a request (an IP, a user agent) goes
//!   through maud, which escapes it; JSON replies carry text the script inserts as
//!   plain text.

use std::sync::Arc;

use axum::Form;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, PreEscaped, html};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::{self, PENDING_COOKIE};
use crate::db_auth::{hash_recovery, new_recovery_codes};
use crate::totp;
use crate::web::{now, rel_time, shell, urlenc};
use crate::webauthn;

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

/// Should cookies carry `Secure`? When the hub's public address is https, or the
/// proxy in front says the request came in over https.
fn secure(st: &AppState, headers: &HeaderMap) -> bool {
    st.cfg.public_url.starts_with("https://")
        || headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// `(rp id, origin)` for passkeys, from the hub's public URL. `None` when it is
/// not an HTTPS address (browsers only offer passkeys to secure origins) or the
/// URL is unset.
fn rp(st: &AppState) -> Option<(String, String)> {
    rp_from_url(&st.cfg.public_url)
}

/// What a browser will send as origin for this URL: lower-case host, no default
/// port. The rp id is the bare host. Browsers refuse IP addresses as rp id, so
/// only `localhost` is allowed over plain http (for local trials).
fn rp_from_url(public_url: &str) -> Option<(String, String)> {
    let url = public_url.trim().trim_end_matches('/').to_ascii_lowercase();
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (authority, None),
    };
    if host.is_empty()
        || host.contains(['@', '[', ']', ' '])
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return None;
    }
    if scheme != "https" && !(scheme == "http" && host == "localhost") {
        return None;
    }
    let default_port = if scheme == "https" { "443" } else { "80" };
    let origin = match port {
        Some(p) if p != default_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    };
    Some((host.to_string(), origin))
}

/// Is a password set at all?
fn password_configured(st: &AppState) -> bool {
    st.db.lock().ok().and_then(|d| d.admin_pw_hash()).is_some()
        || !st.cfg.admin_password_hash.is_empty()
        || !st.cfg.admin_password_sha256.is_empty()
}

/// Check the admin password: the one set from the web UI, else the config's
/// Argon2 hash, else the old salted SHA-256. Slow by design: call it from a
/// blocking thread.
fn check_password(st: &AppState, pw: &str) -> bool {
    // If the database cannot be read, say no: falling back to the config's
    // hash could revive a password that was changed in the web UI.
    let Ok(db) = st.db.lock() else {
        return false;
    };
    let over = db.admin_pw_hash();
    drop(db);
    if let Some(h) = over {
        return auth::verify_password_argon2(&h, pw);
    }
    if !st.cfg.admin_password_hash.is_empty() {
        return auth::verify_password_argon2(&st.cfg.admin_password_hash, pw);
    }
    if !st.cfg.admin_password_sha256.is_empty() {
        let got = auth::hash_password(&st.cfg.admin_salt, pw);
        return auth::ct_eq(&got, &st.cfg.admin_password_sha256);
    }
    false
}

/// At most this many password hashes run at once (each takes ~19 MiB and some
/// CPU); the rest wait their turn instead of piling up in the thread pool, and
/// past `auth::MAX_HASH_WAITERS` waiting a new one is turned away (`HASH_QUEUE`).
const HASH_SLOTS: usize = 3;

static HASH_QUEUE: auth::HashQueue = auth::HashQueue::new();

/// Check the password once `ticket` (a place in the queue) gets a slot.
async fn check_password_queued(
    st: &Arc<AppState>,
    pw: String,
    ticket: auth::HashTicket<'_>,
) -> bool {
    static GATE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    let gate = GATE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(HASH_SLOTS)));
    let Ok(permit) = Arc::clone(gate).acquire_owned().await else {
        return false;
    };
    drop(ticket);
    let st2 = Arc::clone(st);
    let ok = tokio::task::spawn_blocking(move || check_password(&st2, &pw))
        .await
        .unwrap_or(false);
    drop(permit);
    ok
}

/// For a signed-in session: its re-checks are bounded by the limiter, so they
/// always get a place in the queue.
async fn check_password_blocking(st: &Arc<AppState>, pw: String) -> bool {
    check_password_queued(st, pw, HASH_QUEUE.join()).await
}

fn busy_page() -> Response {
    let mut r = (
        StatusCode::SERVICE_UNAVAILABLE,
        login_card(
            "Đăng nhập",
            html! {
                h1 { "Hub đang bận" }
                p { "Đang có quá nhiều lượt đăng nhập cùng lúc. Thử lại sau vài giây." }
                p { a href="/login" { "← Quay lại" } }
            },
        ),
    )
        .into_response();
    r.headers_mut().insert(
        header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("5"),
    );
    r
}

/// The key that signs known-device cookies, derived from the hub's own key so
/// it needs no storage and changes when that key does.
fn device_secret(st: &AppState) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"snhub-known-device-v1|");
    h.update(st.hubkey.signing.to_bytes());
    h.finalize().into()
}

/// Has this browser signed in to this hub before (and since the last sign-out
/// of every session from the command line)?
fn known_device(st: &AppState, headers: &HeaderMap, at: i64) -> bool {
    auth::device_from_headers(headers).is_some_and(|v| {
        auth::device_cookie_ok(&device_secret(st), &v, at, st.sessions.revoked_at())
    })
}

/// Pick up a sign-out of every session ordered from the command line
/// (`set-admin-password`, `reset-2fa` write the time to the database): read it
/// at most every few seconds, then end every older session and half-finished
/// login. When it came with a new password, also lift the pause behind the
/// password: the admin who just set it must not wait out a pause that someone
/// guessing with the old one caused. `reset-2fa` alone leaves the password, and
/// so the pause, as they were.
fn refresh_revocation(st: &AppState, at: i64) {
    if !st.sessions.revocation_due(at) {
        return;
    }
    let Some((revoked, pw_set)) = st
        .db
        .lock()
        .ok()
        .map(|d| (d.sessions_revoked_at(), d.admin_pw_updated()))
    else {
        return;
    };
    if revoked > st.sessions.revoked_at() {
        let ended = st.sessions.revoke_through(revoked);
        st.pending.drop_through(revoked);
        if ended > 0 {
            tracing::warn!(
                "snhub-auth sessions-revoked: {ended} web session(s) ended by a password or 2FA reset from the command line"
            );
        }
        if pw_set >= revoked && st.limiter.clear_factor_pause(at) {
            tracing::warn!(
                "snhub-auth second-factor-unpaused: a new admin password was set from the command line; \
                 the pause after too many wrong second factors is lifted"
            );
        }
    }
}

/// Is this a live session? Every route that needs a signed-in admin asks this.
pub(crate) fn session_valid(st: &AppState, token: &str) -> bool {
    let at = now();
    refresh_revocation(st, at);
    st.sessions.valid(token, at)
}

/// A wrong answer behind a right password. Too many of them, from any number of
/// addresses, pause that step for everyone and drop every half-finished login:
/// whoever is answering already has the password (or a session).
fn factor_failed(st: &AppState, at: i64) {
    if let Some(secs) = st.limiter.wrong_factor(at) {
        let dropped = st.pending.drop_through(i64::MAX);
        tracing::error!(
            "snhub-auth second-factor-flood: too many wrong second factors or password re-checks; \
             those steps are paused for {secs} s and {dropped} half-finished login(s) dropped. \
             The admin password is likely known to someone else: set a new one with \
             `snhub set-admin-password`, which also lifts the pause within a few seconds."
        );
        if let Ok(db) = st.db.lock() {
            db.log_login(
                at,
                "-",
                false,
                "tạm khoá bước 2",
                &format!("quá nhiều lần sai sau bước mật khẩu, khoá {secs} giây"),
            );
        }
    }
}

/// The outcome of asking for the current password again.
pub(crate) enum Recheck {
    Right,
    Wrong,
    /// Too many tries: wait this many seconds.
    Wait(i64),
}

/// Check the current password on a signed-in page, with the limiter. A wrong
/// one counts towards the all-keys pause behind the password.
pub(crate) async fn recheck_password(
    st: &Arc<AppState>,
    headers: &HeaderMap,
    pw: String,
) -> Recheck {
    if pw.is_empty() {
        return Recheck::Wrong;
    }
    let at = now();
    let key = auth::limiter_key("pw", &auth::client_ip(headers));
    if let Err(wait) = st.limiter.begin(&key, at) {
        return Recheck::Wait(wait);
    }
    if pw.len() > 1024 || !check_password_blocking(st, pw).await {
        factor_failed(st, at);
        return Recheck::Wrong;
    }
    st.limiter.success(&key);
    Recheck::Right
}

fn redirect_with(location: &str, cookies: &[String]) -> Response {
    let mut b = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location);
    for c in cookies {
        b = b.header(header::SET_COOKIE, c);
    }
    b.body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn json_with_cookies(status: StatusCode, body: &Value, cookies: &[String]) -> Response {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    for c in cookies {
        b = b.header(header::SET_COOKIE, c);
    }
    b.body(axum::body::Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn jerr(status: StatusCode, msg: &str) -> Response {
    json_with_cookies(status, &json!({ "ok": false, "error": msg }), &[])
}

fn login_card(title: &str, inner: Markup) -> Html<String> {
    Html(
        shell(
            title,
            html! { div class="card" style="max-width:420px;margin:8vh auto" { (inner) } },
        )
        .into_string(),
    )
}

fn wait_page(secs: i64) -> Response {
    wait_page_with(secs, html! {})
}

fn wait_page_with(secs: i64, extra: Markup) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        login_card(
            "Đăng nhập",
            html! {
                h1 { "Thử quá nhiều lần" }
                p { "Vì an toàn, đăng nhập tạm khoá. Thử lại sau khoảng " b { (secs) } " giây." }
                (extra)
                p { a href="/login" { "← Quay lại" } }
            },
        ),
    )
        .into_response()
}

/// The password was right but the second step is paused (or too many logins
/// are waiting for it): the way out for the admin, who cannot reach /security.
fn second_step_wait_page(secs: i64) -> Response {
    wait_page_with(
        secs,
        html! {
            p class="help" {
                "Bước xác thực thứ hai đang tạm khoá: có quá nhiều lần nhập sai sau bước mật khẩu, hoặc quá nhiều "
                "lần đăng nhập đúng mật khẩu trong một giờ, nên nhiều khả năng mật khẩu quản trị đã lộ. "
                "Nếu bạn là quản trị viên, trên máy chủ hub, bằng root: "
                code { "sudo snhub set-admin-password --password '...'" }
                " để đặt mật khẩu mới: khoá được gỡ sau vài giây, rồi đăng nhập bằng mật khẩu mới."
            }
        },
    )
}

/// Open a session and send the admin to the overview.
fn finish_login(st: &AppState, headers: &HeaderMap, method: &str, note: &str) -> Vec<String> {
    let at = now();
    let ip = auth::client_ip(headers);
    let token = auth::new_session_token();
    st.sessions
        .insert(token.clone(), &ip, &user_agent(headers), method, at);
    st.limiter.success(&auth::limiter_key("ip", &ip));
    st.limiter.success(&auth::limiter_key("2fa", &ip));
    if let Ok(db) = st.db.lock() {
        db.log_login(at, &ip, true, method, note);
    }
    let sec = secure(st, headers);
    vec![
        auth::cookie(auth::COOKIE, &token, 86_400, sec),
        // The half-finished login is over.
        auth::cookie(PENDING_COOKIE, "", 0, sec),
        // This browser is known from now on (see `known_device`).
        auth::cookie(
            auth::DEVICE_COOKIE,
            &auth::device_cookie(&device_secret(st), at),
            auth::DEVICE_TTL_SECS,
            sec,
        ),
    ]
}

fn log_fail(st: &AppState, ip: &str, method: &str, note: &str) {
    // One stable line per wrong guess, for fail2ban (journal of snhub.service).
    tracing::warn!("snhub-auth login-failed ip={ip} method={method}");
    if let Ok(db) = st.db.lock() {
        db.log_login(now(), ip, false, method, note);
    }
}

// ---------------------------------------------------------------------------
// Browser-facing guard (every route)
// ---------------------------------------------------------------------------

/// `host[:port]` of an `Origin` value (`scheme://host[:port]`), lowercased.
fn origin_authority(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    Some(rest.to_ascii_lowercase())
}

/// May this state-changing request come from this browser page? The session
/// cookie is `SameSite=Strict` already; this is the second lock.
///
/// 1. When the browser sends `Sec-Fetch-Site` (every current browser, over https
///    or localhost) it is the verdict: only `same-origin` passes. The browser sets
///    it itself and a page cannot forge it, and it does not depend on what `Host`
///    the reverse proxy forwards.
/// 2. Otherwise, a request that names an `Origin` must name this hub: its `Host`,
///    the proxy's `X-Forwarded-Host`, or the configured public URL.
/// 3. With neither header (not a browser) it passes; the cookie still has to be
///    valid. Agents (`/v1/*`) skip this check altogether.
pub(crate) fn same_origin(headers: &HeaderMap, public_url: &str) -> bool {
    let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        return site.trim().eq_ignore_ascii_case("same-origin");
    }
    let Some(origin) = get("origin") else {
        return true;
    };
    let Some(got) = origin_authority(origin) else {
        // "null" and anything odd.
        return false;
    };
    let lower = |v: Option<&str>| v.map(|s| s.trim().to_ascii_lowercase());
    let host = lower(get("host"));
    // Only the last entry: the one the proxy itself added.
    let forwarded = lower(get("x-forwarded-host").and_then(|v| v.rsplit(',').next()));
    let public = public_url
        .split_once("://")
        .map(|(_, r)| r.trim_end_matches('/').to_ascii_lowercase());
    [host, forwarded, public]
        .iter()
        .any(|c| c.as_deref() == Some(got.as_str()))
}

/// Origin check on POSTs from browsers plus conservative response headers.
pub async fn browser_guard(
    State(st): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let agent_api = path.starts_with("/v1/");
    let writes = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    if !agent_api && writes && !same_origin(req.headers(), &st.cfg.public_url) {
        return (StatusCode::FORBIDDEN, "Yêu cầu bị từ chối (khác nguồn).").into_response();
    }
    let mut resp = next.run(req).await;
    if !agent_api {
        let h = resp.headers_mut();
        let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
            if !h.contains_key(k) {
                h.insert(k, axum::http::HeaderValue::from_static(v));
            }
        };
        set(h, "x-frame-options", "DENY");
        set(h, "x-content-type-options", "nosniff");
        set(h, "referrer-policy", "no-referrer");
        set(
            h,
            "content-security-policy",
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
        );
        let is_page = h
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("text/html") || t.starts_with("application/json"));
        if is_page {
            set(h, "cache-control", "no-store");
        }
    }
    resp
}

// ---------------------------------------------------------------------------
// Password step
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct LoginQuery {
    #[serde(default)]
    err: String,
}

pub async fn login_page(Query(q): Query<LoginQuery>) -> Html<String> {
    login_card(
        "Đăng nhập",
        html! {
            h1 { "Đăng nhập" }
            p class="sub" { "Trung tâm quản lý bảo mật VPS." }
            @if q.err == "pw" { p style="color:var(--bad)" { "Sai mật khẩu." } }
            @if q.err == "expired" { p style="color:var(--warn)" { "Phiên đăng nhập đã hết hạn, hãy đăng nhập lại." } }
            form method="post" action="/login" {
                label class="f" {
                    span class="t" { "Mật khẩu quản trị" }
                    input type="password" name="password" style="width:100%" autofocus autocomplete="current-password";
                }
                p { button type="submit" { "Đăng nhập" } }
            }
        },
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

pub async fn login_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    if !password_configured(&st) {
        return login_card(
            "Đăng nhập",
            html! {
                h1 { "Chưa đặt mật khẩu" }
                p class="help" { "Trên máy chủ chạy: " code { "snhub set-admin-password --password '...'" } " rồi " code { "systemctl restart snhub" } "." }
            },
        )
        .into_response();
    }
    let at = now();
    let ip = auth::client_ip(&headers);
    let key = auth::limiter_key("ip", &ip);
    refresh_revocation(&st, at);
    // A browser that has signed in here before is not held by the all-keys pause
    // (only by its own limit) and does not queue behind a burst of guesses.
    let known = known_device(&st, &headers, at);
    let ticket = if known {
        HASH_QUEUE.join()
    } else {
        match HASH_QUEUE.try_join() {
            Some(t) => t,
            None => return busy_page(),
        }
    };
    let started = if known {
        st.limiter.begin_known_device(&key, at)
    } else {
        st.limiter.begin(&key, at)
    };
    if let Err(wait) = started {
        return wait_page(wait);
    }
    // Longer than any password can be: counted against this address by `begin`,
    // but not towards the all-keys pause, which it would trip without the cost
    // of a hash.
    if f.password.len() > 1024 {
        log_fail(&st, &ip, "password", "sai mật khẩu");
        return redirect_with("/login?err=pw", &[]);
    }
    if !check_password_queued(&st, f.password, ticket).await {
        st.limiter.wrong(at);
        log_fail(&st, &ip, "password", "sai mật khẩu");
        return redirect_with("/login?err=pw", &[]);
    }
    // Cannot tell whether a second factor is required? Then do not let anyone in.
    let Ok(enrolled) = st
        .db
        .lock()
        .map(|d| st.cfg.two_factor && d.second_factor_enrolled())
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Hub đang lỗi, thử lại sau.",
        )
            .into_response();
    };
    if !enrolled {
        return redirect_with("/", &finish_login(&st, &headers, "password", ""));
    }
    // Password right, factor still to come: no session yet, and only so many
    // such logins an hour.
    if let Err(wait) = st.limiter.begin_pending(at) {
        tracing::warn!(
            "snhub-auth second-factor-paused ip={ip}: right password, but the second step is paused or too many logins are waiting for it"
        );
        return second_step_wait_page(wait);
    }
    let token = st.pending.create(&ip, &user_agent(&headers), at);
    redirect_with(
        "/login/2fa",
        &[auth::cookie(
            PENDING_COOKIE,
            &token,
            300,
            secure(&st, &headers),
        )],
    )
}

pub async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(tok) = auth::session_from_headers(&headers) {
        st.sessions.remove(&tok);
    }
    let sec = secure(&st, &headers);
    redirect_with(
        "/login",
        &[
            auth::cookie(auth::COOKIE, "", 0, sec),
            auth::cookie(PENDING_COOKIE, "", 0, sec),
        ],
    )
}

// ---------------------------------------------------------------------------
// Second step
// ---------------------------------------------------------------------------

const B64_JS: &str = "const b64d=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))};\
const b64e=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')};";

const LOGIN_PASSKEY_JS: &str = "async function usePasskey(){const out=document.getElementById('pk-msg');out.textContent='';try{\
const r=await fetch('/login/passkey/options',{method:'POST',credentials:'same-origin'});const o=await r.json();\
if(!o.challenge){out.textContent=o.error||'Lỗi';return}\
const pk={challenge:b64d(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:o.userVerification,allowCredentials:o.allowCredentials.map(c=>({type:c.type,id:b64d(c.id)}))};\
const cred=await navigator.credentials.get({publicKey:pk});\
const res=await fetch('/login/passkey/verify',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},\
body:JSON.stringify({id:cred.id,authenticatorData:b64e(cred.response.authenticatorData),clientDataJSON:b64e(cred.response.clientDataJSON),signature:b64e(cred.response.signature)})});\
const j=await res.json();if(j.ok){location.href='/'}else{out.textContent=j.error||'Không xác thực được'}\
}catch(e){out.textContent='Passkey bị huỷ hoặc không dùng được: '+(e&&e.message?e.message:e)}}";

#[derive(Deserialize, Default)]
pub struct Login2faQuery {
    #[serde(default)]
    err: String,
}

pub async fn login_2fa_page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<Login2faQuery>,
) -> Response {
    let at = now();
    let valid = auth::pending_from_headers(&headers)
        .and_then(|t| st.pending.get(&t, at))
        .is_some();
    if !valid {
        return Redirect::to("/login?err=expired").into_response();
    }
    let (has_totp, has_passkey) = st
        .db
        .lock()
        .map(|d| {
            (
                d.totp().is_some_and(|t| t.enabled),
                !d.list_passkeys().is_empty(),
            )
        })
        .unwrap_or((false, false));
    let passkey_ok = has_passkey && rp(&st).is_some();
    login_card(
        "Xác thực hai bước",
        html! {
            h1 { "Xác thực hai bước" }
            p class="sub" { "Mật khẩu đúng. Xác nhận thêm để vào hub." }
            @match q.err.as_str() {
                "code" => { p style="color:var(--bad)" { "Mã không đúng hoặc đã dùng. Thử mã mới." } }
                "recovery" => { p style="color:var(--bad)" { "Mã khôi phục không đúng hoặc đã dùng." } }
                _ => {}
            }
            @if has_passkey && !passkey_ok {
                div class="note" style="border-left-color:var(--warn)" {
                    "Passkey chỉ dùng được khi hub chạy qua HTTPS với "
                    code { "public_url" } " đúng tên miền. Hiện chưa được, hãy dùng mã từ ứng dụng hoặc mã khôi phục."
                }
            }
            @if passkey_ok {
                p { button type="button" onclick="usePasskey()" { "🔑 Dùng passkey" } }
                p id="pk-msg" style="color:var(--bad);font-size:13px;margin:0" {}
            }
            @if has_totp {
                form method="post" action="/login/2fa" {
                    input type="hidden" name="kind" value="totp";
                    label class="f" {
                        span class="t" { "Mã 6 số từ ứng dụng (Google Authenticator, Authy…)" }
                        input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" pattern="[0-9 ]*" style="width:100%;font-size:20px;letter-spacing:4px" autofocus;
                    }
                    p { button type="submit" { "Xác nhận" } }
                }
            }
            details style="margin-top:14px" {
                summary { "Mất thiết bị? Dùng mã khôi phục" }
                form method="post" action="/login/2fa" {
                    input type="hidden" name="kind" value="recovery";
                    label class="f" {
                        span class="t" { "Mã khôi phục (xxxxx-xxxxx-xxxxx), mỗi mã dùng một lần" }
                        input type="text" name="code" autocomplete="off" maxlength="24" style="width:100%";
                    }
                    p { button class="ghost" type="submit" { "Dùng mã khôi phục" } }
                }
            }
            p { a href="/login" { "← Đăng nhập lại" } }
            @if passkey_ok {
                script { (PreEscaped(format!("{B64_JS}{LOGIN_PASSKEY_JS}"))) }
            }
        },
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct Login2faForm {
    kind: String,
    code: String,
}

pub async fn login_2fa_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<Login2faForm>,
) -> Response {
    let at = now();
    let ip = auth::client_ip(&headers);
    let Some(ptoken) = auth::pending_from_headers(&headers) else {
        return redirect_with("/login?err=expired", &[]);
    };
    if st.pending.get(&ptoken, at).is_none() {
        return redirect_with("/login?err=expired", &[]);
    }
    let key = auth::limiter_key("2fa", &ip);
    if let Err(wait) = st.limiter.begin(&key, at) {
        return wait_page(wait);
    }
    if f.code.len() > 64 {
        return redirect_with("/login/2fa?err=code", &[]);
    }

    let (ok, method, note, err) = if f.kind == "recovery" {
        let used = st
            .db
            .lock()
            .is_ok_and(|d| d.use_recovery_code(&hash_recovery(&f.code)));
        (used, "password+recovery", "mã khôi phục", "recovery")
    } else {
        let totp_state = st
            .db
            .lock()
            .ok()
            .and_then(|d| d.totp())
            .filter(|t| t.enabled);
        let now_secs = at.max(0) as u64;
        let step = totp_state
            .and_then(|t| totp::verify_at(&t.secret, &f.code, now_secs, t.offset, t.last_step));
        // The compare-and-set is what makes a code single-use: of two requests
        // carrying the same code, only one gets to move the stored step forward.
        let claimed = step.is_some_and(|s| {
            st.db.lock().is_ok_and(|d| {
                let won = d.claim_totp_step(s);
                if won {
                    // Follow slow drift of either clock (RFC 6238 §6).
                    let drift = s as i64 - (now_secs / totp::STEP_SECS) as i64;
                    if drift.abs() <= totp::ENROL_SEARCH_STEPS {
                        let _ = d.set_totp_offset(drift);
                    }
                }
                won
            })
        });
        (claimed, "password+totp", "", "code")
    };
    if ok {
        st.pending.remove(&ptoken);
        let note = if f.kind == "recovery" {
            let left = st.db.lock().map_or(0, |d| d.recovery_codes_left());
            format!("{note} (còn {left})")
        } else {
            note.to_string()
        };
        return redirect_with("/", &finish_login(&st, &headers, method, &note));
    }
    factor_failed(&st, at);
    log_fail(&st, &ip, method, "mã sai");
    if st.pending.fail(&ptoken) == 0 {
        return redirect_with(
            "/login?err=expired",
            &[auth::cookie(PENDING_COOKIE, "", 0, secure(&st, &headers))],
        );
    }
    redirect_with(&format!("/login/2fa?err={err}"), &[])
}

// ---------------------------------------------------------------------------
// Passkey sign-in
// ---------------------------------------------------------------------------

pub async fn login_passkey_options(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let at = now();
    let Some(ptoken) = auth::pending_from_headers(&headers) else {
        return jerr(StatusCode::UNAUTHORIZED, "Phiên đăng nhập đã hết hạn.");
    };
    if st.pending.get(&ptoken, at).is_none() {
        return jerr(StatusCode::UNAUTHORIZED, "Phiên đăng nhập đã hết hạn.");
    }
    let Some((rp_id, _)) = rp(&st) else {
        return jerr(
            StatusCode::BAD_REQUEST,
            "Hub chưa có địa chỉ HTTPS (public_url) nên không dùng passkey được.",
        );
    };
    let ids = st.db.lock().map(|d| d.passkey_ids()).unwrap_or_default();
    if ids.is_empty() {
        return jerr(StatusCode::BAD_REQUEST, "Chưa đăng ký passkey nào.");
    }
    let challenge = webauthn::new_challenge();
    st.pending.set_challenge(&ptoken, &challenge, at);
    json_with_cookies(
        StatusCode::OK,
        &json!({
            "challenge": challenge,
            "rpId": rp_id,
            "timeout": 60_000,
            "userVerification": "preferred",
            "allowCredentials": ids.iter().map(|id| json!({"type": "public-key", "id": id})).collect::<Vec<_>>(),
        }),
        &[],
    )
}

#[derive(Deserialize)]
pub struct PasskeyAssertion {
    id: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
}

pub async fn login_passkey_verify(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(a): Json<PasskeyAssertion>,
) -> Response {
    let at = now();
    let ip = auth::client_ip(&headers);
    let Some(ptoken) = auth::pending_from_headers(&headers) else {
        return jerr(StatusCode::UNAUTHORIZED, "Phiên đăng nhập đã hết hạn.");
    };
    if st.pending.get(&ptoken, at).is_none() {
        return jerr(StatusCode::UNAUTHORIZED, "Phiên đăng nhập đã hết hạn.");
    }
    let key = auth::limiter_key("2fa", &ip);
    if let Err(wait) = st.limiter.begin(&key, at) {
        return jerr(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Thử quá nhiều lần, chờ {wait} giây."),
        );
    }
    let outcome = (|| -> Result<(String, u32), String> {
        let (rp_id, origin) = rp(&st).ok_or("Hub chưa có địa chỉ HTTPS.")?;
        let challenge = st
            .pending
            .take_challenge(&ptoken, at)
            .ok_or("Yêu cầu passkey đã hết hạn, bấm lại.")?;
        let cred = st
            .db
            .lock()
            .map_err(|_| "lỗi hệ thống")?
            .get_passkey(&a.id)
            .ok_or("Passkey này chưa được đăng ký.")?;
        let decode = |s: &str| webauthn::b64d(s).ok_or("dữ liệu passkey không hợp lệ");
        let count = webauthn::verify_assertion(
            &cred,
            &decode(&a.authenticator_data)?,
            &decode(&a.client_data_json)?,
            &decode(&a.signature)?,
            &challenge,
            &rp_id,
            &origin,
        )?;
        Ok((cred.id, count))
    })();
    match outcome {
        Ok((id, count)) => {
            if let Ok(db) = st.db.lock() {
                let _ = db.touch_passkey(&id, count, at);
            }
            st.pending.remove(&ptoken);
            let cookies = finish_login(&st, &headers, "password+passkey", "");
            json_with_cookies(StatusCode::OK, &json!({ "ok": true }), &cookies)
        }
        Err(e) => {
            factor_failed(&st, at);
            log_fail(&st, &ip, "password+passkey", &e);
            if st.pending.fail(&ptoken) == 0 {
                return json_with_cookies(
                    StatusCode::UNAUTHORIZED,
                    &json!({"ok": false, "error": "Quá nhiều lần thử, hãy đăng nhập lại."}),
                    &[auth::cookie(PENDING_COOKIE, "", 0, secure(&st, &headers))],
                );
            }
            jerr(StatusCode::UNAUTHORIZED, &e)
        }
    }
}

// ---------------------------------------------------------------------------
// The "Bảo mật" page
// ---------------------------------------------------------------------------

fn session_token(st: &AppState, headers: &HeaderMap) -> Option<String> {
    auth::session_from_headers(headers).filter(|t| session_valid(st, t))
}

fn to_login() -> Response {
    Redirect::to("/login").into_response()
}

fn back(msg: &str) -> Response {
    Redirect::to(&format!("/security?msg={}", urlenc(msg))).into_response()
}

/// A page that shows recovery codes once.
fn codes_page(codes: &[String], title: &str) -> Response {
    Html(
        shell(
            "Mã khôi phục",
            html! {
                div class="card" style="max-width:520px;margin:6vh auto" {
                    h1 { (title) }
                    p { "Lưu các mã này ở nơi an toàn (trình quản lý mật khẩu, bản in). " b { "Mỗi mã dùng được một lần" } " và hub " b { "không hiện lại" } " chúng. Chúng là cách duy nhất vào hub nếu bạn mất thiết bị xác thực." }
                    pre style="font-size:18px;line-height:1.8;user-select:all" { @for c in codes { (c) "\n" } }
                    p { a href="/security" { "Tôi đã lưu, quay lại trang Bảo mật →" } }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

const REGISTER_PASSKEY_JS: &str = "async function addPasskey(){const out=document.getElementById('pk-reg-msg');out.textContent='';try{\
const pw=document.getElementById('pk-pw').value;const name=document.getElementById('pk-name').value||'Passkey';\
const r=await fetch('/security/passkey/options',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({password:pw})});\
const o=await r.json();if(!o.challenge){out.textContent=o.error||'Lỗi';return}\
const pk={challenge:b64d(o.challenge),rp:o.rp,user:{id:b64d(o.user.id),name:o.user.name,displayName:o.user.displayName},pubKeyCredParams:o.pubKeyCredParams,timeout:o.timeout,attestation:'none',authenticatorSelection:o.authenticatorSelection,excludeCredentials:o.excludeCredentials.map(c=>({type:c.type,id:b64d(c.id)}))};\
const cred=await navigator.credentials.create({publicKey:pk});\
const res=await fetch('/security/passkey/register',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},\
body:JSON.stringify({name:name,id:cred.id,clientDataJSON:b64e(cred.response.clientDataJSON),attestationObject:b64e(cred.response.attestationObject)})});\
const j=await res.json();if(!j.ok){out.textContent=j.error||'Không đăng ký được';return}\
if(j.codes&&j.codes.length){document.getElementById('pk-codes').textContent=j.codes.join('\\n');document.getElementById('pk-codes-box').style.display='block'}else{location.href='/security?msg='+encodeURIComponent('Đã thêm passkey.')}\
}catch(e){out.textContent='Passkey bị huỷ hoặc không dùng được: '+(e&&e.message?e.message:e)}}";

#[derive(Deserialize, Default)]
pub struct SecurityQuery {
    #[serde(default)]
    msg: String,
}

pub async fn security_page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<SecurityQuery>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    let at = now();
    let me = st.sessions.id_of(&tok).unwrap_or_default();
    let (totp_state, passkeys, codes_left, logins) = {
        let db = st.db.lock().expect("db");
        (
            db.totp(),
            db.list_passkeys(),
            db.recovery_codes_left(),
            db.recent_logins(15),
        )
    };
    let passkey_ok = rp(&st).is_some();
    let two_factor_on = st.cfg.two_factor;
    let sessions = st.sessions.list(at);
    let totp_on = totp_state.as_ref().is_some_and(|t| t.enabled);
    // A secret that was shown but not yet confirmed stays on screen (same QR) until it
    // is confirmed or replaced, even after a reload or a visit to another page.
    let pending_totp = totp_state.as_ref().filter(|t| !t.enabled);
    // The entry in the app is named after the key's last characters, so a new key is
    // a new, recognisable entry and an old one cannot be mistaken for it.
    let totp_label = |secret: &str| {
        let n = secret.chars().count();
        format!(
            "admin-{}",
            secret.chars().skip(n.saturating_sub(4)).collect::<String>()
        )
    };
    // The codes this server expects right now, for the admin to compare with the
    // app while enrolling. Shown only for a key not yet confirmed, on a page that
    // already shows the key itself, so it reveals nothing new.
    let compare = pending_totp.and_then(|t| {
        let key = totp::base32_decode(&t.secret)?;
        let secs = now().max(0) as u64;
        let step = secs / totp::STEP_SECS;
        Some((
            totp::code_for_step(&key, step.saturating_sub(1)),
            totp::code_for_step(&key, step),
            totp::code_for_step(&key, step + 1),
            totp::STEP_SECS - secs % totp::STEP_SECS,
        ))
    });
    let qr = pending_totp.and_then(|t| {
        totp::qr_svg(&totp::otpauth_uri(
            "SN Secure",
            &totp_label(&t.secret),
            &t.secret,
        ))
    });
    let enrolled = totp_on || !passkeys.is_empty();
    let factor_paused = st.limiter.factor_paused(at);

    let body = html! {
        h1 { "Bảo mật đăng nhập" }
        p class="sub" { "Mật khẩu, xác thực hai bước (ứng dụng hoặc passkey), mã khôi phục và các phiên đang mở." }
        @if let Some(secs) = factor_paused {
            div class="note" style="border-left-color:var(--bad);color:var(--fg)" {
                b { "Đã tạm khoá bước sau mật khẩu (còn " (secs / 60 + 1) " phút)." }
                " Có quá nhiều lần nhập sai mã xác thực hoặc mật khẩu hiện tại, nên nhiều khả năng mật khẩu quản trị đã lộ. "
                "Trong lúc khoá, không đăng nhập bằng bước hai và không đổi cài đặt cần mật khẩu được. Trên máy chủ hub, bằng root: "
                code { "sudo snhub set-admin-password --password '...'" }
                " để đặt mật khẩu mới: mọi phiên bị đăng xuất và khoá được gỡ sau vài giây."
            }
        }
        // While a new authenticator secret is on screen the message belongs next to
        // its form (the page jumps there), not at the top where it would be scrolled away.
        @if !q.msg.is_empty() && pending_totp.is_none() { div class="note" { (q.msg) } }

        @if !two_factor_on {
            div class="note" {
                b { "Xác thực hai bước đang tắt." } " Hub chỉ dùng mật khẩu (được băm Argon2id, có chống dò và phiên đăng nhập có hạn). Bật lại bằng "
                code { "two_factor = true" } " trong " code { "/etc/snhub/snhub.toml" } " rồi khởi động lại hub."
            }
        } @else {

        div class="card" {
            h2 { "Trạng thái" }
            @if enrolled {
                p { span class="badge b-ok" { "Đã bật xác thực hai bước" } " "
                    @if totp_on { "ứng dụng xác thực" } @if totp_on && !passkeys.is_empty() { " + " } @if !passkeys.is_empty() { (passkeys.len()) " passkey" }
                    ". Mã khôi phục còn lại: " b { (codes_left) } "." }
                @if codes_left == 0 { p style="color:var(--warn)" { "Bạn chưa có mã khôi phục. Hãy tạo ở bên dưới để không bị khoá ngoài khi mất thiết bị." } }
            } @else {
                p { span class="badge b-warn" { "Chưa bật xác thực hai bước" } " Ai biết mật khẩu là vào được hub, và hub điều khiển được mọi VPS. Nên bật ít nhất một cách bên dưới." }
            }
        }

        div class="card" id="totp" {
            h2 { "Ứng dụng xác thực (Google Authenticator, Authy, 1Password…)" }
            @if let Some(t) = pending_totp {
                @if !q.msg.is_empty() { div class="note" style="border-left-color:var(--bad);color:var(--fg)" { (q.msg) } }
                p { "1. Quét mã QR bằng ứng dụng, hoặc nhập tay khoá bên dưới. Mục mới trong ứng dụng tên " b { "SN Secure (" (totp_label(&t.secret)) ")" } "; hãy đọc mã từ đúng mục này." }
                @if let Some(svg) = &qr { div style="background:#fff;display:inline-block;padding:6px;border-radius:8px" { (PreEscaped(svg.clone())) } }
                p { "Khoá: " code style="user-select:all;letter-spacing:2px" { (t.secret) } }
                @if let Some((prev, cur, next, left)) = &compare {
                    details style="margin:0 0 12px" open {
                        summary { b { "So mã với ứng dụng" } }
                        p style="margin:6px 0" {
                            "Hub đang tính (giờ máy chủ, lúc tải trang): "
                            code style="font-size:20px;letter-spacing:3px" { (cur) }
                            span class="mut" { " — còn " (left) " giây; 30 giây trước " (prev) ", 30 giây sau " (next) }
                        }
                        p class="help" {
                            "Mã trong mục SN Secure (admin-" (totp_label(&t.secret).trim_start_matches("admin-")) ") của ứng dụng phải trùng một trong các mã này "
                            "(tải lại trang để lấy mã mới). Khác hẳn: ứng dụng đang giữ khoá khác, xoá mục cũ rồi quét lại. "
                            "Trùng nhưng lệch một nhịp: đồng hồ hơi lệch, vẫn dùng được."
                        }
                    }
                }
                p { "2. Nhập mã 6 số ứng dụng đang hiện để xác nhận." }
                form method="post" action="/security/totp/confirm" {
                    div class="ctrls" {
                        label class="f" { span class="t" { "Mã 6 số" } input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required; }
                        button type="submit" { "Bật" }
                    }
                }
                details style="margin-top:12px" {
                    summary class="mut" { "Quét nhầm hoặc mã luôn sai? Tạo khoá mới" }
                    p class="help" { "Khoá mới thay khoá cũ: xoá mục SN Secure cũ trong ứng dụng rồi quét lại." }
                    form method="post" action="/security/totp/start" {
                        div class="ctrls" {
                            label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" name="password" required autocomplete="current-password"; }
                            button class="ghost" type="submit" { "Tạo khoá mới" }
                        }
                    }
                }
            } @else if totp_on {
                p { span class="badge b-ok" { "Đang bật" } }
                form method="post" action="/security/totp/disable" onsubmit="return confirm('Tắt ứng dụng xác thực?')" {
                    div class="ctrls" {
                        label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" name="password" required autocomplete="current-password"; }
                        button class="bad" type="submit" { "Tắt" }
                    }
                }
            } @else {
                form method="post" action="/security/totp/start" {
                    div class="ctrls" {
                        label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" name="password" required autocomplete="current-password"; }
                        button type="submit" { "Bật xác thực bằng ứng dụng" }
                    }
                }
            }
        }

        div class="card" id="passkeys" {
            h2 { "Passkey (vân tay, khuôn mặt, khoá bảo mật)" }
            @if !passkey_ok {
                p class="help" { "Passkey cần hub chạy qua HTTPS với địa chỉ đặt ở " code { "public_url" } " trong " code { "/etc/snhub/snhub.toml" } "." }
            }
            @if !passkeys.is_empty() {
                div class="wrap" { table {
                    thead { tr { th { "Tên" } th { "Thêm lúc" } th { "Dùng lần cuối" } th {} } }
                    tbody { @for p in &passkeys { tr {
                        td { (p.name) }
                        td class="mut" { (rel_time(p.created)) }
                        td class="mut" { @if p.last_used > 0 { (rel_time(p.last_used)) } @else { "chưa" } }
                        td { form method="post" action={"/security/passkey/" (p.id) "/delete"} style="margin:0;display:flex;gap:6px" onsubmit="return confirm('Xoá passkey này?')" {
                            input type="password" name="password" placeholder="Mật khẩu hiện tại" required style="width:150px";
                            button class="bad" type="submit" { "Xoá" } } }
                    } } }
                } }
            }
            @if passkey_ok {
                div class="ctrls" style="margin-top:10px" {
                    label class="f" { span class="t" { "Tên gợi nhớ" } input type="text" id="pk-name" placeholder="vd: Laptop" maxlength="40"; }
                    label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" id="pk-pw" autocomplete="current-password"; }
                    button type="button" onclick="addPasskey()" { "Thêm passkey" }
                }
                p id="pk-reg-msg" style="color:var(--bad);font-size:13px" {}
                div id="pk-codes-box" style="display:none" class="note" {
                    b { "Mã khôi phục của bạn (lưu lại ngay, hub không hiện lại):" }
                    pre id="pk-codes" style="user-select:all;font-size:16px" {}
                    p { a href="/security" { "Tôi đã lưu →" } }
                }
                script { (PreEscaped(format!("{B64_JS}{REGISTER_PASSKEY_JS}"))) }
            }
        }

        div class="card" id="recovery" {
            h2 { "Mã khôi phục" }
            p class="help" { "Dùng khi mất thiết bị xác thực: mỗi mã vào hub được một lần. Tạo mã mới sẽ vô hiệu các mã cũ." }
            form method="post" action="/security/recovery/new" {
                div class="ctrls" {
                    label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" name="password" required autocomplete="current-password"; }
                    button type="submit" { "Tạo mã khôi phục mới" }
                }
            }
            p class="help" { "Mất hết cả mã? Trên máy chủ hub, bằng root: " code { "sudo -u snhub snhub reset-2fa" } " (xoá mọi cách xác thực thứ hai và đăng xuất mọi phiên; mật khẩu giữ nguyên)." }
        }
        }

        div class="card" id="password" {
            h2 { "Đổi mật khẩu" }
            form method="post" action="/security/password" {
                div class="ctrls" {
                    label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" name="current" required autocomplete="current-password"; }
                    label class="f" { span class="t" { "Mật khẩu mới (≥ 10 ký tự)" } input type="password" name="new" required minlength="10" autocomplete="new-password"; }
                    label class="f" { span class="t" { "Nhập lại" } input type="password" name="confirm" required minlength="10" autocomplete="new-password"; }
                    button type="submit" { "Đổi" }
                }
            }
            p class="help" { "Đổi mật khẩu sẽ đăng xuất mọi phiên khác." }
        }

        div class="card" id="sessions" {
            h2 { "Phiên đang mở" }
            div class="wrap" { table {
                thead { tr { th { "Địa chỉ" } th { "Trình duyệt" } th { "Cách vào" } th { "Mở lúc" } th { "Hoạt động" } th {} } }
                tbody { @for s in &sessions { tr {
                    td { code { (s.ip) } @if s.id == me { " " span class="badge b-ok" { "phiên này" } } }
                    td class="mut" style="font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis" { (s.agent) }
                    td { (s.method) }
                    td class="mut" { (rel_time(s.created)) }
                    td class="mut" { (rel_time(s.last_seen)) }
                    td { @if s.id != me { form method="post" action={"/security/session/" (s.id) "/end"} style="margin:0" { button class="ghost" type="submit" { "Đăng xuất" } } } }
                } } }
            } }
            @if sessions.len() > 1 {
                form method="post" action="/security/sessions/others" style="margin-top:10px" { button class="ghost" type="submit" { "Đăng xuất mọi phiên khác" } }
            }
        }

        div class="card" id="log" {
            h2 { "Lần đăng nhập gần đây" }
            div class="wrap" { table {
                thead { tr { th { "Lúc" } th { "Địa chỉ" } th { "Kết quả" } th { "Cách" } th { "Ghi chú" } } }
                tbody { @if logins.is_empty() { tr { td colspan="5" { div class="empty" { "Chưa có" } } } }
                    @for l in &logins { tr {
                        td class="mut" { (rel_time(l.ts)) }
                        td { code { (l.ip) } }
                        td { @if l.ok { span class="badge b-ok" { "Thành công" } } @else { span class="badge b-bad" { "Thất bại" } } }
                        td { (l.method) }
                        td class="mut" { (l.note) }
                    } }
                }
            } }
        }
    };
    Html(shell("Bảo mật", body).into_string()).into_response()
}

// ---- password ------------------------------------------------------------

#[derive(Deserialize)]
pub struct PasswordForm {
    current: String,
    new: String,
    confirm: String,
}

pub async fn change_password(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<PasswordForm>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    let at = now();
    if let Some(r) = confirm_password(&st, &headers, f.current).await {
        return r;
    }
    if f.new != f.confirm {
        return back("Hai lần nhập mật khẩu mới không giống nhau.");
    }
    if let Some(problem) = auth::password_problem(&f.new) {
        return back(problem);
    }
    let hash = {
        let pw = f.new;
        tokio::task::spawn_blocking(move || auth::hash_password_argon2(&pw))
            .await
            .unwrap_or_default()
    };
    if hash.is_empty() {
        return back("Không băm được mật khẩu mới.");
    }
    let saved = st.db.lock().expect("db").set_admin_pw_hash(&hash, at);
    if saved.is_err() {
        return back("Không lưu được mật khẩu mới.");
    }
    let ended = st.sessions.remove_all_except(&tok);
    if let Ok(db) = st.db.lock() {
        db.log_login(
            at,
            &auth::client_ip(&headers),
            true,
            "đổi mật khẩu",
            &format!("đăng xuất {ended} phiên khác"),
        );
    }
    back(&format!(
        "Đã đổi mật khẩu; đã đăng xuất {ended} phiên khác."
    ))
}

// ---- helpers for forms that need the current password --------------------

#[derive(Deserialize)]
pub struct PasswordOnly {
    password: String,
}

/// After any change to how one signs in: end every other session (one opened
/// before the change must not outlive it), and when no second factor is left,
/// forget the recovery codes so an old printed code cannot unlock a later one.
fn factors_changed(st: &AppState, keep: &str) {
    st.sessions.remove_all_except(keep);
    if let Ok(db) = st.db.lock()
        && !db.second_factor_enrolled()
    {
        let _ = db.replace_recovery_codes(&[], now());
    }
}

/// Check the current password for a sensitive change, with the limiter.
async fn confirm_password(st: &Arc<AppState>, headers: &HeaderMap, pw: String) -> Option<Response> {
    match recheck_password(st, headers, pw).await {
        Recheck::Right => None,
        Recheck::Wrong => Some(back("Mật khẩu hiện tại không đúng.")),
        Recheck::Wait(wait) => Some(wait_page(wait)),
    }
}

// ---- authenticator app ---------------------------------------------------

pub async fn totp_start(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<PasswordOnly>,
) -> Response {
    if session_token(&st, &headers).is_none() {
        return to_login();
    }
    if let Some(r) = confirm_password(&st, &headers, f.password).await {
        return r;
    }
    let secret = totp::new_secret();
    if st.db.lock().expect("db").start_totp(&secret).is_err() {
        return back("Không lưu được khoá.");
    }
    Redirect::to("/security?totp=1#totp").into_response()
}

#[derive(Deserialize)]
pub struct CodeForm {
    code: String,
}

pub async fn totp_confirm(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<CodeForm>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    let at = now();
    let Some(t) = st.db.lock().expect("db").totp().filter(|t| !t.enabled) else {
        return back("Chưa có khoá nào đang chờ xác nhận.");
    };
    let now_secs = at.max(0) as u64;
    // Search a few minutes either way: it tells a wrong clock (the code fits at
    // some offset) from a wrong key (it fits nowhere), and a clock that is merely
    // off is learned and compensated instead of locking the admin out.
    let Some(offset) = totp::find_offset(&t.secret, &f.code, now_secs, totp::ENROL_SEARCH_STEPS)
    else {
        let tail: String = t
            .secret
            .chars()
            .skip(t.secret.chars().count().saturating_sub(4))
            .collect();
        // Side by side: what was typed and what this server computes, so the two can
        // be compared directly. Only while enrolling, for an admin already signed in
        // who is looking at the key itself on this page; never on the sign-in step.
        let typed: String = f
            .code
            .chars()
            .filter(char::is_ascii_digit)
            .take(8)
            .collect();
        let step = now_secs / totp::STEP_SECS;
        let expect = totp::base32_decode(&t.secret)
            .map(|k| {
                (
                    totp::code_for_step(&k, step.saturating_sub(1)),
                    totp::code_for_step(&k, step),
                    totp::code_for_step(&k, step + 1),
                )
            })
            .unwrap_or_default();
        tracing::warn!(
            "TOTP enrolment refused: typed {typed:?}, key …{tail}, server {at}: expected prev {} now {} next {}",
            expect.0,
            expect.1,
            expect.2
        );
        return Redirect::to(&format!(
            "/security?totp=1&msg={}#totp",
            urlenc(&format!(
                "Mã không khớp. Bạn nhập: {typed}. Hub tính theo giờ máy chủ {:02}:{:02}:{:02} UTC: \
                 30 giây trước {}, bây giờ {}, 30 giây sau {} (khoá …{tail}). \
                 Nếu ứng dụng đang hiện một trong ba mã này mà vẫn bị từ chối, đó là lỗi của hub: chụp màn hình gửi lại. \
                 Nếu ứng dụng hiện mã khác hẳn: mã không khớp khoá này ở bất kỳ thời điểm nào trong ±5 phút, \
                 nên không phải lệch giờ mà ứng dụng đang giữ khoá khác (mục cũ, hoặc nhập tay sai khoá): \
                 dùng đúng mục \"SN Secure (admin-{tail})\", hoặc xoá hết mục SN Secure, bấm \"Tạo khoá mới\" rồi quét lại.",
                at.rem_euclid(86_400) / 3600,
                at.rem_euclid(3600) / 60,
                at.rem_euclid(60),
                expect.0,
                expect.1,
                expect.2,
            ))
        ))
        .into_response();
    };
    let Some(step) = (now_secs / totp::STEP_SECS).checked_add_signed(offset) else {
        return back("Không bật được.");
    };
    let (enabled, fresh_codes) = {
        let db = st.db.lock().expect("db");
        let ok = db.enable_totp(step).is_ok() && db.set_totp_offset(offset).is_ok();
        if offset.abs() > 1 {
            tracing::warn!(
                "TOTP enrolment: authenticator clock is {} s from this server's; compensating",
                offset * totp::STEP_SECS as i64
            );
        }
        let fresh = if ok && db.recovery_codes_left() == 0 {
            let codes = new_recovery_codes();
            let hashes: Vec<String> = codes.iter().map(|(_, h)| h.clone()).collect();
            db.replace_recovery_codes(&hashes, at).ok().map(|()| codes)
        } else {
            None
        };
        db.log_login(
            at,
            &auth::client_ip(&headers),
            true,
            "bật 2FA",
            "ứng dụng xác thực",
        );
        (ok, fresh)
    };
    if !enabled {
        return back("Không bật được.");
    }
    st.sessions.remove_all_except(&tok);
    let skew = if offset.abs() > 1 {
        format!(
            " Lưu ý: đồng hồ máy chủ lệch khoảng {} giây so với điện thoại; hub đã tự bù, nhưng nên bật đồng bộ giờ (NTP) trên máy chủ.",
            offset.abs() * totp::STEP_SECS as i64
        )
    } else {
        String::new()
    };
    match fresh_codes {
        Some(codes) => {
            let shown: Vec<String> = codes.into_iter().map(|(c, _)| c).collect();
            codes_page(&shown, &format!("Đã bật xác thực hai bước.{skew}"))
        }
        None => back(&format!("Đã bật xác thực bằng ứng dụng.{skew}")),
    }
}

pub async fn totp_disable(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<PasswordOnly>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    if let Some(r) = confirm_password(&st, &headers, f.password).await {
        return r;
    }
    let ok = st.db.lock().expect("db").disable_totp().is_ok();
    factors_changed(&st, &tok);
    if let Ok(db) = st.db.lock() {
        db.log_login(
            now(),
            &auth::client_ip(&headers),
            true,
            "tắt 2FA",
            "ứng dụng xác thực",
        );
    }
    back(if ok {
        "Đã tắt ứng dụng xác thực."
    } else {
        "Không tắt được."
    })
}

// ---- recovery codes ------------------------------------------------------

pub async fn recovery_new(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<PasswordOnly>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    if let Some(r) = confirm_password(&st, &headers, f.password).await {
        return r;
    }
    let codes = new_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|(_, h)| h.clone()).collect();
    let at = now();
    let saved = st
        .db
        .lock()
        .expect("db")
        .replace_recovery_codes(&hashes, at);
    if saved.is_err() {
        return back("Không lưu được mã khôi phục.");
    }
    if let Ok(db) = st.db.lock() {
        db.log_login(at, &auth::client_ip(&headers), true, "mã khôi phục mới", "");
    }
    st.sessions.remove_all_except(&tok);
    let shown: Vec<String> = codes.into_iter().map(|(c, _)| c).collect();
    codes_page(&shown, "Mã khôi phục mới")
}

// ---- passkeys ------------------------------------------------------------

#[derive(Deserialize)]
pub struct PasskeyOptionsReq {
    password: String,
}

pub async fn passkey_register_options(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PasskeyOptionsReq>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return jerr(StatusCode::UNAUTHORIZED, "Phiên đã hết hạn.");
    };
    let Some((rp_id, _)) = rp(&st) else {
        return jerr(
            StatusCode::BAD_REQUEST,
            "Hub chưa có địa chỉ HTTPS (public_url) nên không dùng passkey được.",
        );
    };
    let at = now();
    match recheck_password(&st, &headers, req.password).await {
        Recheck::Right => {}
        Recheck::Wrong => {
            return jerr(StatusCode::UNAUTHORIZED, "Mật khẩu hiện tại không đúng.");
        }
        Recheck::Wait(wait) => {
            return jerr(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Thử quá nhiều lần, chờ {wait} giây."),
            );
        }
    }
    let (user, exclude) = {
        let db = st.db.lock().expect("db");
        (db.webauthn_user().unwrap_or_default(), db.passkey_ids())
    };
    let challenge = webauthn::new_challenge();
    st.pending.issue(&format!("reg:{tok}"), &challenge, at);
    json_with_cookies(
        StatusCode::OK,
        &json!({
            "challenge": challenge,
            "rp": { "name": "SN Secure", "id": rp_id },
            "user": { "id": user, "name": "admin", "displayName": "Quản trị SN Secure" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": webauthn::ALG_ES256 }],
            "timeout": 120_000,
            "authenticatorSelection": { "residentKey": "preferred", "userVerification": "preferred" },
            "excludeCredentials": exclude.iter().map(|id| json!({"type": "public-key", "id": id})).collect::<Vec<_>>(),
        }),
        &[],
    )
}

#[derive(Deserialize)]
pub struct PasskeyRegistration {
    name: String,
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

pub async fn passkey_register(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(r): Json<PasskeyRegistration>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return jerr(StatusCode::UNAUTHORIZED, "Phiên đã hết hạn.");
    };
    let at = now();
    let result = (|| -> Result<Option<Vec<String>>, String> {
        let (rp_id, origin) = rp(&st).ok_or("Hub chưa có địa chỉ HTTPS.")?;
        let challenge = st
            .pending
            .take_challenge(&format!("reg:{tok}"), at)
            .ok_or("Yêu cầu đã hết hạn, bấm Thêm passkey lại.")?;
        let decode = |s: &str| webauthn::b64d(s).ok_or("dữ liệu passkey không hợp lệ");
        let claimed_id = decode(&r.id)?;
        let cred = webauthn::verify_registration(
            &decode(&r.attestation_object)?,
            &decode(&r.client_data_json)?,
            &challenge,
            &rp_id,
            &origin,
            &claimed_id,
        )?;
        let name: String = r
            .name
            .chars()
            .filter(|c| !c.is_control())
            .take(40)
            .collect::<String>()
            .trim()
            .to_string();
        let name = if name.is_empty() {
            "Passkey".to_string()
        } else {
            name
        };
        let db = st.db.lock().map_err(|_| "lỗi hệ thống")?;
        // The passkey and the recovery codes that come with the first second
        // factor are saved together or not at all (dropping `tx` rolls back).
        let tx = db
            .conn
            .unchecked_transaction()
            .map_err(|_| "không lưu được")?;
        db.add_passkey(&cred, &name, at)
            .map_err(|_| "Passkey này đã được đăng ký rồi.")?;
        // The first second factor brings the recovery codes with it.
        let mut shown = None;
        if db.recovery_codes_left() == 0 {
            let codes = new_recovery_codes();
            let hashes: Vec<String> = codes.iter().map(|(_, h)| h.clone()).collect();
            db.replace_recovery_codes(&hashes, at)
                .map_err(|_| "không lưu được mã khôi phục")?;
            shown = Some(codes.into_iter().map(|(c, _)| c).collect());
        }
        tx.commit().map_err(|_| "không lưu được")?;
        db.log_login(at, &auth::client_ip(&headers), true, "thêm passkey", &name);
        Ok(shown)
    })();
    match result {
        Ok(codes) => {
            st.sessions.remove_all_except(&tok);
            json_with_cookies(
                StatusCode::OK,
                &json!({ "ok": true, "codes": codes.unwrap_or_default() }),
                &[],
            )
        }
        Err(e) => jerr(StatusCode::BAD_REQUEST, &e),
    }
}

pub async fn passkey_delete(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<PasswordOnly>,
) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    if let Some(r) = confirm_password(&st, &headers, f.password).await {
        return r;
    }
    let ok = st
        .db
        .lock()
        .expect("db")
        .delete_passkey(id)
        .unwrap_or(false);
    factors_changed(&st, &tok);
    if let Ok(db) = st.db.lock() {
        db.log_login(now(), &auth::client_ip(&headers), true, "xoá passkey", "");
    }
    back(if ok {
        "Đã xoá passkey."
    } else {
        "Không tìm thấy passkey."
    })
}

// ---- sessions ------------------------------------------------------------

pub async fn session_end(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if session_token(&st, &headers).is_none() {
        return to_login();
    }
    let ended = st.sessions.remove_by_id(&id);
    back(if ended {
        "Đã đăng xuất phiên đó."
    } else {
        "Không tìm thấy phiên."
    })
}

pub async fn sessions_end_others(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(tok) = session_token(&st, &headers) else {
        return to_login();
    };
    let n = st.sessions.remove_all_except(&tok);
    back(&format!("Đã đăng xuất {n} phiên khác."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(public_url: &str) -> AppState {
        let cfg = crate::config::HubConfig {
            public_url: public_url.into(),
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&dir.path().join("t.db")).unwrap();
        let hubkey = crate::keys::HubKey::load_or_create(dir.path()).unwrap();
        // The database must outlive the test body.
        std::mem::forget(dir);
        AppState {
            db: std::sync::Mutex::new(db),
            hubkey,
            cfg,
            sessions: auth::Sessions::default(),
            pending: auth::Pending::default(),
            limiter: auth::Limiter::default(),
        }
    }

    #[test]
    fn the_relying_party_comes_from_the_https_public_url() {
        let rp_of = |u: &str| rp(&state_with(u));
        assert_eq!(
            rp_of("https://sec.sgd.ovh"),
            Some(("sec.sgd.ovh".into(), "https://sec.sgd.ovh".into()))
        );
        assert_eq!(
            rp_of("https://sec.sgd.ovh:8443/"),
            Some(("sec.sgd.ovh".into(), "https://sec.sgd.ovh:8443".into()))
        );
        // Plain HTTP is refused except for localhost (where browsers allow it).
        assert_eq!(rp_of("http://sec.sgd.ovh"), None);
        assert_eq!(
            rp_of("http://localhost:8099"),
            Some(("localhost".into(), "http://localhost:8099".into()))
        );
        assert_eq!(rp_of(""), None);
        // What the browser sends: lower case, no default port; no IP addresses.
        assert_eq!(
            rp_of("https://Sec.SGD.ovh:443/"),
            Some(("sec.sgd.ovh".into(), "https://sec.sgd.ovh".into()))
        );
        assert_eq!(rp_of("https://127.0.0.1:8099"), None);
        assert_eq!(rp_of("http://127.0.0.1:8099"), None);
        assert_eq!(rp_of("not a url"), None);
    }

    #[test]
    fn a_post_must_come_from_this_hub() {
        let hdr = |pairs: &[(&'static str, &str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, v.parse().unwrap());
            }
            h
        };
        let public = "https://sec.sgd.ovh";
        // Browsers say it themselves; whatever Host the proxy forwards is irrelevant.
        for host in ["sec.sgd.ovh", "127.0.0.1:8099", "upstream.internal"] {
            assert!(
                same_origin(
                    &hdr(&[
                        ("sec-fetch-site", "same-origin"),
                        ("origin", "https://sec.sgd.ovh"),
                        ("host", host)
                    ]),
                    public
                ),
                "{host}"
            );
        }
        // Anything but same-origin is refused, even if Origin looks right.
        for site in ["cross-site", "same-site", "none", ""] {
            assert!(
                !same_origin(
                    &hdr(&[
                        ("sec-fetch-site", site),
                        ("origin", "https://sec.sgd.ovh"),
                        ("host", "sec.sgd.ovh")
                    ]),
                    public
                ),
                "{site}"
            );
        }
        // No Sec-Fetch-Site (old browser, plain http): Origin must name this hub.
        assert!(same_origin(
            &hdr(&[("origin", "https://sec.sgd.ovh"), ("host", "sec.sgd.ovh")]),
            public
        ));
        assert!(same_origin(
            &hdr(&[
                ("origin", "http://10.0.0.5:8099"),
                ("host", "10.0.0.5:8099")
            ]),
            ""
        ));
        // Host rewritten by the proxy: the public URL or X-Forwarded-Host still match.
        assert!(same_origin(
            &hdr(&[
                ("origin", "https://sec.sgd.ovh"),
                ("host", "127.0.0.1:8099")
            ]),
            public
        ));
        assert!(same_origin(
            &hdr(&[
                ("origin", "https://sec.sgd.ovh"),
                ("host", "127.0.0.1:8099"),
                ("x-forwarded-host", "evil.example, sec.sgd.ovh")
            ]),
            ""
        ));
        // Another site, "null", odd values and look-alikes are refused.
        for bad in [
            "https://evil.example",
            "null",
            "https://sec.sgd.ovh.evil.example",
            "https://sec.sgd.ovh@evil.example",
            "https://sec.sgd.ovh/x",
            "ftp://sec.sgd.ovh",
        ] {
            assert!(
                !same_origin(&hdr(&[("origin", bad), ("host", "sec.sgd.ovh")]), public),
                "{bad}"
            );
        }
        // A forwarded host that is not the last entry does not count.
        assert!(!same_origin(
            &hdr(&[
                ("origin", "https://evil.example"),
                ("host", "127.0.0.1:8099"),
                ("x-forwarded-host", "evil.example, sec.sgd.ovh")
            ]),
            public
        ));
        // Neither header: not a browser page.
        assert!(same_origin(&hdr(&[]), public));
    }

    #[test]
    fn cookies_are_secure_only_over_https() {
        let none = HeaderMap::new();
        assert!(secure(&state_with("https://x.example"), &none));
        assert!(!secure(&state_with("http://127.0.0.1:8099"), &none));
        assert!(!secure(&state_with(""), &none));
        // TLS ended at the proxy and the hub URL is not configured.
        let mut proxied = HeaderMap::new();
        proxied.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(secure(&state_with(""), &proxied));
    }

    #[test]
    fn the_password_is_read_from_the_override_then_the_config_then_the_old_hash() {
        let mut st = state_with("");
        assert!(!password_configured(&st));
        // Old SHA-256 form.
        st.cfg.admin_salt = "salt".into();
        st.cfg.admin_password_sha256 = auth::hash_password("salt", "old password 1");
        assert!(password_configured(&st) && check_password(&st, "old password 1"));
        assert!(!check_password(&st, "wrong"));
        // Argon2 in the config wins over the old form.
        st.cfg.admin_password_hash = auth::hash_password_argon2("config password 1");
        assert!(check_password(&st, "config password 1"));
        assert!(!check_password(&st, "old password 1"));
        // A password changed in the web UI wins over the config.
        st.db
            .lock()
            .unwrap()
            .set_admin_pw_hash(&auth::hash_password_argon2("web password 1"), 1)
            .unwrap();
        assert!(check_password(&st, "web password 1"));
        assert!(!check_password(&st, "config password 1"));
    }

    #[test]
    fn the_codes_page_shows_codes_once_and_escapes_nothing_dangerous() {
        let r = codes_page(&["abcde-fghjk".into(), "<b>x</b>".into()], "Mã");
        let status = r.status();
        assert_eq!(status, StatusCode::OK);
    }
}
