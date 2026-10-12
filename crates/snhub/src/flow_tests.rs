//! The whole sign-in and 2FA enrolment flow, through the real router (no socket).

use super::*;
use axum::body::to_bytes;
use axum::http::{HeaderMap, Method, Request};
use tower::ServiceExt;

const PW: &str = "correct horse battery";

struct Hub {
    app: Router,
    st: Arc<AppState>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    /// Value of the cookie this reply sets (empty = cleared).
    fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| {
                let first = c.split(';').next()?;
                let (n, v) = first.split_once('=')?;
                (n == name).then(|| v.to_string())
            })
    }
}

fn hub() -> Hub {
    hub_with(true)
}

fn hub_with(two_factor: bool) -> Hub {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("t.sqlite")).unwrap();
    let hubkey = HubKey::load_or_create(dir.path()).unwrap();
    // The database must outlive the test body.
    std::mem::forget(dir);
    db.set_admin_pw_hash(&auth::hash_password_argon2(PW), now())
        .unwrap();
    let cfg = HubConfig {
        public_url: "https://sec.example.test".into(),
        two_factor,
        ..Default::default()
    };
    let st = Arc::new(AppState {
        db: Mutex::new(db),
        hubkey,
        cfg,
        sessions: auth::Sessions::default(),
        pending: auth::Pending::default(),
        limiter: auth::Limiter::default(),
    });
    Hub {
        app: router(st.clone()),
        st,
    }
}

fn pw_form() -> String {
    format!("password={}", web::urlenc(PW))
}

impl Hub {
    async fn send(&self, method: Method, uri: &str, cookie: &str, form: &str) -> Reply {
        self.send_from("", method, uri, cookie, form).await
    }
    /// `send`, as a client the proxy saw at `ip` (none when empty).
    async fn send_from(
        &self,
        ip: &str,
        method: Method,
        uri: &str,
        cookie: &str,
        form: &str,
    ) -> Reply {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "sec.example.test")
            .header("sec-fetch-site", "same-origin");
        if !ip.is_empty() {
            b = b.header("x-forwarded-for", ip);
        }
        if !cookie.is_empty() {
            b = b.header(header::COOKIE, cookie);
        }
        let body = if form.is_empty() {
            Body::empty()
        } else {
            b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form.to_string())
        };
        self.request(b.body(body).unwrap()).await
    }
    async fn request(&self, req: Request<Body>) -> Reply {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = to_bytes(body, 4 << 20).await.unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }
    async fn get(&self, uri: &str, cookie: &str) -> Reply {
        self.send(Method::GET, uri, cookie, "").await
    }
    async fn post(&self, uri: &str, cookie: &str, form: &str) -> Reply {
        self.send(Method::POST, uri, cookie, form).await
    }
    async fn sign_in(&self) -> String {
        let r = self.post("/login", "", &pw_form()).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        assert_eq!(r.location(), "/");
        format!("snhub_session={}", r.set_cookie("snhub_session").unwrap())
    }
    /// The code the authenticator app would show `step_offset` steps from now.
    fn code_at(&self, step_offset: i64) -> String {
        let secret = self.st.db.lock().unwrap().totp().unwrap().secret;
        let key = totp::base32_decode(&secret).unwrap();
        let step = (now() / 30 + step_offset) as u64;
        totp::code_for_step(&key, step)
    }
    /// A six-digit code that fits the pending/enabled key at no step within the
    /// enrolment search window, so "wrong code" tests cannot pass by chance.
    fn wrong_code(&self) -> String {
        let secret = self.st.db.lock().unwrap().totp().unwrap().secret;
        let key = totp::base32_decode(&secret).unwrap();
        let step = now() / 30;
        let near: Vec<String> = (-12..=12)
            .map(|d| totp::code_for_step(&key, (step + d) as u64))
            .collect();
        (0..1000)
            .map(|i| format!("{:06}", i * 997 % 1_000_000))
            .find(|c| !near.contains(c))
            .unwrap()
    }
    fn enrolled(&self) -> bool {
        self.st.db.lock().unwrap().second_factor_enrolled()
    }
}

#[tokio::test]
async fn pages_need_a_session_and_a_wrong_password_gets_in_nowhere() {
    let h = hub();
    assert_eq!(h.get("/security", "").await.location(), "/login");
    assert_eq!(h.get("/", "").await.location(), "/login");
    let r = h.post("/login", "", "password=nope").await;
    assert_eq!(r.location(), "/login?err=pw");
    assert!(r.set_cookie("snhub_session").is_none());
    // A cross-site POST never reaches the handler.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header("host", "sec.example.test")
        .header("sec-fetch-site", "cross-site")
        .header("origin", "https://evil.example")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(pw_form()))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn enrolling_an_authenticator_app_then_signing_in_with_it() {
    let h = hub();
    let cookie = h.sign_in().await;
    let page = h.get("/security", &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Chưa bật xác thực hai bước"));

    // Starting needs the current password.
    let r = h
        .post("/security/totp/start", &cookie, "password=wrong")
        .await;
    assert!(
        r.location().starts_with("/security?msg="),
        "{}",
        r.location()
    );
    let r = h.post("/security/totp/start", &cookie, &pw_form()).await;
    assert_eq!(r.location(), "/security?totp=1#totp");
    let page = h.get("/security?totp=1", &cookie).await;
    assert!(page.body.contains("<svg"), "QR shown");
    // A reload or a visit to the page without the query keeps the same QR on screen.
    let again = h.get("/security", &cookie).await;
    assert!(again.body.contains("<svg") && again.body.contains("Tạo khoá mới"));
    // The code the hub expects is shown next to the QR, to compare with the app.
    assert!(again.body.contains("So mã với ứng dụng"));
    assert!(again.body.contains(&h.code_at(0)) || again.body.contains(&h.code_at(-1)));
    assert!(page.body.contains("/security/totp/confirm"));
    // Not enabled until a code is confirmed.
    assert!(!h.enrolled());

    // A wrong code: told so, next to the form, and nothing is enabled.
    let r = h
        .post(
            "/security/totp/confirm",
            &cookie,
            &format!("code={}", h.wrong_code()),
        )
        .await;
    let loc = r.location();
    assert!(loc.starts_with("/security?totp=1&msg="), "{loc}");
    let page = h.get(loc.split('#').next().unwrap(), &cookie).await;
    assert!(page.body.contains("Mã không khớp"), "{}", page.body);
    // What was typed and what the hub expects, side by side.
    assert!(page.body.contains(&format!("Bạn nhập: {}", h.wrong_code())));
    assert!(page.body.contains(&h.code_at(0)) || page.body.contains(&h.code_at(1)));
    assert!(!h.enrolled());

    // The right code turns it on and shows the recovery codes once.
    let r = h
        .post(
            "/security/totp/confirm",
            &cookie,
            &format!("code={}", h.code_at(0)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.location());
    assert!(r.body.contains("Mã khôi phục"), "{}", r.body);
    assert!(h.enrolled());
    assert_eq!(h.st.db.lock().unwrap().recovery_codes_left(), 8);
    let page = h.get("/security", &cookie).await;
    assert!(page.body.contains("Đã bật xác thực hai bước"));

    // Signing in now stops at the second step.
    let out = h.get("/logout", &cookie).await;
    assert_eq!(out.location(), "/login");
    let r = h.post("/login", "", &pw_form()).await;
    assert_eq!(r.location(), "/login/2fa");
    assert!(r.set_cookie("snhub_session").is_none(), "no session yet");
    let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let second = h.get("/login/2fa", &pending).await;
    assert_eq!(second.status, StatusCode::OK);
    assert!(second.body.contains("Xác thực hai bước"));
    // The home page is still closed.
    assert_eq!(h.get("/", &pending).await.location(), "/login");

    // A wrong code is refused; the code for the next step opens the door once.
    let r = h
        .post("/login/2fa", &pending, "kind=totp&code=000000")
        .await;
    assert_eq!(r.location(), "/login/2fa?err=code");
    let good = h.code_at(1);
    let r = h
        .post("/login/2fa", &pending, &format!("kind=totp&code={good}"))
        .await;
    assert_eq!(r.location(), "/", "{}", r.body);
    let session = format!("snhub_session={}", r.set_cookie("snhub_session").unwrap());
    assert_eq!(h.get("/", &session).await.status, StatusCode::OK);
    // The same code cannot be used again (new password-correct login).
    let r = h.post("/login", "", &pw_form()).await;
    let pending2 = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post("/login/2fa", &pending2, &format!("kind=totp&code={good}"))
        .await;
    assert_eq!(r.location(), "/login/2fa?err=code", "replay refused");
}

#[tokio::test]
async fn a_recovery_code_signs_in_once_and_2fa_can_be_switched_off() {
    let h = hub();
    let cookie = h.sign_in().await;
    h.post("/security/totp/start", &cookie, &pw_form()).await;
    let r = h
        .post(
            "/security/totp/confirm",
            &cookie,
            &format!("code={}", h.code_at(0)),
        )
        .await;
    // Take a code from the page that shows them.
    let code = r
        .body
        .split("user-select:all")
        .nth(1)
        .and_then(|s| s.split('>').nth(1))
        .and_then(|s| s.split_whitespace().next())
        .unwrap()
        .to_string();
    assert_eq!(code.len(), 17, "{code}");
    let r = h.post("/login", "", &pw_form()).await;
    let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post(
            "/login/2fa",
            &pending,
            &format!("kind=recovery&code={code}"),
        )
        .await;
    assert_eq!(r.location(), "/");
    let again = h.post("/login", "", &pw_form()).await;
    let pending = format!("snhub_2fa={}", again.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post(
            "/login/2fa",
            &pending,
            &format!("kind=recovery&code={code}"),
        )
        .await;
    assert_eq!(r.location(), "/login/2fa?err=recovery", "used once only");

    // Switching it off needs the password.
    let r = h
        .post("/security/totp/disable", &cookie, "password=wrong")
        .await;
    assert!(r.location().starts_with("/security?msg="));
    assert!(h.enrolled());
    let r = h.post("/security/totp/disable", &cookie, &pw_form()).await;
    assert!(r.location().starts_with("/security?msg="));
    assert!(!h.enrolled());
    assert_eq!(
        h.st.db.lock().unwrap().recovery_codes_left(),
        0,
        "no factor left, no recovery codes left"
    );
}

#[tokio::test]
async fn with_two_factor_switched_off_sign_in_is_the_password_and_its_pages_do_not_exist() {
    let h = hub_with(false);
    // Even a factor left over in the database is not asked for.
    {
        let db = h.st.db.lock().unwrap();
        db.start_totp("L4LWBK3GKX772VX3UCR7SHY5OCFJUFKN").unwrap();
        db.enable_totp(1).unwrap();
        assert!(db.second_factor_enrolled());
    }
    let cookie = h.sign_in().await; // straight in: password only
    let page = h.get("/security", &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Xác thực hai bước đang tắt"));
    assert!(!page.body.contains("Quét mã QR"));
    // The rest of the page is there: password, sessions, sign-in log.
    assert!(page.body.contains("Đổi mật khẩu") && page.body.contains("Phiên đang mở"));
    // No nudge on the overview.
    let home = h.get("/", &cookie).await;
    assert!(!home.body.contains("mới chỉ có mật khẩu"));
    // The 2FA endpoints are not routed at all.
    for (method, uri) in [
        (Method::GET, "/login/2fa"),
        (Method::POST, "/security/totp/start"),
        (Method::POST, "/security/totp/confirm"),
        (Method::POST, "/security/recovery/new"),
        (Method::POST, "/login/passkey/options"),
        (Method::POST, "/security/passkey/register"),
    ] {
        let r = h.send(method, uri, &cookie, "password=x").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn a_server_clock_minutes_off_is_learned_at_enrolment_and_followed_at_sign_in() {
    let h = hub();
    let cookie = h.sign_in().await;
    h.post("/security/totp/start", &cookie, &pw_form()).await;
    // The phone runs four steps (about two minutes) ahead of this server: a plain
    // ±30 s window would refuse every code.
    let r = h
        .post(
            "/security/totp/confirm",
            &cookie,
            &format!("code={}", h.code_at(4)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.location());
    assert!(r.body.contains("chậm hơn giờ thật"), "the admin is told");
    let t = h.st.db.lock().unwrap().totp().unwrap();
    assert!(t.enabled);
    assert!((3..=5).contains(&t.offset), "offset {}", t.offset);

    // Signing in with the phone's (still ahead) clock works.
    let r = h.post("/login", "", &pw_form()).await;
    let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post(
            "/login/2fa",
            &pending,
            &format!("kind=totp&code={}", h.code_at(5)),
        )
        .await;
    assert_eq!(r.location(), "/", "{}", r.body);
    // A code by the server's own clock is now outside the learned window.
    let r = h.post("/login", "", &pw_form()).await;
    let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post(
            "/login/2fa",
            &pending,
            &format!("kind=totp&code={}", h.code_at(-3)),
        )
        .await;
    assert_eq!(r.location(), "/login/2fa?err=code");
}

#[tokio::test]
async fn the_reset_command_has_the_documented_name() {
    use clap::CommandFactory;
    let cmd = Cli::command();
    let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
    assert!(names.contains(&"reset-2fa"), "{names:?}");
    assert!(names.contains(&"totp-now"));
    assert!(names.contains(&"set-admin-password"));
}

#[tokio::test]
async fn a_server_clock_hours_off_is_recognised_from_the_browser_clock() {
    let h = hub();
    let cookie = h.sign_in().await;
    h.post("/security/totp/start", &cookie, &pw_form()).await;
    // The page tells the browser this server's time, to compare with its own.
    let page = h.get("/security", &cookie).await;
    assert!(page.body.contains("clock-skew") && page.body.contains("client-ts"));

    // This server runs 107 minutes slow: the phone's code is 214 steps ahead.
    let ahead = 214;
    let code = h.code_at(ahead);
    // Without the browser's time the code fits nowhere near this server's clock.
    let r = h
        .post("/security/totp/confirm", &cookie, &format!("code={code}"))
        .await;
    assert!(
        r.location().starts_with("/security?totp=1&msg="),
        "{}",
        r.location()
    );
    assert!(!h.enrolled());
    // With it, the hub finds the phone's time, enables and keeps the offset.
    let browser = now() + ahead * 30;
    let r = h
        .post(
            "/security/totp/confirm",
            &cookie,
            &format!("code={code}&client_ts={browser}"),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.location());
    assert!(r.body.contains("chậm hơn giờ thật"), "{}", r.body);
    let t = h.st.db.lock().unwrap().totp().unwrap();
    assert!(
        t.enabled && (ahead - 1..=ahead + 1).contains(&t.offset),
        "{}",
        t.offset
    );

    // Signing in with the phone's next code works despite this server's clock.
    let r = h.post("/login", "", &pw_form()).await;
    let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post(
            "/login/2fa",
            &pending,
            &format!("kind=totp&code={}", h.code_at(ahead + 1)),
        )
        .await;
    assert_eq!(r.location(), "/", "{}", r.body);
}

#[tokio::test]
async fn a_browser_clock_that_is_wildly_off_is_not_trusted() {
    let h = hub();
    let cookie = h.sign_in().await;
    h.post("/security/totp/start", &cookie, &pw_form()).await;
    // Three days ahead: beyond what is believable; refused.
    let ahead = 3 * 2880;
    let browser = now() + ahead * 30;
    let r = h
        .post(
            "/security/totp/confirm",
            &cookie,
            &format!("code={}&client_ts={browser}", h.code_at(ahead)),
        )
        .await;
    assert!(r.location().starts_with("/security?totp=1&msg="));
    assert!(!h.enrolled());
}

/// Enrol the authenticator app for the signed-in admin.
async fn enrol_totp(h: &Hub, cookie: &str) {
    h.post("/security/totp/start", cookie, &pw_form()).await;
    let r = h
        .post(
            "/security/totp/confirm",
            cookie,
            &format!("code={}", h.code_at(0)),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.location());
    assert!(h.enrolled());
}

#[tokio::test]
async fn wrong_codes_from_many_addresses_pause_the_second_step_for_everyone() {
    let h = hub();
    let cookie = h.sign_in().await;
    enrol_totp(&h, &cookie).await;
    // Someone who has the password guesses codes, one address per guess, so no
    // per-address limit ever applies.
    let mut pendings = Vec::new();
    for _ in 0..3 {
        let r = h.post("/login", "", &pw_form()).await;
        assert_eq!(r.location(), "/login/2fa");
        pendings.push(r.set_cookie("snhub_2fa").unwrap());
    }
    let wrong = format!("kind=totp&code={}", h.wrong_code());
    let mut n = 0;
    for p in &pendings[..2] {
        for _ in 0..5 {
            n += 1;
            let ip = format!("198.51.100.{n}");
            let cookie = format!("snhub_2fa={p}");
            let r = h
                .send_from(&ip, Method::POST, "/login/2fa", &cookie, &wrong)
                .await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "guess {n}");
        }
    }
    // Ten wrong answers: the step is paused for everyone, the half-finished
    // logins are gone (the third had not been tried yet), and a right password
    // no longer starts a new one.
    assert!(h.st.limiter.factor_paused(now()).is_some());
    assert!(h.st.pending.get(&pendings[2], now()).is_none());
    let r = h.post("/login", "", &pw_form()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.location());
    let right = format!("kind=totp&code={}", h.code_at(1));
    let third = format!("snhub_2fa={}", pendings[2]);
    let r = h
        .send_from("203.0.113.200", Method::POST, "/login/2fa", &third, &right)
        .await;
    assert_ne!(r.location(), "/", "no way in while paused");
    // The signed-in admin is told what happened.
    let page = h.get("/security", &cookie).await;
    assert!(
        page.body.contains("Đã tạm khoá bước sau mật khẩu"),
        "{}",
        page.body
    );
    // The current-password re-check is paused too.
    let r = h.post("/security/recovery/new", &cookie, &pw_form()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

/// Someone with the password guesses second factors until that step is paused.
async fn trip_factor_pause(h: &Hub) {
    let wrong = format!("kind=totp&code={}", h.wrong_code());
    let mut n = 0;
    for _ in 0..2 {
        let r = h.post("/login", "", &pw_form()).await;
        let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
        for _ in 0..5 {
            n += 1;
            let ip = format!("198.51.100.{n}");
            h.send_from(&ip, Method::POST, "/login/2fa", &pending, &wrong)
                .await;
        }
    }
    assert!(h.st.limiter.factor_paused(now()).is_some());
}

#[tokio::test]
async fn a_new_password_from_the_command_line_lifts_the_second_step_pause() {
    let h = hub();
    let cookie = h.sign_in().await;
    enrol_totp(&h, &cookie).await;
    trip_factor_pause(&h).await;
    // The admin, with the right password, is told the way out.
    let r = h.post("/login", "", &pw_form()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.body.contains("snhub set-admin-password"), "{}", r.body);

    // What `snhub set-admin-password` writes, from another process.
    const NEW: &str = "a new and longer passphrase";
    let at = now() - 1;
    {
        let db = h.st.db.lock().unwrap();
        db.set_admin_pw_hash(&auth::hash_password_argon2(NEW), at)
            .unwrap();
        db.revoke_sessions(at).unwrap();
    }
    h.st.sessions.recheck_revocation();
    let r = h
        .post("/login", "", &format!("password={}", web::urlenc(NEW)))
        .await;
    assert_eq!(r.location(), "/login/2fa", "{}", r.body);
    assert_eq!(h.st.limiter.factor_paused(now()), None);
    let pending = format!("snhub_2fa={}", r.set_cookie("snhub_2fa").unwrap());
    let r = h
        .post(
            "/login/2fa",
            &pending,
            &format!("kind=totp&code={}", h.code_at(1)),
        )
        .await;
    assert_eq!(r.location(), "/", "{}", r.body);
    // The old password is worth nothing now.
    assert_eq!(
        h.post("/login", "", &pw_form()).await.location(),
        "/login?err=pw"
    );
}

#[tokio::test]
async fn a_2fa_reset_alone_leaves_the_pause_behind_the_password() {
    let h = hub();
    let cookie = h.sign_in().await;
    enrol_totp(&h, &cookie).await;
    trip_factor_pause(&h).await;
    // What `snhub reset-2fa` writes: the password, set long ago, stays.
    let at = now() - 1;
    {
        let db = h.st.db.lock().unwrap();
        let hash = db.admin_pw_hash().unwrap();
        db.set_admin_pw_hash(&hash, 1).unwrap();
        db.reset_2fa().unwrap();
        db.revoke_sessions(at).unwrap();
    }
    h.st.sessions.recheck_revocation();
    // No second factor is left, so the password signs in...
    let cookie = h.sign_in().await;
    // ...but whoever made those guesses may know it: what needs it again waits.
    assert!(h.st.limiter.factor_paused(now()).is_some());
    let r = h.post("/security/recovery/new", &cookie, &pw_form()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_browser_that_signed_in_before_is_not_locked_out_by_a_flood() {
    let h = hub_with(false);
    let r = h.post("/login", "", &pw_form()).await;
    assert_eq!(r.location(), "/");
    let device = r
        .set_cookie(auth::DEVICE_COOKIE)
        .expect("known-device cookie");
    // Many wrong passwords from all over pause the password step for everyone...
    for _ in 0..100 {
        h.st.limiter.wrong(now());
    }
    let r = h.post("/login", "", &pw_form()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // ...but not for this browser, and a forged cookie does not help.
    let forged = format!("{}=1.ab", auth::DEVICE_COOKIE);
    let r = h.post("/login", &forged, &pw_form()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let known = format!("{}={device}", auth::DEVICE_COOKIE);
    let r = h.post("/login", &known, &pw_form()).await;
    assert_eq!(r.location(), "/", "{}", r.body);
    assert!(r.set_cookie("snhub_session").is_some());
}

#[tokio::test]
async fn a_reset_from_the_command_line_signs_out_the_running_hub() {
    let h = hub_with(false);
    let at = now();
    h.st.sessions
        .insert("before".into(), "1.1.1.1", "UA", "password", at - 20);
    let pending = h.st.pending.create("1.1.1.1", "UA", at - 20);
    // What `snhub set-admin-password` / `reset-2fa` write, from another process.
    h.st.db.lock().unwrap().revoke_sessions(at - 10).unwrap();
    assert_eq!(
        h.get("/", "snhub_session=before").await.location(),
        "/login",
        "an older session is over"
    );
    assert!(h.st.pending.get(&pending, at).is_none());
    // A sign-in after it works.
    let cookie = h.sign_in().await;
    assert_eq!(h.get("/", &cookie).await.status, StatusCode::OK);
}

fn agent_key(h: &Hub) -> (String, ed25519_dalek::SigningKey) {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pubkey = snsec_common::crypto::encode_pubkey(&sk.verifying_key());
    let id =
        h.st.db
            .lock()
            .unwrap()
            .enroll_agent("web-01", &pubkey, now())
            .unwrap();
    (id, sk)
}

fn signed_report(id: &str, sk: &ed25519_dalek::SigningKey, seq: u64) -> String {
    signed_report_with(id, sk, seq, serde_json::json!({}))
}

/// A signed report whose body has `extra`'s fields on top of the bare minimum.
fn signed_report_with(
    id: &str,
    sk: &ed25519_dalek::SigningKey,
    seq: u64,
    extra: serde_json::Value,
) -> String {
    let mut body = serde_json::json!({
        "agent_version": "t",
        "cycle": snsec_common::schema::CycleStats::default(),
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    let env = snsec_common::schema::Envelope {
        schema_version: snsec_common::SCHEMA_VERSION,
        agent_id: id.to_string(),
        epoch: 1,
        seq,
        issued_at: now(),
        expires_at: now() + 3600,
        body,
    };
    serde_json::to_string(&snsec_common::crypto::sign(sk, id, &env).unwrap()).unwrap()
}

impl Hub {
    async fn post_report(&self, body: String) -> Reply {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/report")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        self.request(req).await
    }
}

#[tokio::test]
async fn reports_are_bounded_in_size_rate_and_history() {
    let h = hub_with(false);
    let (id, sk) = agent_key(&h);
    // New ids carry 128 random bits.
    assert!(id.starts_with("web-01-"), "{id}");
    assert_eq!(id.rsplit('-').next().unwrap().len(), 32, "{id}");

    let r = h.post_report(signed_report(&id, &sk, 1)).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "ok"));
    let r = h.post_report(signed_report(&id, &sk, 1)).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "duplicate"));
    // A queue flushed after an outage goes through at once...
    for seq in 2..=60 {
        let r = h.post_report(signed_report(&id, &sk, seq)).await;
        assert_eq!(r.status, StatusCode::OK, "seq {seq}: {}", r.body);
    }
    // ...but a flood is turned away, and what was refused is not stored, so the
    // agent keeps it and sends it later.
    let r = h.post_report(signed_report(&id, &sk, 61)).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    {
        let db = h.st.db.lock().unwrap();
        assert_eq!(db.last_report_seq(&id).unwrap(), 60);
        let kept: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM reports WHERE agent_id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, 10);
    }
    // A body over the limit is refused before anything reads it.
    let r = h.post_report("x".repeat(AGENT_BODY_LIMIT + 1)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // A report signed by another key is refused as before.
    let (_, other) = agent_key(&h);
    let r = h.post_report(signed_report(&id, &other, 62)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_report_from_an_agent_watching_a_botnet_wave_still_gets_in() {
    let h = hub_with(false);
    let (id, sk) = agent_key(&h);
    // Agents deployed so far list every would-be ban of a cycle: in observe mode
    // a wave of some 12,000 addresses makes a report past 1 MiB.
    let would: Vec<serde_json::Value> = (0..12_000u32)
        .map(|n| {
            serde_json::json!({
                "ip": format!("198.{}.{}.{}", 18 + n / 65_536, (n / 256) % 256, n % 256),
                "reason": "rate", "ttl_secs": 3600, "strike": 1, "layer": "l3",
            })
        })
        .collect();
    let report = signed_report_with(&id, &sk, 1, serde_json::json!({ "would_ban": would }));
    assert!(report.len() > 1024 * 1024, "{}", report.len());
    assert!(report.len() < AGENT_BODY_LIMIT, "{}", report.len());
    let r = h.post_report(report).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "ok"));
    let stored = h.st.db.lock().unwrap().latest_report(&id).unwrap().unwrap();
    assert_eq!(stored.would_ban.len(), 12_000);
}

#[tokio::test]
async fn a_ban_order_holds_one_address_or_nothing() {
    let h = hub_with(false);
    let cookie = h.sign_in().await;
    let (id, _) = agent_key(&h);
    let orders = |h: &Hub| {
        let d = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap().2;
        let bans: Vec<String> = d.bans.iter().map(|b| b.ip.clone()).collect();
        (bans, d.unbans)
    };
    for bad in [
        "1.2.3.4 }; flush ruleset; add element inet sn sn_ban4 { 5.6.7.8",
        "::/0",
        "127.0.0.1",
        "0.0.0.0",
        "hunt",
    ] {
        let form = format!("ip={}&ttl=3600", web::urlenc(bad));
        let r = h.post(&format!("/agent/{id}/ban"), &cookie, &form).await;
        assert!(r.location().contains("at=ctl"), "{bad}: {}", r.location());
        let form = format!("ip={}", web::urlenc(bad));
        let r = h.post(&format!("/agent/{id}/unban"), &cookie, &form).await;
        assert!(r.location().contains("at=ctl"), "{bad}");
    }
    assert_eq!(orders(&h), (vec![], vec![]), "nothing was stored");
    // The page says why.
    let r = h
        .post(&format!("/agent/{id}/ban"), &cookie, "ip=127.0.0.1")
        .await;
    let page = h
        .get(r.location().split('#').next().unwrap(), &cookie)
        .await;
    assert!(
        page.body.contains("cần đúng một địa chỉ IP"),
        "{}",
        page.body
    );

    // Good input is stored in its canonical form.
    let form = format!("ip={}&ttl=60", web::urlenc("::ffff:203.0.113.7"));
    h.post(&format!("/agent/{id}/ban"), &cookie, &form).await;
    let form = format!("ip={}", web::urlenc("2001:DB8:1:2::9/64"));
    h.post(&format!("/agent/{id}/unban"), &cookie, &form).await;
    assert_eq!(
        orders(&h),
        (
            vec!["203.0.113.7".to_string()],
            vec!["2001:db8:1:2::/64".to_string()]
        )
    );
}

#[tokio::test]
async fn an_ipv6_top_talker_is_banned_by_the_64_the_vps_lists_it_under() {
    let h = hub_with(false);
    let cookie = h.sign_in().await;
    let (id, sk) = agent_key(&h);
    let cycle = snsec_common::schema::CycleStats {
        top_ips: vec![snsec_common::schema::IpCount {
            ip: "2001:db8:1:2::/64".into(),
            requests: 9_000,
            err4xx: 0,
            sensitive_posts: 0,
        }],
        ..Default::default()
    };
    let r = h
        .post_report(signed_report_with(
            &id,
            &sk,
            1,
            serde_json::json!({ "cycle": cycle }),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // The "Chặn" button next to it posts the /64...
    let page = h.get(&format!("/agent/{id}"), &cookie).await;
    assert!(
        page.body.contains(r#"name="ip" value="2001:db8:1:2::/64""#),
        "{}",
        page.body
    );
    // ...and the order stores it.
    let r = h
        .post(
            &format!("/agent/{id}/ban"),
            &cookie,
            &format!("ip={}&ttl=3600", web::urlenc("2001:db8:1:2::/64")),
        )
        .await;
    assert_eq!(r.location(), format!("/agent/{id}"));
    let d = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap().2;
    let bans: Vec<&str> = d.bans.iter().map(|b| b.ip.as_str()).collect();
    assert_eq!(bans, ["2001:db8:1:2::/64"]);
    assert_eq!(d.bans[0].ttl_secs, 3600);
}

#[tokio::test]
async fn free_text_stored_by_an_older_hub_never_reaches_an_agent() {
    let h = hub_with(false);
    let cookie = h.sign_in().await;
    let (id, _) = agent_key(&h);
    let junk = "1.2.3.4 }; flush ruleset";
    let body = serde_json::json!({
        "mode": "observe",
        "bans": [
            { "ip": junk, "ttl_secs": 3600, "reason": "admin", "created_at": now() },
            { "ip": "203.0.113.9", "ttl_secs": 3600, "reason": "admin", "created_at": now() },
        ],
        "unbans": [junk, "2001:db8:1:2::/64"],
    });
    h.st.db
        .lock()
        .unwrap()
        .conn
        .execute(
            "UPDATE desired SET body_json = ?1 WHERE agent_id = ?2",
            [body.to_string(), id.clone()],
        )
        .unwrap();
    let r = h.get(&format!("/v1/desired?agent_id={id}"), "").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!r.body.contains("flush ruleset"), "{}", r.body);
    assert!(r.body.contains("203.0.113.9") && r.body.contains("2001:db8:1:2::/64"));
    // The next order is written without it, so later versions cannot carry it.
    h.post(&format!("/agent/{id}/mode"), &cookie, "mode=enforce")
        .await;
    let json: String =
        h.st.db
            .lock()
            .unwrap()
            .conn
            .query_row(
                "SELECT body_json FROM desired WHERE agent_id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
    assert!(!json.contains("flush ruleset"), "{json}");
    assert!(json.contains("enforce") && json.contains("203.0.113.9"));
}

#[tokio::test]
async fn an_ai_key_needs_the_password_and_does_not_follow_a_new_host() {
    let h = hub_with(false);
    let cookie = h.sign_in().await;
    let form = |endpoint: &str, key: &str, pw: &str| {
        format!(
            "name=H&kind=openai&endpoint={}&model=m&api_key={key}&password={}",
            web::urlenc(endpoint),
            web::urlenc(pw)
        )
    };
    let providers = |h: &Hub| h.st.db.lock().unwrap().list_providers().unwrap();
    // Saving needs the current password.
    let r = h
        .post(
            "/settings/provider",
            &cookie,
            &form("http://127.0.0.1:1/v1", "sk-secret-1", "wrong password"),
        )
        .await;
    assert!(
        r.location().starts_with("/settings?msg="),
        "{}",
        r.location()
    );
    assert!(providers(&h).is_empty());
    h.post(
        "/settings/provider",
        &cookie,
        &form("http://127.0.0.1:1/v1", "sk-secret-1", PW),
    )
    .await;
    let p = providers(&h).pop().expect("saved");
    assert_eq!(p.api_key, "sk-secret-1");
    // Pointing it elsewhere without typing the key again is refused.
    let edit = |endpoint: &str| format!("id={}&{}", p.id, form(endpoint, "", PW));
    let r = h
        .post(
            "/settings/provider",
            &cookie,
            &edit("https://evil.example/v1"),
        )
        .await;
    let page = h.get(&r.location(), &cookie).await;
    assert!(page.body.contains("nhập lại API key"), "{}", page.body);
    let stored = providers(&h).pop().unwrap();
    assert_eq!(
        (stored.endpoint.as_str(), stored.api_key.as_str()),
        ("http://127.0.0.1:1/v1", "sk-secret-1")
    );
    // The same host with another path keeps it.
    h.post(
        "/settings/provider",
        &cookie,
        &edit("http://127.0.0.1:1/v2"),
    )
    .await;
    let stored = providers(&h).pop().unwrap();
    assert_eq!(
        (stored.endpoint.as_str(), stored.api_key.as_str()),
        ("http://127.0.0.1:1/v2", "sk-secret-1")
    );
    // A connection test needs the password too.
    let test = format!("/settings/provider/{}/test", p.id);
    let r = h.post(&test, &cookie, "password=").await;
    let page = h.get(&r.location(), &cookie).await;
    assert!(
        page.body.contains("Mật khẩu hiện tại không đúng"),
        "{}",
        page.body
    );
}

#[cfg(unix)]
#[test]
fn the_database_and_its_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;
    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = data.join("snhub.sqlite");
    drop(Db::open(&path).unwrap());
    assert_eq!(mode(&path), 0o600, "created private");
    // One an older version left readable is tightened when opened.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(Db::open(&path).unwrap());
    assert_eq!(mode(&path), 0o600);
    // The data directory goes to 0700 when it holds only the hub's files...
    HubKey::load_or_create(&data).unwrap();
    std::fs::create_dir_all(data.join("public")).unwrap();
    lock_data_dir(&data);
    assert_eq!(mode(&data), 0o700);
    // ...and is left alone when it holds anything else.
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(shared.join("other.txt"), b"x").unwrap();
    lock_data_dir(&shared);
    assert_eq!(mode(&shared), 0o755);
}

#[tokio::test]
async fn the_install_command_for_a_new_vps_carries_no_token() {
    let h = hub();
    let cookie = h.sign_in().await;
    let r = h.post("/add-vps", &cookie, "name=web-01").await;
    assert_eq!(r.status, StatusCode::OK);
    let cmd = r
        .body
        .split("<pre>")
        .nth(1)
        .and_then(|s| s.split("</pre>").next())
        .unwrap()
        .to_string();
    assert_eq!(
        cmd,
        "curl -fsSL https://sec.example.test/install.sh | sudo sh -s -- --hub https://sec.example.test --name web-01"
    );
    // The token is on the page, apart from the command.
    let token = r
        .body
        .split("user-select:all;font-size:16px\">")
        .nth(1)
        .and_then(|s| s.split("</pre>").next())
        .unwrap();
    assert!(token.len() >= 32 && !cmd.contains(token));
    // A name that is not a plain word is quoted for the shell.
    let r = h.post("/add-vps", &cookie, "name=a%3B+rm+-rf+%2F").await;
    assert!(
        r.body.contains("--name &#39;a; rm -rf /&#39;") || r.body.contains("--name 'a; rm -rf /'"),
        "{}",
        r.body
    );
}

#[test]
fn shell_words_are_quoted_only_when_needed() {
    assert_eq!(web::sh_quote("web-01.example"), "web-01.example");
    assert_eq!(web::sh_quote("a b"), "'a b'");
    assert_eq!(web::sh_quote("it's"), r"'it'\''s'");
    assert_eq!(web::sh_quote("$(id)"), "'$(id)'");
    assert_eq!(web::sh_quote("-x"), "'-x'");
    assert_eq!(web::sh_quote(""), "''");
}

#[path = "flow_tests_mcp.rs"]
mod mcp_flow;
