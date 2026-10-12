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
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "sec.example.test")
            .header("sec-fetch-site", "same-origin");
        if !cookie.is_empty() {
            b = b.header(header::COOKIE, cookie);
        }
        let body = if form.is_empty() {
            Body::empty()
        } else {
            b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form.to_string())
        };
        let resp = self
            .app
            .clone()
            .oneshot(b.body(body).unwrap())
            .await
            .unwrap();
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
    assert!(r.body.contains("lệch khoảng"), "the admin is told");
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
