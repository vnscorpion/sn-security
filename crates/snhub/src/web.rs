//! Server-rendered admin UI (HTMX-ready, but plain forms for v1). maud
//! autoescapes all interpolated values, so attacker-controlled strings from
//! reports (paths, user-agents, process names) cannot inject markup.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;
use snsec_common::schema::{DesiredBan, Mode};

use crate::AppState;
use crate::auth;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const STYLE: &str = r#"
:root{--bg:#0f1419;--card:#1a2129;--fg:#e6e9ee;--mut:#8b98a8;--line:#2a333d;--acc:#4ca3ff;--bad:#ff5c5c;--warn:#ffb020;--ok:#3ecf8e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;align-items:center;gap:16px;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--card)}
header .brand{font-weight:700}main{max-width:1100px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
h1{font-size:20px;margin:0 0 12px}h2{font-size:16px;margin:0 0 10px;color:var(--mut)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px}
.ok{background:rgba(62,207,142,.15);color:var(--ok)}.stale{background:rgba(255,176,32,.15);color:var(--warn)}
.off{background:rgba(255,92,92,.15);color:var(--bad)}.mut{color:var(--mut)}
input,select,button{font:inherit;padding:6px 10px;border-radius:8px;border:1px solid var(--line);background:#0d1218;color:var(--fg)}
button{background:var(--acc);color:#04121f;border:0;cursor:pointer;font-weight:600}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button.danger{background:var(--bad);color:#2a0606}
form.inline{display:inline-flex;gap:6px;align-items:center;margin:0}
code{background:#0d1218;padding:2px 6px;border-radius:6px}
pre{background:#0d1218;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.row{display:flex;gap:16px;flex-wrap:wrap}.row>*{flex:1 1 240px}
.kv{color:var(--mut)}.big{font-size:22px;font-weight:700}
"#;

fn shell(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="vi" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "SN Secure — " (title) }
                style { (maud::PreEscaped(STYLE)) }
            }
            body {
                header {
                    span class="brand" { "🛡 SN Secure" }
                    a href="/" { "Tổng quan" }
                    a href="/add-vps" { "Thêm VPS" }
                    a href="/log" { "Nhật ký" }
                    span style="flex:1" {}
                    a href="/logout" { "Đăng xuất" }
                }
                main { (body) }
            }
        }
    }
}

/// Returns `Some(redirect)` when the request is not authenticated; the caller
/// returns it immediately. `None` means the session is valid.
fn guard(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    match auth::session_from_headers(headers) {
        Some(tok) if st.sessions.valid(&tok) => None,
        _ => Some(Redirect::to("/login").into_response()),
    }
}

fn rel_time(ts: i64) -> String {
    if ts == 0 {
        return "chưa bao giờ".into();
    }
    let d = (now() - ts).max(0);
    if d < 90 {
        format!("{d}s trước")
    } else if d < 5400 {
        format!("{}m trước", d / 60)
    } else if d < 172_800 {
        format!("{}h trước", d / 3600)
    } else {
        format!("{} ngày trước", d / 86_400)
    }
}

fn status_pill(last_seen: i64) -> Markup {
    let d = now() - last_seen;
    if last_seen == 0 || d > 3 * 900 {
        html! { span class="pill off" { "mất liên lạc" } }
    } else if d > 2 * 900 {
        html! { span class="pill stale" { "chậm" } }
    } else {
        html! { span class="pill ok" { "online" } }
    }
}

// ---- login ----------------------------------------------------------------

pub async fn login_page() -> Html<String> {
    Html(
        shell(
            "Đăng nhập",
            html! {
                div class="card" style="max-width:360px;margin:60px auto" {
                    h1 { "Đăng nhập" }
                    form method="post" action="/login" {
                        p { input type="password" name="password" placeholder="Mật khẩu admin" style="width:100%" autofocus; }
                        button type="submit" { "Vào" }
                    }
                    p class="mut" { "Đặt mật khẩu bằng: " code { "snhub set-admin-password" } }
                }
            },
        )
        .into_string(),
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

pub async fn login_post(State(st): State<Arc<AppState>>, Form(f): Form<LoginForm>) -> Response {
    if st.cfg.admin_password_sha256.is_empty() {
        return Html("Chưa đặt mật khẩu admin. Chạy: snhub set-admin-password".to_string())
            .into_response();
    }
    let got = auth::hash_password(&st.cfg.admin_salt, &f.password);
    if !auth::ct_eq(&got, &st.cfg.admin_password_sha256) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(
                shell(
                    "Đăng nhập",
                    html! {
                        div class="card" style="max-width:360px;margin:60px auto" {
                            h1 { "Sai mật khẩu" }
                            a href="/login" { "Thử lại" }
                        }
                    },
                )
                .into_string(),
            ),
        )
            .into_response();
    }
    let token = auth::new_session_token();
    st.sessions.insert(token.clone());
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400",
        auth::COOKIE,
        token
    );
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(tok) = auth::session_from_headers(&headers) {
        st.sessions.remove(&tok);
    }
    let clear = format!("{}=; Path=/; Max-Age=0", auth::COOKIE);
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/login")
        .header(header::SET_COOKIE, clear)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ---- overview --------------------------------------------------------------

pub async fn overview(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let agents = db.list_agents().unwrap_or_default();
    let rows: Vec<_> = agents
        .iter()
        .map(|a| {
            let rep = db.latest_report(&a.id).ok().flatten();
            let (req, bans, alerts, load) = rep
                .as_ref()
                .map(|r| {
                    (
                        r.cycle.requests,
                        r.bans.len(),
                        r.alerts.len(),
                        r.cycle.load1,
                    )
                })
                .unwrap_or((0, 0, 0, 0.0));
            (a.clone(), req, bans, alerts, load)
        })
        .collect();
    drop(db);

    let body = html! {
        h1 { "Tổng quan — " (rows.len()) " VPS" }
        div class="card" {
            table {
                thead { tr {
                    th { "Tên" } th { "Trạng thái" } th { "Chế độ" } th { "Load" }
                    th { "Req/chu kỳ" } th { "Ban" } th { "Cảnh báo" } th { "Phiên bản" } th { "Báo cáo cuối" }
                }}
                tbody {
                    @if rows.is_empty() {
                        tr { td colspan="9" class="mut" { "Chưa có VPS nào. " a href="/add-vps" { "Thêm VPS" } "." } }
                    }
                    @for (a, req, bans, alerts, load) in &rows {
                        tr {
                            td { a href={"/agent/" (a.id)} { (a.name) } br; span class="mut" { (a.id) } }
                            td { (status_pill(a.last_seen)) }
                            td { @if a.mode == "enforce" { span class="pill ok" { "enforce" } } @else { span class="pill stale" { "observe" } } }
                            td { (format!("{:.2}", load)) }
                            td { (req) }
                            td { @if *bans > 0 { span class="pill off" { (bans) } } @else { "0" } }
                            td { @if *alerts > 0 { span class="pill stale" { (alerts) } } @else { "0" } }
                            td class="mut" { (a.version) }
                            td class="mut" { (rel_time(a.last_seen)) }
                        }
                    }
                }
            }
        }
    };
    Html(shell("Tổng quan", body).into_string()).into_response()
}

// ---- agent detail ----------------------------------------------------------

pub async fn agent_detail(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let Some(agent) = db.agent(&id).ok().flatten() else {
        return (StatusCode::NOT_FOUND, "VPS không tồn tại").into_response();
    };
    let report = db.latest_report(&id).ok().flatten();
    let desired = db.get_desired(&id).ok().flatten();
    drop(db);

    let mode = desired
        .as_ref()
        .map(|(_, _, b)| b.mode)
        .unwrap_or(Mode::Observe);

    let body = html! {
        p { a href="/" { "← Tổng quan" } }
        h1 { (agent.name) " " (status_pill(agent.last_seen)) }
        p class="mut" { code { (agent.id) } " · phiên bản " (agent.version) " · báo cáo cuối " (rel_time(agent.last_seen)) }

        div class="card" {
            h2 { "Điều khiển" }
            form class="inline" method="post" action={"/agent/" (agent.id) "/mode"} {
                "Chế độ: "
                select name="mode" {
                    option value="observe" selected[mode==Mode::Observe] { "observe (chỉ báo)" }
                    option value="enforce" selected[mode==Mode::Enforce] { "enforce (ban thật)" }
                }
                button type="submit" { "Áp dụng" }
            }
            span class="mut" { "  —  áp dụng ở chu kỳ kế tiếp (≤ 15 phút)." }
            hr style="border-color:var(--line)";
            form class="inline" method="post" action={"/agent/" (agent.id) "/ban"} {
                "Ban IP: " input type="text" name="ip" placeholder="1.2.3.4" required;
                "TTL(s): " input type="number" name="ttl" value="3600" style="width:90px";
                button type="submit" { "Ban" }
            }
            "  "
            form class="inline" method="post" action={"/agent/" (agent.id) "/unban"} {
                "Gỡ ban: " input type="text" name="ip" placeholder="1.2.3.4" required;
                button class="ghost" type="submit" { "Unban" }
            }
        }

        @if let Some(r) = &report {
            div class="row" {
                div class="card" { div class="kv" { "Request/chu kỳ" } div class="big" { (r.cycle.requests) } }
                div class="card" { div class="kv" { "Load 1m" } div class="big" { (format!("{:.2}", r.cycle.load1)) } }
                div class="card" { div class="kv" { "CPU busy" } div class="big" { (format!("{:.0}%", r.cycle.cpu_busy_pct)) } }
                div class="card" { div class="kv" { "Ban chu kỳ" } div class="big" { (r.bans.len()) } }
            }

            @if !r.alerts.is_empty() {
                div class="card" {
                    h2 { "Cảnh báo" }
                    @for al in &r.alerts {
                        p { span class="pill off" { (al.severity) } " " strong { (al.kind) } " — " (al.message) }
                    }
                }
            }

            div class="card" {
                h2 { "Top IP" }
                table {
                    thead { tr { th { "IP" } th { "Request" } th { "4xx" } th { "POST nhạy cảm" } th {} } }
                    tbody {
                        @if r.cycle.top_ips.is_empty() { tr { td colspan="5" class="mut" { "—" } } }
                        @for ip in &r.cycle.top_ips {
                            tr {
                                td { code { (ip.ip) } }
                                td { (ip.requests) }
                                td { (ip.err4xx) }
                                td { (ip.sensitive_posts) }
                                td {
                                    form class="inline" method="post" action={"/agent/" (agent.id) "/ban"} {
                                        input type="hidden" name="ip" value=(ip.ip);
                                        input type="hidden" name="ttl" value="3600";
                                        button class="danger" type="submit" { "Ban" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            @if !r.bans.is_empty() {
                div class="card" {
                    h2 { "Đã ban chu kỳ này" }
                    table {
                        thead { tr { th { "IP" } th { "Lý do" } th { "TTL" } th { "Strike" } th { "Tầng" } } }
                        tbody { @for b in &r.bans {
                            tr { td { code { (b.ip) } } td { (b.reason) } td { (b.ttl_secs) "s" } td { (b.strike) } td { (b.layer) } }
                        }}
                    }
                }
            }

            @if let Some(t) = &r.triage {
                div class="card" {
                    h2 { "Triage — nhãn " span class="pill off" { (t.label) } }
                    table {
                        thead { tr { th { "PID" } th { "CPU%" } th { "Process" } th { "Exe" } th { "User" } th { "Score" } } }
                        tbody { @for p in &t.top_processes {
                            tr { td { (p.pid) } td { (format!("{:.1}", p.cpu_pct)) } td { (p.comm) } td { code { (p.exe) } } td { (p.user) } td { (p.score) } }
                        }}
                    }
                    @if !t.persistence.is_empty() {
                        h2 style="margin-top:12px" { "Persistence" }
                        @for h in &t.persistence { p class="mut" { (h) } }
                    }
                }
            }

            @if !r.findings.is_empty() {
                div class="card" {
                    h2 { "Findings" }
                    table {
                        thead { tr { th { "Score" } th { "Verdict" } th { "Path" } th { "Rules" } } }
                        tbody { @for f in &r.findings {
                            tr { td { (f.score) } td { (f.verdict) } td { code { (f.path) } } td class="mut" { (f.rules.join(", ")) } }
                        }}
                    }
                }
            }
        } @else {
            div class="card mut" { "Chưa có báo cáo nào từ VPS này." }
        }
    };
    Html(shell(&agent.name, body).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct BanForm {
    ip: String,
    #[serde(default)]
    ttl: Option<u64>,
}

pub async fn ban_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<BanForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let ttl = f.ttl.unwrap_or(3600).min(24 * 3600);
    let ip = f.ip.trim().to_string();
    let db = st.db.lock().expect("db");
    let _ = db.update_desired(&id, now(), "admin", "ban", &ip, |d| {
        d.unbans.retain(|x| x != &ip);
        d.bans.push(DesiredBan {
            ip: ip.clone(),
            ttl_secs: ttl,
            reason: "admin".into(),
        });
    });
    drop(db);
    Redirect::to(&format!("/agent/{id}")).into_response()
}

pub async fn unban_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<BanForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let ip = f.ip.trim().to_string();
    let db = st.db.lock().expect("db");
    let _ = db.update_desired(&id, now(), "admin", "unban", &ip, |d| {
        d.bans.retain(|b| b.ip != ip);
        if !d.unbans.contains(&ip) {
            d.unbans.push(ip.clone());
        }
    });
    drop(db);
    Redirect::to(&format!("/agent/{id}")).into_response()
}

#[derive(Deserialize)]
pub struct ModeForm {
    mode: String,
}

pub async fn mode_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ModeForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let mode = if f.mode == "enforce" {
        Mode::Enforce
    } else {
        Mode::Observe
    };
    let db = st.db.lock().expect("db");
    let _ = db.update_desired(&id, now(), "admin", "mode", mode.as_str(), |d| {
        d.mode = mode;
    });
    drop(db);
    Redirect::to(&format!("/agent/{id}")).into_response()
}

// ---- add vps ---------------------------------------------------------------

pub async fn add_vps_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    Html(
        shell(
            "Thêm VPS",
            html! {
                h1 { "Thêm VPS" }
                div class="card" {
                    p class="mut" { "Nhập tên gợi nhớ, hub sẽ sinh một token dùng một lần (hết hạn 15 phút) và lệnh cài." }
                    form method="post" action="/add-vps" {
                        input type="text" name="name" placeholder="vd: web-01" required;
                        button type="submit" { "Sinh lệnh cài" }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct AddVpsForm {
    name: String,
}

pub async fn add_vps_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<AddVpsForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let token = match db.create_enroll_token(f.name.trim(), now(), 900) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    drop(db);

    let base = if st.cfg.public_url.is_empty() {
        format!("http://{}", st.cfg.bind)
    } else {
        st.cfg.public_url.trim_end_matches('/').to_string()
    };
    let install = format!(
        "curl -fsSL {base}/install.sh | sudo sh -s -- --hub {base} --name {name} --token {token}",
        name = f.name.trim(),
    );
    Html(
        shell(
            "Lệnh cài",
            html! {
                p { a href="/add-vps" { "← Thêm VPS khác" } }
                h1 { "Lệnh cài cho " (f.name) }
                div class="card" {
                    p class="mut" { "Dán lệnh sau vào VPS (chạy bằng root). Token hết hạn sau 15 phút." }
                    pre { (install) }
                }
                p { a href="/" { "Về tổng quan" } }
            },
        )
        .into_string(),
    )
    .into_response()
}

// ---- log -------------------------------------------------------------------

pub async fn log_page(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let decisions = db.recent_decisions(200).unwrap_or_default();
    drop(db);
    let body = html! {
        h1 { "Nhật ký quyết định" }
        div class="card" {
            table {
                thead { tr { th { "Thời gian" } th { "VPS" } th { "Ai" } th { "Hành động" } th { "Chi tiết" } } }
                tbody {
                    @if decisions.is_empty() { tr { td colspan="5" class="mut" { "—" } } }
                    @for (agent, who, action, detail, ts) in &decisions {
                        tr { td class="mut" { (rel_time(*ts)) } td { (agent) } td { (who) } td { (action) } td { (detail) } }
                    }
                }
            }
        }
    };
    Html(shell("Nhật ký", body).into_string()).into_response()
}
