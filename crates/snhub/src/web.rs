//! Server-rendered admin UI. maud autoescapes every interpolated value, so
//! attacker-controlled strings from reports (paths, user-agents, process names)
//! cannot inject markup. Wording is plain Vietnamese with short explanations of
//! the few technical terms; routes and form field names are unchanged.

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
:root{
 --bg:#0e1116;--card:#161b22;--card2:#1b222c;--fg:#e8ecf1;--mut:#9aa7b4;
 --line:#273039;--acc:#4ca3ff;--acc-ink:#04121f;--bad:#ff6b6b;--warn:#ffc34d;--ok:#45d19a;
 --radius:12px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:18px;
 padding:12px 20px;border-bottom:1px solid var(--line);background:rgba(14,17,22,.9);
 backdrop-filter:blur(8px)}
header .brand{font-weight:800;letter-spacing:.2px;margin-right:4px}
header nav{display:flex;gap:16px;flex-wrap:wrap}
header .sp{flex:1}
main{max-width:1120px;margin:0 auto;padding:22px 16px 60px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:14px;margin:0 0 12px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.sub{color:var(--mut);margin:0 0 18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:18px;margin-bottom:16px}
.help{color:var(--mut);font-size:13px;margin:6px 0 0}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:520px}
th,td{text-align:left;padding:10px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--card2)}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.b-ok{background:rgba(69,209,154,.16);color:var(--ok)}
.b-warn{background:rgba(255,195,77,.16);color:var(--warn)}
.b-bad{background:rgba(255,107,107,.16);color:var(--bad)}
.b-mut{background:rgba(154,167,180,.16);color:var(--mut)}
.mut{color:var(--mut)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px}
.stat .n{font-size:26px;font-weight:800;line-height:1.1}
.stat .l{color:var(--mut);font-size:13px;margin-top:2px}
input,select,button,textarea{font:inherit;padding:8px 12px;border-radius:9px;border:1px solid var(--line);
 background:#0d1218;color:var(--fg)}
input:focus,select:focus{outline:2px solid rgba(76,163,255,.4);border-color:var(--acc)}
button{background:var(--acc);color:var(--acc-ink);border:0;cursor:pointer;font-weight:700}
button:hover{filter:brightness(1.07)}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button.bad{background:var(--bad);color:#2a0606}
label.f{display:block}
label.f .t{display:block;color:var(--mut);font-size:12px;margin-bottom:5px}
.ctrls{display:flex;gap:22px;flex-wrap:wrap;align-items:flex-end}
.ctrls form{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin:0}
.divider{height:1px;background:var(--line);border:0;margin:16px 0}
code{background:#0d1218;padding:2px 7px;border-radius:6px;font-size:13px;word-break:break-all}
pre{background:#0d1218;padding:14px;border-radius:9px;overflow:auto;white-space:pre-wrap;word-break:break-all;
 border:1px solid var(--line)}
.empty{color:var(--mut);text-align:center;padding:26px 10px}
.note{background:var(--card2);border:1px solid var(--line);border-left:3px solid var(--acc);
 border-radius:8px;padding:12px 14px;color:var(--mut);font-size:13px;margin-bottom:16px}
"#;

fn shell(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="vi" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="dark";
                title { "SN Secure — " (title) }
                style { (maud::PreEscaped(STYLE)) }
            }
            body {
                header {
                    span class="brand" { "🛡 SN Secure" }
                    nav {
                        a href="/" { "Tổng quan" }
                        a href="/add-vps" { "Thêm VPS" }
                        a href="/log" { "Nhật ký" }
                    }
                    span class="sp" {}
                    a href="/logout" { "Đăng xuất" }
                }
                main { (body) }
            }
        }
    }
}

fn guard(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    match auth::session_from_headers(headers) {
        Some(tok) if st.sessions.valid(&tok) => None,
        _ => Some(Redirect::to("/login").into_response()),
    }
}

fn rel_time(ts: i64) -> String {
    if ts == 0 {
        return "chưa có".into();
    }
    let d = (now() - ts).max(0);
    if d < 90 {
        format!("{d} giây trước")
    } else if d < 5400 {
        format!("{} phút trước", d / 60)
    } else if d < 172_800 {
        format!("{} giờ trước", d / 3600)
    } else {
        format!("{} ngày trước", d / 86_400)
    }
}

/// online if a report arrived within 2 cycles; stale up to 3; else offline.
fn is_online(last_seen: i64) -> bool {
    last_seen != 0 && (now() - last_seen) <= 2 * 900
}

fn status_badge(last_seen: i64) -> Markup {
    let d = now() - last_seen;
    if last_seen == 0 || d > 3 * 900 {
        html! { span class="badge b-bad" { "Mất kết nối" } }
    } else if d > 2 * 900 {
        html! { span class="badge b-warn" { "Chậm" } }
    } else {
        html! { span class="badge b-ok" { "Đang hoạt động" } }
    }
}

fn mode_badge(mode: &str) -> Markup {
    if mode == "enforce" {
        html! { span class="badge b-ok" { "Chặn tự động" } }
    } else {
        html! { span class="badge b-warn" { "Chỉ theo dõi" } }
    }
}

/// Plain-Vietnamese names for the triage label.
fn label_vi(l: &str) -> &'static str {
    match l {
        "miner" => "Đào coin (chiếm CPU)",
        "php-bot" => "Mã độc PHP",
        "ddos-l7" => "Tấn công web (L7)",
        "bruteforce" => "Dò mật khẩu",
        "disk-full" => "Đầy ổ đĩa",
        "mixed" => "Nhiều dấu hiệu",
        _ => "Chưa rõ",
    }
}

fn verdict_vi(v: &str) -> &'static str {
    match v {
        "malicious" => "Độc hại",
        "suspicious" => "Nghi ngờ",
        "encoded-commercial" => "Mã hoá (hợp lệ)",
        "clean" => "Sạch",
        _ => "Khác",
    }
}

fn reason_vi(r: &str) -> &'static str {
    match r {
        "bruteforce" => "Dò mật khẩu",
        "probe" => "Dò lỗ hổng",
        "scanner" => "Quét tự động",
        "bad_ua" => "Công cụ tấn công",
        "rate" => "Truy cập bất thường",
        "ddos-l7-flood" => "Flood web",
        "hub" => "Admin đặt",
        "xmlrpc_pingback" => "xmlrpc pingback",
        _ => "Khác",
    }
}

fn alert_kind_vi(k: &str) -> &str {
    match k {
        "ban_cap" => "Chặn quá nhiều trong một lần quét (nghi tấn công diện rộng)",
        "watch_blind" => "Có truy cập web nhưng không đọc được log",
        _ => k,
    }
}

fn action_vi(a: &str) -> &str {
    match a {
        "ban" => "Chặn IP",
        "unban" => "Gỡ chặn IP",
        "mode" => "Đổi chế độ",
        "job" => "Lệnh một lần",
        other => other,
    }
}

fn severity_cls(s: &str) -> &'static str {
    match s {
        "urgent" => "b-bad",
        "warn" => "b-warn",
        _ => "b-mut",
    }
}

fn severity_vi(s: &str) -> &'static str {
    match s {
        "urgent" => "Khẩn",
        "warn" => "Cảnh báo",
        _ => "Thông tin",
    }
}

// ---- login ----------------------------------------------------------------

fn login_shell(title: &str, inner: Markup) -> String {
    shell(
        title,
        html! {
            div class="card" style="max-width:380px;margin:8vh auto" {
                (inner)
            }
        },
    )
    .into_string()
}

pub async fn login_page() -> Html<String> {
    Html(login_shell(
        "Đăng nhập",
        html! {
            h1 { "Đăng nhập" }
            p class="sub" { "Trung tâm quản lý bảo mật VPS." }
            form method="post" action="/login" {
                label class="f" {
                    span class="t" { "Mật khẩu quản trị" }
                    input type="password" name="password" style="width:100%" autofocus;
                }
                p { button type="submit" { "Đăng nhập" } }
            }
            p class="help" { "Chưa có mật khẩu? Trên máy chủ chạy: " code { "snhub set-admin-password --password '...'" } }
        },
    ))
}

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

pub async fn login_post(State(st): State<Arc<AppState>>, Form(f): Form<LoginForm>) -> Response {
    if st.cfg.admin_password_sha256.is_empty() {
        return Html(login_shell(
            "Đăng nhập",
            html! {
                h1 { "Chưa đặt mật khẩu" }
                p class="help" { "Trên máy chủ chạy: " code { "snhub set-admin-password --password '...'" } " rồi " code { "systemctl restart snhub" } "." }
            },
        ))
        .into_response();
    }
    let got = auth::hash_password(&st.cfg.admin_salt, &f.password);
    if !auth::ct_eq(&got, &st.cfg.admin_password_sha256) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(login_shell(
                "Đăng nhập",
                html! {
                    h1 { "Sai mật khẩu" }
                    p { a href="/login" { "← Thử lại" } }
                },
            )),
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

    let total = rows.len();
    let online = rows.iter().filter(|(a, ..)| is_online(a.last_seen)).count();
    let enforcing = rows.iter().filter(|(a, ..)| a.mode == "enforce").count();
    let banned: usize = rows.iter().map(|(_, _, b, ..)| *b).sum();
    let alerts: usize = rows.iter().map(|(_, _, _, al, _)| *al).sum();

    let body = html! {
        h1 { "Tổng quan" }
        p class="sub" { "Toàn bộ VPS đang được bảo vệ và theo dõi." }

        div class="stats" {
            div class="stat" { div class="n" { (total) } div class="l" { "VPS" } }
            div class="stat" { div class="n" style="color:var(--ok)" { (online) } div class="l" { "Đang hoạt động" } }
            div class="stat" { div class="n" { (enforcing) } div class="l" { "Đang chặn tự động" } }
            div class="stat" { div class="n" { (banned) } div class="l" { "IP chặn (lần quét cuối)" } }
            div class="stat" { div class="n" style=(if alerts>0 {"color:var(--warn)"} else {""}) { (alerts) } div class="l" { "Cảnh báo" } }
        }

        div class="note" {
            b { "Chỉ theo dõi" } " = chỉ ghi nhận, chưa chặn ai (an toàn, nên dùng vài ngày đầu). "
            b { "Chặn tự động" } " = tự chặn IP xấu. Đổi chế độ trong trang từng VPS."
        }

        div class="card" {
            div class="wrap" {
                table {
                    thead { tr {
                        th { "VPS" } th { "Trạng thái" } th { "Chế độ" } th { "Tải CPU" }
                        th { "Lượt truy cập" } th { "IP chặn" } th { "Cảnh báo" } th { "Bản sn" } th { "Cập nhật" }
                    }}
                    tbody {
                        @if rows.is_empty() {
                            tr { td colspan="9" { div class="empty" { "Chưa có VPS nào. " a href="/add-vps" { "Thêm VPS đầu tiên →" } } } }
                        }
                        @for (a, req, bans, alerts, load) in &rows {
                            tr {
                                td { a href={"/agent/" (a.id)} { b { (a.name) } } br; span class="mut" style="font-size:12px" { (a.id) } }
                                td { (status_badge(a.last_seen)) }
                                td { (mode_badge(&a.mode)) }
                                td { (format!("{:.2}", load)) }
                                td { (req) }
                                td { @if *bans > 0 { span class="badge b-bad" { (bans) } } @else { "0" } }
                                td { @if *alerts > 0 { span class="badge b-warn" { (alerts) } } @else { "0" } }
                                td class="mut" { (a.version) }
                                td class="mut" { (rel_time(a.last_seen)) }
                            }
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
        h1 { (agent.name) " " (status_badge(agent.last_seen)) " " (mode_badge(mode.as_str())) }
        p class="sub" { code { (agent.id) } " · bản sn " (agent.version) " · cập nhật " (rel_time(agent.last_seen)) }

        div class="card" {
            h2 { "Điều khiển" }
            p class="help" { "Mọi thao tác áp dụng ở lần quét kế tiếp của VPS (tối đa ~15 phút), vì VPS tự gọi về hub chứ hub không gọi vào VPS." }
            div class="ctrls" {
                form method="post" action={"/agent/" (agent.id) "/mode"} {
                    label class="f" {
                        span class="t" { "Chế độ bảo vệ" }
                        select name="mode" {
                            option value="observe" selected[mode==Mode::Observe] { "Chỉ theo dõi (chưa chặn)" }
                            option value="enforce" selected[mode==Mode::Enforce] { "Chặn tự động (ban IP xấu)" }
                        }
                    }
                    button type="submit" { "Lưu" }
                }
            }
            hr class="divider";
            div class="ctrls" {
                form method="post" action={"/agent/" (agent.id) "/ban"} {
                    label class="f" { span class="t" { "Chặn một IP" } input type="text" name="ip" placeholder="vd: 1.2.3.4"; }
                    label class="f" { span class="t" { "Thời hạn (giây)" } input type="number" name="ttl" value="3600" style="width:110px"; }
                    button type="submit" { "Chặn" }
                }
                form method="post" action={"/agent/" (agent.id) "/unban"} {
                    label class="f" { span class="t" { "Gỡ chặn một IP" } input type="text" name="ip" placeholder="vd: 1.2.3.4"; }
                    button class="ghost" type="submit" { "Gỡ chặn" }
                }
            }
            hr class="divider";
            div class="ctrls" {
                form method="post" action={"/agent/" (agent.id) "/job"} {
                    input type="hidden" name="kind" value="hunt";
                    label class="f" { span class="t" { "Quét mã độc (số ngày gần đây)" } input type="number" name="days" value="1" style="width:110px"; }
                    button type="submit" { "Quét ngay" }
                }
                form method="post" action={"/agent/" (agent.id) "/job"} {
                    input type="hidden" name="kind" value="undo";
                    label class="f" { span class="t" { "Hoàn tác" } button class="ghost" type="submit" { "Gỡ chặn + thả cách ly" } }
                }
            }
            p class="help" { "“Hoàn tác” chỉ chạy nếu VPS bật tuỳ chọn cho phép (" code { "[remote] allow_undo" } ")." }
        }

        @if let Some(r) = &report {
            div class="stats" {
                div class="stat" { div class="n" { (r.cycle.requests) } div class="l" { "Lượt truy cập / lần quét" } }
                div class="stat" { div class="n" { (format!("{:.2}", r.cycle.load1)) } div class="l" { "Tải CPU (load 1 phút)" } }
                div class="stat" { div class="n" { (format!("{:.0}%", r.cycle.cpu_busy_pct)) } div class="l" { "CPU đang dùng" } }
                div class="stat" { div class="n" style=(if r.bans.is_empty() {""} else {"color:var(--bad)"}) { (r.bans.len()) } div class="l" { "IP vừa bị chặn" } }
            }

            @if r.cycle.watch_blind {
                div class="note" style="border-left-color:var(--warn)" { "Có truy cập web nhưng không đọc được log — kiểm tra đường dẫn/định dạng log trong " code { "/etc/sn/agent.toml" } "." }
            }

            @if !r.alerts.is_empty() {
                div class="card" {
                    h2 { "Cảnh báo" }
                    @for al in &r.alerts {
                        p { span class={"badge " (severity_cls(&al.severity))} { (severity_vi(&al.severity)) } " " (alert_kind_vi(&al.kind)) }
                    }
                }
            }

            div class="card" {
                h2 { "IP truy cập nhiều nhất" }
                div class="wrap" {
                    table {
                        thead { tr { th { "IP" } th { "Lượt truy cập" } th { "Lỗi 4xx" } th { "Đăng nhập thử" } th {} } }
                        tbody {
                            @if r.cycle.top_ips.is_empty() { tr { td colspan="5" { div class="empty" { "Chưa có dữ liệu" } } } }
                            @for ip in &r.cycle.top_ips {
                                tr {
                                    td { code { (ip.ip) } }
                                    td { (ip.requests) }
                                    td { (ip.err4xx) }
                                    td { (ip.sensitive_posts) }
                                    td {
                                        form method="post" action={"/agent/" (agent.id) "/ban"} style="margin:0" {
                                            input type="hidden" name="ip" value=(ip.ip);
                                            input type="hidden" name="ttl" value="3600";
                                            button class="bad" type="submit" { "Chặn" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                p class="help" { "“Đăng nhập thử” = số lần POST vào wp-login.php/xmlrpc.php (dấu hiệu dò mật khẩu)." }
            }

            @if !r.bans.is_empty() {
                div class="card" {
                    h2 { "IP vừa bị chặn" }
                    div class="wrap" {
                        table {
                            thead { tr { th { "IP" } th { "Lý do" } th { "Thời hạn" } th { "Số lần vi phạm" } th { "Tầng chặn" } } }
                            tbody { @for b in &r.bans {
                                tr {
                                    td { code { (b.ip) } }
                                    td { (reason_vi(&b.reason)) }
                                    td { (b.ttl_secs / 60) " phút" }
                                    td { (b.strike) }
                                    td { span class="badge b-mut" { @if b.layer == "l7" { "Web (L7)" } @else { "Mạng (L3)" } } }
                                }
                            }}
                        }
                    }
                }
            }

            @if let Some(t) = &r.triage {
                div class="card" {
                    h2 { "Khám nhanh — kết luận: " span class="badge b-bad" { (label_vi(&t.label)) } }
                    div class="wrap" {
                        table {
                            thead { tr { th { "PID" } th { "CPU%" } th { "Tiến trình" } th { "Đường dẫn" } th { "Người chạy" } th { "Điểm ngờ" } } }
                            tbody { @for p in &t.top_processes {
                                tr { td { (p.pid) } td { (format!("{:.1}", p.cpu_pct)) } td { (p.comm) } td { code { (p.exe) } } td { (p.user) } td { (p.score) } }
                            }}
                        }
                    }
                    @if !t.persistence.is_empty() {
                        h2 style="margin-top:14px" { "Dấu vết bám trụ (khởi động lại vẫn còn)" }
                        @for h in &t.persistence { p class="mut" style="font-size:13px" { (h) } }
                    }
                }
            }

            @if !r.findings.is_empty() {
                div class="card" {
                    h2 { "File nghi ngờ" }
                    div class="wrap" {
                        table {
                            thead { tr { th { "Điểm ngờ" } th { "Kết luận" } th { "Đường dẫn" } th { "Dấu hiệu khớp" } } }
                            tbody { @for f in &r.findings {
                                tr {
                                    td { (f.score) }
                                    td { @if f.verdict == "malicious" { span class="badge b-bad" { (verdict_vi(&f.verdict)) } } @else { span class="badge b-warn" { (verdict_vi(&f.verdict)) } } }
                                    td { code { (f.path) } }
                                    td class="mut" { (f.rules.join(", ")) }
                                }
                            }}
                        }
                    }
                }
            }
        } @else {
            div class="card" { div class="empty" { "Chưa nhận được báo cáo nào từ VPS này. Sau khi cài agent, VPS sẽ báo về sau vài phút." } }
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
    if ip.is_empty() {
        return Redirect::to(&format!("/agent/{id}")).into_response();
    }
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
    if ip.is_empty() {
        return Redirect::to(&format!("/agent/{id}")).into_response();
    }
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

#[derive(Deserialize)]
pub struct JobForm {
    kind: String,
    #[serde(default)]
    days: Option<u32>,
}

pub async fn job_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<JobForm>,
) -> Response {
    use snsec_common::schema::Job;
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let (job, detail) = match f.kind.as_str() {
        "hunt" => {
            let days = f.days.unwrap_or(1).clamp(1, 30);
            (Job::Hunt { days }, format!("quét mã độc {days} ngày"))
        }
        "undo" => (Job::Undo, "hoàn tác".to_string()),
        _ => return (StatusCode::BAD_REQUEST, "unknown job").into_response(),
    };
    let db = st.db.lock().expect("db");
    let _ = db.queue_job(&id, now(), "admin", job, &detail);
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
                p class="sub" { "Đặt tên gợi nhớ, hub sẽ tạo lệnh cài để bạn dán vào VPS." }
                div class="card" style="max-width:520px" {
                    form method="post" action="/add-vps" {
                        label class="f" {
                            span class="t" { "Tên VPS" }
                            input type="text" name="name" placeholder="vd: web-01" style="width:100%" required autofocus;
                        }
                        p { button type="submit" { "Tạo lệnh cài" } }
                    }
                    p class="help" { "Lệnh cài kèm một mã dùng một lần, hết hạn sau 15 phút. VPS mới sẽ ở chế độ “Chỉ theo dõi”." }
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
                h1 { "Lệnh cài cho “" (f.name) "”" }
                div class="card" {
                    p { "Đăng nhập VPS bằng " b { "root" } " và dán nguyên dòng dưới đây:" }
                    pre { (install) }
                    p class="help" { "Mã cài hết hạn sau 15 phút. Cài xong, VPS sẽ hiện ở Tổng quan sau vài phút (chế độ “Chỉ theo dõi”)." }
                }
                p { a href="/" { "Về Tổng quan" } }
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
        h1 { "Nhật ký thao tác" }
        p class="sub" { "Mọi thao tác trên hub (ai làm, lúc nào, VPS nào)." }
        div class="card" {
            div class="wrap" {
                table {
                    thead { tr { th { "Thời gian" } th { "VPS" } th { "Người" } th { "Thao tác" } th { "Chi tiết" } } }
                    tbody {
                        @if decisions.is_empty() { tr { td colspan="5" { div class="empty" { "Chưa có thao tác nào" } } } }
                        @for (agent, who, action, detail, ts) in &decisions {
                            tr { td class="mut" { (rel_time(*ts)) } td { (agent) } td { (who) } td { (action_vi(action)) } td { (detail) } }
                        }
                    }
                }
            }
        }
    };
    Html(shell("Nhật ký", body).into_string()).into_response()
}
