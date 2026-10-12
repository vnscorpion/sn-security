//! Server-rendered admin UI. maud autoescapes every interpolated value, so
//! attacker-controlled strings from reports (paths, user-agents, process names)
//! cannot inject markup. Wording is plain Vietnamese with short explanations of
//! the few technical terms; routes and form field names are unchanged.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;
use snsec_common::schema::{DesiredBan, DesiredBody, Mode, ReportBody};

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
header form.ipcheck{margin:0}
header form.ipcheck input{width:190px;padding:6px 12px;border-radius:999px}
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
                    form class="ipcheck" method="get" action="/check-ip" {
                        input type="text" name="ip" placeholder="Tra cứu IP..." autocomplete="off" aria-label="Tra cứu IP";
                    }
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

/// The address VPSes use to reach this hub (the configured public URL, or the
/// bind address when none is set).
fn hub_base(st: &AppState) -> String {
    if st.cfg.public_url.is_empty() {
        format!("http://{}", st.cfg.bind)
    } else {
        st.cfg.public_url.trim_end_matches('/').to_string()
    }
}

/// Version of this hub build. Agents are released together with the hub, so an
/// agent reporting an older version is missing features the hub can show.
const HUB_VERSION: &str = env!("CARGO_PKG_VERSION");

fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    // Ignore a pre-release/build suffix on the patch number ("1-rc1", "1+abc").
    let patch = it
        .next()
        .unwrap_or("0")
        .split(['-', '+'])
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

/// True when the agent reports a version older than this hub. An unknown or
/// unparsable version (e.g. an agent that has not reported yet) is not flagged.
fn agent_outdated(agent_version: &str) -> bool {
    match (parse_version(agent_version), parse_version(HUB_VERSION)) {
        (Some(agent), Some(hub)) => agent < hub,
        _ => false,
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
        "watch_blind" => "Có truy cập web nhưng nhiều lần quét liền không có dòng log mới",
        "log_not_found" => "Không tìm thấy file log nào khớp cấu hình",
        "log_unreadable" => "Có file log nhưng agent không đọc được",
        "log_format" => "Đọc được log nhưng sai định dạng",
        "mem_high" => "RAM gần đầy",
        "cpu_high" => "CPU cao liên tục",
        "bot_ua" => "Nhiều IP khác nhau cùng dùng một User-Agent (nghi bot phân tán)",
        "bot_shape" => "Nhiều IP khác nhau cùng gửi một kiểu request (nghi bot phân tán)",
        "malware_found" => "Phát hiện file mã độc",
        "malware_suspect" => "Có file nghi ngờ cần xem",
        _ => k,
    }
}

/// One table of the busiest User-Agents or request shapes of the last cycle.
/// Flagged rows come with a ModSecurity rule to review and the example IPs.
/// The values come from web logs, so they are attacker-controlled: maud escapes
/// them, and the rule text is escaped again by `snsec_common::waf`.
fn pattern_table(
    heading: &str,
    key_head: &str,
    rows: &[snsec_common::schema::PatternStat],
    rule_for: fn(&str) -> Option<String>,
) -> Markup {
    html! {
        h2 style="margin-top:6px" { (heading) }
        div class="wrap" {
            table {
                thead { tr { th { (key_head) } th { "Lượt" } th { "IP khác nhau" } th {} } }
                tbody {
                    @if rows.is_empty() { tr { td colspan="4" { div class="empty" { "Chưa có dữ liệu" } } } }
                    @for p in rows {
                        tr {
                            td { code style="word-break:break-all" { (p.key) } }
                            td { (p.requests) }
                            td { (p.ips) @if p.ips_capped { "+" } }
                            td { @if p.flagged { span class="badge b-bad" { "Bất thường" } } }
                        }
                        @if p.flagged {
                            tr { td colspan="4" {
                                details open {
                                    summary { "Cách xử lý mục này" }
                                    @if snsec_common::waf::claims_crawler(&p.key) {
                                        p class="help" style="color:var(--warn)" {
                                            "Mục này tự nhận là crawler của công cụ tìm kiếm (Googlebot, Bingbot…), chưa được xác minh. "
                                            "Crawler thật cũng đến từ nhiều IP. Chặn nhầm sẽ ảnh hưởng SEO, nên hãy kiểm tra bằng reverse DNS trước khi chặn."
                                        }
                                    }
                                    @if let Some(rule) = rule_for(&p.key) {
                                        p class="help" {
                                            "Nếu VPS chạy ModSecurity (cPanel, Plesk, DirectAdmin, OPanel), thêm luật dưới đây rồi để chế độ "
                                            code { "DetectionOnly" } " một lúc, xem nó có chặn nhầm khách thật không, sau đó mới bật chặn. "
                                            "Hub không tự ghi luật vào VPS."
                                        }
                                        pre style="white-space:pre-wrap;word-break:break-all;margin:0 0 10px" { (rule) }
                                    } @else {
                                        p class="help" { "Hub không tạo được luật an toàn cho giá trị này (quá dài, có ký tự đặc biệt/mã hoá %, hoặc quá chung chung nên sẽ chặn nhầm). Hãy tự viết luật nếu cần." }
                                    }
                                    @if !p.sample_ips.is_empty() {
                                        p class="help" style="margin:0" {
                                            "Một vài IP mẫu (" (p.sample_ips.len()) "): "
                                            span style="font-family:monospace" { (p.sample_ips.join(", ")) }
                                        }
                                    }
                                    p class="help" style="margin:6px 0 0" {
                                        "Nếu không có WAF thì chỉ chặn được theo IP/CIDR bằng ô chặn IP ở trên. Với bot phân tán, "
                                        "IP đổi liên tục nên cách này gần như không hiệu quả."
                                    }
                                }
                            } }
                        }
                    }
                }
            }
        }
    }
}

/// A ban as the hub presents it: merged from what the VPS reports as in force
/// and what an admin has ordered from the hub.
struct BanView {
    key: String,
    /// The address as stored, used by the "gỡ chặn" form.
    ip: String,
    by_admin: bool,
    reason: String,
    expires_at: i64,
    /// `false` while the ban is only ordered from the hub and the VPS has not
    /// yet confirmed it in a report.
    applied: bool,
}

/// Every ban currently in force or on its way to the VPS. `at` is "now".
fn ban_views(report: Option<&ReportBody>, desired: Option<&DesiredBody>, at: i64) -> Vec<BanView> {
    let mut out: Vec<BanView> = Vec::new();
    if let Some(r) = report {
        for b in r.active_bans.iter().filter(|b| b.expires_at > at) {
            out.push(BanView {
                key: key_of(&b.ip),
                ip: b.ip.clone(),
                by_admin: b.reason == "hub",
                reason: b.reason.clone(),
                expires_at: b.expires_at,
                applied: true,
            });
        }
        // Agents older than `active_bans` only report the latest cycle's bans.
        for b in &r.bans {
            let expires_at = r.cycle.started_at + b.ttl_secs as i64;
            let key = key_of(&b.ip);
            if expires_at > at && !out.iter().any(|v| v.key == key) {
                out.push(BanView {
                    key,
                    ip: b.ip.clone(),
                    by_admin: false,
                    reason: b.reason.clone(),
                    expires_at,
                    applied: true,
                });
            }
        }
    }
    if let Some(d) = desired {
        for b in &d.bans {
            if b.created_at == 0 {
                continue; // written before ban times were recorded; age unknown
            }
            let expires_at = b.created_at + b.ttl_secs.min(24 * 3600) as i64;
            let key = key_of(&b.ip);
            if expires_at > at && !out.iter().any(|v| v.key == key) {
                out.push(BanView {
                    key,
                    ip: b.ip.clone(),
                    by_admin: true,
                    reason: b.reason.clone(),
                    expires_at,
                    applied: false,
                });
            }
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// `(listed, total)` when the VPS had more bans than it listed in its report, so
/// the hub's view of its blocklist is partial. `None` when the list is complete.
fn ban_list_partial(report: Option<&ReportBody>) -> Option<(usize, usize)> {
    let r = report?;
    let listed = r.active_bans.len();
    let total = r.active_bans_total as usize;
    (total > listed).then_some((listed, total))
}

/// Number of bans in force that the hub cannot list individually.
fn hidden_bans(report: Option<&ReportBody>) -> usize {
    ban_list_partial(report).map_or(0, |(listed, total)| total - listed)
}

/// Rows per page in the blocklist.
const BAN_PAGE_SIZE: usize = 50;

/// Slice bounds for a 1-based `page`: `(start, end, page, pages)`. An
/// out-of-range page is clamped to the nearest valid one; an empty list is one
/// (empty) page.
fn page_bounds(total: usize, page: usize, size: usize) -> (usize, usize, usize, usize) {
    let pages = total.div_ceil(size).max(1);
    let page = page.clamp(1, pages);
    let start = (page - 1) * size;
    (start, (start + size).min(total), page, pages)
}

/// Percent-encode a query-string value (everything but unreserved characters).
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Link to a page of an agent's blocklist, keeping the filter.
fn bans_url(agent_id: &str, q: &str, page: usize) -> String {
    let mut url = format!("/agent/{agent_id}?page={page}");
    if !q.is_empty() {
        url.push_str("&q=");
        url.push_str(&urlenc(q));
    }
    url.push_str("#bans");
    url
}

/// "còn 12 phút" / "còn 3 giờ" until `ts`.
fn expires_in(ts: i64) -> String {
    let d = (ts - now()).max(0);
    if d < 90 {
        format!("còn {d} giây")
    } else if d < 5400 {
        format!("còn {} phút", d / 60)
    } else if d < 172_800 {
        format!("còn {} giờ", d / 3600)
    } else {
        format!("còn {} ngày", d / 86_400)
    }
}

/// One VPS line on the overview page.
struct OverviewRow {
    agent: crate::db::AgentRow,
    req: u64,
    bans: usize,
    alerts: usize,
    load: f64,
    /// RAM in use (%), or `None` when the agent has not reported it.
    mem: Option<f64>,
}

/// Colour-coded RAM percentage: green below 75%, amber to 90%, red above.
fn mem_badge(mem: Option<f64>) -> Markup {
    match mem {
        None => html! { span class="mut" { "—" } },
        Some(p) => {
            let cls = if p >= 90.0 {
                "b-bad"
            } else if p >= 75.0 {
                "b-warn"
            } else {
                "b-ok"
            };
            html! { span class={"badge " (cls)} { (format!("{p:.0}%")) } }
        }
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
    let rows: Vec<OverviewRow> = agents
        .iter()
        .map(|a| {
            let rep = db.latest_report(&a.id).ok().flatten();
            let desired = db.get_desired(&a.id).ok().flatten();
            // Listed bans plus any the VPS has but could not fit in its report.
            let bans = ban_views(rep.as_ref(), desired.as_ref().map(|(_, _, d)| d), now()).len()
                + hidden_bans(rep.as_ref());
            match rep {
                Some(r) => OverviewRow {
                    agent: a.clone(),
                    req: r.cycle.requests,
                    bans,
                    alerts: r.alerts.len(),
                    load: r.cycle.load1,
                    // Reports from agents older than the RAM feature carry 0.
                    mem: (r.cycle.mem_total_mb > 0).then_some(r.cycle.mem_used_pct),
                },
                None => OverviewRow {
                    agent: a.clone(),
                    req: 0,
                    bans,
                    alerts: 0,
                    load: 0.0,
                    mem: None,
                },
            }
        })
        .collect();
    drop(db);

    let total = rows.len();
    let online = rows.iter().filter(|r| is_online(r.agent.last_seen)).count();
    let enforcing = rows.iter().filter(|r| r.agent.mode == "enforce").count();
    let banned: usize = rows.iter().map(|r| r.bans).sum();
    let alerts: usize = rows.iter().map(|r| r.alerts).sum();

    let body = html! {
        h1 { "Tổng quan" }
        p class="sub" { "Toàn bộ VPS đang được bảo vệ và theo dõi." }

        div class="stats" {
            div class="stat" { div class="n" { (total) } div class="l" { "VPS" } }
            div class="stat" { div class="n" style="color:var(--ok)" { (online) } div class="l" { "Đang hoạt động" } }
            div class="stat" { div class="n" { (enforcing) } div class="l" { "Đang chặn tự động" } }
            div class="stat" { div class="n" { (banned) } div class="l" { "IP đang bị chặn" } }
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
                        th { "VPS" } th { "Trạng thái" } th { "Chế độ" } th { "Tải CPU" } th { "RAM" }
                        th { "Lượt truy cập" } th { "IP chặn" } th { "Cảnh báo" } th { "Bản sn" } th { "Cập nhật" }
                    }}
                    tbody {
                        @if rows.is_empty() {
                            tr { td colspan="10" { div class="empty" { "Chưa có VPS nào. " a href="/add-vps" { "Thêm VPS đầu tiên →" } } } }
                        }
                        @for row in &rows {
                            @let a = &row.agent;
                            tr {
                                td { a href={"/agent/" (a.id)} { b { (a.name) } } br; span class="mut" style="font-size:12px" { (a.id) } }
                                td { (status_badge(a.last_seen)) }
                                td { (mode_badge(&a.mode)) }
                                td { (format!("{:.2}", row.load)) }
                                td { (mem_badge(row.mem)) }
                                td { (row.req) }
                                td { @if row.bans > 0 { span class="badge b-bad" { (row.bans) } } @else { "0" } }
                                td { @if row.alerts > 0 { span class="badge b-warn" { (row.alerts) } } @else { "0" } }
                                td class="mut" {
                                    (a.version)
                                    @if agent_outdated(&a.version) { " " span class="badge b-warn" { "cũ" } }
                                }
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

#[derive(Deserialize, Default)]
pub struct AgentQuery {
    /// Filter for the blocklist (substring of the address).
    #[serde(default)]
    q: String,
    #[serde(default)]
    page: usize,
}

pub async fn agent_detail(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(aq): Query<AgentQuery>,
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
    let bans = ban_views(report.as_ref(), desired.as_ref().map(|(_, _, d)| d), now());
    let partial = ban_list_partial(report.as_ref());
    let hidden = hidden_bans(report.as_ref());

    // Blocklist: filter by address, then show one page.
    let needle = aq.q.trim().to_lowercase();
    let filtered: Vec<&BanView> = bans
        .iter()
        .filter(|b| {
            needle.is_empty()
                || b.ip.to_lowercase().contains(&needle)
                || b.key.to_lowercase().contains(&needle)
        })
        .collect();
    let (start, end, page, pages) = page_bounds(filtered.len(), aq.page, BAN_PAGE_SIZE);
    let shown = &filtered[start..end];

    let body = html! {
        p { a href="/" { "← Tổng quan" } }
        h1 { (agent.name) " " (status_badge(agent.last_seen)) " " (mode_badge(mode.as_str())) }
        p class="sub" {
            code { (agent.id) } " · bản sn " (agent.version) " · cập nhật " (rel_time(agent.last_seen))
            @if let Some(r) = &report {
                @if !r.host.os.is_empty() { " · " (r.host.os) }
                // Empty from agents older than this field.
                @if !r.host.web_server.is_empty() && r.host.web_server != "unknown" { " · web server: " b { (r.host.web_server) } }
            }
        }

        @if agent_outdated(&agent.version) {
            div class="note" style="border-left-color:var(--warn)" {
                "Agent trên VPS này là bản " b { (agent.version) } ", cũ hơn hub (" (HUB_VERSION) "). "
                "Một số số liệu mới (như RAM) sẽ chưa hiện cho tới khi cập nhật. Chạy trên VPS, bằng root:"
                pre style="margin:10px 0 0" { "curl -fsSL " (hub_base(&st)) "/install.sh | sudo sh -s -- --hub " (hub_base(&st)) " --upgrade" }
            }
        }

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
                    // PHP files are always all scanned; `days` only widens the net for other recently changed files.
                    input type="hidden" name="days" value="7";
                    label class="f" { span class="t" { "Quét mã độc (toàn bộ file PHP)" } button type="submit" { "Quét ngay" } }
                }
                form method="post" action={"/agent/" (agent.id) "/job"} {
                    input type="hidden" name="kind" value="undo";
                    label class="f" { span class="t" { "Hoàn tác" } button class="ghost" type="submit" { "Gỡ chặn + thả cách ly" } }
                }
            }
            p class="help" { "“Hoàn tác” chỉ chạy nếu VPS bật tuỳ chọn cho phép (" code { "[remote] allow_undo" } ")." }
        }

        div class="card" id="bans" {
            h2 { "IP đang bị chặn (" (bans.len() + hidden) ")" }

            @if let Some((listed, total)) = partial {
                div class="note" style="border-left-color:var(--warn)" {
                    "VPS này đang chặn " b { (total) } " IP nhưng chỉ gửi về hub " b { (listed) } " IP (những IP bị chặn lâu nhất). "
                    "Phần còn lại vẫn đang bị chặn trên VPS nhưng hub không liệt kê được, nên ô lọc và ô tra cứu IP "
                    "chỉ chắc chắn với các IP trong danh sách này."
                }
            }

            @if !bans.is_empty() || !needle.is_empty() {
                form method="get" action={"/agent/" (agent.id)} style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px" {
                    input type="text" name="q" value=(aq.q.trim()) placeholder="Lọc theo IP, vd: 203.0.113" style="flex:1;min-width:200px" autocomplete="off";
                    button type="submit" { "Lọc" }
                    @if !needle.is_empty() { a href={"/agent/" (agent.id) "#bans"} style="align-self:center" { "Xoá lọc" } }
                }
                @if !needle.is_empty() {
                    p class="help" style="margin:0 0 10px" { "Có " b { (filtered.len()) } " IP khớp “" (aq.q.trim()) "”." }
                }
            }

            div class="wrap" {
                table {
                    thead { tr { th { "IP" } th { "Do ai chặn" } th { "Lý do" } th { "Hết hạn" } th { "Trạng thái" } th {} } }
                    tbody {
                        @if filtered.is_empty() {
                            tr { td colspan="6" { div class="empty" {
                                @if needle.is_empty() { "Hiện không có IP nào bị chặn." } @else { "Không có IP nào khớp bộ lọc." }
                            } } }
                        }
                        @for b in shown {
                            tr {
                                td { code { (b.ip) } }
                                td { @if b.by_admin { span class="badge b-mut" { "Admin" } } @else { span class="badge b-mut" { "Tự động" } } }
                                td { (if b.by_admin { "Admin đặt" } else { reason_vi(&b.reason) }) }
                                td class="mut" { (expires_in(b.expires_at)) }
                                td {
                                    @if b.applied { span class="badge b-ok" { "Đang hiệu lực" } }
                                    @else { span class="badge b-warn" { "Chờ VPS áp dụng" } }
                                }
                                td {
                                    form method="post" action={"/agent/" (agent.id) "/unban"} style="margin:0" {
                                        input type="hidden" name="ip" value=(b.ip);
                                        button class="ghost" type="submit" { "Gỡ chặn" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if pages > 1 {
                div style="display:flex;gap:14px;align-items:center;justify-content:center;margin-top:14px" {
                    @if page > 1 { a href=(bans_url(&agent.id, aq.q.trim(), page - 1)) { "← Trước" } } @else { span class="mut" { "← Trước" } }
                    span class="mut" { "Trang " (page) " / " (pages) " · hiển thị " (start + 1) "–" (end) " trong " (filtered.len()) }
                    @if page < pages { a href=(bans_url(&agent.id, aq.q.trim(), page + 1)) { "Sau →" } } @else { span class="mut" { "Sau →" } }
                }
            }
            p class="help" { "“Chờ VPS áp dụng” = lệnh chặn đã gửi, VPS sẽ nhận ở lần quét kế tiếp (tối đa ~15 phút) rồi tự chuyển sang “Đang hiệu lực”." }
        }

        @if let Some(r) = &report {
            div class="stats" {
                div class="stat" { div class="n" { (r.cycle.requests) } div class="l" { "Lượt truy cập / lần quét" } }
                div class="stat" { div class="n" { (format!("{:.2}", r.cycle.load1)) } div class="l" { "Tải CPU (load 1 phút)" } }
                div class="stat" { div class="n" { (format!("{:.0}%", r.cycle.cpu_busy_pct)) } div class="l" { "CPU đang dùng" } }
                // Always shown, so a missing figure is explained instead of silently absent.
                @if r.cycle.mem_total_mb > 0 {
                    div class="stat" {
                        div class="n" style=(if r.cycle.mem_used_pct >= 90.0 {"color:var(--bad)"} else if r.cycle.mem_used_pct >= 75.0 {"color:var(--warn)"} else {""}) {
                            (format!("{:.0}%", r.cycle.mem_used_pct))
                        }
                        div class="l" { "RAM đang dùng (tổng " (r.cycle.mem_total_mb) " MB)" }
                    }
                    div class="stat" {
                        div class="n" { (format!("{:.0}%", r.cycle.swap_used_pct)) }
                        div class="l" { "Swap đang dùng" }
                    }
                } @else {
                    div class="stat" {
                        div class="n mut" { "—" }
                        div class="l" { "RAM: chưa có số liệu — agent trên VPS này cần cập nhật" }
                    }
                }
                // Older agents do not send this, so 0 would be a false alarm for them.
                @if !agent_outdated(&agent.version) {
                    div class="stat" {
                        div class="n" style=(if r.cycle.log_files == 0 {"color:var(--bad)"} else {""}) { (r.cycle.log_files) }
                        div class="l" { "File log đang theo dõi" }
                    }
                }
            }

            @if r.cycle.watch_blind {
                div class="note" style="border-left-color:var(--warn)" {
                    "Agent đang gặp vấn đề khi đọc log của web server (chi tiết ở mục Cảnh báo bên dưới). "
                    "Trên VPS, chạy " code { "sn env" } " để xem agent đang theo dõi những file log nào, và sửa " code { "[[watch.sources]]" } " trong " code { "/etc/sn/agent.toml" } " nếu cần."
                }
            }

            @if !r.alerts.is_empty() {
                div class="card" {
                    h2 { "Cảnh báo" }
                    @for al in &r.alerts {
                        p {
                            span class={"badge " (severity_cls(&al.severity))} { (severity_vi(&al.severity)) } " " (alert_kind_vi(&al.kind))
                            // The agent's own wording carries the specifics (which glob, which file).
                            br; span class="mut" style="font-size:13px" { (al.message) }
                        }
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

            @if !r.cycle.top_cpu.is_empty() {
                div class="card" {
                    h2 { "Ai đang dùng CPU" }
                    div class="wrap" {
                        table {
                            thead { tr { th { "Tài khoản" } th { "Chương trình" } th { "Số tiến trình" } th { "% CPU của cả máy" } } }
                            tbody { @for g in &r.cycle.top_cpu {
                                tr { td { (g.user) } td { code { (g.comm) } } td { (g.procs) } td { (format!("{:.1}", g.cpu_pct)) } }
                            }}
                        }
                    }
                    p class="help" {
                        "Trung bình từ lần quét trước đến nay (không phải một thời điểm), gộp theo tài khoản và chương trình. "
                        "Tiến trình chạy xong trước khi agent kịp nhìn sẽ không có ở đây nên tổng có thể nhỏ hơn mức CPU chung. "
                        "Tài khoản chiếm CPU thường là site bị tấn công hoặc có mã độc: xem thêm mục “Truy cập lặp lại” và “Quét mã độc”."
                    }
                }
            }

            // Old agents do not send these; say so rather than show an empty table.
            div class="card" {
                h2 { "Truy cập lặp lại từ nhiều IP" }
                @if agent_outdated(&agent.version) && r.cycle.top_shapes.is_empty() && r.cycle.top_user_agents.is_empty() {
                    p class="help" style="margin:0" { "Chưa có số liệu: agent trên VPS này cũ (chưa gửi mục này) hoặc lần quét gần nhất chưa có truy cập động nào. Cập nhật agent nếu nghi là bản cũ." }
                } @else {
                    p class="help" style="margin:0 0 12px" {
                        "Trong lần quét gần nhất có " b { (r.cycle.dynamic_requests) } " lượt truy cập động (không tính ảnh, CSS, JS). "
                        "Bot phân tán dùng hàng trăm IP, mỗi IP chỉ vài lượt nên không bị luật theo IP bắt; điểm chung của chúng là cùng User-Agent "
                        "hoặc cùng kiểu request (đường dẫn + tên tham số, không lưu giá trị). Mục nào tăng vọt so với bình thường sẽ có nhãn “Bất thường”."
                    }
                    (pattern_table("User-Agent nhiều nhất", "User-Agent", &r.cycle.top_user_agents, snsec_common::waf::rule_for_user_agent))
                    div style="height:14px" {}
                    (pattern_table("Kiểu request nhiều nhất", "Kiểu request", &r.cycle.top_shapes, snsec_common::waf::rule_for_shape))
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

            // Always shown: "scanned, nothing found" must look different from "never scanned".
            div class="card" id="scan" {
                h2 { "Quét mã độc" }
                @if let Some(h) = &r.hunt {
                    p style="margin:0 0 12px" {
                        "Lần quét cuối " b { (rel_time(h.at)) } ": đã xem " b { (h.scanned) } " file PHP trong " (h.duration_secs) " giây. "
                        @if h.malicious == 0 && h.suspicious == 0 {
                            span class="badge b-ok" { "Không phát hiện gì" }
                        } @else {
                            @if h.malicious > 0 { span class="badge b-bad" { (h.malicious) " độc hại" } " " }
                            @if h.suspicious > 0 { span class="badge b-warn" { (h.suspicious) " nghi ngờ" } }
                        }
                    }
                } @else if agent_outdated(&agent.version) {
                    p class="help" style="margin:0 0 12px" { "Agent trên VPS này quá cũ nên chưa gửi kết quả quét lên hub. Cập nhật agent để thấy kết quả." }
                } @else {
                    p class="help" style="margin:0 0 12px" { "Chưa có kết quả quét. VPS tự quét lúc 3 giờ sáng mỗi ngày; hoặc bấm “Quét ngay” ở mục Điều khiển phía trên." }
                }

                @if !r.findings.is_empty() {
                    div class="wrap" {
                        table {
                            thead { tr { th { "Điểm" } th { "Kết luận" } th { "Đường dẫn" } th { "Dấu hiệu khớp" } } }
                            tbody { @for f in &r.findings {
                                tr {
                                    td { (f.score) }
                                    td { @if f.verdict == "malicious" { span class="badge b-bad" { (verdict_vi(&f.verdict)) } } @else { span class="badge b-warn" { (verdict_vi(&f.verdict)) } } }
                                    td { code { (f.path) } br; span class="mut" style="font-size:12px" { (f.context) } }
                                    td class="mut" { (f.rules.join(", ")) }
                                }
                            }}
                        }
                    }
                    p class="help" {
                        "Điểm ≥ 100 là “độc hại” (đủ chắc chắn để cách ly), 70–99 là “nghi ngờ” (cần bạn xem). "
                        "Đây là heuristic nên có thể sai: đọc đoạn mã trích ra trước khi xử lý. Cách ly bằng " code { "sn clean --yes" }
                        " trên VPS (chỉ file “độc hại”, khôi phục được bằng " code { "sn restore <id>" } ")."
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
    let ts = now();
    let key = key_of(&ip);
    let db = st.db.lock().expect("db");
    let _ = db.update_desired(&id, ts, "admin", "ban", &ip, |d| {
        d.unbans.retain(|x| key_of(x) != key);
        // Forget lapsed bans (the agent's firewall expires its own entries) and
        // any older order for this same address, then record the new one.
        d.bans.retain(|b| {
            b.created_at > 0 && b.created_at + b.ttl_secs as i64 > ts && key_of(&b.ip) != key
        });
        d.bans.push(DesiredBan {
            ip: ip.clone(),
            ttl_secs: ttl,
            reason: "admin".into(),
            created_at: ts,
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
    let key = key_of(&ip);
    let db = st.db.lock().expect("db");
    let _ = db.update_desired(&id, now(), "admin", "unban", &ip, |d| {
        d.bans.retain(|b| key_of(&b.ip) != key);
        if !d.unbans.iter().any(|u| key_of(u) == key) {
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

    let base = hub_base(&st);
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

// ---- ip check --------------------------------------------------------------

/// Canonical key an IP is tracked under: plain IPv4, or the /64 for IPv6.
/// Anything that is not an address is compared verbatim.
fn key_of(s: &str) -> String {
    match s.trim().parse::<IpAddr>() {
        Ok(ip) => snsec_common::net::ban_key(ip),
        Err(_) => s.trim().to_string(),
    }
}

/// A short description of special-purpose addresses that should rarely be
/// banned, or `None` for an ordinary public address.
fn special_ip_note(ip: IpAddr) -> Option<&'static str> {
    match snsec_common::net::normalize(ip) {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("IP nội bộ của chính máy (loopback)")
            } else if v4.is_private() || v4.is_link_local() {
                Some("IP mạng nội bộ — thường không phải kẻ tấn công từ internet")
            } else if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() {
                Some("Địa chỉ đặc biệt, không phải IP của một máy cụ thể")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("IP nội bộ của chính máy (loopback)")
            } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                Some("IP mạng nội bộ — thường không phải kẻ tấn công từ internet")
            } else if v6.is_unspecified() || v6.is_multicast() {
                Some("Địa chỉ đặc biệt, không phải IP của một máy cụ thể")
            } else {
                None
            }
        }
    }
}

/// What the hub knows about one IP on one VPS.
struct IpOnAgent {
    id: String,
    name: String,
    last_seen: i64,
    /// `(requests, 4xx, sensitive posts)` if the IP is in the latest top list.
    traffic: Option<(u64, u64, u64)>,
    /// The ban on this address, in force or on its way to the VPS.
    ban: Option<BanView>,
    /// `(listed, total)` if the VPS's reported blocklist is cut short, in which
    /// case "not in the list" does not prove the address is unblocked.
    partial: Option<(usize, usize)>,
    /// Agent version; an agent older than the blocklist report cannot say
    /// whether an address is blocked.
    version: String,
    would_ban: Option<String>,
    hub_unban: bool,
}

#[derive(Deserialize)]
pub struct CheckIpQuery {
    #[serde(default)]
    ip: String,
}

pub async fn check_ip(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<CheckIpQuery>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let input = q.ip.trim().to_string();

    let search_form = html! {
        form method="get" action="/check-ip" style="display:flex;gap:10px;flex-wrap:wrap" {
            input type="text" name="ip" value=(input) placeholder="vd: 203.0.113.7 hoặc 2001:db8::1" style="flex:1;min-width:240px" autofocus;
            button type="submit" { "Tra cứu" }
        }
    };

    if input.is_empty() {
        return Html(
            shell(
                "Tra cứu IP",
                html! {
                    h1 { "Tra cứu IP" }
                    p class="sub" { "Nhập một địa chỉ IP để xem nó có đang bị chặn hoặc truy cập nhiều ở VPS nào." }
                    div class="card" { (search_form) }
                },
            )
            .into_string(),
        )
        .into_response();
    }

    let Ok(ip) = input.parse::<IpAddr>() else {
        return Html(
            shell(
                "Tra cứu IP",
                html! {
                    h1 { "Tra cứu IP" }
                    div class="card" { (search_form) }
                    div class="note" style="border-left-color:var(--bad)" {
                        "“" (input) "” không phải địa chỉ IP hợp lệ. Hãy nhập IPv4 (vd 203.0.113.7) hoặc IPv6 (vd 2001:db8::1)."
                    }
                },
            )
            .into_string(),
        )
        .into_response();
    };

    let key = snsec_common::net::ban_key(ip);

    let db = st.db.lock().expect("db");
    let agents = db.list_agents().unwrap_or_default();
    let mut hits: Vec<IpOnAgent> = Vec::new();
    for a in &agents {
        let rep = db.latest_report(&a.id).ok().flatten();
        let desired = db.get_desired(&a.id).ok().flatten();
        let mut hit = IpOnAgent {
            id: a.id.clone(),
            name: a.name.clone(),
            last_seen: a.last_seen,
            traffic: None,
            ban: None,
            partial: ban_list_partial(rep.as_ref()),
            version: a.version.clone(),
            would_ban: None,
            hub_unban: false,
        };
        if let Some(r) = &rep {
            hit.traffic = r
                .cycle
                .top_ips
                .iter()
                .find(|t| key_of(&t.ip) == key)
                .map(|t| (t.requests, t.err4xx, t.sensitive_posts));
            hit.would_ban = r
                .would_ban
                .iter()
                .find(|b| key_of(&b.ip) == key)
                .map(|b| b.reason.clone());
        }
        hit.ban = ban_views(rep.as_ref(), desired.as_ref().map(|(_, _, d)| d), now())
            .into_iter()
            .find(|b| b.key == key);
        if let Some((_, _, d)) = &desired {
            hit.hub_unban = d.unbans.iter().any(|u| key_of(u) == key);
        }
        hits.push(hit);
    }
    let history: Vec<_> = db
        .recent_decisions(500)
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, _, _, detail, _)| key_of(detail) == key)
        .take(20)
        .collect();
    drop(db);

    let seen_anywhere = hits
        .iter()
        .any(|h| h.traffic.is_some() || h.ban.is_some() || h.would_ban.is_some());

    let body = html! {
        h1 { "Tra cứu IP" }
        div class="card" { (search_form) }

        h2 { "Kết quả cho " code { (input) } }
        @if key != input {
            p class="help" { "Hub theo dõi IPv6 theo cả dải " code { (key) } " (một máy thường dùng cả dải /64)." }
        }
        @if let Some(note) = special_ip_note(ip) {
            div class="note" style="border-left-color:var(--warn)" { (note) }
        }

        @if !seen_anywhere && history.is_empty() {
            div class="note" {
                "Chưa thấy IP này trong báo cáo gần nhất của VPS nào, và chưa có thao tác nào của admin với nó. "
                "Hub chỉ nhìn thấy 20 IP truy cập nhiều nhất trong lần quét gần nhất của mỗi VPS, nên “không thấy” không có nghĩa IP chưa từng truy cập."
            }
        }

        div class="card" {
            h2 { "Theo từng VPS" }
            div class="wrap" {
                table {
                    thead { tr {
                        th { "VPS" } th { "Truy cập (lần quét cuối)" } th { "Tình trạng chặn" } th {}
                    }}
                    tbody {
                        @if hits.is_empty() {
                            tr { td colspan="4" { div class="empty" { "Chưa có VPS nào." } } }
                        }
                        @for h in &hits {
                            tr {
                                td {
                                    a href={"/agent/" (h.id)} { b { (h.name) } } br;
                                    span class="mut" style="font-size:12px" { "cập nhật " (rel_time(h.last_seen)) }
                                }
                                td {
                                    @if let Some((req, e4, posts)) = h.traffic {
                                        (req) " lượt · " (e4) " lỗi 4xx · " (posts) " đăng nhập thử"
                                    } @else { span class="mut" { "không thấy" } }
                                }
                                td {
                                    @if let Some(b) = &h.ban {
                                        @if b.applied {
                                            span class="badge b-bad" { "Đang bị chặn" }
                                        } @else {
                                            span class="badge b-warn" { "Đã đặt chặn, chờ VPS áp dụng" }
                                        }
                                        " " span class="mut" {
                                            (if b.by_admin { "Admin đặt" } else { reason_vi(&b.reason) }) " · " (expires_in(b.expires_at))
                                        }
                                    }
                                    @if let Some(reason) = &h.would_ban {
                                        span class="badge b-warn" { "Sẽ bị chặn (chưa bật)" } " " span class="mut" { (reason_vi(reason)) }
                                    }
                                    @if h.hub_unban && h.ban.is_none() {
                                        span class="badge b-ok" { "Admin đã gỡ chặn" }
                                    }
                                    @if h.ban.is_none() && h.would_ban.is_none() && !h.hub_unban {
                                        @if let Some((listed, total)) = h.partial {
                                            span class="badge b-warn" { "Chưa chắc" } " "
                                            span class="mut" { "VPS chặn " (total) " IP nhưng hub chỉ nhận " (listed) " — không loại trừ được IP này" }
                                        } @else if agent_outdated(&h.version) {
                                            span class="badge b-warn" { "Chưa chắc" } " "
                                            span class="mut" { "agent cũ (" (h.version) ") chưa báo đủ danh sách chặn — hãy cập nhật agent" }
                                        } @else if h.version.is_empty() {
                                            span class="mut" { "—" }
                                        } @else {
                                            span class="mut" { "Không bị chặn" }
                                        }
                                    }
                                }
                                td style="white-space:nowrap" {
                                    form method="post" action={"/agent/" (h.id) "/ban"} style="display:inline;margin:0" {
                                        input type="hidden" name="ip" value=(input);
                                        input type="hidden" name="ttl" value="3600";
                                        button class="bad" type="submit" { "Chặn" }
                                    }
                                    " "
                                    form method="post" action={"/agent/" (h.id) "/unban"} style="display:inline;margin:0" {
                                        input type="hidden" name="ip" value=(input);
                                        button class="ghost" type="submit" { "Gỡ chặn" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            p class="help" { "“Chặn” có hiệu lực 1 giờ, áp dụng ở lần quét kế tiếp của VPS (tối đa ~15 phút)." }
        }

        @if !history.is_empty() {
            div class="card" {
                h2 { "Lịch sử thao tác của admin với IP này" }
                div class="wrap" {
                    table {
                        thead { tr { th { "Thời gian" } th { "VPS" } th { "Người" } th { "Thao tác" } } }
                        tbody { @for (agent, who, action, _, ts) in &history {
                            tr { td class="mut" { (rel_time(*ts)) } td { (agent) } td { (who) } td { (action_vi(action)) } }
                        }}
                    }
                }
            }
        }
    };
    Html(shell("Tra cứu IP", body).into_string()).into_response()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_of_normalizes_ipv4_and_ipv6() {
        assert_eq!(key_of(" 203.0.113.7 "), "203.0.113.7");
        // IPv6 is tracked per /64.
        assert_eq!(key_of("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        // An already-aggregated key is kept as written.
        assert_eq!(key_of("2001:db8:1:2::/64"), "2001:db8:1:2::/64");
        // IPv4-mapped IPv6 collapses to the IPv4 address.
        assert_eq!(key_of("::ffff:203.0.113.7"), "203.0.113.7");
        // Non-addresses are compared verbatim (e.g. decision details).
        assert_eq!(key_of("hunt 1 ngày"), "hunt 1 ngày");
    }

    #[test]
    fn special_addresses_are_flagged() {
        let note = |s: &str| special_ip_note(s.parse().unwrap());
        assert!(note("127.0.0.1").is_some());
        assert!(note("10.1.2.3").is_some());
        assert!(note("192.168.0.9").is_some());
        assert!(note("::1").is_some());
        assert!(note("fd00::1").is_some());
        assert!(note("203.0.113.7").is_none());
        assert!(note("2001:db8::1").is_none());
    }

    fn stat(key: &str, flagged: bool) -> snsec_common::schema::PatternStat {
        snsec_common::schema::PatternStat {
            key: key.into(),
            requests: 400,
            ips: 190,
            ips_capped: false,
            flagged,
            sample_ips: vec!["203.0.113.5".into(), "198.51.100.9".into()],
        }
    }

    #[test]
    fn a_flagged_pattern_shows_a_rule_and_sample_ips_but_a_normal_one_does_not() {
        let rows = [
            stat("GET /?tss-sc&tsscat", true),
            stat("GET /shop?page", false),
        ];
        let html = pattern_table("t", "k", &rows, snsec_common::waf::rule_for_shape).into_string();
        assert!(html.contains("Bất thường"));
        assert!(html.contains("SecRule REQUEST_METHOD"));
        assert!(html.contains("203.0.113.5"));
        // Only one row is flagged, so only one rule is offered.
        assert_eq!(html.matches("SecRule REQUEST_METHOD").count(), 1);
    }

    #[test]
    fn log_values_cannot_inject_markup_into_the_table() {
        let evil = "<script>alert(1)</script>";
        let html = pattern_table(
            "t",
            "k",
            &[stat(evil, true)],
            snsec_common::waf::rule_for_user_agent,
        )
        .into_string();
        assert!(!html.contains("<script>alert(1)"), "{html}");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_new_alert_kinds_have_vietnamese_labels() {
        for k in ["cpu_high", "bot_ua", "bot_shape"] {
            assert_ne!(alert_kind_vi(k), k, "{k} has no label");
        }
    }

    fn report_with(active: Vec<snsec_common::schema::ActiveBanInfo>) -> ReportBody {
        use snsec_common::schema::{CycleStats, HostInfo};
        let total = active.len() as u32;
        ReportBody {
            agent_version: "t".into(),
            host: HostInfo::default(),
            cycle: CycleStats::default(),
            bans: vec![],
            would_ban: vec![],
            alerts: vec![],
            triage: None,
            findings: vec![],
            applied_desired: Default::default(),
            capabilities: vec![],
            active_bans: active,
            active_bans_total: total,
            hunt: None,
        }
    }

    fn admin_ban(ip: &str, created_at: i64, ttl: u64) -> DesiredBan {
        DesiredBan {
            ip: ip.into(),
            ttl_secs: ttl,
            reason: "admin".into(),
            created_at,
        }
    }

    #[test]
    fn admin_ban_shows_up_before_the_vps_confirms_it() {
        // The reported bug: a ban ordered from the hub counted as 0 because
        // only the agent's own automatic bans were shown.
        let desired = DesiredBody {
            bans: vec![admin_ban("203.0.113.7", 1_000, 3600)],
            ..Default::default()
        };
        let v = ban_views(Some(&report_with(vec![])), Some(&desired), 1_500);
        assert_eq!(v.len(), 1);
        assert!(!v[0].applied, "not yet confirmed by the VPS");
        assert!(v[0].by_admin);
        assert_eq!(v[0].expires_at, 4_600);
    }

    #[test]
    fn confirmed_ban_is_not_counted_twice() {
        let desired = DesiredBody {
            bans: vec![admin_ban("203.0.113.7", 1_000, 3600)],
            ..Default::default()
        };
        let active = vec![snsec_common::schema::ActiveBanInfo {
            ip: "203.0.113.7".into(),
            reason: "hub".into(),
            expires_at: 4_600,
            strike: 0,
            layer: "l3".into(),
        }];
        let v = ban_views(Some(&report_with(active)), Some(&desired), 1_500);
        assert_eq!(v.len(), 1);
        assert!(v[0].applied);
        assert!(v[0].by_admin, "reason \"hub\" means ordered from the hub");
    }

    #[test]
    fn lapsed_and_legacy_bans_are_ignored() {
        let desired = DesiredBody {
            bans: vec![
                admin_ban("198.51.100.1", 1_000, 60), // lapsed by t=2000
                admin_ban("198.51.100.2", 0, 3600),   // no timestamp: age unknown
            ],
            ..Default::default()
        };
        assert!(ban_views(None, Some(&desired), 2_000).is_empty());
    }

    #[test]
    fn ipv6_bans_match_on_the_slash_64() {
        let desired = DesiredBody {
            bans: vec![admin_ban("2001:db8:1:2:3:4:5:6", 1_000, 3600)],
            ..Default::default()
        };
        let active = vec![snsec_common::schema::ActiveBanInfo {
            ip: "2001:db8:1:2::/64".into(),
            reason: "probe".into(),
            expires_at: 9_000,
            strike: 1,
            layer: "l3".into(),
        }];
        // The agent reports the /64; the admin typed a single address. Same ban.
        let v = ban_views(Some(&report_with(active)), Some(&desired), 1_500);
        assert_eq!(v.len(), 1);
        assert!(v[0].applied);
        assert!(!v[0].by_admin);
    }

    #[test]
    fn paging_covers_every_row_exactly_once() {
        // 120 rows, 50 per page -> 3 pages: 0..50, 50..100, 100..120.
        assert_eq!(page_bounds(120, 1, 50), (0, 50, 1, 3));
        assert_eq!(page_bounds(120, 2, 50), (50, 100, 2, 3));
        assert_eq!(page_bounds(120, 3, 50), (100, 120, 3, 3));
        // An exact multiple does not add an empty trailing page.
        assert_eq!(page_bounds(100, 2, 50), (50, 100, 2, 2));
        // Out-of-range pages clamp instead of slicing out of bounds.
        assert_eq!(page_bounds(120, 0, 50), (0, 50, 1, 3));
        assert_eq!(page_bounds(120, 99, 50), (100, 120, 3, 3));
        // An empty list is one empty page.
        assert_eq!(page_bounds(0, 1, 50), (0, 0, 1, 1));
        assert_eq!(page_bounds(0, 7, 50), (0, 0, 1, 1));
    }

    #[test]
    fn urlenc_escapes_everything_unsafe() {
        assert_eq!(urlenc("203.0.113"), "203.0.113");
        assert_eq!(urlenc("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(urlenc("2001:db8::1"), "2001%3Adb8%3A%3A1");
        assert_eq!(urlenc("đ"), "%C4%91");
        assert_eq!(
            bans_url("web-01-ab12cd", "10.0 ", 2),
            "/agent/web-01-ab12cd?page=2&q=10.0%20#bans"
        );
        assert_eq!(bans_url("x", "", 1), "/agent/x?page=1#bans");
    }

    #[test]
    fn truncated_blocklist_is_detected() {
        let mut r = report_with(vec![]);
        assert_eq!(ban_list_partial(Some(&r)), None);
        assert_eq!(hidden_bans(Some(&r)), 0);
        // The VPS says it blocks 1234 but listed 500.
        r.active_bans = (0..500)
            .map(|i| snsec_common::schema::ActiveBanInfo {
                ip: format!("10.0.{}.{}", i / 250, i % 250),
                reason: "rate".into(),
                expires_at: 9_999,
                strike: 1,
                layer: "l3".into(),
            })
            .collect();
        r.active_bans_total = 1234;
        assert_eq!(ban_list_partial(Some(&r)), Some((500, 1234)));
        assert_eq!(hidden_bans(Some(&r)), 734);
        // An older agent leaves the total at 0: never "partial", never negative.
        r.active_bans_total = 0;
        assert_eq!(ban_list_partial(Some(&r)), None);
        assert_eq!(hidden_bans(None), 0);
    }

    #[test]
    fn version_comparison_flags_only_older_agents() {
        assert_eq!(parse_version("0.2.0"), Some((0, 2, 0)));
        assert_eq!(parse_version("v1.10.3"), Some((1, 10, 3)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("abc"), None);
        // 0.1.0 is older than this hub build; "" (never reported) is not flagged.
        assert!(agent_outdated("0.0.1"));
        assert!(!agent_outdated(""));
        assert!(!agent_outdated("not-a-version"));
        assert!(!agent_outdated(HUB_VERSION));
        // Numeric, not lexical: 0.10.0 is newer than 0.9.0.
        assert!(parse_version("0.10.0") > parse_version("0.9.0"));
    }

    #[test]
    fn mem_badge_thresholds() {
        let cls = |p| mem_badge(Some(p)).into_string();
        assert!(cls(10.0).contains("b-ok"));
        assert!(cls(75.0).contains("b-warn"));
        assert!(cls(89.9).contains("b-warn"));
        assert!(cls(90.0).contains("b-bad"));
        assert!(mem_badge(None).into_string().contains("—"));
    }
}
