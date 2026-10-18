//! The "Hermes" page: tokens for the MCP endpoint (`/mcp`) and how to connect an
//! outside agent such as Hermes to it.
//!
//! Making or revoking a token asks for the current password again: a token with
//! scope `act` can order every VPS (within the closed list of actions), so a
//! stolen session must not be able to mint one quietly.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;

use crate::AppState;
use crate::auth;
use crate::db_mcp::{SCOPE_ACT, SCOPE_PROPOSE, SCOPE_READ};
use crate::web::{guard, hub_base, now, rel_time, shell, urlenc};
use crate::web_auth::{Recheck, recheck_password};

fn scope_vi(scope: &str) -> &'static str {
    match scope {
        SCOPE_READ => "Chỉ xem",
        SCOPE_PROPOSE => "Xem + đề xuất (chờ duyệt)",
        SCOPE_ACT => "Toàn quyền xử lý",
        _ => "?",
    }
}

fn back(msg: &str) -> Response {
    Redirect::to(&format!("/settings/hermes?msg={}", urlenc(msg))).into_response()
}

#[derive(Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    msg: String,
}

pub async fn page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    render(&st, &q.msg, None)
}

/// The page; `fresh` is a token just made, shown this once.
fn render(st: &AppState, msg: &str, fresh: Option<(&str, &str, &str)>) -> Response {
    let tokens = st
        .db
        .lock()
        .map(|d| d.list_mcp_tokens())
        .unwrap_or_default();
    let url = format!("{}/mcp", hub_base(st));
    let body = html! {
        h1 { "Kết nối Hermes (MCP)" }
        p class="sub" {
            "Hub có sẵn một MCP server. Hermes Agent (hoặc agent nào hỗ trợ MCP qua HTTP) kết nối vào để đọc tình trạng các VPS, "
            "lấy bằng chứng sự cố và, nếu token cho phép, xử lý: chặn IP, quét mã độc, gửi và thực hiện kế hoạch xử lý."
        }
        @if !msg.is_empty() { div class="note" { (msg) } }
        @if let Some((name, scope, token)) = fresh {
            div class="card" style="border-color:var(--warn)" {
                h2 { "Token mới: " (name) " (" (scope_vi(scope)) ")" }
                p { b { "Chép ngay, hub không hiện lại token này." } }
                pre style="user-select:all;font-size:15px" { (token) }
                (config_snippet(&url, Some(token)))
            }
        }
        div class="card" {
            h2 { "Token đang dùng" }
            @if tokens.is_empty() {
                div class="empty" { "Chưa có token nào." }
            } @else {
                div class="wrap" { table {
                    thead { tr { th { "Tên" } th { "Quyền" } th { "Tạo" } th { "Dùng lần cuối" } th {} } }
                    tbody { @for t in &tokens { tr {
                        td { (t.name) }
                        td { (scope_vi(&t.scope)) }
                        td class="mut" { (rel_time(t.created)) }
                        td class="mut" {
                            @if t.last_used > 0 { (rel_time(t.last_used)) " · " code { (t.last_ip) } } @else { "chưa" }
                        }
                        td {
                            form method="post" action={"/settings/hermes/token/" (t.id) "/revoke"} style="margin:0;display:flex;gap:6px"
                                onsubmit="return confirm('Thu hồi token này? Hermes dùng nó sẽ mất kết nối ngay.')" {
                                input type="password" name="password" placeholder="Mật khẩu hiện tại" required style="width:150px" autocomplete="current-password";
                                button class="bad" type="submit" { "Thu hồi" }
                            }
                        }
                    } } }
                } }
            }
        }
        div class="pair" {
        div class="card" {
            h2 { "Tạo token" }
            form method="post" action="/settings/hermes/token" {
                div class="ctrls" {
                    label class="f" { span class="t" { "Tên gợi nhớ" } input type="text" name="name" value="hermes" maxlength="40" required; }
                    label class="f" { span class="t" { "Quyền" }
                        select name="scope" {
                            option value=(SCOPE_READ) { "Chỉ xem" }
                            option value=(SCOPE_PROPOSE) selected { "Xem + đề xuất (admin duyệt)" }
                            option value=(SCOPE_ACT) { "Toàn quyền xử lý" }
                        }
                    }
                    label class="f" { span class="t" { "Mật khẩu hiện tại" } input type="password" name="password" required autocomplete="current-password"; }
                    button type="submit" { "Tạo token" }
                }
            }
            ul class="help" style="margin:10px 0 0;padding-left:18px" {
                li { b { "Chỉ xem" } ": danh sách VPS, trạng thái, bằng chứng, các đề xuất, nhật ký." }
                li { b { "Xem + đề xuất" } ": thêm yêu cầu VPS thu thập bằng chứng và gửi kế hoạch xử lý; kế hoạch chờ bạn duyệt trên trang VPS như đề xuất của AI tích hợp." }
                li { b { "Toàn quyền xử lý" } ": thêm thực hiện kế hoạch ngay, chặn/bỏ chặn IP, đổi chế độ, quét mã độc, cài ClamAV. "
                    "Vẫn chỉ trong danh sách hành động cố định, mỗi hành động được hub đối chiếu với bằng chứng của VPS và agent kiểm lại trước khi làm; "
                    "không có lệnh tuỳ ý nào chạy trên VPS. Hub còn giới hạn thêm: chỉ chặn IP công khai, tối đa 500 lệnh chặn mỗi VPS, "
                    "60 thao tác thay đổi mỗi giờ mỗi token, chỉ gỡ được lệnh chặn do hub đặt, chỉ bật chứ không tắt chế độ tự chặn. "
                    "Muốn Hermes tự xử lý cấp cứu không cần bạn bấm thì chọn mức này." }
            }
            p class="help" { "Mọi thao tác qua token được ghi vào Nhật ký với tên " code { "mcp:<tên token>" } ". Giữ token như mật khẩu (trong ~/.hermes/.env, quyền 600); lộ thì thu hồi ở đây." }
        }
        div class="card" {
            h2 { "Cấu hình Hermes" }
            (config_snippet(&url, None))
        }
        }
    };
    Html(shell("Hermes", body).into_string()).into_response()
}

fn config_snippet(url: &str, token: Option<&str>) -> Markup {
    let env_line = format!("SNSEC_MCP_TOKEN={}", token.unwrap_or("snmcp_…"));
    let yaml = format!(
        "mcp_servers:\n  snsec:\n    url: \"{url}\"\n    headers:\n      Authorization: \"Bearer ${{SNSEC_MCP_TOKEN}}\"\n    timeout: 120\n    connect_timeout: 30\n    # Bỏ dấu # dòng dưới để Hermes hỏi bạn trước mỗi công cụ không chỉ-đọc:\n    # trust: untrusted"
    );
    html! {
        p { "1. Thêm vào " code { "~/.hermes/.env" } ":" }
        pre style="user-select:all" { (env_line) }
        p { "2. Thêm vào " code { "~/.hermes/config.yaml" } ":" }
        pre style="user-select:all" { (yaml) }
        p { "3. Kiểm tra: " code { "hermes mcp test snsec" } " (hoặc " code { "/reload-mcp" } " trong phiên đang chạy). Công cụ hiện ra dạng " code { "mcp__snsec__list_vps" } ", " code { "mcp__snsec__get_vps_status" } "…" }
        p class="help" {
            "Hermes chạy trên chính máy hub thì có thể dùng " code { "http://127.0.0.1:8099/mcp" } " (không qua Internet). "
            "Đặt " code { "trust: untrusted" } " nếu muốn Hermes hỏi bạn trước mọi công cụ không chỉ-đọc (bỏ đi nếu muốn Hermes tự xử lý, kể cả trong cron). "
            "Nếu reverse proxy (Caddy) của hub có giới hạn IP cho giao diện quản trị, hãy cho đường dẫn " code { "/mcp" } " đi qua riêng (xem deploy/examples/Caddyfile), "
            "nếu không Hermes chỉ nhận được 403."
        }
    }
}

#[derive(Deserialize)]
pub struct CreateForm {
    name: String,
    scope: String,
    password: String,
}

pub async fn create_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<CreateForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    match recheck_password(&st, &headers, f.password).await {
        Recheck::Right => {}
        Recheck::Wrong => return back("Mật khẩu hiện tại không đúng."),
        Recheck::Wait(w) => return back(&format!("Thử quá nhiều lần, chờ {w} giây.")),
    }
    let at = now();
    // Each token has its own name, so the log says which one did what.
    if st.db.lock().is_ok_and(|d| d.mcp_name_taken(&f.name)) {
        return back("Tên này đã có token khác dùng: đặt tên khác (ví dụ theo máy chạy Hermes).");
    }
    let made = st
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("db"))
        .and_then(|d| {
            let r = d.create_mcp_token(&f.name, &f.scope, at);
            if let Ok((_, _)) = &r {
                d.log_login(
                    at,
                    &auth::client_ip(&headers),
                    true,
                    "tạo token Hermes",
                    &f.scope,
                );
            }
            r
        });
    match made {
        Ok((id, token)) => {
            let name = st
                .db
                .lock()
                .ok()
                .and_then(|d| d.list_mcp_tokens().into_iter().find(|t| t.id == id))
                .map(|t| t.name)
                .unwrap_or_default();
            render(&st, "", Some((&name, &f.scope, &token)))
        }
        Err(e) => back(&format!("Không tạo được token: {e:#}")),
    }
}

#[derive(Deserialize)]
pub struct RevokeForm {
    password: String,
}

pub async fn revoke_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<RevokeForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    match recheck_password(&st, &headers, f.password).await {
        Recheck::Right => {}
        Recheck::Wrong => return back("Mật khẩu hiện tại không đúng."),
        Recheck::Wait(w) => return back(&format!("Thử quá nhiều lần, chờ {w} giây.")),
    }
    let ok = st
        .db
        .lock()
        .map(|d| {
            let ok = d.revoke_mcp_token(id).unwrap_or(false);
            if ok {
                d.log_login(
                    now(),
                    &auth::client_ip(&headers),
                    true,
                    "thu hồi token Hermes",
                    &id.to_string(),
                );
            }
            ok
        })
        .unwrap_or(false);
    back(if ok {
        "Đã thu hồi token."
    } else {
        "Không tìm thấy token."
    })
}
