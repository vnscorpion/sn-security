//! The "WAF" page: ModSecurity rules the hub orders onto the VPSes.
//!
//! Blocking by what a request *is* (a scanner's User-Agent, a probe for
//! `/.env`, a bot's request shape) instead of by address: a shopper behind the
//! same carrier NAT as a bot is not blocked. Every rule starts log-only; the
//! page shows how often it matched and examples, and an admin then lets it block.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use snsec_common::schema::WafStatus;
use snsec_common::waf::{MAX_WAF_RULES, WafKind};

use crate::AppState;
use crate::db::AgentRow;
use crate::db_waf::{AddOutcome, STARTER_PATHS, STARTER_TOKENS, WafHits, WafRuleRow, kind_vi};
use crate::web::{guard, now, rel_time, shell, urlenc};

fn back(msg: &str, agent: &str) -> Response {
    // Only two places to return to, both built here: no open redirect.
    if !agent.is_empty()
        && agent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Redirect::to(&format!("/agent/{agent}?at=waf&msg={}#waf", urlenc(msg)))
            .into_response();
    }
    Redirect::to(&format!("/waf?msg={}", urlenc(msg))).into_response()
}

#[derive(Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    msg: String,
}

/// What the configuration on a VPS means for a blocking rule.
pub(crate) fn engine_badge(w: &WafStatus) -> Markup {
    let (cls, text) = match w.engine.as_str() {
        "on" => ("b-ok", "Đang bật"),
        "detection_only" => ("b-warn", "Chỉ ghi nhận (DetectionOnly)"),
        "off" => ("b-bad", "Tắt"),
        "missing" => ("b-bad", "Chưa cài"),
        _ => ("b-mut", "Không rõ"),
    };
    html! { span class={"badge " (cls)} { (text) } }
}

fn server_vi(s: &str) -> &str {
    match s {
        "apache" => "Apache",
        "litespeed" => "LiteSpeed",
        "openlitespeed" => "OpenLiteSpeed",
        "nginx" => "Nginx",
        "" => "không nhận ra",
        other => other,
    }
}

/// One line per VPS: web server, ModSecurity state, rules in force, last error.
pub(crate) fn status_row(a: &AgentRow, w: Option<&WafStatus>) -> Markup {
    html! {
        tr {
            td { a href={"/agent/" (a.id)} { (a.name) } }
            @match w {
                None => {
                    td colspan="4" class="mut" { "Agent chưa hỗ trợ WAF (bản " (a.version) "): cập nhật agent trên VPS này." }
                }
                Some(w) => {
                    td { (server_vi(&w.server)) }
                    td { (engine_badge(w)) }
                    td {
                        (w.applied) " luật"
                        @if w.blocking > 0 { ", " (w.blocking) " đang chặn" }
                        @if !w.refused.is_empty() { br; span class="mut" { "Agent bỏ qua: #" (join_ids(&w.refused)) } }
                        @if !w.rules_file.is_empty() { br; code { (w.rules_file) } }
                        @for n in w.notes.iter().take(5) { br; span style="color:var(--warn);font-size:12px" { (n) } }
                    }
                    td {
                        @if !w.error.is_empty() {
                            span class="badge b-bad" { "Lỗi " (rel_time(w.error_at)) }
                            pre style="margin:6px 0 0;font-size:12px" { (w.error) }
                        } @else if w.applied_at > 0 {
                            span class="mut" { "Áp dụng " (rel_time(w.applied_at)) }
                        } @else {
                            span class="mut" { "Chưa áp dụng" }
                        }
                    }
                }
            }
        }
    }
}

fn join_ids(ids: &[u32]) -> String {
    ids.iter()
        .take(20)
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", #")
}

/// The rules table. `scope_names` maps agent ids to names for the scope column;
/// `here` is the VPS page the table sits on (forms come back to it).
pub(crate) fn rules_table(
    rules: &[WafRuleRow],
    hits: &HashMap<u32, WafHits>,
    scope_names: &HashMap<String, String>,
    here: &str,
) -> Markup {
    html! {
        div class="wrap" {
            table {
                thead { tr { th { "#" } th { "Loại" } th { "Giá trị" } th { "Phạm vi" } th { "Chế độ" } th { "Trúng" } th {} } }
                tbody {
                    @if rules.is_empty() { tr { td colspan="7" { div class="empty" { "Chưa có luật nào" } } } }
                    @for r in rules {
                        @let h = hits.get(&r.id);
                        tr {
                            td class="mut" { (r.id) }
                            td { (kind_vi(r.kind)) }
                            td {
                                code style="word-break:break-all" { (r.value) }
                                @if !r.note.is_empty() { br; span class="mut" style="font-size:12px" { (r.note) } }
                            }
                            td {
                                @if r.agent_id.is_empty() { "Mọi VPS" }
                                @else { (scope_names.get(&r.agent_id).map_or(r.agent_id.as_str(), String::as_str)) }
                            }
                            td {
                                @if r.block { span class="badge b-bad" { "Chặn (403)" } }
                                @else { span class="badge b-mut" { "Chỉ ghi nhận" } }
                                br; span class="mut" style="font-size:12px" { (rel_time(r.updated_at)) " · " (r.updated_by) }
                            }
                            td {
                                @match h {
                                    Some(h) if h.count > 0 => {
                                        b { (h.count) } " lần"
                                        @if h.blocked > 0 { br; span class="badge b-bad" style="font-size:11px" { (h.blocked) " trả 403" } }
                                        br; span class="mut" style="font-size:12px" { "gần nhất " (rel_time(h.last_at)) }
                                        @if !h.samples.is_empty() {
                                            details {
                                                summary class="mut" style="font-size:12px" { "Ví dụ" }
                                                @for s in &h.samples { div style="font-family:monospace;font-size:12px;word-break:break-all" { (s) } }
                                            }
                                        }
                                    }
                                    _ => { span class="mut" { "0" } }
                                }
                            }
                            td style="white-space:nowrap" {
                                form method="post" action={"/waf/" (r.id) "/block"} style="display:inline" {
                                    input type="hidden" name="back" value=(here);
                                    @if r.block {
                                        input type="hidden" name="on" value="0";
                                        button class="ghost" type="submit" { "Chỉ ghi nhận" }
                                    } @else {
                                        input type="hidden" name="on" value="1";
                                        button type="submit" { "Bật chặn" }
                                    }
                                }
                                " "
                                form method="post" action={"/waf/" (r.id) "/delete"} style="display:inline" {
                                    input type="hidden" name="back" value=(here);
                                    button class="ghost" type="submit" { "Xoá" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The "add a rule" form. `fixed_scope`: on a VPS page, the rule is for it.
pub(crate) fn add_form(agents: &[AgentRow], fixed_scope: Option<&str>) -> Markup {
    html! {
        form method="post" action="/waf/add" class="ctrls" style="gap:12px" {
            label class="f" { span class="t" { "Loại" }
                select name="kind" {
                    option value="path" { "Đường dẫn dò quét (vd /.env, /.git/)" }
                    option value="ua_token" { "Công cụ quét (từ trong User-Agent, vd sqlmap)" }
                    option value="user_agent" { "User-Agent (khớp nguyên chuỗi)" }
                    option value="shape" { "Kiểu request (METHOD /path?a&b)" }
                }
            }
            label class="f" style="flex:1;min-width:220px" { span class="t" { "Giá trị" }
                input type="text" name="value" required maxlength="250" style="width:100%" placeholder="/.env";
            }
            @if let Some(id) = fixed_scope {
                input type="hidden" name="scope" value=(id);
                input type="hidden" name="back" value=(id);
            } @else {
                label class="f" { span class="t" { "Áp cho" }
                    select name="scope" {
                        option value="" { "Mọi VPS" }
                        @for a in agents { option value=(a.id) { (a.name) } }
                    }
                }
            }
            label class="f" { span class="t" { "Ghi chú" }
                input type="text" name="note" maxlength="200" placeholder="(tuỳ chọn)";
            }
            button type="submit" { "Thêm (chỉ ghi nhận)" }
        }
        p class="help" {
            "Đường dẫn kết thúc bằng " code { "/" } " áp cho mọi thứ bên dưới. Công cụ quét: chữ thường, từ 4 ký tự, không trùng từ trình duyệt thật gửi."
        }
    }
}

pub async fn page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let agents = db.list_agents().unwrap_or_default();
    let statuses: Vec<(AgentRow, Option<WafStatus>)> = agents
        .iter()
        .map(|a| {
            let w = db.latest_report(&a.id).ok().flatten().and_then(|r| r.waf);
            (a.clone(), w)
        })
        .collect();
    let rules = db.list_waf_rules().unwrap_or_default();
    let hits = db.waf_hits(None).unwrap_or_default();
    drop(db);
    let names: HashMap<String, String> = agents
        .iter()
        .map(|a| (a.id.clone(), a.name.clone()))
        .collect();
    let not_blocking = statuses
        .iter()
        .filter(|(_, w)| w.as_ref().is_some_and(|w| w.engine != "on"))
        .count();
    let body = html! {
        h1 { "WAF (ModSecurity)" }
        p class="sub" {
            "Chặn theo nội dung request thay vì chặn IP. Luật mới chỉ " b { "ghi nhận" } ": xem số lần trúng và ví dụ, đúng thì bấm "
            b { "Bật chặn" } " (trả 403)."
        }
        @if !q.msg.is_empty() { div class="note" { (q.msg) } }
        @if not_blocking > 0 {
            div class="note" style="border-left-color:var(--warn)" {
                (not_blocking) " VPS có ModSecurity không ở trạng thái bật: luật ở đó chỉ ghi nhận (hoặc không chạy), kể cả luật đã bật chặn."
            }
        }
        div class="card" {
            h2 { "Trên từng VPS" }
            div class="wrap" {
                table {
                    thead { tr { th { "VPS" } th { "Máy chủ web" } th { "ModSecurity" } th { "Luật" } th { "Lần áp gần nhất" } } }
                    tbody {
                        @if statuses.is_empty() { tr { td colspan="5" { div class="empty" { "Chưa có VPS" } } } }
                        @for (a, w) in &statuses { (status_row(a, w.as_ref())) }
                    }
                }
            }
        }
        div class="card" {
            h2 { "Luật (" (rules.len()) ")" }
            (rules_table(&rules, &hits, &names, ""))
        }
        div class="card" {
            h2 { "Thêm luật" }
            (add_form(&agents, None))
            hr class="divider";
            form method="post" action="/waf/starter" class="ctrls" {
                button class="ghost" type="submit" { "Thêm gói luật cơ bản (chỉ ghi nhận)" }
            }
            p class="help" {
                "Gói cơ bản: dò file " code { (STARTER_PATHS.join(" ")) }
                " và công cụ quét " code { (STARTER_TOKENS.join(" ")) } ". Tối đa " (MAX_WAF_RULES) " luật cho một VPS."
            }
        }
    };
    Html(shell("WAF", body).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct AddForm {
    kind: String,
    value: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    back: String,
}

pub async fn add_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<AddForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let Some(kind) = WafKind::parse(&f.kind) else {
        return back("Loại luật không hợp lệ.", &f.back);
    };
    let db = st.db.lock().expect("db");
    let msg = match db.add_waf_rule(kind, &f.value, f.scope.trim(), &f.note, "admin", now()) {
        Ok(AddOutcome::Added(id)) => format!("Đã thêm luật #{id} ở chế độ chỉ ghi nhận."),
        Ok(AddOutcome::Exists(id)) => format!("Luật này đã có (#{id})."),
        Err(e) => format!("Không thêm được: {e}"),
    };
    drop(db);
    back(&msg, &f.back)
}

#[derive(Deserialize)]
pub struct BlockForm {
    on: String,
    #[serde(default)]
    back: String,
}

pub async fn block_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<u32>,
    Form(f): Form<BlockForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let block = f.on == "1";
    let db = st.db.lock().expect("db");
    let msg = match db.set_waf_block(id, block, "admin", now()) {
        Ok(true) if block => format!("Luật #{id} sẽ chặn (403) sau lần VPS lấy lệnh kế tiếp."),
        Ok(true) => format!("Luật #{id} trở về chỉ ghi nhận."),
        Ok(false) => "Không có luật này.".to_string(),
        Err(e) => format!("Lỗi: {e}"),
    };
    drop(db);
    back(&msg, &f.back)
}

#[derive(Deserialize)]
pub struct BackForm {
    #[serde(default)]
    back: String,
}

pub async fn delete_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<u32>,
    Form(f): Form<BackForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let msg = match db.remove_waf_rule(id, "admin", now()) {
        Ok(true) => format!("Đã xoá luật #{id}."),
        Ok(false) => "Không có luật này.".to_string(),
        Err(e) => format!("Lỗi: {e}"),
    };
    drop(db);
    back(&msg, &f.back)
}

pub async fn starter_post(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let msg = match db.add_waf_starter("admin", now()) {
        Ok(0) => "Gói cơ bản đã có đủ.".to_string(),
        Ok(n) => format!("Đã thêm {n} luật cơ bản ở chế độ chỉ ghi nhận."),
        Err(e) => format!("Không thêm được: {e}"),
    };
    drop(db);
    back(&msg, "")
}
