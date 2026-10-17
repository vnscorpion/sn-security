//! The "AI phân tích traffic" card on a VPS page and the buttons behind it.
//!
//! Everything shown that came from the model or from a VPS's traffic (the
//! summary, the reasons, a rule's value, an address) goes through maud, which
//! escapes it.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use snsec_common::ai;
use snsec_common::waf::WafKind;

use crate::AppState;
use crate::analysis;
use crate::db_ai::AiState;
use crate::db_traffic::TrafficRow;
use crate::db_waf::kind_vi;
use crate::traffic_ai::{self, TrafficAction, TrafficItem};
use crate::web::{guard, now, rel_time, urlenc};
use crate::web_ai::autonomy_vi;

fn status_vi(s: &str) -> &'static str {
    match s {
        "proposed" => "Chờ duyệt",
        "done" => "Xong",
        "rejected" => "Đã bỏ qua",
        "error" => "Lỗi",
        _ => "?",
    }
}

fn status_cls(s: &str) -> &'static str {
    match s {
        "done" => "b-ok",
        "error" => "b-bad",
        "rejected" => "b-mut",
        _ => "b-warn",
    }
}

fn risk_badge(risk: &str) -> Markup {
    match risk {
        "low" => html! { span class="badge b-ok" { "Chưa chặn gì" } },
        _ => html! { span class="badge b-bad" { "Cắt IP" } },
    }
}

fn action_vi(it: &TrafficItem) -> Markup {
    match &it.action {
        TrafficAction::WafRule { kind, value } => html! {
            "Luật WAF, chỉ ghi nhận: "
            @if let Some(k) = WafKind::parse(kind) { b { (kind_vi(k)) } " " }
            code { (value) }
        },
        TrafficAction::BanIp { ip, ttl_secs } => html! {
            "Chặn " code { (ip) } " trong " b { (ttl_secs / 60) " phút" }
        },
    }
}

fn back(id: &str, msg: &str) -> Response {
    Redirect::to(&format!(
        "/agent/{id}?msg={}&at=traffic#traffic",
        urlenc(msg)
    ))
    .into_response()
}

/// What the card shows, gathered under one database lock.
pub struct CardData {
    pub row: Option<TrafficRow>,
    pub state: AiState,
    pub has_provider: bool,
    pub running: bool,
}

pub fn card_data(st: &AppState, agent_id: &str) -> CardData {
    let db = st.db.lock().expect("db");
    CardData {
        row: db.latest_traffic(agent_id).ok().flatten(),
        state: db.ai_state(agent_id).unwrap_or_default(),
        has_provider: db.default_provider().ok().flatten().is_some(),
        running: analysis::running(agent_id),
    }
}

pub fn card(agent_id: &str, d: &CardData, msg: &str) -> Markup {
    html! {
        div class="card" id="traffic" {
            h2 { "AI phân tích traffic" }
            @if !msg.is_empty() {
                div class="note" { (msg) }
            }
            @if !d.has_provider {
                p { "Chưa cấu hình AI. " a href="/settings" { "Vào Cài đặt AI →" } }
            } @else {
                div class="ctrls" {
                    form method="post" action={"/agent/" (agent_id) "/traffic/analyze"} {
                        button type="submit" disabled[d.running] { "Phân tích traffic" }
                    }
                    form method="post" action={"/agent/" (agent_id) "/ai/autonomy"} {
                        label class="f" {
                            span class="t" { "Mức tự xử lý" }
                            select name="autonomy" {
                                @for a in [ai::AUTONOMY_OFF, ai::AUTONOMY_APPROVE, ai::AUTONOMY_AUTO_SAFE, ai::AUTONOMY_AUTO_ALL] {
                                    option value=(a) selected[d.state.autonomy == a] { (autonomy_vi(a)) }
                                }
                            }
                        }
                        button class="ghost" type="submit" { "Lưu" }
                    }
                }
                @if d.running {
                    p class="help" { span class="badge b-warn" { "Đang phân tích…" } }
                }
            }
            @if let Some(p) = &d.row {
                (proposal(agent_id, p))
            } @else if d.has_provider {
                p class="help" { "Chưa có phân tích. AI tự xem khi traffic có bất thường (tối đa 15 phút/lần), hoặc bấm “Phân tích traffic”." }
            }
        }
    }
}

fn proposal(agent_id: &str, p: &TrafficRow) -> Markup {
    let open = p.status == "proposed";
    let remaining = p.items.len().saturating_sub(p.applied.len());
    html! {
        hr class="divider";
        p class="help" {
            (rel_time(p.created)) " · " (p.provider) @if p.auto { " · tự động" } " "
            span class={"badge " (status_cls(&p.status))} { (status_vi(&p.status)) }
        }
        @if !p.note.is_empty() { p style="color:var(--warn)" { (p.note) } }
        @if !p.summary.is_empty() { p style="margin:8px 0" { (p.summary) } }
        @if p.items.is_empty() && p.status != "error" {
            p class="help" { "AI không đề xuất hành động nào." }
        }
        @if !p.items.is_empty() {
            div class="wrap" {
                table {
                    thead { tr { th { "#" } th { "Hành động" } th { "Mức" } th { "Lý do (AI)" } th {} } }
                    tbody {
                        @for (i, it) in p.items.iter().enumerate() {
                            tr {
                                td { (i + 1) }
                                td { (action_vi(it)) }
                                td { (risk_badge(&it.risk)) }
                                td class="mut" { (it.reason) }
                                td {
                                    @if p.applied.contains(&i) {
                                        span class="badge b-ok" { "Đã áp dụng" }
                                    } @else if open {
                                        form method="post" action={"/agent/" (agent_id) "/traffic/" (p.id) "/apply"} style="margin:0" {
                                            input type="hidden" name="idx" value=(i);
                                            button class="ghost" type="submit" { "Áp dụng" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if open && remaining > 0 {
                div class="ctrls" style="margin-top:12px" {
                    form method="post" action={"/agent/" (agent_id) "/traffic/" (p.id) "/apply"} {
                        input type="hidden" name="idx" value="all";
                        button type="submit" onclick="return confirm('Áp dụng tất cả đề xuất chưa chạy?')" { "Áp dụng tất cả (" (remaining) ")" }
                    }
                    form method="post" action={"/agent/" (agent_id) "/traffic/" (p.id) "/reject"} {
                        button class="ghost" type="submit" { "Bỏ qua" }
                    }
                }
            }
        }
        @if !p.rejected.is_empty() {
            details {
                summary { "Hub đã loại " (p.rejected.len()) " đề xuất của AI" }
                ul { @for r in &p.rejected { li class="mut" { (r) } } }
            }
        }
    }
}

pub async fn analyze_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let msg = match traffic_ai::request(&st, &id) {
        Ok(m) => m,
        Err(e) => format!("{e:#}"),
    };
    back(&id, &msg)
}

#[derive(Deserialize)]
pub struct ApplyForm {
    /// `all` or the index of one action.
    idx: String,
}

pub async fn apply_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, pid)): Path<(String, i64)>,
    Form(f): Form<ApplyForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let Some(row) = db
        .get_traffic(pid)
        .ok()
        .flatten()
        .filter(|p| p.agent_id == id)
    else {
        drop(db);
        return back(&id, "Không có đề xuất này.");
    };
    if row.status != "proposed" {
        drop(db);
        return back(&id, "Đề xuất này đã xử lý rồi.");
    }
    let indices: Vec<usize> = if f.idx == "all" {
        (0..row.items.len()).collect()
    } else {
        match f.idx.parse::<usize>() {
            Ok(i) => vec![i],
            Err(_) => {
                drop(db);
                return back(&id, "Chỉ số không hợp lệ.");
            }
        }
    };
    let lines = traffic_ai::apply(&db, &row, &indices, "admin", now());
    drop(db);
    if lines.is_empty() {
        back(&id, "Không có gì mới để áp dụng.")
    } else {
        back(&id, &lines.join(" · "))
    }
}

pub async fn reject_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, pid)): Path<(String, i64)>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    if let Some(row) = db
        .get_traffic(pid)
        .ok()
        .flatten()
        .filter(|p| p.agent_id == id && p.status == "proposed")
    {
        let _ = db.update_traffic(row.id, "rejected", &row.applied, &row.note);
    }
    drop(db);
    back(&id, "Đã bỏ qua đề xuất.")
}
