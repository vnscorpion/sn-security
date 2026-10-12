//! The hub pages for AI-assisted incident response: the settings page where the
//! operator enters an endpoint, a model and a key (any OpenAI-compatible server
//! or Anthropic), and the "AI" card on a VPS page with the analysis, the
//! proposed actions and the buttons that carry them out.
//!
//! Everything shown that came from a VPS or from the model (command lines, file
//! names, the diagnosis, the reasons) goes through maud, which escapes it.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;
use snsec_common::ai::{self, Proposed};
use snsec_common::schema::{Action, Evidence, ReportBody};

use crate::AppState;
use crate::ai_client::{self, KIND_ANTHROPIC, KIND_OPENAI};
use crate::analysis;
use crate::db_ai::{AiState, ProposalRow, ProviderInput};
use crate::web::{guard, now, rel_time, shell, urlenc};

// ---------------------------------------------------------------------------
// Wording
// ---------------------------------------------------------------------------

#[must_use]
pub fn autonomy_vi(a: &str) -> &'static str {
    match a {
        ai::AUTONOMY_OFF => "Tắt: AI không tự chạy khi có sự cố (vẫn bấm tay được)",
        ai::AUTONOMY_APPROVE => {
            "Duyệt từng bước: AI tự phân tích khi có sự cố, bạn bấm đồng ý (mặc định)"
        }
        ai::AUTONOMY_AUTO_SAFE => {
            "Tự xử lý việc hoàn tác được: cách ly file, khoá shell, gỡ dòng độc, tắt dịch vụ. Việc không hoàn tác được (dừng tiến trình) vẫn chờ bạn"
        }
        ai::AUTONOMY_AUTO_ALL => "Tự xử lý tất cả, kể cả dừng tiến trình",
        _ => "?",
    }
}

fn status_vi(s: &str) -> &'static str {
    match s {
        "proposed" => "Chờ duyệt",
        "executing" => "Đã gửi lệnh, chờ VPS thực hiện",
        "done" => "Đã thực hiện",
        "rejected" => "Đã bỏ qua",
        "error" => "Lỗi",
        _ => "?",
    }
}

fn risk_badge(risk: &str) -> Markup {
    match risk {
        "low" => html! { span class="badge b-ok" { "Thấp · hoàn tác được" } },
        "medium" => html! { span class="badge b-warn" { "Vừa · hoàn tác được" } },
        _ => html! { span class="badge b-bad" { "Cao · không hoàn tác được" } },
    }
}

/// What an action does, in words, with detail from the evidence it points at.
fn action_vi(a: &Action, ev: Option<&Evidence>) -> Markup {
    match a {
        Action::KillProcess { pid, starttime } => {
            let p = ev.and_then(|e| {
                e.processes
                    .iter()
                    .find(|p| p.pid == *pid && p.starttime == *starttime)
            });
            html! {
                "Dừng tiến trình " b { (pid) }
                @if let Some(p) = p {
                    " (" code { (p.comm) } ", tài khoản " (p.user) ", " code { (p.exe) } ")"
                }
            }
        }
        Action::LockUserShell { user } => {
            html! { "Khoá shell đăng nhập của tài khoản " b { (user) } " (đổi sang nologin)" }
        }
        Action::QuarantineFile { path } => {
            html! { "Cách ly file " code { (path) } " (chuyển vào kho cách ly, khôi phục được)" }
        }
        Action::RemoveShellLine {
            path,
            line_no,
            sha256,
        } => {
            let line = ev.and_then(|e| {
                e.persistence
                    .iter()
                    .find(|p| p.path == *path && p.line_no == *line_no && p.sha256 == *sha256)
            });
            html! {
                "Gỡ dòng " b { (line_no) } " khỏi " code { (path) }
                @if let Some(l) = line { ": " code { (l.line) } }
            }
        }
        Action::DisableService { unit } => {
            html! { "Tắt và vô hiệu hoá dịch vụ " b { (unit) } }
        }
    }
}

fn back(id: &str, msg: &str) -> Response {
    Redirect::to(&format!("/agent/{id}?msg={}#ai", urlenc(msg))).into_response()
}

// ---------------------------------------------------------------------------
// The card on a VPS page
// ---------------------------------------------------------------------------

/// Everything the card needs, gathered by the page handler under one db lock.
pub struct AiCardData {
    pub state: AiState,
    pub proposal: Option<ProposalRow>,
    pub evidence: Option<Evidence>,
    pub has_provider: bool,
    pub provider_name: String,
}

pub fn ai_card(agent_id: &str, report: Option<&ReportBody>, d: &AiCardData, msg: &str) -> Markup {
    let can_evidence = report.is_some_and(|r| analysis::can(r, "evidence"));
    let can_remediate = report.is_some_and(|r| analysis::can(r, "remediate"));
    let pending =
        d.state.pending && now() - d.state.pending_since < crate::db_ai::PENDING_TIMEOUT_SECS;
    html! {
        div class="card" id="ai" {
            h2 { "AI xử lý sự cố" }
            @if !msg.is_empty() {
                div class="note" { (msg) }
            }
            p class="help" style="margin:0 0 12px" {
                "Agent thu thập bằng chứng (tiến trình, file khởi động shell, file lạ trong /tmp và /dev/shm, đăng nhập SSH, cổng đang mở), "
                "hub gửi cho AI bạn đã cấu hình để chẩn đoán và đề xuất hành động. AI chỉ được đề xuất trong một danh sách cố định và "
                "chỉ nhắm vào thứ có trong bằng chứng; agent kiểm tra lại trước khi làm."
            }

            @if !d.has_provider {
                p { "Chưa cấu hình AI. " a href="/settings" { "Vào Cài đặt AI →" } }
            } @else if !can_evidence {
                p class="help" {
                    "Agent trên VPS này cũ hoặc đã tắt thu thập bằng chứng nên chưa dùng được. Cập nhật agent: "
                    code { "install.sh --upgrade" } "."
                }
            } @else {
                div class="ctrls" {
                    form method="post" action={"/agent/" (agent_id) "/ai/analyze"} {
                        button type="submit" disabled[pending] { "Phân tích bằng AI" }
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
                p class="help" {
                    "Đang dùng: " b { (if d.provider_name.is_empty() { "—" } else { d.provider_name.as_str() }) }
                    " · " a href="/settings" { "Cài đặt AI" }
                    @if pending { " · " span class="badge b-warn" { "Đang chờ bằng chứng / phân tích…" } }
                    @if let Some(ev) = &d.evidence {
                        " · bằng chứng gần nhất " (rel_time(ev.at)) " · " a href={"/agent/" (agent_id) "/evidence.json"} { "xem JSON" }
                    }
                }
                @if d.state.autonomy == ai::AUTONOMY_AUTO_ALL || d.state.autonomy == ai::AUTONOMY_AUTO_SAFE {
                    div class="note" style="border-left-color:var(--warn)" {
                        "Mức tự xử lý đang bật: khi có sự cố (CPU cao liên tục, mã độc, tấn công diện rộng), AI sẽ được gọi và các hành động được phép sẽ chạy mà không cần bạn bấm. "
                        "Mọi hành động đều ghi lại để hoàn tác (trừ dừng tiến trình) và có thể xem ở Nhật ký."
                    }
                }
                @if !can_remediate {
                    p class="help" {
                        "VPS này chưa cho phép hub thực hiện hành động (AI vẫn phân tích và đề xuất được). Để bật, chạy trên VPS bằng root: "
                        code { "curl -fsSL <HUB>/install.sh | sudo sh -s -- --hub <HUB> --upgrade --allow-remote-fix" }
                    }
                }
            }

            @if let Some(p) = &d.proposal {
                (proposal_block(agent_id, p, d.evidence.as_ref(), can_remediate))
            }
        }
    }
}

fn proposal_block(
    agent_id: &str,
    p: &ProposalRow,
    ev: Option<&Evidence>,
    can_remediate: bool,
) -> Markup {
    let open = p.status == "proposed";
    html! {
        hr class="divider";
        h2 style="margin-top:0" {
            "Đề xuất #" (p.id) " "
            span class={"badge " (match p.status.as_str() { "done" => "b-ok", "error" => "b-bad", "rejected" => "b-mut", _ => "b-warn" })} { (status_vi(&p.status)) }
        }
        p class="help" { (rel_time(p.created)) " · " (p.provider) @if p.auto { " · tự động" } }
        @if !p.note.is_empty() { p style="color:var(--warn)" { (p.note) } }
        @if !p.diagnosis.is_empty() {
            p style="margin:8px 0" b { "Chẩn đoán: " } (p.diagnosis)
        }
        @if p.plan.proposed.is_empty() && p.status != "error" {
            p class="help" { "AI không đề xuất hành động nào." }
        }
        @if !p.plan.proposed.is_empty() {
            div class="wrap" {
                table {
                    thead { tr { th { "#" } th { "Hành động" } th { "Rủi ro" } th { "Lý do (AI)" } th {} } }
                    tbody {
                        @for (i, pr) in p.plan.proposed.iter().enumerate() {
                            (action_row(agent_id, p, i, pr, ev, open && can_remediate))
                        }
                    }
                }
            }
            @if open && can_remediate {
                @let remaining = p.plan.proposed.len().saturating_sub(p.applied.len());
                @if remaining > 0 {
                    div class="ctrls" style="margin-top:12px" {
                        form method="post" action={"/agent/" (agent_id) "/ai/" (p.id) "/apply"} {
                            input type="hidden" name="idx" value="all";
                            button type="submit" onclick="return confirm('Thực hiện tất cả hành động chưa chạy trên VPS này?')" { "Thực hiện tất cả (" (remaining) ")" }
                        }
                        form method="post" action={"/agent/" (agent_id) "/ai/" (p.id) "/reject"} {
                            button class="ghost" type="submit" { "Bỏ qua đề xuất" }
                        }
                    }
                }
            }
        }
        @if !p.plan.rejected.is_empty() {
            details {
                summary { "Hub đã loại " (p.plan.rejected.len()) " đề xuất của AI (không hợp lệ hoặc không có trong bằng chứng)" }
                ul { @for r in &p.plan.rejected { li class="mut" { (r) } } }
            }
        }
        @if let Some(res) = &p.result {
            h2 style="margin-top:14px" { "Kết quả trên VPS (" (rel_time(res.at)) ")" }
            div class="wrap" {
                table {
                    thead { tr { th { "Lệnh" } th { "Kết quả" } th { "Chi tiết" } } }
                    tbody { @for r in &res.results {
                        tr {
                            td { (r.index + 1) }
                            td { @if r.ok { span class="badge b-ok" { "Thành công" } } @else { span class="badge b-bad" { "Thất bại" } } }
                            td { (r.message) }
                        }
                    } }
                }
            }
            p class="help" {
                "Hoàn tác (trừ dừng tiến trình) chạy trên VPS bằng root: " code { "sn undo --remediation" } " (trả lại shell, dòng đã gỡ, bật lại dịch vụ) và " code { "sn restore <id>" } " (file đã cách ly). "
                "Nút “Hoàn tác” của hub chỉ gỡ chặn IP và thả nhốt tiến trình, không đụng tới việc của AI."
            }
        }
    }
}

fn action_row(
    agent_id: &str,
    p: &ProposalRow,
    i: usize,
    pr: &Proposed,
    ev: Option<&Evidence>,
    can_click: bool,
) -> Markup {
    let done = p.applied.contains(&i);
    html! {
        tr {
            td { (i + 1) }
            td { (action_vi(&pr.action, ev)) }
            td { (risk_badge(&pr.risk)) }
            td class="mut" { (pr.reason) }
            td {
                @if done {
                    span class="badge b-ok" { "Đã gửi lệnh" }
                } @else if can_click {
                    form method="post" action={"/agent/" (agent_id) "/ai/" (p.id) "/apply"} style="margin:0" {
                        input type="hidden" name="idx" value=(i);
                        button class="ghost" type="submit" { "Thực hiện" }
                    }
                }
            }
        }
    }
}

/// Gather what the card needs for `agent_id`.
pub fn card_data(st: &AppState, agent_id: &str) -> AiCardData {
    let db = st.db.lock().expect("db");
    AiCardData {
        state: db.ai_state(agent_id).unwrap_or_default(),
        proposal: db.latest_proposal(agent_id).ok().flatten(),
        evidence: db.latest_evidence(agent_id).ok().flatten(),
        has_provider: db.default_provider().ok().flatten().is_some(),
        provider_name: db
            .default_provider()
            .ok()
            .flatten()
            .map(|p| p.name)
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Handlers on a VPS
// ---------------------------------------------------------------------------

pub async fn ai_analyze_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let msg = match analysis::request(&st, &id) {
        Ok(m) => m,
        Err(e) => format!("{e:#}"),
    };
    back(&id, &msg)
}

#[derive(Deserialize)]
pub struct AutonomyForm {
    autonomy: String,
}

pub async fn ai_autonomy_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<AutonomyForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    if !ai::is_valid_autonomy(&f.autonomy) {
        return (StatusCode::BAD_REQUEST, "mức tự xử lý không hợp lệ").into_response();
    }
    let db = st.db.lock().expect("db");
    let _ = db.set_autonomy(&id, &f.autonomy);
    let _ = db.record_decision(&id, "admin", "ai_autonomy", &f.autonomy, now());
    drop(db);
    back(&id, "Đã lưu mức tự xử lý.")
}

#[derive(Deserialize)]
pub struct ApplyForm {
    /// `all` or the index of one action.
    idx: String,
}

pub async fn ai_apply_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, pid)): Path<(String, i64)>,
    Form(f): Form<ApplyForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    let Some(p) = db
        .get_proposal(pid)
        .ok()
        .flatten()
        .filter(|p| p.agent_id == id)
    else {
        return (StatusCode::NOT_FOUND, "đề xuất không tồn tại").into_response();
    };
    if !matches!(p.status.as_str(), "proposed" | "executing") {
        drop(db);
        return back(&id, "Đề xuất này không còn ở trạng thái chờ duyệt.");
    }
    let indices: Vec<usize> = if f.idx == "all" {
        (0..p.plan.proposed.len()).collect()
    } else {
        match f.idx.parse::<usize>() {
            Ok(i) => vec![i],
            Err(_) => return (StatusCode::BAD_REQUEST, "chỉ số không hợp lệ").into_response(),
        }
    };
    let msg = match analysis::order(&db, &id, &p, &indices, "admin", now()) {
        Ok(job) => format!(
            "Đã gửi lệnh cho VPS (mã {job}). Kết quả hiện ở đây sau lần báo cáo kế tiếp của VPS."
        ),
        Err(e) => format!("Không gửi được lệnh: {e:#}"),
    };
    drop(db);
    back(&id, &msg)
}

pub async fn ai_reject_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, pid)): Path<(String, i64)>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let db = st.db.lock().expect("db");
    if db
        .get_proposal(pid)
        .ok()
        .flatten()
        .is_some_and(|p| p.agent_id == id && p.status == "proposed")
    {
        let _ = db.set_proposal_status(pid, "rejected", "");
    }
    drop(db);
    back(&id, "Đã bỏ qua đề xuất.")
}

/// The evidence the hub holds for a VPS, as JSON, so the operator can read
/// exactly what an AI was given.
pub async fn evidence_download(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let ev = st
        .db
        .lock()
        .expect("db")
        .latest_evidence(&id)
        .ok()
        .flatten();
    match ev {
        Some(e) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    "application/json; charset=utf-8".to_string(),
                ),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            serde_json::to_string_pretty(&e).unwrap_or_default(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Chưa có bằng chứng").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Settings page
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SettingsQuery {
    #[serde(default)]
    edit: Option<i64>,
    #[serde(default)]
    msg: String,
}

pub async fn settings_page(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<SettingsQuery>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let (providers, editing) = {
        let db = st.db.lock().expect("db");
        let list = db.list_providers().unwrap_or_default();
        let editing = q.edit.and_then(|id| db.get_provider(id).ok().flatten());
        (list, editing)
    };
    let body = html! {
        h1 { "Cài đặt AI" }
        p class="sub" { "AI là “bộ não” chẩn đoán sự cố từ bằng chứng agent thu thập. Bạn tự nhập endpoint, model và API key." }
        @if !q.msg.is_empty() { div class="note" { (q.msg) } }

        div class="card" {
            h2 { "Nhà cung cấp AI" }
            div class="wrap" {
                table {
                    thead { tr { th { "Tên" } th { "Loại" } th { "Endpoint" } th { "Model" } th { "API key" } th {} } }
                    tbody {
                        @if providers.is_empty() {
                            tr { td colspan="6" { div class="empty" { "Chưa có nhà cung cấp nào. Thêm ở form bên dưới." } } }
                        }
                        @for p in &providers {
                            tr {
                                td { b { (p.name) } @if p.is_default { " " span class="badge b-ok" { "đang dùng" } } }
                                td { (if p.kind == KIND_ANTHROPIC { "Anthropic" } else { "OpenAI-compatible" }) }
                                td {
                                    code style="word-break:break-all" { (if p.endpoint.is_empty() { "(mặc định)" } else { p.endpoint.as_str() }) }
                                    br;
                                    span class="mut" style="font-size:12px" {
                                        "Sẽ gọi: "
                                        @match ai_client::request_url(&p.kind, &p.endpoint) {
                                            Ok(u) => { code style="word-break:break-all" { (u) } }
                                            Err(e) => { span style="color:var(--bad)" { (e.to_string()) } }
                                        }
                                    }
                                }
                                td { code { (p.model) } }
                                td class="mut" { (ai_client::mask_key(&p.api_key)) }
                                td {
                                    div style="display:flex;gap:6px;flex-wrap:wrap" {
                                        form method="post" action={"/settings/provider/" (p.id) "/test"} style="margin:0" { button class="ghost" type="submit" { "Thử kết nối" } }
                                        @if !p.is_default {
                                            form method="post" action={"/settings/provider/" (p.id) "/default"} style="margin:0" { button class="ghost" type="submit" { "Đặt làm mặc định" } }
                                        }
                                        a href={"/settings?edit=" (p.id) "#form"} style="align-self:center" { "Sửa" }
                                        form method="post" action={"/settings/provider/" (p.id) "/delete"} style="margin:0"
                                             onsubmit="return confirm('Xoá nhà cung cấp này?')" { button class="bad" type="submit" { "Xoá" } }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        div class="card" id="form" {
            h2 { (if editing.is_some() { "Sửa nhà cung cấp" } else { "Thêm nhà cung cấp" }) }
            form method="post" action="/settings/provider" {
                @if let Some(e) = &editing { input type="hidden" name="id" value=(e.id); }
                div class="ctrls" {
                    label class="f" { span class="t" { "Tên gợi nhớ" }
                        input type="text" name="name" value=(editing.as_ref().map_or("", |e| e.name.as_str())) placeholder="vd: Hermes" required maxlength="60"; }
                    label class="f" { span class="t" { "Loại API" }
                        select name="kind" {
                            option value=(KIND_OPENAI) selected[editing.as_ref().is_none_or(|e| e.kind == KIND_OPENAI)] { "OpenAI-compatible (Hermes, OpenRouter, vLLM, Ollama, LiteLLM…)" }
                            option value=(KIND_ANTHROPIC) selected[editing.as_ref().is_some_and(|e| e.kind == KIND_ANTHROPIC)] { "Anthropic (Claude)" }
                        } }
                }
                div class="ctrls" {
                    label class="f" style="flex:1;min-width:260px" { span class="t" { "Endpoint" }
                        input type="text" name="endpoint" value=(editing.as_ref().map_or("", |e| e.endpoint.as_str())) placeholder="vd: https://api.example.com/v1" style="width:100%"; }
                    label class="f" { span class="t" { "Model" }
                        input type="text" name="model" value=(editing.as_ref().map_or("", |e| e.model.as_str())) placeholder="vd: hermes-4-405b" required maxlength="120"; }
                }
                div class="ctrls" {
                    label class="f" style="flex:1;min-width:260px" { span class="t" { "API key" (if editing.is_some() { " (để trống = giữ key cũ)" } else { "" }) }
                        input type="password" name="api_key" autocomplete="off" placeholder="sk-…" style="width:100%"; }
                }
                p { button type="submit" { "Lưu" } " " @if editing.is_some() { a href="/settings" { "Huỷ" } } }
            }
            p class="help" {
                "OpenAI-compatible: nhập địa chỉ gốc (ví dụ " code { "https://openrouter.ai/api/v1" } ") hoặc đầy đủ tới " code { "/chat/completions" } ". "
                "Hermes chạy trên máy bạn (Ollama, vLLM) cũng dùng loại này, ví dụ " code { "http://127.0.0.1:11434/v1" } " (key có thể để trống). "
                "Anthropic: để trống endpoint để dùng api.anthropic.com."
            }
        }

        div class="card" {
            h2 { "Dữ liệu gửi đi và bảo mật" }
            ul {
                li { "Khi phân tích, hub gửi cho nhà cung cấp bạn chọn phần " b { "bằng chứng" } " của VPS: tên tiến trình và dòng lệnh, đường dẫn file lạ, các dòng đáng ngờ trong file khởi động shell (không gửi toàn bộ file), IP đăng nhập SSH, cổng đang mở. Không gửi nội dung website hay database. Lưu ý: dòng lệnh và các dòng khởi động/cron có thể chứa mật khẩu hoặc token gõ trên dòng lệnh; agent che các dạng phổ biến (" code { "password=…" } ", " code { "--token" } ", " code { "-pMẬT_KHẨU" } ", " code { "user:pass@host" } ", " code { "Bearer …" } ") nhưng không đảm bảo che hết, và bằng chứng cũng được lưu trong database của hub. Nếu không chấp nhận điều đó, hãy dùng model chạy trên máy bạn." }
                li { "Nếu không muốn gửi ra ngoài, dùng model chạy trên máy bạn (Ollama/vLLM) hoặc tắt thu thập bằng chứng trên VPS (" code { "[remote] allow_evidence = false" } ")." }
                li { "API key được lưu nguyên văn trong file SQLite của hub (chỉ user chạy hub đọc được) vì hub cần dùng nó; trang này chỉ hiện 4 ký tự cuối." }
                li { "AI không chạy lệnh. Nó chỉ chọn trong danh sách hành động cố định (dừng tiến trình, khoá shell, cách ly file, gỡ dòng khỏi file khởi động shell, tắt vài dịch vụ), và chỉ nhắm vào thứ có trong bằng chứng. Hub và agent kiểm tra lại, mọi hành động (trừ dừng tiến trình) hoàn tác được." }
                li { "Nội dung trong bằng chứng do máy có thể đã bị xâm nhập viết ra, kẻ tấn công có thể chèn câu chữ nhằm lừa AI. Vì vậy mức " b { "Tự xử lý" } " chỉ nên bật sau khi bạn đã xem AI đề xuất đúng vài lần ở chế độ duyệt." }
            }
        }
    };
    Html(shell("Cài đặt AI", body).into_string()).into_response()
}

fn settings_back(msg: &str) -> Response {
    Redirect::to(&format!("/settings?msg={}", urlenc(msg))).into_response()
}

#[derive(Deserialize)]
pub struct ProviderForm {
    #[serde(default)]
    id: String,
    name: String,
    kind: String,
    #[serde(default)]
    endpoint: String,
    model: String,
    #[serde(default)]
    api_key: String,
}

pub async fn provider_save_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<ProviderForm>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let (name, endpoint, model) = (f.name.trim(), f.endpoint.trim(), f.model.trim());
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
        return settings_back("Tên không hợp lệ.");
    }
    if !ai_client::is_valid_kind(&f.kind) {
        return settings_back("Loại API không hợp lệ.");
    }
    if let Err(e) = ai_client::request_url(&f.kind, endpoint) {
        return settings_back(&format!("Endpoint không hợp lệ: {e}"));
    }
    if model.is_empty() || model.chars().count() > 120 || model.chars().any(char::is_whitespace) {
        return settings_back("Model không hợp lệ (không để trống hoặc có khoảng trắng).");
    }
    if f.api_key.len() > 512 || f.api_key.chars().any(char::is_control) {
        return settings_back("API key không hợp lệ.");
    }
    let id = f.id.trim().parse::<i64>().ok();
    let saved = st.db.lock().expect("db").save_provider(
        id,
        &ProviderInput {
            name,
            kind: &f.kind,
            endpoint,
            model,
            api_key: f.api_key.trim(),
        },
        now(),
    );
    match saved {
        Ok(_) => settings_back("Đã lưu nhà cung cấp AI."),
        Err(e) => settings_back(&format!("Không lưu được: {e:#}")),
    }
}

pub async fn provider_default_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(pid): Path<i64>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let _ = st.db.lock().expect("db").set_default_provider(pid);
    settings_back("Đã đặt làm mặc định.")
}

pub async fn provider_delete_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(pid): Path<i64>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let _ = st.db.lock().expect("db").delete_provider(pid);
    settings_back("Đã xoá.")
}

pub async fn provider_test_post(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(pid): Path<i64>,
) -> Response {
    if let Some(r) = guard(&st, &headers) {
        return r;
    }
    let provider = st
        .db
        .lock()
        .expect("db")
        .get_provider(pid)
        .ok()
        .flatten()
        .map(|p| p.to_provider());
    let Some(provider) = provider else {
        return settings_back("Không tìm thấy nhà cung cấp.");
    };
    let name = provider.name.clone();
    // The call blocks for up to a few seconds: off the async threads.
    let result = tokio::task::spawn_blocking(move || {
        ai_client::complete(
            &provider,
            "You are a connection test. Reply with the single word OK.",
            "Reply with OK.",
        )
    })
    .await;
    let msg = match result {
        Ok(Ok(text)) => format!(
            "“{name}” kết nối được. Phản hồi: {}",
            text.chars().take(80).collect::<String>().replace('\n', " ")
        ),
        Ok(Err(e)) => format!("“{name}” lỗi: {e:#}"),
        Err(_) => format!("“{name}”: phép thử bị ngắt."),
    };
    settings_back(&msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snsec_common::ai::Plan;
    use snsec_common::schema::{EvProc, HostInfo};

    fn data(proposal: Option<ProposalRow>, ev: Option<Evidence>) -> AiCardData {
        AiCardData {
            state: AiState::default(),
            proposal,
            evidence: ev,
            has_provider: true,
            provider_name: "Hermes".into(),
        }
    }

    fn report(caps: &[&str]) -> ReportBody {
        ReportBody {
            agent_version: "t".into(),
            host: HostInfo::default(),
            cycle: snsec_common::schema::CycleStats::default(),
            bans: vec![],
            would_ban: vec![],
            alerts: vec![],
            triage: None,
            findings: vec![],
            applied_desired: Default::default(),
            capabilities: caps.iter().map(|c| (*c).to_string()).collect(),
            active_bans: vec![],
            active_bans_total: 0,
            hunt: None,
            clamav: None,
            evidence: None,
            remediation: None,
        }
    }

    fn proposal(status: &str, diagnosis: &str, reason: &str) -> ProposalRow {
        ProposalRow {
            id: 7,
            agent_id: "a1".into(),
            created: 1,
            provider: "Hermes".into(),
            status: status.into(),
            diagnosis: diagnosis.into(),
            plan: Plan {
                diagnosis: diagnosis.into(),
                proposed: vec![Proposed {
                    action: Action::KillProcess {
                        pid: 99,
                        starttime: 5,
                    },
                    reason: reason.into(),
                    risk: "high".into(),
                }],
                rejected: vec!["bỏ qua: x".into()],
            },
            note: String::new(),
            job_id: String::new(),
            applied: vec![],
            result: None,
            auto: false,
        }
    }

    #[test]
    fn model_and_machine_text_is_escaped() {
        let ev = Evidence {
            processes: vec![EvProc {
                pid: 99,
                starttime: 5,
                comm: "<img src=x onerror=alert(1)>".into(),
                ..EvProc::default()
            }],
            ..Evidence::default()
        };
        let html = ai_card(
            "a1",
            Some(&report(&["evidence", "remediate"])),
            &data(
                Some(proposal(
                    "proposed",
                    "<script>alert(2)</script>",
                    "<b>x</b>",
                )),
                Some(ev),
            ),
            "",
        )
        .into_string();
        assert!(!html.contains("<script>alert(2)"), "{html}");
        assert!(!html.contains("<img src=x"), "{html}");
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn buttons_appear_only_when_the_vps_can_and_the_proposal_is_open() {
        let open = proposal("proposed", "d", "r");
        let h = ai_card(
            "a1",
            Some(&report(&["evidence", "remediate"])),
            &data(Some(open.clone()), None),
            "",
        )
        .into_string();
        assert!(h.contains("/agent/a1/ai/7/apply"), "{h}");
        assert!(h.contains("Thực hiện tất cả"));
        // The VPS has not allowed remediation: no apply buttons, and the way to enable it is shown.
        let h = ai_card(
            "a1",
            Some(&report(&["evidence"])),
            &data(Some(open.clone()), None),
            "",
        )
        .into_string();
        assert!(!h.contains("/agent/a1/ai/7/apply"));
        assert!(h.contains("--allow-remote-fix"));
        // A finished proposal has none either.
        let h = ai_card(
            "a1",
            Some(&report(&["evidence", "remediate"])),
            &data(Some(proposal("done", "d", "r")), None),
            "",
        )
        .into_string();
        assert!(!h.contains("/agent/a1/ai/7/apply"));
    }

    #[test]
    fn without_a_provider_or_an_up_to_date_agent_the_card_says_what_to_do() {
        let mut d = data(None, None);
        d.has_provider = false;
        let h = ai_card("a1", Some(&report(&["evidence"])), &d, "").into_string();
        assert!(h.contains("/settings"));
        let h = ai_card("a1", Some(&report(&[])), &data(None, None), "").into_string();
        assert!(h.contains("Agent trên VPS này cũ"));
    }

    #[test]
    fn the_autonomy_choices_all_have_wording() {
        for a in [
            ai::AUTONOMY_OFF,
            ai::AUTONOMY_APPROVE,
            ai::AUTONOMY_AUTO_SAFE,
            ai::AUTONOMY_AUTO_ALL,
        ] {
            assert_ne!(autonomy_vi(a), "?", "{a}");
        }
    }
}
