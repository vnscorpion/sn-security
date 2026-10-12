//! The hub's side of AI-assisted incident response: when to ask for evidence, how
//! to run the analysis, and how an approved (or autonomy-allowed) plan becomes a
//! job for the agent.
//!
//! The model never acts. It only fills in a [`Plan`] that [`snsec_common::ai`]
//! checks against the agent's own evidence; carrying a plan out is a signed job to
//! the agent, which checks again.

use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use anyhow::{Result, bail};
use snsec_common::ai::{self, Plan};
use snsec_common::schema::{Action, Job, ReportBody};

use crate::AppState;
use crate::db::Db;
use crate::db_ai::{AiState, NewProposal, PENDING_TIMEOUT_SECS, ProposalRow};

/// At most one automatic analysis per VPS in this long: an incident that stays
/// on must not turn into a stream of model calls (and their cost).
pub const AUTO_COOLDOWN_SECS: i64 = 30 * 60;
/// Evidence younger than this is reused by a manual "analyse" click.
pub const FRESH_EVIDENCE_SECS: i64 = 10 * 60;
/// The agent refuses evidence older than 2 hours; the hub stops a little earlier.
pub const MAX_ORDER_EVIDENCE_AGE_SECS: i64 = 100 * 60;

/// Model calls in flight at once, across every VPS (analyses and connection
/// tests). One more is refused, not queued: each can hold a blocking thread for
/// minutes, and each costs money.
pub const MAX_MODEL_CALLS: usize = 3;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Which VPSes have an analysis running, and the permits for model calls.
pub struct Slots {
    running: Mutex<Vec<String>>,
    calls: Arc<tokio::sync::Semaphore>,
}

static SLOTS: LazyLock<Slots> = LazyLock::new(|| Slots::new(MAX_MODEL_CALLS));

/// Why an analysis did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// One is already running for this VPS.
    Running,
    /// Every model-call permit is taken.
    Busy,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Running => f.write_str(
                "AI đang phân tích sự cố của VPS này; kết quả hiện ở đây khi xong, không cần bấm lại.",
            ),
            Refused::Busy => write!(
                f,
                "AI đang bận ({MAX_MODEL_CALLS} yêu cầu cùng lúc); thử lại sau ít phút."
            ),
        }
    }
}

/// An analysis claimed for one VPS, with its model-call permit. Dropping it
/// (when the run ends, however it ends) frees both.
pub struct Claim {
    slots: &'static Slots,
    agent_id: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Slots {
    fn new(calls: usize) -> Slots {
        Slots {
            running: Mutex::new(Vec::new()),
            calls: Arc::new(tokio::sync::Semaphore::new(calls)),
        }
    }

    /// Claim the one analysis this VPS may have running, and a model call.
    fn claim(&'static self, agent_id: &str) -> Result<Claim, Refused> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if running.iter().any(|a| a == agent_id) {
            return Err(Refused::Running);
        }
        let permit = Arc::clone(&self.calls)
            .try_acquire_owned()
            .map_err(|_| Refused::Busy)?;
        running.push(agent_id.to_string());
        Ok(Claim {
            slots: self,
            agent_id: agent_id.to_string(),
            _permit: permit,
        })
    }

    fn is_running(&self, agent_id: &str) -> bool {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|a| a == agent_id)
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.slots
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|a| a != &self.agent_id);
    }
}

/// Is an analysis running for this VPS right now?
#[must_use]
pub fn running(agent_id: &str) -> bool {
    SLOTS.is_running(agent_id)
}

/// A permit for one model call outside an analysis (a connection test), if one
/// is free.
#[must_use]
pub fn model_call_permit() -> Option<tokio::sync::OwnedSemaphorePermit> {
    Arc::clone(&SLOTS.calls).try_acquire_owned().ok()
}

/// Start an analysis for `agent_id` on a blocking thread. Call it with the
/// database lock held (`db`), so deciding and claiming are one step: a second
/// report or click cannot start another one for the same VPS, and the
/// cool-down starts now.
///
/// # Errors
/// When one is already running for this VPS, or every model call is taken.
pub fn start(st: &Arc<AppState>, db: &Db, agent_id: &str, at: i64) -> Result<(), Refused> {
    let claim = SLOTS.claim(agent_id)?;
    let _ = db.touch_analysis(agent_id, at);
    let st2 = Arc::clone(st);
    let id = agent_id.to_string();
    tokio::task::spawn_blocking(move || {
        let _claim = claim;
        run(&st2, &id);
    });
    Ok(())
}

/// The evidence an analysis was waiting for arrived while every model call was
/// taken: it is not queued. Say so on the VPS page and stop waiting.
pub fn note_busy(db: &Db, agent_id: &str, at: i64) {
    let _ = db.create_proposal(
        at,
        &NewProposal {
            agent_id,
            provider: "",
            status: "error",
            plan: &Plan::default(),
            note: &format!(
                "{} Bằng chứng đã nhận; bấm “Phân tích bằng AI” để phân tích.",
                Refused::Busy
            ),
            auto: false,
        },
    );
    let _ = db.set_pending(agent_id, false, at);
}

/// Does the agent understand (and has its VPS allowed) this kind of job? The
/// agent lists `evidence` / `remediate` in its capabilities only when both the
/// code and its `[remote]` setting permit it.
#[must_use]
pub fn can(r: &ReportBody, capability: &str) -> bool {
    r.capabilities.iter().any(|c| c == capability)
}

/// Does this report describe something worth an automatic analysis?
#[must_use]
pub fn looks_like_incident(r: &ReportBody) -> bool {
    r.alerts
        .iter()
        .any(|a| matches!(a.kind.as_str(), "cpu_high" | "malware_found" | "ban_cap"))
        || r.triage
            .as_ref()
            .is_some_and(|t| matches!(t.label.as_str(), "miner" | "php-bot" | "mixed"))
}

fn pending_now(s: &AiState, at: i64) -> bool {
    s.pending && at - s.pending_since < PENDING_TIMEOUT_SECS
}

/// Should an analysis start by itself now?
#[must_use]
pub fn should_auto_trigger(s: &AiState, at: i64, r: &ReportBody, has_provider: bool) -> bool {
    s.autonomy != ai::AUTONOMY_OFF
        && has_provider
        && can(r, "evidence")
        && !pending_now(s, at)
        && at - s.last_analysis >= AUTO_COOLDOWN_SECS
        && looks_like_incident(r)
}

/// Order `indices` of a proposal's actions as one job to the agent. Returns the
/// job id.
///
/// # Errors
/// When the agent cannot or may not do it, the evidence is too old, or there is
/// nothing new to order.
pub fn order(
    db: &Db,
    agent_id: &str,
    proposal: &ProposalRow,
    indices: &[usize],
    who: &str,
    at: i64,
) -> Result<String> {
    let Some(report) = db.latest_report(agent_id)? else {
        bail!("VPS chưa gửi báo cáo nào");
    };
    if !can(&report, "remediate") {
        bail!(
            "Agent trên VPS này cũ hoặc đang tắt lệnh từ hub ([remote] hub_orders = false): cập nhật agent rồi thử lại"
        );
    }
    match db.latest_evidence(agent_id)? {
        Some(ev) if at - ev.at <= MAX_ORDER_EVIDENCE_AGE_SECS => {}
        _ => bail!(
            "bằng chứng đã cũ (hoặc chưa có): hãy bấm “Phân tích bằng AI” lại để lấy bằng chứng mới"
        ),
    }
    let mut applied = proposal.applied.clone();
    let mut actions: Vec<Action> = Vec::new();
    for &i in indices {
        let Some(p) = proposal.plan.proposed.get(i) else {
            continue;
        };
        if applied.contains(&i) {
            continue;
        }
        actions.push(p.action.clone());
        applied.push(i);
    }
    if actions.is_empty() {
        bail!("không có hành động mới nào để thực hiện");
    }
    applied.sort_unstable();
    let job_id = format!("p{}-{at}", proposal.id);
    let detail = format!(
        "{who}: {} hành động từ đề xuất #{}",
        actions.len(),
        proposal.id
    );
    db.queue_job(
        agent_id,
        at,
        who,
        Job::Remediate {
            id: job_id.clone(),
            actions,
        },
        &detail,
    )?;
    db.mark_proposal_ordered(proposal.id, &job_id, &applied)?;
    Ok(job_id)
}

/// Run one analysis for `agent_id` now, from the evidence the hub holds. Blocking
/// (it calls the model): run it on a blocking thread. Never panics; any failure
/// becomes a proposal with status `error` so the operator sees why.
pub fn run(st: &Arc<AppState>, agent_id: &str) {
    let at = now();
    // Gather everything under the lock, then release it for the model call.
    let gathered = {
        let db = st.db.lock().expect("db");
        let provider = db.default_provider().ok().flatten();
        let ev = db.latest_evidence(agent_id).ok().flatten();
        let report = db.latest_report(agent_id).ok().flatten();
        let host = db
            .agent(agent_id)
            .ok()
            .flatten()
            .map(|a| a.name)
            .unwrap_or_default();
        (provider, ev, report, host)
    };
    let (provider, ev, report, host) = gathered;

    let fail = |provider_name: &str, note: String| {
        let db = st.db.lock().expect("db");
        let _ = db.create_proposal(
            at,
            &NewProposal {
                agent_id,
                provider: provider_name,
                status: "error",
                plan: &Plan::default(),
                note: &note,
                auto: false,
            },
        );
        let _ = db.touch_analysis(agent_id, at);
        let _ = db.set_pending(agent_id, false, at);
    };
    let Some(provider) = provider else {
        return fail(
            "",
            "Chưa cấu hình AI: vào Cài đặt AI để thêm endpoint, model và API key.".into(),
        );
    };
    let Some(ev) = ev else {
        return fail(&provider.name, "Chưa có bằng chứng từ VPS này.".into());
    };
    let alerts: Vec<String> = report
        .as_ref()
        .map(|r| {
            r.alerts
                .iter()
                .map(|a| {
                    format!(
                        "{}: {}",
                        a.kind,
                        a.message.chars().take(160).collect::<String>()
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let reply = crate::ai_client::complete(
        &provider.to_provider(),
        ai::system_prompt(),
        &ai::user_prompt(&host, &alerts, &ev),
    );
    let text = match reply {
        Ok(t) => t,
        Err(e) => return fail(&provider.name, format!("Gọi AI thất bại: {e:#}")),
    };
    let plan = match ai::parse_plan(&text, &ev) {
        Ok(p) => p,
        Err(e) => {
            let head: String = text.chars().take(200).collect();
            return fail(
                &provider.name,
                format!("Không đọc được câu trả lời của AI ({e}): {head}"),
            );
        }
    };

    let db = st.db.lock().expect("db");
    // The model call can take minutes: use the autonomy level in force NOW, so an
    // operator who switched it off meanwhile is obeyed (fail closed on a read error).
    let autonomy = db
        .ai_state(agent_id)
        .map(|s| s.autonomy)
        .unwrap_or_else(|_| ai::AUTONOMY_OFF.to_string());
    let auto = autonomy == ai::AUTONOMY_AUTO_SAFE || autonomy == ai::AUTONOMY_AUTO_ALL;
    let id = match db.create_proposal(
        at,
        &NewProposal {
            agent_id,
            provider: &provider.name,
            status: "proposed",
            plan: &plan,
            note: "",
            auto,
        },
    ) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("create_proposal: {e:#}");
            return;
        }
    };
    let _ = db.touch_analysis(agent_id, at);
    let _ = db.set_pending(agent_id, false, at);

    // Unattended: order what the VPS's autonomy level allows. The rest waits for a click.
    if auto && let Ok(Some(proposal)) = db.get_proposal(id) {
        auto_order(&db, agent_id, &proposal, &autonomy, at);
    }
}

/// Marks a proposal whose unattended order could not be sent yet; the next report
/// from the VPS retries it (see [`retry_waiting`]).
const WAITING_NOTE: &str =
    "Chưa gửi được lệnh tự động (VPS còn lệnh khác chưa chạy), sẽ tự thử lại";

/// Order what the VPS's autonomy level allows without a click. If the VPS still has
/// an unrun job (one slot per VPS), the proposal is left waiting and retried when
/// the VPS next reports, instead of being dropped.
fn auto_order(db: &Db, agent_id: &str, proposal: &ProposalRow, autonomy: &str, at: i64) {
    let indices: Vec<usize> = proposal
        .plan
        .proposed
        .iter()
        .enumerate()
        .filter(|(i, p)| !proposal.applied.contains(i) && ai::auto_allows(autonomy, &p.risk))
        .map(|(i, _)| i)
        .collect();
    if indices.is_empty() {
        return;
    }
    match order(db, agent_id, proposal, &indices, "ai-auto", at) {
        Ok(job) => tracing::info!(
            "ai-auto: {agent_id} ordered {} action(s), job {job}",
            indices.len()
        ),
        Err(e) => {
            tracing::warn!("ai-auto: {agent_id}: {e:#}");
            let _ =
                db.set_proposal_status(proposal.id, "proposed", &format!("{WAITING_NOTE} ({e:#})"));
        }
    }
}

/// A proposal that was waiting for the job slot gets another try. Called with each
/// report from the VPS, which is when the slot frees up.
pub fn retry_waiting(db: &Db, agent_id: &str, at: i64) {
    let Ok(Some(p)) = db.latest_proposal(agent_id) else {
        return;
    };
    // Only a proposal that was waiting, for a couple of hours: evidence ages out.
    if p.status != "proposed" || !p.note.starts_with(WAITING_NOTE) || at - p.created > 2 * 3600 {
        return;
    }
    let Ok(state) = db.ai_state(agent_id) else {
        return;
    };
    if state.autonomy == ai::AUTONOMY_AUTO_SAFE || state.autonomy == ai::AUTONOMY_AUTO_ALL {
        auto_order(db, agent_id, &p, &state.autonomy, at);
    }
}

/// An operator's "analyse with AI" click: use the evidence the hub already has
/// if it is fresh, otherwise ask the agent for new evidence and analyse when it
/// arrives. Returns a short message for the page.
///
/// # Errors
/// When no AI is configured or the agent cannot collect evidence.
pub fn request(st: &Arc<AppState>, agent_id: &str) -> Result<String> {
    let at = now();
    let db = st.db.lock().expect("db");
    if db.default_provider()?.is_none() {
        bail!("Chưa cấu hình AI: vào Cài đặt AI để thêm endpoint, model và API key.");
    }
    if running(agent_id) {
        bail!("{}", Refused::Running);
    }
    let Some(report) = db.latest_report(agent_id)? else {
        bail!("VPS chưa gửi báo cáo nào");
    };
    if !can(&report, "evidence") {
        bail!(
            "Agent trên VPS này cũ hoặc đang tắt lệnh từ hub ([remote] hub_orders = false): cập nhật agent rồi thử lại"
        );
    }
    if let Some(ev) = db.latest_evidence(agent_id)?
        && at - ev.at <= FRESH_EVIDENCE_SECS
    {
        if let Err(e) = start(st, &db, agent_id, at) {
            bail!("{e}");
        }
        // Still under the lock: the run cannot clear it before it is set.
        db.set_pending(agent_id, true, at)?;
        return Ok("Đang phân tích bằng AI (dùng bằng chứng mới thu thập)…".into());
    }
    db.queue_job(
        agent_id,
        at,
        "admin",
        Job::Evidence,
        "thu thập bằng chứng cho AI",
    )?;
    db.set_pending(agent_id, true, at)?;
    Ok("Đã gửi lệnh thu thập bằng chứng. VPS sẽ gửi trong vòng ~5–15 phút, sau đó AI tự phân tích.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use snsec_common::schema::{Alert, HostInfo, TriageSummary};

    fn report(caps: &[&str], alerts: &[&str], label: Option<&str>) -> ReportBody {
        ReportBody {
            agent_version: "t".into(),
            host: HostInfo::default(),
            cycle: snsec_common::schema::CycleStats::default(),
            bans: vec![],
            would_ban: vec![],
            alerts: alerts
                .iter()
                .map(|k| Alert {
                    kind: (*k).into(),
                    message: "m".into(),
                    severity: "warn".into(),
                })
                .collect(),
            triage: label.map(|l| TriageSummary {
                label: l.into(),
                top_processes: vec![],
                persistence: vec![],
                load1: 0.0,
                disk_pct: 0,
                inode_pct: 0,
                mem_used_pct: 0.0,
            }),
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

    fn state(autonomy: &str, pending: bool, pending_since: i64, last: i64) -> AiState {
        AiState {
            autonomy: autonomy.into(),
            pending,
            pending_since,
            last_analysis: last,
        }
    }

    #[test]
    fn what_counts_as_an_incident() {
        assert!(looks_like_incident(&report(&[], &["cpu_high"], None)));
        assert!(looks_like_incident(&report(&[], &["malware_found"], None)));
        assert!(looks_like_incident(&report(&[], &[], Some("miner"))));
        assert!(!looks_like_incident(&report(
            &[],
            &["mem_high"],
            Some("unknown")
        )));
        assert!(!looks_like_incident(&report(&[], &[], None)));
    }

    #[test]
    fn an_incident_starts_an_analysis_only_when_everything_allows_it() {
        let r = report(&["evidence"], &["cpu_high"], None);
        let t = 1_000_000;
        let idle = state("approve", false, 0, 0);
        assert!(should_auto_trigger(&idle, t, &r, true));
        // Off, no provider, old agent, calm server, cooldown, already pending.
        assert!(!should_auto_trigger(
            &state("off", false, 0, 0),
            t,
            &r,
            true
        ));
        assert!(!should_auto_trigger(&idle, t, &r, false));
        assert!(!should_auto_trigger(
            &idle,
            t,
            &report(&[], &["cpu_high"], None),
            true
        ));
        assert!(!should_auto_trigger(
            &idle,
            t,
            &report(&["evidence"], &[], None),
            true
        ));
        assert!(!should_auto_trigger(
            &state("approve", false, 0, t - 60),
            t,
            &r,
            true
        ));
        assert!(should_auto_trigger(
            &state("approve", false, 0, t - AUTO_COOLDOWN_SECS),
            t,
            &r,
            true
        ));
        assert!(!should_auto_trigger(
            &state("approve", true, t - 60, 0),
            t,
            &r,
            true
        ));
        // A request the agent never answered stops blocking after a while.
        assert!(should_auto_trigger(
            &state("approve", true, t - PENDING_TIMEOUT_SECS - 1, 0),
            t,
            &r,
            true
        ));
    }

    #[test]
    fn the_capability_check_reads_the_agents_own_list() {
        let r = report(&["evidence", "clamav"], &[], None);
        assert!(can(&r, "evidence") && !can(&r, "remediate"));
    }

    #[test]
    fn one_analysis_per_vps_and_only_a_few_model_calls_at_once() {
        let slots: &'static Slots = Box::leak(Box::new(Slots::new(2)));
        let a = slots.claim("vps-a").unwrap();
        assert_eq!(slots.claim("vps-a").err(), Some(Refused::Running));
        let b = slots.claim("vps-b").unwrap();
        // Every call is taken: refused at once, not queued, and nothing is left
        // marked as running.
        assert_eq!(slots.claim("vps-c").err(), Some(Refused::Busy));
        assert!(!slots.is_running("vps-c"));
        assert!(slots.is_running("vps-a"));
        // A run that ends (or panics: the claim is dropped either way) frees both.
        drop(a);
        assert!(!slots.is_running("vps-a"));
        let c = slots.claim("vps-c").unwrap();
        let a2 = slots.claim("vps-a");
        assert_eq!(a2.err(), Some(Refused::Busy));
        drop((b, c));
        assert!(slots.claim("vps-a").is_ok());
    }

    #[test]
    fn a_busy_hub_says_so_on_the_vps_page_and_stops_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        db.set_pending("a1", true, 100).unwrap();
        note_busy(&db, "a1", 120);
        assert!(!db.ai_state("a1").unwrap().pending);
        let p = db.latest_proposal("a1").unwrap().unwrap();
        assert_eq!(p.status, "error");
        assert!(p.note.contains("AI đang bận"), "{}", p.note);
    }
}
