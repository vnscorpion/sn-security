//! Agent-facing API: signed report ingest and signed desired-state delivery.
//! No admin auth here — authentication is the ed25519 signatures themselves.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use snsec_common::crypto;
use snsec_common::schema::{Envelope, ReportBody, Signed};

use crate::AppState;
use crate::analysis;
use crate::desired::sign_desired;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// POST /v1/report — body is a [`Signed`] wrapping an [`Envelope<ReportBody>`].
pub async fn post_report(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> impl IntoResponse {
    let signed: Signed = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
    };

    // The lock is held only to read the key, and again below for the writes:
    // checking the signature over a large body and parsing it happen without it.
    let (pubkey, last) = {
        let db = st.db.lock().expect("db mutex");
        let pubkey = match db.agent_pubkey(&signed.key_id) {
            Ok(Some(pk)) => pk,
            // The same answer as a bad signature: no oracle for which ids exist.
            _ => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
        };
        (pubkey, db.last_report_seq(&signed.key_id).unwrap_or(0))
    };
    let vk = match crypto::parse_pubkey(&pubkey) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "bad stored key").into_response(),
    };

    let env: Envelope<ReportBody> = match crypto::open(&[vk], &signed, now()) {
        Ok(e) => e,
        Err(_) => return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    };
    if env.agent_id != signed.key_id {
        return (StatusCode::BAD_REQUEST, "agent_id mismatch").into_response();
    }

    // Replay / monotonicity: ignore an already-seen or older seq idempotently.
    if env.seq <= last {
        return (StatusCode::OK, "duplicate").into_response();
    }
    let body_json = serde_json::to_string(&env.body).unwrap_or_default();

    let db = st.db.lock().expect("db mutex");
    // Again under the lock: a concurrent report may have moved it on.
    if env.seq <= db.last_report_seq(&env.agent_id).unwrap_or(0) {
        return (StatusCode::OK, "duplicate").into_response();
    }
    // Not stored, so the agent keeps it queued and sends it again later.
    if !db.take_report_token(&env.agent_id, now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "too many reports").into_response();
    }
    if let Err(e) = db.record_report(&env.agent_id, env.seq, now(), &env.body, &body_json) {
        tracing::error!("record_report: {e:#}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response();
    }
    // Where this signed, new report came from: the VPS's own public address,
    // which on a cloud that NATs it is on none of its interfaces. Sent back in
    // the desired state so the agent never bans it (best effort).
    if let Err(e) = db.note_self_ip(&env.agent_id, &crate::auth::client_ip(&headers), now()) {
        tracing::warn!("note_self_ip: {e:#}");
    }

    // AI-assisted incident response (best effort: never fails the report).
    let at = now();
    let agent_id = env.agent_id.clone();
    let mut analyse_now = false;
    let ai = db.ai_state(&agent_id).unwrap_or_default();
    if let Some(ev) = &env.body.evidence {
        let _ = db.save_evidence(&agent_id, ev);
        // The evidence an analysis was waiting for (not one collected before it asked).
        analyse_now = ai.pending && ev.at + 5 >= ai.pending_since;
    }
    if let Some(rem) = &env.body.remediation {
        let _ = db.attach_remediation(&agent_id, rem);
    }
    // This report shows what the VPS has run, so a job slot may have freed up: let a
    // proposal that was waiting for it be ordered now.
    analysis::retry_waiting(&db, &agent_id, at);
    if !analyse_now {
        let has_provider = db.default_provider().ok().flatten().is_some();
        // A proposal still waiting for an answer (or for the VPS) means the last
        // analysis has not been dealt with: asking the model again about the same
        // incident would only repeat itself and cost money.
        let open_proposal = db
            .latest_ai_proposal(&agent_id)
            .ok()
            .flatten()
            .is_some_and(|p| {
                matches!(p.status.as_str(), "proposed" | "executing") && at - p.created < 24 * 3600
            });
        if !open_proposal && analysis::should_auto_trigger(&ai, at, &env.body, has_provider) {
            // An incident on a VPS where the operator allowed it: collect evidence;
            // the analysis starts when it arrives.
            let queued = db.queue_job(
                &agent_id,
                at,
                "ai-auto",
                snsec_common::schema::Job::Evidence,
                "thu thập bằng chứng (tự động, có sự cố)",
            );
            if queued.is_ok() {
                let _ = db.set_pending(&agent_id, true, at);
            }
        }
    }
    // Claimed while the lock is still held, so two reports cannot both start one.
    if analyse_now && let Err(e) = analysis::start(&st, &db, &agent_id, at) {
        tracing::info!("analysis for {agent_id} not started: {e}");
        if e == analysis::Refused::Busy {
            analysis::note_busy(&db, &agent_id, at);
        }
    }
    drop(db);
    (StatusCode::OK, "ok").into_response()
}

#[derive(Deserialize)]
pub struct DesiredQuery {
    agent_id: String,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    seq: u64,
}

/// GET /v1/desired?agent_id=..&epoch=..&seq=.. — returns a signed desired body,
/// or 304 if the agent already has the current version.
///
/// The agent signs the pull with its own key (see [`check_pull`]). An unknown
/// agent, a missing, bad or replayed signature all get the same bare 404 after
/// the same work, so this endpoint does not tell a stranger which agent ids
/// exist.
pub async fn get_desired(
    State(st): State<Arc<AppState>>,
    Query(q): Query<DesiredQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let at = now();
    let agent = pull_agent(&st.db.lock().expect("db mutex"), &q.agent_id);
    // The signature is checked without holding the database.
    let Some(pull) = check_pull(agent.as_ref(), &q, &headers, at) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let found = {
        let db = st.db.lock().expect("db mutex");
        if !record_pull(&db, &q.agent_id, pull) {
            return StatusCode::NOT_FOUND.into_response();
        }
        // A signed pull (verified, and later than any before it) comes from
        // the VPS itself: its address is the VPS's own too. The agent pulls
        // over IPv4 where it can and reports the system's usual way, so a
        // dual-stack VPS gets both its addresses known (best effort; a
        // change is in the desired state this very answer carries).
        if matches!(pull, Pull::Signed(_))
            && let Err(e) = db.note_self_ip(&q.agent_id, &crate::auth::client_ip(&headers), at)
        {
            tracing::warn!("note_self_ip: {e:#}");
        }
        db.get_desired(&q.agent_id)
    };
    let (epoch, version, body) = match found {
        Ok(Some(v)) => v,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    // Already current?
    if epoch == q.epoch && version <= q.seq {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let signed = match sign_desired(&st.hubkey, &q.agent_id, epoch, version, body, now()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("sign_desired: {e:#}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let json = serde_json::to_string(&signed).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The signed pulls the hub took, one row per agent: the time the last one was
/// signed at. A row also means the agent signs its pulls, so an unsigned pull
/// for that id is never answered again.
const PULLS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS desired_pulls (
    agent_id TEXT PRIMARY KEY,
    last_ts INTEGER NOT NULL
)";

/// What deciding on a pull needs, read in one query: the agent's key, and the
/// time its last accepted signed pull was signed at (`None`: it never signed).
/// Never the agent's reports, which are large and slow to parse.
struct PullAgent {
    pubkey: String,
    last_signed: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pull {
    /// From an agent that predates signing.
    Unsigned,
    /// Signed by the agent at this time.
    Signed(i64),
}

fn pull_agent(db: &crate::db::Db, agent_id: &str) -> Option<PullAgent> {
    use rusqlite::OptionalExtension;
    db.conn.execute_batch(PULLS_SCHEMA).ok()?;
    db.conn
        .query_row(
            "SELECT a.pubkey, p.last_ts FROM agents a \
             LEFT JOIN desired_pulls p ON p.agent_id = a.id WHERE a.id = ?1",
            rusqlite::params![agent_id],
            |r| {
                Ok(PullAgent {
                    pubkey: r.get(0)?,
                    last_signed: r.get(1)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
}

/// A key nobody holds: a pull for an unknown id is checked against it, so it
/// takes as long as one for a real agent with a bad signature.
static NOBODY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    crypto::encode_pubkey(&ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]).verifying_key())
});

/// May this request read the agent's desired state, and as what?
///
/// A signed pull (both headers) must verify against the agent's key, be signed
/// within a day of the hub's clock, and be signed later than the last pull taken
/// from that agent: a copy of an earlier request (an access log, a proxy) reads
/// nothing. The agent keeps its times increasing across its processes and clock
/// steps. An unsigned pull is answered only for an agent that never signed one,
/// which is an agent older than signing.
fn check_pull(
    agent: Option<&PullAgent>,
    q: &DesiredQuery,
    headers: &axum::http::HeaderMap,
    now: i64,
) -> Option<Pull> {
    use snsec_common::schema::{HDR_PULL_SIG, HDR_PULL_TS};

    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match (header(HDR_PULL_TS), header(HDR_PULL_SIG)) {
        (None, None) => agent
            .filter(|a| a.last_signed.is_none())
            .map(|_| Pull::Unsigned),
        (Some(ts), Some(sig)) => {
            let ts: i64 = ts.trim().parse().ok()?;
            let key = agent.map_or(NOBODY.as_str(), |a| a.pubkey.as_str());
            let vk = crypto::parse_pubkey(key).ok()?;
            let verified =
                crypto::verify_desired_pull(&vk, &q.agent_id, q.epoch, q.seq, ts, sig.trim(), now);
            let agent = agent?;
            match verified {
                Ok(()) => {}
                Err(crypto::CryptoError::OutOfWindow { .. }) => {
                    // The agent's own key, so the clock is what is wrong: say so.
                    tracing::warn!(
                        "desired pull from {} refused: signed {}s away from the hub's clock (check the VPS clock)",
                        q.agent_id,
                        now.saturating_sub(ts)
                    );
                    return None;
                }
                Err(_) => return None,
            }
            if let Some(last) = agent.last_signed.filter(|&last| ts <= last) {
                tracing::info!(
                    "desired pull from {} refused: signed at {ts}, not after the last one ({last}); a copied request, or the VPS clock went back",
                    q.agent_id
                );
                return None;
            }
            Some(Pull::Signed(ts))
        }
        _ => None,
    }
}

/// Take a checked pull, under the same lock as the read that answers it. A
/// signed one moves the agent's last time forward, or is refused when another
/// pull got there first with the same or a later time; an unsigned one is
/// refused once any signed pull came in.
fn record_pull(db: &crate::db::Db, agent_id: &str, pull: Pull) -> bool {
    use rusqlite::OptionalExtension;
    if db.conn.execute_batch(PULLS_SCHEMA).is_err() {
        return false;
    }
    match pull {
        Pull::Unsigned => db
            .conn
            .query_row(
                "SELECT 1 FROM desired_pulls WHERE agent_id = ?1",
                rusqlite::params![agent_id],
                |_| Ok(()),
            )
            .optional()
            .is_ok_and(|row| row.is_none()),
        Pull::Signed(ts) => db
            .conn
            .execute(
                "INSERT INTO desired_pulls (agent_id, last_ts) VALUES (?1, ?2) \
                 ON CONFLICT(agent_id) DO UPDATE SET last_ts = excluded.last_ts \
                 WHERE excluded.last_ts > desired_pulls.last_ts",
                rusqlite::params![agent_id, ts],
            )
            .is_ok_and(|changed| changed == 1),
    }
}

#[cfg(test)]
mod desired_pull_tests;

#[derive(Deserialize)]
pub struct EnrollReq {
    token: String,
    name: String,
    agent_pubkey: String,
    #[serde(default)]
    agent_version: String,
}

/// POST /v1/enroll — consume a single-use token, register the agent's pubkey,
/// return the agent id and the hub/root public keys.
pub async fn post_enroll(State(st): State<Arc<AppState>>, body: String) -> Response {
    let req: EnrollReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
    };
    if crypto::parse_pubkey(&req.agent_pubkey).is_err() {
        return (StatusCode::BAD_REQUEST, "bad agent_pubkey").into_response();
    }
    let _ = req.agent_version;

    let db = st.db.lock().expect("db mutex");
    let name = match db.consume_token(&req.token, now()) {
        Ok(Some(n)) => n,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid or used token").into_response(),
        Err(e) => {
            tracing::error!("consume_token: {e:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };
    // Prefer the operator-chosen name from the token.
    let display = if name.is_empty() { req.name } else { name };
    let agent_id = match db.enroll_agent(&display, &req.agent_pubkey, now()) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("enroll_agent: {e:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };
    let resp = serde_json::json!({
        "agent_id": agent_id,
        "hub_pubkeys": [st.hubkey.pubkey_str()],
        "root_pubkeys": if st.cfg.root_pubkey.is_empty() {
            Vec::new()
        } else {
            vec![st.cfg.root_pubkey.clone()]
        },
    });
    (StatusCode::OK, resp.to_string()).into_response()
}
