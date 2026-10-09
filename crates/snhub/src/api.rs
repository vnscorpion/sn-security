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
use crate::desired::sign_desired;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// POST /v1/report — body is a [`Signed`] wrapping an [`Envelope<ReportBody>`].
pub async fn post_report(State(st): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    let signed: Signed = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
    };

    let db = st.db.lock().expect("db mutex");
    let pubkey = match db.agent_pubkey(&signed.key_id) {
        Ok(Some(pk)) => pk,
        _ => return (StatusCode::UNAUTHORIZED, "unknown agent").into_response(),
    };
    let vk = match crypto::parse_pubkey(&pubkey) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "bad stored key").into_response(),
    };

    let env: Envelope<ReportBody> = match crypto::open(&[vk], &signed, now()) {
        Ok(e) => e,
        Err(_) => return (StatusCode::UNAUTHORIZED, "signature/verify failed").into_response(),
    };
    if env.agent_id != signed.key_id {
        return (StatusCode::BAD_REQUEST, "agent_id mismatch").into_response();
    }

    // Replay / monotonicity: ignore an already-seen or older seq idempotently.
    let last = db.last_report_seq(&env.agent_id).unwrap_or(0);
    if env.seq <= last {
        return (StatusCode::OK, "duplicate").into_response();
    }

    let body_json = serde_json::to_string(&env.body).unwrap_or_default();
    if let Err(e) = db.record_report(&env.agent_id, env.seq, now(), &env.body, &body_json) {
        tracing::error!("record_report: {e:#}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response();
    }
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
pub async fn get_desired(
    State(st): State<Arc<AppState>>,
    Query(q): Query<DesiredQuery>,
) -> Response {
    let db = st.db.lock().expect("db mutex");
    let (epoch, version, body) = match db.get_desired(&q.agent_id) {
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
