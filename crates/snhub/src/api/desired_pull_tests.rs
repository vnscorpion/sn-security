//! Who may read an agent's desired state (`GET /v1/desired`).

use std::sync::{Arc, Mutex};

use axum::body::to_bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use snsec_common::crypto;
use snsec_common::schema::{
    CAP_SIGNED_DESIRED, CycleStats, DesiredBody, Envelope, HDR_PULL_SIG, HDR_PULL_TS, ReportBody,
    Signed,
};

use super::{DesiredQuery, get_desired, now, pull_allowed};
use crate::AppState;
use crate::db::Db;

struct Agent {
    id: String,
    sk: SigningKey,
}

fn db() -> Db {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("t.sqlite")).unwrap();
    // The database must outlive the test body.
    std::mem::forget(dir);
    db
}

fn enroll(db: &Db, name: &str) -> Agent {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = crypto::encode_pubkey(&sk.verifying_key());
    let id = db.enroll_agent(name, &pk, now()).unwrap();
    Agent { id, sk }
}

fn report(db: &Db, agent: &Agent, seq: u64, caps: &[&str]) {
    let body: ReportBody = serde_json::from_value(serde_json::json!({
        "agent_version": "0.9.0",
        "cycle": CycleStats::default(),
        "capabilities": caps,
    }))
    .unwrap();
    let json = serde_json::to_string(&body).unwrap();
    db.record_report(&agent.id, seq, now(), &body, &json)
        .unwrap();
}

fn query(id: &str, epoch: u64, seq: u64) -> DesiredQuery {
    DesiredQuery {
        agent_id: id.to_string(),
        epoch,
        seq,
    }
}

fn signed(sk: &SigningKey, id: &str, epoch: u64, seq: u64, ts: i64) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(HDR_PULL_TS, HeaderValue::from_str(&ts.to_string()).unwrap());
    let sig = crypto::sign_desired_pull(sk, id, epoch, seq, ts);
    h.insert(HDR_PULL_SIG, HeaderValue::from_str(&sig).unwrap());
    h
}

fn unsigned() -> HeaderMap {
    HeaderMap::new()
}

#[test]
fn an_agent_that_predates_signing_still_gets_its_orders_unsigned() {
    let db = db();
    let a = enroll(&db, "web-01");
    // Freshly enrolled, no report yet.
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
    // An older agent's report: no `signed_desired`.
    report(&db, &a, 1, &["triage", "hunt"]);
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
}

#[test]
fn once_an_agent_says_it_signs_an_unsigned_pull_is_refused() {
    let db = db();
    let a = enroll(&db, "web-01");
    report(&db, &a, 1, &["triage", CAP_SIGNED_DESIRED]);
    let q = query(&a.id, 1, 1);
    assert!(!pull_allowed(&db, &q, &unsigned(), now()));
    assert!(pull_allowed(
        &db,
        &q,
        &signed(&a.sk, &a.id, 1, 1, now()),
        now()
    ));
}

#[test]
fn a_bad_or_half_signature_is_refused_even_for_an_agent_that_never_signed() {
    let db = db();
    let a = enroll(&db, "web-01");
    let q = query(&a.id, 0, 0);
    let t = now();
    // Another key.
    let stranger = SigningKey::generate(&mut OsRng);
    assert!(!pull_allowed(
        &db,
        &q,
        &signed(&stranger, &a.id, 0, 0, t),
        t
    ));
    // Only one of the two headers.
    let full = signed(&a.sk, &a.id, 0, 0, t);
    for keep in [HDR_PULL_TS, HDR_PULL_SIG] {
        let mut h = HeaderMap::new();
        h.insert(keep, full.get(keep).unwrap().clone());
        assert!(!pull_allowed(&db, &q, &h, t), "only {keep}");
    }
    // A time that is not a number.
    let mut h = full.clone();
    h.insert(HDR_PULL_TS, HeaderValue::from_static("soon"));
    assert!(!pull_allowed(&db, &q, &h, t));
    assert!(pull_allowed(&db, &q, &full, t));
}

#[test]
fn a_signature_covers_the_query_and_allows_a_day_of_clock_skew() {
    let db = db();
    let a = enroll(&db, "web-01");
    let b = enroll(&db, "web-02");
    report(&db, &a, 1, &[CAP_SIGNED_DESIRED]);
    let t = now();
    // Signed for another (epoch, seq), or by another agent for this one's id.
    assert!(!pull_allowed(
        &db,
        &query(&a.id, 1, 2),
        &signed(&a.sk, &a.id, 1, 1, t),
        t
    ));
    assert!(!pull_allowed(
        &db,
        &query(&a.id, 1, 1),
        &signed(&b.sk, &a.id, 1, 1, t),
        t
    ));
    assert!(!pull_allowed(
        &db,
        &query(&a.id, 1, 1),
        &signed(&a.sk, &b.id, 1, 1, t),
        t
    ));
    // A VPS clock a few hours off still works; one more than a day off does not.
    let q = query(&a.id, 1, 1);
    for ts in [t - 23 * 3600, t + 23 * 3600] {
        assert!(
            pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 1, ts), t),
            "{ts}"
        );
    }
    for ts in [t - 25 * 3600, t + 25 * 3600] {
        assert!(
            !pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 1, ts), t),
            "{ts}"
        );
    }
}

#[test]
fn an_agent_rolled_back_to_an_older_binary_is_answered_after_its_next_report() {
    let db = db();
    let a = enroll(&db, "web-01");
    report(&db, &a, 1, &[CAP_SIGNED_DESIRED]);
    assert!(!pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
    // `sn.bak` restored: its report no longer lists the capability.
    report(&db, &a, 2, &["triage"]);
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
}

#[test]
fn an_unknown_agent_is_refused_signed_or_not() {
    let db = db();
    let a = enroll(&db, "web-01");
    let ghost = format!("{}x", a.id);
    let t = now();
    assert!(!pull_allowed(&db, &query(&ghost, 0, 0), &unsigned(), t));
    assert!(!pull_allowed(
        &db,
        &query(&ghost, 0, 0),
        &signed(&a.sk, &ghost, 0, 0, t),
        t
    ));
}

fn app(db: Db) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let hubkey = crate::keys::HubKey::load_or_create(dir.path()).unwrap();
    std::mem::forget(dir);
    Arc::new(AppState {
        db: Mutex::new(db),
        hubkey,
        cfg: crate::config::HubConfig::default(),
        sessions: crate::auth::Sessions::default(),
        pending: crate::auth::Pending::default(),
        limiter: crate::auth::Limiter::default(),
    })
}

async fn pull(st: &Arc<AppState>, q: DesiredQuery, headers: HeaderMap) -> (StatusCode, Vec<u8>) {
    let resp = get_desired(State(Arc::clone(st)), Query(q), headers).await;
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, body.to_vec())
}

#[tokio::test]
async fn an_unknown_id_and_a_bad_signature_get_the_same_answer() {
    let st = app(db());
    let (a, legacy) = {
        let db = st.db.lock().unwrap();
        let a = enroll(&db, "web-01");
        report(&db, &a, 1, &[CAP_SIGNED_DESIRED]);
        (a, enroll(&db, "web-02"))
    };
    let t = now();
    let stranger = SigningKey::generate(&mut OsRng);

    let unknown = pull(&st, query("web-01-000000", 0, 0), unsigned()).await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    for (q, h) in [
        (query(&a.id, 0, 0), unsigned()),
        (query(&a.id, 0, 0), signed(&stranger, &a.id, 0, 0, t)),
        (
            query(&legacy.id, 0, 0),
            signed(&stranger, &legacy.id, 0, 0, t),
        ),
        (
            query("web-01-000000", 0, 0),
            signed(&a.sk, "web-01-000000", 0, 0, t),
        ),
    ] {
        assert_eq!(pull(&st, q, h).await, unknown);
    }

    // The agent itself gets its desired state, signed by the hub and for it.
    let (status, body) = pull(&st, query(&a.id, 0, 0), signed(&a.sk, &a.id, 0, 0, t)).await;
    assert_eq!(status, StatusCode::OK);
    let s: Signed = serde_json::from_slice(&body).unwrap();
    let env: Envelope<DesiredBody> =
        crypto::open(&[st.hubkey.signing.verifying_key()], &s, t).unwrap();
    assert_eq!(env.agent_id, a.id);

    // "Nothing new" is an answer too, so it also needs the signature.
    let (epoch, seq) = (env.epoch, env.seq);
    let current = pull(
        &st,
        query(&a.id, epoch, seq),
        signed(&a.sk, &a.id, epoch, seq, t),
    )
    .await;
    assert_eq!(current.0, StatusCode::NOT_MODIFIED);
    assert_eq!(
        pull(&st, query(&a.id, epoch, seq), unsigned()).await,
        unknown
    );

    // An agent that predates signing keeps working unsigned.
    assert_eq!(
        pull(&st, query(&legacy.id, 0, 0), unsigned()).await.0,
        StatusCode::OK
    );
}
