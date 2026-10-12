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

use super::{DesiredQuery, Pull, check_pull, get_desired, now, pull_agent, record_pull};
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

/// Check and take a pull, the way `get_desired` does.
fn pull_allowed(db: &Db, q: &DesiredQuery, headers: &HeaderMap, now: i64) -> bool {
    check_pull(pull_agent(db, &q.agent_id).as_ref(), q, headers, now)
        .is_some_and(|p| record_pull(db, &q.agent_id, p))
}

#[test]
fn an_agent_that_predates_signing_still_gets_its_orders_unsigned() {
    let db = db();
    let a = enroll(&db, "web-01");
    // Freshly enrolled, no report yet.
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
    // An older agent's report.
    report(&db, &a, 1, &["triage", "hunt"]);
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
}

#[test]
fn once_an_agent_signed_a_pull_an_unsigned_one_is_refused() {
    let db = db();
    let a = enroll(&db, "web-01");
    let t = now();
    let q = query(&a.id, 1, 1);
    assert!(pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 1, t), t));
    assert!(!pull_allowed(&db, &q, &unsigned(), t));
    // Whatever its reports say afterwards: only the agent's key can sign, and a
    // binary rolled back past signing must be upgraded again, not trusted.
    report(&db, &a, 1, &["triage"]);
    assert!(!pull_allowed(&db, &q, &unsigned(), t));
    assert!(pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 1, t + 1), t));
}

#[test]
fn the_decision_never_reads_the_agents_reports() {
    // Reports are large and slow to parse, and a stranger could make the hub do
    // it at will (and time it). What counts is the first signed pull, which an
    // agent that signs makes before its first report.
    let db = db();
    let a = enroll(&db, "web-01");
    report(&db, &a, 1, &["triage", CAP_SIGNED_DESIRED]);
    assert!(pull_allowed(&db, &query(&a.id, 0, 0), &unsigned(), now()));
}

#[test]
fn a_copied_signed_pull_reads_nothing() {
    let db = db();
    let a = enroll(&db, "web-01");
    let t = now();
    let q = query(&a.id, 1, 4);
    let h = signed(&a.sk, &a.id, 1, 4, t);
    assert!(pull_allowed(&db, &q, &h, t));
    // The same headers again (an access log, a proxy): refused, now and later.
    assert!(!pull_allowed(&db, &q, &h, t));
    assert!(!pull_allowed(&db, &q, &h, t + 600));
    // An older one too, even for another (epoch, seq).
    assert!(!pull_allowed(
        &db,
        &query(&a.id, 1, 3),
        &signed(&a.sk, &a.id, 1, 3, t - 300),
        t
    ));
    // The agent's next pull is signed later, and goes through.
    assert!(pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 4, t + 1), t));
}

#[test]
fn two_pulls_checked_at_once_are_taken_once() {
    // Both pass the check before either is recorded: only the first is taken.
    let db = db();
    let a = enroll(&db, "web-01");
    let t = now();
    let q = query(&a.id, 0, 0);
    let h = signed(&a.sk, &a.id, 0, 0, t);
    let first = check_pull(pull_agent(&db, &a.id).as_ref(), &q, &h, t);
    let second = check_pull(pull_agent(&db, &a.id).as_ref(), &q, &h, t);
    assert_eq!(first, Some(Pull::Signed(t)));
    assert_eq!(second, first);
    assert!(record_pull(&db, &a.id, first.unwrap()));
    assert!(!record_pull(&db, &a.id, second.unwrap()));
    // And an unsigned pull checked before the first signed one came in.
    let b = enroll(&db, "web-02");
    let q = query(&b.id, 0, 0);
    let old = check_pull(pull_agent(&db, &b.id).as_ref(), &q, &unsigned(), t);
    assert_eq!(old, Some(Pull::Unsigned));
    assert!(pull_allowed(&db, &q, &signed(&b.sk, &b.id, 0, 0, t), t));
    assert!(!record_pull(&db, &b.id, old.unwrap()));
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
    // None of these counted as a signed pull: unsigned still works.
    assert!(pull_allowed(&db, &q, &unsigned(), t));
    assert!(pull_allowed(&db, &q, &full, t));
}

#[test]
fn a_signature_covers_the_query_and_allows_a_day_of_clock_skew() {
    let db = db();
    let a = enroll(&db, "web-01");
    let b = enroll(&db, "web-02");
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
    for ts in [t - 25 * 3600, t + 25 * 3600] {
        assert!(
            !pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 1, ts), t),
            "{ts}"
        );
    }
    for ts in [t - 23 * 3600, t + 23 * 3600] {
        assert!(
            pull_allowed(&db, &q, &signed(&a.sk, &a.id, 1, 1, ts), t),
            "{ts}"
        );
    }
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
async fn an_unknown_id_and_a_bad_or_copied_signature_get_the_same_answer() {
    let st = app(db());
    let (a, legacy) = {
        let db = st.db.lock().unwrap();
        (enroll(&db, "web-01"), enroll(&db, "web-02"))
    };
    let t = now();
    let stranger = SigningKey::generate(&mut OsRng);

    // The agent itself gets its desired state, signed by the hub and for it.
    let first = signed(&a.sk, &a.id, 0, 0, t);
    let (status, body) = pull(&st, query(&a.id, 0, 0), first.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let s: Signed = serde_json::from_slice(&body).unwrap();
    let env: Envelope<DesiredBody> =
        crypto::open(&[st.hubkey.signing.verifying_key()], &s, t).unwrap();
    assert_eq!(env.agent_id, a.id);

    let unknown = pull(&st, query("web-01-000000", 0, 0), unsigned()).await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    for (q, h) in [
        // It signs now, so an unsigned pull is not from it.
        (query(&a.id, 0, 0), unsigned()),
        (query(&a.id, 0, 0), signed(&stranger, &a.id, 0, 0, t + 1)),
        // Its own earlier request, replayed.
        (query(&a.id, 0, 0), first),
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

    // "Nothing new" is an answer too, so it also needs a fresh signature.
    let (epoch, seq) = (env.epoch, env.seq);
    let current = pull(
        &st,
        query(&a.id, epoch, seq),
        signed(&a.sk, &a.id, epoch, seq, t + 1),
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
