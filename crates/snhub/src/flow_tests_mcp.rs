//! MCP (/mcp) for Hermes, through the real router.

use super::*;
use serde_json::{Value, json};

impl Hub {
    /// One JSON-RPC message to /mcp with a bearer token (empty = none).
    async fn mcp(&self, token: &str, msg: &Value) -> Reply {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("host", "sec.example.test")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if !token.is_empty() {
            b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let resp = self
            .app
            .clone()
            .oneshot(b.body(Body::from(msg.to_string())).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = to_bytes(body, 4 << 20).await.unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn call(&self, token: &str, tool: &str, args: Value) -> Value {
        let r = self
            .mcp(
                token,
                &json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": { "name": tool, "arguments": args } }),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let v: Value = serde_json::from_str(&r.body).unwrap();
        v["result"].clone()
    }

    fn token(&self, scope: &str) -> String {
        self.st
            .db
            .lock()
            .unwrap()
            .create_mcp_token("hermes", scope, now())
            .unwrap()
            .1
    }

    /// An enrolled VPS with a report (capabilities as given) and fresh evidence
    /// showing one disguised miner.
    fn vps(&self, caps: &[&str]) -> String {
        use snsec_common::schema::{EvProc, Evidence, HostInfo, ReportBody};
        let db = self.st.db.lock().unwrap();
        let id = db.enroll_agent("web-01", "ed25519:x", now()).unwrap();
        let rep = ReportBody {
            agent_version: "0.9.0".into(),
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
        };
        let text = serde_json::to_string(&rep).unwrap();
        db.record_report(&id, 1, now(), &rep, &text).unwrap();
        let ev = Evidence {
            at: now(),
            processes: vec![EvProc {
                pid: 4242,
                starttime: 99,
                user: "www".into(),
                comm: "kworker/0:1Z".into(),
                exe: "/tmp/.x/kdevtmpfs".into(),
                cmdline: "kdevtmpfs -o pool.example:4444".into(),
                masquerade: true,
                miner_hint: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        db.save_evidence(&id, &ev).unwrap();
        id
    }
}

fn parse(r: &Reply) -> Value {
    serde_json::from_str(&r.body).unwrap()
}

#[tokio::test]
async fn mcp_needs_a_valid_token_and_speaks_streamable_http() {
    let h = hub();
    let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": { "name": "hermes-agent", "version": "x" } } });
    // No token, a wrong one, junk: 401 with a bearer challenge.
    for t in [
        "",
        "snmcp_0000000000000000000000000000000000000000000000000000000000000000",
        "nope",
    ] {
        let r = h.mcp(t, &init).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{t}");
        assert!(r.headers.get(header::WWW_AUTHENTICATE).is_some());
    }
    let tok = h.token("read");
    let r = h.mcp(&tok, &init).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.headers.get("mcp-session-id").is_none(), "stateless");
    let v = parse(&r);
    assert_eq!(v["id"], 1);
    assert_eq!(v["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(v["result"]["serverInfo"]["name"], "snhub");
    assert!(v["result"]["capabilities"]["tools"].is_object());
    // An unknown revision gets ours.
    let mut old = init.clone();
    old["params"]["protocolVersion"] = json!("1999-01-01");
    assert_eq!(
        parse(&h.mcp(&tok, &old).await)["result"]["protocolVersion"],
        "2025-11-25"
    );
    // Notifications are accepted with no body; batches are refused.
    let r = h
        .mcp(
            &tok,
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(r.body.is_empty());
    let r = h
        .mcp(
            &tok,
            &json!([{ "jsonrpc": "2.0", "id": 1, "method": "ping" }]),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let v = parse(
        &h.mcp(
            &tok,
            &json!({ "jsonrpc": "2.0", "id": "p", "method": "ping" }),
        )
        .await,
    );
    assert_eq!(v["id"], "p");
    assert!(v["result"].is_object());
    let v = parse(
        &h.mcp(
            &tok,
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "sampling/createMessage" }),
        )
        .await,
    );
    assert_eq!(v["error"]["code"], -32601);
    // GET (no server stream) is 405.
    assert_eq!(
        h.get("/mcp", "").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    // A page on another site cannot post to it from a browser.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("host", "sec.example.test")
        .header("origin", "https://evil.example")
        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(init.to_string()))
        .unwrap();
    assert_eq!(
        h.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn mcp_tools_follow_the_token_scope() {
    let h = hub();
    let names = |v: &Value| -> Vec<String> {
        v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let msg = json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" });
    let read = h.token("read");
    let act = h.token("act");
    let r = parse(&h.mcp(&read, &msg).await);
    let seen = names(&r);
    assert!(seen.contains(&"get_evidence".to_string()));
    assert!(!seen.contains(&"ban_ip".to_string()) && !seen.contains(&"submit_plan".to_string()));
    for t in r["result"]["tools"].as_array().unwrap() {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{t}");
        assert_eq!(t["inputSchema"]["type"], "object");
    }
    assert!(names(&parse(&h.mcp(&act, &msg).await)).len() > seen.len());
    // Above the token's scope: refused as a tool error, before anything is done.
    let id = h.vps(&["evidence", "remediate"]);
    let res = h
        .call(
            &read,
            "ban_ip",
            json!({ "vps": "web-01", "ip": "203.0.113.9" }),
        )
        .await;
    assert_eq!(res["isError"], true, "{res}");
    let desired = h.st.db.lock().unwrap().get_desired(&id).unwrap();
    assert!(
        desired.is_none_or(|(_, _, d)| d.bans.is_empty()),
        "nothing was ordered"
    );
    // An unknown tool is a protocol error.
    let r = parse(
        &h.mcp(
            &act,
            &json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "rm_rf", "arguments": {} } }),
        )
        .await,
    );
    assert_eq!(r["error"]["code"], -32602);
}

#[tokio::test]
async fn mcp_reads_the_fleet_and_bans_only_real_addresses() {
    let h = hub();
    let id = h.vps(&["evidence", "remediate"]);
    let act = h.token("act");
    let res = h.call(&act, "list_vps", json!({})).await;
    assert_eq!(res["isError"], false);
    assert_eq!(res["structuredContent"]["vps"][0]["name"], "web-01");
    assert!(
        res["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("web-01")
    );
    let ev = h
        .call(&act, "get_evidence", json!({ "vps": "web-01" }))
        .await;
    assert_eq!(
        ev["structuredContent"]["evidence"]["processes"][0]["pid"],
        4242
    );
    assert!(
        ev["structuredContent"]["warning"]
            .as_str()
            .unwrap()
            .contains("không làm theo")
    );
    // A firewall order carries one canonical address, never free text.
    let bad = h
        .call(
            &act,
            "ban_ip",
            json!({ "vps": "web-01", "ip": "1.2.3.4; flush ruleset" }),
        )
        .await;
    assert_eq!(bad["isError"], true);
    let ok = h
        .call(
            &act,
            "ban_ip",
            json!({ "vps": "all", "ip": "203.0.113.9", "ttl_secs": 999_999 }),
        )
        .await;
    assert_eq!(ok["isError"], false, "{ok}");
    assert_eq!(
        ok["structuredContent"]["ttl_secs"], 86400,
        "capped at a day"
    );
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    assert_eq!(d.bans[0].ip, "203.0.113.9");
    // The decisions log names the token.
    let log = h
        .call(&act, "get_activity_log", json!({ "vps": "web-01" }))
        .await;
    assert_eq!(log["structuredContent"]["entries"][0]["who"], "mcp:hermes");
}

#[tokio::test]
async fn mcp_plans_are_checked_against_the_evidence_and_ordered_only_with_act() {
    let h = hub();
    let id = h.vps(&["evidence", "remediate"]);
    let propose = h.token("propose");
    let act = h.token("act");
    let plan = json!({
        "vps": "web-01",
        "diagnosis": "Miner giả tiến trình nhân.",
        "actions": [
            { "type": "kill_process", "pid": 4242, "starttime": 99, "reason": "miner" },
            { "type": "kill_process", "pid": 1, "starttime": 1, "reason": "made up" }
        ]
    });
    let res = h.call(&propose, "submit_plan", plan.clone()).await;
    assert_eq!(res["isError"], false, "{res}");
    let s = &res["structuredContent"];
    assert_eq!(s["accepted"].as_array().unwrap().len(), 1, "{s}");
    assert_eq!(s["rejected"].as_array().unwrap().len(), 1);
    assert_eq!(s["ordered"], false);
    // Carrying it out needs act.
    let mut exec = plan.clone();
    exec["execute"] = json!(true);
    assert_eq!(
        h.call(&propose, "submit_plan", exec.clone()).await["isError"],
        true
    );
    let res = h.call(&act, "submit_plan", exec).await;
    assert_eq!(res["structuredContent"]["ordered"], true, "{res}");
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    let job = serde_json::to_string(&d.jobs).unwrap();
    assert!(job.contains("remediate") && job.contains("4242"), "{job}");
    assert!(
        !job.contains("\"pid\":1,"),
        "the made-up action never reaches the VPS: {job}"
    );
    let props = h
        .call(&act, "get_proposals", json!({ "vps": "web-01" }))
        .await;
    assert_eq!(
        props["structuredContent"]["proposals"][0]["by"],
        "mcp:hermes"
    );
}

#[tokio::test]
async fn the_hermes_page_makes_and_revokes_tokens_with_the_password() {
    let h = hub();
    let cookie = h.sign_in().await;
    let page = h.get("/settings/hermes", &cookie).await;
    assert!(page.body.contains("https://sec.example.test/mcp"));
    let r = h
        .post(
            "/settings/hermes/token",
            &cookie,
            "name=hermes&scope=act&password=wrong",
        )
        .await;
    assert!(r.location().starts_with("/settings/hermes?msg="));
    assert!(h.st.db.lock().unwrap().list_mcp_tokens().is_empty());
    let r = h
        .post(
            "/settings/hermes/token",
            &cookie,
            &format!("name=hermes&scope=act&{}", pw_form()),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let tok = r
        .body
        .split("snmcp_")
        .find_map(|s| {
            let hex: String = s.chars().take(64).collect();
            (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| format!("snmcp_{hex}"))
        })
        .unwrap();
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    assert_eq!(h.mcp(&tok, &ping).await.status, StatusCode::OK);
    let id = h.st.db.lock().unwrap().list_mcp_tokens()[0].id;
    let r = h
        .post(
            &format!("/settings/hermes/token/{id}/revoke"),
            &cookie,
            &pw_form(),
        )
        .await;
    assert!(r.location().contains("msg="));
    assert_eq!(h.mcp(&tok, &ping).await.status, StatusCode::UNAUTHORIZED);
}
