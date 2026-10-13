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
            json!({ "vps": "web-01", "ip": "45.133.1.10" }),
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
            json!({ "vps": "all", "ip": "45.133.1.10", "ttl_secs": 999_999 }),
        )
        .await;
    assert_eq!(ok["isError"], false, "{ok}");
    assert_eq!(
        ok["structuredContent"]["ttl_secs"], 86400,
        "capped at a day"
    );
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    assert_eq!(d.bans[0].ip, "45.133.1.10");
    // The decisions log names the token.
    let log = h
        .call(&act, "get_activity_log", json!({ "vps": "web-01" }))
        .await;
    let who = log["structuredContent"]["entries"][0]["who"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(who.starts_with("mcp:hermes#"), "{who}");
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
    let by = props["structuredContent"]["proposals"][0]["by"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(by.starts_with("mcp:hermes#"), "{by}");
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

#[tokio::test]
async fn waiting_states_are_answers_not_errors() {
    // Hermes stops calling a server after three errors in a row: "not yet" must
    // not look like one.
    let h = hub();
    let act = h.token("act");
    {
        let db = h.st.db.lock().unwrap();
        db.enroll_agent("bare", "ed25519:y", now()).unwrap();
    }
    let ev = h.call(&act, "get_evidence", json!({ "vps": "bare" })).await;
    assert_eq!(ev["isError"], false, "{ev}");
    assert_eq!(ev["structuredContent"]["status"], "none");
    let plan = json!({ "vps": "bare", "diagnosis": "d", "actions": [] });
    let r = h.call(&act, "submit_plan", plan).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["status"], "need_evidence");
    // A busy VPS: the order is not sent, and says so plainly.
    let id = h.vps(&["evidence", "remediate", "clamav"]);
    let first = h
        .call(&act, "run_malware_scan", json!({ "vps": "web-01" }))
        .await;
    assert_eq!(first["structuredContent"]["queued"], true, "{first}");
    let second = h
        .call(&act, "install_clamav", json!({ "vps": "web-01" }))
        .await;
    assert_eq!(second["isError"], false, "{second}");
    assert_eq!(second["structuredContent"]["busy"], true);
    // Evidence that is still fresh is not asked for again.
    let r = h
        .call(&act, "request_evidence", json!({ "vps": "web-01" }))
        .await;
    assert_eq!(r["structuredContent"]["fresh"], true, "{r}");
    let _ = id;
}

#[tokio::test]
async fn an_outside_agent_cannot_free_an_attacker_or_switch_protection_off() {
    let h = hub();
    let id = h.vps(&["evidence", "remediate"]);
    let act = h.token("act");
    // Only the admin turns automatic blocking off.
    let r = h
        .call(
            &act,
            "set_mode",
            json!({ "vps": "web-01", "mode": "observe" }),
        )
        .await;
    assert_eq!(r["isError"], true);
    let r = h
        .call(
            &act,
            "set_mode",
            json!({ "vps": "web-01", "mode": "enforce" }),
        )
        .await;
    assert_eq!(r["structuredContent"]["mode"], "enforce", "{r}");
    // Unban lifts only what the hub ordered; nothing goes on the VPS's own
    // unban list.
    h.call(
        &act,
        "ban_ip",
        json!({ "vps": "web-01", "ip": "45.133.1.10" }),
    )
    .await;
    let r = h
        .call(
            &act,
            "unban_ip",
            json!({ "vps": "web-01", "ip": "45.133.1.10" }),
        )
        .await;
    assert_eq!(r["structuredContent"]["lifted_on"][0], "web-01", "{r}");
    let r = h
        .call(
            &act,
            "unban_ip",
            json!({ "vps": "web-01", "ip": "91.92.93.94" }),
        )
        .await;
    assert_eq!(r["structuredContent"]["no_hub_ban_on"][0], "web-01", "{r}");
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    assert!(
        d.bans.is_empty() && d.unbans.is_empty(),
        "{:?} {:?}",
        d.bans,
        d.unbans
    );
    // Private networks are not for an outside agent to block.
    let r = h
        .call(&act, "ban_ip", json!({ "vps": "all", "ip": "10.0.0.1" }))
        .await;
    assert_eq!(r["isError"], true);
}

#[tokio::test]
async fn a_plan_from_hermes_does_not_hide_the_built_in_ai() {
    let h = hub();
    let id = h.vps(&["evidence", "remediate"]);
    let propose = h.token("propose");
    {
        let db = h.st.db.lock().unwrap();
        db.create_proposal(
            now(),
            &crate::db_ai::NewProposal {
                agent_id: &id,
                provider: "AI tích hợp",
                status: "proposed",
                plan: &snsec_common::ai::Plan::default(),
                note: "",
                auto: false,
            },
        )
        .unwrap();
    }
    let plan = json!({ "vps": "web-01", "diagnosis": "d", "actions": [] });
    h.call(&propose, "submit_plan", plan).await;
    let db = h.st.db.lock().unwrap();
    assert_eq!(
        db.latest_ai_proposal(&id).unwrap().unwrap().provider,
        "AI tích hợp"
    );
    assert!(
        db.latest_mcp_proposal(&id)
            .unwrap()
            .unwrap()
            .provider
            .starts_with("mcp:")
    );
}

#[tokio::test]
async fn a_huge_plan_is_refused_before_it_costs_anything() {
    let h = hub();
    h.vps(&["evidence", "remediate"]);
    let propose = h.token("propose");
    let junk: Vec<Value> = (0..5_000).map(|_| json!(0)).collect();
    let r = h
        .call(
            &propose,
            "submit_plan",
            json!({ "vps": "web-01", "diagnosis": "d", "actions": junk }),
        )
        .await;
    assert_eq!(r["isError"], true);
    // And a body over the endpoint's limit never reaches the parser.
    let big = "x".repeat(200 * 1024);
    let r = h
        .mcp(
            &propose,
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "params": { "pad": big } }),
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_new_password_revokes_every_hermes_token() {
    let h = hub();
    let cookie = h.sign_in().await;
    let tok = h.token("act");
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    assert_eq!(h.mcp(&tok, &ping).await.status, StatusCode::OK);
    let new_pw = "another long passphrase";
    let r = h
        .post(
            "/security/password",
            &cookie,
            &format!(
                "{}&new={}&confirm={}",
                pw_form().replace("password=", "current="),
                web::urlenc(new_pw),
                web::urlenc(new_pw)
            ),
        )
        .await;
    assert!(r.location().contains("msg="), "{}", r.location());
    assert_eq!(h.mcp(&tok, &ping).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_admin_can_lift_every_ban_on_one_vps_or_all() {
    use snsec_common::schema::{DesiredBan, Mode};
    let h = hub();
    let cookie = h.sign_in().await;
    let id = h.vps(&["evidence", "remediate", "unban_all"]);
    {
        let db = h.st.db.lock().unwrap();
        db.update_desired(&id, now(), "admin", "ban", "x", |d| {
            d.bans.push(DesiredBan {
                ip: "45.133.1.10".into(),
                ttl_secs: 3600,
                reason: "admin".into(),
                created_at: now(),
            });
            d.mode = Mode::Enforce;
        })
        .unwrap();
    }
    let r = h
        .post(&format!("/agent/{id}/unban-all"), &cookie, "observe=on")
        .await;
    assert!(r.location().contains("msg="), "{}", r.location());
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    assert!(d.unban_all_seq > 0);
    assert!(d.bans.is_empty() && d.unbans.is_empty());
    assert_eq!(d.mode, Mode::Observe);
    let first = d.unban_all_seq;

    // Every VPS at once; the marker always moves forward.
    let r = h.post("/unban-all", &cookie, "observe=").await;
    assert!(r.location().starts_with("/?msg="), "{}", r.location());
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    assert!(d.unban_all_seq > first);
    // The overview shows the message.
    let page = h.get(&r.location(), &cookie).await;
    assert!(page.body.contains("gỡ toàn bộ lệnh chặn"), "{}", page.body);
}

#[tokio::test]
async fn an_agent_too_old_for_the_marker_gets_its_listed_bans_as_unbans() {
    use snsec_common::schema::ActiveBanInfo;
    let h = hub();
    let id = h.vps(&["evidence", "remediate"]);
    {
        let db = h.st.db.lock().unwrap();
        let mut rep = db.latest_report(&id).unwrap().unwrap();
        rep.active_bans = vec![ActiveBanInfo {
            ip: "91.92.93.94".into(),
            reason: "rate".into(),
            expires_at: now() + 600,
            strike: 1,
            layer: "l3".into(),
        }];
        let text = serde_json::to_string(&rep).unwrap();
        db.record_report(&id, 2, now(), &rep, &text).unwrap();
        db.unban_all(&id, now(), "console", false).unwrap();
    }
    let (_, _, d) = h.st.db.lock().unwrap().get_desired(&id).unwrap().unwrap();
    assert_eq!(d.unbans, vec!["91.92.93.94".to_string()]);
}

#[tokio::test]
async fn a_vps_is_removed_only_with_its_name_and_the_password() {
    let h = hub();
    let cookie = h.sign_in().await;
    let id = h.vps(&["evidence", "remediate"]);
    let page = h.get(&format!("/agent/{id}"), &cookie).await;
    assert!(page.body.contains("Xoá VPS khỏi hub"));
    let url = format!("/agent/{id}/delete");
    // Wrong name, wrong password: nothing happens.
    let r = h
        .post(&url, &cookie, &format!("confirm=web-02&{}", pw_form()))
        .await;
    assert!(r.location().contains("msg="));
    let r = h.post(&url, &cookie, "confirm=web-01&password=wrong").await;
    assert!(r.location().contains("msg="));
    assert!(h.st.db.lock().unwrap().agent(&id).unwrap().is_some());
    // Name and password: gone, with everything the hub held for it.
    let r = h
        .post(&url, &cookie, &format!("confirm=web-01&{}", pw_form()))
        .await;
    assert!(r.location().starts_with("/?msg="), "{}", r.location());
    let db = h.st.db.lock().unwrap();
    assert!(db.agent(&id).unwrap().is_none());
    assert!(
        db.agent_pubkey(&id).unwrap().is_none(),
        "its key no longer works"
    );
    assert!(db.latest_report(&id).unwrap().is_none());
    assert!(db.get_desired(&id).unwrap().is_none());
    assert!(db.latest_evidence(&id).unwrap().is_none());
    // The log keeps a line saying who removed it.
    let log = db.recent_decisions(5).unwrap();
    assert!(
        log.iter()
            .any(|(a, who, action, ..)| a == &id && who == "admin" && action == "remove_vps")
    );
}
