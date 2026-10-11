//! Hub client: build and sign reports, flush the spool, fetch and apply signed
//! desired-state. Pull model — the VPS always initiates; the hub never calls in.
//! Standalone (no hub configured) still runs locally and writes the latest
//! report to disk for the operator.

use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use snsec_common::crypto;
use snsec_common::schema::{
    ActiveBanInfo, BanEvent, CycleStats, DesiredBody, DesiredRef, Envelope, HostInfo, Mode,
    ReportBody, Signed, TriageSummary,
};
use snsec_common::{AGENT_VERSION, SCHEMA_VERSION};

use crate::config::Config;
use crate::state::State;
use crate::util;

const MAX_FLUSH_PER_CYCLE: usize = 50;
/// RAM-in-use percentage (excluding reclaimable cache) that raises an alert.
const MEM_ALERT_PCT: f64 = 90.0;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

fn capabilities() -> Vec<String> {
    vec![
        "triage".into(),
        "contain".into(),
        "hunt".into(),
        "watch".into(),
        "ban".into(),
        "undo".into(),
    ]
}

fn host_info() -> HostInfo {
    let hostname = nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    let os = crate::sys::proc::read_trim("/etc/os-release")
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_default();
    let kernel = crate::sys::proc::read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    HostInfo {
        hostname,
        os,
        kernel,
        cgroup: crate::sys::cgroup::version_str().to_string(),
        firewall: if crate::sys::fw::available() {
            "nftables".into()
        } else {
            "none".into()
        },
        web_server: crate::discover::detect_listener(&crate::sys::netstat::all())
            .name()
            .to_string(),
    }
}

/// Build the report, enqueue it, then (if a hub is configured) flush the spool
/// and apply desired state.
pub fn sync(
    cfg: &Config,
    state: &State,
    cycle: CycleStats,
    bans: Vec<BanEvent>,
    would_ban: Vec<BanEvent>,
    mut alerts: Vec<snsec_common::schema::Alert>,
) -> Result<()> {
    let hub_configured = !cfg.hub.url.is_empty() && !cfg.hub.agent_key.is_empty();

    // Take the hub's orders *before* building the report, so a ban the admin
    // just ordered is already in force (and visible in `active_bans`) in this
    // very report instead of one cycle later.
    if hub_configured && let Err(e) = fetch_and_apply_desired(cfg, state) {
        eprintln!("hub: desired fetch/apply failed: {e:#}");
    }

    let mut meta = state.meta();
    let seq = meta.next_report_seq;
    meta.next_report_seq += 1;

    if cycle.mem_total_mb > 0 && cycle.mem_used_pct >= MEM_ALERT_PCT {
        alerts.push(snsec_common::schema::Alert {
            kind: "mem_high".into(),
            message: format!(
                "RAM {:.0}% in use of {} MB (swap {:.0}%)",
                cycle.mem_used_pct, cycle.mem_total_mb, cycle.swap_used_pct
            ),
            severity: if cycle.mem_used_pct >= 95.0 {
                "urgent"
            } else {
                "warn"
            }
            .into(),
        });
    }

    let triage: Option<TriageSummary> = std::fs::read(state.dir.join("triage-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());

    let (active_list, active_total) = active_bans(state);
    let body = ReportBody {
        agent_version: AGENT_VERSION.to_string(),
        host: host_info(),
        cycle,
        bans,
        would_ban,
        alerts,
        triage,
        findings: Vec::new(),
        applied_desired: meta.applied_desired,
        capabilities: capabilities(),
        active_bans: active_list,
        active_bans_total: active_total,
    };

    let body_json = serde_json::to_vec(&body)?;
    state.queue_report(seq, &body_json)?;
    state.save_meta(&meta)?;

    // Always keep a readable latest report for the operator.
    let _ = std::fs::write(state.dir.join("last-report.json"), &body_json);

    if !hub_configured {
        return Ok(()); // standalone
    }

    let signing_key =
        crypto::parse_secret(&cfg.hub.agent_key).context("parsing agent_key (hub.agent_key)")?;

    if let Err(e) = flush_reports(cfg, state, &signing_key, meta.epoch) {
        eprintln!("hub: report flush failed (queued for retry): {e:#}");
    }
    Ok(())
}

/// At most this many bans are listed per report (the full count is always sent).
const MAX_LISTED_BANS: usize = 500;

/// Every ban still in force, whoever set it (expired entries dropped), as
/// `(listed, total)`. When there are more than `MAX_LISTED_BANS` the list keeps
/// the ones that last longest — repeat offenders and admin orders — and `total`
/// still reports the real number so the hub can say the list is partial.
fn active_bans(state: &State) -> (Vec<ActiveBanInfo>, u32) {
    let now = util::now_secs();
    let mut v: Vec<ActiveBanInfo> = state
        .bans()
        .into_iter()
        .filter(|(_, b)| b.expires_ts > now)
        .map(|(ip, b)| ActiveBanInfo {
            ip,
            reason: b.reason,
            expires_at: b.expires_ts,
            strike: b.strike,
            layer: b.layer,
        })
        .collect();
    let total = u32::try_from(v.len()).unwrap_or(u32::MAX);
    // Longest-lasting first; ties broken by address so the cut is deterministic.
    v.sort_by(|a, b| {
        b.expires_at
            .cmp(&a.expires_at)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    v.truncate(MAX_LISTED_BANS);
    (v, total)
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .build()
}

fn flush_reports(cfg: &Config, state: &State, sk: &SigningKey, epoch: u64) -> Result<()> {
    let agent = http_agent();
    let url = format!("{}/v1/report", cfg.hub.url.trim_end_matches('/'));
    let now = util::now_secs();
    for (path, seq) in state.queued().into_iter().take(MAX_FLUSH_PER_CYCLE) {
        let body_json = std::fs::read(&path)?;
        let body: ReportBody = serde_json::from_slice(&body_json)?;
        let env = Envelope {
            schema_version: SCHEMA_VERSION,
            agent_id: cfg.hub.agent_id.clone(),
            epoch,
            seq,
            issued_at: now,
            expires_at: now + 7 * 86_400,
            body,
        };
        let signed = crypto::sign(sk, &cfg.hub.agent_id, &env)?;
        let payload = serde_json::to_string(&signed)?;
        match agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&payload)
        {
            Ok(_) => state.drop_queued(&path),
            Err(e) => {
                anyhow::bail!("posting report seq {seq}: {e}");
            }
        }
    }
    Ok(())
}

fn hub_keys(cfg: &Config) -> Vec<VerifyingKey> {
    cfg.hub
        .hub_pubkeys
        .iter()
        .filter_map(|s| crypto::parse_pubkey(s).ok())
        .collect()
}

fn root_keys(cfg: &Config) -> Vec<VerifyingKey> {
    cfg.hub
        .root_pubkeys
        .iter()
        .filter_map(|s| crypto::parse_pubkey(s).ok())
        .collect()
}

fn fetch_and_apply_desired(cfg: &Config, state: &State) -> Result<()> {
    let keys = hub_keys(cfg);
    if keys.is_empty() {
        return Ok(()); // no hub keys configured; cannot trust desired
    }
    let agent = http_agent();
    let meta = state.meta();
    let url = format!(
        "{}/v1/desired?agent_id={}&epoch={}&seq={}",
        cfg.hub.url.trim_end_matches('/'),
        cfg.hub.agent_id,
        meta.last_desired.epoch,
        meta.last_desired.seq
    );
    let resp = agent.get(&url).call();
    let text = match resp {
        Ok(r) => r.into_string().context("reading desired body")?,
        Err(ureq::Error::Status(304, _)) => return Ok(()), // not modified
        Err(e) => anyhow::bail!("GET desired: {e}"),
    };
    if text.trim().is_empty() {
        return Ok(());
    }
    let signed: Signed = serde_json::from_str(&text).context("parsing desired envelope")?;
    let now = util::now_secs();
    let env: Envelope<DesiredBody> =
        crypto::open(&keys, &signed, now).context("verifying desired signature")?;

    if env.agent_id != cfg.hub.agent_id {
        anyhow::bail!("desired agent_id mismatch");
    }
    // Replay / monotonicity defence.
    if !env.is_newer_than(meta.last_desired.epoch, meta.last_desired.seq) {
        return Ok(());
    }

    apply_desired(cfg, state, &env.body)?;

    let mut meta = state.meta();
    meta.last_desired = DesiredRef {
        epoch: env.epoch,
        seq: env.seq,
    };
    meta.applied_desired = meta.last_desired;
    state.save_meta(&meta)?;
    Ok(())
}

fn apply_desired(cfg: &Config, state: &State, d: &DesiredBody) -> Result<()> {
    // Hard local bounds (SEC-2): the hub can never exceed these.
    let _timer = d.timer_interval_secs.clamp(300, 900);

    // Operator bans / unbans (web-port only, like every other ban).
    let now = util::now_secs();
    let mut adds: Vec<(String, u64)> = Vec::new();
    for b in &d.bans {
        let ttl = b.ttl_secs.min(24 * 3600);
        let ttl = if b.created_at > 0 {
            // Apply only what is left of the ban. This body is re-sent on every
            // unrelated desired change (mode, another ban...); without this an
            // old ban would be re-armed with a full fresh TTL each time.
            let remaining = b.created_at + ttl as i64 - now;
            if remaining <= 0 {
                continue; // already lapsed
            }
            remaining as u64
        } else {
            ttl
        };
        adds.push((normalize_ban_key(&b.ip), ttl));
    }
    let dels: Vec<String> = d.unbans.iter().map(|ip| normalize_ban_key(ip)).collect();

    if (!adds.is_empty() || !dels.is_empty()) && crate::sys::fw::available() {
        crate::sys::fw::ensure_table(&cfg.fw.web_ports)?;
        crate::sys::fw::apply_bans(&adds, &dels)?;
        // Record operator bans in state so reports stay consistent.
        let mut active = state.bans();
        for (key, ttl) in &adds {
            active.insert(
                key.clone(),
                crate::state::ActiveBan {
                    reason: "hub".into(),
                    expires_ts: now + *ttl as i64,
                    strike: 0,
                    layer: "l3".into(),
                },
            );
        }
        for key in &dels {
            active.remove(key);
        }
        let _ = state.save_bans(&active);
    }

    // Policy tier (trusted_proxies / patterns / mode->observe) must be root
    // signed. We verify it but defer wiring patterns to v1.1; a bad signature
    // is rejected loudly.
    if let Some(policy) = &d.policy {
        let roots = root_keys(cfg);
        if roots.is_empty() {
            eprintln!("hub: policy present but no root_pubkeys configured; ignoring");
        } else if crypto::verify_detached(&roots, policy.env.as_bytes(), &policy.sig).is_err() {
            anyhow::bail!("policy signature invalid (not signed by a configured root key)");
        } else {
            // Signature valid; apply only the mode de-escalation here for v1.
            if cfg.remote.allow_mode_observe {
                eprintln!("hub: root policy accepted (mode/patterns application is v1.1)");
            }
        }
    }

    // Mode: escalation (observe -> enforce) is always honoured; de-escalation
    // (enforce -> observe) is gated behind `[remote] allow_mode_observe` so a
    // compromised hub cannot silently disable protection fleet-wide (SEC-2).
    // The effective mode is stored as an override that `watch` reads.
    {
        let mut meta = state.meta();
        let current = meta.mode_override.unwrap_or(cfg.watch.mode);
        match d.mode {
            Mode::Enforce => {
                if current != Mode::Enforce {
                    meta.mode_override = Some(Mode::Enforce);
                    state.save_meta(&meta)?;
                    eprintln!("hub: mode -> enforce (from hub)");
                }
            }
            Mode::Observe => {
                if current == Mode::Enforce {
                    if cfg.remote.allow_mode_observe {
                        meta.mode_override = Some(Mode::Observe);
                        state.save_meta(&meta)?;
                        eprintln!("hub: mode -> observe (allow_mode_observe)");
                    } else {
                        eprintln!(
                            "hub: ignoring observe request (set [remote] allow_mode_observe=true, or run `sn disable` locally)"
                        );
                    }
                } else {
                    meta.mode_override = Some(Mode::Observe);
                    state.save_meta(&meta)?;
                }
            }
        }
    }

    // One-shot jobs: run only when jobs_seq advanced beyond what we last ran.
    if d.jobs_seq > 0 {
        let mut meta = state.meta();
        if d.jobs_seq > meta.last_jobs_seq {
            for job in &d.jobs {
                run_job(cfg, state, job);
            }
            meta.last_jobs_seq = d.jobs_seq;
            state.save_meta(&meta)?;
        }
    }
    Ok(())
}

/// Execute one hub-issued job, honouring the local allow-list.
fn run_job(cfg: &Config, state: &State, job: &snsec_common::schema::Job) {
    use snsec_common::schema::Job;
    match job {
        Job::Hunt { days } => {
            // Spawn a detached hunt so the watch cycle returns promptly; findings
            // land in the next report.
            let days = (*days).clamp(1, 30);
            match std::process::Command::new("/usr/local/bin/sn")
                .arg("hunt")
                .arg("--days")
                .arg(days.to_string())
                .spawn()
            {
                Ok(_) => eprintln!("hub: started `sn hunt --days {days}`"),
                Err(e) => eprintln!("hub: could not start hunt: {e}"),
            }
        }
        Job::Undo => {
            if cfg.remote.allow_undo {
                match crate::undo::run_all(&state.dir) {
                    Ok(n) => eprintln!("hub: undo reversed {n} action(s)"),
                    Err(e) => eprintln!("hub: undo failed: {e:#}"),
                }
            } else {
                eprintln!("hub: ignoring undo job (set [remote] allow_undo=true to permit)");
            }
        }
        Job::Contain { .. } => {
            eprintln!("hub: remote contain is not supported in v1 (use SSH + `sn contain`)");
        }
        Job::Fetch { .. } => {
            eprintln!("hub: remote fetch is not supported in v1");
        }
    }
}

fn normalize_ban_key(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(parsed) => snsec_common::net::ban_key(parsed),
        Err(_) => ip.to_string(),
    }
}

/// `sn enroll` — generate a keypair, register with the hub, persist config.
pub fn enroll(config_path: &std::path::Path, url: &str, name: &str, token: &str) -> Result<()> {
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let pk = crypto::encode_pubkey(&sk.verifying_key());

    let agent = http_agent();
    let enroll_url = format!("{}/v1/enroll", url.trim_end_matches('/'));
    let req = serde_json::json!({
        "token": token,
        "name": name,
        "agent_pubkey": pk,
        "agent_version": AGENT_VERSION,
    });
    let resp = agent
        .post(&enroll_url)
        .set("Content-Type", "application/json")
        .send_string(&req.to_string())
        .context("POST /v1/enroll")?;
    let text = resp.into_string().context("reading enroll response")?;
    let er: EnrollResp = serde_json::from_str(&text).context("parsing enroll response")?;

    // Merge into (or create) the config file.
    let mut cfg = Config::load(config_path).unwrap_or_else(|_| default_config());
    cfg.hub.url = url.trim_end_matches('/').to_string();
    cfg.hub.agent_id = er.agent_id;
    cfg.hub.agent_key = crypto::encode_secret(&sk);
    cfg.hub.hub_pubkeys = er.hub_pubkeys;
    cfg.hub.root_pubkeys = er.root_pubkeys;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let toml = toml::to_string_pretty(&cfg).context("serializing config")?;
    write_private(config_path, toml.as_bytes())?;
    println!(
        "enrolled as {} ; config written to {}",
        cfg.hub.agent_id,
        config_path.display()
    );
    Ok(())
}

fn default_config() -> Config {
    // Parse an empty TOML to get all serde defaults.
    toml::from_str("").expect("empty config parses to defaults")
}

/// Write a file with 0600 permissions (contains the agent secret key).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    use std::io::Write;
    f.write_all(bytes)?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct EnrollResp {
    agent_id: String,
    #[serde(default)]
    hub_pubkeys: Vec<String>,
    #[serde(default)]
    root_pubkeys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ActiveBan;
    use std::collections::HashMap;

    fn ban(expires_ts: i64) -> ActiveBan {
        ActiveBan {
            reason: "rate".into(),
            expires_ts,
            strike: 1,
            layer: "l3".into(),
        }
    }

    #[test]
    fn long_ban_list_is_cut_to_the_longest_lasting_but_total_stays_true() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let now = util::now_secs();

        let extra = 20usize;
        let mut bans = HashMap::new();
        for i in 0..(MAX_LISTED_BANS + extra) {
            bans.insert(
                format!("10.0.{}.{}", i / 250, i % 250),
                ban(now + 1000 + i as i64),
            );
        }
        // Already expired: neither listed nor counted.
        bans.insert("192.0.2.1".into(), ban(now - 5));
        state.save_bans(&bans).unwrap();

        let (list, total) = active_bans(&state);
        assert_eq!(total as usize, MAX_LISTED_BANS + extra);
        assert_eq!(list.len(), MAX_LISTED_BANS);
        // The `extra` shortest-lived bans were the ones dropped.
        assert!(
            list.iter()
                .all(|b| b.expires_at >= now + 1000 + extra as i64)
        );
        assert!(!list.iter().any(|b| b.ip == "192.0.2.1"));
    }

    #[test]
    fn short_list_is_sent_whole() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let now = util::now_secs();
        let mut bans = HashMap::new();
        bans.insert("198.51.100.1".into(), ban(now + 60));
        bans.insert("198.51.100.2".into(), ban(now + 120));
        state.save_bans(&bans).unwrap();

        let (list, total) = active_bans(&state);
        assert_eq!(total, 2);
        assert_eq!(list.len(), 2);
        // Longest-lasting first.
        assert_eq!(list[0].ip, "198.51.100.2");
    }
}
