//! Hub client: build and sign reports, flush the spool, fetch and apply signed
//! desired-state. Pull model — the VPS always initiates; the hub never calls in.
//! Standalone (no hub configured) still runs locally and writes the latest
//! report to disk for the operator.

use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use snsec_common::crypto;
use snsec_common::net;
use snsec_common::schema::{
    ActiveBanInfo, BanEvent, CAP_SIGNED_DESIRED, CycleStats, DesiredBody, DesiredRef, Envelope,
    Finding, HDR_PULL_SIG, HDR_PULL_TS, HostInfo, HuntSummary, ReportBody, Signed, TriageSummary,
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

fn capabilities(cfg: &Config) -> Vec<String> {
    let mut caps: Vec<String> = [
        "triage", "contain", "hunt", "watch", "ban", "undo",
        // Understands the `install_clamav` job (older agents cannot parse it).
        "clamav",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    // Signs its desired-state pulls: from now on the hub answers no unsigned
    // pull for this agent id.
    caps.push(CAP_SIGNED_DESIRED.into());
    // Listed only when this VPS allows them, so the hub offers the AI features
    // exactly where they will work. An agent that predates them lists neither.
    if cfg.remote.hub_orders {
        caps.push("evidence".into());
        caps.push("remediate".into());
    }
    caps
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

    // Reserved under the meta lock, so no other writer can hand out the same
    // number or roll it back.
    let seq = state.update_meta(|m| {
        let seq = m.next_report_seq;
        m.next_report_seq += 1;
        seq
    })?;
    let meta = state.meta();

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

    // The last malware scan: its findings and a summary, so the hub can show
    // "scanned N files, nothing found" as well as what was found.
    let (hunt, findings) = latest_hunt(state);
    alerts.extend(hunt_alerts(hunt.as_ref()));

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
        findings,
        applied_desired: meta.applied_desired,
        capabilities: capabilities(cfg),
        active_bans: active_list,
        active_bans_total: active_total,
        hunt,
        clamav: Some(crate::clamav_run::info(cfg, state)),
        evidence: fresh_evidence(state, &meta),
        remediation: fresh_remediation(state, &meta),
    };

    let body_json = serde_json::to_vec(&body)?;
    state.queue_report(seq, &body_json)?;
    // Queued: they need not travel again.
    let sent_evidence = body.evidence.as_ref().map(|e| e.at);
    let sent_remediation = body.remediation.as_ref().map(|r| r.id.clone());
    if sent_evidence.is_some() || sent_remediation.is_some() {
        state.update_meta(|m| {
            if let Some(at) = sent_evidence {
                m.last_evidence_sent = m.last_evidence_sent.max(at);
            }
            if let Some(id) = sent_remediation {
                m.last_remediation_sent = id;
            }
        })?;
    }

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

/// At most this many findings travel in one report (the summary has the totals).
const MAX_REPORTED_FINDINGS: usize = 100;

/// The most recent `sn hunt` result, as left in the state directory.
fn latest_hunt(state: &State) -> (Option<HuntSummary>, Vec<Finding>) {
    let summary = std::fs::read(state.dir.join("hunt-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<HuntSummary>(&b).ok());
    // Already sorted best-first by `sn hunt`.
    let mut findings: Vec<Finding> = std::fs::read(state.dir.join("findings-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    findings.truncate(MAX_REPORTED_FINDINGS);
    (summary, findings)
}

/// Alerts for what the last scan found. They persist in every report until the
/// files are dealt with (`sn clean`) or a later scan no longer finds them.
fn hunt_alerts(hunt: Option<&HuntSummary>) -> Vec<snsec_common::schema::Alert> {
    let Some(h) = hunt else {
        return Vec::new();
    };
    let mut alerts = Vec::new();
    if h.malicious > 0 {
        alerts.push(snsec_common::schema::Alert {
            kind: "malware_found".into(),
            message: format!(
                "{} malicious and {} suspicious file(s) in the last scan",
                h.malicious, h.suspicious
            ),
            severity: "urgent".into(),
        });
    } else if h.suspicious > 0 {
        alerts.push(snsec_common::schema::Alert {
            kind: "malware_suspect".into(),
            message: format!("{} suspicious file(s) in the last scan", h.suspicious),
            severity: "warn".into(),
        });
    }
    alerts
}

/// The malware scan's sandbox, as unit-file lines, each with the oldest systemd
/// that knows it.
///
/// The scan reads files users control and may run ClamAV's parsers over them as
/// root. So besides a read-only system it gets no network, no devices, no kernel
/// knobs, and no way to reach systemd's control sockets: uid 0 could otherwise
/// ask systemd to start an unconfined unit, which is how sn-watch itself starts
/// `sn remediate`. clamdscan reaches clamd over its unix socket, which a private
/// network leaves alone; the scan itself never uses the network.
///
/// The nightly unit (deploy/systemd/sn-hunt.service) and the copy install.sh
/// writes carry the same lines; a test keeps the three in step. A unit file only
/// warns about a setting its systemd does not know, but `systemd-run` refuses the
/// whole command, so the hub-started scan leaves out what the host is too old for.
const HUNT_SANDBOX: &[(&str, u32)] = &[
    ("NoNewPrivileges=yes", 0),
    ("ProtectSystem=strict", 0),
    ("ReadWritePaths=/var/lib/sn", 0),
    ("ReadOnlyPaths=/etc/sn", 0),
    ("PrivateTmp=yes", 0),
    ("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", 0),
    ("UMask=0077", 0),
    ("InaccessiblePaths=-/run/dbus/system_bus_socket", 0),
    ("InaccessiblePaths=-/run/systemd/private", 0),
    ("PrivateNetwork=yes", 0),
    ("PrivateDevices=yes", 0),
    ("ProtectKernelTunables=yes", 0),
    ("ProtectKernelModules=yes", 0),
    ("ProtectControlGroups=yes", 0),
    ("RestrictNamespaces=yes", 0),
    ("SystemCallFilter=@system-service", 239),
    // A refused call fails instead of killing the scan.
    ("SystemCallErrorNumber=EPERM", 239),
    ("RestrictSUIDSGID=yes", 242),
];

/// Arguments for `systemd-run` that start a malware scan in a unit of its own.
///
/// A scan must NOT be a child of `sn-watch.service`: that is a one-shot unit and
/// systemd kills every process left in it when it finishes, about a second
/// after the cycle starts. The fixed unit name also stops two scans overlapping,
/// and `--collect` stops a failed scan from blocking the next one. Priority is
/// kept low so a scan never starves the sites it is checking. `systemd` is the
/// host's systemd version (`None` = unknown: the whole sandbox).
fn hunt_unit_args(days: u32, systemd: Option<u32>) -> Vec<String> {
    let mut args: Vec<String> = [
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=sn-hunt-job",
        "--description=SN Secure malware scan (requested from the hub)",
        "--property=Nice=15",
        "--property=IOSchedulingClass=idle",
        "--property=CPUQuota=40%",
        // Room for ClamAV's `clamscan`, which loads its whole signature database.
        "--property=MemoryMax=2G",
        // Same 30-minute ceiling as the timer's unit (that one is Type=oneshot,
        // where TimeoutStartSec bounds the run; this one is a plain service).
        "--property=RuntimeMaxSec=30min",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.extend(
        HUNT_SANDBOX
            .iter()
            .filter(|(_, since)| systemd.is_none_or(|v| v >= *since))
            .map(|(p, _)| format!("--property={p}")),
    );
    args.extend(["/usr/local/bin/sn", "hunt", "--days"].map(String::from));
    args.push(days.to_string());
    args
}

/// The host's systemd version, from `systemctl --version`.
fn systemd_version() -> Option<u32> {
    let sc = util::find_bin("systemctl")?;
    let out = std::process::Command::new(sc)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    parse_systemd_version(&String::from_utf8_lossy(&out.stdout))
}

/// `systemd 255 (255.4-1ubuntu8)` -> 255.
fn parse_systemd_version(text: &str) -> Option<u32> {
    let rest = text.lines().next()?.trim().strip_prefix("systemd ")?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// The evidence snapshot, once: only when it is newer than what was last sent.
fn fresh_evidence(
    state: &State,
    meta: &crate::state::Meta,
) -> Option<snsec_common::schema::Evidence> {
    let ev = crate::evidence::latest(state)?;
    (ev.at > meta.last_evidence_sent).then_some(ev)
}

/// The result of the last remediation, once.
fn fresh_remediation(
    state: &State,
    meta: &crate::state::Meta,
) -> Option<snsec_common::schema::RemediationReport> {
    let r = crate::remediate::latest_result(state)?;
    (r.id != meta.last_remediation_sent).then_some(r)
}

/// `systemd-run` arguments for `sn evidence`: a short read-only job. It runs as
/// its own unit because the watch unit has a private `/tmp` and a read-only home,
/// so it could not see the places that matter.
fn evidence_unit_args() -> Vec<String> {
    [
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=sn-evidence",
        "--description=SN Secure evidence snapshot (requested from the hub)",
        "--property=Nice=10",
        "--property=IOSchedulingClass=idle",
        "--property=RuntimeMaxSec=15min",
        "--property=MemoryMax=512M",
        "--property=UMask=0077",
        "/usr/local/bin/sn",
        "evidence",
        "--follow",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// `systemd-run` arguments for `sn remediate --job <id>`. Unconfined root: it
/// has to edit users' files, change a shell and stop a service, which the watch
/// unit's sandbox forbids. One at a time (fixed unit name), and bounded in time.
fn remediate_unit_args(id: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=sn-remediate",
        "--description=SN Secure incident response (requested from the hub)",
        "--property=RuntimeMaxSec=10min",
        "--property=MemoryMax=1G",
        // Edits keep each file's own mode; anything new it makes is root's alone.
        "--property=UMask=0077",
        "/usr/local/bin/sn",
        "remediate",
        "--job",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.push(id.to_string());
    args
}

/// `systemd-run` arguments for the ClamAV install: root, low priority, no limit on
/// memory (a package manager and `freshclam` need what they need), one at a time.
/// No UMask=0077 here, unlike the other jobs: package scripts and `freshclam`
/// create system files (configs, the signature database) that other accounts
/// must read. Its own files sit in the state directory, which is 0700.
fn install_clamav_unit_args() -> Vec<String> {
    [
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=sn-install-clamav",
        "--description=SN Secure ClamAV install (requested from the hub)",
        "--property=Nice=10",
        "--property=IOSchedulingClass=idle",
        // A hard stop: TimeoutStartSec does not limit how long a running
        // service may go on, RuntimeMaxSec does.
        "--property=RuntimeMaxSec=90min",
        "/usr/local/bin/sn",
        "install-clamav",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
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

/// Fetch the hub's desired state and apply it, one caller at a time.
///
/// The watch timer and an incident follow-up (below) can both ask at once; two
/// that both see a new order would both run its job. A lock file in the state
/// directory makes the second wait and then see the first one's result.
fn fetch_and_apply_desired(cfg: &Config, state: &State) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state.dir.join("desired.lock"))
        .context("opening desired.lock")?;
    let guard = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| anyhow::anyhow!("locking desired.lock: {e}"))?;
    let result = fetch_and_apply_desired_unlocked(cfg, state);
    // Released here (and if the process dies, by the kernel).
    drop(guard);
    result
}

/// Start the watch service now, so a report (with fresh evidence or a result) is
/// sent at once instead of at the next five-minute tick.
fn start_watch_now() {
    if let Some(sc) = util::find_bin("systemctl") {
        let _ = std::process::Command::new(sc)
            .args(["start", "--no-block", "sn-watch.service"])
            .stdin(std::process::Stdio::null())
            .status();
    }
}

/// How long an incident follow-up keeps polling the hub, and how often.
const FOLLOW_SECS: u64 = 10 * 60;
const FOLLOW_EVERY: Duration = Duration::from_secs(15);

/// After evidence was collected for an incident: send it now, then ask the hub
/// for orders every few seconds for a while (instead of waiting for the next
/// timer tick), and send the result as soon as a remediation has run. An order
/// arrives within seconds of the analysis, and the process it targets is less
/// likely to be gone. Bounded in time; stops early once a result exists.
pub fn follow_incident(cfg: &Config, state: &State) {
    if cfg.hub.url.is_empty() || cfg.hub.agent_key.is_empty() {
        return;
    }
    let started = util::now_secs();
    start_watch_now();
    let deadline = std::time::Instant::now() + Duration::from_secs(FOLLOW_SECS);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(FOLLOW_EVERY);
        if let Err(e) = fetch_and_apply_desired(cfg, state) {
            eprintln!("follow: desired fetch failed: {e:#}");
        }
        if crate::remediate::latest_result(state).is_some_and(|r| r.at >= started) {
            start_watch_now();
            return;
        }
    }
}

fn fetch_and_apply_desired_unlocked(cfg: &Config, state: &State) -> Result<()> {
    let keys = hub_keys(cfg);
    if keys.is_empty() {
        return Ok(()); // no hub keys configured; cannot trust desired
    }
    let sk =
        crypto::parse_secret(&cfg.hub.agent_key).context("parsing agent_key (hub.agent_key)")?;
    let agent = http_agent();
    // Under desired.lock: nothing else writes `last_desired` meanwhile.
    let meta = state.meta();
    let url = format!(
        "{}/v1/desired?agent_id={}&epoch={}&seq={}",
        cfg.hub.url.trim_end_matches('/'),
        cfg.hub.agent_id,
        meta.last_desired.epoch,
        meta.last_desired.seq
    );
    let mut req = agent.get(&url);
    for (name, value) in pull_headers(&sk, &cfg.hub.agent_id, meta.last_desired, util::now_secs()) {
        req = req.set(name, &value);
    }
    let text = match req.call() {
        Ok(r) => r.into_string().context("reading desired body")?,
        Err(ureq::Error::Status(304, _)) => return Ok(()), // not modified
        Err(ureq::Error::Status(404, _)) => anyhow::bail!(
            "GET desired: the hub does not accept this agent's signed request (is the VPS clock right? was this VPS removed from the hub?)"
        ),
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

    // Raised, never lowered, whatever else changed in meta.json meanwhile.
    let applied = DesiredRef {
        epoch: env.epoch,
        seq: env.seq,
    };
    state.update_meta(|m| {
        if env.is_newer_than(m.last_desired.epoch, m.last_desired.seq) {
            m.last_desired = applied;
        }
        if env.is_newer_than(m.applied_desired.epoch, m.applied_desired.seq) {
            m.applied_desired = applied;
        }
    })?;
    Ok(())
}

/// Headers that prove the desired-state pull comes from this agent: a signature
/// by its own key over the agent id, the version it has and the time. The hub
/// answers no unsigned pull for an agent that reported `signed_desired`.
fn pull_headers(
    sk: &SigningKey,
    agent_id: &str,
    have: DesiredRef,
    now: i64,
) -> [(&'static str, String); 2] {
    let sig = crypto::sign_desired_pull(sk, agent_id, have.epoch, have.seq, now);
    [(HDR_PULL_TS, now.to_string()), (HDR_PULL_SIG, sig)]
}

fn apply_desired(cfg: &Config, state: &State, d: &DesiredBody) -> Result<()> {
    // The one local switch: a VPS with `[remote] hub_orders = false` only reports.
    // Otherwise the hub decides (bans, mode, scans, undo, evidence, ClamAV, orders).
    if !cfg.remote.hub_orders {
        eprintln!("hub: orders ignored on this VPS ([remote] hub_orders = false)");
        return Ok(());
    }
    // Hard local bounds (SEC-2): the hub can never exceed these.
    let _timer = d.timer_interval_secs.clamp(300, 900);

    // Operator bans / unbans (web-port only, like every other ban). Only a key
    // rebuilt from a parsed address goes on (see `canonical_ban_key`).
    let now = util::now_secs();
    let mut adds: Vec<(String, u64)> = Vec::new();
    for b in &d.bans {
        let Some(key) = canonical_ban_key(&b.ip) else {
            eprintln!("hub: ignoring ban of {}: not one address", shown(&b.ip));
            continue;
        };
        if let Some(ttl) = hub_ban_ttl(b.ttl_secs, b.created_at, now) {
            adds.push((key, ttl));
        }
    }
    let dels: Vec<String> = d
        .unbans
        .iter()
        .filter_map(|ip| {
            let key = canonical_ban_key(ip);
            if key.is_none() {
                eprintln!("hub: ignoring unban of {}: not one address", shown(ip));
            }
            key
        })
        .collect();

    if (!adds.is_empty() || !dels.is_empty()) && crate::sys::fw::available() {
        // A firewall problem must not stop the rest of the order. This used to
        // return the error, so the desired-state was never marked applied, the
        // same order was retried and failed every cycle, and a job in it (install
        // ClamAV, a scan, an incident order) never ran.
        let applied = crate::sys::fw::ensure_table(&cfg.fw.web_ports)
            .and_then(|()| crate::sys::fw::apply_bans(&adds, &dels));
        match applied {
            Err(e) => eprintln!(
                "hub: could not apply the ban list ({e:#}); carrying on with the rest of the order"
            ),
            Ok(()) => {
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
        }
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
            if cfg.remote.hub_orders {
                eprintln!("hub: root policy accepted (mode/patterns application is v1.1)");
            }
        }
    }

    // Mode: the hub decides, both ways. The effective mode is stored as an
    // override that `watch` reads. (A VPS that must not obey the hub at all sets
    // `[remote] hub_orders = false`, which returns before this point.)
    let mode_changed = state.update_meta(|m| {
        let changed = d.mode != m.mode_override.unwrap_or(cfg.watch.mode);
        if changed {
            m.mode_override = Some(d.mode);
        }
        changed
    })?;
    if mode_changed {
        eprintln!("hub: mode -> {} (from hub)", d.mode.as_str());
    }

    // One-shot jobs: run only when jobs_seq advanced beyond what we last ran.
    if claim_jobs(state, d.jobs_seq)? {
        for job in &d.jobs {
            run_job(cfg, state, job);
        }
    }
    Ok(())
}

/// Take the jobs of `jobs_seq` for this run, if nobody ran them yet. Recorded
/// under the meta lock *before* they run: a crash or a second process can then
/// skip a job, but never run it twice (remediate, undo, install).
fn claim_jobs(state: &State, jobs_seq: u64) -> Result<bool> {
    if jobs_seq == 0 {
        return Ok(false);
    }
    state.update_meta(|m| {
        let new = jobs_seq > m.last_jobs_seq;
        if new {
            m.last_jobs_seq = jobs_seq;
        }
        new
    })
}

/// Longest a hub ban may last on this VPS (REVIEW SEC-2).
const MAX_HUB_BAN_SECS: u64 = 24 * 3600;

/// Seconds a hub ban should still last, or `None` to skip it. Capped at
/// [`MAX_HUB_BAN_SECS`] whatever the body says: a `created_at` in the future
/// cannot stretch it, and a TTL of 0 (which nft would read as "never expires")
/// is dropped.
fn hub_ban_ttl(ttl_secs: u64, created_at: i64, now: i64) -> Option<u64> {
    let ttl = ttl_secs.min(MAX_HUB_BAN_SECS);
    if ttl == 0 {
        return None;
    }
    if created_at <= 0 {
        return Some(ttl); // written before `created_at` existed
    }
    // Apply only what is left of the ban. This body is re-sent on every
    // unrelated desired change (mode, another ban...); without this an old ban
    // would be re-armed with a full fresh TTL each time.
    let created = created_at.min(now);
    let remaining = created.saturating_add(ttl as i64).saturating_sub(now);
    if remaining <= 0 {
        return None; // already lapsed
    }
    Some((remaining as u64).min(ttl))
}

/// Execute one hub-issued job, honouring the local allow-list.
fn run_job(cfg: &Config, state: &State, job: &snsec_common::schema::Job) {
    use snsec_common::schema::Job;
    match job {
        Job::Hunt { days } => {
            // Run the scan as its own systemd unit (see `hunt_unit_args`): a plain
            // child process would be killed when this one-shot cycle ends. Its
            // result reaches the hub in a later report.
            let days = (*days).clamp(1, 30);
            match std::process::Command::new("systemd-run")
                .args(hunt_unit_args(days, systemd_version()))
                .status()
            {
                Ok(s) if s.success() => eprintln!("hub: started malware scan (days={days})"),
                Ok(s) => eprintln!(
                    "hub: could not start the scan ({s}); one may already be running (`systemctl status sn-hunt-job`)"
                ),
                Err(e) => {
                    eprintln!("hub: could not start the scan (is systemd-run installed?): {e}")
                }
            }
        }
        Job::Undo => {
            if cfg.remote.hub_orders {
                match crate::undo::run_all(&state.dir) {
                    Ok(n) => eprintln!("hub: undo reversed {n} action(s)"),
                    Err(e) => eprintln!("hub: undo failed: {e:#}"),
                }
            } else {
                eprintln!("hub: ignoring undo job ([remote] hub_orders = false on this VPS)");
            }
        }
        Job::InstallClamav => {
            if !cfg.remote.hub_orders {
                eprintln!(
                    "hub: ignoring install_clamav job ([remote] hub_orders = false on this VPS)"
                );
                crate::clamav_run::record_order(
                    state,
                    "bỏ qua: VPS này đang tắt lệnh từ hub ([remote] hub_orders = false trong agent.toml)",
                );
                return;
            }
            // Its own systemd unit, like the scan: a package install outlives this
            // one-shot cycle, and the fixed unit name stops two from overlapping.
            match std::process::Command::new("systemd-run")
                .args(install_clamav_unit_args())
                .status()
            {
                Ok(s) if s.success() => {
                    eprintln!("hub: started ClamAV install");
                    crate::clamav_run::record_order(
                        state,
                        "đã nhận lệnh và bắt đầu cài (đơn vị systemd sn-install-clamav)",
                    );
                }
                Ok(s) => {
                    eprintln!(
                        "hub: could not start the ClamAV install ({s}); one may already be running (`systemctl status sn-install-clamav`)"
                    );
                    crate::clamav_run::record_order(
                        state,
                        &format!(
                            "không khởi động được lần cài ({s}); có thể một lần cài khác đang chạy: systemctl status sn-install-clamav"
                        ),
                    );
                }
                Err(e) => {
                    eprintln!("hub: could not start the ClamAV install: {e}");
                    crate::clamav_run::record_order(
                        state,
                        &format!("không chạy được systemd-run: {e}"),
                    );
                }
            }
        }
        Job::Evidence => {
            if !cfg.remote.hub_orders {
                eprintln!("hub: ignoring evidence job ([remote] hub_orders = false on this VPS)");
                return;
            }
            match std::process::Command::new("systemd-run")
                .args(evidence_unit_args())
                .status()
            {
                Ok(s) if s.success() => eprintln!("hub: started evidence collection"),
                Ok(s) => eprintln!("hub: could not start evidence collection ({s})"),
                Err(e) => eprintln!("hub: could not start evidence collection: {e}"),
            }
        }
        Job::Remediate { id, actions } => {
            if !cfg.remote.hub_orders {
                eprintln!("hub: ignoring remediate job ([remote] hub_orders = false on this VPS)");
                return;
            }
            if !crate::remediate::is_valid_job_id(id) {
                eprintln!("hub: ignoring remediate job with an invalid id");
                return;
            }
            // The unit reads the order from a file only root can read.
            let capped: Vec<_> = actions
                .iter()
                .take(snsec_common::ai::MAX_ACTIONS)
                .cloned()
                .collect();
            let path = crate::remediate::job_path(state, id);
            let written = serde_json::to_vec(&capped)
                .map_err(anyhow::Error::from)
                .and_then(|b| write_private(&path, &b));
            if let Err(e) = written {
                eprintln!("hub: could not write the remediation job: {e:#}");
                return;
            }
            match std::process::Command::new("systemd-run")
                .args(remediate_unit_args(id))
                .status()
            {
                Ok(s) if s.success() => {
                    eprintln!("hub: started remediation {id} ({} action(s))", capped.len());
                }
                Ok(s) => eprintln!(
                    "hub: could not start remediation ({s}); one may already be running (`systemctl status sn-remediate`)"
                ),
                Err(e) => eprintln!("hub: could not start remediation: {e}"),
            }
        }
        Job::Unknown => {
            eprintln!("hub: ignoring a job kind this agent does not know (upgrade the agent)");
        }
        Job::Contain { .. } => {
            eprintln!("hub: remote contain is not supported in v1 (use SSH + `sn contain`)");
        }
        Job::Fetch { .. } => {
            eprintln!("hub: remote fetch is not supported in v1");
        }
    }
}

/// The one form a hub ban or unban may take here, rebuilt from the parsed value:
/// a single address (IPv6 as its /64, like every other ban), or an IPv6 /64
/// already in that form (what reports list and the hub's unban button sends
/// back). Anything else is `None`: the text never reaches the firewall script.
/// Loopback, unspecified and multicast addresses are refused too.
fn canonical_ban_key(s: &str) -> Option<String> {
    use std::net::{IpAddr, Ipv6Addr};
    let s = s.trim();
    let ip = match s.parse::<IpAddr>() {
        Ok(ip) => net::normalize(ip),
        Err(_) => {
            let (addr, len) = s.split_once('/')?;
            let v6: Ipv6Addr = addr.parse().ok()?;
            // Exactly a /64, with no host bits set.
            if len != "64" || v6.segments()[4..].iter().any(|&x| x != 0) {
                return None;
            }
            IpAddr::V6(v6)
        }
    };
    let refused = |ip: IpAddr| ip.is_loopback() || ip.is_unspecified() || ip.is_multicast();
    let ok = match ip {
        IpAddr::V4(v4) => !refused(ip) && !v4.is_broadcast(),
        IpAddr::V6(v6) => {
            // The /64 that gets banned: `::/64` holds loopback, unspecified and
            // the IPv4-mapped range.
            let mut prefix = [0u8; 16];
            prefix[..8].copy_from_slice(&v6.octets()[..8]);
            !refused(ip) && !refused(IpAddr::V6(Ipv6Addr::from(prefix)))
        }
    };
    ok.then(|| net::ban_key(ip))
}

/// Text from the hub, safe and short enough for one log line.
fn shown(s: &str) -> String {
    let cut: String = s.chars().take(64).collect();
    format!("{cut:?}")
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

    fn finding(path: &str, score: u32, verdict: &str) -> Finding {
        Finding {
            path: path.into(),
            score,
            verdict: verdict.into(),
            rules: vec![],
            context: String::new(),
            sha256: String::new(),
        }
    }

    #[test]
    fn the_scan_result_reaches_the_report() {
        // The bug this guards: the report used to carry `findings: []` always,
        // so a scan's result never appeared on the hub.
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let findings = vec![
            finding("/home/a/uploads/x.php", 140, "malicious"),
            finding("/home/a/y.php", 80, "suspicious"),
        ];
        std::fs::write(
            state.dir.join("findings-latest.json"),
            serde_json::to_vec(&findings).unwrap(),
        )
        .unwrap();
        let summary = HuntSummary {
            at: 1_000,
            scanned: 4_200,
            duration_secs: 31,
            malicious: 1,
            suspicious: 1,
            ..HuntSummary::default()
        };
        std::fs::write(
            state.dir.join("hunt-latest.json"),
            serde_json::to_vec(&summary).unwrap(),
        )
        .unwrap();

        let (got_summary, got_findings) = latest_hunt(&state);
        assert_eq!(got_findings.len(), 2);
        assert_eq!(got_findings[0].path, "/home/a/uploads/x.php");
        let got_summary = got_summary.unwrap();
        assert_eq!((got_summary.scanned, got_summary.malicious), (4_200, 1));
    }

    #[test]
    fn no_scan_yet_means_no_summary_not_a_clean_one() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let (summary, findings) = latest_hunt(&state);
        assert!(summary.is_none());
        assert!(findings.is_empty());
        assert!(hunt_alerts(summary.as_ref()).is_empty());
    }

    #[test]
    fn reported_findings_are_capped_but_the_summary_keeps_the_total() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let many: Vec<Finding> = (0..(MAX_REPORTED_FINDINGS + 25))
            .map(|i| finding(&format!("/x/{i}.php"), 100, "malicious"))
            .collect();
        std::fs::write(
            state.dir.join("findings-latest.json"),
            serde_json::to_vec(&many).unwrap(),
        )
        .unwrap();
        let (_, got) = latest_hunt(&state);
        assert_eq!(got.len(), MAX_REPORTED_FINDINGS);
    }

    #[test]
    fn malware_alerts_follow_the_scan_counts() {
        let s = |malicious, suspicious| HuntSummary {
            malicious,
            suspicious,
            ..HuntSummary::default()
        };
        // Clean scan: no alert.
        assert!(hunt_alerts(Some(&s(0, 0))).is_empty());
        // Only suspicious: a warning, not an emergency.
        let a = hunt_alerts(Some(&s(0, 3)));
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].kind.as_str(), a[0].severity.as_str()),
            ("malware_suspect", "warn")
        );
        // Anything malicious: urgent, and it says how many.
        let a = hunt_alerts(Some(&s(2, 3)));
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].kind.as_str(), a[0].severity.as_str()),
            ("malware_found", "urgent")
        );
        assert!(a[0].message.contains("2 malicious") && a[0].message.contains("3 suspicious"));
    }

    #[test]
    fn a_hub_requested_scan_runs_in_its_own_unit() {
        let args = hunt_unit_args(7, None);
        // Not a child of the one-shot watch unit, or systemd kills it.
        assert!(args.contains(&"--unit=sn-hunt-job".to_string()));
        assert!(args.contains(&"--no-block".to_string()));
        assert!(args.contains(&"--collect".to_string()));
        // Low priority, and the command + days come last.
        assert!(args.contains(&"--property=Nice=15".to_string()));
        assert!(args.contains(&"--property=IOSchedulingClass=idle".to_string()));
        let tail: Vec<&str> = args
            .iter()
            .rev()
            .take(4)
            .map(String::as_str)
            .rev()
            .collect();
        assert_eq!(tail, ["/usr/local/bin/sn", "hunt", "--days", "7"]);
    }

    /// The `[Service]` settings of a unit, comments and blank lines left out.
    fn service_lines(unit: &str) -> Vec<String> {
        unit.lines()
            .map(str::trim)
            .skip_while(|l| *l != "[Service]")
            .skip(1)
            .take_while(|l| !l.starts_with('['))
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    /// The unit text install.sh writes to `path` (a quoted heredoc).
    fn installed_unit(path: &str) -> String {
        let script = include_str!("../../../deploy/install.sh").replace("\r\n", "\n");
        let start = format!("cat > {path} <<'EOF'\n");
        let from = script
            .find(&start)
            .unwrap_or_else(|| panic!("install.sh does not write {path}"))
            + start.len();
        let len = script[from..].find("\nEOF\n").expect("end of the heredoc");
        script[from..from + len].to_string()
    }

    const HUNT_UNIT: &str = include_str!("../../../deploy/systemd/sn-hunt.service");
    const WATCH_UNIT: &str = include_str!("../../../deploy/systemd/sn-watch.service");

    #[test]
    fn a_hub_requested_scan_is_as_sandboxed_as_the_nightly_one() {
        // The scan can run ClamAV's parsers over files users control, so none of
        // the three definitions may be less confined than the others.
        let args = hunt_unit_args(1, None);
        let nightly = service_lines(HUNT_UNIT);
        let installed = service_lines(&installed_unit("/etc/systemd/system/sn-hunt.service"));
        for (p, _) in HUNT_SANDBOX {
            assert!(
                args.contains(&format!("--property={p}")),
                "systemd-run lacks {p}"
            );
            assert!(nightly.iter().any(|l| l == p), "sn-hunt.service lacks {p}");
            assert!(
                installed.iter().any(|l| l == p),
                "install.sh's unit lacks {p}"
            );
        }
        // And the unit install.sh writes is the shipped one, setting for setting.
        let (mut a, mut b) = (nightly, installed);
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn the_scan_cannot_reach_systemd_or_the_network() {
        // uid 0 talking to systemd could start an unconfined unit; these hold on
        // every systemd the agent supports, however old.
        let args = hunt_unit_args(1, Some(232));
        for p in [
            "InaccessiblePaths=-/run/dbus/system_bus_socket",
            "InaccessiblePaths=-/run/systemd/private",
            "PrivateNetwork=yes",
            "UMask=0077",
            "RestrictNamespaces=yes",
            "ProtectKernelModules=yes",
        ] {
            assert!(args.contains(&format!("--property={p}")), "missing {p}");
        }
    }

    #[test]
    fn an_older_systemd_gets_only_the_settings_it_knows() {
        let has = |args: &[String], p: &str| args.contains(&format!("--property={p}"));
        let el8 = hunt_unit_args(1, Some(239));
        assert!(has(&el8, "SystemCallFilter=@system-service"));
        assert!(!has(&el8, "RestrictSUIDSGID=yes"));
        let old = hunt_unit_args(1, Some(237));
        assert!(!has(&old, "SystemCallFilter=@system-service"));
        assert!(!has(&old, "SystemCallErrorNumber=EPERM"));
        let new = hunt_unit_args(1, Some(255));
        assert_eq!(new, hunt_unit_args(1, None));
        assert!(has(&new, "RestrictSUIDSGID=yes"));
        // The command still comes last.
        assert_eq!(old.last().map(String::as_str), Some("1"));
    }

    #[test]
    fn the_systemd_version_is_read_from_its_first_line() {
        let v = parse_systemd_version("systemd 255 (255.4-1ubuntu8.4)\n+PAM +AUDIT -SELINUX\n");
        assert_eq!(v, Some(255));
        assert_eq!(parse_systemd_version("systemd 239 (239-78.el8)"), Some(239));
        assert_eq!(parse_systemd_version("systemd 252"), Some(252));
        assert_eq!(parse_systemd_version(""), None);
        assert_eq!(parse_systemd_version("not systemd 1"), None);
    }

    #[test]
    fn the_watch_unit_and_the_jobs_it_starts_keep_new_files_private() {
        assert!(service_lines(WATCH_UNIT).iter().any(|l| l == "UMask=0077"));
        let installed = service_lines(&installed_unit("/etc/systemd/system/sn-watch.service"));
        assert!(installed.iter().any(|l| l == "UMask=0077"));
        let umask = "--property=UMask=0077".to_string();
        assert!(evidence_unit_args().contains(&umask));
        assert!(remediate_unit_args("j1").contains(&umask));
        // Deliberately not the package install: see install_clamav_unit_args.
        assert!(!install_clamav_unit_args().contains(&umask));
    }

    #[test]
    fn a_hub_ban_key_is_one_address_rebuilt_from_its_parsed_value() {
        for (input, key) in [
            ("203.0.113.7", "203.0.113.7"),
            (" 203.0.113.7 ", "203.0.113.7"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
            ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
            // What reports list and the hub's unban button sends back.
            ("2001:db8:1:2::/64", "2001:db8:1:2::/64"),
            ("2001:DB8:1:2:0:0:0:0/64", "2001:db8:1:2::/64"),
        ] {
            assert_eq!(canonical_ban_key(input).as_deref(), Some(key), "{input}");
        }
    }

    #[test]
    fn anything_but_one_address_never_reaches_the_firewall() {
        for input in [
            "",
            "web-01",
            // Text that would add its own statements to the nft script.
            "1.2.3.4 } ; flush ruleset",
            "1.2.3.4 }\nadd rule inet sn input accept\n",
            "2001:db8::/64 }\ndelete table inet sn",
            // Ranges wider than one host, or written another way.
            "203.0.113.0/24",
            "1.2.3.4/32",
            "0.0.0.0/0",
            "::/0",
            "2001:db8::/48",
            "2001:db8:1:2::1/64",
            "2001:db8:1:2::/064",
            "::ffff:1.2.3.4/64",
            // Never a client.
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "::2",
            "::/64",
            "ff02::1",
            "ff02::/64",
        ] {
            assert_eq!(canonical_ban_key(input), None, "{input:?}");
        }
    }

    #[test]
    fn a_hub_ban_never_lasts_longer_than_a_day() {
        let now = 1_700_000_000;
        let day = MAX_HUB_BAN_SECS;
        // Entries from before `created_at`: the TTL, capped.
        assert_eq!(hub_ban_ttl(3600, 0, now), Some(3600));
        assert_eq!(hub_ban_ttl(10 * day, 0, now), Some(day));
        // Only what is left of the ban.
        assert_eq!(hub_ban_ttl(3600, now - 100, now), Some(3500));
        assert_eq!(hub_ban_ttl(3600, now - 7200, now), None);
        // A creation time in the future cannot stretch it.
        assert_eq!(hub_ban_ttl(day, now + 10 * 365 * 86_400, now), Some(day));
        assert_eq!(hub_ban_ttl(u64::MAX, i64::MAX, now), Some(day));
        // 0 would be a ban that never expires.
        assert_eq!(hub_ban_ttl(0, 0, now), None);
        assert_eq!(hub_ban_ttl(0, now, now), None);
    }

    #[test]
    fn hub_jobs_are_claimed_once_before_they_run() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        assert!(!claim_jobs(&state, 0).unwrap());
        assert!(claim_jobs(&state, 5).unwrap());
        // Recorded already, before any job ran.
        assert_eq!(state.meta().last_jobs_seq, 5);
        // The same order seen again (a second process, a retried fetch): no rerun.
        assert!(!claim_jobs(&state, 5).unwrap());
        assert!(!claim_jobs(&state, 4).unwrap());
        assert!(claim_jobs(&state, 6).unwrap());
    }

    #[test]
    fn the_desired_pull_is_signed_with_the_agent_key() {
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let have = DesiredRef { epoch: 1, seq: 9 };
        let now = 1_700_000_000;
        let h = pull_headers(&sk, "web-01-a1b2c3", have, now);
        let get = |name: &str| h.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone());
        let ts: i64 = get(HDR_PULL_TS).unwrap().parse().unwrap();
        let sig = get(HDR_PULL_SIG).unwrap();
        // Exactly what the hub checks.
        let vk = sk.verifying_key();
        assert!(crypto::verify_desired_pull(&vk, "web-01-a1b2c3", 1, 9, ts, &sig, now).is_ok());
        assert!(crypto::verify_desired_pull(&vk, "web-01-a1b2c3", 1, 8, ts, &sig, now).is_err());
    }

    #[test]
    fn every_agent_says_it_signs_its_pulls() {
        // A protocol feature, not an order: listed whatever `hub_orders` says.
        let mut cfg = default_config();
        for orders in [true, false] {
            cfg.remote.hub_orders = orders;
            assert!(capabilities(&cfg).iter().any(|c| c == CAP_SIGNED_DESIRED));
        }
    }

    #[test]
    fn the_clamav_install_unit_is_bounded_and_runs_one_at_a_time() {
        let args = install_clamav_unit_args();
        assert!(args.contains(&"--unit=sn-install-clamav".to_string()));
        assert!(args.contains(&"--property=RuntimeMaxSec=90min".to_string()));
        assert_eq!(args.last().map(String::as_str), Some("install-clamav"));
    }
}
