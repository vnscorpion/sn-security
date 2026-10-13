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
    // Signs its desired-state pulls (the hub goes by the first signed pull it
    // gets, after which it answers no unsigned one for this agent id).
    caps.push(CAP_SIGNED_DESIRED.into());
    // Listed only when this VPS allows them, so the hub offers the AI features
    // exactly where they will work. An agent that predates them lists neither.
    if cfg.remote.hub_orders {
        caps.push("evidence".into());
        caps.push("remediate".into());
        // Lifts every ban on the hub's `unban_all_seq`.
        caps.push("unban_all".into());
        // Puts the hub's ModSecurity rules into the web server (`DesiredBody::waf`).
        caps.push("waf".into());
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

    if let Err(e) = prepare_scan(cfg, state) {
        eprintln!("hunt: could not prepare the scan's sandbox: {e:#}");
    }

    // Take the hub's orders *before* building the report, so a ban the admin
    // just ordered is already in force (and visible in `active_bans`) in this
    // very report instead of one cycle later.
    if hub_configured {
        match fetch_and_apply_desired(cfg, state) {
            Ok(refused) => alerts.extend(refused_alert(&refused)),
            Err(e) => eprintln!("hub: desired fetch/apply failed: {e:#}"),
        }
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
    let (hunt, findings) = latest_hunt(cfg, state);
    alerts.extend(hunt_alerts(hunt.as_ref()));

    let triage: Option<TriageSummary> = std::fs::read(state.dir.join("triage-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());

    // The hub's WAF rules in place (a transient unit does the writing), then
    // their state and matches for this report.
    if cfg.remote.hub_orders {
        crate::waf::ensure(state);
    }
    let waf = Some(crate::waf::status(state));

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
        waf,
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

/// Hub bans this VPS refused because the address must never be banned here.
fn refused_alert(refused: &[String]) -> Option<snsec_common::schema::Alert> {
    if refused.is_empty() {
        return None;
    }
    let shown: Vec<&str> = refused.iter().take(10).map(String::as_str).collect();
    Some(snsec_common::schema::Alert {
        kind: "hub_ban_refused".into(),
        message: format!(
            "{} ban order(s) from the hub not applied: the address is protected on this VPS (whitelist, admin session, the VPS's own address, a trusted proxy or Cloudflare): {}{}",
            refused.len(),
            shown.join(", "),
            if refused.len() > shown.len() {
                ", ..."
            } else {
                ""
            }
        ),
        severity: "warn".into(),
    })
}

/// At most this many findings travel in one report (the summary has the totals).
const MAX_REPORTED_FINDINGS: usize = 100;

/// The most recent `sn hunt` result, as left in the state directory (after
/// taking in a newer one from the sandboxed scan).
fn latest_hunt(cfg: &Config, state: &State) -> (Option<HuntSummary>, Vec<Finding>) {
    match import_scan(cfg, state, util::now_secs()) {
        Ok(Imported::Refused(why)) => eprintln!("hunt: scan result not taken in: {why}"),
        Ok(_) => {}
        Err(e) => eprintln!("hunt: could not take in the scan result: {e:#}"),
    }
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

/// The `[hunt]` settings the sandboxed scan reads as its agent.toml, kept in the
/// state directory (see [`HUNT_SANDBOX`]).
const SCAN_CONFIG: &str = "hunt.toml";

/// What the sandboxed scan needs before it starts: its own directory, and its
/// settings without the rest of agent.toml, whose `[hub]` table holds the agent's
/// key. Written again only when they changed.
fn prepare_scan(cfg: &Config, state: &State) -> Result<()> {
    #[derive(serde::Serialize)]
    struct ScanConfig<'a> {
        hunt: &'a crate::config::HuntCfg,
    }
    state.scan_dir()?;
    let text = toml::to_string(&ScanConfig { hunt: &cfg.hunt }).context("writing [hunt] out")?;
    if std::fs::read(state.dir.join(SCAN_CONFIG)).ok().as_deref() != Some(text.as_bytes()) {
        state.save_file(SCAN_CONFIG, text.as_bytes())?;
    }
    Ok(())
}

/// Largest findings file taken in from the scan's directory.
const MAX_SCAN_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Most findings taken in from one scan.
const MAX_SCAN_FINDINGS: usize = 20_000;
/// How far ahead of this clock a scan may say it finished (it runs on the same
/// clock): a later time would hold back every scan after it.
const SCAN_CLOCK_SLACK_SECS: i64 = 300;
/// Verdicts a scan gives (`sn hunt` leaves clean files out).
const SCAN_VERDICTS: &[&str] = &["malicious", "suspicious", "encoded-commercial"];

#[derive(Debug, PartialEq, Eq)]
enum Imported {
    /// Nothing newer than the result in force.
    Nothing,
    /// Taken in, with this many findings kept.
    Taken(usize),
    /// A newer result that cannot be used, and why.
    Refused(&'static str),
}

/// Take in the result the sandboxed scan left in its directory, if it is newer
/// than the one in force.
///
/// That scan runs ClamAV's parsers over files users control, so what it wrote
/// may be an attacker's, and root acts on it: `sn clean` quarantines what the
/// findings list. So the files are read without following a link or waiting on
/// a FIFO, parsed into their types, and only findings on a plain path inside the
/// scanned roots are kept, the summary's counts redone from them. This process
/// then writes them into the state directory, where the scan cannot.
fn import_scan(cfg: &Config, state: &State, now: i64) -> Result<Imported> {
    let dir = state.dir.join(crate::state::SCAN_DIR);
    let Some(bytes) = read_scan_file(&dir.join("hunt-latest.json"), 64 * 1024) else {
        return Ok(Imported::Nothing);
    };
    let Ok(mut summary) = serde_json::from_slice::<HuntSummary>(&bytes) else {
        return Ok(Imported::Refused("summary unreadable"));
    };
    let current = std::fs::read(state.dir.join("hunt-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<HuntSummary>(&b).ok());
    // Not newer: already taken in (and maybe trimmed by `sn clean` since), or
    // older than a scan run by hand.
    if current.is_some_and(|c| summary.at <= c.at) {
        return Ok(Imported::Nothing);
    }
    if summary.at > now.saturating_add(SCAN_CLOCK_SLACK_SECS) {
        return Ok(Imported::Refused("finish time in the future"));
    }
    let Some(found) = read_scan_file(&dir.join("findings-latest.json"), MAX_SCAN_FILE_BYTES)
        .and_then(|b| serde_json::from_slice::<Vec<Finding>>(&b).ok())
    else {
        // Maybe still being written: the next cycle looks again.
        return Ok(Imported::Refused("findings not readable (yet)"));
    };
    let findings = checked_findings(found, &cfg.hunt.allowed_roots);
    let count = |verdict: &str| {
        u32::try_from(findings.iter().filter(|f| f.verdict == verdict).count()).unwrap_or(u32::MAX)
    };
    summary.malicious = count("malicious");
    summary.suspicious = count("suspicious");
    if !matches!(
        summary.clamav_engine.as_str(),
        "" | "clamscan" | "clamdscan"
    ) {
        summary.clamav_engine.clear();
    }
    summary.clamav_note = cut_text(&summary.clamav_note, 300);
    // Findings first: the summary is what marks a scan as finished.
    state.save_file(
        "findings-latest.json",
        &serde_json::to_vec_pretty(&findings)?,
    )?;
    state.save_file("hunt-latest.json", &serde_json::to_vec_pretty(&summary)?)?;
    Ok(Imported::Taken(findings.len()))
}

/// The findings worth keeping from a scan's own file: a known verdict on a plain
/// absolute path strictly inside one of the scanned roots, text cut to size,
/// best first.
fn checked_findings(found: Vec<Finding>, roots: &[String]) -> Vec<Finding> {
    let roots: Vec<&std::path::Path> = roots
        .iter()
        .map(std::path::Path::new)
        .filter(|r| r.is_absolute())
        .collect();
    let mut kept: Vec<Finding> = found
        .into_iter()
        .filter(|f| {
            SCAN_VERDICTS.contains(&f.verdict.as_str()) && plain_path_under(&f.path, &roots)
        })
        .map(|f| {
            let sha_ok = f.sha256.len() == 64 && f.sha256.bytes().all(|b| b.is_ascii_hexdigit());
            Finding {
                rules: f.rules.iter().take(64).map(|r| cut_text(r, 200)).collect(),
                context: cut_text(&f.context, 512),
                sha256: if sha_ok { f.sha256 } else { String::new() },
                ..f
            }
        })
        .collect();
    kept.sort_by_key(|f| std::cmp::Reverse(f.score));
    kept.truncate(MAX_SCAN_FINDINGS);
    kept
}

/// `p` is an absolute path of plain names only (no `..`), strictly inside one
/// of `roots`.
fn plain_path_under(p: &str, roots: &[&std::path::Path]) -> bool {
    use std::path::{Component, Path};
    let path = Path::new(p);
    p.len() <= 4096
        && !p.contains('\0')
        && path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && roots.iter().any(|r| path.starts_with(r) && path != *r)
}

/// At most `max` characters of `s`, control characters made spaces.
fn cut_text(s: &str, max: usize) -> String {
    crate::clamav::clean_text(&s.chars().take(max).collect::<String>())
}

/// A file the sandboxed scan wrote: read only if it is a regular file (never
/// through a link, never waiting on a FIFO) of at most `cap` bytes.
fn read_scan_file(path: &std::path::Path, cap: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > cap {
        return None;
    }
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// The malware scan's sandbox, as unit-file lines, each with the oldest systemd
/// that knows it.
///
/// The scan reads files users control and may run ClamAV's parsers over them as
/// root. So it may write only a directory of its own, never the files root acts
/// on (undo records, orders, evidence): the next watch cycle checks what it left
/// before anything uses it (see [`import_scan`]). It gets no network, no devices,
/// no kernel knobs, and no socket where uid 0 can have code run for it:
/// systemd's (which is how sn-watch itself starts `sn remediate`), root's own
/// user manager, snapd, container and VM daemons. Where systemd can, /run is an
/// empty read-only directory with only clamd's socket directories in it (a
/// private network leaves unix sockets alone), and /etc/sn holds only the
/// `[hunt]` settings a watch cycle copies out: agent.toml has the agent's key.
///
/// The nightly unit (deploy/systemd/sn-hunt.service) and the copy install.sh
/// writes carry the same lines; a test keeps the three in step. A unit file only
/// warns about a setting its systemd does not know, but `systemd-run` refuses the
/// whole command, so the hub-started scan leaves out what the host is too old for.
const HUNT_SANDBOX: &[(&str, u32)] = &[
    ("NoNewPrivileges=yes", 0),
    ("ProtectSystem=strict", 0),
    ("Environment=SN_STATE_DIR=/var/lib/sn/hunt", 0),
    ("ReadWritePaths=/var/lib/sn/hunt", 0),
    ("PrivateTmp=yes", 0),
    ("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", 0),
    ("UMask=0077", 0),
    ("InaccessiblePaths=-/run/dbus/system_bus_socket", 0),
    ("InaccessiblePaths=-/run/systemd/private", 0),
    ("InaccessiblePaths=-/run/user", 0),
    ("InaccessiblePaths=-/run/snapd.socket", 0),
    ("InaccessiblePaths=-/run/docker.sock", 0),
    ("InaccessiblePaths=-/run/containerd", 0),
    ("InaccessiblePaths=-/run/podman", 0),
    ("InaccessiblePaths=-/run/libvirt", 0),
    ("TemporaryFileSystem=/run:ro", 238),
    ("BindReadOnlyPaths=-/run/clamav", 238),
    ("BindReadOnlyPaths=-/run/clamd.scan", 238),
    ("TemporaryFileSystem=/etc/sn:ro", 238),
    (
        "BindReadOnlyPaths=-/var/lib/sn/hunt.toml:/etc/sn/agent.toml",
        238,
    ),
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
        // A queued report that cannot be read back would block every later one.
        let body: ReportBody = match std::fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|b| serde_json::from_slice(&b).map_err(anyhow::Error::from))
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("hub: dropping unreadable queued report seq {seq}: {e}");
                state.drop_queued(&path);
                continue;
            }
        };
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
            // Refused for good (malformed, or larger than the hub accepts): sending
            // it again would only block every later report behind it.
            Err(ureq::Error::Status(code @ (400 | 413 | 422), _)) => {
                eprintln!("hub: dropping queued report seq {seq}: the hub refused it ({code})");
                state.drop_queued(&path);
            }
            // Too soon after the last one: the next cycle sends it.
            Err(ureq::Error::Status(429, _)) => return Ok(()),
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
/// Returns the hub bans refused as protected.
fn fetch_and_apply_desired(cfg: &Config, state: &State) -> Result<Vec<String>> {
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

fn fetch_and_apply_desired_unlocked(cfg: &Config, state: &State) -> Result<Vec<String>> {
    let keys = hub_keys(cfg);
    if keys.is_empty() {
        return Ok(Vec::new()); // no hub keys configured; cannot trust desired
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
    let ts = pull_ts(meta.last_pull_ts, util::now_secs());
    let mut req = agent.get(&url);
    for (name, value) in pull_headers(&sk, &cfg.hub.agent_id, meta.last_desired, ts) {
        req = req.set(name, &value);
    }
    let resp = req.call();
    if matches!(&resp, Ok(_) | Err(ureq::Error::Status(304, _))) {
        // Answered, so the hub has this time now: the next pull must be later.
        state.update_meta(|m| m.last_pull_ts = m.last_pull_ts.max(ts))?;
    }
    let text = match resp {
        Ok(r) => r.into_string().context("reading desired body")?,
        Err(ureq::Error::Status(304, _)) => return Ok(Vec::new()), // not modified
        Err(ureq::Error::Status(404, _)) => anyhow::bail!(
            "GET desired: the hub does not accept this agent's signed request (is the VPS clock right? was this VPS removed from the hub?)"
        ),
        Err(e) => anyhow::bail!("GET desired: {e}"),
    };
    if text.trim().is_empty() {
        return Ok(Vec::new());
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
        return Ok(Vec::new());
    }

    let refused = apply_desired(cfg, state, &env.body)?;

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
    Ok(refused)
}

/// The time to sign a pull at: now, but always after the last pull the hub
/// answered, which it requires (a copy of an earlier request then reads
/// nothing). Two pulls in one second, or a clock that stepped back, still get
/// a later time.
fn pull_ts(last: i64, now: i64) -> i64 {
    now.max(last.saturating_add(1))
}

/// Headers that prove the desired-state pull comes from this agent: a signature
/// by its own key over the agent id, the version it has and the time. Once an
/// agent has made one signed pull, the hub answers no unsigned one for it.
fn pull_headers(
    sk: &SigningKey,
    agent_id: &str,
    have: DesiredRef,
    now: i64,
) -> [(&'static str, String); 2] {
    let sig = crypto::sign_desired_pull(sk, agent_id, have.epoch, have.seq, now);
    [(HDR_PULL_TS, now.to_string()), (HDR_PULL_SIG, sig)]
}

/// The VPS's own addresses as the hub reports them, checked: single addresses
/// only (no loopback, unspecified or multicast), at most `MAX_SELF_IPS`.
fn checked_self_ips(list: &[String]) -> Vec<String> {
    use snsec_common::schema::MAX_SELF_IPS;
    let mut out: Vec<String> = Vec::new();
    for s in list {
        let Ok(ip) = s.trim().parse::<std::net::IpAddr>() else {
            continue;
        };
        let ip = net::normalize(ip);
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        let ip = ip.to_string();
        if !out.contains(&ip) && out.len() < MAX_SELF_IPS {
            out.push(ip);
        }
    }
    out
}

/// May a hub ban of `key` go ahead here? Not for an address this VPS protects
/// (whitelist, admin sessions, its own addresses, trusted proxies,
/// Cloudflare), nor for one no hub should ever ban (private, carrier-grade NAT,
/// unique-local, link-local: an older hub did not refuse those).
fn hub_ban_allowed(key: &str, wl: &crate::whitelist::Whitelist, never_ban: &[net::Cidr]) -> bool {
    let reserved = net::Cidr::parse(key)
        .and_then(|c| snsec_common::ranges::never_ban_reason(c.addr))
        .is_some();
    !reserved && !crate::whitelist::key_protected(key, wl, never_ban)
}

/// Apply a desired state from the hub. Returns the bans it ordered that were
/// refused because the address is protected here.
fn apply_desired(cfg: &Config, state: &State, d: &DesiredBody) -> Result<Vec<String>> {
    // The one local switch: a VPS with `[remote] hub_orders = false` only reports.
    // Otherwise the hub decides (bans, mode, scans, undo, evidence, ClamAV, orders).
    if !cfg.remote.hub_orders {
        eprintln!("hub: orders ignored on this VPS ([remote] hub_orders = false)");
        return Ok(Vec::new());
    }
    // Hard local bounds (SEC-2): the hub can never exceed these.
    let _timer = d.timer_interval_secs.clamp(300, 900);

    // This VPS's own public address as the hub saw its reports arrive: on a
    // cloud that NATs it, its own cron, loopback and cache-preload requests
    // come from there, and must never get it banned.
    let self_ips = checked_self_ips(&d.self_ips);
    state.update_meta(|m| {
        if m.self_ips != self_ips {
            m.self_ips = self_ips;
        }
    })?;

    // "Lift every ban" from the admin (too many wrong bans): before the operator
    // bans below, so a ban ordered after it still applies. Once per marker.
    if d.unban_all_seq > 0 {
        let take = state.update_meta(|m| {
            let new = d.unban_all_seq > m.last_unban_all_seq;
            if new {
                m.last_unban_all_seq = d.unban_all_seq;
            }
            new
        });
        if matches!(take, Ok(true)) {
            match crate::sys::fw::flush_bans() {
                Ok(()) => eprintln!("hub: every ban lifted on the admin's order"),
                Err(e) => eprintln!("hub: could not lift the bans ({e:#})"),
            }
            let _ = state.save_bans(&Default::default());
            // Forget the offence counts too, or the next offence of an address
            // that was banned wrongly would start at a longer ban.
            let _ = state.save_strikes(&Default::default());
        }
    }

    // ModSecurity rules: kept here, put in place by `waf::ensure` each cycle.
    if let Some(rules) = &d.waf {
        crate::waf::set_rules(state, rules);
    }

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

    // The hub's bans pass the same protections as the agent's own: a ban from
    // the UI, MCP or an AI must not lock out an admin, this VPS's own address or
    // a Cloudflare edge (every visitor behind it would get errors).
    let mut refused = Vec::new();
    let firewall = (!adds.is_empty() || !dels.is_empty()) && crate::sys::fw::available();
    if !adds.is_empty() || firewall {
        let wl = crate::whitelist::build(cfg, &crate::sys::netstat::all(), Some(state));
        let never_ban = cfg.never_ban_cidrs();
        adds.retain(|(key, _)| {
            let ok = hub_ban_allowed(key, &wl, &never_ban);
            if !ok {
                eprintln!("hub: not banning {key}: the address is protected on this VPS");
                refused.push(key.clone());
            }
            ok
        });
        if firewall && (!adds.is_empty() || !dels.is_empty()) {
            // A firewall problem must not stop the rest of the order. This used
            // to return the error, so the desired-state was never marked
            // applied, the same order was retried and failed every cycle, and a
            // job in it (install ClamAV, a scan, an incident order) never ran.
            let mut white = wl.keys();
            white.extend(crate::whitelist::cidr_keys(&never_ban));
            let applied = crate::sys::fw::prepare(&cfg.fw.web_ports, &white)
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
    }
    // An address the admin unbanned also loses its offence count: banned
    // wrongly, its next busy cycle must not start a step up the ladder.
    if !dels.is_empty() {
        let mut strikes = state.strikes();
        let before = strikes.len();
        for key in &dels {
            strikes.remove(key);
        }
        if strikes.len() != before {
            let _ = state.save_strikes(&strikes);
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
        if d.mode == snsec_common::schema::Mode::Enforce {
            // Start enforcing with a clean slate: offences counted before (an
            // older agent counted them in observe mode too) must not make the
            // first real bans week-long.
            let _ = state.save_strikes(&Default::default());
        }
    }

    // One-shot jobs: run only when jobs_seq advanced beyond what we last ran.
    if claim_jobs(state, d.jobs_seq)? {
        for job in &d.jobs {
            run_job(cfg, state, job);
        }
    }
    Ok(refused)
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
            // Its directory and settings, in case no watch cycle made them yet.
            if let Err(e) = prepare_scan(cfg, state) {
                eprintln!("hub: could not prepare the scan's sandbox: {e:#}");
                return;
            }
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
    fn an_unban_all_order_lifts_every_ban_once_and_forgets_the_counts() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let now = util::now_secs();
        let fill = || {
            let mut bans = HashMap::new();
            bans.insert("45.133.1.10".to_string(), ban(now + 3600));
            state.save_bans(&bans).unwrap();
            let mut strikes = HashMap::new();
            strikes.insert(
                "45.133.1.10".to_string(),
                crate::state::Strike {
                    count: 3,
                    last_ts: now,
                    rate_only: false,
                },
            );
            state.save_strikes(&strikes).unwrap();
        };
        fill();
        let cfg = default_config();
        let d = DesiredBody {
            unban_all_seq: 7,
            ..DesiredBody::default()
        };
        apply_desired(&cfg, &state, &d).unwrap();
        assert!(state.bans().is_empty());
        assert!(state.strikes().is_empty());
        assert_eq!(state.meta().last_unban_all_seq, 7);
        // The same marker again (a later, unrelated desired change) does nothing.
        fill();
        apply_desired(&cfg, &state, &d).unwrap();
        assert_eq!(state.bans().len(), 1);
        // A newer one acts again.
        let d2 = DesiredBody {
            unban_all_seq: 8,
            ..DesiredBody::default()
        };
        apply_desired(&cfg, &state, &d2).unwrap();
        assert!(state.bans().is_empty());
    }

    fn strikes_of(keys: &[&str]) -> HashMap<String, crate::state::Strike> {
        keys.iter()
            .map(|k| {
                (
                    (*k).to_string(),
                    crate::state::Strike {
                        count: 4,
                        last_ts: util::now_secs(),
                        rate_only: false,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn an_unban_from_the_hub_forgets_that_addresses_offences() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        state
            .save_strikes(&strikes_of(&[
                "203.0.113.7",
                "2001:db8:1:2::/64",
                "45.133.1.10",
            ]))
            .unwrap();
        let d = DesiredBody {
            unbans: vec!["203.0.113.7".into(), "2001:db8:1:2::9".into()],
            ..DesiredBody::default()
        };
        apply_desired(&default_config(), &state, &d).unwrap();
        let left: Vec<String> = state.strikes().into_keys().collect();
        assert_eq!(left, ["45.133.1.10"]);
    }

    #[test]
    fn switching_to_enforce_starts_from_a_clean_slate() {
        use snsec_common::schema::Mode;
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let cfg = default_config();
        state.save_strikes(&strikes_of(&["203.0.113.7"])).unwrap();
        // To observe (the default already): nothing forgotten.
        apply_desired(&cfg, &state, &DesiredBody::default()).unwrap();
        assert_eq!(state.strikes().len(), 1);
        let enforce = DesiredBody {
            mode: Mode::Enforce,
            ..DesiredBody::default()
        };
        apply_desired(&cfg, &state, &enforce).unwrap();
        assert!(state.strikes().is_empty());
        assert_eq!(state.meta().mode_override, Some(Mode::Enforce));
        // Already enforcing: a later desired state keeps what was counted since.
        state.save_strikes(&strikes_of(&["203.0.113.8"])).unwrap();
        apply_desired(&cfg, &state, &enforce).unwrap();
        assert_eq!(state.strikes().len(), 1);
    }

    #[test]
    fn the_vps_keeps_the_address_the_hub_saw_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let d = DesiredBody {
            self_ips: vec![
                "198.51.100.20".into(),
                " ::ffff:198.51.100.21 ".into(),
                "127.0.0.1".into(),
                "not an address".into(),
                "198.51.100.20".into(),
                "2001:db8::5".into(),
                "198.51.100.22".into(),
                "198.51.100.23".into(),
            ],
            ..DesiredBody::default()
        };
        apply_desired(&default_config(), &state, &d).unwrap();
        assert_eq!(
            state.meta().self_ips,
            [
                "198.51.100.20",
                "198.51.100.21",
                "2001:db8::5",
                "198.51.100.22"
            ]
        );
        // A VPS that only reports ignores the hub entirely.
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let mut cfg = default_config();
        cfg.remote.hub_orders = false;
        apply_desired(&cfg, &state, &d).unwrap();
        assert!(state.meta().self_ips.is_empty());
    }

    #[test]
    fn a_hub_ban_of_a_protected_address_is_refused() {
        use crate::whitelist::Whitelist;
        let cidr = |s| net::Cidr::parse(s).unwrap();
        // The admin's SSH session, inside the /64 the hub wants banned.
        let wl = Whitelist::of(vec![cidr("2402:800:6310:12a::5"), cidr("203.0.113.7")]);
        let never_ban = vec![cidr("104.16.0.0/13")];
        for key in [
            "2402:800:6310:12a::/64",
            "203.0.113.7",
            // A Cloudflare edge.
            "104.16.1.1",
            // Never a client on the Internet, whatever an older hub accepted.
            "10.0.0.5",
            "100.64.1.1",
            "fd00:1::/64",
        ] {
            assert!(!hub_ban_allowed(key, &wl, &never_ban), "{key}");
        }
        for key in ["45.133.1.10", "2402:800:6310:12b::/64"] {
            assert!(hub_ban_allowed(key, &wl, &never_ban), "{key}");
        }
        let a = refused_alert(&["104.16.1.1".into()]).unwrap();
        assert_eq!(
            (a.kind.as_str(), a.severity.as_str()),
            ("hub_ban_refused", "warn")
        );
        assert!(a.message.contains("104.16.1.1"));
        assert!(refused_alert(&[]).is_none());
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

        let (got_summary, got_findings) = latest_hunt(&default_config(), &state);
        assert_eq!(got_findings.len(), 2);
        assert_eq!(got_findings[0].path, "/home/a/uploads/x.php");
        let got_summary = got_summary.unwrap();
        assert_eq!((got_summary.scanned, got_summary.malicious), (4_200, 1));
    }

    #[test]
    fn no_scan_yet_means_no_summary_not_a_clean_one() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let (summary, findings) = latest_hunt(&default_config(), &state);
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
        let (_, got) = latest_hunt(&default_config(), &state);
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
        // uid 0 talking to systemd (or root's user manager, snapd, a container
        // daemon) could start an unconfined process; these hold on every systemd
        // the agent supports, however old.
        let args = hunt_unit_args(1, Some(232));
        for p in [
            "InaccessiblePaths=-/run/dbus/system_bus_socket",
            "InaccessiblePaths=-/run/systemd/private",
            "InaccessiblePaths=-/run/user",
            "InaccessiblePaths=-/run/snapd.socket",
            "InaccessiblePaths=-/run/docker.sock",
            "InaccessiblePaths=-/run/containerd",
            "InaccessiblePaths=-/run/podman",
            "PrivateNetwork=yes",
            "UMask=0077",
            "RestrictNamespaces=yes",
            "ProtectKernelModules=yes",
            "Environment=SN_STATE_DIR=/var/lib/sn/hunt",
            "ReadWritePaths=/var/lib/sn/hunt",
        ] {
            assert!(args.contains(&format!("--property={p}")), "missing {p}");
        }
    }

    #[test]
    fn the_scan_writes_only_its_own_directory_and_never_sees_the_agent_key() {
        let args = hunt_unit_args(1, None);
        let has = |p: &str| args.contains(&format!("--property={p}"));
        let scan_dir = format!("/var/lib/sn/{}", crate::state::SCAN_DIR);
        assert!(has(&format!("Environment=SN_STATE_DIR={scan_dir}")));
        assert!(has(&format!("ReadWritePaths={scan_dir}")));
        // Nothing else: undo records, orders and evidence stay out of its reach.
        let writable = args
            .iter()
            .filter(|a| a.starts_with("--property=ReadWritePaths="))
            .count();
        assert_eq!(writable, 1);
        // /etc/sn is only the [hunt] settings a watch cycle copies out.
        assert!(has("TemporaryFileSystem=/etc/sn:ro"));
        assert!(has(&format!(
            "BindReadOnlyPaths=-/var/lib/sn/{SCAN_CONFIG}:/etc/sn/agent.toml"
        )));
        // /run is empty but for clamd's socket directories.
        assert!(has("TemporaryFileSystem=/run:ro"));
        assert!(has("BindReadOnlyPaths=-/run/clamav"));
        // The nightly unit the same way (the sync test covers the rest of it).
        let nightly = service_lines(HUNT_UNIT);
        assert!(!nightly.iter().any(|l| l == "ReadWritePaths=/var/lib/sn"));
        assert!(
            nightly
                .iter()
                .any(|l| *l == format!("ReadWritePaths={scan_dir}"))
        );
    }

    #[test]
    fn an_upgrade_rewrites_the_units_a_fresh_install_writes() {
        // `install.sh --upgrade` is how enrolled VPSes get a new agent: a sandbox
        // that only a fresh install wrote would never reach them.
        let script = include_str!("../../../deploy/install.sh").replace("\r\n", "\n");
        let def = script
            .find("\nwrite_service_units() {\n")
            .expect("install.sh defines write_service_units");
        let body = &script[def..def + script[def..].find("\n}\n").expect("its end")];
        for unit in ["sn-watch.service", "sn-hunt.service"] {
            assert!(
                body.contains(&format!("cat > /etc/systemd/system/{unit} <<'EOF'\n")),
                "{unit} is not written by the function"
            );
        }
        let upgrade = script
            .find("if [ \"$UPGRADE\" -eq 1 ]; then\n")
            .expect("the upgrade branch");
        let end = upgrade + script[upgrade..].find("exit 0").expect("its end");
        let branch = &script[upgrade..end];
        assert!(def < upgrade, "defined before the upgrade branch runs");
        let calls = |text: &str| text.lines().any(|l| l.trim() == "write_service_units");
        assert!(calls(branch));
        assert!(branch.contains("systemctl daemon-reload"));
        // And by a fresh install.
        assert!(calls(&script[end..]));
    }

    #[test]
    fn an_older_systemd_gets_only_the_settings_it_knows() {
        let has = |args: &[String], p: &str| args.contains(&format!("--property={p}"));
        let el8 = hunt_unit_args(1, Some(239));
        assert!(has(&el8, "SystemCallFilter=@system-service"));
        assert!(has(&el8, "TemporaryFileSystem=/run:ro"));
        assert!(!has(&el8, "RestrictSUIDSGID=yes"));
        let old = hunt_unit_args(1, Some(237));
        assert!(!has(&old, "SystemCallFilter=@system-service"));
        assert!(!has(&old, "SystemCallErrorNumber=EPERM"));
        assert!(!has(&old, "TemporaryFileSystem=/run:ro"));
        assert!(!has(&old, "BindReadOnlyPaths=-/run/clamav"));
        // What it has instead: the known sockets one by one.
        assert!(has(&old, "InaccessiblePaths=-/run/user"));
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
    fn each_pull_is_signed_later_than_the_last_one_answered() {
        let now = 1_700_000_000;
        assert_eq!(pull_ts(0, now), now);
        assert_eq!(pull_ts(now - 300, now), now);
        // Two in one second (watch and an incident follow-up), or a clock that
        // went back an hour: still later than what the hub has.
        assert_eq!(pull_ts(now, now), now + 1);
        assert_eq!(pull_ts(now + 3600, now), now + 3601);
        assert_eq!(pull_ts(i64::MAX, now), i64::MAX);
    }

    #[test]
    fn the_scan_gets_its_settings_but_never_the_agent_key() {
        use rand::rngs::OsRng;
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let mut cfg = default_config();
        let secret = crypto::encode_secret(&SigningKey::generate(&mut OsRng));
        cfg.hub.agent_key = secret.clone();
        cfg.hub.agent_id = "web-01-a1b2c3".into();
        cfg.hunt.allowed_roots = vec!["/home".into(), "/www/wwwroot".into()];
        cfg.hunt.days = 3;
        prepare_scan(&cfg, &state).unwrap();

        let path = dir.path().join(SCAN_CONFIG);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&secret) && !text.contains("agent_key") && !text.contains("[hub]"));
        // What the scan loads as its agent.toml.
        let seen = Config::load(&path).unwrap();
        assert_eq!(seen.hunt.allowed_roots, cfg.hunt.allowed_roots);
        assert_eq!(seen.hunt.days, 3);
        assert!(seen.hub.agent_key.is_empty() && seen.hub.agent_id.is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let scan_dir = dir.path().join(crate::state::SCAN_DIR);
        assert_eq!(std::fs::metadata(&scan_dir).unwrap().mode() & 0o7777, 0o700);
        // A changed setting reaches the next scan.
        cfg.hunt.days = 5;
        prepare_scan(&cfg, &state).unwrap();
        assert_eq!(Config::load(&path).unwrap().hunt.days, 5);
    }

    /// What a sandboxed scan leaves in its own directory. Its counts are wrong on
    /// purpose: they are redone from the findings that are kept.
    fn scan_left(state: &State, at: i64, findings: &[Finding]) {
        let dir = state.scan_dir().unwrap();
        std::fs::write(
            dir.join("findings-latest.json"),
            serde_json::to_vec(findings).unwrap(),
        )
        .unwrap();
        let summary = HuntSummary {
            at,
            scanned: 50,
            malicious: 99,
            suspicious: 99,
            ..HuntSummary::default()
        };
        std::fs::write(
            dir.join("hunt-latest.json"),
            serde_json::to_vec(&summary).unwrap(),
        )
        .unwrap();
    }

    fn scan_state() -> (tempfile::TempDir, State, Config) {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let mut cfg = default_config();
        cfg.hunt.allowed_roots = vec!["/home".into(), "/var/www".into()];
        (dir, state, cfg)
    }

    #[test]
    fn a_sandboxed_scan_result_is_taken_in_once_and_only_what_it_may_name() {
        use std::os::unix::fs::MetadataExt;
        let (_d, state, cfg) = scan_state();
        let now = 1_700_000_000;
        scan_left(
            &state,
            now - 10,
            &[
                finding("/var/www/y.php", 80, "suspicious"),
                finding("/home/a/public_html/x.php", 140, "malicious"),
                // Outside the scanned roots, or not a plain path inside them:
                // `sn clean` would act on these as root.
                finding("/etc/passwd", 200, "malicious"),
                finding("/home/../etc/shadow", 200, "malicious"),
                finding("home/a/z.php", 200, "malicious"),
                finding("/home", 200, "malicious"),
                finding("/homework/z.php", 200, "malicious"),
                finding("/home/a/\0.php", 200, "malicious"),
                // Not a verdict a scan gives.
                finding("/home/a/w.php", 10, "clean"),
            ],
        );
        assert_eq!(import_scan(&cfg, &state, now).unwrap(), Imported::Taken(2));
        let (summary, findings) = latest_hunt(&cfg, &state);
        let summary = summary.unwrap();
        assert_eq!(
            (summary.at, summary.scanned),
            (now - 10, 50),
            "the scan's own numbers"
        );
        assert_eq!((summary.malicious, summary.suspicious), (1, 1), "recounted");
        let paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/home/a/public_html/x.php", "/var/www/y.php"]);
        // Written by this process, root's alone.
        for name in ["hunt-latest.json", "findings-latest.json"] {
            let mode = std::fs::metadata(state.dir.join(name)).unwrap().mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        // Once: `sn clean` may have trimmed it since, so the same scan is not
        // taken in again; a later one is.
        assert_eq!(import_scan(&cfg, &state, now).unwrap(), Imported::Nothing);
        scan_left(&state, now, &[]);
        assert_eq!(import_scan(&cfg, &state, now).unwrap(), Imported::Taken(0));
        assert_eq!(latest_hunt(&cfg, &state).0.unwrap().malicious, 0);
    }

    #[test]
    fn a_scan_run_by_hand_later_is_kept() {
        let (_d, state, cfg) = scan_state();
        let now = 1_700_000_000;
        let by_hand = HuntSummary {
            at: now,
            ..HuntSummary::default()
        };
        std::fs::write(
            state.dir.join("hunt-latest.json"),
            serde_json::to_vec(&by_hand).unwrap(),
        )
        .unwrap();
        scan_left(
            &state,
            now - 60,
            &[finding("/home/a/x.php", 140, "malicious")],
        );
        assert_eq!(import_scan(&cfg, &state, now).unwrap(), Imported::Nothing);
        assert!(!state.dir.join("findings-latest.json").exists());
    }

    #[test]
    fn a_forged_scan_result_cannot_hold_back_later_ones_or_bloat_the_report() {
        let (_d, state, cfg) = scan_state();
        let now = 1_700_000_000;
        // A finish time far ahead would make every real scan after it look older.
        scan_left(&state, now + 86_400, &[]);
        assert!(matches!(
            import_scan(&cfg, &state, now).unwrap(),
            Imported::Refused(_)
        ));
        assert!(!state.dir.join("hunt-latest.json").exists());

        let mut big = finding("/home/a/x.php", 140, "malicious");
        big.context = "\u{1b}[2J".to_string() + &"A".repeat(10_000);
        big.rules = vec!["r".repeat(1_000); 1_000];
        big.sha256 = "not a hash".into();
        let mut good = finding("/home/a/y.php", 100, "malicious");
        good.sha256 = "ab".repeat(32);
        scan_left(&state, now, &[big, good]);
        assert_eq!(import_scan(&cfg, &state, now).unwrap(), Imported::Taken(2));
        let (_, findings) = latest_hunt(&cfg, &state);
        let big = findings.iter().find(|f| f.path == "/home/a/x.php").unwrap();
        assert!(big.context.chars().count() <= 512 && !big.context.contains('\u{1b}'));
        assert!(big.rules.len() <= 64 && big.rules.iter().all(|r| r.len() <= 200));
        assert!(big.sha256.is_empty());
        let good = findings.iter().find(|f| f.path == "/home/a/y.php").unwrap();
        assert_eq!(good.sha256, "ab".repeat(32));

        // An oversized summary is not even read.
        let dir = state.dir.join(crate::state::SCAN_DIR);
        let mut huge = serde_json::to_vec(&HuntSummary {
            at: now + 1,
            ..HuntSummary::default()
        })
        .unwrap();
        huge.extend(std::iter::repeat_n(b' ', 128 * 1024));
        std::fs::write(dir.join("hunt-latest.json"), huge).unwrap();
        assert_eq!(
            import_scan(&cfg, &state, now + 1).unwrap(),
            Imported::Nothing
        );
    }

    #[test]
    fn scan_files_are_never_read_through_a_link_or_waited_on() {
        let (d, state, cfg) = scan_state();
        let now = 1_700_000_000;
        let dir = state.scan_dir().unwrap();
        // A link to a summary somewhere else.
        let elsewhere = d.path().join("elsewhere.json");
        let summary = HuntSummary {
            at: now,
            ..HuntSummary::default()
        };
        std::fs::write(&elsewhere, serde_json::to_vec(&summary).unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("hunt-latest.json")).unwrap();
        assert_eq!(import_scan(&cfg, &state, now).unwrap(), Imported::Nothing);

        // A FIFO for the findings: no writer ever comes, and the cycle must not
        // wait for one.
        std::fs::remove_file(dir.join("hunt-latest.json")).unwrap();
        std::fs::write(
            dir.join("hunt-latest.json"),
            serde_json::to_vec(&summary).unwrap(),
        )
        .unwrap();
        nix::unistd::mkfifo(
            &dir.join("findings-latest.json"),
            nix::sys::stat::Mode::S_IRWXU,
        )
        .unwrap();
        assert!(matches!(
            import_scan(&cfg, &state, now).unwrap(),
            Imported::Refused(_)
        ));
        assert!(!state.dir.join("hunt-latest.json").exists());
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
