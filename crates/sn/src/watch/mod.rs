//! `sn watch` — one timer cycle: read new log lines, count per IP, apply the
//! fixed patterns and the dynamic baseline, ban abusers on the web ports (in
//! enforce mode) or record `would_ban` (in observe mode), then build a report
//! and sync with the hub. Designed to run for 1–3 seconds and exit.

pub mod baseline;
pub mod patterns;
pub mod tail;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use snsec_common::logfmt::{self, LogFormat};
use snsec_common::net::{self, Cidr};
use snsec_common::schema::{BanEvent, CycleStats, IpCount};

use crate::config::{Config, LogSource, SourcesMode};
use crate::discover;
use crate::state::{ActiveBan, State, Strike};
use crate::sys::{fw, netstat};
use crate::util;
use crate::whitelist::Whitelist;

use baseline::Baseline;
use patterns::IpAgg;

/// Per-cycle, in-memory result before we decide bans.
struct CycleData {
    per_ip: HashMap<String, IpAgg>,
    /// Representative parsed IP per ban-key, for whitelist/CIDR checks.
    ip_of_key: HashMap<String, IpAddr>,
    lines_read: u64,
    parse_errors: u64,
    requests: u64,
    /// Log files the configured globs matched this cycle.
    files_matched: u32,
    /// Of those, files we had already seen in an earlier cycle (so a quiet one
    /// really means "no new lines", not "first look, started at the end").
    files_known: u32,
    /// Matched files that could not be opened or read.
    unreadable: u32,
    /// First read error, for the alert text.
    first_error: Option<String>,
}

const MAX_TRACKED_IPS: usize = 100_000;
const MAX_BYTES_PER_FILE: u64 = 64 * 1024 * 1024;
/// Total log bytes a single cycle will parse before stopping (offsets still
/// advance so the next cycle resumes). Bounds worst-case cycle time under flood.
const CYCLE_BYTE_BUDGET: u64 = 256 * 1024 * 1024;

/// Options for one watch invocation.
pub struct Options {
    /// Replay a single log file end-to-end (no hub, no nft) and print would_ban.
    pub replay: Option<PathBuf>,
    pub force: bool,
}

pub fn run(cfg: &Config, state: &State, opts: &Options) -> Result<()> {
    let _ = opts.force;
    if let Some(path) = &opts.replay {
        return replay(cfg, path);
    }

    let started = util::now_secs();
    let start_ms = util::now_millis();
    let trusted = cfg.trusted_cidrs();
    let conns = netstat::all();
    let wl = crate::whitelist::build(cfg, &conns);

    // Work out which logs to follow (detected each cycle), then read them.
    let resolved = resolve_sources(cfg, &conns);
    let data = collect(state, &trusted, &resolved.sources)?;

    // Busiest-IP count for the baseline (whitelisted IPs excluded).
    let busiest = data
        .per_ip
        .iter()
        .filter(|(k, _)| !key_protected(k, &data.ip_of_key, &wl, &trusted))
        .map(|(_, a)| a.requests)
        .max()
        .unwrap_or(0);

    let slot = baseline::slot_of(started);
    let mut base: Baseline = load_baseline(state);
    base.observe(slot, busiest);
    let threshold = base.threshold(slot, cfg.watch.k, cfg.watch.min_requests);
    let baseline_ready = base.ready(slot);
    save_baseline(state, &base);

    // Decide bans.
    let mut strikes = state.strikes();
    let mut active = state.bans();
    // Effective mode: the hub-pushed override (if any) wins over local config.
    let effective_mode = state.meta().mode_override.unwrap_or(cfg.watch.mode);
    let enforce = effective_mode == snsec_common::schema::Mode::Enforce;
    let mut applied: Vec<BanEvent> = Vec::new();
    let mut would: Vec<BanEvent> = Vec::new();
    let mut to_add: Vec<(String, u64)> = Vec::new();

    let mut candidates: Vec<(&String, &IpAgg)> = data.per_ip.iter().collect();
    // Stable order: busiest first, so the per-cycle cap keeps the worst.
    candidates.sort_by_key(|(_, a)| std::cmp::Reverse(a.requests));

    for (key, agg) in candidates {
        if key_protected(key, &data.ip_of_key, &wl, &trusted) {
            continue;
        }
        let decision = decide(key, agg, threshold);
        let Some((reason, base_ttl, do_ban)) = decision else {
            continue;
        };
        if !do_ban {
            // report-only pattern
            would.push(BanEvent {
                ip: key.clone(),
                reason: reason.to_string(),
                ttl_secs: 0,
                strike: 0,
                layer: "report".into(),
            });
            continue;
        }

        // Escalate by strike history.
        let now = started;
        let s = strikes.entry(key.clone()).or_insert(Strike {
            count: 0,
            last_ts: now,
        });
        // Decay: a clean week resets the ladder.
        if now - s.last_ts > 7 * 86_400 {
            s.count = 0;
        }
        s.count = s.count.saturating_add(1);
        s.last_ts = now;
        let ttl = base_ttl.max(ladder_ttl(s.count));
        let strike = s.count;

        let ev = BanEvent {
            ip: key.clone(),
            reason: reason.to_string(),
            ttl_secs: ttl,
            strike,
            layer: "l3".into(),
        };

        if enforce {
            if applied.len() >= cfg.fw.max_bans_per_cycle as usize {
                // Too many bans: likely distributed attack or broken rule.
                break;
            }
            to_add.push((key.clone(), ttl));
            active.insert(
                key.clone(),
                ActiveBan {
                    reason: reason.to_string(),
                    expires_ts: now + ttl as i64,
                    strike,
                    layer: "l3".into(),
                },
            );
            applied.push(ev);
        } else {
            would.push(ev);
        }
    }

    let over_cap = applied.len() >= cfg.fw.max_bans_per_cycle as usize;

    // Apply firewall changes (enforce only).
    if enforce {
        if fw::available() {
            if let Err(e) = fw::ensure_table(&cfg.fw.web_ports) {
                eprintln!("watch: ensure_table: {e:#}");
            }
            let _ = fw::set_whitelist(&wl.keys());
            if let Err(e) = fw::apply_bans(&to_add, &[]) {
                eprintln!("watch: apply_bans: {e:#}");
            }
        } else {
            eprintln!("watch: nft not available; running report-only this cycle");
        }
    }

    // Prune expired bans from state (nft expires its own).
    let now = started;
    active.retain(|_, b| b.expires_ts > now);
    state.save_bans(&active)?;
    state.save_strikes(&strikes)?;

    // Build cycle stats + top IPs.
    let top_ips = top_ips(&data);

    // Can we actually see the web server's traffic?
    let mut meta = state.meta();
    let (mut alerts, streak) = assess_logs(
        &LogHealth {
            files_matched: data.files_matched,
            files_known: data.files_known,
            unreadable: data.unreadable,
            lines_read: data.lines_read,
            parse_errors: data.parse_errors,
            web_traffic: has_web_traffic(&conns),
            prev_streak: meta.blind_streak,
        },
        &resolved.tried,
        data.first_error.as_deref(),
    );
    let log_problem = !alerts.is_empty();
    if meta.blind_streak != streak {
        meta.blind_streak = streak;
        state.save_meta(&meta)?;
    }
    if over_cap {
        alerts.push(snsec_common::schema::Alert {
            kind: "ban_cap".into(),
            message: "ban cap reached this cycle; possible distributed attack".into(),
            severity: "urgent".into(),
        });
    }
    let (cpu_busy, _load1) = quick_cpu_busy();
    let mem = crate::sys::proc::meminfo().unwrap_or_default();

    let cycle = CycleStats {
        started_at: started,
        duration_ms: util::now_millis().saturating_sub(start_ms),
        lines_read: data.lines_read,
        parse_errors: data.parse_errors,
        requests: data.requests,
        load1: crate::sys::proc::loadavg1(),
        cpu_busy_pct: (cpu_busy * 10.0).round() / 10.0,
        mem_total_mb: mem.total_mb(),
        mem_used_pct: (mem.used_pct() * 10.0).round() / 10.0,
        swap_used_pct: (mem.swap_used_pct() * 10.0).round() / 10.0,
        log_files: data.files_matched,
        top_ips,
        baseline_ready,
        watch_blind: log_problem,
        overload: data.per_ip.len() >= MAX_TRACKED_IPS,
    };

    // Report + hub sync.
    crate::hub::sync(cfg, state, cycle, applied, would, alerts)?;
    Ok(())
}

fn decide(_key: &str, agg: &IpAgg, threshold: u64) -> Option<(&'static str, u64, bool)> {
    if let Some(hit) = patterns::evaluate(agg) {
        return Some((hit.reason, hit.ttl_secs, hit.ban));
    }
    if agg.requests >= threshold {
        return Some(("rate", 600, true));
    }
    None
}

fn ladder_ttl(strike: u32) -> u64 {
    match strike {
        0 | 1 => 600,    // 10 min
        2 => 3600,       // 1 hour
        3 => 86_400,     // 24 hours
        _ => 7 * 86_400, // 7 days
    }
}

fn key_protected(
    key: &str,
    ip_of_key: &HashMap<String, IpAddr>,
    wl: &Whitelist,
    trusted: &[Cidr],
) -> bool {
    if let Some(ip) = ip_of_key.get(key) {
        wl.protects(*ip) || net::in_any(trusted, *ip)
    } else if let Ok(ip) = key.split('/').next().unwrap_or(key).parse::<IpAddr>() {
        wl.protects(ip) || net::in_any(trusted, ip)
    } else {
        false
    }
}

fn collect(state: &State, trusted: &[Cidr], sources: &[LogSource]) -> Result<CycleData> {
    let mut offsets = state.offsets();
    let mut data = CycleData {
        per_ip: HashMap::new(),
        ip_of_key: HashMap::new(),
        lines_read: 0,
        parse_errors: 0,
        requests: 0,
        files_matched: 0,
        files_known: 0,
        unreadable: 0,
        first_error: None,
    };

    let mut total_bytes: u64 = 0;

    'outer: for src in sources {
        let fmt = LogFormat::from_str_opt(&src.format).unwrap_or(LogFormat::Combined);
        for path in expand_glob(&src.glob) {
            if total_bytes >= CYCLE_BYTE_BUDGET {
                break 'outer; // offsets already saved advance next cycle
            }
            data.files_matched += 1;
            let key = path.to_string_lossy().to_string();
            let prev = offsets.get(&key).copied();
            if prev.is_some() {
                data.files_known += 1;
            }
            // A file seen for the first time starts at its end — never its whole
            // history. This holds for a file that appears later too (a new site,
            // a changed glob), not just for the first cycle after install; reading
            // old lines would turn yesterday's traffic into a burst of bans.
            let read = match tail::read_new(&path, prev, true, MAX_BYTES_PER_FILE) {
                Ok(r) => r,
                Err(e) => {
                    data.unreadable += 1;
                    data.first_error
                        .get_or_insert_with(|| format!("{}: {e}", path.display()));
                    continue;
                }
            };
            total_bytes += read.bytes;
            offsets.insert(key, read.new_offset);
            for line in &read.lines {
                data.lines_read += 1;
                match logfmt::parse_line(fmt, line, trusted) {
                    Some(parsed) => {
                        if parsed.client.is_loopback() {
                            continue;
                        }
                        data.requests += 1;
                        let bankey = net::ban_key(parsed.client);
                        data.ip_of_key
                            .entry(bankey.clone())
                            .or_insert(parsed.client);
                        if data.per_ip.len() >= MAX_TRACKED_IPS
                            && !data.per_ip.contains_key(&bankey)
                        {
                            continue; // cap reached; count stays in `requests`
                        }
                        data.per_ip.entry(bankey).or_default().observe(&parsed);
                    }
                    None => data.parse_errors += 1,
                }
            }
        }
    }

    state.save_offsets(&offsets)?;
    Ok(data)
}

/// The log sources in effect for this cycle, and how they were chosen.
pub struct Resolved {
    pub sources: Vec<LogSource>,
    /// Every pattern considered, so "found nothing" can say where it looked.
    pub tried: Vec<String>,
    /// The web server detected on :80/:443 (`None` in manual mode).
    pub listener: Option<discover::Listener>,
}

/// What the config file lists explicitly (`sources`, or the older `logs`).
fn configured_sources(cfg: &Config) -> Vec<LogSource> {
    if !cfg.watch.sources.is_empty() {
        return cfg.watch.sources.clone();
    }
    cfg.watch
        .logs
        .iter()
        .map(|g| LogSource {
            glob: g.clone(),
            format: cfg.watch.format.clone(),
        })
        .collect()
}

/// Choose the logs to follow. In `auto` mode (the default) the agent detects the
/// web server and reads its logs, which is what makes one agent build work on
/// every panel and keeps working after a web-server switch. The explicit sources
/// in the config are only a fallback there. `manual` uses them and nothing else.
fn resolve_sources(cfg: &Config, conns: &[netstat::Conn]) -> Resolved {
    let configured = configured_sources(cfg);
    match cfg.watch.sources_mode {
        SourcesMode::Manual => Resolved {
            tried: configured.iter().map(|s| s.glob.clone()).collect(),
            sources: configured,
            listener: None,
        },
        SourcesMode::Auto => {
            let listener = discover::detect_listener(conns);
            let found = discover::discover(listener, "");
            let mut tried = found.tried;
            if found.found.is_empty() {
                // Nothing at the usual places: fall back to whatever is configured.
                tried.extend(configured.iter().map(|s| s.glob.clone()));
                Resolved {
                    sources: configured,
                    tried,
                    listener: Some(listener),
                }
            } else {
                Resolved {
                    sources: found.found,
                    tried,
                    listener: Some(listener),
                }
            }
        }
    }
}

pub(crate) fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => paths
            .flatten()
            .filter(|p| p.is_file() && is_access_log_candidate(p))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Panels put error logs and archives next to the access logs (DirectAdmin:
/// `site.com.log`, `site.com.error.log`, `site.com.bytes`). Parsing those as
/// access logs only produces parse errors, so skip them.
fn is_access_log_candidate(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    const SKIP_SUFFIX: &[&str] = &[".gz", ".bz2", ".xz", ".zst", ".zip", ".bytes", ".tmp"];
    if SKIP_SUFFIX.iter().any(|s| name.ends_with(s)) {
        return false;
    }
    // `error` / `bytes` as a whole word of the file name: error.log, error_log,
    // site.com.error.log, cPanel's site.com-bytes_log — but not
    // "errorlog.com.log", which is a real access log for a site of that name.
    !name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| token == "error" || token == "bytes")
}

/// What is being followed right now, for `sn env`: how it was chosen, and the
/// files each source matches.
pub fn describe_sources(cfg: &Config) -> (Resolved, Vec<(LogSource, Vec<PathBuf>)>) {
    let resolved = resolve_sources(cfg, &netstat::all());
    let files = resolved
        .sources
        .iter()
        .map(|s| (s.clone(), expand_glob(&s.glob)))
        .collect();
    (resolved, files)
}

/// Inputs to [`assess_logs`], kept separate from the I/O so it can be tested.
struct LogHealth {
    files_matched: u32,
    files_known: u32,
    unreadable: u32,
    lines_read: u64,
    parse_errors: u64,
    web_traffic: bool,
    /// Quiet-with-traffic cycles in a row before this one.
    prev_streak: u32,
}

/// Consecutive quiet cycles (with web connections open) before it is reported.
/// One is ordinary — idle keep-alive connections hold a port open with no new
/// requests — so a single cycle must not raise an alarm.
const BLIND_STREAK_ALERT: u32 = 3;

/// Decide whether the agent can actually see the web server's traffic. Returns
/// the alerts to raise and the updated quiet-cycle streak.
fn assess_logs(
    h: &LogHealth,
    globs: &[String],
    first_error: Option<&str>,
) -> (Vec<snsec_common::schema::Alert>, u32) {
    use snsec_common::schema::Alert;
    let warn = |kind: &str, message: String| Alert {
        kind: kind.into(),
        message,
        severity: "warn".into(),
    };
    let mut alerts = Vec::new();

    if h.files_matched == 0 {
        let what = if globs.is_empty() {
            "no log source is configured".to_string()
        } else {
            format!("no access log file found; looked for: {}", globs.join(", "))
        };
        alerts.push(warn("log_not_found", what));
        return (alerts, 0);
    }
    if h.unreadable >= h.files_matched {
        alerts.push(warn(
            "log_unreadable",
            format!(
                "{} log file(s) found but none could be read ({})",
                h.files_matched,
                first_error.unwrap_or("unknown error")
            ),
        ));
        return (alerts, 0);
    }
    if h.lines_read >= 20 && h.parse_errors * 2 > h.lines_read {
        alerts.push(warn(
            "log_format",
            format!(
                "{} of {} log lines could not be parsed; check `format` in agent.toml",
                h.parse_errors, h.lines_read
            ),
        ));
    }

    // Quiet cycle with traffic. Needs a file we already knew: a file first seen
    // this cycle starts at its end and so reads nothing by design.
    let quiet = h.lines_read == 0 && h.files_known > 0 && h.web_traffic;
    let streak = if quiet { h.prev_streak + 1 } else { 0 };
    if streak >= BLIND_STREAK_ALERT {
        alerts.push(warn(
            "watch_blind",
            format!("web connections are open but no new log lines for {streak} cycles in a row"),
        ));
    }
    (alerts, streak)
}

fn top_ips(data: &CycleData) -> Vec<IpCount> {
    let mut v: Vec<IpCount> = data
        .per_ip
        .iter()
        .map(|(k, a)| IpCount {
            ip: k.clone(),
            requests: a.requests,
            err4xx: a.err4xx,
            sensitive_posts: a.login_posts + a.xmlrpc_posts,
        })
        .collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.requests));
    v.truncate(20);
    v
}

fn has_web_traffic(conns: &[netstat::Conn]) -> bool {
    conns
        .iter()
        .any(|c| c.state == netstat::ST_ESTABLISHED && matches!(c.local_port, 80 | 443))
}

fn quick_cpu_busy() -> (f64, f64) {
    use crate::sys::proc;
    let (t0, i0) = proc::cpu_total_idle().unwrap_or((0, 0));
    std::thread::sleep(std::time::Duration::from_millis(120));
    let (t1, i1) = proc::cpu_total_idle().unwrap_or((0, 0));
    let busy = if t1 > t0 {
        100.0 * (1.0 - (i1.saturating_sub(i0)) as f64 / (t1 - t0).max(1) as f64)
    } else {
        0.0
    };
    (busy, proc::loadavg1())
}

fn load_baseline(state: &State) -> Baseline {
    std::fs::read(state.dir.join("baseline.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_baseline(state: &State, b: &Baseline) {
    if let Ok(bytes) = serde_json::to_vec(b) {
        let _ = std::fs::write(state.dir.join("baseline.json"), bytes);
    }
}

/// Replay mode: read a whole file, run detection, print would_ban. No side
/// effects on the firewall or hub — a tool for tuning on captured logs.
fn replay(cfg: &Config, path: &PathBuf) -> Result<()> {
    let trusted = cfg.trusted_cidrs();
    let fmt = cfg
        .watch
        .sources
        .first()
        .map(|s| s.format.clone())
        .unwrap_or_else(|| cfg.watch.format.clone());
    let fmt = LogFormat::from_str_opt(&fmt).unwrap_or(LogFormat::Combined);

    let text = std::fs::read_to_string(path)?;
    let mut per_ip: HashMap<String, IpAgg> = HashMap::new();
    let mut parsed_ok = 0u64;
    let mut parse_errors = 0u64;
    for line in text.lines() {
        match logfmt::parse_line(fmt, line, &trusted) {
            Some(p) => {
                parsed_ok += 1;
                per_ip
                    .entry(net::ban_key(p.client))
                    .or_default()
                    .observe(&p);
            }
            None => parse_errors += 1,
        }
    }
    let threshold = u64::from(cfg.watch.min_requests);
    let mut bans = 0u64;
    println!("== replay {} ==", path.display());
    println!("parsed {parsed_ok} lines, {parse_errors} parse errors");
    for (key, agg) in &per_ip {
        if let Some((reason, ttl, _do_ban)) = decide(key, agg, threshold) {
            bans += 1;
            println!(
                "would_ban {key:<20} reason={reason:<16} ttl={ttl:<6} req={} 404={} posts={}",
                agg.requests,
                agg.err404,
                agg.login_posts + agg.xmlrpc_posts
            );
        }
    }
    println!("total would_ban: {bans}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> LogHealth {
        LogHealth {
            files_matched: 3,
            files_known: 3,
            unreadable: 0,
            lines_read: 100,
            parse_errors: 0,
            web_traffic: true,
            prev_streak: 0,
        }
    }

    fn kinds(alerts: &[snsec_common::schema::Alert]) -> Vec<&str> {
        alerts.iter().map(|a| a.kind.as_str()).collect()
    }

    #[test]
    fn healthy_cycle_raises_nothing() {
        let (alerts, streak) = assess_logs(&health(), &["/x/*.log".into()], None);
        assert!(alerts.is_empty());
        assert_eq!(streak, 0);
    }

    #[test]
    fn first_cycle_after_install_is_not_blind() {
        // Files are first seen this cycle, so they start at the end and read
        // nothing by design. This used to raise a false "cannot read logs".
        let h = LogHealth {
            files_known: 0,
            lines_read: 0,
            ..health()
        };
        let (alerts, streak) = assess_logs(&h, &["/x/*.log".into()], None);
        assert!(alerts.is_empty());
        assert_eq!(streak, 0);
    }

    #[test]
    fn blind_needs_a_streak_not_a_single_quiet_cycle() {
        let quiet = |prev| LogHealth {
            lines_read: 0,
            prev_streak: prev,
            ..health()
        };
        let g = ["/x/*.log".to_string()];
        let (a1, s1) = assess_logs(&quiet(0), &g, None);
        assert!(a1.is_empty());
        assert_eq!(s1, 1);
        let (a2, s2) = assess_logs(&quiet(s1), &g, None);
        assert!(a2.is_empty());
        assert_eq!(s2, 2);
        let (a3, s3) = assess_logs(&quiet(s2), &g, None);
        assert_eq!(kinds(&a3), ["watch_blind"]);
        assert_eq!(s3, 3);
        // Lines arrive again: the streak resets and the alert clears.
        let (a4, s4) = assess_logs(
            &LogHealth {
                prev_streak: s3,
                ..health()
            },
            &g,
            None,
        );
        assert!(a4.is_empty());
        assert_eq!(s4, 0);
    }

    #[test]
    fn quiet_without_web_connections_is_just_a_quiet_server() {
        let h = LogHealth {
            lines_read: 0,
            web_traffic: false,
            prev_streak: 5,
            ..health()
        };
        let (alerts, streak) = assess_logs(&h, &["/x/*.log".into()], None);
        assert!(alerts.is_empty());
        assert_eq!(streak, 0);
    }

    #[test]
    fn nothing_matched_names_the_globs() {
        let h = LogHealth {
            files_matched: 0,
            files_known: 0,
            lines_read: 0,
            ..health()
        };
        let globs = vec!["/var/log/httpd/domains/*.log".to_string()];
        let (alerts, _) = assess_logs(&h, &globs, None);
        assert_eq!(kinds(&alerts), ["log_not_found"]);
        assert!(alerts[0].message.contains("/var/log/httpd/domains/*.log"));

        let (alerts, _) = assess_logs(&h, &[], None);
        assert_eq!(kinds(&alerts), ["log_not_found"]);
        assert!(alerts[0].message.contains("no log source"));
    }

    #[test]
    fn unreadable_files_report_the_error() {
        let h = LogHealth {
            unreadable: 3,
            lines_read: 0,
            ..health()
        };
        let (alerts, _) = assess_logs(&h, &["/x/*.log".into()], Some("/x/a.log: denied"));
        assert_eq!(kinds(&alerts), ["log_unreadable"]);
        assert!(alerts[0].message.contains("denied"));
        // Some readable files: not an alert.
        let h = LogHealth {
            unreadable: 1,
            ..health()
        };
        assert!(assess_logs(&h, &[], Some("e")).0.is_empty());
    }

    #[test]
    fn wrong_log_format_is_called_out() {
        let g = ["/x/*.log".to_string()];
        let bad = LogHealth {
            lines_read: 100,
            parse_errors: 80,
            ..health()
        };
        assert_eq!(kinds(&assess_logs(&bad, &g, None).0), ["log_format"]);
        // A few bad lines are normal.
        let few = LogHealth {
            lines_read: 100,
            parse_errors: 30,
            ..health()
        };
        assert!(assess_logs(&few, &g, None).0.is_empty());
        // Too few lines to judge.
        let tiny = LogHealth {
            lines_read: 10,
            parse_errors: 10,
            ..health()
        };
        assert!(assess_logs(&tiny, &g, None).0.is_empty());
    }

    #[test]
    fn directadmin_error_logs_and_archives_are_skipped() {
        let ok = |p: &str| is_access_log_candidate(Path::new(p));
        // The files DirectAdmin writes per domain.
        assert!(ok("/var/log/httpd/domains/example.com.log"));
        assert!(!ok("/var/log/httpd/domains/example.com.error.log"));
        assert!(!ok("/var/log/httpd/domains/example.com.bytes"));
        assert!(!ok("/var/log/httpd/domains/example.com.log.gz"));
        // Other servers.
        assert!(ok("/var/log/nginx/access.log"));
        assert!(!ok("/var/log/nginx/error.log"));
        assert!(!ok("/usr/local/apache/domlogs/error_log"));
        assert!(ok("/usr/local/apache/domlogs/example.com-ssl_log"));
        // cPanel's per-site byte counter is not an access log either.
        assert!(!ok("/usr/local/apache/domlogs/example.com-bytes_log"));
        // "error" must be a whole word: this is a real access log.
        assert!(ok("/var/log/httpd/domains/errorlog.com.log"));
    }
}
