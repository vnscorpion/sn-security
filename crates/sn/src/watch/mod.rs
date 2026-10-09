//! `sn watch` — one timer cycle: read new log lines, count per IP, apply the
//! fixed patterns and the dynamic baseline, ban abusers on the web ports (in
//! enforce mode) or record `would_ban` (in observe mode), then build a report
//! and sync with the hub. Designed to run for 1–3 seconds and exit.

pub mod baseline;
pub mod patterns;
pub mod tail;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;
use snsec_common::logfmt::{self, LogFormat};
use snsec_common::net::{self, Cidr};
use snsec_common::schema::{BanEvent, CycleStats, IpCount};

use crate::config::{Config, LogSource};
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

    // Gather and parse new log lines.
    let data = collect(cfg, state, &trusted)?;

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
    let enforce = cfg.watch.mode == snsec_common::schema::Mode::Enforce;
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
    let watch_blind = data.lines_read == 0 && has_web_traffic(&conns);
    let (cpu_busy, _load1) = quick_cpu_busy();

    let cycle = CycleStats {
        started_at: started,
        duration_ms: util::now_millis().saturating_sub(start_ms),
        lines_read: data.lines_read,
        parse_errors: data.parse_errors,
        requests: data.requests,
        load1: crate::sys::proc::loadavg1(),
        cpu_busy_pct: (cpu_busy * 10.0).round() / 10.0,
        top_ips,
        baseline_ready,
        watch_blind,
        overload: data.per_ip.len() >= MAX_TRACKED_IPS,
    };

    // Report + hub sync.
    crate::hub::sync(cfg, state, cycle, applied, would, over_cap, watch_blind)?;
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

fn collect(cfg: &Config, state: &State, trusted: &[Cidr]) -> Result<CycleData> {
    let mut offsets = state.offsets();
    let mut data = CycleData {
        per_ip: HashMap::new(),
        ip_of_key: HashMap::new(),
        lines_read: 0,
        parse_errors: 0,
        requests: 0,
    };

    let sources = resolve_sources(cfg);
    let first_run = offsets.is_empty();
    let mut total_bytes: u64 = 0;

    'outer: for src in sources {
        let fmt = LogFormat::from_str_opt(&src.format).unwrap_or(LogFormat::Combined);
        for path in expand_glob(&src.glob) {
            if total_bytes >= CYCLE_BYTE_BUDGET {
                break 'outer; // offsets already saved advance next cycle
            }
            let key = path.to_string_lossy().to_string();
            let prev = offsets.get(&key).copied();
            let read = match tail::read_new(&path, prev, first_run, MAX_BYTES_PER_FILE) {
                Ok(r) => r,
                Err(_) => continue,
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

fn resolve_sources(cfg: &Config) -> Vec<LogSource> {
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

fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => paths.flatten().filter(|p| p.is_file()).collect(),
        Err(_) => Vec::new(),
    }
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
