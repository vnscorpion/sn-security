//! `sn watch` — one timer cycle: read new log lines, count per IP, apply the
//! fixed patterns and the dynamic baseline, ban abusers on the web ports (in
//! enforce mode) or record `would_ban` (in observe mode), then build a report
//! and sync with the hub. Designed to run for 1–3 seconds and exit.

pub mod baseline;
pub mod bots;
pub mod cpu;
pub mod decide;
pub mod patterns;
pub mod tail;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use snsec_common::logfmt::{self, LogFormat, LogLine};
use snsec_common::net::{self, Cidr};
use snsec_common::ranges;
use snsec_common::schema::{Alert, CycleStats, IpCount, Mode};

use crate::config::{Config, LogSource, SourcesMode};
use crate::discover;
use crate::state::State;
use crate::sys::{fw, netstat};
use crate::util;
use crate::whitelist;

use baseline::Baseline;
use decide::{
    ABS_CEILING, Candidate, Cycle, Decisions, STORM_FACTOR, alert, backlog_alert, backlog_state,
    cloudflare_alert, cycle_span, decide_bans, misplaced_alert, per_cycle, proxy_alert, proxy_keys,
    prune_active, prune_strikes, prune_unbanned, robust_busiest, scale, storm_alert, unban_grace,
    unlisted_alert,
};
use patterns::{IpAgg, Judge, PatternHit};

/// Per-cycle, in-memory result before we decide bans.
struct CycleData {
    per_ip: HashMap<String, IpAgg>,
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
    /// Of the unreadable files, those refused for what they are (a symlink, not
    /// a regular file, the wrong owner or mode), and the first with its reason.
    refused: u32,
    first_refused: Option<String>,
    /// What the dynamic requests looked like (User-Agents, request shapes).
    bots: bots::Aggregates,
    /// A read hit its byte cap, so the logs hold more than this cycle read.
    catch_up: bool,
}

impl CycleData {
    /// The aggregate a request with this ban key counts in, `None` once
    /// [`MAX_TRACKED_IPS`] keys are tracked and this is a new one.
    fn track(&mut self, bankey: String) -> Option<&mut IpAgg> {
        if self.per_ip.len() >= MAX_TRACKED_IPS && !self.per_ip.contains_key(&bankey) {
            return None; // cap reached; count stays in `requests`
        }
        Some(self.per_ip.entry(bankey).or_default())
    }
}

/// Addresses (IPv6 /64s) tracked per cycle. With at most about a kilobyte per
/// address however it is used (see `patterns::IpAgg`), the worst case stays
/// well inside sn-watch's 192 MB memory limit; past it, new addresses only
/// count in the cycle's totals (and the report says `overload`).
const MAX_TRACKED_IPS: usize = 50_000;
const MAX_BYTES_PER_FILE: u64 = 64 * 1024 * 1024;
/// Total log bytes a single cycle will parse before stopping (offsets still
/// advance so the next cycle resumes). Bounds worst-case cycle time under flood.
const CYCLE_BYTE_BUDGET: u64 = 256 * 1024 * 1024;

/// The search crawler a ban key belongs to, by its published ranges (an IPv6
/// key by its /64, which is how Google publishes its ranges).
fn crawler_of(key: &str) -> Option<ranges::Crawler> {
    Cidr::parse(key).and_then(|c| ranges::verified_crawler(c.addr))
}

/// Options for one watch invocation.
pub struct Options {
    /// Replay a single log file end-to-end (no hub, no nft) and print would_ban.
    pub replay: Option<PathBuf>,
    pub force: bool,
}

/// The same hit, only reported.
fn report_only(hit: PatternHit) -> PatternHit {
    PatternHit {
        ttl_secs: 0,
        ban: false,
        escalate: false,
        ttl_cap: 0,
        ..hit
    }
}

pub fn run(cfg: &Config, state: &State, opts: &Options) -> Result<()> {
    let _ = opts.force;
    if let Some(path) = &opts.replay {
        return replay(cfg, path);
    }

    let started = util::now_secs();
    let start_ms = util::now_millis();
    let trusted = cfg.trusted_cidrs();
    // Never banned here: the trusted proxies and, unless switched off,
    // Cloudflare (one that carries a single client aside, see below).
    let never_ban = cfg.never_ban_cidrs();
    let conns = netstat::all();
    let wl = whitelist::build(cfg, &conns, Some(state));
    let meta = state.meta();

    // How much log this cycle covers: since the last one started.
    let prev_cycle = match meta.last_cycle_ts {
        0 => state.cpu_sample().at, // the first cycle of an upgraded agent
        t => t,
    };
    let span = cycle_span(prev_cycle, started);
    // Effective mode: the hub-pushed override (if any) wins over local config.
    let effective_mode = meta.mode_override.unwrap_or(cfg.watch.mode);
    let enforce = effective_mode == Mode::Enforce;
    state.update_meta(|m| {
        m.last_cycle_ts = started;
        m.last_mode = Some(effective_mode);
    })?;

    // Work out which logs to follow (detected each cycle), then read them.
    let resolved = resolve_sources(cfg, &conns, &meta.log_sets);
    let data = collect(
        state,
        &trusted,
        wl.own_addrs(),
        &resolved.sources,
        &resolved.dropped,
    )?;
    // A backlog after a gap: `rate` and `scanner` are not judged on it.
    let (backlog, gap_left) = backlog_state(span, data.catch_up, meta.gap_cycles_left);
    let log_sets = if resolved.dropped.is_empty() {
        Vec::new()
    } else {
        resolved.kept.clone()
    };
    state.update_meta(|m| {
        m.gap_cycles_left = gap_left;
        if m.log_sets != log_sets {
            m.log_sets = log_sets;
        }
    })?;
    let protected = |k: &str| whitelist::key_protected(k, &wl, &never_ban);

    let slot = baseline::slot_of(started);
    let mut base: Baseline = load_baseline(state);
    let ceiling = scale(ABS_CEILING, span);
    let floor = scale(u64::from(cfg.watch.min_requests), span);
    // Never above the ceiling (unless the configured floor is): however the
    // baseline was fed, ten dynamic requests a second on one site is a flood.
    let threshold = scale(
        base.threshold(slot, cfg.watch.k, cfg.watch.min_requests),
        span,
    )
    .min(ceiling.max(floor));
    let baseline_ready = base.ready(slot);
    let judge = Judge {
        threshold,
        baseline_ready,
        ceiling,
        volume: !backlog,
        crawler: false,
        span,
        volume_exempt: false,
    };

    // Decide bans.
    let mut strikes = state.strikes();
    // Start enforcing with a clean slate, whoever switched the mode (the hub,
    // or `mode` in agent.toml): offences counted before (an older agent
    // counted them in observe mode too, and wrote them without `rate_only`)
    // must not make the first real bans long.
    if enforce && meta.last_mode != Some(Mode::Enforce) {
        strikes.clear();
    }
    let mut active = state.bans();
    let mut unbanned = state.unbanned();
    let unbanned_before = unbanned.len();
    prune_unbanned(&mut unbanned, started);

    // Addresses that matched anything (left out of what the baseline learns),
    // the candidates, and Cloudflare addresses that sent attack traffic.
    let mut matched: HashSet<&String> = HashSet::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut via_cloudflare: Vec<String> = Vec::new();
    for (key, agg) in &data.per_ip {
        let Some(hit) = patterns::judge(agg, &judge) else {
            continue;
        };
        matched.insert(key);
        // A crawler, a panel or FTP session, an address the admin unbanned a
        // little while ago: only ever judged more leniently, so only an
        // address that matched something needs looking up.
        let lenient = Judge {
            crawler: crawler_of(key).is_some(),
            volume_exempt: wl.session_peer(key) || unban_grace(&unbanned, key, started),
            ..judge
        };
        let hit = if lenient.crawler || lenient.volume_exempt {
            match patterns::judge(agg, &lenient) {
                Some(h) => h,
                None => continue,
            }
        } else {
            hit
        };
        if protected(key) {
            let Some(net) = Cidr::parse(key) else {
                continue;
            };
            let cloudflare = ranges::is_cloudflare(net.addr) && !wl.protects_net(net);
            if !cloudflare {
                continue;
            }
            let trusted_edge = trusted.iter().any(|c| c.overlaps(&net));
            if trusted_edge || agg.clients() >= 2 {
                // An edge that carries visitors: never banned here. Attack
                // traffic through it is reported, for a rule at Cloudflare.
                if hit.ban && hit.reason != "rate" {
                    via_cloudflare.push(key.clone());
                    candidates.push(Candidate {
                        key,
                        agg,
                        hit: report_only(hit),
                    });
                }
                continue;
            }
            // A Cloudflare address with one client that is no trusted proxy
            // here (a Worker, say): judged like any other.
        }
        candidates.push(Candidate { key, agg, hit });
    }
    via_cloudflare.sort_unstable();
    // Stable order: busiest first, so the per-cycle cap keeps the worst.
    candidates.sort_by(|a, b| b.agg.requests.cmp(&a.agg.requests).then(a.key.cmp(b.key)));
    let proxies = proxy_keys(&candidates);
    let Decisions {
        applied,
        would,
        to_add,
        unlisted,
        storm,
    } = decide_bans(
        &candidates,
        &Cycle {
            storm_floor: threshold.saturating_mul(STORM_FACTOR),
            ban_cap: cfg.fw.max_bans_per_cycle as usize,
            enforce,
            now: started,
            span,
        },
        &mut strikes,
        &mut active,
    );

    // What the baseline learns: only a cycle of ordinary traffic (not an idle
    // one, not a backlog after a gap, not a read cut short by a flood), and
    // from it the third busiest of the addresses that matched nothing, stayed
    // under the bar, are not protected and are no verified crawler.
    if data.lines_read > 0 && !backlog && !data.catch_up {
        let mut quiet: Vec<(u64, &String)> = data
            .per_ip
            .iter()
            .filter(|(k, _)| !matched.contains(k))
            .map(|(k, a)| (a.site_dynamic(), k))
            .filter(|(n, _)| *n > 0 && *n < threshold)
            .collect();
        quiet.sort_unstable_by(|a, b| b.cmp(a));
        let ordinary: Vec<u64> = quiet
            .into_iter()
            .filter(|(_, k)| !protected(k) && crawler_of(k).is_none())
            .take(3)
            .map(|(n, _)| n)
            .collect();
        let value = robust_busiest(&ordinary);
        if value > 0 {
            base.learn(
                slot,
                per_cycle(value, span),
                cfg.watch.k,
                cfg.watch.min_requests,
            );
            save_baseline(state, &base);
        }
    }

    let over_cap = applied.len() >= cfg.fw.max_bans_per_cycle as usize;

    // Apply firewall changes (enforce only). What may never be banned is
    // accepted by the firewall before any ban rule.
    if enforce {
        if fw::available() {
            let white = wl.keys(&trusted);
            if let Err(e) = fw::prepare(&cfg.fw.web_ports, cfg.fw.block_quic, &white) {
                eprintln!("watch: preparing the firewall: {e:#}");
            }
            if let Err(e) = fw::apply_bans(&to_add, &[]) {
                eprintln!("watch: apply_bans: {e:#}");
            }
        } else {
            eprintln!("watch: nft not available; running report-only this cycle");
        }
    }

    // Prune bans from state (nft expires its own), keeping those that ended
    // within the stretch of log the next cycle may still read.
    let now = started;
    prune_active(&mut active, now);
    state.save_bans(&active)?;
    prune_strikes(&mut strikes, now);
    state.save_strikes(&strikes)?;
    if unbanned.len() != unbanned_before {
        state.save_unbanned(&unbanned)?;
    }

    // Build cycle stats + top IPs.
    let top_ips = top_ips(&data);

    // Can we actually see the web server's traffic?
    let meta = state.meta();
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
        // This field only: a hub order applied meanwhile changed others.
        state.update_meta(|m| m.blind_streak = streak)?;
    }
    if over_cap {
        alerts.push(snsec_common::schema::Alert {
            kind: "ban_cap".into(),
            message: "ban cap reached this cycle; possible distributed attack".into(),
            severity: "urgent".into(),
        });
    }

    // CPU over the interval since the last cycle, and who used it.
    let cpu_now = measure_cpu(state, started, cfg.watch.cpu_alert_pct, meta.cpu_streak);
    if meta.cpu_streak != cpu_now.streak {
        state.update_meta(|m| m.cpu_streak = cpu_now.streak)?;
    }
    let cpu_high = cpu_now.alert.is_some();
    alerts.extend(cpu_now.alert);

    // Distributed bots: one User-Agent or request shape from many addresses.
    // Only a cycle that looks like ordinary traffic is judged and learned from:
    // not one with no lines, not a catch-up read after the agent was off (hours
    // of traffic in one cycle look like a surge of everything), not one cut
    // short by its byte cap.
    let representative = data.lines_read > 0 && !backlog && !data.catch_up && !cpu_now.gap;
    let mut base_bots = state.bot_baseline();
    let (flagged_ua, flagged_shape) = if cfg.watch.bot_detection && representative {
        let verdict = bots::assess(
            &data.bots,
            &base_bots,
            &bots::BotCfg {
                min_ips: cfg.watch.bot_min_ips,
                min_requests: cfg.watch.bot_min_requests,
                surge: cfg.watch.bot_surge,
            },
            cpu_high,
        );
        alerts.extend(verdict.alerts);
        base_bots.update(&data.bots, &verdict.flagged_ua, &verdict.flagged_shape);
        if let Err(e) = state.save_bot_baseline(&base_bots) {
            eprintln!("watch: save bot baseline: {e:#}");
        }
        (verdict.flagged_ua, verdict.flagged_shape)
    } else {
        Default::default()
    };
    let (top_user_agents, top_shapes) = data.bots.top_patterns(&flagged_ua, &flagged_shape);
    let mem = crate::sys::proc::meminfo().unwrap_or_default();

    let cycle = CycleStats {
        started_at: started,
        duration_ms: util::now_millis().saturating_sub(start_ms),
        lines_read: data.lines_read,
        parse_errors: data.parse_errors,
        requests: data.requests,
        load1: crate::sys::proc::loadavg1(),
        cpu_busy_pct: (cpu_now.busy * 10.0).round() / 10.0,
        mem_total_mb: mem.total_mb(),
        mem_used_pct: (mem.used_pct() * 10.0).round() / 10.0,
        swap_used_pct: (mem.swap_used_pct() * 10.0).round() / 10.0,
        log_files: data.files_matched,
        dynamic_requests: data.bots.dynamic,
        top_user_agents,
        top_shapes,
        top_cpu: cpu_now.groups,
        top_ips,
        baseline_ready,
        watch_blind: log_problem,
        overload: data.per_ip.len() >= MAX_TRACKED_IPS,
    };

    alerts.extend(refused_alert(data.refused, data.first_refused.as_deref()));
    alerts.extend(unlisted_alert(unlisted));
    alerts.extend(storm_alert(storm, threshold));
    alerts.extend(proxy_alert(&proxies));
    alerts.extend(cloudflare_alert(&via_cloudflare));
    alerts.extend(backlog_alert(backlog && data.lines_read > 0, span));
    alerts.extend(misplaced_alert(&cfg.misplaced_keys()));
    let web_listening = conns
        .iter()
        .any(|c| c.state == netstat::ST_LISTEN && matches!(c.local_port, 80 | 443));
    alerts.extend(listener_alert(&resolved, data.files_matched, web_listening));

    // Report + hub sync.
    crate::hub::sync(cfg, state, cycle, applied, would, alerts)?;
    Ok(())
}

/// Logs were picked without knowing which web server writes them: something
/// listens on :80/:443 (`web_listening`) that is not a server the agent knows.
fn listener_alert(resolved: &Resolved, files: u32, web_listening: bool) -> Option<Alert> {
    if resolved.listener != Some(discover::Listener::Unknown) || files == 0 || !web_listening {
        return None;
    }
    let dropped = if resolved.dropped.is_empty() {
        String::new()
    } else {
        format!(
            "; of log sets that name the same sites only one is read (the one read before, while it is written; else the newest), left out: {}",
            resolved.dropped.join(", ")
        )
    };
    Some(alert(
        "listener_unknown",
        "warn",
        format!(
            "the program on :80/:443 is not a web server the agent recognises (Varnish, HAProxy, Caddy, a container proxy...), so it reads the logs it can find{dropped}. Set sources_mode = \"manual\" and list the front server's logs under [[watch.sources]]"
        ),
    ))
}

/// Is this request's client one to leave out entirely: loopback, or one of
/// this VPS's own addresses (its cron, loopback and cache-preload requests
/// over its public address)?
fn not_a_visitor(ip: IpAddr, own: &[IpAddr]) -> bool {
    let ip = net::normalize(ip);
    ip.is_loopback() || own.contains(&ip)
}

/// Read the new lines of every log in `sources` and count them per address.
/// `own`: this VPS's (and the hub's) addresses, not counted. `dropped`: log
/// patterns left out this cycle (another set names the same sites): their
/// files are moved to their end, so a later switch to them starts from now.
fn collect(
    state: &State,
    trusted: &[Cidr],
    own: &[IpAddr],
    sources: &[LogSource],
    dropped: &[String],
) -> Result<CycleData> {
    let mut offsets = state.offsets();
    let mut data = CycleData {
        per_ip: HashMap::new(),
        lines_read: 0,
        parse_errors: 0,
        requests: 0,
        files_matched: 0,
        files_known: 0,
        unreadable: 0,
        first_error: None,
        refused: 0,
        first_refused: None,
        bots: bots::Aggregates::default(),
        catch_up: false,
    };

    let mut total_bytes: u64 = 0;
    // Files matched this cycle, readable or not; `cut_short` when the byte
    // budget ended the cycle before the last of them.
    let mut seen = HashSet::new();
    let mut cut_short = false;
    // The hub's WAF rules, applied to each request: what they match is
    // counted here, whatever ModSecurity logs.
    let matcher = crate::waf::hub_rules(state)
        .map(|r| snsec_common::waf::Matcher::new(&r))
        .filter(|m| !m.is_empty());
    let mut waf_hits = crate::waf_conf::Tally::default();
    let mut matched: Vec<u32> = Vec::new();
    let now = crate::util::now_secs();
    // Each log file is a site of its own (panels write one per vhost), unless
    // the format names the vhost.
    let mut file_no: u32 = 0;

    'outer: for src in sources {
        let fmt = LogFormat::from_str_opt(&src.format).unwrap_or(LogFormat::Combined);
        for path in expand_glob(&src.glob) {
            if total_bytes >= CYCLE_BYTE_BUDGET {
                data.catch_up = true;
                cut_short = true;
                break 'outer; // offsets already saved advance next cycle
            }
            data.files_matched += 1;
            file_no = file_no.wrapping_add(1);
            let key = path.to_string_lossy().to_string();
            seen.insert(key.clone());
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
                    if let Some(why) = tail::refusal(&e) {
                        data.refused += 1;
                        data.first_refused
                            .get_or_insert_with(|| format!("{}: {why}", path.display()));
                    }
                    data.first_error
                        .get_or_insert_with(|| format!("{}: {e}", path.display()));
                    continue;
                }
            };
            total_bytes += read.bytes;
            if read.bytes >= MAX_BYTES_PER_FILE {
                data.catch_up = true;
            }
            offsets.insert(key, read.new_offset);
            // The site a WAF example names: the vhost when the format has it,
            // else the log file (one per site on a panel).
            let file_site = path
                .file_name()
                .map(|n| n.to_string_lossy().trim_end_matches(".log").to_string())
                .unwrap_or_default();
            for line in &read.lines {
                data.lines_read += 1;
                match logfmt::parse_line(fmt, line, trusted) {
                    Some(parsed) => {
                        if not_a_visitor(parsed.client, own) {
                            continue;
                        }
                        data.requests += 1;
                        let bankey = net::ban_key(parsed.client);
                        // A trusted proxy (Cloudflare...) is not a client: counting
                        // distinct "IPs" there would count the proxy's own edges.
                        if !net::in_any(trusted, parsed.client) {
                            data.bots.observe(
                                &parsed,
                                bots::hash64(bankey.as_bytes()),
                                parsed.client,
                            );
                        }
                        if let Some(m) = &matcher {
                            m.check(
                                &parsed.method,
                                &parsed.path,
                                &parsed.user_agent,
                                &mut matched,
                            );
                            for id in &matched {
                                waf_hits.add(*id, parsed.status == 403, now, || {
                                    let site = if parsed.host.is_empty() {
                                        file_site.as_str()
                                    } else {
                                        parsed.host.as_str()
                                    };
                                    crate::waf_conf::sample_of(site, &parsed.path)
                                });
                            }
                        }
                        let site = site_of(&parsed, file_no);
                        if let Some(agg) = data.track(bankey) {
                            agg.observe(&parsed, site);
                        }
                    }
                    None => {
                        data.parse_errors += 1;
                        // Still a request from that address: a quirk of the
                        // format that breaks a line must not hide its sender
                        // from the rate check.
                        if let Some(ip) = logfmt::leading_ip(line)
                            && !not_a_visitor(ip, own)
                            && !net::in_any(trusted, ip)
                            && let Some(agg) = data.track(net::ban_key(ip))
                        {
                            agg.observe_unparsed(file_no);
                        }
                    }
                }
            }
        }
    }

    // The log sets left out this cycle: at their end now, so that if they are
    // read again later they start from there (not from where they were left
    // long ago, and not from their end then, losing what came between).
    for glob in dropped {
        for path in expand_glob(glob) {
            let key = path.to_string_lossy().to_string();
            if seen.contains(&key) {
                continue;
            }
            if let Ok(at) = tail::offset_at_end(&path) {
                offsets.insert(key.clone(), at);
                seen.insert(key);
            }
        }
    }

    // Forget files no source matches any more (rotated away, a site removed,
    // a file that stopped passing the owner check), so offsets.json cannot grow
    // without bound. Not after a cut-short cycle: the files it never reached
    // keep their place.
    if !cut_short {
        offsets.retain(|k, _| seen.contains(k));
    }
    crate::waf::add_hits(state, waf_hits);
    state.save_offsets(&offsets)?;
    Ok(data)
}

/// The site a request counts on: its vhost where the log format names it,
/// else the log file it was read from (`file_no`), which on a panel is one per
/// vhost. The two kinds of id never meet.
fn site_of(line: &LogLine, file_no: u32) -> u32 {
    if line.host.is_empty() {
        file_no & !(1 << 31)
    } else {
        bots::hash64(line.host.to_ascii_lowercase().as_bytes()) as u32 | (1 << 31)
    }
}

/// The log sources in effect for this cycle, and how they were chosen.
pub struct Resolved {
    pub sources: Vec<LogSource>,
    /// Every pattern considered, so "found nothing" can say where it looked.
    pub tried: Vec<String>,
    /// The web server detected on :80/:443 (`None` in manual mode).
    pub listener: Option<discover::Listener>,
    /// Log sets left out because another set names the same sites (an
    /// unrecognised front server, where both nginx's and Apache's logs exist).
    pub dropped: Vec<String>,
    /// The patterns read (auto mode), remembered when some were left out.
    pub kept: Vec<String>,
}

/// What the config file lists explicitly (`sources`, or the older `logs`).
fn configured_sources(cfg: &Config) -> Vec<LogSource> {
    if !cfg.watch.sources.is_empty() {
        return cfg.watch.sources.clone();
    }
    cfg.watch
        .logs
        .iter()
        .map(|g| LogSource::new(g.clone(), cfg.watch.format.clone()))
        .collect()
}

/// Choose the logs to follow. In `auto` mode (the default) the agent detects the
/// web server and reads its logs, which is what makes one agent build work on
/// every panel and keeps working after a web-server switch. The explicit sources
/// in the config are only a fallback there. `manual` uses them and nothing else.
/// `prefer`: the log sets read last cycle (see `discover::discover`).
fn resolve_sources(cfg: &Config, conns: &[netstat::Conn], prefer: &[String]) -> Resolved {
    let configured = configured_sources(cfg);
    match cfg.watch.sources_mode {
        SourcesMode::Manual => Resolved {
            tried: configured.iter().map(|s| s.glob.clone()).collect(),
            sources: configured,
            listener: None,
            dropped: Vec::new(),
            kept: Vec::new(),
        },
        SourcesMode::Auto => {
            let listener = discover::detect_listener(conns);
            let found = discover::discover(listener, "", prefer);
            let mut tried = found.tried;
            if found.found.is_empty() {
                // Nothing at the usual places: fall back to whatever is configured.
                tried.extend(configured.iter().map(|s| s.glob.clone()));
                Resolved {
                    sources: configured,
                    tried,
                    listener: Some(listener),
                    dropped: Vec::new(),
                    kept: Vec::new(),
                }
            } else {
                Resolved {
                    sources: found.found,
                    tried,
                    listener: Some(listener),
                    dropped: found.dropped,
                    kept: found.kept,
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
    // The sets the watch cycles have been reading, as they would pick again.
    let prefer = State::open().map(|s| s.meta().log_sets).unwrap_or_default();
    let resolved = resolve_sources(cfg, &netstat::all(), &prefer);
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

/// Matched logs left unread because they are not what the web server writes (a
/// symlink, not a regular file, another owner, writable by others). Raised even
/// when other logs are read: the traffic in these is not seen at all.
fn refused_alert(refused: u32, first: Option<&str>) -> Option<snsec_common::schema::Alert> {
    (refused > 0).then(|| snsec_common::schema::Alert {
        kind: "log_refused".into(),
        message: format!(
            "{refused} log file(s) skipped as unsafe to read ({}); a log must be a regular file owned by root or the web server and not writable by group or others",
            first.unwrap_or("unknown")
        ),
        severity: "warn".into(),
    })
}

fn top_ips(data: &CycleData) -> Vec<IpCount> {
    let mut v: Vec<IpCount> = data
        .per_ip
        .iter()
        .map(|(k, a)| IpCount {
            ip: k.clone(),
            requests: u64::from(a.requests),
            err4xx: u64::from(a.err4xx),
            sensitive_posts: u64::from(a.login_posts) + u64::from(a.xmlrpc_posts),
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

/// A 120 ms look at the CPU, used only when there is no earlier sample to
/// compare with (the first cycle, or after a reboot or a long gap).
fn quick_cpu_busy() -> f64 {
    use crate::sys::proc;
    let (t0, i0) = proc::cpu_total_idle().unwrap_or((0, 0));
    std::thread::sleep(std::time::Duration::from_millis(120));
    let (t1, i1) = proc::cpu_total_idle().unwrap_or((0, 0));
    if t1 > t0 {
        100.0 * (1.0 - (i1.saturating_sub(i0)) as f64 / (t1 - t0).max(1) as f64)
    } else {
        0.0
    }
}

struct CpuReading {
    /// Busy % averaged since the previous cycle (a short sample the first time).
    busy: f64,
    groups: Vec<snsec_common::schema::CpuGroup>,
    streak: u32,
    alert: Option<snsec_common::schema::Alert>,
    /// A long time passed since the previous cycle (agent was off or stalled).
    gap: bool,
}

/// Compare the CPU counters with the ones stored last cycle, store the new ones,
/// and name who used the CPU. Never fails the cycle: a missing or unreadable
/// `/proc` just means no reading.
fn measure_cpu(state: &State, now: i64, threshold: f64, prev_streak: u32) -> CpuReading {
    use crate::sys::proc;
    let prev = state.cpu_sample();
    let (total, idle) = proc::cpu_total_idle().unwrap_or((0, 0));
    let procs = proc::cpu_procs();
    let busy_opt = cpu::busy_pct(&prev, now, total, idle);

    let groups = if busy_opt.is_some_and(|b| b >= cpu::GROUPS_MIN_BUSY) {
        let mut users: HashMap<i32, String> = HashMap::new();
        let rows: Vec<(String, String, u64)> = cpu::deltas(&prev, &procs)
            .into_iter()
            .map(|(p, d)| {
                let user = users
                    .entry(p.pid)
                    .or_insert_with(|| {
                        proc::uid(p.pid)
                            .map(proc::username)
                            .unwrap_or_else(|| "?".to_string())
                    })
                    .clone();
                (user, p.comm.clone(), d)
            })
            .collect();
        cpu::group(&rows, total.saturating_sub(prev.total))
    } else {
        Vec::new()
    };

    if total > 0
        && let Err(e) = state.save_cpu_sample(&cpu::make_sample(now, total, idle, &procs))
    {
        eprintln!("watch: save cpu sample: {e:#}");
    }

    let busy = busy_opt.unwrap_or_else(quick_cpu_busy);
    let streak = cpu::next_streak(prev_streak, busy_opt, threshold);
    let alert = (busy_opt.is_some() && streak >= cpu::CPU_STREAK_ALERT).then(|| {
        snsec_common::schema::Alert {
            kind: "cpu_high".into(),
            message: cpu::describe(busy, streak, &groups),
            severity: "warn".into(),
        }
    });
    CpuReading {
        busy,
        groups,
        streak,
        alert,
        gap: cpu::is_gap(&prev, now),
    }
}

fn load_baseline(state: &State) -> Baseline {
    std::fs::read(state.dir.join("baseline.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Baseline>(&b).ok())
        .unwrap_or_default()
        .checked()
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
                let site = site_of(&p, 0);
                per_ip
                    .entry(net::ban_key(p.client))
                    .or_default()
                    .observe(&p, site);
            }
            None => parse_errors += 1,
        }
    }
    // Judged as one cycle of a server whose baseline is learned, at the floor.
    let judge = Judge {
        threshold: u64::from(cfg.watch.min_requests),
        baseline_ready: true,
        ceiling: ABS_CEILING,
        volume: true,
        crawler: false,
        span: 300,
        volume_exempt: false,
    };
    let never_ban = cfg.never_ban_cidrs();
    let mut bans = 0u64;
    println!("== replay {} ==", path.display());
    println!("parsed {parsed_ok} lines, {parse_errors} parse errors");
    for (key, agg) in &per_ip {
        if whitelist::key_protected(key, &whitelist::Whitelist::default(), &never_ban) {
            continue;
        }
        let j = Judge {
            crawler: crawler_of(key).is_some(),
            ..judge
        };
        if let Some(hit) = patterns::judge(agg, &j)
            && hit.ban
        {
            bans += 1;
            println!(
                "would_ban {key:<20} reason={:<16} ttl={:<6} req={} dyn={} 404={} posts={}",
                hit.reason,
                hit.ttl_secs,
                agg.requests,
                agg.dynamic(),
                agg.err404,
                u64::from(agg.login_posts) + u64::from(agg.xmlrpc_posts)
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
    fn offsets_are_kept_only_for_files_still_matched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let state = State::at(dir.path().join("state"));
        let src = [LogSource::new(
            format!("{}/*.log", logs.display()),
            "combined".into(),
        )];
        let a = logs.join("a.log");
        let b = logs.join("b.log");
        for p in [&a, &b] {
            std::fs::write(p, "x\n").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        collect(&state, &[], &[], &src, &[]).unwrap();
        assert_eq!(state.offsets().len(), 2);

        // A file that cannot be read this cycle keeps its place.
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o666)).unwrap();
        let d = collect(&state, &[], &[], &src, &[]).unwrap();
        assert_eq!(d.unreadable, 1);
        assert_eq!(state.offsets().len(), 2);

        // A file no glob matches any more is forgotten.
        std::fs::remove_file(&b).unwrap();
        collect(&state, &[], &[], &src, &[]).unwrap();
        let keys: Vec<String> = state.offsets().into_keys().collect();
        assert_eq!(keys, [a.to_string_lossy().to_string()]);
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

    #[test]
    fn an_unrecognised_front_server_is_named() {
        let resolved = |listener, dropped: Vec<String>| Resolved {
            sources: Vec::new(),
            tried: Vec::new(),
            listener,
            dropped,
            kept: Vec::new(),
        };
        let unknown = resolved(
            Some(discover::Listener::Unknown),
            vec!["/var/log/httpd/domains/*.log".into()],
        );
        let a = listener_alert(&unknown, 4, true).unwrap();
        assert_eq!(a.kind, "listener_unknown");
        assert!(
            a.message.contains("/var/log/httpd/domains/*.log"),
            "{}",
            a.message
        );
        assert!(listener_alert(&unknown, 0, true).is_none(), "nothing read");
        // Nothing on :80/:443 at all (the web server is down): not this alert.
        assert!(listener_alert(&unknown, 4, false).is_none());
        let known = resolved(Some(discover::Listener::Nginx), Vec::new());
        assert!(listener_alert(&known, 4, true).is_none());
        assert!(
            listener_alert(&resolved(None, Vec::new()), 4, true).is_none(),
            "manual"
        );
    }

    #[test]
    fn every_vhost_log_is_a_site_of_its_own() {
        use std::io::Write;
        const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0) Chrome/148.0.0.0 Safari/537.36";
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let state = State::at(dir.path().join("state"));
        let src = [LogSource::new(
            format!("{}/*.log", logs.display()),
            "combined".into(),
        )];
        let sites = [logs.join("shop.example.log"), logs.join("blog.example.log")];
        for p in &sites {
            std::fs::write(p, "").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        collect(&state, &[], &[], &src, &[]).unwrap();
        for p in &sites {
            let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
            for i in 0..200 {
                writeln!(
                    f,
                    r#"203.0.113.9 - - [10/Oct/2026:01:02:03 +0000] "GET /?p={i} HTTP/1.1" 200 1 "-" "{BROWSER}""#
                )
                .unwrap();
            }
        }
        let d = collect(&state, &[], &[], &src, &[]).unwrap();
        let a = &d.per_ip["203.0.113.9"];
        assert_eq!((a.dynamic(), a.site_dynamic()), (400, 200));
        // A format that names the vhost counts by vhost instead.
        let l = logfmt::parse_line(
            LogFormat::Combined,
            r#"203.0.113.9 - - [x] "GET / HTTP/1.1" 200 1 "-" "x""#,
            &[],
        )
        .unwrap();
        assert_eq!(site_of(&l, 7), 7);
        let named = LogLine {
            host: "Shop.Example".into(),
            ..l.clone()
        };
        let other = LogLine {
            host: "shop.example".into(),
            ..l
        };
        assert_eq!(site_of(&named, 7), site_of(&other, 9));
        assert_ne!(site_of(&named, 7), 7);
    }

    #[test]
    fn waf_rules_are_counted_from_the_access_logs() {
        use snsec_common::waf::{WafKind, WafRule};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let state = State::at(dir.path().join("state"));
        let src = [LogSource::new(
            format!("{}/*.log", logs.display()),
            "combined".into(),
        )];
        let log = logs.join("shop.example.log");
        std::fs::write(&log, "").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        crate::waf::set_rules(
            &state,
            &[
                WafRule {
                    id: 60_001,
                    kind: WafKind::Path,
                    value: "/.env".into(),
                    block: false,
                },
                WafRule {
                    id: 60_002,
                    kind: WafKind::UaToken,
                    value: "sqlmap".into(),
                    block: true,
                },
            ],
        );
        collect(&state, &[], &[], &src, &[]).unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        for line in [
            r#"198.51.100.7 - - [x] "GET /.env HTTP/1.1" 404 1 "-" "curl/8""#,
            r#"198.51.100.7 - - [x] "GET //./.env?a=1 HTTP/1.1" 404 1 "-" "curl/8""#,
            r#"198.51.100.8 - - [x] "GET /?id=1 HTTP/1.1" 403 1 "-" "sqlmap/1.8""#,
            r#"198.51.100.9 - - [x] "GET /shop HTTP/1.1" 200 1 "-" "Mozilla/5.0""#,
        ] {
            writeln!(f, "{line}").unwrap();
        }
        collect(&state, &[], &[], &src, &[]).unwrap();
        let st = crate::waf::status(&state, true);
        let by_id = |id| st.hits.iter().find(|h| h.id == id).unwrap();
        assert_eq!(by_id(60_001).count, 2);
        assert_eq!(by_id(60_001).blocked, 0);
        assert_eq!(
            by_id(60_001).samples,
            vec!["shop.example /.env".to_string()]
        );
        assert_eq!((by_id(60_002).count, by_id(60_002).blocked), (1, 1));
        // Taken by that report: the next one starts from zero.
        assert!(crate::waf::status(&state, true).hits.is_empty());
    }

    #[test]
    fn refused_logs_are_named_and_unparsable_lines_still_count() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let state = State::at(dir.path().join("state"));
        let src = [LogSource::new(
            format!("{}/*.log", logs.display()),
            "combined".into(),
        )];
        let good = logs.join("a.log");
        let open = logs.join("b.log");
        for (p, mode) in [(&good, 0o644), (&open, 0o666)] {
            std::fs::write(p, "x\n").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let d = collect(&state, &[], &[], &src, &[]).unwrap();
        assert_eq!((d.unreadable, d.refused), (1, 1));
        let first = d.first_refused.as_deref().unwrap();
        assert!(
            first.contains("b.log") && first.contains("writable"),
            "{first}"
        );
        // Raised although another log is read.
        let a = refused_alert(d.refused, d.first_refused.as_deref()).unwrap();
        assert_eq!(
            (a.kind.as_str(), a.severity.as_str()),
            ("log_refused", "warn")
        );
        assert!(a.message.contains("b.log"), "{}", a.message);
        assert!(refused_alert(0, None).is_none());

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&good)
            .unwrap();
        writeln!(
            f,
            r#"203.0.113.9 - - [10/Oct/2026:01:02:03 +0000] "GET / HTTP/1.1" 200 1 "-" "ua""#
        )
        .unwrap();
        writeln!(f, "203.0.113.9 - - [10/Oct/2026:01:02:03 +0000] \"GET /").unwrap();
        writeln!(f, "203.0.113.9 some future layout").unwrap();
        writeln!(f, "127.0.0.1 local junk").unwrap();
        writeln!(f, "junk without an address").unwrap();
        drop(f);
        let d = collect(&state, &[], &[], &src, &[]).unwrap();
        assert_eq!((d.lines_read, d.parse_errors, d.requests), (5, 4, 1));
        assert_eq!(d.per_ip["203.0.113.9"].requests, 3);
        assert_eq!(d.per_ip.len(), 1);
    }

    #[test]
    fn the_vps_own_requests_are_not_counted_and_a_set_left_out_moves_to_its_end() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let read = dir.path().join("nginx");
        let left = dir.path().join("httpd");
        for d in [&read, &left] {
            std::fs::create_dir(d).unwrap();
        }
        let state = State::at(dir.path().join("state"));
        let src = [LogSource::new(
            format!("{}/*.log", read.display()),
            "combined".into(),
        )];
        let dropped = [format!("{}/*.log", left.display())];
        let (a, b) = (read.join("shop.log"), left.join("shop.log"));
        for p in [&a, &b] {
            std::fs::write(p, "").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        collect(&state, &[], &[], &src, &dropped).unwrap();
        let line = |ip: &str| {
            format!(
                r#"{ip} - - [10/Oct/2026:01:02:03 +0000] "GET /wp-cron.php HTTP/1.1" 200 1 "-" "WordPress/6.6""#
            )
        };
        for p in [&a, &b] {
            let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
            for ip in [
                "198.51.100.20",
                "2001:db8:5:6::10",
                "2001:db8:5:6::99",
                "203.0.113.9",
            ] {
                writeln!(f, "{}", line(ip)).unwrap();
            }
        }
        // The VPS's own addresses (its public one behind a cloud's NAT, its
        // IPv6): their cron, loopback and preload requests are not visitors.
        let own: [IpAddr; 2] = [
            "198.51.100.20".parse().unwrap(),
            "2001:db8:5:6::10".parse().unwrap(),
        ];
        let d = collect(&state, &[], &own, &src, &dropped).unwrap();
        let mut keys: Vec<&str> = d.per_ip.keys().map(String::as_str).collect();
        keys.sort_unstable();
        // A neighbour in the same /64 still counts.
        assert_eq!(keys, ["2001:db8:5:6::/64", "203.0.113.9"]);
        assert_eq!(d.per_ip["2001:db8:5:6::/64"].requests, 1);
        // The set left out was not read, but its place moved with it.
        assert_eq!(d.lines_read, 4);
        let offsets = state.offsets();
        let at = offsets[&b.to_string_lossy().to_string()];
        assert_eq!(at.pos, std::fs::metadata(&b).unwrap().len());
        assert!(at.pos > 0);
    }
}
