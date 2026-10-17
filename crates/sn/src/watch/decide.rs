//! What a cycle does with the addresses that matched a rule: which are banned
//! and for how long (the strike ladder), which are only reported, and the
//! alerts that say why. Kept apart from the log reading and the firewall, and
//! free of anything Linux-specific, so it can be tested on its own.

use std::collections::HashMap;

use snsec_common::schema::{Alert, BanEvent};

use super::patterns::{self, IpAgg, PatternHit};
use crate::state::{ActiveBan, Strike};

/// The stretch of log the thresholds are written for: one timer interval.
const CYCLE_SECS: i64 = 300;
/// The longest stretch since the last cycle that is still judged by `rate`
/// and `scanner` (with thresholds scaled to it). Longer means the agent was
/// off (timer stopped, reboot, VM paused) and the read is a backlog: hours of
/// ordinary traffic in one go, which those rules would take for floods.
pub(super) const MAX_SPAN_JUDGED: i64 = 900;
/// Spans are clamped to this before scaling.
const MAX_SPAN: i64 = 3600;
/// Dynamic requests on one site in one cycle (ten a second) at or above which
/// a `rate` hit bans whatever else is known: while the baseline is still
/// learning, from a proxy-looking address, and above any learned threshold
/// (the threshold itself never goes past it).
pub(super) const ABS_CEILING: u64 = 3000;
/// More `rate` bans than this in one cycle is a storm: a threshold far too low
/// for this traffic. Then the browser-looking and shared addresses under
/// [`STORM_FACTOR`] times the threshold are only reported; floods from tools,
/// libraries or no User-Agent are banned as usual.
const RATE_STORM_BANS: usize = 20;
pub(super) const STORM_FACTOR: u64 = 3;
/// Cycles after a gap that may still be reading its backlog (each read hit its
/// byte cap): `rate` and `scanner` wait until the reads reach the end of the
/// logs, but not longer than this, so a flood that keeps the reads capped is
/// judged again soon.
const GAP_CATCH_UP_CYCLES: u32 = 3;
/// How long after the admin unbanned an address from the hub `rate` and
/// `scanner` only report it (unless it passes the ceiling).
pub(super) const UNBAN_GRACE_SECS: i64 = 6 * 3600;
/// Most unbanned addresses remembered for that grace.
const MAX_UNBANNED: usize = 10_000;

/// Seconds of log this cycle covers: since the last cycle started, at least one
/// interval, at most [`MAX_SPAN`]. One interval when there was no earlier cycle
/// or the clock went back.
pub(super) fn cycle_span(prev: i64, now: i64) -> i64 {
    if prev <= 0 || prev > now {
        CYCLE_SECS
    } else {
        (now - prev).clamp(CYCLE_SECS, MAX_SPAN)
    }
}

/// A per-interval count scaled to a span of log.
pub(super) fn scale(per_cycle: u64, span: i64) -> u64 {
    per_cycle.saturating_mul(span.clamp(CYCLE_SECS, MAX_SPAN) as u64) / CYCLE_SECS as u64
}

/// A count over a span of log brought back to one interval.
pub(super) fn per_cycle(count: u64, span: i64) -> u64 {
    count.saturating_mul(CYCLE_SECS as u64) / span.clamp(CYCLE_SECS, MAX_SPAN) as u64
}

/// Is this cycle's read a backlog, so `rate` and `scanner` are not judged? Only
/// after a real gap: more than [`MAX_SPAN_JUDGED`] since the last cycle, or one
/// of the next [`GAP_CATCH_UP_CYCLES`] cycles while the reads still hit their
/// byte cap. A read cut short by a flood without a gap is judged: it covers
/// less time than the span, so the thresholds only err on the high side.
/// Returns `(backlog, catch-up cycles left after this one)`.
pub(super) fn backlog_state(span: i64, catch_up: bool, left: u32) -> (bool, u32) {
    let gap = span > MAX_SPAN_JUDGED;
    let backlog = gap || left > 0;
    let next = if !catch_up {
        0
    } else if gap {
        GAP_CATCH_UP_CYCLES
    } else {
        left.saturating_sub(1)
    };
    (backlog, next)
}

/// Is `key` within the grace that follows an unban from the hub?
pub(crate) fn unban_grace(unbanned: &HashMap<String, i64>, key: &str, now: i64) -> bool {
    unbanned
        .get(key)
        .is_some_and(|at| *at <= now + 60 && now - at < UNBAN_GRACE_SECS)
}

/// Forget unbans past their grace, and keep at most [`MAX_UNBANNED`] (the
/// most recent).
pub(crate) fn prune_unbanned(unbanned: &mut HashMap<String, i64>, now: i64) {
    unbanned.retain(|_, at| *at <= now + 60 && now - *at < UNBAN_GRACE_SECS);
    if unbanned.len() > MAX_UNBANNED {
        let mut by_age: Vec<(i64, String)> =
            unbanned.iter().map(|(k, at)| (*at, k.clone())).collect();
        by_age.sort_unstable_by(|a, b| b.cmp(a));
        for (_, k) in by_age.into_iter().skip(MAX_UNBANNED) {
            unbanned.remove(&k);
        }
    }
}

/// Keep the bans still running, and those that ended within the longest span
/// a cycle judges: the log of the next cycle may still have been written
/// while they were in force.
pub(super) fn prune_active(active: &mut HashMap<String, ActiveBan>, now: i64) {
    active.retain(|_, b| b.expires_ts > now - MAX_SPAN_JUDGED);
}

/// Report-only entries one report carries; the rest are only counted.
const MAX_REPORT_ONLY: usize = 200;

/// An address that matched a rule this cycle, and what it matched.
pub(super) struct Candidate<'a> {
    pub(super) key: &'a String,
    pub(super) agg: &'a IpAgg,
    pub(super) hit: PatternHit,
}

/// What one cycle decides, before anything is applied.
pub(super) struct Decisions {
    /// Bans applied this cycle (enforce mode).
    pub(super) applied: Vec<BanEvent>,
    /// Report-only hits, and in observe mode the bans enforce would apply.
    pub(super) would: Vec<BanEvent>,
    /// `(key, ttl)` for the firewall.
    pub(super) to_add: Vec<(String, u64)>,
    /// Addresses that matched a rule but are in neither list.
    pub(super) unlisted: u64,
    /// A rate storm: `(rate bans kept, rate bans held back as reports)`.
    pub(super) storm: Option<(usize, usize)>,
}

/// What one cycle's decisions need besides the candidates.
pub(super) struct Cycle {
    /// Dynamic requests (per site) from which a `rate` hit is banned even in
    /// a storm: [`STORM_FACTOR`] times the threshold.
    pub(super) storm_floor: u64,
    pub(super) ban_cap: usize,
    pub(super) enforce: bool,
    pub(super) now: i64,
    /// Seconds of log this cycle covers.
    pub(super) span: i64,
}

/// Decide what to do with `candidates`, busiest first and none of them
/// protected. At most `ban_cap` bans (enforce stops there and raises
/// `ban_cap`) and [`MAX_REPORT_ONLY`] report-only entries are listed, so
/// however many addresses a flood brings the report stays small.
///
/// More than [`RATE_STORM_BANS`] `rate` bans in one cycle is a storm: the
/// browser-looking and shared ones under `storm_floor` are only reported. An
/// address whose ban was in force during any of this cycle's stretch of log is
/// left alone for the same reason, or when its ban lasts longer than this
/// offence asks: its established connections kept showing up in the log while
/// it was banned, and that is no new offence. Strikes change only in enforce
/// mode, and only for the bans applied.
pub(super) fn decide_bans(
    candidates: &[Candidate],
    cy: &Cycle,
    strikes: &mut HashMap<String, Strike>,
    active: &mut HashMap<String, ActiveBan>,
) -> Decisions {
    let (now, enforce, ban_cap) = (cy.now, cy.enforce, cy.ban_cap);
    let mut d = Decisions {
        applied: Vec::new(),
        would: Vec::new(),
        to_add: Vec::new(),
        unlisted: 0,
        storm: None,
    };
    let is_rate_ban = |h: &PatternHit| h.ban && h.reason == "rate";
    let far_over = |a: &IpAgg| {
        a.site_dynamic() >= cy.storm_floor
            || a.lines() >= cy.storm_floor.saturating_mul(patterns::TOTAL_FACTOR)
    };
    // What a threshold set too low for this traffic bans: browsers and shared
    // addresses. A flood from a tool, a library or no User-Agent is banned in a
    // storm too.
    let rate_bans = candidates.iter().filter(|c| is_rate_ban(&c.hit)).count();
    let storm = rate_bans > RATE_STORM_BANS;
    let held_back = |c: &Candidate| {
        storm
            && is_rate_ban(&c.hit)
            && (c.agg.browser_looking() || !c.hit.escalate)
            && !far_over(c.agg)
    };
    if storm {
        let held = candidates.iter().filter(|c| held_back(c)).count();
        d.storm = Some((rate_bans - held, held));
    }
    let (mut banned, mut reported) = (0usize, 0usize);
    for c in candidates {
        let key = c.key;
        let mut hit = c.hit.clone();
        if held_back(c) {
            hit = PatternHit {
                ttl_secs: 0,
                ban: false,
                escalate: false,
                ttl_cap: 0,
                ..hit
            };
        }
        if !hit.ban {
            // Report-only pattern. The busiest are enough to see what goes on;
            // one per address would let a crowd of addresses swell the report
            // past what the hub accepts.
            if reported >= MAX_REPORT_ONLY {
                d.unlisted += 1;
                continue;
            }
            reported += 1;
            d.would.push(BanEvent {
                ip: key.clone(),
                reason: hit.reason.to_string(),
                ttl_secs: 0,
                strike: 0,
                layer: "report".into(),
            });
            continue;
        }
        if let Some(b) = active.get(key.as_str())
            && b.expires_ts > now - cy.span
            && (b.reason == hit.reason || hit.ttl_secs <= (b.expires_ts - now).max(0) as u64)
        {
            continue;
        }
        if banned >= ban_cap {
            // Too many bans: likely distributed attack or broken rule. Checked
            // before the strike, so an address left alone is not counted.
            if enforce {
                break;
            }
            d.unlisted += 1;
            continue;
        }
        banned += 1;

        let (ttl, strike) = strike_ttl(strikes, key, &hit, now, enforce);
        let ev = BanEvent {
            ip: key.clone(),
            reason: hit.reason.to_string(),
            ttl_secs: ttl,
            strike,
            layer: "l3".into(),
        };
        if enforce {
            d.to_add.push((key.clone(), ttl));
            active.insert(
                key.clone(),
                ActiveBan {
                    reason: hit.reason.to_string(),
                    expires_ts: now + ttl as i64,
                    strike,
                    layer: "l3".into(),
                },
            );
            d.applied.push(ev);
        } else {
            d.would.push(ev);
        }
    }
    d
}

/// Addresses whose `rate` hit was only reported because they look like a proxy
/// or CDN edge (many rendering browsers): the operator should know.
pub(super) fn proxy_keys(candidates: &[Candidate]) -> Vec<String> {
    candidates
        .iter()
        .filter(|c| c.agg.looks_like_proxy() && c.hit.reason == "rate" && !c.hit.ban)
        .map(|c| c.key.clone())
        .collect()
}

/// A clean week resets the strike ladder...
const STRIKE_DECAY_SECS: i64 = 7 * 86_400;
/// ...a clean day, for an address whose every offence was `rate`: a busy shared
/// address (an office, a carrier NAT) is not an attacker that came back.
const RATE_STRIKE_DECAY_SECS: i64 = 86_400;
/// Most addresses (or /64s) strikes.json remembers.
const MAX_STRIKES: usize = 100_000;

fn decay_of(s: &Strike) -> i64 {
    if s.rate_only {
        RATE_STRIKE_DECAY_SECS
    } else {
        STRIKE_DECAY_SECS
    }
}

/// The key's strike entry after one more offence that climbs the ladder.
fn next_strike(prev: Option<&Strike>, hit: &PatternHit, now: i64) -> Strike {
    let mut s = match prev {
        Some(p) if now - p.last_ts <= decay_of(p) => p.clone(),
        _ => Strike {
            count: 0,
            last_ts: now,
            rate_only: true,
        },
    };
    s.count = s.count.saturating_add(1);
    s.last_ts = now;
    s.rate_only &= hit.reason == "rate";
    s
}

/// The ban length for an offence and its strike number. An offence that may
/// escalate counts on the key's ladder (a clean week, or a clean day for
/// rate-only offences, resets it), up to its `ttl_cap`; one that may not gets
/// exactly its own ban, and is neither counted nor lengthened by earlier
/// strikes (strike 0). With `record` false (observe mode) nothing is written:
/// a would-be ban must not make the first real one longer.
pub(super) fn strike_ttl(
    strikes: &mut HashMap<String, Strike>,
    key: &str,
    hit: &PatternHit,
    now: i64,
    record: bool,
) -> (u64, u32) {
    if !hit.escalate {
        return (hit.ttl_secs, 0);
    }
    let s = next_strike(strikes.get(key), hit, now);
    let mut ttl = hit.ttl_secs.max(ladder_ttl(s.count));
    if hit.ttl_cap > 0 {
        ttl = ttl.min(hit.ttl_cap.max(hit.ttl_secs));
    }
    let count = s.count;
    if record {
        strikes.insert(key.to_string(), s);
    }
    (ttl, count)
}

fn ladder_ttl(strike: u32) -> u64 {
    match strike {
        0 | 1 => 600,    // 10 min
        2 => 3600,       // 1 hour
        3 => 86_400,     // 24 hours
        _ => 7 * 86_400, // 7 days
    }
}

/// Forget strikes past their decay window, which count as none anyway, and
/// keep at most [`MAX_STRIKES`], the most recent first, so strikes.json stays
/// small however many addresses a flood brings.
pub(super) fn prune_strikes(strikes: &mut HashMap<String, Strike>, now: i64) {
    strikes.retain(|_, s| now - s.last_ts <= decay_of(s));
    let excess = strikes.len().saturating_sub(MAX_STRIKES);
    if excess == 0 {
        return;
    }
    let mut oldest: Vec<(i64, u32, String)> = strikes
        .iter()
        .map(|(k, s)| (s.last_ts, s.count, k.clone()))
        .collect();
    oldest.select_nth_unstable(excess - 1);
    for (_, _, k) in oldest.into_iter().take(excess) {
        strikes.remove(&k);
    }
}

pub(super) fn alert(kind: &str, severity: &str, message: String) -> Alert {
    Alert {
        kind: kind.into(),
        message,
        severity: severity.into(),
    }
}

/// Too many `rate` bans at once: the browser-looking ones were held back.
/// Urgent: either the threshold is wrong for this traffic, or a wave of
/// browser-looking addresses is under way that only a WAF rule can stop.
pub(super) fn storm_alert(storm: Option<(usize, usize)>, threshold: u64) -> Option<Alert> {
    let (kept, held) = storm?;
    Some(alert(
        "rate_storm",
        "urgent",
        format!(
            "{} addresses passed the request-rate threshold ({threshold} dynamic requests per site) in one cycle; {kept} were banned (floods from tools, libraries or no User-Agent, and anything at {STORM_FACTOR}x or more), {held} browser-looking or shared ones only reported. The threshold may be too low for this traffic, or this is a wave of browser-looking bots that needs a WAF rule",
            kept + held
        ),
    ))
}

/// The first few of `keys`, joined, with "..." when there are more.
fn some_of(keys: &[String]) -> String {
    let shown: Vec<&str> = keys.iter().take(5).map(String::as_str).collect();
    format!(
        "{}{}",
        shown.join(", "),
        if keys.len() > shown.len() {
            ", ..."
        } else {
            ""
        }
    )
}

/// Proxy-looking addresses whose rate hit was only reported.
pub(super) fn proxy_alert(keys: &[String]) -> Option<Alert> {
    if keys.is_empty() {
        return None;
    }
    Some(alert(
        "proxy_in_logs",
        "warn",
        format!(
            "{} address(es) carry many different browsers, like a proxy or CDN edge, and passed the request-rate threshold: {}. They were not banned (banning an edge cuts off everyone behind it). If it is a proxy, add its ranges to trusted_proxies so the real visitors are seen",
            keys.len(),
            some_of(keys)
        ),
    ))
}

/// Attack patterns from Cloudflare addresses that carry visitors: never
/// banned here (it would cut every visitor routed through that edge off), so
/// the operator must stop them at Cloudflare or in the WAF.
pub(super) fn cloudflare_alert(keys: &[String]) -> Option<Alert> {
    if keys.is_empty() {
        return None;
    }
    Some(alert(
        "attack_via_cloudflare",
        "warn",
        format!(
            "{} Cloudflare address(es) sent requests that match an attack rule (password guessing, probes, scanning tools): {}. A Cloudflare edge is not banned on the VPS, as every visitor behind it would be cut off; block the attacker in Cloudflare (WAF rule) or restore real visitor addresses (trusted_proxies with a log format that carries them)",
            keys.len(),
            some_of(keys)
        ),
    ))
}

/// A backlog was read: `rate` and `scanner` were not judged.
pub(super) fn backlog_alert(skipped: bool, span: i64) -> Option<Alert> {
    skipped.then(|| {
        alert(
            "backlog_skipped",
            "info",
            format!(
                "this cycle read a backlog (about {} minutes of log, or more than one cycle can read at once); the request-rate and 404-scan rules were not applied to it, the others were",
                span / 60
            ),
        )
    })
}

/// `[watch]` keys written under a `[[watch.sources]]` entry.
pub(super) fn misplaced_alert(keys: &[String]) -> Option<Alert> {
    if keys.is_empty() {
        return None;
    }
    Some(alert(
        "config_misplaced",
        "warn",
        format!(
            "/etc/sn/agent.toml has key(s) under a [[watch.sources]] entry, where they do nothing: {}. Move them above the first [[watch.sources]] line",
            keys.join(", ")
        ),
    ))
}

/// Addresses that matched a rule but are not in the report: report-only past
/// [`MAX_REPORT_ONLY`], or would-be bans past the per-cycle ban cap in observe
/// mode (in enforce mode that is the `ban_cap` alert).
pub(super) fn unlisted_alert(unlisted: u64) -> Option<Alert> {
    (unlisted > 0).then(|| Alert {
        kind: "report_cap".into(),
        message: format!(
            "{unlisted} more address(es) matched a rule this cycle; the report lists only the busiest"
        ),
        severity: "warn".into(),
    })
}

/// What the baseline learns from one cycle: of the ordinary addresses (none
/// that matched a rule or reached the bar, sorted busiest first), the third
/// busiest, or the least busy of fewer. One or two flooders never set what is
/// normal.
pub(super) fn robust_busiest(desc: &[u64]) -> u64 {
    desc.get(2).or(desc.last()).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use patterns::Judge;
    use snsec_common::logfmt::{self, LogFormat};

    #[test]
    fn strikes_past_the_decay_window_are_forgotten_and_the_map_is_capped() {
        let now: i64 = 1_000_000_000;
        let strike = |count, age: i64| Strike {
            count,
            last_ts: now - age,
            rate_only: false,
        };
        let mut s: HashMap<String, Strike> = HashMap::new();
        s.insert("old".into(), strike(4, STRIKE_DECAY_SECS + 1));
        s.insert("week".into(), strike(4, STRIKE_DECAY_SECS));
        s.insert("new".into(), strike(1, 0));
        // Rate-only offences are forgotten after a clean day.
        let rate = |age: i64| Strike {
            rate_only: true,
            ..strike(3, age)
        };
        s.insert("rate-day".into(), rate(RATE_STRIKE_DECAY_SECS));
        s.insert("rate-old".into(), rate(RATE_STRIKE_DECAY_SECS + 1));
        prune_strikes(&mut s, now);
        let mut keys: Vec<&str> = s.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["new", "rate-day", "week"]);

        // A flood of distinct addresses: the oldest strikes go first.
        let n = MAX_STRIKES + 10;
        let mut s: HashMap<String, Strike> = (0..n)
            .map(|i| (format!("k{i}"), strike(1, (n - i) as i64)))
            .collect();
        prune_strikes(&mut s, now);
        assert_eq!(s.len(), MAX_STRIKES);
        assert!(!s.contains_key("k0") && !s.contains_key("k9"));
        assert!(s.contains_key("k10") && s.contains_key(&format!("k{}", n - 1)));
    }

    const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0) Chrome/148.0.0.0 Safari/537.36";
    const NOW: i64 = 1_000_000_000;

    /// One address's cycle on one site: `(path, status, user agent, times)`.
    fn agg(requests: &[(&str, u16, &str, usize)]) -> IpAgg {
        let mut a = IpAgg::default();
        for &(path, status, ua, times) in requests {
            let l = format!(
                r#"198.51.100.7 - - [10/Oct/2026:01:02:03 +0000] "GET {path} HTTP/1.1" {status} 1 "-" "{ua}""#
            );
            let parsed = logfmt::parse_line(LogFormat::Combined, &l, &[]).unwrap();
            for _ in 0..times {
                a.observe(&parsed, 1);
            }
        }
        a
    }

    /// A server whose baseline has learned its traffic.
    fn ready(threshold: u64) -> Judge {
        Judge {
            threshold,
            baseline_ready: true,
            ceiling: ABS_CEILING,
            volume: true,
            crawler: false,
            span: CYCLE_SECS,
            volume_exempt: false,
            // The ban logic is what these tests exercise.
            rate_bans: true,
        }
    }

    /// The addresses that matched something, as `run` hands them on.
    fn cands<'a>(keys: &'a [String], aggs: &'a [IpAgg], threshold: u64) -> Vec<Candidate<'a>> {
        keys.iter()
            .zip(aggs)
            .filter_map(|(key, agg)| {
                patterns::judge(agg, &ready(threshold)).map(|hit| Candidate { key, agg, hit })
            })
            .collect()
    }

    fn cycle(threshold: u64, ban_cap: usize, enforce: bool, now: i64) -> Cycle {
        Cycle {
            storm_floor: threshold * STORM_FACTOR,
            ban_cap,
            enforce,
            now,
            span: CYCLE_SECS,
        }
    }

    /// What a page with a few `<img>` tags makes its visitor's browser send.
    fn lured() -> IpAgg {
        let mut r = vec![
            ("/.env", 404, BROWSER, 1),
            ("/.git/config", 404, BROWSER, 1),
            ("/phpmyadmin/", 404, BROWSER, 1),
        ];
        let misses: Vec<String> = (0..10).map(|i| format!("/old{i}.php")).collect();
        r.extend(misses.iter().map(|p| (p.as_str(), 404, BROWSER, 1)));
        agg(&r)
    }

    fn decide_with(
        a: IpAgg,
        enforce: bool,
        strikes: &mut HashMap<String, Strike>,
        active: &mut HashMap<String, ActiveBan>,
    ) -> Decisions {
        let keys = ["198.51.100.7".to_string()];
        let aggs = [a];
        decide_bans(
            &cands(&keys, &aggs, 300),
            &cycle(300, 200, enforce, NOW),
            strikes,
            active,
        )
    }

    fn decide_one(a: IpAgg, enforce: bool, strikes: &mut HashMap<String, Strike>) -> Decisions {
        decide_with(a, enforce, strikes, &mut HashMap::new())
    }

    fn strike(count: u32, age: i64) -> Strike {
        Strike {
            count,
            last_ts: NOW - age,
            rate_only: false,
        }
    }

    #[test]
    fn a_browser_lured_into_probing_is_neither_struck_nor_escalated() {
        // An address already on its third strike (a shared NAT, an earlier
        // real offence): the lure still gets only its short ban.
        let mut strikes: HashMap<String, Strike> = HashMap::new();
        strikes.insert("198.51.100.7".into(), strike(3, 60));
        for enforce in [true, false] {
            let d = decide_one(lured(), enforce, &mut strikes);
            let ev = d.applied.iter().chain(&d.would).next().unwrap();
            assert_eq!((ev.reason.as_str(), ev.strike), ("probe", 0));
            assert!(ev.ttl_secs <= 600, "{}", ev.ttl_secs);
            assert_eq!(strikes["198.51.100.7"].count, 3);
            assert_eq!(strikes["198.51.100.7"].last_ts, NOW - 60);
        }
        let mut none = HashMap::new();
        decide_one(lured(), true, &mut none);
        assert!(none.is_empty(), "no strike entry for a lure");

        // The same probes from a tool count, and climb the ladder.
        let tool = || agg(&[("/.env", 404, "", 1), ("/.git/config", 404, "", 1)]);
        let d = decide_one(tool(), true, &mut strikes);
        assert_eq!(d.applied[0].strike, 4);
        assert_eq!(d.applied[0].ttl_secs, 7 * 86_400);
        assert_eq!(strikes["198.51.100.7"].count, 4);
    }

    #[test]
    fn observe_mode_says_what_enforce_would_do_without_counting_a_strike() {
        // Weeks in observe used to leave busy addresses at strike 4+, so the
        // first enforce hit was a week-long ban.
        let tool = || agg(&[("/.env", 404, "", 1)]);
        let mut strikes: HashMap<String, Strike> = HashMap::new();
        strikes.insert("198.51.100.7".into(), strike(1, 600));
        for _ in 0..5 {
            let d = decide_one(tool(), false, &mut strikes);
            assert_eq!((d.would[0].strike, d.would[0].ttl_secs), (2, 86_400));
        }
        assert_eq!(strikes["198.51.100.7"].count, 1);
        let mut empty = HashMap::new();
        decide_one(tool(), false, &mut empty);
        assert!(empty.is_empty());
    }

    fn running(reason: &str, left: i64) -> ActiveBan {
        ActiveBan {
            reason: reason.into(),
            expires_ts: NOW + left,
            strike: 1,
            layer: "l3".into(),
        }
    }

    #[test]
    fn an_address_already_banned_is_not_struck_again_for_the_same_thing() {
        // An office NAT banned at 09:00 keeps loading pages over its open
        // connections: the 09:05 log shows the same volume. No new strike.
        let flood = || agg(&[("/?s=x", 200, "curl/8.5", 400)]);
        let mut active: HashMap<String, ActiveBan> = HashMap::new();
        active.insert("198.51.100.7".into(), running("rate", 300));
        let mut strikes = HashMap::new();
        let d = decide_with(flood(), true, &mut strikes, &mut active);
        assert!(d.applied.is_empty() && d.to_add.is_empty());
        assert!(strikes.is_empty());
        // Nor while a longer admin ban from the hub is running.
        active.insert("198.51.100.7".into(), running("hub", 20 * 3600));
        assert!(
            decide_with(flood(), true, &mut strikes, &mut active)
                .applied
                .is_empty()
        );
        // A worse offence than the running ban still applies.
        active.insert("198.51.100.7".into(), running("rate", 300));
        let probe = agg(&[("/.env", 404, "sqlmap/1.7", 1)]);
        let d = decide_with(probe, true, &mut strikes, &mut active);
        assert_eq!(d.applied[0].reason, "probe");
    }

    #[test]
    fn the_cycle_right_after_a_ban_ends_still_reads_the_log_of_its_last_minutes() {
        // 09:00 banned for ten minutes. At 09:10 the ban has just ended, but
        // the 09:05-09:10 log was written while it ran (keep-alive
        // connections, accepted before the drop): no second strike for that.
        let flood = || agg(&[("/?s=x", 200, "curl/8.5", 400)]);
        let mut active: HashMap<String, ActiveBan> = HashMap::new();
        let mut strikes = HashMap::new();
        for ended in [0, 1, 100, CYCLE_SECS - 1] {
            active.insert("198.51.100.7".into(), running("rate", -ended));
            let d = decide_with(flood(), true, &mut strikes, &mut active);
            assert!(d.applied.is_empty(), "ended {ended}s ago");
        }
        assert!(strikes.is_empty());
        // The next cycle's log was written after the ban: a new offence.
        active.insert("198.51.100.7".into(), running("rate", -CYCLE_SECS));
        let d = decide_with(flood(), true, &mut strikes, &mut active);
        assert_eq!(d.applied[0].reason, "rate");
        // A longer stretch of log reaches further back.
        active.insert("198.51.100.7".into(), running("rate", -500));
        let keys = ["198.51.100.7".to_string()];
        let aggs = [flood()];
        let long = Cycle {
            span: 600,
            ..cycle(300, 200, true, NOW)
        };
        let d = decide_bans(
            &cands(&keys, &aggs, 300),
            &long,
            &mut HashMap::new(),
            &mut active,
        );
        assert!(d.applied.is_empty());
        // Kept in state that long, and no longer.
        let mut a: HashMap<String, ActiveBan> = HashMap::new();
        a.insert("ended".into(), running("rate", -(MAX_SPAN_JUDGED - 1)));
        a.insert("long-gone".into(), running("rate", -MAX_SPAN_JUDGED));
        a.insert("running".into(), running("rate", 60));
        prune_active(&mut a, NOW);
        let mut kept: Vec<&str> = a.keys().map(String::as_str).collect();
        kept.sort_unstable();
        assert_eq!(kept, ["ended", "running"]);
    }

    #[test]
    fn rate_strikes_fade_after_a_day_and_browser_rate_bans_stop_at_an_hour() {
        let rate = PatternHit {
            reason: "rate",
            ttl_secs: 600,
            ban: true,
            escalate: true,
            ttl_cap: 0,
        };
        let rate_strike = |count, age| Strike {
            rate_only: true,
            ..strike(count, age)
        };
        let mut s: HashMap<String, Strike> = HashMap::new();
        // A clean day resets a rate-only ladder.
        s.insert("k".into(), rate_strike(3, RATE_STRIKE_DECAY_SECS + 1));
        assert_eq!(strike_ttl(&mut s, "k", &rate, NOW, true), (600, 1));
        assert!(s["k"].rate_only);
        // Within the day it climbs, as before.
        s.insert("k".into(), rate_strike(3, 3600));
        assert_eq!(strike_ttl(&mut s, "k", &rate, NOW, true), (7 * 86_400, 4));
        // From browsers alone: never past an hour, however often.
        let browsers = PatternHit {
            ttl_cap: 3600,
            ..rate.clone()
        };
        s.insert("k".into(), rate_strike(3, 3600));
        assert_eq!(strike_ttl(&mut s, "k", &browsers, NOW, true), (3600, 4));
        // Any other offence keeps the key's ladder for a week.
        let probe = PatternHit {
            reason: "probe",
            ttl_secs: 86_400,
            ..rate.clone()
        };
        s.insert("k".into(), rate_strike(1, 3600));
        strike_ttl(&mut s, "k", &probe, NOW, true);
        assert!(!s["k"].rate_only);
        assert_eq!(strike_ttl(&mut s, "k", &rate, NOW + 2 * 86_400, true).1, 3);
        // Observe mode writes nothing.
        let mut none = HashMap::new();
        assert_eq!(strike_ttl(&mut none, "k", &rate, NOW, false), (600, 1));
        assert!(none.is_empty());
    }

    #[test]
    fn a_rate_storm_holds_back_only_browsers_and_still_bans_tool_floods() {
        // Thirty browser-looking addresses over the threshold at once: the
        // threshold is too low for this traffic, or a wave only a WAF stops.
        let mut keys: Vec<String> = (0..31).map(|i| format!("203.0.113.{i}")).collect();
        let mut aggs: Vec<IpAgg> = (0..30)
            .map(|_| agg(&[("/?s=x", 200, BROWSER, 400)]))
            .collect();
        // One of them floods far harder.
        aggs.push(agg(&[("/?s=x", 200, BROWSER, 1000)]));
        // And five flood with curl and python: banned, storm or not.
        for i in 0..5 {
            keys.push(format!("198.51.100.{i}"));
            let ua = if i % 2 == 0 {
                "curl/8.5"
            } else {
                "python-requests/2.31"
            };
            aggs.push(agg(&[("/?s=x", 200, ua, 400)]));
        }
        let c = cands(&keys, &aggs, 300);
        assert_eq!(c.len(), 36);
        let (mut strikes, mut active) = (HashMap::new(), HashMap::new());
        let d = decide_bans(&c, &cycle(300, 200, true, NOW), &mut strikes, &mut active);
        let mut banned: Vec<&str> = d.applied.iter().map(|e| e.ip.as_str()).collect();
        banned.sort_unstable();
        assert_eq!(
            banned,
            [
                "198.51.100.0",
                "198.51.100.1",
                "198.51.100.2",
                "198.51.100.3",
                "198.51.100.4",
                "203.0.113.30"
            ]
        );
        assert_eq!(d.would.len(), 30);
        assert!(
            d.would
                .iter()
                .all(|e| e.reason == "rate" && e.layer == "report" && e.ip.starts_with("203."))
        );
        assert_eq!(d.storm, Some((6, 30)));
        assert_eq!(strikes.len(), 6);
        let a = storm_alert(d.storm, 300).unwrap();
        assert_eq!(
            (a.kind.as_str(), a.severity.as_str()),
            ("rate_storm", "urgent")
        );
        assert!(a.message.contains("36 addresses"), "{}", a.message);
        // A botnet of curl floods is no storm to hold back: every one banned.
        let bots: Vec<String> = (0..40).map(|i| format!("192.0.2.{i}")).collect();
        let floods: Vec<IpAgg> = (0..40)
            .map(|_| agg(&[("/?s=x", 200, "curl/8.5", 350)]))
            .collect();
        let d = decide_bans(
            &cands(&bots, &floods, 300),
            &cycle(300, 200, true, NOW),
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        assert_eq!((d.applied.len(), d.would.len()), (40, 0));
        assert_eq!(d.storm, Some((40, 0)));
        // Twenty is not yet a storm.
        let c = cands(&keys[..20], &aggs[..20], 300);
        let d = decide_bans(
            &c,
            &cycle(300, 200, true, NOW),
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        assert_eq!((d.applied.len(), d.storm), (20, None));
        assert!(storm_alert(None, 300).is_none());
    }

    #[test]
    fn report_only_entries_and_observed_bans_are_capped() {
        // 250 addresses that each fetched /.env once (a /48 is 65k /64s), the
        // busiest first as `run` sorts them.
        let keys: Vec<String> = (0..250).map(|i| format!("2001:db8:0:{i:x}::/64")).collect();
        let aggs: Vec<IpAgg> = (0..250)
            .map(|i| agg(&[("/.env", 404, BROWSER, 1), ("/", 200, BROWSER, 10 - i / 25)]))
            .collect();
        let candidates = cands(&keys, &aggs, 1000);
        for enforce in [true, false] {
            let mut strikes = HashMap::new();
            let d = decide_bans(
                &candidates,
                &cycle(1000, 5, enforce, 0),
                &mut strikes,
                &mut HashMap::new(),
            );
            assert!(d.applied.is_empty());
            assert_eq!(d.would.len(), MAX_REPORT_ONLY);
            assert!(
                d.would
                    .iter()
                    .all(|e| e.layer == "report" && e.ttl_secs == 0)
            );
            assert_eq!(d.would[0].ip, keys[0]);
            assert_eq!(d.unlisted, 50);
            assert!(strikes.is_empty());
        }

        // Bans: enforce applies the first `ban_cap` and stops; observe lists as
        // many and counts the rest. Only enforce strikes, and only those.
        let tools: Vec<IpAgg> = (0..8).map(|_| agg(&[("/", 404, "nikto", 1)])).collect();
        let candidates = cands(&keys, &tools, 1000);
        for enforce in [true, false] {
            let (mut strikes, mut active) = (HashMap::new(), HashMap::new());
            let d = decide_bans(
                &candidates,
                &cycle(1000, 5, enforce, 0),
                &mut strikes,
                &mut active,
            );
            if enforce {
                assert_eq!(strikes.len(), 5);
                assert_eq!((d.applied.len(), d.to_add.len(), active.len()), (5, 5, 5));
                assert!(d.would.is_empty());
                assert_eq!(d.unlisted, 0); // the `ban_cap` alert says it
            } else {
                assert!(strikes.is_empty());
                assert!(d.applied.is_empty() && d.to_add.is_empty() && active.is_empty());
                assert_eq!(d.would.len(), 5);
                assert_eq!(d.unlisted, 3);
            }
        }
        assert!(unlisted_alert(0).is_none());
        let a = unlisted_alert(3).unwrap();
        assert_eq!(
            (a.kind.as_str(), a.severity.as_str()),
            ("report_cap", "warn")
        );
        assert!(a.message.contains('3'));
    }

    #[test]
    fn a_backlog_is_judged_against_its_own_length_or_not_at_all() {
        let now = 100_000;
        assert_eq!(cycle_span(0, now), CYCLE_SECS, "no earlier cycle");
        assert_eq!(cycle_span(now + 60, now), CYCLE_SECS, "clock went back");
        assert_eq!(cycle_span(now - 290, now), CYCLE_SECS);
        assert_eq!(cycle_span(now - 600, now), 600);
        assert_eq!(cycle_span(now - 7200, now), MAX_SPAN);
        // Ten minutes of log get twice the five-minute bar.
        assert_eq!(scale(300, 600), 600);
        assert_eq!(scale(300, CYCLE_SECS), 300);
        assert_eq!(scale(10, 7200), 120, "at most an hour's worth");
        assert!(cycle_span(now - 7200, now) > MAX_SPAN_JUDGED);
        let a = backlog_alert(true, 7200).unwrap();
        assert_eq!(
            (a.kind.as_str(), a.severity.as_str()),
            ("backlog_skipped", "info")
        );
        assert!(backlog_alert(false, 7200).is_none());
    }

    #[test]
    fn a_flood_that_fills_the_read_is_judged_but_a_backlog_after_a_gap_is_not() {
        // A flood big enough that this cycle's read hit its byte cap, with no
        // gap before it: judged (the old code skipped `rate` for as long as
        // the flood kept the reads capped).
        assert_eq!(backlog_state(CYCLE_SECS, true, 0), (false, 0));
        assert_eq!(backlog_state(CYCLE_SECS, false, 0), (false, 0));
        // Two hours off: not judged, nor the next reads while they still
        // catch up...
        assert_eq!(backlog_state(7200, true, 0), (true, GAP_CATCH_UP_CYCLES));
        assert_eq!(
            backlog_state(CYCLE_SECS, true, GAP_CATCH_UP_CYCLES),
            (true, GAP_CATCH_UP_CYCLES - 1)
        );
        // ...until a read reaches the end of the logs (that one still holds
        // backlog)...
        assert_eq!(backlog_state(CYCLE_SECS, false, 2), (true, 0));
        assert_eq!(backlog_state(CYCLE_SECS, true, 0), (false, 0));
        // ...or a few cycles have passed: a flood that keeps the reads capped
        // after a gap is judged again soon.
        let mut left = backlog_state(7200, true, 0).1;
        let mut skipped = 1;
        loop {
            let (backlog, next) = backlog_state(CYCLE_SECS, true, left);
            if !backlog {
                break;
            }
            skipped += 1;
            left = next;
        }
        assert_eq!(skipped, 1 + GAP_CATCH_UP_CYCLES);
        // A gap with nothing more to read is one backlog cycle.
        assert_eq!(backlog_state(7200, false, 0), (true, 0));
    }

    #[test]
    fn an_unbanned_address_gets_a_grace_and_the_list_stays_small() {
        let mut u: HashMap<String, i64> = HashMap::new();
        u.insert("203.0.113.7".into(), NOW - 60);
        u.insert("old".into(), NOW - UNBAN_GRACE_SECS);
        u.insert("future".into(), NOW + 3600);
        assert!(unban_grace(&u, "203.0.113.7", NOW));
        assert!(!unban_grace(&u, "old", NOW));
        assert!(!unban_grace(&u, "future", NOW), "a clock that jumped");
        assert!(!unban_grace(&u, "198.51.100.1", NOW));
        prune_unbanned(&mut u, NOW);
        assert_eq!(u.keys().collect::<Vec<_>>(), ["203.0.113.7"]);
        let mut u: HashMap<String, i64> = (0..MAX_UNBANNED as i64 + 10)
            .map(|i| (format!("k{i}"), NOW - 1000 + i / 100))
            .collect();
        prune_unbanned(&mut u, NOW);
        assert_eq!(u.len(), MAX_UNBANNED);
        assert!(u.contains_key(&format!("k{}", MAX_UNBANNED + 9)));
    }

    #[test]
    fn the_baseline_learns_from_ordinary_addresses_not_the_busiest_one() {
        assert_eq!(robust_busiest(&[]), 0);
        assert_eq!(robust_busiest(&[40]), 40);
        assert_eq!(robust_busiest(&[90, 40]), 40);
        // Two flooders just under the bar do not set what is normal.
        assert_eq!(robust_busiest(&[2900, 2800, 35, 20, 3]), 35);
    }

    #[test]
    fn configuration_and_proxy_problems_are_named() {
        let a = misplaced_alert(&["mode".into(), "trusted_proxies".into()]).unwrap();
        assert_eq!(a.kind, "config_misplaced");
        assert!(a.message.contains("mode, trusted_proxies"), "{}", a.message);
        assert!(misplaced_alert(&[]).is_none());
        let a = proxy_alert(&["203.0.113.9".into()]).unwrap();
        assert_eq!(a.kind, "proxy_in_logs");
        assert!(a.message.contains("trusted_proxies"));
        assert!(proxy_alert(&[]).is_none());
        let keys: Vec<String> = (0..7).map(|i| format!("104.16.0.{i}")).collect();
        let a = cloudflare_alert(&keys).unwrap();
        assert_eq!(a.kind, "attack_via_cloudflare");
        assert!(a.message.contains("104.16.0.4, ...") && !a.message.contains("104.16.0.5"));
        assert!(cloudflare_alert(&[]).is_none());
    }
}
