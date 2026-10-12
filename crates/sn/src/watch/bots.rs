//! Distributed-bot detection: one User-Agent or request *shape* that suddenly
//! arrives from many different IPs.
//!
//! The per-IP rules cannot see this. A botnet on residential proxies sends a few
//! requests from each of hundreds of addresses, so no single address is above any
//! threshold, and each request looks like an ordinary browser. What gives it away
//! is what they all have in common, and that it is new or far above normal.
//!
//! * A **shape** is `METHOD /path?name1&name2`: the request with parameter
//!   *values* stripped (they can carry tokens and personal data) and numeric or
//!   token-like path segments collapsed.
//! * A pattern is flagged when, in one cycle, it comes from at least `min_ips`
//!   distinct addresses, makes at least `min_requests` dynamic requests, each
//!   address making only a few, and is at least `surge` times its usual volume.
//! * "Usual volume" is a per-pattern moving average that is **frozen while the
//!   pattern is flagged**. Without that, a long attack would teach the baseline
//!   that it is normal and the alert would go quiet while the attack continued.
//! * Alerts only. This never bans anything: the addresses are throwaway; the
//!   sensible response is a WAF rule (see `snsec_common::waf`) or, without a WAF,
//!   an IP block chosen by a human.
//!
//! Everything is bounded: a hostile log (every request a different UA, every
//! request a different parameter name) cannot make the agent's memory grow.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use snsec_common::logfmt::LogLine;
use snsec_common::schema::{Alert, PatternStat};

/// Distinct patterns tracked per kind per cycle; beyond it new ones are only
/// counted as overflow.
const MAX_KEYS: usize = 2_000;
/// Distinct addresses remembered per pattern; the count saturates here.
const IP_CAP: usize = 256;
/// Addresses kept as examples (only used for flagged patterns).
const SAMPLE_IPS: usize = 20;
/// Patterns shown per kind in the report.
const TOP_N: usize = 10;
/// Longest key kept; longer ones are cut at a character boundary.
const KEY_MAX_CHARS: usize = 200;
/// Entries kept per kind in the persisted baseline.
const BASELINE_MAX: usize = 400;
/// Cycles of observation before any alert (about an hour at 5 minutes).
const WARMUP_CYCLES: u32 = 12;
/// Weight of the newest cycle in the moving average.
const EWMA_ALPHA: f64 = 0.2;
/// Per-cycle decay of a pattern that was not seen.
const EWMA_DECAY: f64 = 0.85;
/// A distributed bot makes few requests per address; many per address is the
/// per-IP rules' job. (Skipped once the address count saturates.)
const MAX_AVG_PER_IP: f64 = 8.0;
/// Alerts raised per kind per cycle at most.
const MAX_ALERTS_PER_KIND: usize = 3;
/// How long (in cycles, about a day) a flagged pattern's baseline stays frozen.
/// After that the pattern is allowed to become "normal": either it was never an
/// attack (a new feature, a campaign) or it has been going so long that the
/// alert has said all it can. The top-patterns table keeps showing it either way.
const MAX_FROZEN_CYCLES: u32 = 288;

/// Thresholds, from `[watch]` in the agent config.
#[derive(Debug, Clone, Copy)]
pub struct BotCfg {
    pub min_ips: u32,
    pub min_requests: u32,
    pub surge: f64,
}

// ---------------------------------------------------------------------------
// Per-cycle aggregation
// ---------------------------------------------------------------------------

struct Stat {
    requests: u64,
    ips: HashSet<u64>,
    sample: Vec<IpAddr>,
}

impl Stat {
    fn new() -> Stat {
        Stat {
            requests: 0,
            ips: HashSet::new(),
            sample: Vec::new(),
        }
    }

    fn add(&mut self, ip_hash: u64, ip: IpAddr) {
        self.requests += 1;
        if self.ips.len() < IP_CAP && self.ips.insert(ip_hash) && self.sample.len() < SAMPLE_IPS {
            self.sample.push(ip);
        }
    }

    fn capped(&self) -> bool {
        self.ips.len() >= IP_CAP
    }
}

/// What one cycle's dynamic requests looked like.
#[derive(Default)]
pub struct Aggregates {
    /// Requests that are not static assets.
    pub dynamic: u64,
    ua: HashMap<String, Stat>,
    shapes: HashMap<String, Stat>,
    /// Requests whose pattern could not be tracked because the map was full.
    pub overflow: u64,
    buf: String,
}

impl Aggregates {
    /// Count one parsed request from `client` (`ip_hash` identifies the address,
    /// or the /64 for IPv6, for distinct counting).
    pub fn observe(&mut self, line: &LogLine, ip_hash: u64, client: IpAddr) {
        // Static files, and requests the server already refused (403, 429, 444:
        // after a WAF rule is installed the bot keeps coming but no longer
        // reaches the site, and the alert should stop).
        if is_static(&line.path) || matches!(line.status, 403 | 429 | 444) {
            return;
        }
        self.dynamic += 1;

        let ua = line.user_agent.trim();
        if !ua.is_empty() && ua != "-" {
            bump(&mut self.ua, &mut self.overflow, ua, ip_hash, client);
        }

        let mut buf = std::mem::take(&mut self.buf);
        write_shape(&line.method, &line.path, &mut buf);
        bump(&mut self.shapes, &mut self.overflow, &buf, ip_hash, client);
        self.buf = buf;
    }
}

fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn bump(map: &mut HashMap<String, Stat>, overflow: &mut u64, key: &str, ip_hash: u64, ip: IpAddr) {
    let key = truncate_chars(key, KEY_MAX_CHARS);
    if let Some(s) = map.get_mut(key) {
        s.add(ip_hash, ip);
    } else if map.len() < MAX_KEYS {
        let mut s = Stat::new();
        s.add(ip_hash, ip);
        map.insert(key.to_string(), s);
    } else {
        *overflow += 1;
    }
}

/// FNV-1a: a fast hash for distinct-address counting (not a security boundary).
#[must_use]
pub fn hash64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

const STATIC_EXT: &[&str] = &[
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "pdf", "zip", "gz",
    "txt", "xml",
];

/// Is this request for a static file? Judged by the extension of the last path
/// segment; a query string does not change that.
fn is_static(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or(target);
    let last = path.rsplit('/').next().unwrap_or(path);
    match last.rsplit_once('.') {
        Some((_, ext)) => STATIC_EXT.iter().any(|e| ext.eq_ignore_ascii_case(e)),
        None => false,
    }
}

/// Collapse a path segment that identifies one object (a number, a hash, an
/// e-mail address, an opaque token) so that `/p/101` and `/p/102` are one shape.
fn normalize_segment(seg: &str) -> &str {
    let b = seg.as_bytes();
    if b.is_empty() {
        return seg;
    }
    let all_digits = b.iter().all(u8::is_ascii_digit);
    let hexish = b.len() >= 8 && b.iter().all(|c| c.is_ascii_hexdigit() || *c == b'-');
    let has_digit = b.iter().any(u8::is_ascii_digit);
    let token_like = b.len() >= 20 && has_digit;
    // Opaque short tokens (`aB3dE5gH7jK`): letters of both cases plus a digit.
    let mixed_token = b.len() >= 8
        && has_digit
        && b.iter().any(u8::is_ascii_uppercase)
        && b.iter().any(u8::is_ascii_lowercase);
    if all_digits || hexish || token_like || mixed_token || seg.contains('@') || seg.contains("%40")
    {
        "{id}"
    } else if b.len() > 48 {
        "{long}"
    } else {
        seg
    }
}

/// Build the shape of a request into `buf` (cleared first):
/// `METHOD /normalized/path?sorted&param&names`.
fn write_shape(method: &str, target: &str, buf: &mut String) {
    buf.clear();
    let method = truncate_chars(method, 8);
    buf.push_str(&method.to_ascii_uppercase());
    buf.push(' ');

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query.split('#').next().unwrap_or("");

    let start = buf.len();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        buf.push('/');
        buf.push_str(normalize_segment(seg));
    }
    if buf.len() == start {
        buf.push('/');
    }
    // Keep the path part to a sane length (cut on a character boundary).
    let path_end = start + truncate_chars(&buf[start..], 120).len();
    buf.truncate(path_end);

    let mut names: Vec<&str> = query
        .split('&')
        .map(|p| p.split('=').next().unwrap_or(""))
        .filter(|n| !n.is_empty())
        .map(|n| truncate_chars(n, 40))
        // A bare key can itself be a token or an address (`?user@example.com`).
        .map(|n| match normalize_segment(n) {
            "{id}" | "{long}" => "{k}",
            other => other,
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names.truncate(12);
    if !names.is_empty() {
        buf.push('?');
        buf.push_str(&names.join("&"));
    }
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

/// Usual volume per pattern (requests per cycle), learned over time.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BotBaseline {
    /// Cycles observed so far; alerts wait for `WARMUP_CYCLES`.
    pub cycles: u32,
    pub ua: HashMap<String, f64>,
    pub shape: HashMap<String, f64>,
    /// Consecutive cycles each currently-flagged pattern has been flagged.
    #[serde(default)]
    pub ua_age: HashMap<String, u32>,
    #[serde(default)]
    pub shape_age: HashMap<String, u32>,
}

impl BotBaseline {
    /// Fold one cycle into the baseline. A flagged pattern is left untouched
    /// (frozen), so a sustained attack does not become "normal" while it lasts.
    pub fn update(
        &mut self,
        agg: &Aggregates,
        flagged_ua: &HashSet<String>,
        flagged_shape: &HashSet<String>,
    ) {
        fold(&mut self.ua, &mut self.ua_age, &agg.ua, flagged_ua);
        fold(
            &mut self.shape,
            &mut self.shape_age,
            &agg.shapes,
            flagged_shape,
        );
        self.cycles = self.cycles.saturating_add(1);
    }
}

fn fold(
    base: &mut HashMap<String, f64>,
    ages: &mut HashMap<String, u32>,
    seen: &HashMap<String, Stat>,
    flagged: &HashSet<String>,
) {
    // How long each pattern has been flagged without a break.
    ages.retain(|k, _| flagged.contains(k));
    for k in flagged {
        let a = ages.entry(k.clone()).or_insert(0);
        *a = a.saturating_add(1);
    }
    for (k, v) in base.iter_mut() {
        if !seen.contains_key(k) {
            *v *= EWMA_DECAY;
        }
    }
    base.retain(|_, v| *v >= 1.0);
    for (k, st) in seen {
        let is_flagged = flagged.contains(k);
        if is_flagged && ages.get(k).copied().unwrap_or(0) <= MAX_FROZEN_CYCLES {
            continue; // frozen
        }
        let now = st.requests as f64;
        // A pattern seen for the first time without being flagged starts at its
        // own level. One that is only now being absorbed after a long flag starts
        // from zero and is learned over several cycles, so a day-long attack does
        // not turn into "normal" in a single step.
        let start = if is_flagged { 0.0 } else { now };
        let e = base.entry(k.clone()).or_insert(start);
        *e = EWMA_ALPHA * now + (1.0 - EWMA_ALPHA) * *e;
    }
    // Bound the size: drop the least significant entries.
    if base.len() > BASELINE_MAX {
        let mut by_value: Vec<(String, f64)> = base.iter().map(|(k, v)| (k.clone(), *v)).collect();
        by_value.sort_by(|a, b| a.1.total_cmp(&b.1));
        for (k, _) in by_value.into_iter().take(base.len() - BASELINE_MAX) {
            base.remove(&k);
        }
    }
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

/// The outcome of looking at one cycle.
#[derive(Default)]
pub struct Assessment {
    pub alerts: Vec<Alert>,
    pub flagged_ua: HashSet<String>,
    pub flagged_shape: HashSet<String>,
}

fn qualifies(st: &Stat, usual: f64, cfg: &BotCfg) -> bool {
    let ips = st.ips.len() as f64;
    st.requests >= u64::from(cfg.min_requests)
        // The distinct count saturates at IP_CAP, so a higher setting could
        // never be met and would silently disable detection.
        && st.ips.len() >= (cfg.min_ips as usize).min(IP_CAP)
        && (st.capped() || st.requests as f64 / ips <= MAX_AVG_PER_IP)
        && st.requests as f64 >= cfg.surge * usual.max(1.0)
}

fn describe(kind_word: &str, key: &str, st: &Stat, usual: f64, cpu_high: bool) -> String {
    let plus = if st.capped() { "+" } else { "" };
    let crawler = snsec_common::waf::claims_crawler(key);
    let history = if usual < 1.0 {
        "not seen recently".to_string()
    } else {
        format!("usually about {usual:.0}")
    };
    format!(
        "{} requests from {}{plus} different IPs in one cycle ({history}); {kind_word}: {}{}{}",
        st.requests,
        st.ips.len(),
        truncate_chars(key, 140),
        if crawler {
            " [claims to be a known crawler; not verified]"
        } else {
            ""
        },
        if cpu_high {
            " [CPU is high at the same time]"
        } else {
            ""
        },
    )
}

/// Decide which patterns of this cycle look like a distributed bot.
#[must_use]
pub fn assess(agg: &Aggregates, base: &BotBaseline, cfg: &BotCfg, cpu_high: bool) -> Assessment {
    let mut out = Assessment::default();
    if base.cycles < WARMUP_CYCLES {
        return out; // still learning what normal looks like
    }
    let severity = if cpu_high { "urgent" } else { "warn" };

    let mut found: Vec<(&String, &Stat, f64)> = agg
        .ua
        .iter()
        .filter_map(|(k, st)| {
            let usual = base.ua.get(k).copied().unwrap_or(0.0);
            qualifies(st, usual, cfg).then_some((k, st, usual))
        })
        .collect();
    found.sort_by(|a, b| b.1.requests.cmp(&a.1.requests).then(a.0.cmp(b.0)));
    for (k, st, usual) in &found {
        out.flagged_ua.insert((*k).clone());
        if out.alerts.iter().filter(|a| a.kind == "bot_ua").count() < MAX_ALERTS_PER_KIND {
            out.alerts.push(Alert {
                kind: "bot_ua".into(),
                message: describe("User-Agent", k, st, *usual, cpu_high),
                severity: severity.into(),
            });
        }
    }

    // A shape with no parameters is just a page; only parameterised ones count.
    let mut found: Vec<(&String, &Stat, f64)> = agg
        .shapes
        .iter()
        .filter(|(k, _)| k.contains('?'))
        .filter_map(|(k, st)| {
            let usual = base.shape.get(k).copied().unwrap_or(0.0);
            qualifies(st, usual, cfg).then_some((k, st, usual))
        })
        .collect();
    found.sort_by(|a, b| b.1.requests.cmp(&a.1.requests).then(a.0.cmp(b.0)));
    for (k, st, usual) in &found {
        out.flagged_shape.insert((*k).clone());
        if out.alerts.iter().filter(|a| a.kind == "bot_shape").count() < MAX_ALERTS_PER_KIND {
            out.alerts.push(Alert {
                kind: "bot_shape".into(),
                message: describe("request", k, st, *usual, cpu_high),
                severity: severity.into(),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn top(map: &HashMap<String, Stat>, flagged: &HashSet<String>) -> Vec<PatternStat> {
    let mut all: Vec<(&String, &Stat)> = map.iter().collect();
    all.sort_by(|a, b| b.1.requests.cmp(&a.1.requests).then(a.0.cmp(b.0)));
    let mut picked: Vec<(&String, &Stat)> = all.iter().take(TOP_N).copied().collect();
    // A flagged pattern is shown even when it is not in the top N.
    for &(k, st) in all.iter().skip(TOP_N) {
        if flagged.contains(k) && picked.len() < TOP_N + 5 {
            picked.push((k, st));
        }
    }
    picked
        .into_iter()
        .map(|(k, st)| {
            let is_flagged = flagged.contains(k);
            PatternStat {
                key: k.clone(),
                requests: st.requests,
                ips: u32::try_from(st.ips.len()).unwrap_or(u32::MAX),
                ips_capped: st.capped(),
                flagged: is_flagged,
                sample_ips: if is_flagged {
                    st.sample.iter().map(ToString::to_string).collect()
                } else {
                    Vec::new()
                },
            }
        })
        .collect()
}

impl Aggregates {
    /// The busiest User-Agents and shapes of the cycle, for the report.
    #[must_use]
    pub fn top_patterns(
        &self,
        flagged_ua: &HashSet<String>,
        flagged_shape: &HashSet<String>,
    ) -> (Vec<PatternStat>, Vec<PatternStat>) {
        (top(&self.ua, flagged_ua), top(&self.shapes, flagged_shape))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snsec_common::logfmt::{LogFormat, parse_line};

    const UA: &str = "Mozilla/5.0 (Macintosh) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0";

    fn line(ip: &str, target: &str, ua: &str) -> LogLine {
        let l = format!(
            r#"{ip} - - [12/Oct/2026:02:42:29 +0700] "GET {target} HTTP/1.1" 200 1234 "-" "{ua}""#
        );
        parse_line(LogFormat::Combined, &l, &[]).unwrap()
    }

    fn feed(agg: &mut Aggregates, ip: &str, target: &str, ua: &str) {
        let parsed = line(ip, target, ua);
        let addr: IpAddr = ip.parse().unwrap();
        agg.observe(&parsed, hash64(ip.as_bytes()), addr);
    }

    fn cfg() -> BotCfg {
        BotCfg {
            min_ips: 25,
            min_requests: 50,
            surge: 5.0,
        }
    }

    fn warm() -> BotBaseline {
        BotBaseline {
            cycles: WARMUP_CYCLES,
            ..BotBaseline::default()
        }
    }

    fn shape(method: &str, target: &str) -> String {
        let mut b = String::new();
        write_shape(method, target, &mut b);
        b
    }

    /// `n` different addresses, each making `per` requests of the same kind.
    fn flood(agg: &mut Aggregates, n: u32, per: u32, target: &str, ua: &str) {
        for i in 0..n {
            let ip = format!("203.0.{}.{}", i / 250, i % 250 + 1);
            for _ in 0..per {
                feed(agg, &ip, target, ua);
            }
        }
    }

    // ---- shapes ----------------------------------------------------------

    #[test]
    fn a_shape_keeps_parameter_names_and_drops_their_values() {
        // The attack from the report that motivated this feature.
        let s = shape(
            "GET",
            "/?tss-sc=review-khach-hang&tsscat=12&tst10_filter=a%20b&utm=zzz#frag",
        );
        assert_eq!(s, "GET /?tss-sc&tsscat&tst10_filter&utm");
        // Same names in another order or with other values: the same shape.
        assert_eq!(
            s,
            shape("GET", "/?utm=1&tst10_filter=x&tsscat=y&tss-sc=other")
        );
    }

    #[test]
    fn ids_in_the_path_are_collapsed_but_words_are_kept() {
        assert_eq!(shape("GET", "/product/12345/"), "GET /product/{id}");
        assert_eq!(
            shape("GET", "/product/678/?color=red"),
            "GET /product/{id}?color"
        );
        assert_eq!(
            shape("GET", "/order/3f2b9c1e-7d4a-4b6e-9c1a-0e5d8f7a2b3c"),
            "GET /order/{id}"
        );
        assert_eq!(shape("GET", "/u/someone@example.com/x"), "GET /u/{id}/x");
        assert_eq!(
            shape("get", "/tin-tuc/bai-viet-a"),
            "GET /tin-tuc/bai-viet-a"
        );
        assert_eq!(shape("GET", ""), "GET /");
    }

    #[test]
    fn tokens_and_addresses_never_end_up_in_a_shape() {
        // Opaque short tokens in the path.
        assert_eq!(shape("GET", "/reset/aB3dE5gH7jK"), "GET /reset/{id}");
        // A bare query key can itself be a token or an e-mail address.
        assert_eq!(shape("GET", "/verify?9f8e7d6c5b4a"), "GET /verify?{k}");
        assert_eq!(shape("GET", "/x?user@example.com"), "GET /x?{k}");
        assert_eq!(shape("GET", "/x?AbC123xyz&page=2"), "GET /x?page&{k}");
        // Ordinary words and names are kept.
        assert_eq!(
            shape("GET", "/blog/Hello-World?utm=1"),
            "GET /blog/Hello-World?utm"
        );
    }

    #[test]
    fn requests_the_server_already_refused_are_not_counted() {
        let mut agg = Aggregates::default();
        for status in [403, 429, 444] {
            let l = format!(
                r#"203.0.113.9 - - [12/Oct/2026:02:42:29 +0700] "GET /?a=1 HTTP/1.1" {status} 0 "-" "{UA}""#
            );
            let p = parse_line(LogFormat::Combined, &l, &[]).unwrap();
            agg.observe(&p, 1, "203.0.113.9".parse().unwrap());
        }
        assert_eq!(agg.dynamic, 0);
        feed(&mut agg, "203.0.113.9", "/?a=1", UA); // 200
        assert_eq!(agg.dynamic, 1);
    }

    #[test]
    fn a_min_ips_above_the_tracking_cap_still_works() {
        // 300 would be unreachable: the distinct count saturates at IP_CAP.
        let mut agg = Aggregates::default();
        flood(&mut agg, 400, 2, "/?a=1&b=2", UA);
        let big = BotCfg {
            min_ips: 300,
            ..cfg()
        };
        assert!(!assess(&agg, &warm(), &big, false).alerts.is_empty());
    }

    #[test]
    fn a_first_sighting_says_so_instead_of_usually_zero() {
        let mut agg = Aggregates::default();
        flood(&mut agg, 100, 2, "/?a=1&b=2", UA);
        let a = assess(&agg, &warm(), &cfg(), false);
        let m = &a.alerts[0].message;
        assert!(m.contains("not seen recently"), "{m}");
        assert!(!m.contains("usually about 0"), "{m}");
    }

    #[test]
    fn static_files_are_not_dynamic_requests() {
        for p in [
            "/a.css",
            "/wp-content/uploads/2026/x.JPG?ver=1",
            "/f.woff2",
            "/favicon.ico",
        ] {
            assert!(is_static(p), "{p}");
        }
        for p in [
            "/",
            "/?a=1",
            "/wp-admin/admin-ajax.php",
            "/wp-json/x",
            "/blog/post",
        ] {
            assert!(!is_static(p), "{p}");
        }
    }

    #[test]
    fn static_files_do_not_count_toward_the_aggregates() {
        let mut agg = Aggregates::default();
        feed(&mut agg, "198.51.100.1", "/a.css", UA);
        feed(&mut agg, "198.51.100.1", "/page", UA);
        assert_eq!(agg.dynamic, 1);
        assert_eq!(agg.shapes.len(), 1);
    }

    // ---- detection -------------------------------------------------------

    #[test]
    fn the_reported_attack_is_flagged() {
        // 200 residential addresses, 2 requests each, one UA, one heavy filter.
        let mut agg = Aggregates::default();
        flood(
            &mut agg,
            200,
            2,
            "/?tss-sc=review-khach-hang&tsscat=1&tst10_filter=2",
            UA,
        );
        let a = assess(&agg, &warm(), &cfg(), false);
        let kinds: Vec<&str> = a.alerts.iter().map(|x| x.kind.as_str()).collect();
        assert!(
            kinds.contains(&"bot_ua") && kinds.contains(&"bot_shape"),
            "{kinds:?}"
        );
        assert!(a.flagged_shape.contains("GET /?tss-sc&tsscat&tst10_filter"));
        assert!(a.flagged_ua.contains(UA));
        assert!(a.alerts.iter().all(|x| x.severity == "warn"));
        // The alert says what and how big, so a person can act on it.
        let m = &a
            .alerts
            .iter()
            .find(|x| x.kind == "bot_shape")
            .unwrap()
            .message;
        assert!(m.contains("400 requests from 200 different IPs"), "{m}");
        assert!(m.contains("tss-sc&tsscat&tst10_filter"), "{m}");
    }

    #[test]
    fn high_cpu_at_the_same_time_makes_it_urgent() {
        let mut agg = Aggregates::default();
        flood(&mut agg, 60, 2, "/?a=1&b=2", UA);
        let a = assess(&agg, &warm(), &cfg(), true);
        assert!(!a.alerts.is_empty());
        assert!(a.alerts.iter().all(|x| x.severity == "urgent"));
        assert!(a.alerts[0].message.contains("CPU is high"));
    }

    #[test]
    fn ordinary_diverse_traffic_is_not_flagged() {
        // Many visitors, each with their own browser and their own pages.
        let mut agg = Aggregates::default();
        for i in 0..120u32 {
            let ip = format!("203.0.{}.{}", i / 250, i % 250 + 1);
            let ua = format!("Mozilla/5.0 Browser/{} Version/{}", i % 17, i);
            feed(&mut agg, &ip, &format!("/page-{}/?q={}", i % 30, i), &ua);
        }
        let a = assess(&agg, &warm(), &cfg(), false);
        assert!(
            a.alerts.is_empty(),
            "{:?}",
            a.alerts.iter().map(|x| &x.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_single_address_flooding_is_left_to_the_per_ip_rules() {
        let mut agg = Aggregates::default();
        flood(&mut agg, 3, 200, "/?a=1&b=2", UA);
        assert!(assess(&agg, &warm(), &cfg(), false).alerts.is_empty());
    }

    #[test]
    fn many_addresses_each_hammering_is_also_not_this_signature() {
        // 30 addresses, 50 requests each: the per-IP rate rule handles that.
        let mut agg = Aggregates::default();
        flood(&mut agg, 30, 50, "/?a=1&b=2", UA);
        assert!(assess(&agg, &warm(), &cfg(), false).alerts.is_empty());
    }

    #[test]
    fn nothing_is_reported_while_the_baseline_is_still_warming_up() {
        let mut agg = Aggregates::default();
        flood(&mut agg, 200, 2, "/?a=1&b=2", UA);
        let cold = BotBaseline {
            cycles: WARMUP_CYCLES - 1,
            ..BotBaseline::default()
        };
        assert!(assess(&agg, &cold, &cfg(), false).alerts.is_empty());
    }

    #[test]
    fn a_pattern_that_is_always_this_busy_is_normal() {
        // A steady site: the same shape and UA from ~60 addresses every cycle,
        // from the day the agent was installed. The warm-up cycles teach the
        // baseline that this is normal, so it never alerts.
        let mut base = BotBaseline::default();
        for _ in 0..(WARMUP_CYCLES + 20) {
            let mut agg = Aggregates::default();
            flood(&mut agg, 60, 2, "/?wc-ajax=get_fragments", UA);
            let a = assess(&agg, &base, &cfg(), false);
            assert!(a.alerts.is_empty(), "alerted on steady traffic");
            base.update(&agg, &a.flagged_ua, &a.flagged_shape);
        }
        // ...but several times that volume is a surge.
        let mut surge = Aggregates::default();
        flood(&mut surge, 400, 2, "/?wc-ajax=get_fragments", UA);
        assert!(!assess(&surge, &base, &cfg(), false).alerts.is_empty());
    }

    #[test]
    fn a_long_attack_does_not_teach_the_baseline_that_it_is_normal() {
        // The reason the baseline freezes while flagged: otherwise this would go
        // quiet after a few cycles although the attack carries on.
        let mut base = warm();
        let mut alerted_cycles = 0;
        for _ in 0..40 {
            let mut agg = Aggregates::default();
            flood(&mut agg, 200, 2, "/?tss-sc=x&tsscat=y", UA);
            let a = assess(&agg, &base, &cfg(), false);
            if !a.alerts.is_empty() {
                alerted_cycles += 1;
            }
            base.update(&agg, &a.flagged_ua, &a.flagged_shape);
        }
        assert_eq!(
            alerted_cycles, 40,
            "must keep alerting for as long as it lasts"
        );
    }

    #[test]
    fn a_pattern_flagged_for_a_whole_day_is_eventually_absorbed() {
        // A new but legitimate steady pattern (a feature launched after
        // install) must not alert forever. After about a day it is learned.
        let mut base = warm();
        let mut last_alert = 0;
        for cycle in 1..=(MAX_FROZEN_CYCLES as usize + 40) {
            let mut agg = Aggregates::default();
            flood(&mut agg, 100, 2, "/?new-widget=1&v=2", UA);
            let a = assess(&agg, &base, &cfg(), false);
            if !a.alerts.is_empty() {
                last_alert = cycle;
            }
            base.update(&agg, &a.flagged_ua, &a.flagged_shape);
        }
        assert!(
            last_alert > MAX_FROZEN_CYCLES as usize,
            "must keep alerting for the whole frozen period (last alert at {last_alert})"
        );
        assert!(
            last_alert < MAX_FROZEN_CYCLES as usize + 30,
            "then it is learned and the alert stops (last alert at {last_alert})"
        );
    }

    #[test]
    fn the_alert_clears_when_the_attack_stops() {
        let mut base = warm();
        let mut agg = Aggregates::default();
        flood(&mut agg, 200, 2, "/?tss-sc=x&tsscat=y", UA);
        let a = assess(&agg, &base, &cfg(), false);
        base.update(&agg, &a.flagged_ua, &a.flagged_shape);
        // Back to a little normal traffic.
        let mut calm = Aggregates::default();
        flood(&mut calm, 4, 2, "/?tss-sc=x&tsscat=y", UA);
        assert!(assess(&calm, &base, &cfg(), false).alerts.is_empty());
    }

    #[test]
    fn a_page_without_parameters_is_not_a_shape_alert() {
        let mut agg = Aggregates::default();
        flood(&mut agg, 200, 2, "/promo", "Mozilla/5.0 Various");
        let a = assess(&agg, &warm(), &cfg(), false);
        assert!(a.alerts.iter().all(|x| x.kind != "bot_shape"));
    }

    #[test]
    fn a_crawler_claim_is_noted_but_not_trusted() {
        let mut agg = Aggregates::default();
        flood(
            &mut agg,
            60,
            2,
            "/page",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        );
        let a = assess(&agg, &warm(), &cfg(), false);
        let m = &a
            .alerts
            .iter()
            .find(|x| x.kind == "bot_ua")
            .unwrap()
            .message;
        assert!(m.contains("claims to be a known crawler"), "{m}");
    }

    #[test]
    fn flagged_patterns_carry_example_addresses_and_others_do_not() {
        let mut agg = Aggregates::default();
        flood(&mut agg, 200, 2, "/?a=1&b=2", UA);
        feed(&mut agg, "198.51.100.9", "/about", "curl/8.0");
        let a = assess(&agg, &warm(), &cfg(), false);
        let (uas, shapes) = agg.top_patterns(&a.flagged_ua, &a.flagged_shape);
        let flagged = uas.iter().find(|p| p.key == UA).unwrap();
        assert!(flagged.flagged);
        assert_eq!(flagged.ips, 200);
        assert_eq!(flagged.sample_ips.len(), SAMPLE_IPS);
        let other = uas.iter().find(|p| p.key == "curl/8.0").unwrap();
        assert!(!other.flagged && other.sample_ips.is_empty());
        assert!(shapes.iter().any(|p| p.flagged));
    }

    // ---- bounds ----------------------------------------------------------

    #[test]
    fn a_hostile_log_cannot_grow_memory_without_limit() {
        // Every request a different UA and a different parameter name.
        let mut agg = Aggregates::default();
        for i in 0..(MAX_KEYS as u32 + 500) {
            let ip = format!("10.1.{}.{}", i / 250 % 250, i % 250 + 1);
            feed(&mut agg, &ip, &format!("/?p{i}=1"), &format!("UA-{i}"));
        }
        assert_eq!(agg.ua.len(), MAX_KEYS);
        assert_eq!(agg.shapes.len(), MAX_KEYS);
        assert!(agg.overflow > 0, "the excess is counted, not stored");
    }

    #[test]
    fn address_tracking_per_pattern_is_capped() {
        let mut agg = Aggregates::default();
        flood(&mut agg, (IP_CAP + 100) as u32, 1, "/?a=1&b=2", UA);
        let st = &agg.ua[UA];
        assert_eq!(st.ips.len(), IP_CAP);
        assert!(st.capped());
        // Saturated means "at least this many": still a distributed signature,
        // even though requests-per-address cannot be computed.
        let a = assess(&agg, &warm(), &cfg(), false);
        assert!(a.flagged_ua.contains(UA));
        assert!(
            a.alerts[0].message.contains("256+"),
            "{}",
            a.alerts[0].message
        );
    }

    #[test]
    fn keys_are_cut_at_a_character_boundary() {
        let long = "é".repeat(500);
        let mut agg = Aggregates::default();
        feed(&mut agg, "198.51.100.1", "/x", &long);
        let key = agg.ua.keys().next().unwrap();
        assert_eq!(key.chars().count(), KEY_MAX_CHARS);
    }

    #[test]
    fn the_baseline_stays_bounded_and_forgets_what_stopped() {
        let mut base = warm();
        // Far more distinct patterns than the baseline keeps, each busy enough
        // to be remembered.
        let mut agg = Aggregates::default();
        for i in 0..(BASELINE_MAX as u32 + 300) {
            let ip = format!("10.2.{}.{}", i / 250, i % 250 + 1);
            for _ in 0..5 {
                feed(&mut agg, &ip, &format!("/?q{i}=1"), &format!("UA-{i}"));
            }
        }
        base.update(&agg, &HashSet::new(), &HashSet::new());
        assert!(base.shape.len() <= BASELINE_MAX && base.ua.len() <= BASELINE_MAX);
        // They stop arriving: the entries decay away.
        let empty = Aggregates::default();
        for _ in 0..30 {
            base.update(&empty, &HashSet::new(), &HashSet::new());
        }
        assert!(base.ua.is_empty() && base.shape.is_empty());
    }

    #[test]
    fn the_baseline_survives_a_save() {
        let mut base = warm();
        let mut agg = Aggregates::default();
        flood(&mut agg, 40, 2, "/?a=1&b=2", UA);
        base.update(&agg, &HashSet::new(), &HashSet::new());
        let json = serde_json::to_string(&base).unwrap();
        let back: BotBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cycles, base.cycles);
        assert_eq!(back.ua.len(), base.ua.len());
    }
}
