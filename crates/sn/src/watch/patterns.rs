//! Fixed detection patterns (no baseline needed), the `rate` rule, and the
//! per-address accumulator they all read.
//!
//! What a rule counts is chosen so that ordinary visitors stay below it:
//!
//! * `rate` counts **dynamic** requests (pages, APIs, forms), never page assets
//!   (images, CSS, JS, fonts, media) or 206/304 answers: one shopper's page
//!   view is one dynamic request and dozens of assets.
//! * Counters are kept **per site** (log file, or vhost where the format names
//!   it) and a rule fires on the busiest site, with a VPS-wide backstop at
//!   [`BACKSTOP`] times the per-site bar: an agency, a monitor or a crawler that
//!   touches forty sites on one VPS is not forty times one visitor.
//! * Several browsers behind one address (a carrier NAT, an office) raise the
//!   rate bar, up to [`MAX_CLIENTS`] times, and such a ban stays short.
//! * A request without a User-Agent or with a tool's taints only itself, not
//!   every other request from that address.
//!
//! Attacks keep matching: password guessing (WordPress answers a wrong
//! password with 200), XML-RPC floods, `.env`/`.git` sweeps, exploit sweeps
//! with a tool or no User-Agent, scanners with many 404s on non-asset paths, and
//! floods of several dynamic requests a second.

use std::collections::HashSet;

use snsec_common::logfmt::LogLine;

/// Counters of one address on one site in one cycle.
#[derive(Debug, Default, Clone, Copy)]
pub struct SiteCounters {
    /// Requests that are not page assets and not answered 206/304.
    pub dynamic: u64,
    /// POSTs to `wp-login.php` answered with anything but a redirect: a wrong
    /// password (200), or a lockout plugin's 401/403/429/503.
    pub login_fail: u64,
    /// POSTs to `wp-login.php` answered with a redirect: a successful login, a
    /// password-protected post unlocked (`?action=postpass`), a registration or
    /// a password reset.
    pub login_redirect: u64,
    /// POSTs to `xmlrpc.php` from WordPress itself (pingbacks) or Jetpack.
    pub xmlrpc_wp: u64,
    /// Every other POST to `xmlrpc.php` (`system.multicall` guessing...).
    pub xmlrpc_other: u64,
    /// 404s for a path that is not a page asset.
    pub err404_page: u64,
}

impl SiteCounters {
    fn add(&mut self, o: &SiteCounters) {
        self.dynamic += o.dynamic;
        self.login_fail += o.login_fail;
        self.login_redirect += o.login_redirect;
        self.xmlrpc_wp += o.xmlrpc_wp;
        self.xmlrpc_other += o.xmlrpc_other;
        self.err404_page += o.err404_page;
    }
}

/// Per-address aggregate for one cycle. Everything that could grow with the
/// traffic is capped (distinct paths, sites, browsers), so a hostile address
/// cannot blow up memory.
#[derive(Debug, Default)]
pub struct IpAgg {
    /// Every log line from this address, parsed or not.
    pub requests: u64,
    pub err4xx: u64,
    pub err404: u64,
    /// POSTs to wp-login.php / xmlrpc.php, whatever the answer (for the report).
    pub login_posts: u64,
    pub xmlrpc_posts: u64,
    pub wp_pingback: u64,
    /// Requests for a path only a scanner asks for (see [`is_probe_path`]).
    pub probe_hits: u64,
    /// Of those, the ones sent with no User-Agent or a tool's on that request.
    probe_nb_hits: u64,
    /// The kinds of probe asked for (bits of [`ProbeKind`]).
    probe_kinds: u16,
    /// 4xx answers to paths that are not page assets.
    err4xx_page: u64,
    /// 404s for non-asset paths sent with no User-Agent or a tool's.
    err404_page_nb: u64,
    /// Requests with a scanning tool's User-Agent, and those answered 4xx.
    bad_ua_reqs: u64,
    bad_ua_4xx: u64,
    /// Requests with no User-Agent, and those answered 4xx.
    empty_ua_reqs: u64,
    empty_ua_4xx: u64,
    /// Dynamic requests whose User-Agent is not a browser's (none, a tool's, a
    /// bot's, a library's).
    nonbrowser_dynamic: u64,
    /// Distinct browser User-Agents seen (hashes), up to [`BROWSER_UA_CAP`].
    browser_uas: Vec<u64>,
    /// Counters per site, up to [`MAX_SITES`] sites; `total` has them all.
    sites: Vec<(u64, SiteCounters)>,
    total: SiteCounters,
    paths: HashSet<u64>,
    paths_capped: bool,
}

const PATH_CAP: usize = 64;
/// Sites tracked per address; beyond them only the VPS-wide totals count.
const MAX_SITES: usize = 32;
/// Distinct browser User-Agents remembered per address.
const BROWSER_UA_CAP: usize = 24;
/// Most clients assumed behind one address when raising the rate bar.
pub const MAX_CLIENTS: u64 = 4;
/// A VPS-wide count must be this many times a per-site bar to match.
pub const BACKSTOP: u64 = 3;
/// All lines (assets included) may reach this many times the rate threshold:
/// a flood of static files is still a flood.
pub const TOTAL_FACTOR: u64 = 10;
/// A crawler verified by its address gets this many times the rate threshold.
pub const CRAWLER_FACTOR: u64 = 10;
/// Clients behind one address from which a rate ban is a short shared-NAT ban.
const SHARED_CLIENTS: u64 = 3;
/// Length of a rate ban that never climbs the ladder (shared NAT, crawler).
const SHORT_RATE_TTL: u64 = 600;
/// Longest a rate ban from browsers alone may get on the ladder.
const BROWSER_RATE_CAP: u64 = 3600;
/// Browsers and sites that make an address look like a proxy or CDN edge.
const PROXY_BROWSERS: usize = 20;
const PROXY_SITES: usize = 3;

/// Failed logins plus other XML-RPC POSTs on one site above which it is
/// password guessing.
const LOGIN_FAILS: u64 = 10;
/// Login redirects (successes, unlocks) or WordPress/Jetpack XML-RPC calls on
/// one site above which it is still abuse.
const LOGIN_REDIRECTS: u64 = 60;
const XMLRPC_WP: u64 = 60;
/// Page 404s on one site, over at least [`SCANNER_PATHS`] distinct paths.
const SCANNER_404: u64 = 30;
const SCANNER_PATHS: usize = 20;
/// Requests with a tool's User-Agent that ban by themselves (one answered 4xx
/// is enough).
const TOOL_UA_REQS: u64 = 3;
/// Requests without a User-Agent above which, if at least half were answered
/// 4xx, the address is a scanner.
const EMPTY_UA_REQS: u64 = 50;

/// Distinct probe kinds that make a sweep.
const PROBE_DISTINCT: u32 = 3;
/// 4xx answers over as many distinct paths that, with a probe, make a sweep.
const PROBE_MISSES: u64 = 10;
/// Ban for a sweep from a browser's User-Agent: short, and never escalated.
const PROBE_SWEEP_TTL: u64 = 600;
/// Up to this many requests a lone probe is reported. A busy address with one
/// stray `/.env` is not worth a line in the report.
const PROBE_REPORT_MAX: u64 = 20;

/// What a User-Agent says about its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UaClass {
    /// None at all (`""` or `-`).
    Empty,
    /// A scanning tool's (see [`BAD_UA`]).
    Tool,
    /// A browser's: `Mozilla/...`, not a bot's.
    Browser,
    /// Anything else: crawlers, HTTP libraries, WordPress, monitors.
    Other,
}

fn classify_ua(ua: &str) -> UaClass {
    let ua = ua.trim();
    if ua.is_empty() || ua == "-" {
        return UaClass::Empty;
    }
    let lower = ua.to_ascii_lowercase();
    if BAD_UA.iter().any(|b| lower.contains(b)) {
        return UaClass::Tool;
    }
    let botlike = [
        "bot", "crawl", "spider", "slurp", "http://", "https://", "headless",
    ]
    .iter()
    .any(|t| lower.contains(t));
    if lower.starts_with("mozilla/") && !botlike {
        UaClass::Browser
    } else {
        UaClass::Other
    }
}

impl IpAgg {
    /// Count one parsed request, made to `site` (any stable id: the log
    /// file's, or the vhost's when the format names it).
    pub fn observe(&mut self, line: &LogLine, site: u64) {
        self.requests += 1;
        let path = line.path.split('?').next().unwrap_or(&line.path);
        let asset = is_asset(path);
        let ua = classify_ua(&line.user_agent);
        let nb = matches!(ua, UaClass::Empty | UaClass::Tool);
        let is_4xx = (400..500).contains(&line.status);
        let mut c = SiteCounters::default();

        if is_4xx {
            self.err4xx += 1;
            if !asset {
                self.err4xx_page += 1;
            }
            if line.status == 404 {
                self.err404 += 1;
                if !asset {
                    c.err404_page = 1;
                    if nb {
                        self.err404_page_nb += 1;
                    }
                }
            }
        }
        if !asset && !matches!(line.status, 206 | 304) {
            c.dynamic = 1;
            if ua != UaClass::Browser {
                self.nonbrowser_dynamic += 1;
            }
        }
        if self.paths.len() < PATH_CAP {
            self.paths.insert(fxhash(path.as_bytes()));
        } else {
            self.paths_capped = true;
        }

        let is_post = line.method.eq_ignore_ascii_case("POST");
        if is_post && path.ends_with("/wp-login.php") {
            self.login_posts += 1;
            if (300..400).contains(&line.status) {
                c.login_redirect = 1;
            } else {
                c.login_fail = 1;
            }
        }
        if path.ends_with("/xmlrpc.php") {
            let wp = line.user_agent.starts_with("WordPress/");
            if is_post {
                self.xmlrpc_posts += 1;
                // Automattic's own servers call every Jetpack site of a VPS.
                if !snsec_common::ranges::is_jetpack(line.client) {
                    if wp || line.user_agent.contains("Jetpack") {
                        c.xmlrpc_wp = 1;
                    } else {
                        c.xmlrpc_other = 1;
                    }
                }
            }
            if wp {
                self.wp_pingback += 1;
            }
        }

        if let Some(kind) = is_probe_path(path) {
            // phpMyAdmin is a real tool on many hosting panels: only a miss is
            // a probe.
            if kind != ProbeKind::DbAdmin || is_4xx {
                self.probe_hits += 1;
                self.probe_kinds |= kind as u16;
                if nb {
                    self.probe_nb_hits += 1;
                }
            }
        }
        match ua {
            UaClass::Empty => {
                self.empty_ua_reqs += 1;
                if is_4xx {
                    self.empty_ua_4xx += 1;
                }
            }
            UaClass::Tool => {
                self.bad_ua_reqs += 1;
                if is_4xx {
                    self.bad_ua_4xx += 1;
                }
            }
            UaClass::Browser => {
                let h = fxhash(line.user_agent.trim().as_bytes());
                if self.browser_uas.len() < BROWSER_UA_CAP && !self.browser_uas.contains(&h) {
                    self.browser_uas.push(h);
                }
            }
            UaClass::Other => {}
        }

        self.total.add(&c);
        if let Some((_, s)) = self.sites.iter_mut().find(|(id, _)| *id == site) {
            s.add(&c);
        } else if self.sites.len() < MAX_SITES {
            self.sites.push((site, c));
        }
    }

    /// A line from this address that could not be parsed: still a request.
    pub fn observe_unparsed(&mut self) {
        self.requests += 1;
    }

    #[must_use]
    pub fn distinct_paths(&self) -> usize {
        if self.paths_capped {
            PATH_CAP
        } else {
            self.paths.len()
        }
    }

    /// Dynamic requests from this address on every site of the VPS.
    #[must_use]
    pub fn dynamic(&self) -> u64 {
        self.total.dynamic
    }

    /// The most of one counter on any one site.
    fn site_max(&self, f: impl Fn(&SiteCounters) -> u64) -> u64 {
        self.sites.iter().map(|(_, s)| f(s)).max().unwrap_or(0)
    }

    /// Dynamic requests from this address on its busiest site: what the rate
    /// threshold is measured against, and what the baseline learns.
    #[must_use]
    pub fn site_dynamic(&self) -> u64 {
        self.site_max(|s| s.dynamic)
    }

    /// How many people seem to be behind this address: its distinct browser
    /// User-Agents, from 1 up to [`MAX_CLIENTS`].
    #[must_use]
    pub fn clients(&self) -> u64 {
        (self.browser_uas.len() as u64).clamp(1, MAX_CLIENTS)
    }

    /// Many browsers on several sites: what a proxy or CDN edge that is not
    /// in `trusted_proxies` looks like in the logs.
    #[must_use]
    pub fn looks_like_proxy(&self) -> bool {
        self.browser_uas.len() >= PROXY_BROWSERS && self.sites.len() >= PROXY_SITES
    }

    /// Mostly browsers: at most a quarter of the dynamic requests came with
    /// another User-Agent.
    fn browser_looking(&self) -> bool {
        self.nonbrowser_dynamic.saturating_mul(4) <= self.total.dynamic
    }

    /// Several probe kinds, or a probe among many misses: what a scan looks
    /// like, and also what a web page can make a visitor's browser do.
    fn probe_sweep(&self) -> bool {
        self.probe_hits > 0
            && (self.probe_kinds.count_ones() >= PROBE_DISTINCT
                || (self.err4xx_page >= PROBE_MISSES
                    && self.distinct_paths() >= PROBE_MISSES as usize))
    }

    /// Password guessing on one site, or across many.
    fn bruteforce(&self) -> bool {
        let over = |s: &SiteCounters, f: u64| {
            s.login_fail + s.xmlrpc_other > LOGIN_FAILS * f
                || s.login_redirect > LOGIN_REDIRECTS * f
                || s.xmlrpc_wp > XMLRPC_WP * f
        };
        self.sites.iter().any(|(_, s)| over(s, 1)) || over(&self.total, BACKSTOP)
    }

    /// Many 404s for pages (not images or scripts) over many paths.
    fn scanner(&self) -> bool {
        let pages = self.site_max(|s| s.err404_page) > SCANNER_404
            || self.total.err404_page > SCANNER_404 * BACKSTOP;
        pages && self.distinct_paths() > SCANNER_PATHS
    }
}

/// Outcome of evaluating the rules for one address.
#[derive(Debug, Clone)]
pub struct PatternHit {
    pub reason: &'static str,
    pub ttl_secs: u64,
    /// `false` for report-only patterns (e.g. xmlrpc pingback).
    pub ban: bool,
    /// Counts as a strike and grows on the ladder. `false` when nothing in the
    /// evidence is beyond what a web page can make a visitor's browser send,
    /// or for a busy shared address: that ban stays as short as `ttl_secs`
    /// however often it recurs.
    pub escalate: bool,
    /// Longest the ladder may make this ban (0: no limit).
    pub ttl_cap: u64,
}

fn hit(reason: &'static str, ttl_secs: u64, ban: bool, escalate: bool) -> Option<PatternHit> {
    Some(PatternHit {
        reason,
        ttl_secs,
        ban,
        escalate,
        ttl_cap: 0,
    })
}

/// Evaluate the fixed patterns. A cycle covers roughly one timer interval of
/// logs, so the plan's per-5-minute windows map onto a single cycle.
/// `crawler`: the address is in a search crawler's published ranges (it may
/// follow stale links into many 404s: reported, not banned). `volume`: the
/// cycle covers a normal stretch of log, so counts of 404s mean what they say.
#[must_use]
pub fn evaluate(a: &IpAgg, crawler: bool, volume: bool) -> Option<PatternHit> {
    if a.bruteforce() {
        return hit("bruteforce", 3600, true, true);
    }
    if a.probe_nb_hits > 0 {
        return hit("probe", 86_400, true, true);
    }
    let mut report = None;
    if volume && a.scanner() {
        let nb = a.err404_page_nb * 2 > a.total.err404_page;
        if crawler {
            report = hit("scanner", 0, false, false);
        } else {
            return hit("scanner", 1800, true, nb);
        }
    }
    if a.bad_ua_reqs >= TOOL_UA_REQS || a.bad_ua_4xx > 0 {
        return hit("bad_ua", 3600, true, true);
    }
    if a.empty_ua_reqs > EMPTY_UA_REQS && a.empty_ua_4xx * 2 >= a.empty_ua_reqs {
        return hit("bad_ua", 86_400, true, true);
    }
    if a.probe_sweep() {
        return hit("probe", PROBE_SWEEP_TTL, true, false);
    }
    if report.is_some() {
        return report;
    }
    if a.wp_pingback > 3 {
        return hit("xmlrpc_pingback", 0, false, false);
    }
    if a.probe_hits > 0 && a.requests <= PROBE_REPORT_MAX {
        return hit("probe", 0, false, false);
    }
    None
}

/// What the rules need to know besides the address's own counts.
#[derive(Debug, Clone, Copy)]
pub struct Judge {
    /// Dynamic requests one client may make on one site this cycle.
    pub threshold: u64,
    /// The baseline has learned this server's traffic. Until then a rate hit
    /// is only reported, unless the address passes `ceiling`.
    pub baseline_ready: bool,
    /// Dynamic requests (on all sites) at or above which a rate hit bans even
    /// while the baseline is still learning, or from a proxy-looking address.
    pub ceiling: u64,
    /// The cycle covers a normal stretch of log: `rate` and `scanner` are
    /// judged. Not after a gap, when hours of traffic arrive at once.
    pub volume: bool,
    /// The address is in a search crawler's published ranges.
    pub crawler: bool,
}

/// Every rule for one address: the fixed patterns, then `rate`.
#[must_use]
pub fn judge(a: &IpAgg, j: &Judge) -> Option<PatternHit> {
    let found = evaluate(a, j.crawler, j.volume);
    if !j.volume {
        return found;
    }
    let Some(rate) = rate_hit(a, j) else {
        return found;
    };
    match found {
        // A pattern that bans and climbs the ladder keeps its own reason.
        Some(h) if h.ban && h.escalate => Some(h),
        // A report-only rate hit never hides a ban.
        Some(h) if h.ban && !rate.ban => Some(h),
        // Over the rate threshold, a pattern that only reports or never
        // escalates must not shield the flood from the rate ban.
        Some(h) if rate.ban => Some(PatternHit {
            ttl_secs: rate.ttl_secs.max(h.ttl_secs),
            ..rate
        }),
        _ => Some(rate),
    }
}

/// The `rate` rule. The bar is `threshold` dynamic requests on one site, times
/// the browsers behind the address (at most [`MAX_CLIENTS`]); also matched by
/// [`BACKSTOP`] times that on all sites together, or by every line (assets
/// too) reaching [`TOTAL_FACTOR`] times `threshold`.
fn rate_hit(a: &IpAgg, j: &Judge) -> Option<PatternHit> {
    let t = if j.crawler {
        j.threshold.saturating_mul(CRAWLER_FACTOR)
    } else {
        j.threshold
    };
    let clients = a.clients();
    let bar = t.saturating_mul(clients);
    let over = a.site_dynamic() >= bar
        || a.dynamic() >= bar.saturating_mul(BACKSTOP)
        || a.requests >= t.saturating_mul(TOTAL_FACTOR);
    if !over {
        return None;
    }
    let rate = |ttl_secs, ban, escalate, ttl_cap| {
        Some(PatternHit {
            reason: "rate",
            ttl_secs,
            ban,
            escalate,
            ttl_cap,
        })
    };
    let ceiling = a.dynamic() >= j.ceiling;
    if (!j.baseline_ready || a.looks_like_proxy()) && !ceiling {
        return rate(0, false, false, 0);
    }
    if j.crawler || clients >= SHARED_CLIENTS {
        // A search engine, or a carrier NAT / office: a short fixed ban, never
        // the week-long ladder.
        return rate(SHORT_RATE_TTL, true, false, 0);
    }
    let cap = if a.browser_looking() {
        BROWSER_RATE_CAP
    } else {
        0
    };
    rate(SHORT_RATE_TTL, true, true, cap)
}

/// What a probe path is after: one kind per secret or tool, however many
/// spellings or files of it a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum ProbeKind {
    Env = 1,
    Git = 1 << 1,
    Svn = 1 << 2,
    Hg = 1 << 3,
    Aws = 1 << 4,
    DbAdmin = 1 << 5,
    WpConfigBackup = 1 << 6,
    DsStore = 1 << 7,
    PhpUnit = 1 << 8,
}

/// Paths only a scanner asks for: secrets and version-control data left in the
/// web root, and database admin tools. Matched on whole path segments, so
/// `/blog/.environment`, `/assets/config.json` or a post called
/// `/phpmyadmin-la-gi/` are ordinary requests.
fn is_probe_path(path: &str) -> Option<ProbeKind> {
    let lower = path.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    let (first, last) = (segs.first()?, segs.last()?);
    // .env, .env.local, .env.bak, .env~ - but not .envrc or .environment.
    let env_file = last
        .strip_prefix(".env")
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphanumeric()));
    if env_file {
        return Some(ProbeKind::Env);
    }
    if matches!(*last, "wp-config.php.bak" | "wp-config.php~") {
        return Some(ProbeKind::WpConfigBackup);
    }
    if *last == ".ds_store" {
        return Some(ProbeKind::DsStore);
    }
    for s in &segs {
        match *s {
            ".git" => return Some(ProbeKind::Git),
            ".svn" => return Some(ProbeKind::Svn),
            ".hg" => return Some(ProbeKind::Hg),
            ".aws" => return Some(ProbeKind::Aws),
            _ => {}
        }
    }
    // The directory itself, or a versioned install of it (`phpMyAdmin-5.2.1`).
    let db_admin = *first == "pma"
        || first.strip_prefix("phpmyadmin").is_some_and(|rest| {
            rest.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
        });
    if db_admin {
        return Some(ProbeKind::DbAdmin);
    }
    if segs.windows(2).any(|w| w == ["vendor", "phpunit"]) {
        return Some(ProbeKind::PhpUnit);
    }
    None
}

/// File types a page pulls in by itself: styles, scripts, images, fonts and
/// media. Archives, backups, `.txt`, `.xml` and `.php` are not: a scanner asks
/// for those, and a sitemap is generated by PHP.
const ASSET_EXT: &[&str] = &[
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp",
    "tif", "tiff", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "m4a",
    "mov",
];

/// Is this a page asset? Judged by the extension of the last path segment (no
/// query string).
#[must_use]
pub fn is_asset(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or(path);
    match last.rsplit_once('.') {
        Some((_, ext)) => ASSET_EXT.iter().any(|e| ext.eq_ignore_ascii_case(e)),
        None => false,
    }
}

/// What a scanning tool's User-Agent contains (lowercase).
const BAD_UA: &[&str] = &[
    "sqlmap",
    "nikto",
    "masscan",
    "nmap",
    "zgrab",
    "dirbuster",
    "wpscan",
    "acunetix",
    "nuclei",
    "havij",
];

/// FxHash-style hash for path dedup (fast, non-crypto).
fn fxhash(bytes: &[u8]) -> u64 {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
    let mut h: u64 = 0;
    for &b in bytes {
        h = (h.rotate_left(5) ^ b as u64).wrapping_mul(SEED);
    }
    h
}

#[cfg(test)]
mod tests;
