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
//!   rate bar, up to [`MAX_CLIENTS`] times, and such a ban stays short. A
//!   browser counts once it has fetched what a page pulls in (an image, a
//!   script, a 304): a flood tool that only rotates User-Agents gains nothing.
//! * A request without a User-Agent or with a tool's taints only itself, not
//!   every other request from that address.
//!
//! Paths are read the way the server resolves them (query cut, percent-decoded,
//! `//`, `.` and `..` resolved, a `.php` segment anywhere is the script), so
//! `/wp-login.php/x.css` or `/wp-login%2ephp` is a login, not an image.
//!
//! Attacks keep matching: password guessing (WordPress answers a wrong
//! password with 200), XML-RPC floods, `.env`/`.git` sweeps, exploit sweeps
//! with a tool, a library or no User-Agent, scanners with many 404s on
//! non-asset paths, and floods of several dynamic requests a second.

use snsec_common::logfmt::LogLine;

use super::decide::scale;

/// Counters of one address on one site in one cycle.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SiteCounters {
    /// Every line, assets included.
    pub lines: u32,
    /// Requests that are not page assets and not answered 206/304.
    pub dynamic: u32,
    /// 404s for a page asset (`/r123.css`): cheap for nginx, a full WordPress
    /// page render where `.htaccess` sends misses to `index.php`.
    pub asset_miss: u32,
    /// POSTs to `wp-login.php` answered with anything but a redirect: a wrong
    /// password (200), a lockout plugin's 401/403/429/503, the first step of a
    /// two-factor login (200).
    pub login_fail: u32,
    /// POSTs to `wp-login.php` answered with a redirect: a successful login,
    /// or a refusal from a plugin that redirects failed logins.
    pub login_ok: u32,
    /// The same for `?action=postpass` (a password-protected post unlocked),
    /// `register` and `lostpassword`.
    pub login_other: u32,
    /// Logged-in admin pages (`/wp-admin/`, `post.php`...) answered 200: what
    /// a successful login is followed by.
    pub admin_ok: u32,
    /// POSTs to `xmlrpc.php` with WordPress's own User-Agent (pingbacks).
    pub xmlrpc_wp: u32,
    /// Every other POST to `xmlrpc.php` (`system.multicall` guessing...).
    pub xmlrpc_other: u32,
    /// 404s for a path that is not a page asset.
    pub err404_page: u32,
}

impl SiteCounters {
    fn add(&mut self, o: &SiteCounters) {
        let add = |a: &mut u32, b: u32| *a = a.saturating_add(b);
        add(&mut self.lines, o.lines);
        add(&mut self.dynamic, o.dynamic);
        add(&mut self.asset_miss, o.asset_miss);
        add(&mut self.login_fail, o.login_fail);
        add(&mut self.login_ok, o.login_ok);
        add(&mut self.login_other, o.login_other);
        add(&mut self.admin_ok, o.admin_ok);
        add(&mut self.xmlrpc_wp, o.xmlrpc_wp);
        add(&mut self.xmlrpc_other, o.xmlrpc_other);
        add(&mut self.err404_page, o.err404_page);
    }
}

/// The per-site counters of one address: the first site inline (most
/// addresses visit one), the others in a list grown one entry at a time.
#[derive(Debug, Default)]
struct Sites {
    first: Option<(u32, SiteCounters)>,
    more: Vec<(u32, SiteCounters)>,
}

impl Sites {
    fn add(&mut self, site: u32, c: &SiteCounters) {
        match &mut self.first {
            None => {
                self.first = Some((site, *c));
                return;
            }
            Some((id, s)) if *id == site => {
                s.add(c);
                return;
            }
            Some(_) => {}
        }
        if let Some((_, s)) = self.more.iter_mut().find(|(id, _)| *id == site) {
            s.add(c);
        } else if self.more.len() + 1 < MAX_SITES {
            self.more.reserve_exact(1);
            self.more.push((site, *c));
        }
    }

    fn iter(&self) -> impl Iterator<Item = &SiteCounters> {
        self.first.iter().chain(&self.more).map(|(_, s)| s)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        usize::from(self.first.is_some()) + self.more.len()
    }
}

/// Per-address aggregate for one cycle. Everything that could grow with the
/// traffic is capped (distinct paths, sites, browsers), and the counters are
/// 32-bit, so a flood of addresses stays within the service's memory limit.
#[derive(Debug, Default)]
pub struct IpAgg {
    /// Every log line from this address, parsed or not.
    pub requests: u32,
    pub err4xx: u32,
    pub err404: u32,
    /// POSTs to wp-login.php / xmlrpc.php, whatever the answer (for the report).
    pub login_posts: u32,
    pub xmlrpc_posts: u32,
    pub wp_pingback: u32,
    /// Requests for a path only a scanner asks for (see [`is_probe_path`]).
    pub probe_hits: u32,
    /// Of those, the ones sent with no User-Agent or a tool's on that request...
    probe_tool_hits: u32,
    /// ...and those sent with another User-Agent that is not a browser's (an
    /// HTTP library, a bot): no browser sends those, whatever page it is on.
    probe_other_hits: u32,
    /// The kinds of probe asked for (bits of [`ProbeKind`]).
    probe_kinds: u16,
    /// 4xx answers to paths that are not page assets.
    err4xx_page: u32,
    /// 404s for non-asset paths sent with a User-Agent that is not a browser's.
    err404_page_nb: u32,
    /// Requests with a scanning tool's User-Agent, and those answered 4xx.
    bad_ua_reqs: u32,
    bad_ua_4xx: u32,
    /// Requests with no User-Agent, and those answered 4xx.
    empty_ua_reqs: u32,
    empty_ua_4xx: u32,
    /// Dynamic requests, and lines, whose User-Agent is not a browser's (none,
    /// a tool's, a bot's, a library's).
    nonbrowser_dynamic: u32,
    nonbrowser_lines: u32,
    /// Lines whose User-Agent claims a known crawler (not verified).
    crawler_claims: u32,
    /// Distinct browser User-Agents seen (31-bit hashes), up to
    /// [`BROWSER_UA_CAP`]; the top bit is set once that browser fetched a page
    /// asset or got a 206/304, as a browser rendering pages does.
    browser_uas: Vec<u32>,
    sites: Sites,
    /// Every site together.
    total: SiteCounters,
    /// Distinct paths (hashes), up to [`PATH_CAP`].
    paths: Vec<u32>,
    paths_capped: bool,
}

/// Distinct paths remembered per address.
const PATH_CAP: usize = 32;
/// Sites tracked per address; beyond them only the VPS-wide totals count.
const MAX_SITES: usize = 8;
/// Distinct browser User-Agents remembered per address.
const BROWSER_UA_CAP: usize = 24;
const RENDERED: u32 = 1 << 31;
/// Most clients assumed behind one address when raising the rate bar.
pub const MAX_CLIENTS: u64 = 4;
/// A VPS-wide count must be this many times a per-site bar to match.
pub const BACKSTOP: u64 = 3;
/// All lines (assets included) on one site may reach this many times the rate
/// threshold: a flood of static files is still a flood...
pub const TOTAL_FACTOR: u64 = 10;
/// ...and never fewer than this many per cycle, whatever the floor.
const TOTAL_FLOOR: u64 = 3000;
/// 404s for page assets on one site may reach this many times the rate bar.
const ASSET_MISS_FACTOR: u64 = 3;
/// A crawler verified by its address gets this many times the rate threshold.
pub const CRAWLER_FACTOR: u64 = 10;
/// Clients behind one address (browsing many pages) from which a rate ban is
/// a short shared-NAT ban.
const SHARED_CLIENTS: u64 = 3;
/// Lines per dynamic request from which an address is rendering pages (a
/// browser fetching each page's images, scripts and styles).
const RENDER_RATIO: u64 = 3;
/// Length of a rate ban that never climbs the ladder (shared NAT, crawler).
const SHORT_RATE_TTL: u64 = 600;
/// Longest a rate ban from browsers alone may get on the ladder.
const BROWSER_RATE_CAP: u64 = 3600;
/// A browser-looking address is banned for `rate` only this many times over
/// its bar (below the absolute ceiling): plain busy browsing is reported.
const CLEAR_FACTOR: u64 = 3;
/// Rendering browsers that make an address look like a proxy or CDN edge.
const PROXY_BROWSERS: usize = 20;

/// Failed logins plus other XML-RPC POSTs on one site above which it is
/// password guessing.
const LOGIN_FAILS: u64 = 10;
/// Redirected logins on one site that no logged-in admin page followed (a
/// plugin that redirects failed logins, or logins to the front end).
const LOGINS_UNCONFIRMED: u64 = 30;
/// Unlocked protected posts, registrations, password-reset requests, or
/// WordPress's own XML-RPC calls on one site above which it is still abuse.
const LOGIN_OTHER: u64 = 60;
const XMLRPC_WP: u64 = 20;
/// Page 404s on one site, over at least [`SCANNER_PATHS`] distinct paths.
const SCANNER_404: u64 = 30;
const SCANNER_PATHS: usize = 20;
/// Requests with a tool's User-Agent that ban by themselves (one answered 4xx
/// is enough).
const TOOL_UA_REQS: u32 = 3;
/// Requests without a User-Agent above which, if at least half were answered
/// 4xx, the address is a scanner.
const EMPTY_UA_REQS: u64 = 50;

/// Distinct probe kinds that make a sweep.
const PROBE_DISTINCT: u32 = 3;
/// 4xx answers over as many distinct paths that, with a probe, make a sweep.
const PROBE_MISSES: u32 = 10;
/// Ban for a sweep from a browser's User-Agent: short, and never escalated.
const PROBE_SWEEP_TTL: u64 = 600;
/// Up to this many requests a lone probe is reported. A busy address with one
/// stray `/.env` is not worth a line in the report.
const PROBE_REPORT_MAX: u32 = 20;

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

/// A request path read the way the web server resolves it.
#[derive(Debug, PartialEq, Eq)]
struct ReqPath {
    /// No query string or fragment, percent-decoded once, `//`, `.` and `..`
    /// resolved; `/` for the root.
    norm: String,
    /// It names a directory (ends in `/`), not a file.
    dir: bool,
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `%XX` decoded once, as the server does before it looks for the file.
fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl ReqPath {
    fn of(raw: &str) -> ReqPath {
        let path = raw.split(['?', '#']).next().unwrap_or(raw);
        // Most paths are already plain: one copy, no splitting.
        let plain = path.starts_with('/')
            && !path.contains('%')
            && !path.contains("//")
            && !path.contains("/./")
            && !path.contains("/../")
            && !path.ends_with("/.")
            && !path.ends_with("/..");
        if plain {
            let dir = path.ends_with('/');
            let trimmed = path.trim_end_matches('/');
            let norm = if trimmed.is_empty() { "/" } else { trimmed };
            return ReqPath {
                norm: norm.to_string(),
                dir,
            };
        }
        let decoded = percent_decode(path);
        let mut segs: Vec<&str> = Vec::new();
        for s in decoded.split('/') {
            match s {
                "" | "." => {}
                ".." => {
                    segs.pop();
                }
                s => segs.push(s),
            }
        }
        let dir = segs.is_empty()
            || decoded.ends_with('/')
            || decoded.ends_with("/.")
            || decoded.ends_with("/..");
        let mut norm = String::with_capacity(decoded.len() + 1);
        for s in &segs {
            norm.push('/');
            norm.push_str(s);
        }
        if norm.is_empty() {
            norm.push('/');
        }
        ReqPath { norm, dir }
    }

    fn segments(&self) -> impl Iterator<Item = &str> {
        self.norm.split('/').filter(|s| !s.is_empty())
    }

    /// The PHP script the server runs: the first segment that names a `.php`
    /// file. What follows it (`/wp-login.php/x.css`) is only PATH_INFO.
    fn script(&self) -> Option<&str> {
        self.segments()
            .find(|s| s.len() > 4 && s.as_bytes()[s.len() - 4..].eq_ignore_ascii_case(b".php"))
    }

    /// A page asset: a file with an asset's extension, run by no script.
    fn is_asset(&self) -> bool {
        if self.dir || self.script().is_some() {
            return false;
        }
        let last = self.segments().last().unwrap_or("");
        match last.rsplit_once('.') {
            Some((_, ext)) => ASSET_EXT.iter().any(|e| ext.eq_ignore_ascii_case(e)),
            None => false,
        }
    }

    /// A wp-admin page only a logged-in user gets with a 200: the dashboard
    /// itself or one of the usual screens (not `admin-ajax.php`,
    /// `admin-post.php`, `install.php`... which answer anyone).
    fn is_admin_page(&self) -> bool {
        if !self
            .norm
            .as_bytes()
            .windows(8)
            .any(|w| w.eq_ignore_ascii_case(b"wp-admin"))
        {
            return false;
        }
        let segs: Vec<&str> = self.segments().collect();
        let Some(at) = segs.iter().position(|s| s.eq_ignore_ascii_case("wp-admin")) else {
            return false;
        };
        match &segs[at + 1..] {
            [] => true,
            [page] => ADMIN_PAGES.iter().any(|p| page.eq_ignore_ascii_case(p)),
            _ => false,
        }
    }
}

/// The value of `name` in a request's query string, as sent.
fn query_param<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let q = raw.split_once('?')?.1;
    let q = q.split('#').next().unwrap_or(q);
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then_some(v)
    })
}

/// Screens under `/wp-admin/` that need a login.
const ADMIN_PAGES: &[&str] = &[
    "index.php",
    "admin.php",
    "edit.php",
    "post.php",
    "post-new.php",
    "profile.php",
    "upload.php",
    "media-new.php",
    "users.php",
    "user-edit.php",
    "plugins.php",
    "themes.php",
    "options-general.php",
    "edit-comments.php",
    "edit-tags.php",
    "update-core.php",
    "tools.php",
    "nav-menus.php",
    "widgets.php",
    "customize.php",
    "site-editor.php",
];

/// `wp-login.php` actions whose redirect is no login: unlocking a protected
/// post, registering, asking for a password reset.
const LOGIN_OTHER_ACTIONS: &[&str] = &["postpass", "register", "lostpassword", "retrievepassword"];

impl IpAgg {
    /// Count one parsed request, made to `site` (any stable id: the log
    /// file's, or the vhost's when the format names it).
    pub fn observe(&mut self, line: &LogLine, site: u32) {
        let inc = |n: &mut u32| *n = n.saturating_add(1);
        inc(&mut self.requests);
        let p = ReqPath::of(&line.path);
        let asset = p.is_asset();
        let ua = classify_ua(&line.user_agent);
        let browser = ua == UaClass::Browser;
        let status = line.status;
        let is_4xx = (400..500).contains(&status);
        let cached = matches!(status, 206 | 304);
        let mut c = SiteCounters {
            lines: 1,
            ..SiteCounters::default()
        };

        if !browser {
            inc(&mut self.nonbrowser_lines);
        }
        if is_4xx {
            inc(&mut self.err4xx);
            if !asset {
                inc(&mut self.err4xx_page);
            }
        }
        if status == 404 {
            inc(&mut self.err404);
            if asset {
                c.asset_miss = 1;
            } else {
                c.err404_page = 1;
                if !browser {
                    inc(&mut self.err404_page_nb);
                }
            }
        }
        if !asset && !cached {
            c.dynamic = 1;
            if !browser {
                inc(&mut self.nonbrowser_dynamic);
            }
        }
        self.note_path(&p.norm);

        let is_post = line.method.eq_ignore_ascii_case("POST");
        match p.script() {
            Some(s) if s.eq_ignore_ascii_case("wp-login.php") && is_post => {
                inc(&mut self.login_posts);
                if (300..400).contains(&status) {
                    let action = query_param(&line.path, "action").unwrap_or("");
                    if LOGIN_OTHER_ACTIONS.contains(&action) {
                        c.login_other = 1;
                    } else {
                        c.login_ok = 1;
                    }
                } else {
                    c.login_fail = 1;
                }
            }
            Some(s) if s.eq_ignore_ascii_case("xmlrpc.php") => {
                let wp = line.user_agent.starts_with("WordPress/");
                if is_post {
                    inc(&mut self.xmlrpc_posts);
                    // Automattic's own servers call every Jetpack site of a VPS.
                    if !snsec_common::ranges::is_jetpack(line.client) {
                        if wp {
                            c.xmlrpc_wp = 1;
                        } else {
                            c.xmlrpc_other = 1;
                        }
                    }
                }
                if wp {
                    inc(&mut self.wp_pingback);
                }
            }
            _ => {}
        }
        if status == 200 && line.method.eq_ignore_ascii_case("GET") && p.is_admin_page() {
            c.admin_ok = 1;
        }

        if let Some(kind) = is_probe_path(&p.norm) {
            // phpMyAdmin is a real tool on many hosting panels: only a miss is
            // a probe.
            if kind != ProbeKind::DbAdmin || is_4xx {
                inc(&mut self.probe_hits);
                self.probe_kinds |= kind as u16;
                match ua {
                    UaClass::Empty | UaClass::Tool => inc(&mut self.probe_tool_hits),
                    UaClass::Other => inc(&mut self.probe_other_hits),
                    UaClass::Browser => {}
                }
            }
        }
        match ua {
            UaClass::Empty => {
                inc(&mut self.empty_ua_reqs);
                if is_4xx {
                    inc(&mut self.empty_ua_4xx);
                }
            }
            UaClass::Tool => {
                inc(&mut self.bad_ua_reqs);
                if is_4xx {
                    inc(&mut self.bad_ua_4xx);
                }
            }
            UaClass::Browser => {
                self.note_browser(&line.user_agent, (asset && status < 400) || cached);
            }
            UaClass::Other => {
                if snsec_common::waf::claims_crawler(&line.user_agent) {
                    inc(&mut self.crawler_claims);
                }
            }
        }

        self.total.add(&c);
        self.sites.add(site, &c);
    }

    /// A line from this address that could not be parsed: still a request.
    pub fn observe_unparsed(&mut self, site: u32) {
        self.requests = self.requests.saturating_add(1);
        self.nonbrowser_lines = self.nonbrowser_lines.saturating_add(1);
        let c = SiteCounters {
            lines: 1,
            ..SiteCounters::default()
        };
        self.total.add(&c);
        self.sites.add(site, &c);
    }

    fn note_path(&mut self, norm: &str) {
        let h = fxhash(norm.as_bytes()) as u32;
        if self.paths.contains(&h) {
            return;
        }
        if self.paths.len() < PATH_CAP {
            self.paths.push(h);
        } else {
            self.paths_capped = true;
        }
    }

    fn note_browser(&mut self, ua: &str, rendered: bool) {
        let h = fxhash(ua.trim().as_bytes()) as u32 & !RENDERED;
        let flag = if rendered { RENDERED } else { 0 };
        if let Some(x) = self.browser_uas.iter_mut().find(|x| **x & !RENDERED == h) {
            *x |= flag;
        } else if self.browser_uas.len() < BROWSER_UA_CAP {
            self.browser_uas.push(h | flag);
        }
    }

    #[must_use]
    pub fn distinct_paths(&self) -> usize {
        if self.paths_capped {
            PATH_CAP + 1
        } else {
            self.paths.len()
        }
    }

    /// Dynamic requests from this address on every site of the VPS.
    #[must_use]
    pub fn dynamic(&self) -> u64 {
        u64::from(self.total.dynamic)
    }

    /// Every line from this address on every site of the VPS.
    #[must_use]
    pub fn lines(&self) -> u64 {
        u64::from(self.total.lines)
    }

    /// The most of one counter on any one site.
    fn site_max(&self, f: impl Fn(&SiteCounters) -> u32) -> u64 {
        self.sites
            .iter()
            .map(|s| u64::from(f(s)))
            .max()
            .unwrap_or(0)
    }

    /// Dynamic requests from this address on its busiest site: what the rate
    /// threshold is measured against, and what the baseline learns.
    #[must_use]
    pub fn site_dynamic(&self) -> u64 {
        self.site_max(|s| s.dynamic)
    }

    /// Browsers seen fetching what pages pull in (assets, 206/304 answers).
    fn rendering_browsers(&self) -> u64 {
        self.browser_uas
            .iter()
            .filter(|x| **x & RENDERED != 0)
            .count() as u64
    }

    /// How many people seem to be behind this address, from 1 up to
    /// [`MAX_CLIENTS`]: its rendering browsers, and at least two for an address
    /// that renders pages. Browsers of one make and version send the same
    /// User-Agent (an office on managed Chrome, a family of Android phones),
    /// so a busy rendering address is not taken for one person.
    #[must_use]
    pub fn clients(&self) -> u64 {
        let mut n = self.rendering_browsers();
        if self.rendering() {
            n = n.max(2);
        }
        n.clamp(1, MAX_CLIENTS)
    }

    /// Many rendering browsers over many pages: what a proxy or CDN edge that
    /// is not in `trusted_proxies` looks like in the logs, on one site or
    /// several. A flood that rotates User-Agents hits a few paths.
    #[must_use]
    pub fn looks_like_proxy(&self) -> bool {
        self.rendering_browsers() >= PROXY_BROWSERS as u64 && self.many_paths()
    }

    /// More distinct paths than are remembered: people browsing a site, not
    /// a tool repeating a few requests.
    fn many_paths(&self) -> bool {
        self.distinct_paths() > PATH_CAP
    }

    /// Mostly browsers: at most a quarter of the lines, and of the dynamic
    /// requests, came with another User-Agent.
    #[must_use]
    pub fn browser_looking(&self) -> bool {
        u64::from(self.nonbrowser_dynamic) * 4 <= self.dynamic()
            && u64::from(self.nonbrowser_lines) * 4 <= u64::from(self.requests)
    }

    /// Browsers rendering pages: several lines (assets) per dynamic request.
    fn rendering(&self) -> bool {
        self.browser_looking()
            && self.dynamic() > 0
            && self.lines() >= RENDER_RATIO * self.dynamic()
    }

    /// Most lines claim a known crawler by User-Agent (not verified).
    fn claims_crawler(&self) -> bool {
        self.crawler_claims > 0 && u64::from(self.crawler_claims) * 2 > u64::from(self.requests)
    }

    /// Several probe kinds, or a probe among many misses: what a scan looks
    /// like, and also what a web page can make a visitor's browser do.
    fn probe_sweep(&self) -> bool {
        self.probe_hits > 0
            && (self.probe_kinds.count_ones() >= PROBE_DISTINCT
                || (self.err4xx_page >= PROBE_MISSES
                    && self.distinct_paths() >= PROBE_MISSES as usize))
    }

    /// Password guessing on one site, or across many. A redirected login
    /// counts as a success only when a logged-in admin page followed it; each
    /// such success also excuses one answered-200 attempt (the first step of a
    /// two-factor login). Redirects nothing confirmed get a bar of their own.
    fn bruteforce(&self, span: i64) -> bool {
        let bar = |x: u64, f: u64| scale(x, span).saturating_mul(f);
        let over = |s: &SiteCounters, f: u64| {
            let confirmed = s.login_ok.min(s.admin_ok);
            let fails =
                u64::from(s.login_fail.saturating_sub(confirmed)) + u64::from(s.xmlrpc_other);
            let unconfirmed = u64::from(s.login_ok - confirmed);
            fails > bar(LOGIN_FAILS, f)
                || unconfirmed > bar(LOGINS_UNCONFIRMED, f)
                || u64::from(s.login_other) > bar(LOGIN_OTHER, f)
                || u64::from(s.xmlrpc_wp) > bar(XMLRPC_WP, f)
        };
        self.sites.iter().any(|s| over(s, 1)) || over(&self.total, BACKSTOP)
    }

    /// Many 404s for pages (not images or scripts) over many paths.
    fn scanner(&self, span: i64) -> bool {
        let bar = scale(SCANNER_404, span);
        let pages = self.site_max(|s| s.err404_page) > bar
            || u64::from(self.total.err404_page) > bar.saturating_mul(BACKSTOP);
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

/// What the rules need to know besides the address's own counts.
#[derive(Debug, Clone, Copy)]
pub struct Judge {
    /// Dynamic requests one client may make on one site this cycle.
    pub threshold: u64,
    /// The baseline has learned this server's traffic. Until then a rate hit
    /// is only reported, unless the address passes `ceiling`.
    pub baseline_ready: bool,
    /// Dynamic requests on one site (three times that on all sites) at or
    /// above which a rate hit bans whatever the baseline or the address's
    /// look: about ten a second.
    pub ceiling: u64,
    /// The cycle covers a normal stretch of log: `rate` and `scanner` are
    /// judged. Not after a gap, when hours of traffic arrive at once.
    pub volume: bool,
    /// The address is in a search crawler's published ranges.
    pub crawler: bool,
    /// Seconds of log this cycle covers: the other rules' per-cycle bars grow
    /// with it (see [`scale`]).
    pub span: i64,
    /// `rate` and `scanner` only report this address unless it passes
    /// `ceiling`: an open panel or FTP session, or an address the admin
    /// unbanned a little while ago.
    pub volume_exempt: bool,
    /// Counting requests may ban an address. Off in the agent ([`RATE_BANS`]):
    /// a count cannot tell a busy shop, an office behind one address or a
    /// crawler from a flood, so `rate` only reports and the hub (its AI, or the
    /// admin) decides what to block from the traffic it sees.
    pub rate_bans: bool,
}

/// Whether the agent bans on a request count alone. It does not: only an
/// attack that is clear from what was asked for (password guessing, probes,
/// attack tools) bans on its own. The `rate` rule still reports the address.
pub const RATE_BANS: bool = false;

/// Evaluate the fixed patterns. A cycle covers roughly one timer interval of
/// logs, so the plan's per-5-minute windows map onto a single cycle (longer
/// spans scale the bars).
#[must_use]
pub fn evaluate(a: &IpAgg, j: &Judge) -> Option<PatternHit> {
    if a.bruteforce(j.span) {
        return hit("bruteforce", 3600, true, true);
    }
    // A probe sent by a tool, a library or a bot itself: no browser sends
    // those User-Agents, whatever page it is on. A verified crawler only
    // follows a link someone put there.
    if a.probe_tool_hits > 0 || (!j.crawler && a.probe_other_hits > 0) {
        return hit("probe", 86_400, true, true);
    }
    let mut report = None;
    if j.volume && a.scanner(j.span) {
        let nb = a.err404_page_nb * 2 > a.total.err404_page;
        if j.crawler || j.volume_exempt {
            report = hit("scanner", 0, false, false);
        } else {
            // A crawler by name only: banned, but never up the ladder.
            return hit("scanner", 1800, true, nb && !a.claims_crawler());
        }
    }
    if a.bad_ua_reqs >= TOOL_UA_REQS || a.bad_ua_4xx > 0 {
        return hit("bad_ua", 3600, true, true);
    }
    if u64::from(a.empty_ua_reqs) > scale(EMPTY_UA_REQS, j.span)
        && a.empty_ua_4xx * 2 >= a.empty_ua_reqs
    {
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

/// Every rule for one address: the fixed patterns, then `rate`.
#[must_use]
pub fn judge(a: &IpAgg, j: &Judge) -> Option<PatternHit> {
    let found = evaluate(a, j);
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
/// the clients behind the address (at most [`MAX_CLIENTS`]); also matched by
/// [`BACKSTOP`] times that on all sites together, by 404s for page assets at
/// [`ASSET_MISS_FACTOR`] times it, or by every line (assets too) on one site
/// reaching [`TOTAL_FACTOR`] times `threshold` (at least [`TOTAL_FLOOR`]) per
/// client, unless the address is browsers rendering many different pages.
/// Past `ceiling` it always matches.
fn rate_hit(a: &IpAgg, j: &Judge) -> Option<PatternHit> {
    let (t, ceiling) = if j.crawler {
        (
            j.threshold.saturating_mul(CRAWLER_FACTOR),
            j.ceiling.saturating_mul(CRAWLER_FACTOR),
        )
    } else {
        (j.threshold, j.ceiling)
    };
    let clients = a.clients();
    let bar = t.saturating_mul(clients);
    let lines_bar = t
        .saturating_mul(TOTAL_FACTOR)
        .max(scale(TOTAL_FLOOR, j.span))
        .saturating_mul(clients);
    let site_dynamic = a.site_dynamic();
    let site_lines = a.site_max(|s| s.lines);
    let miss_bar = bar.saturating_mul(ASSET_MISS_FACTOR);
    let over_dynamic = site_dynamic >= bar || a.dynamic() >= bar.saturating_mul(BACKSTOP);
    let over_misses = a.site_max(|s| s.asset_miss) >= miss_bar
        || u64::from(a.total.asset_miss) >= miss_bar.saturating_mul(BACKSTOP);
    // A browser rendering pages fetches many different files; a flood of
    // static files repeats a few.
    let browsing = a.browser_looking() && a.many_paths();
    let over_lines =
        !browsing && (site_lines >= lines_bar || a.lines() >= lines_bar.saturating_mul(BACKSTOP));
    let at_ceiling = site_dynamic >= ceiling
        || a.dynamic() >= ceiling.saturating_mul(BACKSTOP)
        || site_lines >= ceiling.saturating_mul(TOTAL_FACTOR);
    if !(over_dynamic || over_misses || over_lines || at_ceiling) {
        return None;
    }
    let rate = |ttl_secs, ban: bool, escalate, ttl_cap| {
        // A count alone only reports, unless this agent is told to ban on it.
        let ban = ban && j.rate_bans;
        Some(PatternHit {
            reason: "rate",
            ttl_secs: if ban { ttl_secs } else { 0 },
            ban,
            escalate: ban && escalate,
            ttl_cap: if ban { ttl_cap } else { 0 },
        })
    };
    if (j.volume_exempt || !j.baseline_ready || a.looks_like_proxy()) && !at_ceiling {
        return rate(0, false, false, 0);
    }
    // An address browsing the way people do (browsers, many different pages)
    // loses its access only for a clear attack: pages well past the bar,
    // missing files, or the absolute ceiling. Busy but plausible browsing is
    // reported; a bot dressed as a browser is a job for the WAF (its
    // User-Agent or request shape), not for a ban that also hits whoever
    // shares the address. Rotating User-Agents over a few paths is no
    // browsing and is judged below.
    let clear_flood = at_ceiling
        || over_lines
        || over_misses
        || site_dynamic >= bar.saturating_mul(CLEAR_FACTOR)
        || a.dynamic() >= bar.saturating_mul(CLEAR_FACTOR * BACKSTOP);
    if browsing && !clear_flood {
        return rate(0, false, false, 0);
    }
    // A search engine (or one by name), browsers rendering pages, several
    // browsers over many pages (a carrier NAT, an office): a short fixed ban,
    // never the ladder. Rotating User-Agents over a few paths is no NAT.
    let shared = clients >= SHARED_CLIENTS && a.many_paths();
    if j.crawler || a.claims_crawler() || a.rendering() || shared {
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

/// File types a page pulls in by itself: styles, scripts, images, fonts,
/// media (video segments and playlists too) and PDFs. Archives, backups,
/// `.txt`, `.xml` and `.php` are not: a scanner asks for those, and a sitemap
/// is generated by PHP.
const ASSET_EXT: &[&str] = &[
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp",
    "tif", "tiff", "woff", "woff2", "ttf", "otf", "eot", "mp4", "m4v", "webm", "ogv", "mkv", "mov",
    "ts", "m4s", "m3u8", "mpd", "mp3", "ogg", "oga", "opus", "wav", "m4a", "aac", "flac", "weba",
    "pdf",
];

/// Is this a page asset? Judged on the path as the server resolves it: the
/// extension of its last segment, when no `.php` segment runs it.
#[cfg(test)]
#[must_use]
pub fn is_asset(path: &str) -> bool {
    ReqPath::of(path).is_asset()
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
