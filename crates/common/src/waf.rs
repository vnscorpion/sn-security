//! ModSecurity rules for traffic the agent flags: bots spread over many
//! addresses, vulnerability scanners, probes for files no site should serve.
//!
//! A bot spread over hundreds of residential IPs cannot be stopped by blocking
//! addresses: they change faster than anyone can list them, and the same
//! addresses carry real shoppers behind carrier NAT. What stays constant is
//! what the bot *sends*, so the right place to stop it is the web server's WAF
//! (ModSecurity), which the hosting panels run.
//!
//! Two uses:
//! - [`rule_for_user_agent`] / [`rule_for_shape`]: text the hub shows next to a
//!   flagged pattern, for a human to read.
//! - [`WafRule`]: a rule the hub *orders*, as data (kind, value, id, block or
//!   log). The hub never sends rule text: the agent renders every rule here,
//!   from a fixed template, so a compromised hub cannot slip `SecRuleEngine Off`,
//!   an `exec:` action or an `Include` into the web server's configuration.
//!   [`Matcher`] applies the same rules to access-log lines, which is how the
//!   agent counts what a rule matches (whatever the engine logs).
//!
//! Every value that came from a log (attacker-controlled) is checked against a
//! narrow character set; anything that cannot be expressed safely, or that
//! would also match ordinary visitors, yields `None`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Rule ids in ModSecurity's range reserved for local rules (1-99,999).
const ID_BASE: u32 = 70_000;
const ID_SPAN: u32 = 29_999;

/// Ids of rules the hub orders. Kept apart from the hashed ids of
/// [`rule_id`], which an operator may have pasted into their own config.
pub const MANAGED_ID_MIN: u32 = 60_000;
pub const MANAGED_ID_MAX: u32 = 69_999;
/// At most this many managed rules on one VPS.
pub const MAX_WAF_RULES: usize = 300;
/// No value of any kind is longer.
pub const VALUE_MAX: usize = 250;

/// A stable rule id for a key, so re-generating the same rule gives the same id.
#[must_use]
pub fn rule_id(key: &str) -> u32 {
    let mut h: u32 = 2_166_136_261; // FNV-1a
    for b in key.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(16_777_619);
    }
    ID_BASE + h % ID_SPAN
}

/// The agent cuts long values (User-Agents at 200 characters, parameter names
/// at 40, paths at 120). A rule built from a cut value would never match, so
/// those get no rule rather than one that looks valid and does nothing.
const UA_MAX: usize = 199;
const NAME_MAX: usize = 39;
const PATH_MAX: usize = 119;
/// Parameter names one shape rule may require.
const NAMES_MAX: usize = 16;
/// A shape whose path is a placeholder, `/` or `/index.php` needs this many
/// parameter names, or it would match every request that merely carries `?p`,
/// `?s` (WordPress search) or `?fbclid`.
const MIN_NAMES_LOOSE_PATH: usize = 3;
/// Scanner words: long enough not to occur by chance, short enough to be a word.
const TOKEN_MIN: usize = 4;
const TOKEN_MAX: usize = 32;
const TOKEN_MIN_LETTERS: usize = 3;

/// Printable ASCII only, without `"` or `\` (so no operand ever needs escaping,
/// whatever the engine's quoting rules) and without `%{...}`, which ModSecurity
/// expands inside operands: a User-Agent of `%{REQUEST_HEADERS.User-Agent}`
/// would turn the rule into "match every request".
fn is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= VALUE_MAX
        && s.bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
        && !s.contains("%{")
}

/// Parameter names are matched by ModSecurity after URL-decoding, but the log
/// holds them encoded, so anything with a `%` would not match.
fn is_plain(s: &str) -> bool {
    is_safe(s) && !s.contains('%')
}

/// Characters a path in a rule may hold: nothing URL-decoding changes (no `%`,
/// no `+`), nothing a regular expression treats specially except `.`.
fn is_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'/' | b'.' | b'_' | b'~' | b',' | b':' | b'@' | b'!' | b'-'
        )
}

/// User-Agent substrings of well-known crawlers. They legitimately arrive from
/// many addresses and surge when a crawl starts. The claim is not verified (that
/// needs reverse DNS), and it is not a reason to stay silent: a bot can claim
/// anything.
const CRAWLER_TOKENS: &[&str] = &[
    "googlebot",
    "bingbot",
    "applebot",
    "yandex",
    "baiduspider",
    "duckduckbot",
    "facebookexternalhit",
    "semrushbot",
    "ahrefsbot",
];

/// Does this User-Agent (or shape) claim to be a known search/SEO crawler?
#[must_use]
pub fn claims_crawler(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    CRAWLER_TOKENS.iter().any(|t| lower.contains(t))
}

/// Words real browsers, apps and crawlers send. A scanner-word rule that is
/// one of these, or part of one, would block ordinary visitors or search
/// engines, so it is refused.
const COMMON_UA_WORDS: &[&str] = &[
    "mozilla",
    "applewebkit",
    "webkit",
    "gecko",
    "khtml",
    "like",
    "chrome",
    "chromium",
    "safari",
    "firefox",
    "edge",
    "edg/",
    "opera",
    "opr/",
    "version",
    "mobile",
    "android",
    "iphone",
    "ipad",
    "ipod",
    "macintosh",
    "windows",
    "linux",
    "x11",
    "compatible",
    "intel",
    "win64",
    "wow64",
    "x64",
    "x86_64",
    "aarch64",
    "arm64",
    "armv7l",
    "armv8l",
    "cros",
    "ubuntu",
    "fedora",
    "samsungbrowser",
    "crios",
    "fxios",
    "build",
    "15e148",
    "trident",
    "msie",
    "yabrowser",
    "ucbrowser",
    "miuibrowser",
    "huaweibrowser",
    "vivaldi",
    "brave",
    "silk",
    "kindle",
    "tablet",
    "http",
    "https",
    "www.",
    "google",
    "bing",
    "yahoo",
    "facebook",
    "twitter",
    "whatsapp",
    "telegram",
    "slack",
    "discord",
    "skype",
    "spider",
    "crawl",
    "robot",
    "preview",
];

/// A User-Agent exactly as a stock browser sends it. Since Chrome reduced its
/// User-Agent (`Chrome/148.0.0.0`), one such string is shared by every user of
/// that browser version on that system: an exact-match rule on it would block
/// all of them.
fn is_stock_browser(ua: &str) -> bool {
    ua.starts_with("Mozilla/5.0 (")
        && (ua.contains("AppleWebKit/537.36 (KHTML, like Gecko)")
            || ua.contains("AppleWebKit/605.1.15 (KHTML, like Gecko)")
            || ua.contains("Gecko/20100101 Firefox/"))
}

/// Exact paths every site serves to everyone.
const COMMON_PATHS: &[&str] = &[
    "/index.php",
    "/index.html",
    "/wp-admin/admin-ajax.php",
    "/wp-cron.php",
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    "/wp-json",
];

/// What a rule does on a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Write a line to the web server's error log and let the request through.
    Log,
    /// Answer 403 (and log it).
    Block,
}

impl Verdict {
    /// A log-only rule stays out of the audit log: the request goes on to
    /// phase 2, so its record would hold the cookies and the request body (a
    /// rule on `/wp-login.php` would collect passwords). The agent counts
    /// matches from the access log, not from ModSecurity's logs. A blocking
    /// rule stops in phase 1, before the body is read, and its audit record is
    /// how the site owner sees the 403 in the panel's WAF page.
    fn actions(self) -> &'static str {
        match self {
            Verdict::Log => "pass,log,noauditlog",
            Verdict::Block => "deny,status:403,log,auditlog",
        }
    }
}

/// What a managed rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafKind {
    /// The whole User-Agent header, exactly as logged.
    UserAgent,
    /// A request shape, `METHOD /path?name1&name2` (see [`rule_for_shape`]).
    Shape,
    /// A path no site should serve, such as `/.env`. A value ending in `/`
    /// covers everything below it, for a hidden directory only (`/.git/`).
    Path,
    /// A word in the User-Agent of a vulnerability scanner (`sqlmap`, `nikto`),
    /// matched case-insensitively.
    UaToken,
}

impl WafKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WafKind::UserAgent => "user_agent",
            WafKind::Shape => "shape",
            WafKind::Path => "path",
            WafKind::UaToken => "ua_token",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user_agent" => Some(WafKind::UserAgent),
            "shape" => Some(WafKind::Shape),
            "path" => Some(WafKind::Path),
            "ua_token" => Some(WafKind::UaToken),
            _ => None,
        }
    }

    fn msg(self) -> &'static str {
        match self {
            WafKind::UserAgent => "SN Secure: distributed bot (User-Agent)",
            WafKind::Shape => "SN Secure: distributed bot (request shape)",
            WafKind::Path => "SN Secure: probe for a file no site serves",
            WafKind::UaToken => "SN Secure: vulnerability scanner",
        }
    }
}

/// A rule the hub orders on a VPS. The agent renders it with [`WafRule::render`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafRule {
    /// Assigned by the hub, in `MANAGED_ID_MIN..=MANAGED_ID_MAX`. The agent
    /// reports hits by this id.
    pub id: u32,
    pub kind: WafKind,
    pub value: String,
    /// `false`: log only (the request goes through); `true`: answer 403.
    #[serde(default)]
    pub block: bool,
}

impl WafRule {
    /// The ModSecurity text for this rule, or `None` when the id is outside the
    /// managed range or the value is not acceptable.
    #[must_use]
    pub fn render(&self) -> Option<String> {
        if !(MANAGED_ID_MIN..=MANAGED_ID_MAX).contains(&self.id) {
            return None;
        }
        let verdict = if self.block {
            Verdict::Block
        } else {
            Verdict::Log
        };
        render(self.kind, &self.value, self.id, verdict)
    }

    /// Would the agent accept this rule? The hub checks before storing one.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.render().is_some()
    }
}

/// Is `value` acceptable for `kind`? (Same checks as rendering, no id needed.)
#[must_use]
pub fn valid_value(kind: WafKind, value: &str) -> bool {
    render(kind, value, MANAGED_ID_MIN, Verdict::Log).is_some()
}

fn valid_token(value: &str) -> bool {
    (TOKEN_MIN..=TOKEN_MAX).contains(&value.len())
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
        && value.bytes().filter(u8::is_ascii_lowercase).count() >= TOKEN_MIN_LETTERS
        && !COMMON_UA_WORDS
            .iter()
            .chain(CRAWLER_TOKENS)
            .any(|w| w.contains(value) || value.contains(w))
}

/// A probe path: absolute, already normal (`normalizePath` leaves it as it is),
/// not one every site serves. A prefix (`/x/`) only for a hidden directory.
fn valid_path(value: &str) -> bool {
    let normal = value.starts_with('/')
        && (3..=PATH_MAX).contains(&value.len())
        && value.bytes().all(is_path_char)
        && !value.contains("//")
        && !value.contains("/./")
        && !value.contains("/../")
        && !value.ends_with("/.")
        && !value.ends_with("/..");
    if !normal || COMMON_PATHS.contains(&value.trim_end_matches('/')) {
        return false;
    }
    !value.ends_with('/') || value[1..].starts_with('.')
}

fn render(kind: WafKind, value: &str, id: u32, verdict: Verdict) -> Option<String> {
    if !is_safe(value) {
        return None;
    }
    let head = format!(
        "id:{id},phase:1,{},msg:'{}',tag:'sn-secure'",
        verdict.actions(),
        kind.msg()
    );
    match kind {
        WafKind::UserAgent => {
            if value.len() > UA_MAX || is_stock_browser(value) {
                return None;
            }
            Some(format!(
                "SecRule REQUEST_HEADERS:User-Agent \"@streq {value}\" \"{head},t:none\""
            ))
        }
        WafKind::UaToken => valid_token(value).then(|| {
            format!(
                "SecRule REQUEST_HEADERS:User-Agent \"@contains {value}\" \"{head},t:none,t:lowercase\""
            )
        }),
        WafKind::Path => {
            if !valid_path(value) {
                return None;
            }
            let op = if value.ends_with('/') {
                "@beginsWith"
            } else {
                "@streq"
            };
            // Decoded and normalised, so `/%2eenv` and `//./.env` cannot walk round it.
            Some(format!(
                "SecRule REQUEST_FILENAME \"{op} {value}\" \"{head},t:none,t:urlDecodeUni,t:normalizePath\""
            ))
        }
        WafKind::Shape => {
            let s = Shape::parse(value)?;
            Some(s.render(&head))
        }
    }
}

/// A request shape, as the agent writes it (`METHOD /path?name1&name2`, path
/// segments that vary written as `{id}`, `{long}`...; no trailing `/`).
struct Shape<'a> {
    method: &'a str,
    /// `None` when the path varies (a placeholder in it): the rule leaves it out.
    path: Option<&'a str>,
    names: Vec<&'a str>,
}

impl<'a> Shape<'a> {
    fn parse(shape: &'a str) -> Option<Shape<'a>> {
        let (method, rest) = shape.split_once(' ')?;
        if method.len() < 3 || method.len() > 8 || !method.bytes().all(|b| b.is_ascii_uppercase()) {
            return None;
        }
        let (path, params) = rest.split_once('?')?;
        let names: Vec<&str> = params.split('&').filter(|n| !n.is_empty()).collect();
        let names_ok = !names.is_empty()
            && names.len() <= NAMES_MAX
            && names
                .iter()
                .all(|n| is_plain(n) && n.len() <= NAME_MAX && !n.contains(['{', '}', ' ']));
        if !names_ok || !path.starts_with('/') || path.len() > PATH_MAX {
            return None;
        }
        let varies = path.contains('{');
        if varies {
            // Placeholders are `{word}` segments; the rest is plain path.
            let plain = path.split('/').all(|seg| {
                (seg.starts_with('{')
                    && seg.ends_with('}')
                    && seg[1..seg.len() - 1]
                        .bytes()
                        .all(|b| b.is_ascii_lowercase()))
                    || seg.bytes().all(is_path_char)
            });
            if !plain {
                return None;
            }
        } else if !path.bytes().all(is_path_char) || path.contains("//") {
            return None;
        }
        let loose = varies || path == "/" || COMMON_PATHS.contains(&path);
        if loose && names.len() < MIN_NAMES_LOOSE_PATH {
            return None;
        }
        Some(Shape {
            method,
            path: (!varies).then_some(path),
            names,
        })
    }

    fn render(&self, head: &str) -> String {
        let mut lines = vec![format!(
            "SecRule REQUEST_METHOD \"@streq {}\" \"{head},t:none,chain\"",
            self.method
        )];
        if let Some(path) = self.path {
            // The agent drops a trailing `/` when it writes a shape, so the rule
            // takes the path with or without one.
            let op = if path == "/" {
                "@streq /".to_string()
            } else {
                format!("@rx ^{}/?$", path_regex(path.trim_end_matches('/')))
            };
            lines.push(format!(
                "    SecRule REQUEST_FILENAME \"{op}\" \"t:none,t:urlDecodeUni,t:normalizePath,chain\""
            ));
        }
        for (i, name) in self.names.iter().enumerate() {
            let last = i + 1 == self.names.len();
            lines.push(format!(
                "    SecRule ARGS_GET_NAMES \"@streq {name}\" \"t:none{}\"",
                if last { "" } else { ",chain" }
            ));
        }
        lines.join("\n")
    }
}

/// A path as a regular expression: `.` is the only character in the allowed
/// set that means something there, and a class (`[.]`) needs no backslash.
fn path_regex(path: &str) -> String {
    path.replace('.', "[.]")
}

/// The first line of the file the agent manages.
pub const FILE_MARKER: &str = "# Managed by SN Secure";

/// The whole managed file for a set of rules: a header, then each rule in id
/// order. Rules that do not render, that repeat an id, or that exceed
/// [`MAX_WAF_RULES`] are left out and returned, so the agent can report them.
#[must_use]
pub fn render_file(rules: &[WafRule]) -> (String, Vec<WafRule>) {
    let mut sorted: Vec<&WafRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.id);
    let mut out = format!(
        "{FILE_MARKER} (agent `sn`). Rewritten from the hub on every change: edits here are lost.\n\
         # Rules {MANAGED_ID_MIN}-{MANAGED_ID_MAX}. pass,log = log only; deny = blocking.\n"
    );
    let mut skipped = Vec::new();
    let mut kept = 0usize;
    let mut last_id = None;
    for r in sorted {
        if last_id == Some(r.id) || kept >= MAX_WAF_RULES {
            skipped.push(r.clone());
            continue;
        }
        match r.render() {
            Some(text) => {
                out.push('\n');
                out.push_str(&text);
                out.push('\n');
                kept += 1;
                last_id = Some(r.id);
            }
            None => skipped.push(r.clone()),
        }
    }
    (out, skipped)
}

/// Block requests whose User-Agent is exactly `ua` (text for a human to read).
#[must_use]
pub fn rule_for_user_agent(ua: &str) -> Option<String> {
    render(WafKind::UserAgent, ua, rule_id(ua), Verdict::Block)
}

/// Block requests that match a *shape* (`METHOD /path?name1&name2`): that method,
/// that path (when it is concrete) and every one of those parameter names.
///
/// Only shapes that have parameters are accepted: without them the rule would be
/// "block this page", which is not a bot rule.
#[must_use]
pub fn rule_for_shape(shape: &str) -> Option<String> {
    render(WafKind::Shape, shape, rule_id(shape), Verdict::Block)
}

// ---------------------------------------------------------------------------
// The same rules, applied to access-log lines
// ---------------------------------------------------------------------------

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `%XX`-decode (as ModSecurity's `urlDecodeUni` does for these, `+` too).
#[must_use]
pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The path ModSecurity's `REQUEST_FILENAME` with `t:urlDecodeUni,
/// t:normalizePath` holds for a request target from a log line: no query
/// string, decoded, no empty or `.` segments, `..` resolved.
#[must_use]
pub fn normal_path(target: &str) -> String {
    let raw = target.split(['?', '#']).next().unwrap_or("");
    let decoded = url_decode(raw);
    let mut segs: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segs.join("/"));
    if decoded.ends_with('/') && !segs.is_empty() {
        out.push('/');
    }
    out
}

/// The decoded parameter names of a request target's query string.
fn query_names(target: &str) -> Vec<String> {
    let Some((_, q)) = target.split_once('?') else {
        return Vec::new();
    };
    let q = q.split('#').next().unwrap_or("");
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| url_decode(p.split('=').next().unwrap_or("")))
        .collect()
}

struct ShapeRule {
    id: u32,
    method: String,
    path: Option<String>,
    names: Vec<String>,
}

/// The hub's rules as checks on access-log lines: what a rule matches is
/// counted from the requests the web server logged, whatever ModSecurity
/// writes (or does not write) to its own logs.
#[derive(Default)]
pub struct Matcher {
    exact_paths: HashMap<String, Vec<u32>>,
    prefixes: Vec<(String, u32)>,
    exact_uas: HashMap<String, Vec<u32>>,
    tokens: Vec<(String, u32)>,
    shapes: Vec<ShapeRule>,
}

impl Matcher {
    /// Only the rules the agent would write (valid id and value).
    #[must_use]
    pub fn new(rules: &[WafRule]) -> Matcher {
        let mut m = Matcher::default();
        for r in rules.iter().filter(|r| r.is_valid()) {
            match r.kind {
                WafKind::Path if r.value.ends_with('/') => m.prefixes.push((r.value.clone(), r.id)),
                WafKind::Path => m.exact_paths.entry(r.value.clone()).or_default().push(r.id),
                WafKind::UserAgent => m.exact_uas.entry(r.value.clone()).or_default().push(r.id),
                WafKind::UaToken => m.tokens.push((r.value.clone(), r.id)),
                WafKind::Shape => {
                    if let Some(s) = Shape::parse(&r.value) {
                        m.shapes.push(ShapeRule {
                            id: r.id,
                            method: s.method.to_string(),
                            path: s.path.map(|p| p.trim_end_matches('/').to_string()),
                            names: s.names.iter().map(|n| (*n).to_string()).collect(),
                        });
                    }
                }
            }
        }
        m
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact_paths.is_empty()
            && self.prefixes.is_empty()
            && self.exact_uas.is_empty()
            && self.tokens.is_empty()
            && self.shapes.is_empty()
    }

    /// Ids of the rules a request matches, into `out` (cleared first).
    pub fn check(&self, method: &str, target: &str, ua: &str, out: &mut Vec<u32>) {
        out.clear();
        if let Some(ids) = self.exact_uas.get(ua) {
            out.extend(ids);
        }
        if !self.tokens.is_empty() {
            let lower = ua.to_ascii_lowercase();
            out.extend(
                self.tokens
                    .iter()
                    .filter(|(t, _)| lower.contains(t.as_str()))
                    .map(|(_, id)| *id),
            );
        }
        if self.exact_paths.is_empty() && self.prefixes.is_empty() && self.shapes.is_empty() {
            return;
        }
        let path = normal_path(target);
        if let Some(ids) = self.exact_paths.get(&path) {
            out.extend(ids);
        }
        out.extend(
            self.prefixes
                .iter()
                .filter(|(p, _)| path.starts_with(p.as_str()))
                .map(|(_, id)| *id),
        );
        if self.shapes.is_empty() {
            return;
        }
        let names = query_names(target);
        let bare = if path.len() > 1 {
            path.trim_end_matches('/')
        } else {
            path.as_str()
        };
        for s in &self.shapes {
            let path_ok = s
                .path
                .as_deref()
                .is_none_or(|p| p == bare || (p.is_empty() && bare == "/"));
            if s.method == method && path_ok && s.names.iter().all(|n| names.contains(n)) {
                out.push(s.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed(id: u32, kind: WafKind, value: &str, block: bool) -> WafRule {
        WafRule {
            id,
            kind,
            value: value.to_string(),
            block,
        }
    }

    #[test]
    fn user_agent_rule_is_an_exact_match_with_a_local_id() {
        // The botnet's UA from the incident: Chrome-like, but no AppleWebKit.
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/148.0.0.0 Safari/537.36";
        let rule = rule_for_user_agent(ua).unwrap();
        assert!(rule.starts_with("SecRule REQUEST_HEADERS:User-Agent \"@streq Mozilla/5.0"));
        assert!(rule.contains("phase:1,deny,status:403"));
        let id = rule_id(ua);
        assert!((ID_BASE..ID_BASE + ID_SPAN).contains(&id));
        assert!(rule.contains(&format!("id:{id},")));
        // Same input, same id.
        assert_eq!(rule_id(ua), id);
    }

    #[test]
    fn quotes_and_backslashes_are_refused_rather_than_escaped() {
        assert!(rule_for_user_agent(r#"evil" "id:1,pass""#).is_none());
        assert!(rule_for_user_agent(r"evil\").is_none());
        assert!(!valid_value(WafKind::Shape, "GET /?a\"b&c&d"));
    }

    #[test]
    fn a_stock_browser_user_agent_is_never_a_rule() {
        for ua in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        ] {
            assert!(!valid_value(WafKind::UserAgent, ua), "{ua}");
        }
        assert!(valid_value(WafKind::UserAgent, "python-requests/2.32.3"));
    }

    #[test]
    fn values_that_cannot_be_expressed_safely_give_no_rule() {
        assert!(rule_for_user_agent("").is_none());
        assert!(rule_for_user_agent("bad\nagent").is_none());
        assert!(rule_for_user_agent("caf\u{e9}").is_none());
        assert!(rule_for_shape("GET /").is_none()); // no parameters
        assert!(rule_for_shape("GET /?").is_none());
        assert!(rule_for_shape("garbage").is_none());
        assert!(rule_for_shape("get /?a").is_none()); // method must be upper case
        assert!(rule_for_shape("GET /?a&b\nc").is_none());
    }

    #[test]
    fn modsecurity_macros_in_a_value_give_no_rule() {
        // `%{REQUEST_HEADERS.User-Agent}` as the operand would match everything.
        assert!(rule_for_user_agent("%{REQUEST_HEADERS.User-Agent}").is_none());
        assert!(rule_for_user_agent("x %{TX.a} y").is_none());
        assert!(rule_for_shape("GET /?%{TX.a}&b&c").is_none());
        assert!(rule_for_shape("GET /%{TX.a}?a&b&c").is_none());
        assert!(!valid_value(WafKind::Path, "/%{TX.a}"));
    }

    #[test]
    fn values_the_agent_had_to_cut_or_that_are_encoded_or_huge_give_no_rule() {
        assert!(rule_for_user_agent(&"a".repeat(UA_MAX)).is_some());
        assert!(rule_for_user_agent(&"a".repeat(UA_MAX + 1)).is_none());
        assert!(rule_for_shape(&format!("GET /x?{}&b", "n".repeat(NAME_MAX + 1))).is_none());
        assert!(rule_for_shape("GET /x?cat%5B%5D&b").is_none());
        assert!(rule_for_shape("GET /a%20b?x&y").is_none());
        assert!(rule_for_shape(&format!("GET /{}?x&y", "p".repeat(PATH_MAX))).is_none());
        // Many names, or a long value: a single rule must stay small.
        let many: Vec<String> = (0..=NAMES_MAX).map(|i| format!("n{i}")).collect();
        assert!(rule_for_shape(&format!("GET /x?{}", many.join("&"))).is_none());
        assert!(!valid_value(
            WafKind::Shape,
            &format!("GET /x?{}", "a&".repeat(200))
        ));
    }

    #[test]
    fn a_loosely_anchored_shape_needs_enough_parameters() {
        // "any GET with ?p" would block every WordPress non-permalink request.
        assert!(rule_for_shape("GET /{id}?p").is_none());
        assert!(rule_for_shape("GET /{id}?a&b").is_none());
        assert!(rule_for_shape("GET /{id}?a&b&c").is_some());
        // `/` and `/index.php` anchor nothing either: WordPress search is `/?s`.
        assert!(rule_for_shape("GET /?s").is_none());
        assert!(rule_for_shape("GET /?fbclid").is_none());
        assert!(rule_for_shape("GET /index.php?p").is_none());
        assert!(rule_for_shape("GET /?tss-sc&tsscat&tst10_filter").is_some());
        // A concrete page is anchor enough.
        assert!(rule_for_shape("GET /shop?tss-sc").is_some());
        // A placeholder as a parameter name never matches a real request.
        assert!(rule_for_shape("GET /shop?{k}&a").is_none());
    }

    #[test]
    fn crawler_claims_are_recognised_case_insensitively() {
        assert!(claims_crawler("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(claims_crawler("BINGBOT"));
        assert!(!claims_crawler("Mozilla/5.0 Chrome/148"));
    }

    #[test]
    fn shape_rule_chains_method_path_and_every_parameter_name() {
        let rule = rule_for_shape("GET /?tss-sc&tsscat&tst10_filter").unwrap();
        let lines: Vec<&str> = rule.lines().collect();
        assert!(lines[0].starts_with("SecRule REQUEST_METHOD \"@streq GET\""));
        assert!(lines[0].ends_with(",chain\""));
        assert!(lines[0].contains("id:"));
        assert!(
            lines[1].contains("REQUEST_FILENAME \"@streq /\"") && lines[1].ends_with(",chain\"")
        );
        assert!(
            lines[2].contains("ARGS_GET_NAMES \"@streq tss-sc\"") && lines[2].ends_with(",chain\"")
        );
        assert!(
            lines[3].contains("ARGS_GET_NAMES \"@streq tsscat\"") && lines[3].ends_with(",chain\"")
        );
        // The last link must NOT chain, or the rule would swallow the next one.
        assert!(lines[4].contains("ARGS_GET_NAMES \"@streq tst10_filter\""));
        assert!(!lines[4].contains("chain"));
        // Only the first line carries the id and actions.
        assert_eq!(rule.matches("id:").count(), 1);
        assert_eq!(rule.matches("deny").count(), 1);
    }

    #[test]
    fn a_page_path_matches_with_or_without_its_trailing_slash() {
        let rule = rule_for_shape("GET /shop/item.php?a&b").unwrap();
        assert!(
            rule.contains("REQUEST_FILENAME \"@rx ^/shop/item[.]php/?$\""),
            "{rule}"
        );
        assert!(!rule.contains('\\'));
    }

    #[test]
    fn a_varying_path_is_left_out_of_the_rule() {
        let rule = rule_for_shape("GET /product/{id}?filter&sort&view").unwrap();
        assert!(!rule.contains("REQUEST_FILENAME"));
        assert!(rule.contains("ARGS_GET_NAMES \"@streq filter\""));
        assert!(rule.contains("ARGS_GET_NAMES \"@streq sort\""));
    }

    #[test]
    fn a_log_only_rule_passes_without_an_audit_record_and_a_blocking_one_denies() {
        let log = managed(60_001, WafKind::UserAgent, "BadBot/1.0", false)
            .render()
            .unwrap();
        assert!(log.contains("id:60001,phase:1,pass,log,noauditlog"));
        assert!(!log.contains("deny"));
        let block = managed(60_001, WafKind::UserAgent, "BadBot/1.0", true)
            .render()
            .unwrap();
        assert!(block.contains("id:60001,phase:1,deny,status:403,log,auditlog"));
        assert!(!block.contains("pass"));
        // Every rule clears inherited transformations.
        assert!(log.contains("t:none"));
    }

    #[test]
    fn managed_ids_must_be_in_their_own_range() {
        let r = |id| managed(id, WafKind::UaToken, "sqlmap", true).render();
        assert!(r(59_999).is_none());
        assert!(r(70_000).is_none());
        assert!(r(60_000).is_some());
        assert!(r(69_999).is_some());
    }

    #[test]
    fn scanner_words_are_plain_and_never_something_visitors_send() {
        for good in ["sqlmap", "nikto", "nuclei", "masscan", "zgrab", "headless"] {
            assert!(valid_value(WafKind::UaToken, good), "{good}");
        }
        for bad in [
            "bot", // too short
            "Sqlmap",
            "sql map",
            "mozilla",
            "chrome",
            "safari",
            "afar", // inside "safari"
            "appl", // inside "applewebkit"
            "1234",
            "15e148",
            "x86_64",
            "cros",
            "http",
            "google",
            "googlebot",
            "spider",
            "x\"y\"z",
            "%{tx.a}",
        ] {
            assert!(!valid_value(WafKind::UaToken, bad), "{bad}");
        }
        let rule = managed(60_002, WafKind::UaToken, "sqlmap", true)
            .render()
            .unwrap();
        assert!(rule.contains("\"@contains sqlmap\""));
        assert!(rule.contains("t:lowercase"));
    }

    #[test]
    fn probe_paths_are_normalised_and_only_hidden_directories_take_a_prefix() {
        let file = managed(60_003, WafKind::Path, "/.env", true)
            .render()
            .unwrap();
        assert!(file.contains("REQUEST_FILENAME \"@streq /.env\""));
        assert!(file.contains("t:urlDecodeUni,t:normalizePath"));
        let dir = managed(60_004, WafKind::Path, "/.git/", true)
            .render()
            .unwrap();
        assert!(dir.contains("REQUEST_FILENAME \"@beginsWith /.git/\""));
        assert!(valid_value(WafKind::Path, "/xmlrpc.php"));
        for bad in [
            "/",
            "/a",
            ".env",
            "/.env?x",
            "/a b",
            "//.env",
            "/./.env",
            "/../x",
            "/x/..",
            "/%2eenv",
            "/{id}",
            "/*.php",
            "/a+b",
            "/wp-content/",
            "/wp-admin/",
            "/index.php",
            "/wp-admin/admin-ajax.php",
        ] {
            assert!(!valid_value(WafKind::Path, bad), "{bad}");
        }
    }

    #[test]
    fn the_file_holds_rules_in_id_order_and_leaves_out_bad_or_repeated_ones() {
        let rules = vec![
            managed(60_010, WafKind::Path, "/.env", true),
            managed(60_002, WafKind::UaToken, "sqlmap", false),
            managed(60_010, WafKind::Path, "/.git/", true), // same id again
            managed(60_011, WafKind::UaToken, "chrome", true), // refused
        ];
        let (text, skipped) = render_file(&rules);
        assert!(text.starts_with(FILE_MARKER));
        let a = text.find("id:60002").unwrap();
        let b = text.find("id:60010").unwrap();
        assert!(a < b);
        assert_eq!(text.matches("id:").count(), 2);
        assert_eq!(skipped.len(), 2);
        // Nothing but our template reaches the file.
        for line in text.lines().filter(|l| !l.is_empty()) {
            assert!(line.starts_with('#') || line.trim_start().starts_with("SecRule "));
        }
    }

    #[test]
    fn the_file_never_holds_more_than_the_cap() {
        let rules: Vec<WafRule> = (0..MAX_WAF_RULES as u32 + 5)
            .map(|i| managed(60_000 + i, WafKind::Path, &format!("/.probe{i}"), false))
            .collect();
        let (text, skipped) = render_file(&rules);
        assert_eq!(text.matches("id:").count(), MAX_WAF_RULES);
        assert_eq!(skipped.len(), 5);
    }

    #[test]
    fn rules_travel_as_data() {
        let r = managed(60_005, WafKind::UaToken, "nikto", true);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"id":60005,"kind":"ua_token","value":"nikto","block":true}"#
        );
        let back: WafRule =
            serde_json::from_str(r#"{"id":60005,"kind":"path","value":"/.env"}"#).unwrap();
        assert!(!back.block);
        assert!(serde_json::from_str::<WafRule>(r#"{"id":1,"kind":"raw","value":"x"}"#).is_err());
    }

    #[test]
    fn log_paths_are_normalised_like_modsecurity_does() {
        assert_eq!(normal_path("/.env?x=1"), "/.env");
        assert_eq!(normal_path("//./.env"), "/.env");
        assert_eq!(normal_path("/%2eenv"), "/.env");
        assert_eq!(normal_path("/a/../.git/config"), "/.git/config");
        assert_eq!(normal_path("/shop/"), "/shop/");
        assert_eq!(normal_path("/"), "/");
        assert_eq!(normal_path("/a%zz"), "/a%zz");
        assert_eq!(url_decode("a+b%20c%"), "a b c%");
    }

    #[test]
    fn the_matcher_applies_each_kind_to_log_lines() {
        let rules = vec![
            managed(60_001, WafKind::Path, "/.env", false),
            managed(60_002, WafKind::Path, "/.git/", false),
            managed(60_003, WafKind::UaToken, "sqlmap", false),
            managed(60_004, WafKind::UserAgent, "BadBot/1.0", false),
            managed(60_005, WafKind::Shape, "GET /shop?tss-sc&tsscat", false),
            managed(60_006, WafKind::Shape, "GET /product/{id}?a&b&c", true),
            managed(60_007, WafKind::UaToken, "chrome", true), // invalid: ignored
        ];
        let m = Matcher::new(&rules);
        let mut out = Vec::new();
        let mut ids = |method: &str, target: &str, ua: &str| {
            m.check(method, target, ua, &mut out);
            let mut v = out.clone();
            v.sort_unstable();
            v
        };
        let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
        assert_eq!(ids("GET", "//.env?debug", browser), vec![60_001]);
        assert_eq!(ids("GET", "/.git/config", browser), vec![60_002]);
        assert!(ids("GET", "/.github/x", browser).is_empty());
        assert_eq!(
            ids("GET", "/", "sqlmap/1.8 (https://sqlmap.org)"),
            vec![60_003]
        );
        assert_eq!(ids("GET", "/", "BadBot/1.0"), vec![60_004]);
        assert!(ids("GET", "/", "BadBot/1.0 x").is_empty());
        // Shape: method, path with or without `/`, every name (more is fine).
        assert_eq!(
            ids("GET", "/shop/?tsscat=1&tss-sc=2&x=3", browser),
            vec![60_005]
        );
        assert!(ids("POST", "/shop?tsscat=1&tss-sc=2", browser).is_empty());
        assert!(ids("GET", "/shop?tsscat=1", browser).is_empty());
        assert!(ids("GET", "/shopping?tsscat=1&tss-sc=2", browser).is_empty());
        assert_eq!(
            ids("GET", "/anything/here?a=1&b&c=%20", browser),
            vec![60_006]
        );
        assert!(ids("GET", "/", browser).is_empty());
        assert!(!m.is_empty());
        assert!(Matcher::new(&[]).is_empty());
    }
}
