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
//!
//! Every value that came from a log (attacker-controlled) is escaped, and
//! anything that cannot be expressed safely yields `None` rather than a rule
//! that might block something else.

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
/// A rule whose only anchor is a path placeholder needs this many parameter
/// names, or it would block every request that merely carries `?p` or `?s`.
const MIN_NAMES_WITHOUT_PATH: usize = 3;
/// Scanner words: long enough not to occur by chance, short enough to be a word.
const TOKEN_MIN: usize = 4;
const TOKEN_MAX: usize = 32;

/// Printable ASCII only. Control characters or non-ASCII bytes in a log value
/// are not something to put into a rule. `%{...}` is refused too: ModSecurity
/// expands it inside operands, so a User-Agent of `%{REQUEST_HEADERS.User-Agent}`
/// would turn the rule into "match every request".
fn is_safe(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b)) && !s.contains("%{")
}

/// Parameter names and paths are matched by ModSecurity after URL-decoding, but
/// the log holds them encoded, so anything with a `%` would not match.
fn is_plain(s: &str) -> bool {
    is_safe(s) && !s.contains('%')
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

/// Words every browser sends. A scanner-word rule on one of these would block
/// real visitors, so it is refused outright.
const BROWSER_WORDS: &[&str] = &[
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
    "macintosh",
    "windows",
    "linux",
    "x11",
    "compatible",
    "intel",
    "win64",
    "wow64",
    "x64",
    "ubuntu",
    "samsungbrowser",
    "crios",
    "fxios",
    "build",
];

/// Escape for a double-quoted ModSecurity operand.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// What a rule does on a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Write a line to the web server's error log and let the request through.
    Log,
    /// Answer 403 (and log it).
    Block,
}

impl Verdict {
    /// Both write an error-log line and an audit record: OpenLiteSpeed logs
    /// matches to its error log only at INFO level, so the agent counts them
    /// from the audit log there, and the site owner sees the match in the
    /// panel's WAF page (DirectAdmin reads the audit log, which it rotates at
    /// 10 MB) and can exclude the rule for their site.
    fn actions(self) -> &'static str {
        match self {
            Verdict::Log => "pass,log,auditlog",
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
    /// covers everything below it (`/.git/`).
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
    /// managed range or the value cannot be expressed safely.
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

fn render(kind: WafKind, value: &str, id: u32, verdict: Verdict) -> Option<String> {
    let head = format!(
        "id:{id},phase:1,{},msg:'{}',tag:'sn-secure'",
        verdict.actions(),
        kind.msg()
    );
    match kind {
        WafKind::UserAgent => {
            if !is_safe(value) || value.len() > UA_MAX {
                return None;
            }
            Some(format!(
                "SecRule REQUEST_HEADERS:User-Agent \"@streq {}\" \"{head},t:none\"",
                esc(value)
            ))
        }
        WafKind::UaToken => {
            let ok = (TOKEN_MIN..=TOKEN_MAX).contains(&value.len())
                && value.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                })
                && value.bytes().any(|b| b.is_ascii_lowercase())
                && !BROWSER_WORDS
                    .iter()
                    .any(|w| w.contains(value) || value.contains(w));
            if !ok {
                return None;
            }
            Some(format!(
                "SecRule REQUEST_HEADERS:User-Agent \"@contains {value}\" \"{head},t:none,t:lowercase\""
            ))
        }
        WafKind::Path => {
            let ok = value.starts_with('/')
                && value.len() >= 3
                && value.len() <= PATH_MAX
                && is_plain(value)
                && !value.contains(['?', '#', ' ', '{', '}', '*'])
                && !value.contains("//")
                && !value.contains("/./")
                && !value.contains("/../")
                && !value.ends_with("/.")
                && !value.ends_with("/..");
            if !ok {
                return None;
            }
            let op = if value.ends_with('/') {
                "@beginsWith"
            } else {
                "@streq"
            };
            // Decoded and normalised, so `/%2eenv` and `//./.env` cannot walk round it.
            Some(format!(
                "SecRule REQUEST_FILENAME \"{op} {}\" \"{head},t:none,t:urlDecodeUni,t:normalizePath\"",
                esc(value)
            ))
        }
        WafKind::Shape => render_shape(value, &head),
    }
}

/// `METHOD /path?name1&name2`: that method, that path (when it is concrete)
/// and every one of those parameter names, chained.
fn render_shape(shape: &str, head: &str) -> Option<String> {
    let (method, rest) = shape.split_once(' ')?;
    if method.len() < 3 || method.len() > 8 || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let (path, params) = rest.split_once('?')?;
    let names: Vec<&str> = params.split('&').filter(|n| !n.is_empty()).collect();
    if names.is_empty()
        || !names.iter().all(|n| is_plain(n) && n.len() <= NAME_MAX)
        || !is_plain(path)
        || path.len() > PATH_MAX
    {
        return None;
    }
    if path.contains('{') && names.len() < MIN_NAMES_WITHOUT_PATH {
        return None;
    }

    let mut lines = vec![format!(
        "SecRule REQUEST_METHOD \"@streq {method}\" \"{head},t:none,chain\""
    )];
    // `{id}` / `{long}` placeholders mean the real path varies: leave it out.
    if !path.contains('{') {
        lines.push(format!(
            "    SecRule REQUEST_FILENAME \"@streq {}\" \"t:none,t:urlDecodeUni,t:normalizePath,chain\"",
            esc(path)
        ));
    }
    for (i, name) in names.iter().enumerate() {
        let last = i + 1 == names.len();
        lines.push(format!(
            "    SecRule ARGS_GET_NAMES \"@streq {}\" \"t:none{}\"",
            esc(name),
            if last { "" } else { ",chain" }
        ));
    }
    Some(lines.join("\n"))
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

/// The rule id in a ModSecurity log line (`[id "60012"]`), when it is one of
/// ours. Apache/LiteSpeed write `[id "N"]`; libmodsecurity writes the same.
#[must_use]
pub fn managed_id_in_log_line(line: &str) -> Option<u32> {
    let mut rest = line;
    while let Some(at) = rest.find("[id \"") {
        rest = &rest[at + 5..];
        let end = rest.find('"')?;
        if let Ok(id) = rest[..end].parse::<u32>()
            && (MANAGED_ID_MIN..=MANAGED_ID_MAX).contains(&id)
        {
            return Some(id);
        }
        rest = &rest[end..];
    }
    None
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
    fn quotes_and_backslashes_in_a_user_agent_cannot_break_out_of_the_rule() {
        let rule = rule_for_user_agent(r#"evil" "id:1,pass" \"#).unwrap();
        // Every quote inside the operand is escaped; the operand is one string.
        assert!(rule.contains(r#"@streq evil\" \"id:1,pass\" \\""#));
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
    fn values_the_agent_had_to_cut_or_that_are_encoded_give_no_rule() {
        assert!(rule_for_user_agent(&"a".repeat(UA_MAX)).is_some());
        assert!(rule_for_user_agent(&"a".repeat(UA_MAX + 1)).is_none());
        assert!(rule_for_shape(&format!("GET /?{}&b", "n".repeat(NAME_MAX + 1))).is_none());
        assert!(rule_for_shape("GET /?cat%5B%5D&b").is_none());
        assert!(rule_for_shape("GET /a%20b?x&y").is_none());
        assert!(rule_for_shape(&format!("GET /{}?x&y", "p".repeat(PATH_MAX))).is_none());
    }

    #[test]
    fn a_rule_anchored_only_by_a_placeholder_needs_enough_parameters() {
        // "any GET with ?p" would block every WordPress non-permalink request.
        assert!(rule_for_shape("GET /{id}?p").is_none());
        assert!(rule_for_shape("GET /{id}?a&b").is_none());
        assert!(rule_for_shape("GET /{id}?a&b&c").is_some());
        // A concrete path anchors the rule well enough on its own.
        assert!(rule_for_shape("GET /?tss-sc").is_some());
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
    fn a_varying_path_is_left_out_of_the_rule() {
        let rule = rule_for_shape("GET /product/{id}/?filter&sort&view").unwrap();
        assert!(!rule.contains("REQUEST_FILENAME"));
        assert!(rule.contains("ARGS_GET_NAMES \"@streq filter\""));
        assert!(rule.contains("ARGS_GET_NAMES \"@streq sort\""));
    }

    #[test]
    fn a_log_only_rule_passes_and_a_blocking_one_denies() {
        let log = managed(60_001, WafKind::UserAgent, "BadBot/1.0", false)
            .render()
            .unwrap();
        assert!(log.contains("id:60001,phase:1,pass,log,auditlog"));
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
        assert!(
            managed(59_999, WafKind::UaToken, "sqlmap", true)
                .render()
                .is_none()
        );
        assert!(
            managed(70_000, WafKind::UaToken, "sqlmap", true)
                .render()
                .is_none()
        );
        assert!(
            managed(60_000, WafKind::UaToken, "sqlmap", true)
                .render()
                .is_some()
        );
        assert!(
            managed(69_999, WafKind::UaToken, "sqlmap", true)
                .render()
                .is_some()
        );
    }

    #[test]
    fn scanner_words_are_plain_and_never_a_browser_word() {
        assert!(valid_value(WafKind::UaToken, "sqlmap"));
        assert!(valid_value(WafKind::UaToken, "nikto"));
        assert!(valid_value(WafKind::UaToken, "nuclei"));
        assert!(valid_value(WafKind::UaToken, "masscan"));
        for bad in [
            "bot", // too short
            "Sqlmap", "sql map", "mozilla", "chrome", "safari", "afar", // inside "safari"
            "appl", // inside "applewebkit"
            "1234", "x\"y\"z", "%{tx.a}",
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
    fn probe_paths_are_normalised_and_a_trailing_slash_means_below() {
        let file = managed(60_003, WafKind::Path, "/.env", true)
            .render()
            .unwrap();
        assert!(file.contains("REQUEST_FILENAME \"@streq /.env\""));
        assert!(file.contains("t:urlDecodeUni,t:normalizePath"));
        let dir = managed(60_004, WafKind::Path, "/.git/", true)
            .render()
            .unwrap();
        assert!(dir.contains("REQUEST_FILENAME \"@beginsWith /.git/\""));
        for bad in [
            "/", "/a", ".env", "/.env?x", "/a b", "//.env", "/./.env", "/../x", "/x/..", "/%2eenv",
            "/{id}", "/*.php",
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
    fn hits_are_read_from_the_id_in_a_log_line() {
        let apache = r#"[Tue Oct 14 01:02:03.456789 2026] [:error] [pid 1] [client 1.2.3.4] ModSecurity: Warning. String match "/.env" at REQUEST_FILENAME. [file "/etc/modsecurity.d/sn-secure.conf"] [line "5"] [id "60003"] [msg "SN Secure: probe for a file no site serves"] [hostname "a.example"] [uri "/.env"]"#;
        assert_eq!(managed_id_in_log_line(apache), Some(60_003));
        // Someone else's rule.
        assert_eq!(
            managed_id_in_log_line(r#"[id "949110"] [msg "Inbound Anomaly"]"#),
            None
        );
        // Ours after someone else's in the same line.
        assert_eq!(
            managed_id_in_log_line(r#"[id "949110"] [id "60001"]"#),
            Some(60_001)
        );
        assert_eq!(managed_id_in_log_line("[id \"6000"), None);
        assert_eq!(managed_id_in_log_line("nothing"), None);
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
}
