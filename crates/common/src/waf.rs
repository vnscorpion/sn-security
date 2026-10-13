//! Suggested ModSecurity rules for a flagged distributed-bot pattern.
//!
//! A bot spread over hundreds of residential IPs cannot be stopped by blocking
//! addresses: they change faster than anyone can list them. What stays constant
//! is what the bot *sends*, so the right place to stop it is the web server's
//! WAF (ModSecurity), which the major hosting panels run or require.
//!
//! These are **suggestions for a human to review and paste**: the hub never
//! writes them into a panel's configuration. Every value that came from a log
//! (attacker-controlled) is escaped, and anything that cannot be expressed
//! safely yields `None` rather than a rule that might block something else.
//!
//! Not yet run through a real ModSecurity instance; run a new rule in
//! `DetectionOnly` first and look at what it would have blocked.

/// Rule ids in ModSecurity's range reserved for local rules (1-99,999).
const ID_BASE: u32 = 70_000;
const ID_SPAN: u32 = 29_999;

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

/// Printable ASCII only. Control characters or non-ASCII bytes in a log value
/// are not something to paste into a rule. `%{...}` is refused too: ModSecurity
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
    "adsbot-google",
    "mediapartners-google",
    "google-inspectiontool",
    "googleother",
    "bingbot",
    "applebot",
    "yandex",
    "baiduspider",
    "duckduckbot",
    "coccocbot",
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

/// Block requests whose User-Agent is exactly `ua`.
#[must_use]
pub fn rule_for_user_agent(ua: &str) -> Option<String> {
    if !is_safe(ua) || ua.len() > UA_MAX {
        return None;
    }
    Some(format!(
        "SecRule REQUEST_HEADERS:User-Agent \"@streq {}\" \
         \"id:{},phase:1,deny,status:403,log,msg:'SN Secure: distributed bot (User-Agent)'\"",
        esc(ua),
        rule_id(ua)
    ))
}

/// Block requests that match a *shape* (`METHOD /path?name1&name2`): that method,
/// that path (when it is concrete) and every one of those parameter names.
///
/// Only shapes that have parameters are accepted: without them the rule would be
/// "block this page", which is not a bot rule.
#[must_use]
pub fn rule_for_shape(shape: &str) -> Option<String> {
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
        "SecRule REQUEST_METHOD \"@streq {method}\" \
         \"id:{},phase:1,deny,status:403,log,msg:'SN Secure: distributed bot (request shape)',chain\"",
        rule_id(shape)
    )];
    // `{id}` / `{long}` placeholders mean the real path varies: leave it out.
    if !path.contains('{') {
        lines.push(format!(
            "    SecRule REQUEST_FILENAME \"@streq {}\" \"chain\"",
            esc(path)
        ));
    }
    for (i, name) in names.iter().enumerate() {
        let last = i + 1 == names.len();
        lines.push(format!(
            "    SecRule ARGS_NAMES \"@streq {}\"{}",
            esc(name),
            if last { "" } else { " \"chain\"" }
        ));
    }
    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            lines[1].contains("REQUEST_FILENAME \"@streq /\"") && lines[1].ends_with("\"chain\"")
        );
        assert!(
            lines[2].contains("ARGS_NAMES \"@streq tss-sc\"") && lines[2].ends_with("\"chain\"")
        );
        assert!(
            lines[3].contains("ARGS_NAMES \"@streq tsscat\"") && lines[3].ends_with("\"chain\"")
        );
        // The last link must NOT chain, or the rule would swallow the next one.
        assert!(lines[4].contains("ARGS_NAMES \"@streq tst10_filter\""));
        assert!(!lines[4].contains("chain"));
        // Only the first line carries the id and actions.
        assert_eq!(rule.matches("id:").count(), 1);
    }

    #[test]
    fn a_varying_path_is_left_out_of_the_rule() {
        let rule = rule_for_shape("GET /product/{id}/?filter&sort&view").unwrap();
        assert!(!rule.contains("REQUEST_FILENAME"));
        assert!(rule.contains("ARGS_NAMES \"@streq filter\""));
        assert!(rule.contains("ARGS_NAMES \"@streq sort\""));
    }
}
