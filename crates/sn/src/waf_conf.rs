//! Reading web-server configuration for the managed ModSecurity rules, and
//! counting what the rules match (pure: text in, facts out; the file system
//! and commands are in `waf.rs`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use snsec_common::waf::{MANAGED_ID_MAX, MANAGED_ID_MIN};

/// What one configuration file says about ModSecurity.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfScan {
    /// The last `SecRuleEngine` value, lower-cased: `on`, `off`, `detectiononly`.
    pub engine: Option<String>,
    /// The nginx / OpenLiteSpeed module switch (`modsecurity on|off`). It only
    /// loads the module: with it on, rules still run only where `SecRuleEngine`
    /// is `On`.
    pub module: Option<bool>,
    /// Directories whose `*.conf` files are included (`Include /x/*.conf`).
    pub include_dirs: Vec<String>,
    /// Single files included or named as rules files.
    pub files: Vec<String>,
}

/// Strip a trailing `;` (nginx/OLS) and surrounding quotes.
fn arg(s: &str) -> &str {
    let s = s.trim().trim_end_matches(';').trim();
    s.trim_matches('"').trim_matches('\'')
}

/// Scan one configuration text. Comments (`#`) are skipped; directives are
/// matched case-insensitively, the way Apache does.
#[must_use]
pub fn scan_conf(text: &str) -> ConfScan {
    let mut out = ConfScan::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let rest = parts.next().unwrap_or("").trim();
        match key.as_str() {
            "secruleengine" => out.engine = Some(arg(rest).to_ascii_lowercase()),
            // nginx: `modsecurity on;`; OpenLiteSpeed: `modsecurity on`.
            "modsecurity" => match arg(rest).to_ascii_lowercase().as_str() {
                "on" => out.module = Some(true),
                "off" => out.module = Some(false),
                _ => {}
            },
            "include" | "includeoptional" | "modsecurity_rules_file" => {
                let path = arg(rest);
                if !path.starts_with('/') || path.contains("..") {
                    continue;
                }
                if let Some(dir) = path.strip_suffix("/*.conf") {
                    if !out.include_dirs.iter().any(|d| d == dir) {
                        out.include_dirs.push(dir.to_string());
                    }
                } else if !path.contains('*') && !out.files.iter().any(|f| f == path) {
                    out.files.push(path.to_string());
                }
            }
            _ => {}
        }
    }
    out
}

/// The state the hub shows (`WafStatus::engine`) from what the configuration
/// says: the module switch, every server-level `SecRuleEngine` found, and the
/// panel's own setting (DirectAdmin's, applied per site, wins). Cautious: one
/// `Off` or `DetectionOnly` anywhere at server level is reported, since the
/// order engines apply them in differs. Nothing set: ModSecurity's default,
/// `Off`, where the layout is known (`default_off`), else `unknown`.
#[must_use]
pub fn engine_state(
    module: Option<bool>,
    server: &[String],
    panel: Option<&str>,
    default_off: bool,
) -> &'static str {
    if module == Some(false) {
        return "off";
    }
    let label = |v: &str| match v {
        "on" => "on",
        "detectiononly" => "detection_only",
        "off" => "off",
        _ => "unknown",
    };
    if let Some(p) = panel {
        return label(p);
    }
    if server.iter().any(|v| v == "off") {
        return "off";
    }
    if server.iter().any(|v| v == "detectiononly") {
        return "detection_only";
    }
    if server.iter().any(|v| v == "on") {
        return "on";
    }
    if default_off { "off" } else { "unknown" }
}

/// Rule ids declared in a rules text (`id:123`, `id:'123'`, `"id:123,`), in
/// `lo..=hi`. Used to keep ours clear of ids someone else already took (a
/// duplicate id is a fatal configuration error in ModSecurity 2 and 3).
#[must_use]
pub fn ids_in(text: &str, lo: u32, hi: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("id:") {
        // Not the tail of another word (`ruleRemoveById:`, `xid:`).
        let before = rest[..at].chars().next_back();
        rest = &rest[at + 3..];
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let digits: String = rest
            .trim_start_matches(['\'', '"', ' '])
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(id) = digits.parse::<u32>()
            && (lo..=hi).contains(&id)
        {
            out.push(id);
        }
    }
    out
}

/// Does this text hold a `SecRuleRemoveById` that covers any id in `lo..=hi`?
/// (DirectAdmin writes one per excluded id or range in a site's settings.)
#[must_use]
pub fn removes_range(text: &str, lo: u32, hi: u32) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        let mut parts = line.splitn(2, char::is_whitespace);
        if !parts
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case("secruleremovebyid"))
        {
            return false;
        }
        parts
            .next()
            .unwrap_or("")
            .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .filter(|t| !t.is_empty())
            .any(|t| {
                let (a, b) = t.split_once('-').unwrap_or((t, t));
                match (a.parse::<u32>(), b.parse::<u32>()) {
                    (Ok(a), Ok(b)) => a <= hi && b >= lo,
                    _ => false,
                }
            })
    })
}

/// Did a configuration test pass? `code` is its exit code (`None`: killed or
/// timed out). OpenLiteSpeed's `-t` exits 1 on warnings and 2 on errors; the
/// others exit 0 only when the configuration is good. Any line naming our file
/// together with an error word fails it too: OpenLiteSpeed drops a rules file
/// it cannot load and carries on.
#[must_use]
pub fn test_passed(server: &str, code: Option<i32>, output: &str, file_name: &str) -> bool {
    let code_ok = matches!((server, code), ("openlitespeed", Some(1)) | (_, Some(0)));
    code_ok && !log_blames(output, file_name)
}

/// Does this log text report a problem with our rules file (`Rule id: N is
/// duplicated`, a parse error, an unsupported rule)? A rule *match* names our
/// file too (`[file "..."] [id "N"]`) and carries words a visitor chose (the
/// path `/error_log`), so lines with `[id "` are not complaints.
#[must_use]
pub fn log_blames(text: &str, file_name: &str) -> bool {
    const WORDS: &[&str] = &[
        "error",
        "failed",
        "duplicated",
        "not supported",
        "not able to open",
        "syntax",
    ];
    text.lines().any(|l| {
        if !l.contains(file_name) || l.contains("[id \"") {
            return false;
        }
        let lower = l.to_ascii_lowercase();
        WORDS.iter().any(|w| lower.contains(w))
    })
}

// ---- OPanel ----------------------------------------------------------------
//
// OPanel (OpenLiteSpeed) gives every site its own ModSecurity rules file that
// includes two shared files, `opanel-base.conf` (the engine) and
// `opanel-custom.conf` (rules for every site, written by the panel). No
// directory of rule files is included as a whole, so our file is reached by one
// `Include` line the agent keeps in `opanel-custom.conf`, between two marker
// lines. The block exists only while our file does: an `Include` of a file that
// is missing stops ModSecurity from loading.

/// First line of the block the agent keeps in `opanel-custom.conf`.
pub const HOOK_BEGIN: &str = "# BEGIN SN Secure (managed by sn: do not edit)";
/// Last line of that block.
pub const HOOK_END: &str = "# END SN Secure";
/// A block is three lines; one that ends further on is not ours to cut out.
const HOOK_SPAN: usize = 8;

/// The block that makes the file `live` part of the rules.
#[must_use]
pub fn hook_block(live: &str) -> String {
    format!("{HOOK_BEGIN}\nInclude {live}\n{HOOK_END}\n")
}

/// `text` without our block(s), ending in exactly one newline (or empty).
/// A begin marker without its end close by is left alone.
#[must_use]
pub fn without_hook(text: &str) -> String {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut keep = vec![true; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == HOOK_BEGIN
            && let Some(j) =
                (i + 1..lines.len().min(i + HOOK_SPAN)).find(|&j| lines[j].trim() == HOOK_END)
        {
            keep[i..=j].fill(false);
            i = j + 1;
            continue;
        }
        i += 1;
    }
    let kept: String = lines
        .iter()
        .zip(&keep)
        .filter(|(_, k)| **k)
        .map(|(l, _)| *l)
        .collect();
    let trimmed = kept.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

/// `text` with exactly one block for `live`, at the end.
#[must_use]
pub fn with_hook(text: &str, live: &str) -> String {
    let base = without_hook(text);
    if base.is_empty() {
        hook_block(live)
    } else {
        format!("{base}\n{}", hook_block(live))
    }
}

/// Is the block for `live` in `text`, as [`with_hook`] writes it?
#[must_use]
pub fn hook_in_place(text: &str, live: &str) -> bool {
    with_hook(text, live) == text
}

/// The ModSecurity state of a panel server from its base rules file, the module
/// switch, and the `SecRuleEngine` values found in the other rule files.
#[must_use]
pub fn panel_engine(base: &str, module: Option<bool>, others: &[String]) -> &'static str {
    let mut engines: Vec<String> = scan_conf(base).engine.into_iter().collect();
    engines.extend(others.iter().cloned());
    engine_state(module, &engines, None, true)
}

/// Sites whose virtual host lacks the panel's WAF block (`marker`, such as
/// `# OPANEL WAF BEGIN`): ModSecurity does not run there, so no rule of ours
/// does. `(name, text)`.
#[must_use]
pub fn sites_without_waf(vhosts: &[(String, String)], marker: &str) -> Vec<String> {
    vhosts
        .iter()
        // The panel's own virtual hosts have no dot in their name.
        .filter(|(name, text)| name.contains('.') && !text.contains(marker))
        .map(|(name, _)| name.clone())
        .collect()
}

const SAMPLE_MAX: usize = 160;
/// Examples kept per rule between two reports.
pub const SAMPLES_PER_RULE: usize = 3;

/// `site path` for a request (no query string), printable ASCII only.
#[must_use]
pub fn sample_of(site: &str, target: &str) -> String {
    let path = target.split(['?', '#']).next().unwrap_or("");
    let s = if site.is_empty() {
        path.to_string()
    } else {
        format!("{site} {path}")
    };
    s.chars()
        .filter(|c| (' '..='~').contains(c))
        .take(SAMPLE_MAX)
        .collect()
}

/// Matches counted since the last report, per rule.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Tally {
    pub rules: BTreeMap<u32, RuleTally>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleTally {
    pub count: u64,
    /// Of those, answered 403.
    #[serde(default)]
    pub blocked: u64,
    pub last_at: i64,
    pub samples: Vec<String>,
}

impl Tally {
    /// One request matched rule `id`. `sample` is built only when one is kept.
    pub fn add(&mut self, id: u32, blocked: bool, at: i64, sample: impl FnOnce() -> String) {
        if !(MANAGED_ID_MIN..=MANAGED_ID_MAX).contains(&id) {
            return;
        }
        let t = self.rules.entry(id).or_default();
        t.count = t.count.saturating_add(1);
        if blocked {
            t.blocked = t.blocked.saturating_add(1);
        }
        t.last_at = t.last_at.max(at);
        if t.samples.len() < SAMPLES_PER_RULE {
            let s = sample();
            if !s.is_empty() && !t.samples.contains(&s) {
                t.samples.push(s);
            }
        }
    }

    /// Fold another tally into this one.
    pub fn merge(&mut self, other: Tally) {
        for (id, o) in other.rules {
            let t = self.rules.entry(id).or_default();
            t.count = t.count.saturating_add(o.count);
            t.blocked = t.blocked.saturating_add(o.blocked);
            t.last_at = t.last_at.max(o.last_at);
            for s in o.samples {
                if t.samples.len() < SAMPLES_PER_RULE && !t.samples.contains(&s) {
                    t.samples.push(s);
                }
            }
        }
    }

    /// The tally as the report carries it.
    #[must_use]
    pub fn to_hits(&self) -> Vec<snsec_common::schema::WafHit> {
        self.rules
            .iter()
            .map(|(id, t)| snsec_common::schema::WafHit {
                id: *id,
                count: t.count,
                blocked: t.blocked,
                last_at: t.last_at,
                samples: t.samples.clone(),
            })
            .collect()
    }
}

/// Short, single-line-per-line text of a failed config test for the hub:
/// printable characters only, at most `max` bytes.
#[must_use]
pub fn short_output(text: &str, max: usize) -> String {
    let mut out = String::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let clean: String = line.chars().filter(|c| !c.is_control()).collect();
        let sep = usize::from(!out.is_empty());
        let room = max.saturating_sub(out.len() + sep);
        if room == 0 {
            break;
        }
        if sep == 1 {
            out.push('\n');
        }
        if clean.len() <= room {
            out.push_str(&clean);
        } else {
            // Cut at a character boundary and stop.
            let mut cut = room;
            while !clean.is_char_boundary(cut) {
                cut -= 1;
            }
            out.push_str(&clean[..cut]);
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apache_modsecurity_conf_gives_its_engine_and_rule_directory() {
        let conf = r#"
<IfModule mod_security2.c>
    # SecRuleEngine Off
    SecRuleEngine On
    SecRequestBodyAccess On
    IncludeOptional /etc/modsecurity.d/*.conf
    Include "/etc/httpd/conf/extra/extra-rules.conf"
</IfModule>
"#;
        let s = scan_conf(conf);
        assert_eq!(s.engine.as_deref(), Some("on"));
        assert_eq!(s.module, None);
        assert_eq!(s.include_dirs, vec!["/etc/modsecurity.d"]);
        assert_eq!(s.files, vec!["/etc/httpd/conf/extra/extra-rules.conf"]);
    }

    #[test]
    fn nginx_and_openlitespeed_module_switches_are_not_the_engine() {
        let nginx = "modsecurity on;\nmodsecurity_rules_file /etc/nginx/nginx-modsecurity.conf;\n";
        let s = scan_conf(nginx);
        assert_eq!(s.module, Some(true));
        assert_eq!(s.engine, None);
        assert_eq!(s.files, vec!["/etc/nginx/nginx-modsecurity.conf"]);
        let ols = "module mod_security {\n  modsecurity  on\n  modsecurity_rules_file  /usr/local/lsws/conf/modsec/rules.conf\n  ls_enabled 1\n}\n";
        let s = scan_conf(ols);
        assert_eq!(s.module, Some(true));
        assert_eq!(s.files, vec!["/usr/local/lsws/conf/modsec/rules.conf"]);
    }

    #[test]
    fn the_engine_state_is_cautious() {
        let v = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        // Module on, engine never set: ModSecurity's default is Off.
        assert_eq!(engine_state(Some(true), &[], None, true), "off");
        assert_eq!(engine_state(None, &[], None, false), "unknown");
        assert_eq!(
            engine_state(Some(false), &v(&["on"]), Some("on"), true),
            "off"
        );
        assert_eq!(
            engine_state(None, &v(&["on", "detectiononly"]), None, true),
            "detection_only"
        );
        assert_eq!(engine_state(None, &v(&["on", "off"]), None, true), "off");
        assert_eq!(engine_state(Some(true), &v(&["on"]), None, true), "on");
        // DirectAdmin's own setting is what each site gets.
        assert_eq!(
            engine_state(Some(true), &v(&["off"]), Some("on"), true),
            "on"
        );
        assert_eq!(engine_state(None, &[], Some("off"), true), "off");
    }

    #[test]
    fn relative_or_climbing_includes_are_ignored() {
        let s =
            scan_conf("Include conf.d/*.conf\nInclude /etc/../tmp/*.conf\nInclude /etc/x/*.load\n");
        assert!(s.include_dirs.is_empty());
        assert!(s.files.is_empty());
    }

    #[test]
    fn the_tally_counts_blocks_and_keeps_a_few_distinct_examples() {
        let mut t = Tally::default();
        for i in 0..10 {
            t.add(60_001, i % 2 == 0, 100 + i, || format!("h /p{}", i % 5));
        }
        t.add(60_001, false, 50, || "h /p0".into());
        t.add(949_110, true, 1, String::new);
        let mut other = Tally::default();
        other.add(60_001, true, 200, || "h /z".into());
        other.add(60_002, false, 5, || "h /y".into());
        t.merge(other);
        let hits = t.to_hits();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].count, 12);
        assert_eq!(hits[0].blocked, 6);
        assert_eq!(hits[0].last_at, 200);
        assert_eq!(hits[0].samples.len(), SAMPLES_PER_RULE);
        assert_eq!(hits[1].id, 60_002);
        assert_eq!(sample_of("shop.example", "/.env?x=1"), "shop.example /.env");
        assert_eq!(sample_of("", "/a\u{1}b"), "/ab");
    }

    #[test]
    fn config_tests_are_judged_by_server() {
        let f = "zz-sn-secure.conf";
        assert!(test_passed("apache", Some(0), "Syntax OK", f));
        assert!(!test_passed("apache", Some(1), "AH00526: Syntax error", f));
        assert!(!test_passed("nginx", None, "", f));
        // OpenLiteSpeed: 1 is warnings only, 2 is errors.
        assert!(test_passed("openlitespeed", Some(1), "[WARN] something", f));
        assert!(!test_passed("openlitespeed", Some(2), "[ERROR] x", f));
        // ...and a rules file it could not load still fails the test.
        assert!(!test_passed(
            "openlitespeed",
            Some(0),
            "[ERROR] [Module:mod_security] setSecRule(type 2) /etc/modsecurity.d/zz-sn-secure.conf failed: Rule id: 60001 is duplicated",
            f
        ));
        // Errors about other files are not ours to judge.
        assert!(test_passed(
            "openlitespeed",
            Some(1),
            "[ERROR] /etc/modsecurity.d/REQUEST-901.conf: warning",
            f
        ));
    }

    #[test]
    fn a_match_of_our_rule_is_not_a_complaint_about_it() {
        let f = "zz-sn-secure.conf";
        let hit = r#"[INFO] [Module:mod_security] ModSecurity: Warning. Matched "Operator `Contains' with parameter `nikto'" [file "/etc/modsecurity.d/zz-sn-secure.conf"] [line "9"] [id "60011"] [uri "/error_log"] syntax"#;
        assert!(!log_blames(hit, f));
        assert!(log_blames(
            "[ERROR] /etc/modsecurity.d/zz-sn-secure.conf: Rule id: 60001 is duplicated",
            f
        ));
    }

    #[test]
    fn ids_already_taken_are_found_in_any_quoting() {
        let text = r#"
SecRule ARGS "@rx x" "id:60010,phase:2,deny"
SecRule ARGS "@rx y" "phase:2,id:'60011',deny"
SecAction "id: 60012"
SecRule ARGS "@rx z" "id:949110"
SecRule ARGS "@rx w" "ctl:ruleRemoveById:60013,id:1234"
"#;
        assert_eq!(ids_in(text, 60_000, 69_999), vec![60_010, 60_011, 60_012]);
    }

    #[test]
    fn a_site_exclusion_of_our_ids_is_seen() {
        let r = |t: &str| removes_range(t, 60_000, 69_999);
        assert!(r("SecRuleEngine On\nSecRuleRemoveById 60005\n"));
        assert!(r("SecRuleRemoveById 1-99999\n"));
        assert!(r("SecRuleRemoveById \"949110 60001\"\n"));
        assert!(!r(
            "SecRuleRemoveById 949110\nSecRuleRemoveById 70000-79999\n"
        ));
        assert!(!r("# SecRuleRemoveById 60001\n"));
    }

    #[test]
    fn config_test_output_is_cut_and_cleaned() {
        let out = short_output(
            "AH00526: Syntax error on line 5 of /etc/modsecurity.d/sn-secure.conf:\n\x1b[31mError parsing actions\n\n",
            60,
        );
        assert!(out.starts_with("AH00526"));
        assert!(out.len() <= 60);
        assert!(!out.contains('\x1b'));
    }

    // ---- OPanel ------------------------------------------------------------

    const LIVE: &str = "/usr/local/lsws/conf/opanel/waf/zz-sn-secure.conf";
    // As OPanel writes it (a VPS on OpenLiteSpeed, 2026-10).
    const CUSTOM: &str = "# opanel-mcp: AI crawler bot (added 2026-09-26 03:30 UTC by admin)\nSecRule REQUEST_HEADERS:User-Agent \"@contains claudebot\" \"id:1090000,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'opanel mcp: AI crawler bot'\"\n\n# opanel-mcp: SEO bot (added 2026-09-26 03:31 UTC by admin)\nSecRule REQUEST_HEADERS:User-Agent \"@contains ahrefsbot\" \"id:1090004,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'opanel mcp: SEO bot'\"\n";

    #[test]
    fn the_hook_block_is_added_once_and_taken_out_cleanly() {
        let hooked = with_hook(CUSTOM, LIVE);
        assert!(
            hooked.starts_with(CUSTOM),
            "the panel's rules are untouched"
        );
        assert!(hooked.ends_with(&hook_block(LIVE)));
        assert!(hook_in_place(&hooked, LIVE));
        assert!(!hook_in_place(CUSTOM, LIVE));
        // Adding again changes nothing.
        assert_eq!(with_hook(&hooked, LIVE), hooked);
        // Taking it out gives the panel's file back.
        assert_eq!(without_hook(&hooked), CUSTOM);
        assert_eq!(without_hook(CUSTOM), CUSTOM);
        // A file the panel rewrote without our block is not "in place".
        assert!(!hook_in_place(&without_hook(&hooked), LIVE));
    }

    #[test]
    fn the_hook_works_on_an_empty_file_and_one_without_a_final_newline() {
        let only = with_hook("", LIVE);
        assert_eq!(only, hook_block(LIVE));
        assert_eq!(without_hook(&only), "");
        let bare = with_hook("SecRuleEngine On", LIVE);
        assert!(bare.starts_with("SecRuleEngine On\n\n# BEGIN SN Secure"));
        assert_eq!(without_hook(&bare), "SecRuleEngine On\n");
    }

    #[test]
    fn a_moved_file_changes_the_include_line() {
        let hooked = with_hook(CUSTOM, LIVE);
        assert!(!hook_in_place(&hooked, "/other/zz-sn-secure.conf"));
        let moved = with_hook(&hooked, "/other/zz-sn-secure.conf");
        assert_eq!(moved.matches(HOOK_BEGIN).count(), 1);
        assert!(moved.contains("Include /other/zz-sn-secure.conf"));
        assert!(!moved.contains(LIVE));
    }

    #[test]
    fn a_begin_marker_without_its_end_is_not_cut_out() {
        // Whoever edited the file by hand, or a truncated write: never delete
        // what follows a marker that has no end close by.
        let broken = format!(
            "{CUSTOM}\n{HOOK_BEGIN}\nInclude {LIVE}\nSecRule ARGS \"@contains x\" \"id:1,deny\"\n"
        );
        assert_eq!(without_hook(&broken).matches("SecRule").count(), 3);
        // An end marker far away does not count either.
        let far = format!("{HOOK_BEGIN}\n{}{HOOK_END}\n", "# line\n".repeat(20));
        assert_eq!(without_hook(&far).matches("# line").count(), 20);
    }

    #[test]
    fn two_blocks_are_both_taken_out() {
        let twice = format!("{}\n{CUSTOM}\n{}", hook_block(LIVE), hook_block(LIVE));
        let clean = without_hook(&twice);
        assert!(!clean.contains(HOOK_BEGIN) && clean.contains("claudebot"));
    }

    /// OPanel's module switch is in `httpd_config.conf`.
    fn opanel_engine(base: &str, httpd: &str, others: &[String]) -> &'static str {
        panel_engine(base, scan_conf(httpd).module, others)
    }

    #[test]
    fn opanel_with_the_module_and_the_engine_on_is_on() {
        // opanel-base.conf and the OPANEL managed ModSecurity block of
        // httpd_config.conf as found on the VPS the hub called "not installed".
        let base = "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 134217728\n";
        let httpd = "# OPANEL managed ModSecurity BEGIN\nmodule mod_security {\n    modsecurity             on\n    ls_enabled              1\n}\n# OPANEL managed ModSecurity END\n";
        assert_eq!(opanel_engine(base, httpd, &[]), "on");
        // The module switched off wins over everything.
        let off = httpd.replace("modsecurity             on", "modsecurity             off");
        assert_eq!(opanel_engine(base, &off, &[]), "off");
        // One rule file of the panel that detects only is reported.
        assert_eq!(
            opanel_engine(base, httpd, &["detectiononly".to_string()]),
            "detection_only"
        );
        // Nothing says the engine is on: ModSecurity's default is off.
        assert_eq!(opanel_engine("", httpd, &[]), "off");
    }

    #[test]
    fn sites_without_the_waf_block_are_found_but_not_the_panels_own_hosts() {
        let with =
            "virtualHost x {\n# OPANEL WAF BEGIN\nmodule mod_security {\n}\n# OPANEL WAF END\n}\n"
                .to_string();
        let without = "virtualHost y {\n}\n".to_string();
        let v = vec![
            ("babatap.com".to_string(), with.clone()),
            ("old.example".to_string(), without.clone()),
            ("opanel_tools".to_string(), without),
        ];
        assert_eq!(
            sites_without_waf(&v, "# OPANEL WAF BEGIN"),
            vec!["old.example".to_string()]
        );
    }

    // ---- bPanel (nginx) ----------------------------------------------------

    // As bPanel writes it (a VPS on nginx, 2026-10).
    const BPANEL_CUSTOM: &str = "# bpanel-mcp: added by admin on 2026-09-24 - Block WordPress install probe\nSecRule REQUEST_URI \"@contains /wp-admin/install.php\" \"id:1090000,phase:1,deny,status:403,log,msg:'BPanel MCP: blocked'\"\n";

    #[test]
    fn bpanel_with_its_base_file_on_is_on_without_a_module_switch() {
        // bpanel-base.conf as found on the VPS the hub called "not installed".
        let base = "SecRuleEngine On\nSecRequestBodyAccess Off\n";
        assert_eq!(panel_engine(base, None, &[]), "on");
        assert_eq!(
            panel_engine(base, None, &["detectiononly".to_string()]),
            "detection_only"
        );
        assert_eq!(panel_engine("", None, &[]), "off");
    }

    #[test]
    fn the_hook_goes_at_the_end_of_bpanel_custom_and_comes_out_clean() {
        let live = "/etc/nginx/modsec/zz-sn-secure.conf";
        let hooked = with_hook(BPANEL_CUSTOM, live);
        assert!(hooked.starts_with(BPANEL_CUSTOM));
        assert!(hooked.ends_with(&format!("{HOOK_BEGIN}\nInclude {live}\n{HOOK_END}\n")));
        assert!(hook_in_place(&hooked, live));
        assert_eq!(without_hook(&hooked), BPANEL_CUSTOM);
    }

    #[test]
    fn nginx_sites_are_named_by_file_and_the_panels_own_files_are_skipped() {
        let with = "server {\n    # BPANEL WAF BEGIN\n    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsec/sites/a.com.conf;\n    # BPANEL WAF END\n}\n".to_string();
        let without = "server {\n}\n".to_string();
        let v = vec![
            ("a.com".to_string(), with),
            ("tos.example.vn".to_string(), without.clone()),
            ("00-bpanel-tools".to_string(), without),
        ];
        assert_eq!(
            sites_without_waf(&v, "# BPANEL WAF BEGIN"),
            vec!["tos.example.vn".to_string()]
        );
    }
}
