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
}
