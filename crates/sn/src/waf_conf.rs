//! Reading web-server configuration and error logs for the managed ModSecurity
//! rules (pure: text in, facts out; the file system and commands are in
//! `waf.rs`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use snsec_common::waf::{MANAGED_ID_MAX, MANAGED_ID_MIN};

/// What one configuration file says about ModSecurity.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfScan {
    /// The last `SecRuleEngine` (Apache/libmodsecurity) or `modsecurity`
    /// (nginx/OpenLiteSpeed) value, lower-cased: `on`, `off`, `detectiononly`.
    pub engine: Option<String>,
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
            "modsecurity" => {
                let v = arg(rest).to_ascii_lowercase();
                if v == "on" || v == "off" {
                    out.engine = Some(v);
                }
            }
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
/// duplicated`, a parse error, an unsupported rule)?
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
        if !l.contains(file_name) {
            return false;
        }
        let lower = l.to_ascii_lowercase();
        WORDS.iter().any(|w| lower.contains(w))
    })
}

/// The engine word the hub shows (`WafStatus::engine`).
#[must_use]
pub fn engine_label(v: Option<&str>) -> &'static str {
    match v {
        Some("on") => "on",
        Some("detectiononly") => "detection_only",
        Some("off") => "off",
        _ => "unknown",
    }
}

/// A value between `[name "` and the next `"]` in a ModSecurity log line.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let tag = format!("[{name} \"");
    let start = line.find(&tag)? + tag.len();
    let rest = &line[start..];
    let end = rest.find("\"]")?;
    Some(&rest[..end])
}

/// One match of one of our rules, read from an error-log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: u32,
    /// `host uri`, without the query string, when the line has them.
    pub sample: Option<String>,
}

/// Is this error-log line a match of one of our rules? ModSecurity 2
/// (Apache), libmodsecurity 3 (nginx, OpenLiteSpeed) and LiteSpeed write
/// `[id "N"]`; a line whose message is someone else's is not ours even when
/// its id happens to fall in our range.
#[must_use]
pub fn parse_hit(line: &str) -> Option<Hit> {
    if !line.contains("[id \"") {
        return None;
    }
    let id = snsec_common::waf::managed_id_in_log_line(line)?;
    if let Some(msg) = field(line, "msg")
        && !msg.starts_with("SN Secure")
    {
        return None;
    }
    let host = field(line, "hostname").unwrap_or("");
    let uri = field(line, "uri").unwrap_or("");
    let sample = sample_of(host, uri);
    Some(Hit { id, sample })
}

fn sample_of(host: &str, uri: &str) -> Option<String> {
    let uri = uri.split('?').next().unwrap_or("");
    if uri.is_empty() {
        return None;
    }
    let s = if host.is_empty() {
        uri.to_string()
    } else {
        format!("{host} {uri}")
    };
    Some(
        s.chars()
            .filter(|c| (' '..='~').contains(c))
            .take(SAMPLE_MAX)
            .collect(),
    )
}

/// Matches of our rules in one JSON audit-log record (one line per request,
/// `SecAuditLogFormat JSON`). ModSecurity 3 (nginx, OpenLiteSpeed) lists
/// `transaction.messages[].details.ruleId`; ModSecurity 2 writes
/// `audit_data.messages[]` as text with `[id "N"]`. Only the rule id, the Host
/// and the path are taken: the record also holds headers and bodies.
#[must_use]
pub fn parse_audit_line(line: &str) -> Vec<Hit> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return Vec::new();
    };
    let header = |headers: &serde_json::Value| -> String {
        headers
            .as_object()
            .and_then(|h| {
                h.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                    .and_then(|(_, v)| v.as_str())
            })
            .unwrap_or("")
            .to_string()
    };
    let mut out = Vec::new();
    if let Some(tx) = v.get("transaction")
        && let Some(msgs) = tx.get("messages").and_then(|m| m.as_array())
    {
        // ModSecurity 3.
        let req = tx.get("request");
        let host = req
            .and_then(|r| r.get("headers"))
            .map(header)
            .unwrap_or_default();
        let uri = req
            .and_then(|r| r.get("uri"))
            .and_then(|u| u.as_str())
            .unwrap_or("");
        for m in msgs {
            let ours = m
                .get("message")
                .and_then(|s| s.as_str())
                .is_none_or(|s| s.starts_with("SN Secure"));
            let id = m
                .get("details")
                .and_then(|d| d.get("ruleId"))
                .and_then(|i| {
                    i.as_str()
                        .map(str::to_string)
                        .or_else(|| i.as_u64().map(|n| n.to_string()))
                })
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(id) = id
                && ours
                && (MANAGED_ID_MIN..=MANAGED_ID_MAX).contains(&id)
            {
                out.push(Hit {
                    id,
                    sample: sample_of(&host, uri),
                });
            }
        }
        return out;
    }
    if let Some(msgs) = v
        .get("audit_data")
        .and_then(|a| a.get("messages"))
        .and_then(|m| m.as_array())
    {
        // ModSecurity 2.
        let req = v.get("request");
        let host = req
            .and_then(|r| r.get("headers"))
            .map(header)
            .unwrap_or_default();
        let uri = req
            .and_then(|r| r.get("request_line"))
            .and_then(|l| l.as_str())
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");
        for m in msgs.iter().filter_map(|m| m.as_str()) {
            if let Some(h) = parse_hit(m) {
                out.push(Hit {
                    id: h.id,
                    sample: sample_of(&host, uri),
                });
            }
        }
    }
    out
}

const SAMPLE_MAX: usize = 160;
/// Examples kept per rule between two reports.
pub const SAMPLES_PER_RULE: usize = 3;

/// Matches counted since the last report, per rule.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Tally {
    pub rules: BTreeMap<u32, RuleTally>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleTally {
    pub count: u64,
    pub last_at: i64,
    pub samples: Vec<String>,
}

impl Tally {
    pub fn add(&mut self, hit: Hit, at: i64) {
        if !(MANAGED_ID_MIN..=MANAGED_ID_MAX).contains(&hit.id) {
            return;
        }
        let t = self.rules.entry(hit.id).or_default();
        t.count = t.count.saturating_add(1);
        t.last_at = t.last_at.max(at);
        if let Some(s) = hit.sample
            && t.samples.len() < SAMPLES_PER_RULE
            && !t.samples.contains(&s)
        {
            t.samples.push(s);
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
        assert_eq!(s.include_dirs, vec!["/etc/modsecurity.d"]);
        assert_eq!(s.files, vec!["/etc/httpd/conf/extra/extra-rules.conf"]);
    }

    #[test]
    fn detection_only_and_lowercase_directives_are_read() {
        let s = scan_conf("secruleengine DetectionOnly\n");
        assert_eq!(engine_label(s.engine.as_deref()), "detection_only");
        assert_eq!(engine_label(None), "unknown");
    }

    #[test]
    fn nginx_and_openlitespeed_module_blocks_are_read() {
        let nginx =
            "modsecurity on;\nmodsecurity_rules_file /etc/nginx/nginx-modsecurity-main.conf;\n";
        let s = scan_conf(nginx);
        assert_eq!(s.engine.as_deref(), Some("on"));
        assert_eq!(s.files, vec!["/etc/nginx/nginx-modsecurity-main.conf"]);
        let ols = "module mod_security {\n  modsecurity  on\n  modsecurity_rules_file  /usr/local/lsws/conf/modsec/rules.conf\n  ls_enabled 1\n}\n";
        let s = scan_conf(ols);
        assert_eq!(s.engine.as_deref(), Some("on"));
        assert_eq!(s.files, vec!["/usr/local/lsws/conf/modsec/rules.conf"]);
    }

    #[test]
    fn relative_or_climbing_includes_are_ignored() {
        let s =
            scan_conf("Include conf.d/*.conf\nInclude /etc/../tmp/*.conf\nInclude /etc/x/*.load\n");
        assert!(s.include_dirs.is_empty());
        assert!(s.files.is_empty());
    }

    #[test]
    fn our_hits_are_read_from_apache_and_libmodsecurity_lines() {
        let apache = r#"[Tue Oct 14 01:02:03.456789 2026] [:error] [pid 1] [client 1.2.3.4:5] [client 1.2.3.4] ModSecurity: Warning. String match "/.env" at REQUEST_FILENAME. [file "/etc/modsecurity.d/sn-secure.conf"] [line "5"] [id "60003"] [msg "SN Secure: probe for a file no site serves"] [tag "sn-secure"] [hostname "shop.example"] [uri "/.env"] [unique_id "Zx"]"#;
        assert_eq!(
            parse_hit(apache),
            Some(Hit {
                id: 60_003,
                sample: Some("shop.example /.env".into())
            })
        );
        let v3 = r#"2026/10/14 01:02:03 [error] 77#77: *9 [client 1.2.3.4] ModSecurity: Access denied with code 403 (phase 1). Matched "Operator `Contains' with parameter `sqlmap' against variable `REQUEST_HEADERS:User-Agent' [file "/etc/modsecurity.d/sn-secure.conf"] [line "9"] [id "60011"] [rev ""] [msg "SN Secure: vulnerability scanner"] [data ""] [severity "0"] [hostname "203.0.113.9"] [uri "/index.php?id=1"] [unique_id "1"] [ref "o0,6v20,6"]"#;
        let h = parse_hit(v3).unwrap();
        assert_eq!(h.id, 60_011);
        // The query string is left out of the example.
        assert_eq!(h.sample.as_deref(), Some("203.0.113.9 /index.php"));
    }

    #[test]
    fn other_rules_and_other_lines_are_not_ours() {
        assert_eq!(
            parse_hit(r#"ModSecurity: Warning. [id "949110"] [msg "Inbound Anomaly Score"]"#),
            None
        );
        // Someone else's rule in our range, with its own message.
        assert_eq!(
            parse_hit(r#"ModSecurity: Warning. [id "60001"] [msg "Local rule"]"#),
            None
        );
        assert_eq!(
            parse_hit("AH00558: httpd: Could not reliably determine"),
            None
        );
        // No message field at all: the id decides.
        assert_eq!(parse_hit(r#"[id "60001"]"#).map(|h| h.id), Some(60_001));
    }

    #[test]
    fn the_tally_counts_and_keeps_a_few_distinct_examples() {
        let mut t = Tally::default();
        for i in 0..10 {
            t.add(
                Hit {
                    id: 60_001,
                    sample: Some(format!("h /p{}", i % 5)),
                },
                100 + i,
            );
        }
        t.add(
            Hit {
                id: 60_001,
                sample: Some("h /p0".into()),
            },
            50,
        );
        t.add(
            Hit {
                id: 949_110,
                sample: None,
            },
            1,
        );
        let hits = t.to_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].count, 11);
        assert_eq!(hits[0].last_at, 109);
        assert_eq!(hits[0].samples.len(), SAMPLES_PER_RULE);
    }

    #[test]
    fn our_matches_are_read_from_json_audit_records() {
        let v3 = r#"{"transaction":{"client_ip":"1.2.3.4","time_stamp":"x","request":{"method":"GET","http_version":1.1,"hostname":"203.0.113.9","uri":"/.env?x=1","headers":{"Host":"shop.example","Cookie":"secret"},"body":"pw=1"},"response":{"http_code":403},"producer":{"secrules_engine":"Enabled"},"messages":[{"message":"Inbound Anomaly","details":{"ruleId":"949110"}},{"message":"SN Secure: probe for a file no site serves","details":{"ruleId":"60003","tags":["sn-secure"]}}]}}"#;
        let hits = parse_audit_line(v3);
        assert_eq!(
            hits,
            vec![Hit {
                id: 60_003,
                sample: Some("shop.example /.env".into())
            }]
        );
        let v2 = r#"{"transaction":{"time":"x","remote_address":"1.2.3.4"},"request":{"request_line":"GET /?tss-sc&b HTTP/1.1","headers":{"host":"a.example"}},"audit_data":{"messages":["Warning. Match of \"x\" [id \"60001\"] [msg \"SN Secure: distributed bot (request shape)\"]","Warning. [id \"920350\"]"],"engine_mode":"ENABLED"}}"#;
        let hits = parse_audit_line(v2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, 60_001);
        assert_eq!(hits[0].sample.as_deref(), Some("a.example /"));
        // Someone else's rule in our range, a cut line, a Serial-format line.
        assert!(
            parse_audit_line(
                r#"{"transaction":{"messages":[{"message":"Local","details":{"ruleId":"60002"}}]}}"#
            )
            .is_empty()
        );
        assert!(parse_audit_line(r#"{"transaction":{"messages":[{"det"#).is_empty());
        assert!(parse_audit_line("--a1b2c3d4-H--").is_empty());
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
        assert!(removes_range(
            "SecRuleEngine On\nSecRuleRemoveById 60005\n",
            60_000,
            69_999
        ));
        assert!(removes_range("SecRuleRemoveById 1-99999\n", 60_000, 69_999));
        assert!(removes_range(
            "SecRuleRemoveById \"949110 60001\"\n",
            60_000,
            69_999
        ));
        assert!(!removes_range(
            "SecRuleRemoveById 949110\nSecRuleRemoveById 70000-79999\n",
            60_000,
            69_999
        ));
        assert!(!removes_range(
            "# SecRuleRemoveById 60001\n",
            60_000,
            69_999
        ));
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
