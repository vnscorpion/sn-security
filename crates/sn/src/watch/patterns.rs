//! Fixed detection patterns (no baseline needed) plus the per-IP accumulator
//! that both the patterns and the baseline threshold read.

use std::collections::HashSet;

use snsec_common::logfmt::LogLine;

/// Per-IP aggregate for one cycle. Distinct-path tracking is capped so a single
/// hostile IP cannot blow up memory.
#[derive(Debug, Default)]
pub struct IpAgg {
    pub requests: u64,
    pub err4xx: u64,
    pub err404: u64,
    /// POSTs to wp-login.php / xmlrpc.php.
    pub login_posts: u64,
    pub xmlrpc_posts: u64,
    pub wp_pingback: u64,
    /// Requests for a path only a scanner asks for (see [`is_probe_path`]).
    pub probe_hits: u64,
    pub bad_ua: bool,
    pub empty_ua: bool,
    paths: HashSet<u64>,
    paths_capped: bool,
    /// Distinct probe paths among `probe_hits`, up to [`PROBE_DISTINCT`].
    probe_paths: Vec<u64>,
}

const PATH_CAP: usize = 64;

/// Distinct probe paths that make a scanner on their own.
const PROBE_DISTINCT: usize = 3;
/// 4xx answers over as many distinct paths that, with a probe, make a scanner.
const PROBE_MISSES: u64 = 10;
/// Up to this many requests an uncorroborated probe is reported. Above it the
/// probe decides nothing, so the request-rate check still applies to the
/// address (one `/.env` must not buy a flood its way out of a rate ban).
const PROBE_REPORT_MAX: u64 = 20;

impl IpAgg {
    pub fn observe(&mut self, line: &LogLine) {
        self.requests += 1;
        if (400..500).contains(&line.status) {
            self.err4xx += 1;
            if line.status == 404 {
                self.err404 += 1;
            }
        }
        let path = line.path.split('?').next().unwrap_or(&line.path);
        if self.paths.len() < PATH_CAP {
            self.paths.insert(fxhash(path.as_bytes()));
        } else {
            self.paths_capped = true;
        }

        let is_post = line.method.eq_ignore_ascii_case("POST");
        if is_post && path.ends_with("/wp-login.php") {
            self.login_posts += 1;
        }
        if path.ends_with("/xmlrpc.php") {
            if is_post {
                self.xmlrpc_posts += 1;
            }
            if line.user_agent.starts_with("WordPress/") {
                self.wp_pingback += 1;
            }
        }

        if is_probe_path(path) {
            self.probe_hits += 1;
            let h = fxhash(path.to_ascii_lowercase().as_bytes());
            if self.probe_paths.len() < PROBE_DISTINCT && !self.probe_paths.contains(&h) {
                self.probe_paths.push(h);
            }
        }
        let ua = line.user_agent.trim();
        if ua.is_empty() || ua == "-" {
            self.empty_ua = true;
        } else if is_bad_ua(ua) {
            self.bad_ua = true;
        }
    }

    #[must_use]
    pub fn distinct_paths(&self) -> usize {
        if self.paths_capped {
            PATH_CAP
        } else {
            self.paths.len()
        }
    }

    /// Probe requests plus something that marks a scanner. Any web page can make
    /// a visitor's browser request `/.env` on this site, with the browser's own
    /// User-Agent; one such request must not ban the visitor for a day.
    fn probe_corroborated(&self) -> bool {
        self.probe_hits > 0
            && (self.bad_ua
                || self.empty_ua
                || self.probe_paths.len() >= PROBE_DISTINCT
                || (self.err4xx >= PROBE_MISSES && self.distinct_paths() >= PROBE_MISSES as usize))
    }
}

/// Outcome of evaluating the fixed patterns for one IP.
#[derive(Debug, Clone)]
pub struct PatternHit {
    pub reason: &'static str,
    pub ttl_secs: u64,
    /// `false` for report-only patterns (e.g. xmlrpc pingback).
    pub ban: bool,
}

/// Evaluate the fixed patterns. A cycle covers roughly one timer interval of
/// logs, so the plan's per-5-minute windows map onto a single cycle.
#[must_use]
pub fn evaluate(a: &IpAgg) -> Option<PatternHit> {
    if a.login_posts + a.xmlrpc_posts > 10 {
        return Some(PatternHit {
            reason: "bruteforce",
            ttl_secs: 3600,
            ban: true,
        });
    }
    if a.probe_corroborated() {
        return Some(PatternHit {
            reason: "probe",
            ttl_secs: 86_400,
            ban: true,
        });
    }
    if a.err404 > 30 && a.distinct_paths() > 20 {
        return Some(PatternHit {
            reason: "scanner",
            ttl_secs: 1800,
            ban: true,
        });
    }
    if a.bad_ua || (a.empty_ua && a.requests > 50) {
        return Some(PatternHit {
            reason: "bad_ua",
            ttl_secs: 86_400,
            ban: true,
        });
    }
    if a.wp_pingback > 3 {
        return Some(PatternHit {
            reason: "xmlrpc_pingback",
            ttl_secs: 0,
            ban: false,
        });
    }
    if a.probe_hits > 0 && a.requests <= PROBE_REPORT_MAX {
        return Some(PatternHit {
            reason: "probe",
            ttl_secs: 0,
            ban: false,
        });
    }
    None
}

/// Paths only a scanner asks for: secrets and version-control data left in the
/// web root, and database admin tools. Matched on whole path segments, so
/// `/blog/.environment` or `/assets/config.json` are ordinary requests.
fn is_probe_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    let (Some(first), Some(last)) = (segs.first(), segs.last()) else {
        return false;
    };
    // .env, .env.local, .env.bak, .env~ - but not .envrc or .environment.
    let env_file = last
        .strip_prefix(".env")
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphanumeric()));
    env_file
        || matches!(*last, ".ds_store" | "wp-config.php.bak" | "wp-config.php~")
        || segs
            .iter()
            .any(|s| matches!(*s, ".git" | ".svn" | ".hg" | ".aws"))
        || first.starts_with("phpmyadmin")
        || *first == "pma"
        || segs.windows(2).any(|w| w == ["vendor", "phpunit"])
}

fn is_bad_ua(ua: &str) -> bool {
    const BAD: &[&str] = &[
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
    let lower = ua.to_ascii_lowercase();
    BAD.iter().any(|b| lower.contains(b))
}

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
mod tests {
    use super::*;
    use snsec_common::logfmt::{LogFormat, parse_line};

    fn line(s: &str) -> LogLine {
        parse_line(LogFormat::Combined, s, &[]).unwrap()
    }

    #[test]
    fn bruteforce_detected() {
        let mut a = IpAgg::default();
        for _ in 0..11 {
            a.observe(&line(
                r#"1.2.3.4 - - [x] "POST /wp-login.php HTTP/1.1" 200 1 "-" "x""#,
            ));
        }
        let hit = evaluate(&a).unwrap();
        assert_eq!(hit.reason, "bruteforce");
        assert!(hit.ban);
    }

    const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0) Chrome/148.0.0.0 Safari/537.36";

    fn get(a: &mut IpAgg, path: &str, status: u16, ua: &str) {
        a.observe(&line(&format!(
            r#"1.2.3.4 - - [x] "GET {path} HTTP/1.1" {status} 1 "-" "{ua}""#
        )));
    }

    #[test]
    fn a_lone_probe_from_a_browser_is_only_reported() {
        // Any page can make a visitor's browser fetch /.env here, even a few
        // times; that alone must not ban the visitor.
        let mut a = IpAgg::default();
        get(&mut a, "/", 200, BROWSER);
        for _ in 0..3 {
            get(&mut a, "/.env", 404, BROWSER);
        }
        let hit = evaluate(&a).unwrap();
        assert_eq!(hit.reason, "probe");
        assert!(!hit.ban);
        assert_eq!(hit.ttl_secs, 0);
    }

    #[test]
    fn a_probe_with_a_tool_or_missing_user_agent_bans() {
        for ua in ["sqlmap/1.7", "", "-"] {
            let mut a = IpAgg::default();
            get(&mut a, "/.env", 404, ua);
            let hit = evaluate(&a).unwrap();
            assert_eq!((hit.reason, hit.ban, hit.ttl_secs), ("probe", true, 86_400));
        }
    }

    #[test]
    fn several_probe_paths_or_many_misses_ban() {
        let mut a = IpAgg::default();
        for p in ["/.env", "/.git/config", "/phpmyadmin/"] {
            get(&mut a, p, 404, BROWSER);
        }
        assert!(evaluate(&a).unwrap().ban);

        let mut a = IpAgg::default();
        get(&mut a, "/.env", 404, BROWSER);
        for i in 0..10 {
            get(&mut a, &format!("/old{i}.php"), 404, BROWSER);
        }
        let hit = evaluate(&a).unwrap();
        assert_eq!((hit.reason, hit.ban), ("probe", true));
    }

    #[test]
    fn a_probe_does_not_hide_a_flood_from_the_rate_check() {
        // Busy address with one /.env: the probe decides nothing, so `decide`
        // falls through to the request-rate threshold.
        let mut a = IpAgg::default();
        for _ in 0..500 {
            get(&mut a, "/", 200, BROWSER);
        }
        get(&mut a, "/.env", 404, BROWSER);
        assert!(evaluate(&a).is_none());
    }

    #[test]
    fn probe_paths_match_whole_segments() {
        for p in [
            "/.env",
            "/.ENV",
            "/.env.local",
            "/.env~",
            "/laravel/.env",
            "//.env/",
            "/.git/config",
            "/.git",
            "/app/.git/HEAD",
            "/.svn/entries",
            "/.aws/credentials",
            "/phpmyadmin",
            "/phpMyAdmin-5.2.1/index.php",
            "/pma/",
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/.DS_Store",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/lib/vendor/phpunit/x",
        ] {
            assert!(is_probe_path(p), "{p}");
        }
        for p in [
            "/",
            "/config.json",
            "/assets/config.json",
            "/.envrc",
            "/blog/.environment",
            "/.github/logo.png",
            "/docs/phpmyadmin-guide",
            "/blog/pma/",
            "/wp-config.php",
            "/vendor/phpunit-docs",
            "/search",
        ] {
            assert!(!is_probe_path(p), "{p}");
        }
    }

    #[test]
    fn scanner_needs_both_404_and_paths() {
        let mut a = IpAgg::default();
        for i in 0..40 {
            a.observe(&line(&format!(
                r#"1.2.3.4 - - [x] "GET /x{i} HTTP/1.1" 404 1 "-" "x""#
            )));
        }
        assert_eq!(evaluate(&a).unwrap().reason, "scanner");
    }

    #[test]
    fn pingback_is_report_only() {
        let mut a = IpAgg::default();
        for _ in 0..4 {
            a.observe(&line(
                r#"1.2.3.4 - - [x] "POST /xmlrpc.php HTTP/1.1" 200 1 "-" "WordPress/6.5""#,
            ));
        }
        // 4 xmlrpc POSTs is below the bruteforce threshold (>10), so pingback.
        let hit = evaluate(&a).unwrap();
        assert_eq!(hit.reason, "xmlrpc_pingback");
        assert!(!hit.ban);
    }
}
