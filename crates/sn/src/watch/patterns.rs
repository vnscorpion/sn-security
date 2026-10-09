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
    pub probe_hit: bool,
    pub bad_ua: bool,
    pub empty_ua: bool,
    paths: HashSet<u64>,
    paths_capped: bool,
}

const PATH_CAP: usize = 64;

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
            self.probe_hit = true;
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
    if a.probe_hit {
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
    None
}

fn is_probe_path(path: &str) -> bool {
    const PROBES: &[&str] = &[
        "/.env",
        "/.git/",
        "/.git/config",
        "/phpmyadmin",
        "/pma/",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/.ds_store",
        "/.aws/",
        "/config.json",
        "/.svn/",
        "/vendor/phpunit",
    ];
    let lower = path.to_ascii_lowercase();
    PROBES.iter().any(|p| lower.contains(p))
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

    #[test]
    fn probe_detected() {
        let mut a = IpAgg::default();
        a.observe(&line(
            r#"1.2.3.4 - - [x] "GET /.env HTTP/1.1" 404 1 "-" "x""#,
        ));
        assert_eq!(evaluate(&a).unwrap().reason, "probe");
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
