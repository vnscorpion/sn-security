//! Web-server access-log parsing.
//!
//! Three formats are understood:
//! * [`LogFormat::Combined`] — the stock Nginx/Apache `combined` format. It has
//!   no proxy headers, so behind Cloudflare the client IP cannot be recovered.
//! * [`LogFormat::Sn`] — a custom format the installer configures, carrying the
//!   TCP peer, the real client, `CF-Connecting-IP`, `X-Forwarded-For`, vhost and
//!   request time. This is the recommended format.
//! * [`LogFormat::NginxJson`] — one JSON object per line.
//!
//! The parser is deliberately total: a malformed line yields `None` rather than
//! panicking, so a hostile log cannot crash the agent. Fuzz target lives in the
//! agent crate.

use std::net::IpAddr;

use serde::Deserialize;

use crate::net::{self, Cidr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Combined,
    Sn,
    NginxJson,
}

impl LogFormat {
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<LogFormat> {
        match s.trim().to_ascii_lowercase().as_str() {
            "combined" | "apache" | "nginx" => Some(LogFormat::Combined),
            "sn" => Some(LogFormat::Sn),
            "nginx_json" | "json" => Some(LogFormat::NginxJson),
            _ => None,
        }
    }
}

/// One parsed access-log line, reduced to the fields watch needs.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// The TCP peer address (the proxy, if any).
    pub peer: IpAddr,
    /// The real client address after resolving trusted proxies.
    pub client: IpAddr,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: String,
    /// Upstream/request time in seconds, when the format carries it.
    pub request_time: Option<f64>,
}

impl LogLine {
    /// Is this a POST to a credential/abuse-sensitive WordPress endpoint?
    #[must_use]
    pub fn is_sensitive_post(&self) -> bool {
        if !self.method.eq_ignore_ascii_case("POST") {
            return false;
        }
        let p = self.path.split('?').next().unwrap_or(&self.path);
        p.ends_with("/wp-login.php")
            || p.ends_with("/xmlrpc.php")
            || p.ends_with("/wp-comments-post.php")
            || p.contains("/admin")
    }
}

/// Split a line into logical tokens, treating `"..."` and `[...]` as single
/// tokens (contents only). Handles the quoting used by both `combined` and the
/// `sn` format.
fn tokenize(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::with_capacity(12);
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b'"' | b'[' => {
                let close = if bytes[i] == b'"' { b'"' } else { b']' };
                let start = i + 1;
                let mut j = start;
                while j < n && bytes[j] != close {
                    j += 1;
                }
                // Safe: start..j is within the original &str on byte boundaries
                // because we only split on ASCII delimiters.
                out.push(&line[start..j.min(n)]);
                i = if j < n { j + 1 } else { n };
            }
            _ => {
                let start = i;
                while i < n && bytes[i] != b' ' && bytes[i] != b'\t' {
                    i += 1;
                }
                out.push(&line[start..i]);
            }
        }
    }
    out
}

fn split_request(req: &str) -> (String, String) {
    let mut parts = req.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    (method, path)
}

fn resolve_client(peer: IpAddr, cf: &str, xff: &str, trusted: &[Cidr]) -> IpAddr {
    if !net::in_any(trusted, peer) {
        return net::normalize(peer);
    }
    // Peer is a trusted proxy: prefer CF-Connecting-IP, else the right-most XFF
    // entry that is not itself a trusted proxy.
    if let Ok(ip) = cf.trim().parse::<IpAddr>() {
        return net::normalize(ip);
    }
    for part in xff.split(',').rev() {
        if let Ok(ip) = part.trim().parse::<IpAddr>()
            && !net::in_any(trusted, ip)
        {
            return net::normalize(ip);
        }
    }
    net::normalize(peer)
}

/// Parse one line in the given format. `trusted` are proxy ranges used to
/// recover the real client IP; pass an empty slice if none.
#[must_use]
pub fn parse_line(fmt: LogFormat, line: &str, trusted: &[Cidr]) -> Option<LogLine> {
    match fmt {
        LogFormat::NginxJson => parse_json(line, trusted),
        LogFormat::Combined => {
            let t = tokenize(line);
            // ip - user [time] "req" status bytes "ref" "ua"
            if t.len() < 9 {
                return None;
            }
            let peer: IpAddr = t[0].parse().ok()?;
            let (method, path) = split_request(t[4]);
            let status: u16 = t[5].parse().ok()?;
            Some(LogLine {
                peer: net::normalize(peer),
                client: net::normalize(peer),
                host: String::new(),
                method,
                path,
                status,
                user_agent: t[8].to_string(),
                request_time: None,
            })
        }
        LogFormat::Sn => {
            let t = tokenize(line);
            // realip remote cf xff [time] host "req" status bytes rt "ua"
            if t.len() < 11 {
                return None;
            }
            let peer: IpAddr = t[0].parse().ok()?;
            let client = resolve_client(peer, t[2], t[3], trusted);
            let (method, path) = split_request(t[6]);
            let status: u16 = t[7].parse().ok()?;
            let request_time = t[9].parse::<f64>().ok();
            Some(LogLine {
                peer: net::normalize(peer),
                client,
                host: t[5].to_string(),
                method,
                path,
                status,
                user_agent: t[10].to_string(),
                request_time,
            })
        }
    }
}

#[derive(Deserialize)]
struct JsonLine {
    #[serde(default, alias = "remote_addr")]
    peer: String,
    #[serde(default, alias = "realip", alias = "realip_remote_addr")]
    real: String,
    #[serde(default, alias = "cf_connecting_ip", alias = "http_cf_connecting_ip")]
    cf: String,
    #[serde(default, alias = "xff", alias = "http_x_forwarded_for")]
    x_forwarded_for: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    request: String,
    #[serde(default)]
    method: String,
    #[serde(default, alias = "uri")]
    path: String,
    #[serde(default)]
    status: serde_json::Value,
    #[serde(default, alias = "http_user_agent", alias = "ua")]
    user_agent: String,
    #[serde(default, alias = "request_time")]
    rt: serde_json::Value,
}

fn parse_json(line: &str, trusted: &[Cidr]) -> Option<LogLine> {
    let j: JsonLine = serde_json::from_str(line.trim()).ok()?;
    // In the JSON format, `peer`/remote_addr is the real client if realip is on.
    // We treat `real` (if present) as the TCP peer, else `peer`.
    let peer_str = if j.real.is_empty() { &j.peer } else { &j.real };
    let peer: IpAddr = peer_str.trim().parse().ok()?;
    let client = resolve_client(peer, &j.cf, &j.x_forwarded_for, trusted);
    let (method, path) = if !j.request.is_empty() {
        split_request(&j.request)
    } else {
        (j.method.clone(), j.path.clone())
    };
    let status = match &j.status {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) as u16,
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    };
    let request_time = match &j.rt {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    };
    Some(LogLine {
        peer: net::normalize(peer),
        client,
        host: j.host,
        method,
        path,
        status,
        user_agent: j.user_agent,
        request_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cf_ranges() -> Vec<Cidr> {
        vec![Cidr::parse("173.245.48.0/20").unwrap()]
    }

    #[test]
    fn combined_basic() {
        let l = r#"203.0.113.9 - - [10/Oct/2026:01:02:03 +0000] "GET /wp-login.php HTTP/1.1" 200 1234 "-" "curl/8.0""#;
        let p = parse_line(LogFormat::Combined, l, &[]).unwrap();
        assert_eq!(p.client.to_string(), "203.0.113.9");
        assert_eq!(p.method, "GET");
        assert_eq!(p.path, "/wp-login.php");
        assert_eq!(p.status, 200);
        assert_eq!(p.user_agent, "curl/8.0");
    }

    #[test]
    fn sn_behind_cloudflare() {
        // peer is a CF address; client must come from CF-Connecting-IP.
        let l = r#"173.245.48.1 173.245.48.1 "198.51.100.7" "198.51.100.7, 173.245.48.1" [2026-10-10T01:02:03+00:00] "shop.example.com" "POST /wp-login.php HTTP/2.0" 403 0 0.012 "sqlmap/1.7""#;
        let p = parse_line(LogFormat::Sn, l, &cf_ranges()).unwrap();
        assert_eq!(p.peer.to_string(), "173.245.48.1");
        assert_eq!(p.client.to_string(), "198.51.100.7");
        assert_eq!(p.host, "shop.example.com");
        assert_eq!(p.status, 403);
        assert_eq!(p.request_time, Some(0.012));
        assert!(p.is_sensitive_post());
    }

    #[test]
    fn sn_direct_not_proxied() {
        let l = r#"203.0.113.50 203.0.113.50 "" "" [2026-10-10T01:02:03+00:00] "example.com" "GET / HTTP/1.1" 200 10 0.001 "Mozilla""#;
        let p = parse_line(LogFormat::Sn, l, &cf_ranges()).unwrap();
        assert_eq!(p.client.to_string(), "203.0.113.50");
    }

    #[test]
    fn json_line() {
        let l = r#"{"remote_addr":"198.51.100.7","host":"a.com","request":"GET /x HTTP/1.1","status":"404","http_user_agent":"nikto","request_time":"0.2"}"#;
        let p = parse_line(LogFormat::NginxJson, l, &[]).unwrap();
        assert_eq!(p.client.to_string(), "198.51.100.7");
        assert_eq!(p.status, 404);
        assert_eq!(p.request_time, Some(0.2));
    }

    #[test]
    fn garbage_is_none_not_panic() {
        assert!(parse_line(LogFormat::Combined, "", &[]).is_none());
        assert!(parse_line(LogFormat::Sn, "\"\"\"[", &[]).is_none());
        assert!(parse_line(LogFormat::NginxJson, "not json", &[]).is_none());
        // Unterminated quote must not panic.
        let _ = parse_line(LogFormat::Combined, "1.2.3.4 - - [x \"GET", &[]);
    }
}
