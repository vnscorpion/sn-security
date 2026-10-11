//! Find the web server's access logs without any per-host setup.
//!
//! Hosting panels disagree about where logs live (DirectAdmin: nginx in
//! `/var/log/nginx/domains`, Apache in `/var/log/httpd/domains`; cPanel:
//! `/usr/local/apache/domlogs`; ...), and a server can be switched between web
//! servers after the agent was installed. So the agent works it out each cycle:
//! which web server answers on :80/:443, then which of that server's usual log
//! locations actually exist.
//!
//! Only the *outermost* server's logs are read. With nginx in front of Apache
//! both log every request, so reading both would count every visitor twice, and
//! Apache usually only sees the proxy's `127.0.0.1` anyway.

use std::collections::HashSet;

use crate::config::LogSource;
use crate::sys::{netstat, proc};

/// The web server that answers on :80/:443.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    Nginx,
    Apache,
    LiteSpeed,
    /// Could not tell (nothing recognised is listening, or `/proc` is hidden).
    Unknown,
}

impl Listener {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Listener::Nginx => "nginx",
            Listener::Apache => "apache",
            Listener::LiteSpeed => "litespeed",
            Listener::Unknown => "unknown",
        }
    }
}

// Usual access-log locations per server. A pattern only counts if it matches at
// least one real access-log file (error logs and archives are filtered out).
const NGINX: &[&str] = &[
    "/var/log/nginx/domains/*.log", // DirectAdmin, HestiaCP, VestaCP
    "/var/log/nginx/*access*.log",  // distro packages
    "/www/wwwlogs/*.log",           // aaPanel
];
const APACHE: &[&str] = &[
    "/var/log/httpd/domains/*.log",  // DirectAdmin
    "/var/log/httpd/*access_log",    // RHEL family
    "/var/log/apache2/*access*.log", // Debian family
    "/usr/local/apache/domlogs/*",   // cPanel
    "/www/wwwlogs/*.log",            // aaPanel
    "/home/*/logs/*access*log",      // other panels
];
const LITESPEED: &[&str] = &[
    "/var/log/openlitespeed/*access*.log", // OPanel: <domain>.access.log per website
    "/usr/local/lsws/logs/*access*.log",   // server-level / default vhost
    "/usr/local/apache/domlogs/*",         // cPanel + LiteSpeed
    "/home/*/logs/*access*log",            // CyberPanel
];

/// The patterns to try for a given server. When the server is unknown, try
/// everything: reading too much beats reading nothing.
#[must_use]
pub fn candidate_globs(listener: Listener) -> Vec<&'static str> {
    match listener {
        Listener::Nginx => NGINX.to_vec(),
        Listener::Apache => APACHE.to_vec(),
        Listener::LiteSpeed => LITESPEED.to_vec(),
        Listener::Unknown => {
            let mut all: Vec<&'static str> = Vec::new();
            for g in NGINX.iter().chain(APACHE).chain(LITESPEED) {
                if !all.contains(g) {
                    all.push(*g);
                }
            }
            all
        }
    }
}

/// Map a process name (`/proc/<pid>/stat` comm) to a web server, if it is one.
fn web_kind(comm: &str) -> Option<Listener> {
    match comm {
        "nginx" => Some(Listener::Nginx),
        "httpd" | "apache2" => Some(Listener::Apache),
        "lshttpd" | "litespeed" | "openlitespeed" | "lsws" => Some(Listener::LiteSpeed),
        _ => None,
    }
}

/// Pick the outermost server from the web-server processes found listening.
/// nginx and LiteSpeed are normally the front end when present; Apache is the
/// front end only when it is alone.
#[must_use]
pub fn classify(found: &[Listener]) -> Listener {
    for preferred in [Listener::Nginx, Listener::LiteSpeed, Listener::Apache] {
        if found.contains(&preferred) {
            return preferred;
        }
    }
    Listener::Unknown
}

/// Which web server owns a listening socket on :80 or :443.
#[must_use]
pub fn detect_listener(conns: &[netstat::Conn]) -> Listener {
    let listening: HashSet<u64> = conns
        .iter()
        .filter(|c| c.state == netstat::ST_LISTEN && matches!(c.local_port, 80 | 443))
        .map(|c| c.inode)
        .filter(|&i| i != 0)
        .collect();
    if listening.is_empty() {
        return Listener::Unknown;
    }
    let mut found = Vec::new();
    for pid in proc::list_pids() {
        // Cheap name check first; only web-server processes get their fds read.
        let Some(kind) = proc::read_stat(pid).and_then(|s| web_kind(&s.comm)) else {
            continue;
        };
        if proc::socket_inodes(pid)
            .iter()
            .any(|ino| listening.contains(ino))
        {
            found.push(kind);
        }
    }
    classify(&found)
}

/// What detection came up with.
pub struct Discovery {
    /// Patterns that match at least one access-log file right now.
    pub found: Vec<LogSource>,
    /// Every pattern that was tried, for the "nothing found" message.
    pub tried: Vec<String>,
}

/// Look for the listener's log locations. `root` is put in front of every
/// pattern: `""` in production, a temporary directory in tests.
#[must_use]
pub fn discover(listener: Listener, root: &str) -> Discovery {
    let mut found = Vec::new();
    let mut tried = Vec::new();
    for g in candidate_globs(listener) {
        let pattern = format!("{root}{g}");
        tried.push(pattern.clone());
        if !crate::watch::expand_glob(&pattern).is_empty() {
            found.push(LogSource {
                glob: pattern,
                // Every server above writes the Apache/nginx "combined" layout.
                format: "combined".into(),
            });
        }
    }
    Discovery { found, tried }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(root: &std::path::Path, rel: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "x\n").unwrap();
    }

    fn globs(d: &Discovery) -> Vec<String> {
        d.found.iter().map(|s| s.glob.clone()).collect()
    }

    #[test]
    fn web_server_names_are_recognised() {
        assert_eq!(web_kind("nginx"), Some(Listener::Nginx));
        assert_eq!(web_kind("httpd"), Some(Listener::Apache));
        assert_eq!(web_kind("apache2"), Some(Listener::Apache));
        assert_eq!(web_kind("openlitespeed"), Some(Listener::LiteSpeed));
        // php-fpm and friends are not the listener.
        assert_eq!(web_kind("php-fpm"), None);
        assert_eq!(web_kind("sshd"), None);
    }

    #[test]
    fn the_outermost_server_wins() {
        use Listener::*;
        assert_eq!(classify(&[]), Unknown);
        assert_eq!(classify(&[Apache]), Apache);
        assert_eq!(classify(&[Nginx]), Nginx);
        // nginx in front of Apache (DirectAdmin nginx_apache): nginx.
        assert_eq!(classify(&[Apache, Nginx]), Nginx);
        assert_eq!(classify(&[Apache, LiteSpeed]), LiteSpeed);
    }

    #[test]
    fn nginx_never_reads_apache_logs_and_vice_versa() {
        // A DirectAdmin box with BOTH sets of logs on disk (nginx in front of
        // Apache): reading both would count every visitor twice.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/nginx/domains/example.com.log");
        touch(dir.path(), "var/log/httpd/domains/example.com.log");

        let nginx = discover(Listener::Nginx, root);
        assert_eq!(
            globs(&nginx),
            [format!("{root}/var/log/nginx/domains/*.log")]
        );
        let apache = discover(Listener::Apache, root);
        assert_eq!(
            globs(&apache),
            [format!("{root}/var/log/httpd/domains/*.log")]
        );
        // When the server cannot be identified, read what exists.
        let unknown = discover(Listener::Unknown, root);
        assert_eq!(unknown.found.len(), 2);
    }

    #[test]
    fn error_logs_and_byte_counters_do_not_count_as_a_log_source() {
        // Only error/bytes/archive files present: nothing to follow.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/nginx/domains/example.com.error.log");
        touch(dir.path(), "var/log/nginx/domains/example.com.bytes");
        touch(dir.path(), "var/log/nginx/domains/example.com.log.gz");
        let d = discover(Listener::Nginx, root);
        assert!(d.found.is_empty());
        // ...and the message can say where it looked.
        assert!(
            d.tried
                .iter()
                .any(|t| t.ends_with("/var/log/nginx/domains/*.log"))
        );
    }

    #[test]
    fn opanel_openlitespeed_logs_are_found_and_only_access_logs_are_read() {
        // OPanel on OpenLiteSpeed: one <domain>.access.log per website, next to
        // its error log, the rolled copies and the server-wide stderr.log. The
        // per-site PHP error log lives elsewhere (/var/log/opanel-php).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/openlitespeed/example.com.access.log");
        touch(
            dir.path(),
            "var/log/openlitespeed/shop.example.net.access.log",
        );
        touch(dir.path(), "var/log/openlitespeed/example.com.error.log");
        touch(
            dir.path(),
            "var/log/openlitespeed/example.com.access.log.2026_10_11",
        );
        touch(dir.path(), "usr/local/lsws/logs/stderr.log");
        touch(dir.path(), "var/log/opanel-php/example.com/php_error.log");

        let d = discover(Listener::LiteSpeed, root);
        assert_eq!(
            globs(&d),
            [format!("{root}/var/log/openlitespeed/*access*.log")]
        );
        // Exactly the two access logs: not the error log, the rolled copy or stderr.
        let files = crate::watch::expand_glob(&d.found[0].glob);
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(
            files
                .iter()
                .all(|f| f.to_string_lossy().ends_with(".access.log"))
        );
        // Still found when the server could not be identified.
        assert!(!discover(Listener::Unknown, root).found.is_empty());
    }

    #[test]
    fn opanel_on_nginx_is_found_by_the_generic_nginx_pattern() {
        // OPanel's nginx mode writes /var/log/nginx/<domain>.access.log.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/nginx/example.com.access.log");
        touch(dir.path(), "var/log/nginx/example.com.error.log");
        let d = discover(Listener::Nginx, root);
        assert_eq!(d.found.len(), 1);
        assert_eq!(crate::watch::expand_glob(&d.found[0].glob).len(), 1);
    }

    #[test]
    fn switching_web_server_moves_the_source_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/httpd/domains/example.com.log");
        assert_eq!(discover(Listener::Apache, root).found.len(), 1);
        assert!(discover(Listener::Nginx, root).found.is_empty());
        // The site moves to nginx: its logs appear and are picked up.
        touch(dir.path(), "var/log/nginx/domains/example.com.log");
        assert_eq!(discover(Listener::Nginx, root).found.len(), 1);
    }

    #[test]
    fn unknown_tries_every_location_once() {
        let all = candidate_globs(Listener::Unknown);
        let mut unique = all.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(all.len(), unique.len(), "no pattern listed twice");
        assert!(all.contains(&"/var/log/nginx/domains/*.log"));
        assert!(all.contains(&"/var/log/httpd/domains/*.log"));
    }
}
