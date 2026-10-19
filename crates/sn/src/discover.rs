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
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
    "/var/log/nginx/domains/*.log",     // DirectAdmin, HestiaCP, VestaCP
    "/var/log/nginx/*access*.log",      // distro packages
    "/www/wwwlogs/*.log",               // aaPanel
    "/var/log/virtualmin/*_access_log", // Virtualmin
];
const APACHE: &[&str] = &[
    "/var/log/httpd/domains/*.log",     // DirectAdmin
    "/var/log/httpd/*access_log",       // RHEL family
    "/var/log/apache2/*access*.log",    // Debian family
    "/usr/local/apache/domlogs/*",      // cPanel
    "/www/wwwlogs/*.log",               // aaPanel
    "/var/log/virtualmin/*_access_log", // Virtualmin (~/logs links here)
    "/home/*/logs/*access*log",         // other panels (see TENANT_AREA)
];
const LITESPEED: &[&str] = &[
    "/var/log/openlitespeed/*access*.log", // OPanel: <domain>.access.log per website
    "/usr/local/lsws/logs/*access*.log",   // server-level / default vhost
    "/usr/local/apache/domlogs/*",         // cPanel + LiteSpeed
    "/var/log/httpd/domains/*.log", // DirectAdmin + (Open)LiteSpeed: one VPS had no log found
    "/var/log/httpd/*access*log",   // the same directory, files named *access*
    "/home/*/logs/*access*log",     // CyberPanel (see TENANT_AREA)
];

/// Directories the sites' owners control. Anyone with a site can create a file
/// called `x.access_log` in their own home, so a log there is followed only
/// file by file, each one checked (see [`tenant_log_ok`]).
const TENANT_AREA: &str = "/home/";

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

/// Web-server processes holding a socket that listens on :80 or :443 (the
/// master and its workers), with their pids. The name alone proves nothing, as
/// any user can start a process called nginx; holding that socket does.
fn web_listeners(conns: &[netstat::Conn]) -> Vec<(Listener, i32)> {
    let listening: HashSet<u64> = conns
        .iter()
        .filter(|c| c.state == netstat::ST_LISTEN && matches!(c.local_port, 80 | 443))
        .map(|c| c.inode)
        .filter(|&i| i != 0)
        .collect();
    if listening.is_empty() {
        return Vec::new();
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
            found.push((kind, pid));
        }
    }
    found
}

/// Which web server owns a listening socket on :80 or :443.
#[must_use]
pub fn detect_listener(conns: &[netstat::Conn]) -> Listener {
    let found: Vec<Listener> = web_listeners(conns).into_iter().map(|(k, _)| k).collect();
    classify(&found)
}

/// The users the web server runs as. Its access logs belong to root or to one
/// of them; a file owned by anyone else was not written by it.
#[must_use]
pub fn web_server_uids() -> Vec<u32> {
    let mut uids: Vec<u32> = web_listeners(&netstat::all())
        .into_iter()
        .filter_map(|(_, pid)| proc::uid(pid))
        .collect();
    uids.sort_unstable();
    uids.dedup();
    uids
}

/// A log under a site owner's home is followed only if nothing from the home
/// directory down is a symlink, it has no other hard link, and it passes the
/// check every log gets on open (regular file, owned by root or the web server,
/// not writable by others). What the site's owner can create there is theirs.
fn tenant_log_ok(area: &Path, file: &Path) -> bool {
    let Ok(rel) = file.strip_prefix(area) else {
        return false;
    };
    let mut at = area.to_path_buf();
    for part in rel.components() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if !m.file_type().is_symlink() => {}
            _ => return false,
        }
    }
    crate::watch::tail::open_log(file)
        .and_then(|f| f.metadata())
        .is_ok_and(|m| m.nlink() == 1)
}

/// What detection came up with.
pub struct Discovery {
    /// Patterns that match at least one access-log file right now.
    pub found: Vec<LogSource>,
    /// Every pattern that was tried, for the "nothing found" message.
    pub tried: Vec<String>,
    /// Patterns left out because another one names the same sites (only when
    /// the web server is unknown).
    pub dropped: Vec<String>,
    /// The patterns kept, one per set (see `found`).
    pub kept: Vec<String>,
}

/// How recently a set read last cycle must have been written to stay the one
/// read, when another set names the same sites.
const STICKY_SECS: u64 = 15 * 60;

/// Look for the listener's log locations. `root` is put in front of every
/// pattern: `""` in production, a temporary directory in tests. `prefer`: the
/// patterns read last cycle, kept while they are still written when another
/// set names the same sites.
#[must_use]
pub fn discover(listener: Listener, root: &str, prefer: &[String]) -> Discovery {
    // One set of sources per pattern that matched.
    let mut sets: Vec<(String, Vec<LogSource>)> = Vec::new();
    let mut tried = Vec::new();
    for g in candidate_globs(listener) {
        let pattern = format!("{root}{g}");
        tried.push(pattern.clone());
        // Every server above writes the Apache/nginx "combined" layout.
        let source = |glob: String| LogSource::new(glob, "combined".into());
        let mut set = Vec::new();
        if g.starts_with(TENANT_AREA) {
            // One source per checked file, never the pattern: a file created
            // there after this check is not followed until it passes it too.
            let area = format!("{root}{}", TENANT_AREA.trim_end_matches('/'));
            let area = Path::new(&area);
            for file in crate::watch::expand_glob(&pattern) {
                if let Some(path) = file.to_str()
                    && tenant_log_ok(area, &file)
                {
                    set.push(source(glob::Pattern::escape(path)));
                }
            }
        } else if !crate::watch::expand_glob(&pattern).is_empty() {
            set.push(source(pattern.clone()));
        }
        if !set.is_empty() {
            sets.push((pattern, set));
        }
    }
    // Not knowing which server is in front, both nginx's and Apache's logs may
    // be there, each request in both (and counted twice).
    let dropped = if listener == Listener::Unknown {
        one_set_per_site(&mut sets, prefer)
    } else {
        Vec::new()
    };
    Discovery {
        kept: sets.iter().map(|(p, _)| p.clone()).collect(),
        found: sets.into_iter().flat_map(|(_, s)| s).collect(),
        tried,
        dropped,
    }
}

/// Where two sets of logs name the same sites (the same file names: a server
/// in front and one behind it both logging each request), keep only one: the
/// one read last cycle (in `prefer`) while it is still written, else the one
/// written most recently. A choice that flipped between two busy sets would
/// start each newly chosen file at its end and read almost nothing. Returns
/// the patterns left out.
fn one_set_per_site(sets: &mut Vec<(String, Vec<LogSource>)>, prefer: &[String]) -> Vec<String> {
    let now = std::time::SystemTime::now();
    struct Seen {
        names: HashSet<std::ffi::OsString>,
        newest: Option<std::time::SystemTime>,
    }
    let seen = |set: &[LogSource]| {
        let mut s = Seen {
            names: HashSet::new(),
            newest: None,
        };
        for file in set
            .iter()
            .flat_map(|src| crate::watch::expand_glob(&src.glob))
        {
            let modified = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
            s.newest = s.newest.max(modified);
            if let Some(name) = file.file_name() {
                s.names.insert(name.to_os_string());
            }
        }
        s
    };
    // Read last cycle and written lately.
    let sticky = |pattern: &str, s: &Seen| {
        prefer.iter().any(|p| p == pattern)
            && s.newest.is_some_and(|t| {
                now.duration_since(t)
                    .ok()
                    .is_none_or(|age| age.as_secs() <= STICKY_SECS)
            })
    };
    let mut kept: Vec<((String, Vec<LogSource>), Seen)> = Vec::new();
    let mut dropped = Vec::new();
    for set in sets.drain(..) {
        let this = seen(&set.1);
        let clash: Vec<usize> = kept
            .iter()
            .enumerate()
            .filter(|(_, (_, k))| !k.names.is_disjoint(&this.names))
            .map(|(i, _)| i)
            .collect();
        let newest_kept = clash.iter().map(|&i| kept[i].1.newest).max().flatten();
        let this_sticky = sticky(&set.0, &this);
        let kept_sticky = clash.iter().any(|&i| sticky(&kept[i].0.0, &kept[i].1));
        let take = clash.is_empty()
            || (this_sticky && !kept_sticky)
            || (this_sticky == kept_sticky && this.newest > newest_kept);
        if take {
            for &i in clash.iter().rev() {
                dropped.push(kept.remove(i).0.0);
            }
            kept.push((set, this));
        } else {
            dropped.push(set.0);
        }
    }
    sets.extend(kept.into_iter().map(|(set, _)| set));
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(root: &std::path::Path, rel: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "x\n").unwrap();
        // As a web server leaves its logs, whatever the test's umask.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
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

        let nginx = discover(Listener::Nginx, root, &[]);
        assert_eq!(
            globs(&nginx),
            [format!("{root}/var/log/nginx/domains/*.log")]
        );
        let apache = discover(Listener::Apache, root, &[]);
        assert_eq!(
            globs(&apache),
            [format!("{root}/var/log/httpd/domains/*.log")]
        );
        // When the server cannot be identified (Varnish, HAProxy, Caddy in
        // front), the two sets name the same sites: only the one written most
        // recently is read, or every request would count twice.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let set_mtime = |rel: &str, t| {
            fs::OpenOptions::new()
                .append(true)
                .open(dir.path().join(rel))
                .unwrap()
                .set_modified(t)
                .unwrap();
        };
        set_mtime("var/log/httpd/domains/example.com.log", old);
        let unknown = discover(Listener::Unknown, root, &[]);
        assert_eq!(
            globs(&unknown),
            [format!("{root}/var/log/nginx/domains/*.log")]
        );
        assert_eq!(
            unknown.dropped,
            [format!("{root}/var/log/httpd/domains/*.log")]
        );
        // Apache's set is the live one.
        set_mtime(
            "var/log/nginx/domains/example.com.log",
            old - std::time::Duration::from_secs(60),
        );
        set_mtime(
            "var/log/httpd/domains/example.com.log",
            std::time::SystemTime::now(),
        );
        let unknown = discover(Listener::Unknown, root, &[]);
        assert_eq!(
            globs(&unknown),
            [format!("{root}/var/log/httpd/domains/*.log")]
        );
        // Sets naming different sites are both read.
        touch(dir.path(), "var/log/apache2/other.example_access.log");
        let unknown = discover(Listener::Unknown, root, &[]);
        assert_eq!(unknown.found.len(), 2, "{:?}", globs(&unknown));
        // A known front server never drops anything.
        assert!(discover(Listener::Nginx, root, &[]).dropped.is_empty());
    }

    #[test]
    fn the_set_read_last_cycle_stays_while_it_is_written() {
        // Both nginx's and Apache's logs are written all the time behind an
        // unrecognised front server; slow clients make either one the newer
        // from one cycle to the next. A flipping choice would start each newly
        // chosen file at its end and read almost nothing.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/nginx/domains/example.com.log");
        touch(dir.path(), "var/log/httpd/domains/example.com.log");
        let nginx = format!("{root}/var/log/nginx/domains/*.log");
        let httpd = format!("{root}/var/log/httpd/domains/*.log");
        let set_age = |rel: &str, secs: u64| {
            fs::OpenOptions::new()
                .append(true)
                .open(dir.path().join(rel))
                .unwrap()
                .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(secs))
                .unwrap();
        };
        set_age("var/log/nginx/domains/example.com.log", 60);
        set_age("var/log/httpd/domains/example.com.log", 5);
        let d = discover(Listener::Unknown, root, std::slice::from_ref(&nginx));
        assert_eq!(
            (d.kept.clone(), d.dropped),
            (vec![nginx.clone()], vec![httpd.clone()])
        );
        // With no earlier choice, the newest wins.
        assert_eq!(
            discover(Listener::Unknown, root, &[]).kept,
            std::slice::from_ref(&httpd)
        );
        // The set read last cycle stopped being written: the live one takes over.
        set_age("var/log/nginx/domains/example.com.log", STICKY_SECS + 60);
        let d = discover(Listener::Unknown, root, std::slice::from_ref(&nginx));
        assert_eq!(d.kept, std::slice::from_ref(&httpd));
        // Whichever of the two was read last.
        set_age("var/log/nginx/domains/example.com.log", 5);
        set_age("var/log/httpd/domains/example.com.log", 60);
        let d = discover(Listener::Unknown, root, std::slice::from_ref(&httpd));
        assert_eq!((d.kept, d.dropped), (vec![httpd], vec![nginx]));
    }

    #[test]
    fn error_logs_and_byte_counters_do_not_count_as_a_log_source() {
        // Only error/bytes/archive files present: nothing to follow.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/nginx/domains/example.com.error.log");
        touch(dir.path(), "var/log/nginx/domains/example.com.bytes");
        touch(dir.path(), "var/log/nginx/domains/example.com.log.gz");
        let d = discover(Listener::Nginx, root, &[]);
        assert!(d.found.is_empty());
        // ...and the message can say where it looked.
        assert!(
            d.tried
                .iter()
                .any(|t| t.ends_with("/var/log/nginx/domains/*.log"))
        );
    }

    #[test]
    fn directadmin_with_litespeed_logs_in_the_apache_place() {
        // A DirectAdmin VPS on LiteSpeed reported "no access log found": its
        // domain logs are DirectAdmin's own, the same place as under Apache.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/httpd/domains/example.vn.log");
        touch(dir.path(), "var/log/httpd/domains/example.vn.error.log");
        let d = discover(Listener::LiteSpeed, root, &[]);
        assert_eq!(globs(&d), [format!("{root}/var/log/httpd/domains/*.log")]);
        let files = crate::watch::expand_glob(&d.found[0].glob);
        assert_eq!(files.len(), 1, "the error log is not read: {files:?}");

        // The same directory with the log named after "access" instead.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/httpd/example.vn.access_log");
        touch(dir.path(), "var/log/httpd/example.vn.error_log");
        let d = discover(Listener::LiteSpeed, root, &[]);
        assert_eq!(globs(&d), [format!("{root}/var/log/httpd/*access*log")]);
        let files = crate::watch::expand_glob(&d.found[0].glob);
        assert_eq!(files.len(), 1, "{files:?}");
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

        let d = discover(Listener::LiteSpeed, root, &[]);
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
        assert!(!discover(Listener::Unknown, root, &[]).found.is_empty());
    }

    #[test]
    fn opanel_on_nginx_is_found_by_the_generic_nginx_pattern() {
        // OPanel's nginx mode writes /var/log/nginx/<domain>.access.log.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/nginx/example.com.access.log");
        touch(dir.path(), "var/log/nginx/example.com.error.log");
        let d = discover(Listener::Nginx, root, &[]);
        assert_eq!(d.found.len(), 1);
        assert_eq!(crate::watch::expand_glob(&d.found[0].glob).len(), 1);
    }

    #[test]
    fn logs_under_home_are_followed_file_by_file_and_only_if_trusted() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let at = |rel: &str| dir.path().join(rel);
        // CyberPanel: the web server writes /home/<site>/logs/<site>.access_log.
        touch(dir.path(), "home/example.com/logs/example.com.access_log");
        // What a site's owner could plant in their own home instead:
        // a file others may write,
        touch(dir.path(), "home/open.net/logs/open.net.access_log");
        fs::set_permissions(
            at("home/open.net/logs/open.net.access_log"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        // a symlink to some other log,
        touch(dir.path(), "var/log/other_access.log");
        fs::create_dir_all(at("home/link.org/logs")).unwrap();
        symlink(
            at("var/log/other_access.log"),
            at("home/link.org/logs/link.org.access_log"),
        )
        .unwrap();
        // a symlinked directory on the way,
        fs::create_dir_all(at("home/dirlink.io")).unwrap();
        symlink(at("var/log"), at("home/dirlink.io/logs")).unwrap();
        // and a hard link to a file they do not own.
        fs::create_dir_all(at("home/hard.dev/logs")).unwrap();
        fs::hard_link(
            at("var/log/other_access.log"),
            at("home/hard.dev/logs/hard.dev.access_log"),
        )
        .unwrap();

        let d = discover(Listener::LiteSpeed, root, &[]);
        assert_eq!(
            globs(&d),
            [format!(
                "{root}/home/example.com/logs/example.com.access_log"
            )]
        );
        assert!(
            d.tried
                .iter()
                .any(|t| t.ends_with("/home/*/logs/*access*log"))
        );
        // Apache looks there the same way (older layouts and other panels).
        assert_eq!(globs(&discover(Listener::Apache, root, &[])), globs(&d));

        // The source names that one file, so a file created there later is not
        // read before it has been checked.
        assert_eq!(crate::watch::expand_glob(&d.found[0].glob).len(), 1);
        touch(dir.path(), "home/example.com/logs/forged.access_log");
        assert_eq!(crate::watch::expand_glob(&d.found[0].glob).len(), 1);

        // Never by the pattern, whatever the server.
        for l in [Listener::Apache, Listener::LiteSpeed, Listener::Unknown] {
            assert!(
                candidate_globs(l)
                    .iter()
                    .filter(|g| g.contains("/home"))
                    .all(|g| g.starts_with(TENANT_AREA)),
                "{l:?}"
            );
        }
    }

    #[test]
    fn virtualmin_logs_are_read_where_the_server_writes_them() {
        use std::os::unix::fs::symlink;
        // Virtualmin: the server writes /var/log/virtualmin/<domain>_access_log
        // and the site's ~/logs/access_log is a symlink to it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let at = |rel: &str| dir.path().join(rel);
        touch(dir.path(), "var/log/virtualmin/example.com_access_log");
        touch(dir.path(), "var/log/virtualmin/example.com_error_log");
        fs::create_dir_all(at("home/example/logs")).unwrap();
        symlink(
            at("var/log/virtualmin/example.com_access_log"),
            at("home/example/logs/access_log"),
        )
        .unwrap();

        for l in [Listener::Apache, Listener::Nginx, Listener::Unknown] {
            let d = discover(l, root, &[]);
            // Once, from where the server writes it; not again by the symlink.
            assert_eq!(
                globs(&d),
                [format!("{root}/var/log/virtualmin/*_access_log")],
                "{l:?}"
            );
            let files = crate::watch::expand_glob(&d.found[0].glob);
            assert_eq!(files, [at("var/log/virtualmin/example.com_access_log")]);
        }
    }

    #[test]
    fn switching_web_server_moves_the_source_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        touch(dir.path(), "var/log/httpd/domains/example.com.log");
        assert_eq!(discover(Listener::Apache, root, &[]).found.len(), 1);
        assert!(discover(Listener::Nginx, root, &[]).found.is_empty());
        // The site moves to nginx: its logs appear and are picked up.
        touch(dir.path(), "var/log/nginx/domains/example.com.log");
        assert_eq!(discover(Listener::Nginx, root, &[]).found.len(), 1);
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
