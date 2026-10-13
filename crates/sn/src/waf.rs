//! The web server's ModSecurity, driven by the hub.
//!
//! The hub sends rules as data (`DesiredBody::waf`); they become one file of
//! ours, `zz-sn-secure.conf`, in the directory the server's ModSecurity
//! configuration already includes (`/etc/modsecurity.d/*.conf` on DirectAdmin,
//! for Apache, nginx, LiteSpeed and OpenLiteSpeed alike). Nothing else in the
//! web server's configuration is edited, and a file of that name that lacks
//! our marker is left alone. On DirectAdmin a copy also goes to CustomBuild's
//! `custom/modsecurity/conf`, which `da build modsecurity_rules` copies back
//! after it empties `/etc/modsecurity.d`; and every watch cycle checks the file
//! is still in place.
//!
//! Writing the file, testing the configuration and reloading the server happen
//! in a transient unit (`sn waf-apply`, started with `systemd-run`): the watch
//! cycle's sandbox cannot write to /etc. A failed test, a failed reload, a
//! server that stops listening, or (LiteSpeed, which has no test) an error
//! about our file in its log after the reload puts the previous file back.
//! The watch cycle reads the outcome, and the logs for matches of our rules,
//! and reports both to the hub.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snsec_common::schema::WafStatus;
use snsec_common::waf::{FILE_MARKER, MANAGED_ID_MAX, MANAGED_ID_MIN, WafRule, render_file};

use crate::state::{Offset, State};
use crate::util;
use crate::waf_conf::{self, Tally};

/// Sorts after the CRS files (`REQUEST-*`), and does not end in `.conf.main`.
pub const FILE_NAME: &str = "zz-sn-secure.conf";
const DA_CUSTOMBUILD: &str = "/usr/local/directadmin/custombuild";
const DA_OPTIONS: &str = "/usr/local/directadmin/custombuild/options.conf";
/// CustomBuild copies this directory into `/etc/modsecurity.d` whenever it
/// rebuilds the rules.
const DA_CUSTOM_DIR: &str = "/usr/local/directadmin/custombuild/custom/modsecurity/conf";
/// DirectAdmin's own ModSecurity settings: `SecRuleEngine On|Off` and
/// `SecRuleRemoveById` lines, server-wide and per site (the panel's WAF page).
const DA_GLOBAL_RULES: &str = "/usr/local/directadmin/data/admin/modsecurity_rules";
const DA_SITE_RULES: &[&str] = &[
    "/usr/local/directadmin/data/users/*/domains/*.modsecurity_rules",
    "/usr/local/directadmin/data/users/*/domains/*.subdomains_modsecurity_rules/*.modsecurity_rules",
];
/// Rules waiting for the apply unit (written by the watch cycle).
const RULES_FILE: &str = "waf-rules.json";
/// Outcome of the last apply (written by the apply unit).
const APPLIED_FILE: &str = "waf.json";
/// Log offsets and matches not yet reported (written by the watch cycle).
const LOCAL_FILE: &str = "waf-local.json";
/// The hash recorded when there should be no file.
const NO_FILE: &str = "none";
/// A configuration that failed is tried again after this long.
const RETRY_SECS: i64 = 3600;
/// The apply unit starts at most this often for the same rules, so a panel
/// rebuild that keeps deleting the file cannot make us reload every cycle.
const RESTART_SECS: i64 = 15 * 60;
const TEST_TIMEOUT: Duration = Duration::from_secs(60);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(90);
/// How long the server may take to listen again after a reload, and how long
/// LiteSpeed gets to log a problem with our file.
const LISTEN_WAIT: Duration = Duration::from_secs(15);
const SETTLE: Duration = Duration::from_secs(5);
const OUTPUT_CAP: u64 = 16 * 1024;
const ERROR_MAX: usize = 600;
/// Log reading bounds, per cycle.
const LOG_FILES_MAX: usize = 2000;
const READ_PER_FILE: u64 = 4 << 20;
const READ_TOTAL: u64 = 32 << 20;
/// Rule files scanned for ids already taken.
const SCAN_FILES_MAX: usize = 400;
const SCAN_BYTES_MAX: u64 = 16 << 20;
/// Site settings read for the notes.
const SITES_MAX: usize = 5000;

/// Where matches of our rules are written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogKind {
    /// Error-log lines with `[id "N"]` (Apache, nginx, LiteSpeed).
    #[default]
    ErrorLog,
    /// JSON audit records (OpenLiteSpeed, which logs matches to its error log
    /// only at INFO level).
    Audit,
}

/// Where ModSecurity lives on this VPS and how to drive the web server.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// `apache`, `litespeed`, `openlitespeed`, `nginx`, or empty.
    pub server: String,
    /// `on`, `detection_only`, `off`, `missing` or `unknown`.
    pub engine: String,
    /// Our rules file, in a directory the ModSecurity configuration includes.
    pub live: Option<PathBuf>,
    /// DirectAdmin: the copy CustomBuild puts back after a rebuild.
    pub persist: Option<PathBuf>,
    /// Configuration test (`httpd -t`); `None` when the server has none.
    pub test: Option<Vec<String>>,
    pub reload: Option<Vec<String>>,
    /// The server's own error log, checked after a reload (LiteSpeed).
    pub server_log: Option<PathBuf>,
    /// Logs (globs) where matches are written, and their kind.
    pub logs: Vec<String>,
    pub log_kind: LogKind,
    /// Ids in our range that other rule files already use.
    pub taken: HashSet<u32>,
    /// Why `live` is `None`, for the hub.
    pub why_none: String,
    /// For the admin (sites with the engine off, exclusions of our rules).
    pub notes: Vec<String>,
}

fn da_options() -> HashMap<String, String> {
    fs::read_to_string(DA_OPTIONS)
        .map(|t| {
            t.lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// The web server that runs ModSecurity: DirectAdmin's own setting when there
/// is one (with `nginx_apache` it is nginx, the front end), otherwise the
/// process listening on :80/:443.
fn server_kind(opts: &HashMap<String, String>) -> String {
    if let Some(w) = opts.get("webserver") {
        match w.as_str() {
            "apache" => return "apache".into(),
            "nginx" | "nginx_apache" => return "nginx".into(),
            "litespeed" => return "litespeed".into(),
            "openlitespeed" => return "openlitespeed".into(),
            _ => {}
        }
    }
    match crate::discover::detect_listener(&crate::sys::netstat::all()) {
        crate::discover::Listener::Apache => "apache".into(),
        crate::discover::Listener::Nginx => "nginx".into(),
        crate::discover::Listener::LiteSpeed => {
            if Path::new("/usr/local/lsws/bin/openlitespeed").exists() {
                "openlitespeed".into()
            } else {
                "litespeed".into()
            }
        }
        crate::discover::Listener::Unknown => String::new(),
    }
}

/// ModSecurity's configuration files, the generated "enable" file first; the
/// files they name are followed one level.
fn conf_candidates(server: &str) -> &'static [&'static str] {
    match server {
        // LiteSpeed Enterprise reads Apache's configuration.
        "apache" | "litespeed" => &[
            "/etc/httpd/conf/extra/httpd-modsecurity-enable.conf",
            "/etc/httpd/conf/extra/httpd-modsecurity.conf",
            "/etc/httpd/conf.d/mod_security.conf",
            "/etc/apache2/mods-enabled/security2.conf",
            "/etc/modsecurity/modsecurity.conf",
        ],
        "nginx" => &[
            "/etc/nginx/nginx-modsecurity-enable.conf",
            "/etc/nginx/nginx-modsecurity.conf",
            "/etc/nginx/modsec/main.conf",
        ],
        "openlitespeed" => &[
            "/etc/openlitespeed/httpd-modsecurity-enable.conf",
            "/etc/openlitespeed/httpd-modsecurity.conf",
            "/usr/local/lsws/conf/httpd-modsecurity.conf",
        ],
        _ => &[],
    }
}

fn first_file(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find(|p| Path::new(p).is_file())
        .map(|p| (*p).to_string())
}

/// `systemctl reload <unit>` for the first of these units that is installed.
fn reload_unit(units: &[&str]) -> Option<Vec<String>> {
    let systemctl = util::find_bin("systemctl")?;
    let unit = units.iter().find(|u| {
        [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ]
        .iter()
        .any(|d| Path::new(d).join(format!("{u}.service")).exists())
    })?;
    Some(vec![
        systemctl.to_string_lossy().into_owned(),
        "reload".into(),
        (*unit).to_string(),
    ])
}

/// Test, reload, server log, match logs.
type Commands = (
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<PathBuf>,
    Vec<String>,
    LogKind,
);

fn commands(server: &str) -> Commands {
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    let lswsctrl =
        || first_file(&["/usr/local/lsws/bin/lswsctrl"]).map(|b| vec![b, "restart".into()]);
    match server {
        "apache" => (
            first_file(&[
                "/usr/sbin/httpd",
                "/usr/sbin/apache2ctl",
                "/usr/sbin/apachectl",
            ])
            .map(|b| vec![b, "-t".into()]),
            reload_unit(&["httpd", "apache2"]),
            None,
            v(&[
                "/var/log/httpd/error_log",
                "/var/log/httpd/domains/*.error.log",
                "/var/log/apache2/error.log",
            ]),
            LogKind::ErrorLog,
        ),
        "nginx" => {
            let test = first_file(&["/usr/sbin/nginx", "/usr/local/sbin/nginx"]).map(|b| {
                let mut t = vec![b, "-t".into()];
                if Path::new("/etc/nginx/nginx.conf").is_file() {
                    t.extend(["-c".into(), "/etc/nginx/nginx.conf".into()]);
                }
                t
            });
            (
                test,
                reload_unit(&["nginx"]),
                None,
                v(&[
                    "/var/log/nginx/error.log",
                    "/var/log/nginx/domains/*.error.log",
                ]),
                LogKind::ErrorLog,
            )
        }
        // No configuration test exists for LiteSpeed Enterprise (`lshttpd -t`
        // checks the licence): its log is read after the reload instead.
        "litespeed" => (
            None,
            reload_unit(&["litespeed", "lsws"]).or_else(lswsctrl),
            Some(PathBuf::from("/usr/local/lsws/logs/error.log")),
            v(&[
                "/usr/local/lsws/logs/error.log",
                "/var/log/httpd/domains/*.error.log",
            ]),
            LogKind::ErrorLog,
        ),
        "openlitespeed" => (
            first_file(&["/usr/local/lsws/bin/openlitespeed"]).map(|b| vec![b, "-t".into()]),
            reload_unit(&["openlitespeed", "lsws"]).or_else(lswsctrl),
            Some(PathBuf::from("/usr/local/lsws/logs/error.log")),
            v(&[
                "/var/log/openlitespeed/modsec_audit.log",
                "/var/log/httpd/modsec_audit.log",
                "/usr/local/lsws/logs/auditmodsec.log",
            ]),
            LogKind::Audit,
        ),
        _ => (None, None, None, Vec::new(), LogKind::ErrorLog),
    }
}

/// Ids in our range already used by the other rule files of a directory.
fn taken_ids(dir: &Path) -> HashSet<u32> {
    let mut out = HashSet::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    let mut budget = SCAN_BYTES_MAX;
    for e in entries.filter_map(Result::ok).take(SCAN_FILES_MAX) {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name == FILE_NAME || !(name.ends_with(".conf") || name.ends_with(".conf.main")) {
            continue;
        }
        let Ok(f) = fs::File::open(e.path()) else {
            continue;
        };
        let mut text = String::new();
        if f.take(budget).read_to_string(&mut text).is_err() {
            continue;
        }
        budget = budget.saturating_sub(text.len() as u64);
        out.extend(waf_conf::ids_in(&text, MANAGED_ID_MIN, MANAGED_ID_MAX));
        if budget == 0 {
            break;
        }
    }
    out
}

/// DirectAdmin's WAF settings: the server-wide engine state, and notes about
/// the sites that turned it off or excluded our rules.
fn da_sites(notes: &mut Vec<String>) -> Option<String> {
    let global = fs::read_to_string(DA_GLOBAL_RULES).ok();
    let engine = global
        .as_deref()
        .and_then(|t| waf_conf::scan_conf(t).engine);
    if global
        .as_deref()
        .is_some_and(|t| waf_conf::removes_range(t, MANAGED_ID_MIN, MANAGED_ID_MAX))
    {
        notes.push(
            "Cài đặt ModSecurity chung của DirectAdmin loại trừ luật của SN Secure (SecRuleRemoveById): luật không chạy ở đâu cả."
                .into(),
        );
    }
    let mut off = Vec::new();
    let mut excluded = Vec::new();
    let mut seen = 0usize;
    for g in DA_SITE_RULES {
        let Ok(paths) = glob::glob(g) else { continue };
        for p in paths.filter_map(Result::ok) {
            seen += 1;
            if seen > SITES_MAX {
                break;
            }
            let Ok(t) = fs::read_to_string(&p) else {
                continue;
            };
            let site = p
                .file_name()
                .map(|n| {
                    n.to_string_lossy()
                        .trim_end_matches(".modsecurity_rules")
                        .to_string()
                })
                .unwrap_or_default();
            if waf_conf::scan_conf(&t).engine.as_deref() == Some("off") {
                off.push(site);
            } else if waf_conf::removes_range(&t, MANAGED_ID_MIN, MANAGED_ID_MAX) {
                excluded.push(site);
            }
        }
    }
    let list = |v: &[String]| {
        let mut s = v.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
        if v.len() > 5 {
            s.push_str(", …");
        }
        s
    };
    if !off.is_empty() {
        notes.push(format!(
            "{} tên miền tắt ModSecurity trong DirectAdmin, luật không chạy ở đó: {}",
            off.len(),
            list(&off)
        ));
    }
    if !excluded.is_empty() {
        notes.push(format!(
            "{} tên miền loại trừ luật của SN Secure (SecRuleRemoveById): {}",
            excluded.len(),
            list(&excluded)
        ));
    }
    engine
}

/// Find ModSecurity on this VPS. Reads files only, so it runs in the watch
/// cycle's sandbox as well as in the apply unit.
#[must_use]
pub fn detect() -> Layout {
    let opts = da_options();
    let server = server_kind(&opts);
    let (test, reload, server_log, logs, log_kind) = commands(&server);
    let mut out = Layout {
        server: server.clone(),
        test,
        reload,
        server_log,
        logs,
        log_kind,
        ..Layout::default()
    };
    if server.is_empty() {
        out.engine = "unknown".into();
        out.why_none = "không nhận ra máy chủ web".into();
        return out;
    }
    let directadmin = !opts.is_empty();
    if directadmin && opts.get("modsecurity").is_none_or(|v| v != "yes") {
        out.engine = "missing".into();
        out.why_none =
            "DirectAdmin chưa bật ModSecurity (da build set modsecurity yes; da build modsecurity)"
                .into();
        return out;
    }
    let mut scans = Vec::new();
    for c in conf_candidates(&server) {
        if let Ok(t) = fs::read_to_string(c) {
            scans.push(waf_conf::scan_conf(&t));
        }
    }
    if scans.is_empty() {
        out.engine = "missing".into();
        out.why_none = "không thấy cấu hình ModSecurity của máy chủ web".into();
        return out;
    }
    let named: Vec<String> = scans
        .iter()
        .flat_map(|s| s.files.iter().cloned())
        .take(20)
        .collect();
    for f in named {
        if let Ok(t) = fs::read_to_string(&f) {
            scans.push(waf_conf::scan_conf(&t));
        }
    }
    // Server-wide setting first; DirectAdmin's own settings, applied per site,
    // win. Not set anywhere: ModSecurity's default, Off.
    let mut engine = scans.iter().find_map(|s| s.engine.clone());
    if directadmin {
        if let Some(e) = da_sites(&mut out.notes) {
            engine = Some(e);
        }
        engine.get_or_insert_with(|| "off".into());
    }
    out.engine = waf_conf::engine_label(engine.as_deref()).into();
    let dir = scans
        .iter()
        .flat_map(|s| s.include_dirs.iter())
        .find(|d| safe_dir(Path::new(d)));
    match dir {
        Some(d) => {
            out.live = Some(Path::new(d).join(FILE_NAME));
            out.taken = taken_ids(Path::new(d));
            if d.trim_end_matches('/') == "/etc/modsecurity.d" && Path::new(DA_CUSTOMBUILD).is_dir()
            {
                out.persist = Some(Path::new(DA_CUSTOM_DIR).join(FILE_NAME));
            }
        }
        None => {
            out.why_none =
                "cấu hình ModSecurity không nạp thư mục luật nào dạng <thư mục>/*.conf".into();
        }
    }
    out
}

/// A directory we may put a file into: a real directory (not a link), owned by
/// root and writable by nobody else.
fn safe_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The outcome of the last apply, written by the apply unit.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Applied {
    /// Hash of the file put in place (`NO_FILE`: no file).
    hash: String,
    applied: u32,
    blocking: u32,
    refused: Vec<u32>,
    applied_at: i64,
    rules_file: String,
    error: String,
    error_at: i64,
    /// What failed, so the same thing is not retried every cycle.
    failed_hash: String,
    failed_at: i64,
}

/// The watch cycle's own bookkeeping.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Local {
    offsets: HashMap<String, Offset>,
    tally: Tally,
    started_hash: String,
    started_at: i64,
}

fn load<T: for<'de> Deserialize<'de> + Default>(state: &State, name: &str) -> T {
    fs::read(state.dir.join(name))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save<T: Serialize>(state: &State, name: &str, v: &T) -> Result<()> {
    state.save_file(name, &serde_json::to_vec(v)?)
}

/// What the file should hold.
struct Wanted {
    /// `None`: no file (no rule left to write).
    text: Option<String>,
    hash: String,
    refused: Vec<u32>,
    applied: u32,
    blocking: u32,
}

/// The file for these rules, leaving out ids another rule file already uses
/// (a duplicate id is a fatal error in ModSecurity 2 and 3).
fn wanted(rules: &[WafRule], taken: &HashSet<u32>) -> Wanted {
    let (usable, clashing): (Vec<WafRule>, Vec<WafRule>) =
        rules.iter().cloned().partition(|r| !taken.contains(&r.id));
    let (text, skipped) = render_file(&usable);
    let skipped_ids: HashSet<u32> = skipped.iter().map(|r| r.id).collect();
    let mut refused: Vec<u32> = clashing.iter().map(|r| r.id).collect();
    refused.extend(skipped.iter().map(|r| r.id));
    refused.sort_unstable();
    refused.dedup();
    let kept: Vec<&WafRule> = usable
        .iter()
        .filter(|r| !skipped_ids.contains(&r.id))
        .collect();
    let applied = u32::try_from(kept.len()).unwrap_or(u32::MAX);
    let blocking = u32::try_from(kept.iter().filter(|r| r.block).count()).unwrap_or(u32::MAX);
    if kept.is_empty() {
        Wanted {
            text: None,
            hash: NO_FILE.into(),
            refused,
            applied: 0,
            blocking: 0,
        }
    } else {
        Wanted {
            hash: sha(text.as_bytes()),
            text: Some(text),
            refused,
            applied,
            blocking,
        }
    }
}

/// The hash of what is in place now: the file's, `NO_FILE`, or `None` when
/// the file there is not ours.
fn in_place(live: &Path) -> Option<String> {
    match fs::read(live) {
        Ok(b) if b.starts_with(FILE_MARKER.as_bytes()) => Some(sha(&b)),
        Ok(_) => None,
        Err(_) => Some(NO_FILE.into()),
    }
}

/// The hub's rules, from a desired state (watch cycle). They are put in place
/// by [`ensure`].
pub fn set_rules(state: &State, rules: &[WafRule]) {
    let unchanged = fs::read(state.dir.join(RULES_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<WafRule>>(&b).ok())
        .is_some_and(|old| old == rules);
    if unchanged {
        return;
    }
    let written = serde_json::to_vec(rules)
        .map_err(anyhow::Error::from)
        .and_then(|b| state.save_file(RULES_FILE, &b));
    if let Err(e) = written {
        eprintln!("waf: could not keep the hub's rules: {e:#}");
    }
}

fn hub_rules(state: &State) -> Option<Vec<WafRule>> {
    let bytes = fs::read(state.dir.join(RULES_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Watch cycle (sandboxed), every cycle: start the apply unit when the hub's
/// rules differ from what is in place (new rules, or a panel rebuild that
/// removed the file). Bounded by `RETRY_SECS` / `RESTART_SECS`.
pub fn ensure(state: &State) {
    // The hub never sent rules: the WAF is not ours to manage.
    let Some(rules) = hub_rules(state) else {
        return;
    };
    let now = util::now_secs();
    let layout = detect();
    let want = wanted(&rules, &layout.taken).hash;
    let applied: Applied = load(state, APPLIED_FILE);
    let mut local: Local = load(state, LOCAL_FILE);
    let have = layout.live.as_deref().and_then(in_place);
    if have.as_deref() == Some(want.as_str()) && applied.hash == want && applied.error.is_empty() {
        return;
    }
    if layout.live.is_none() && want == NO_FILE {
        return;
    }
    if applied.failed_hash == want && now - applied.failed_at < RETRY_SECS {
        return;
    }
    if local.started_hash == want && now - local.started_at < RESTART_SECS {
        return;
    }
    match Command::new("systemd-run").args(apply_unit_args()).status() {
        Ok(s) if s.success() => {
            eprintln!("waf: applying {} rule(s) (unit sn-waf-apply)", rules.len());
            local.started_hash = want;
            local.started_at = now;
            if let Err(e) = save(state, LOCAL_FILE, &local) {
                eprintln!("waf: {e:#}");
            }
        }
        Ok(s) => eprintln!("waf: could not start sn-waf-apply ({s}); one may be running"),
        Err(e) => eprintln!("waf: could not run systemd-run: {e}"),
    }
}

/// `systemd-run` arguments for `sn waf-apply`: root outside the watch sandbox
/// (it writes into the web server's configuration and reloads it), one at a
/// time, bounded in time.
fn apply_unit_args() -> Vec<String> {
    [
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=sn-waf-apply",
        "--description=SN Secure WAF rules (from the hub)",
        "--property=RuntimeMaxSec=5min",
        "--property=UMask=0022",
        "/usr/local/bin/sn",
        "waf-apply",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Run a command for at most `timeout`: its exit code (`None`: it could not
/// start, was killed or ran over) and what it printed.
fn run(argv: &[String], timeout: Duration) -> (Option<i32>, String) {
    let Some((prog, args)) = argv.split_first() else {
        return (None, String::new());
    };
    let child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return (None, format!("{prog}: {e}")),
    };
    fn pipe<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(r) = r {
                let _ = r.take(OUTPUT_CAP).read_to_end(&mut buf);
            }
            buf
        })
    }
    let out = pipe(child.stdout.take());
    let err = pipe(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let mut text = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&out.join().unwrap_or_default()));
    match status {
        Some(s) => (s.code(), text),
        None => (
            None,
            format!("{prog}: quá {} giây\n{text}", timeout.as_secs()),
        ),
    }
}

/// Write a configuration file in place: a temporary file in the same directory
/// whose name does not match `*.conf`, readable by the web server, then a
/// rename. Never follows a link.
fn write_conf(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("no parent")?;
    if !safe_dir(dir) {
        anyhow::bail!("{} is not a root-owned directory", dir.display());
    }
    let tmp = dir.join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let written = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.with_context(|| format!("writing {}", path.display()))?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Put back what was there before: the old file, or no file.
fn restore(path: &Path, old: Option<&[u8]>) {
    let r = match old {
        Some(b) => write_conf(path, b),
        None => remove_if_exists(path),
    };
    if let Err(e) = r {
        eprintln!("waf: could not put {} back: {e:#}", path.display());
    }
}

/// Is the web server listening on :80/:443?
fn serving() -> bool {
    crate::discover::detect_listener(&crate::sys::netstat::all())
        != crate::discover::Listener::Unknown
}

fn wait_serving() -> bool {
    let deadline = Instant::now() + LISTEN_WAIT;
    loop {
        if serving() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// What the server log gained since `from` (at most 1 MiB).
fn log_since(path: &Path, from: u64) -> String {
    let Ok(mut f) = fs::File::open(path) else {
        return String::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = if len < from { 0 } else { from };
    if f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = f.take(1 << 20).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn fail(state: &State, out: &mut Applied, want: &str, now: i64, msg: &str) {
    eprintln!("waf: {msg}");
    out.error = waf_conf::short_output(msg, ERROR_MAX);
    out.error_at = now;
    out.failed_hash = want.to_string();
    out.failed_at = now;
    if let Err(e) = save(state, APPLIED_FILE, out) {
        eprintln!("waf: {e:#}");
    }
}

/// Write or remove the live file, test, reload, check; undo on any failure.
/// `Err` carries the message for the hub (the old file is back by then).
fn swap(
    layout: &Layout,
    live: &Path,
    old: Option<&[u8]>,
    text: Option<&str>,
) -> Result<(), String> {
    let was_serving = serving();
    let put = match text {
        Some(t) => write_conf(live, t.as_bytes()),
        None => remove_if_exists(live),
    };
    if let Err(e) = put {
        restore(live, old);
        return Err(format!("không ghi được {}: {e:#}", live.display()));
    }
    if let Some(test) = &layout.test {
        let (code, output) = run(test, TEST_TIMEOUT);
        if !waf_conf::test_passed(&layout.server, code, &output, FILE_NAME) {
            restore(live, old);
            return Err(format!(
                "kiểm tra cấu hình ({}) báo lỗi, đã trả lại file cũ:\n{output}",
                test.join(" ")
            ));
        }
    }
    let Some(reload) = &layout.reload else {
        restore(live, old);
        return Err("không biết cách nạp lại máy chủ web này; đã trả lại file cũ".into());
    };
    let log_from = layout
        .server_log
        .as_ref()
        .and_then(|p| fs::metadata(p).ok())
        .map_or(0, |m| m.len());
    let (code, output) = run(reload, RELOAD_TIMEOUT);
    let why = if code != Some(0) {
        Some(format!("nạp lại ({}) lỗi:\n{output}", reload.join(" ")))
    } else if was_serving && !wait_serving() {
        Some("máy chủ web không còn nghe cổng 80/443 sau khi nạp lại".into())
    } else if let Some(log) = &layout.server_log {
        // LiteSpeed drops a rules file it cannot load and carries on: its log
        // is the only place that says so.
        std::thread::sleep(SETTLE);
        let new = log_since(log, log_from);
        waf_conf::log_blames(&new, FILE_NAME).then(|| {
            let lines: Vec<&str> = new
                .lines()
                .filter(|l| l.contains(FILE_NAME))
                .take(5)
                .collect();
            format!("máy chủ web báo lỗi với file luật:\n{}", lines.join("\n"))
        })
    } else {
        None
    };
    if let Some(why) = why {
        restore(live, old);
        let _ = run(reload, RELOAD_TIMEOUT);
        return Err(format!("{why}\nĐã trả lại file cũ và nạp lại."));
    }
    Ok(())
}

/// `sn waf-apply` (the apply unit, unconfined root): put the rules the watch
/// cycle left in place, test, reload, and undo on any failure.
///
/// # Errors
/// Only when the outcome cannot be recorded.
pub fn apply_now(state: &State) -> Result<()> {
    let Some(rules) = hub_rules(state) else {
        return Ok(());
    };
    let now = util::now_secs();
    let layout = detect();
    let w = wanted(&rules, &layout.taken);
    let mut out: Applied = load(state, APPLIED_FILE);
    out.refused.clone_from(&w.refused);
    let Some(live) = layout.live.clone() else {
        if w.text.is_some() {
            fail(
                state,
                &mut out,
                &w.hash,
                now,
                &format!("không đặt được luật: {}", layout.why_none),
            );
        }
        return Ok(());
    };
    let old = fs::read(&live).ok();
    if let Some(o) = &old
        && !o.starts_with(FILE_MARKER.as_bytes())
    {
        let msg = format!(
            "{} có sẵn và không phải file của SN Secure: không ghi đè",
            live.display()
        );
        fail(state, &mut out, &w.hash, now, &msg);
        return Ok(());
    }
    let have = old.as_deref().map_or_else(|| NO_FILE.to_string(), sha);
    if have != w.hash {
        if let Err(msg) = swap(&layout, &live, old.as_deref(), w.text.as_deref()) {
            fail(state, &mut out, &w.hash, now, &msg);
            return Ok(());
        }
        eprintln!(
            "waf: {} rule(s) in force ({} blocking)",
            w.applied, w.blocking
        );
    }
    // DirectAdmin: keep the copy CustomBuild restores after a rebuild.
    if let Some(p) = &layout.persist {
        let r = match &w.text {
            Some(t) if fs::read(p).ok().as_deref() == Some(t.as_bytes()) => Ok(()),
            Some(t) => fs::create_dir_all(p.parent().unwrap_or(Path::new("/")))
                .map_err(anyhow::Error::from)
                .and_then(|()| write_conf(p, t.as_bytes())),
            None => match fs::read(p) {
                Ok(b) if b.starts_with(FILE_MARKER.as_bytes()) => remove_if_exists(p),
                _ => Ok(()),
            },
        };
        if let Err(e) = r {
            eprintln!(
                "waf: could not keep the DirectAdmin copy {}: {e:#}",
                p.display()
            );
        }
    }
    if have != w.hash || out.hash != w.hash {
        out.applied_at = now;
    }
    out.hash = w.hash;
    out.applied = w.applied;
    out.blocking = w.blocking;
    out.rules_file = if w.text.is_some() {
        live.to_string_lossy().into_owned()
    } else {
        String::new()
    };
    out.error.clear();
    out.error_at = 0;
    out.failed_hash.clear();
    out.failed_at = 0;
    save(state, APPLIED_FILE, &out)
}

/// `sn disable`: take our rules out of the web server (and its DirectAdmin
/// copy), test and reload it. Returns what it did.
pub fn remove_all() -> String {
    let layout = detect();
    if let Some(p) = &layout.persist
        && fs::read(p).is_ok_and(|b| b.starts_with(FILE_MARKER.as_bytes()))
    {
        let _ = fs::remove_file(p);
    }
    let Some(live) = &layout.live else {
        return "WAF: no rules file of ours".into();
    };
    let old = match fs::read(live) {
        Ok(b) if b.starts_with(FILE_MARKER.as_bytes()) => b,
        _ => return "WAF: no rules file of ours".into(),
    };
    match swap(&layout, live, Some(&old), None) {
        Ok(()) => format!(
            "WAF rules removed ({}), web server reloaded",
            live.display()
        ),
        Err(e) => format!("WAF rules NOT removed: {e}"),
    }
}

/// Read new log lines and count matches of our rules.
fn read_hits(layout: &Layout, local: &mut Local, now: i64) {
    let mut files: Vec<PathBuf> = Vec::new();
    for g in &layout.logs {
        if let Ok(paths) = glob::glob(g) {
            files.extend(paths.filter_map(Result::ok).take(LOG_FILES_MAX));
        }
        if files.len() >= LOG_FILES_MAX {
            files.truncate(LOG_FILES_MAX);
            break;
        }
    }
    let marker: &[u8] = match layout.log_kind {
        LogKind::ErrorLog => b"[id \"6",
        LogKind::Audit => b"6",
    };
    let mut budget = READ_TOTAL;
    let mut seen: HashSet<String> = HashSet::new();
    for path in files {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let key = path.to_string_lossy().into_owned();
        if !seen.insert(key.clone()) {
            continue;
        }
        let len = meta.len();
        let start = match local.offsets.get(&key) {
            // Same file, not cut: carry on. Rotated, or truncated in place
            // (logrotate's copytruncate): from the start.
            Some(o) if o.dev == meta.dev() && o.inode == meta.ino() && o.pos <= len => o.pos,
            Some(_) => 0,
            // First sight: only what comes from now on.
            None => len,
        };
        // Behind by more than one cycle reads of a file: its newest part.
        let from = if len - start > READ_PER_FILE {
            len - READ_PER_FILE
        } else {
            start
        };
        // The total budget only defers: the rest is read next cycle.
        let take = (len - from).min(budget);
        let mut end = from;
        if take > 0
            && let Ok(mut f) = fs::File::open(&path)
            && f.seek(SeekFrom::Start(from)).is_ok()
        {
            let mut buf = Vec::with_capacity(usize::try_from(take).unwrap_or(0));
            if f.take(take).read_to_end(&mut buf).is_ok() {
                // Whole lines only; a partial last line is read next time.
                let whole = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
                let mut lines = buf[..whole].split(|&b| b == b'\n');
                if from != start {
                    lines.next(); // a skipped-to position may be mid-line
                }
                for line in lines {
                    if memchr::memmem::find(line, marker).is_none() {
                        continue;
                    }
                    let text = String::from_utf8_lossy(line);
                    match layout.log_kind {
                        LogKind::ErrorLog => {
                            if let Some(hit) = waf_conf::parse_hit(&text) {
                                local.tally.add(hit, now);
                            }
                        }
                        LogKind::Audit => {
                            if memchr::memmem::find(line, b"SN Secure").is_none() {
                                continue;
                            }
                            for hit in waf_conf::parse_audit_line(&text) {
                                local.tally.add(hit, now);
                            }
                        }
                    }
                }
                end = from + whole as u64;
                budget = budget.saturating_sub(whole as u64);
            }
        }
        local.offsets.insert(
            key,
            Offset {
                dev: meta.dev(),
                inode: meta.ino(),
                pos: end,
            },
        );
    }
    local.offsets.retain(|k, _| seen.contains(k));
}

/// Watch cycle (sandboxed): the state of the WAF for the report, with the
/// matches counted since the last report.
pub fn status(state: &State) -> WafStatus {
    let now = util::now_secs();
    let layout = detect();
    let applied: Applied = load(state, APPLIED_FILE);
    let mut local: Local = load(state, LOCAL_FILE);
    if applied.applied > 0 {
        read_hits(&layout, &mut local, now);
    } else {
        local.offsets.clear();
    }
    let hits = local.tally.to_hits();
    local.tally = Tally::default();
    if let Err(e) = save(state, LOCAL_FILE, &local) {
        eprintln!("waf: {e:#}");
    }
    let mut notes = layout.notes;
    if !layout.taken.is_empty()
        && let Some(rules) = hub_rules(state)
    {
        let clash: Vec<String> = rules
            .iter()
            .filter(|r| layout.taken.contains(&r.id))
            .map(|r| format!("#{}", r.id))
            .collect();
        if !clash.is_empty() {
            notes.push(format!(
                "Bỏ qua luật {}: id đã có trong file luật khác của máy chủ web",
                clash.join(", ")
            ));
        }
    }
    WafStatus {
        server: layout.server,
        engine: layout.engine,
        rules_file: applied.rules_file,
        applied: applied.applied,
        blocking: applied.blocking,
        refused: applied.refused,
        error: if applied.error.is_empty() && layout.live.is_none() && applied.applied > 0 {
            layout.why_none
        } else {
            applied.error
        },
        error_at: applied.error_at,
        applied_at: applied.applied_at,
        hits,
        notes,
    }
}

/// `sn env`: one line about the WAF.
#[must_use]
pub fn describe() -> String {
    let l = detect();
    let mut s = format!(
        "waf: server {} | modsecurity {} | rules file {} | test {} | reload {}",
        if l.server.is_empty() { "?" } else { &l.server },
        l.engine,
        l.live.as_ref().map_or_else(
            || format!("none ({})", l.why_none),
            |p| p.display().to_string()
        ),
        l.test.map_or_else(|| "none".into(), |t| t.join(" ")),
        l.reload.map_or_else(|| "none".into(), |t| t.join(" ")),
    );
    for n in l.notes {
        s.push_str("\nwaf: ");
        s.push_str(&n);
    }
    s
}
