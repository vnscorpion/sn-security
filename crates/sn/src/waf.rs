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
//!
//! What a rule matches is counted from the access logs the watch cycle reads
//! anyway ([`snsec_common::waf::Matcher`]), not from ModSecurity's own logs:
//! that works whatever the engine, its log level and format, needs no audit
//! log (which holds cookies and request bodies), and also shows whether a
//! blocking rule really answers 403.
//!
//! In observe mode every rule only logs. `sn disable` takes the file out and
//! keeps it out until `sn waf-on`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snsec_common::schema::WafStatus;
use snsec_common::waf::{FILE_MARKER, MANAGED_ID_MAX, MANAGED_ID_MIN, WafRule, render_file};

use crate::state::State;
use crate::util;
use crate::waf_conf::{self, Tally};

/// Sorts after the CRS files (`REQUEST-*`), and does not end in `.conf.main`.
pub const FILE_NAME: &str = "zz-sn-secure.conf";
const DA_CUSTOMBUILD: &str = "/usr/local/directadmin/custombuild";
const DA_OPTIONS: &str = "/usr/local/directadmin/custombuild/options.conf";
/// CustomBuild copies this directory into `/etc/modsecurity.d` whenever it
/// rebuilds the rules.
const DA_CUSTOM_DIR: &str = "/usr/local/directadmin/custombuild/custom/modsecurity/conf";
const DA_RULES_DIR: &str = "/etc/modsecurity.d";
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
/// The file that was in place before an apply, kept until it finishes, so an
/// apply cut short (a reboot, the unit's time limit) can still be undone.
const BACKUP_FILE: &str = "waf-backup.conf";
/// Matches not yet reported (written by the watch cycle).
const LOCAL_FILE: &str = "waf-local.json";
/// Present after `sn disable`: the WAF file stays out until `sn waf-on`.
const OFF_FILE: &str = "waf-off";
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
/// Rule files scanned for ids already taken.
const SCAN_FILES_MAX: usize = 400;
const SCAN_BYTES_MAX: u64 = 16 << 20;
/// Site settings read for the notes.
const SITES_MAX: usize = 5000;
/// A hosting panel that gives every site its own ModSecurity rules file, which
/// includes two shared ones: `base` (the engine) and `custom` (rules for every
/// site, written by the panel). See `waf_conf` for how our file is reached.
struct Panel {
    /// "OPanel" / "bPanel", for the admin.
    label: &'static str,
    /// The web server the panel drives.
    server: &'static str,
    /// Where the shared rules files and the per-site `sites/` directory are.
    dir: &'static str,
    base: &'static str,
    custom: &'static str,
    /// Virtual host files, to find the sites that do not run ModSecurity.
    vhosts: &'static str,
    /// The line the panel puts at the start of a site's ModSecurity block.
    vhost_marker: &'static str,
    /// Server configuration whose `modsecurity on|off` switches the module.
    module_conf: Option<&'static str>,
}

/// OPanel (OpenLiteSpeed).
const OPANEL: Panel = Panel {
    label: "OPanel",
    server: "openlitespeed",
    dir: "/usr/local/lsws/conf/opanel/waf",
    base: "opanel-base.conf",
    custom: "opanel-custom.conf",
    vhosts: "/usr/local/lsws/conf/opanel/vhosts/*/vhost.conf",
    vhost_marker: "# OPANEL WAF BEGIN",
    module_conf: Some("/usr/local/lsws/conf/httpd_config.conf"),
};

/// bPanel (nginx with libmodsecurity).
const BPANEL: Panel = Panel {
    label: "bPanel",
    server: "nginx",
    dir: "/etc/nginx/modsec",
    base: "bpanel-base.conf",
    custom: "bpanel-custom.conf",
    vhosts: "/etc/nginx/conf.d/*.conf",
    vhost_marker: "# BPANEL WAF BEGIN",
    module_conf: None,
};

const PANELS: [&Panel; 2] = [&OPANEL, &BPANEL];

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
    /// OPanel: the rules file that has to `Include` ours (see `waf_conf`).
    pub hook: Option<PathBuf>,
    /// Configuration test (`httpd -t`); `None` when the server has none.
    pub test: Option<Vec<String>>,
    pub reload: Option<Vec<String>>,
    /// A full restart, for when a reload leaves the server down.
    pub restart: Option<Vec<String>>,
    /// The server's own error log, checked after a reload (LiteSpeed).
    pub server_log: Option<PathBuf>,
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

/// `systemctl <verb> <unit>` for the first of these units that is installed.
fn unit_cmd(verb: &str, units: &[&str]) -> Option<Vec<String>> {
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
        verb.into(),
        (*unit).to_string(),
    ])
}

/// Test, reload, restart, server log.
type Commands = (
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<PathBuf>,
);

fn commands(server: &str) -> Commands {
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
            unit_cmd("reload", &["httpd", "apache2"]),
            unit_cmd("restart", &["httpd", "apache2"]),
            None,
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
                unit_cmd("reload", &["nginx"]),
                unit_cmd("restart", &["nginx"]),
                None,
            )
        }
        // No configuration test exists for LiteSpeed Enterprise (`lshttpd -t`
        // checks the licence): its log is read after the reload instead.
        "litespeed" => (
            None,
            unit_cmd("reload", &["litespeed", "lsws"]).or_else(lswsctrl),
            unit_cmd("restart", &["litespeed", "lsws"]).or_else(lswsctrl),
            Some(PathBuf::from("/usr/local/lsws/logs/error.log")),
        ),
        "openlitespeed" => (
            first_file(&["/usr/local/lsws/bin/openlitespeed"]).map(|b| vec![b, "-t".into()]),
            unit_cmd("reload", &["openlitespeed", "lsws"]).or_else(lswsctrl),
            unit_cmd("restart", &["openlitespeed", "lsws"]).or_else(lswsctrl),
            Some(PathBuf::from("/usr/local/lsws/logs/error.log")),
        ),
        _ => (None, None, None, None),
    }
}

/// What the rule files of a directory hold: ids in our range already used, and
/// any server-level `SecRuleEngine` (a `*.conf.main` setup file may set one).
fn scan_rule_dir(dir: &Path) -> (HashSet<u32>, Vec<String>) {
    let mut taken = HashSet::new();
    let mut engines = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return (taken, engines);
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
        taken.extend(waf_conf::ids_in(&text, MANAGED_ID_MIN, MANAGED_ID_MAX));
        if let Some(e) = waf_conf::scan_conf(&text).engine {
            engines.push(e);
        }
        if budget == 0 {
            break;
        }
    }
    (taken, engines)
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
    let (test, reload, restart, server_log) = commands(&server);
    let mut out = Layout {
        server: server.clone(),
        test,
        reload,
        restart,
        server_log,
        ..Layout::default()
    };
    if server.is_empty() {
        out.engine = "unknown".into();
        out.why_none = "không nhận ra máy chủ web".into();
        return out;
    }
    if let Some(panel) = PANELS
        .iter()
        .find(|p| p.server == server && Path::new(p.dir).join(p.base).is_file())
    {
        return detect_panel(out, panel);
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
    let module = scans.iter().find_map(|s| s.module);
    let mut engines: Vec<String> = scans.iter().filter_map(|s| s.engine.clone()).collect();
    let dir = scans
        .iter()
        .flat_map(|s| s.include_dirs.iter())
        .find(|d| safe_dir(Path::new(d)))
        .cloned();
    match &dir {
        Some(d) => {
            out.live = Some(Path::new(d).join(FILE_NAME));
            let (taken, in_dir) = scan_rule_dir(Path::new(d));
            out.taken = taken;
            engines.extend(in_dir);
            if d.trim_end_matches('/') == DA_RULES_DIR && Path::new(DA_CUSTOMBUILD).is_dir() {
                out.persist = Some(Path::new(DA_CUSTOM_DIR).join(FILE_NAME));
            }
        }
        None => {
            out.why_none =
                "cấu hình ModSecurity không nạp thư mục luật nào dạng <thư mục>/*.conf".into();
        }
    }
    // DirectAdmin's own setting, applied per site, wins over the server level.
    let panel = if directadmin {
        da_sites(&mut out.notes)
    } else {
        None
    };
    out.engine = waf_conf::engine_state(module, &engines, panel.as_deref(), directadmin).into();
    out
}

/// A panel with per-site rules: the engine from its own files, our file next to
/// them, and the shared `custom` file (included by every site's rules) as the
/// hook.
fn detect_panel(mut out: Layout, panel: &Panel) -> Layout {
    let dir = Path::new(panel.dir);
    let read = |p: &Path| fs::read_to_string(p).unwrap_or_default();
    let (taken, mut engines) = scan_rule_dir(dir);
    let (taken_sites, engines_sites) = scan_rule_dir(&dir.join("sites"));
    out.taken = taken.union(&taken_sites).copied().collect();
    engines.extend(engines_sites);
    let module = panel
        .module_conf
        .and_then(|c| waf_conf::scan_conf(&read(Path::new(c))).module);
    out.engine = waf_conf::panel_engine(&read(&dir.join(panel.base)), module, &engines).into();
    let custom = dir.join(panel.custom);
    let custom_ok = fs::symlink_metadata(&custom)
        .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0);
    if !safe_dir(dir) {
        out.why_none = format!("{} không phải thư mục do root sở hữu", panel.dir);
    } else if !custom_ok {
        out.why_none = format!("thiếu {} do root sở hữu trong {}", panel.custom, panel.dir);
    } else {
        out.live = Some(dir.join(FILE_NAME));
        out.hook = Some(custom);
    }
    let mut vhosts = Vec::new();
    if let Ok(paths) = glob::glob(panel.vhosts) {
        for p in paths.filter_map(Result::ok).take(SITES_MAX) {
            let file = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            // One directory per site (`<site>/vhost.conf`), or `<site>.conf`.
            let name = if file == "vhost.conf" {
                p.parent()
                    .and_then(Path::file_name)
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                file.trim_end_matches(".conf").to_string()
            };
            vhosts.push((name, read(&p)));
        }
    }
    let without = waf_conf::sites_without_waf(&vhosts, panel.vhost_marker);
    if !without.is_empty() {
        let mut list = without
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if without.len() > 5 {
            list.push_str(", …");
        }
        out.notes.push(format!(
            "{} tên miền chưa bật WAF trong {}, luật không chạy ở đó: {list}",
            without.len(),
            panel.label
        ));
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

fn ours(bytes: &[u8]) -> bool {
    bytes.starts_with(FILE_MARKER.as_bytes())
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
    /// The file an apply was putting in place when it stopped (empty once it
    /// finished, whichever way). Found in place later, it has not been tested.
    #[serde(default)]
    pending_hash: String,
}

/// The watch cycle's own bookkeeping.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Local {
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

fn switched_off(state: &State) -> bool {
    state.dir.join(OFF_FILE).exists()
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
/// (a duplicate id is a fatal error in ModSecurity 2 and 3). Outside enforce
/// mode no rule blocks.
fn wanted(rules: &[WafRule], taken: &HashSet<u32>, enforce: bool) -> Wanted {
    let (usable, clashing): (Vec<WafRule>, Vec<WafRule>) = rules
        .iter()
        .cloned()
        .map(|mut r| {
            r.block &= enforce;
            r
        })
        .partition(|r| !taken.contains(&r.id));
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
        Ok(b) if ours(&b) => Some(sha(&b)),
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

/// The hub's rules, if it ever sent any.
#[must_use]
pub fn hub_rules(state: &State) -> Option<Vec<WafRule>> {
    let bytes = fs::read(state.dir.join(RULES_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Watch cycle (sandboxed), every cycle: start the apply unit when the hub's
/// rules differ from what is in place (new rules, a mode change, or a panel
/// rebuild that removed the file). Bounded by `RETRY_SECS` / `RESTART_SECS`.
pub fn ensure(state: &State, enforce: bool) {
    // The hub never sent rules: the WAF is not ours to manage.
    let Some(rules) = hub_rules(state) else {
        return;
    };
    if switched_off(state) {
        return;
    }
    let now = util::now_secs();
    let layout = detect();
    let want = wanted(&rules, &layout.taken, enforce).hash;
    let applied: Applied = load(state, APPLIED_FILE);
    let mut local: Local = load(state, LOCAL_FILE);
    let have = layout.live.as_deref().and_then(in_place);
    // OPanel: the panel rewriting `opanel-custom.conf` can take our line out.
    let hook_ok = layout
        .live
        .as_deref()
        .is_none_or(|l| hook_matches(&layout, l, want != NO_FILE));
    if have.as_deref() == Some(want.as_str())
        && applied.hash == want
        && applied.error.is_empty()
        && applied.pending_hash.is_empty()
        && hook_ok
    {
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
    match Command::new("systemd-run")
        .args(apply_unit_args(enforce))
        .status()
    {
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
fn apply_unit_args(enforce: bool) -> Vec<String> {
    let mut args: Vec<String> = [
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
    .collect();
    if !enforce {
        args.push("--observe".into());
    }
    args
}

/// Run a command for at most `timeout`: its exit code (`None`: it could not
/// start, was killed or ran over) and what it printed.
fn run(argv: &[String], timeout: Duration) -> (Option<i32>, String) {
    fn pipe<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(r) = r {
                let _ = r.take(OUTPUT_CAP).read_to_end(&mut buf);
            }
            buf
        })
    }
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
    write_conf_mode(path, bytes, 0o644)
}

/// [`write_conf`] with the file's permission bits given (a file of someone
/// else's is rewritten with the bits it had).
fn write_conf_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("no parent")?;
    if !safe_dir(dir) {
        anyhow::bail!("{} is not a root-owned directory", dir.display());
    }
    write_atomic(path, bytes, mode)
}

/// The writing of [`write_conf_mode`], without the check of the directory. The
/// bits are set on the file itself: the agent runs with a private umask (0077),
/// which would otherwise strip them from `mode` and leave a rules file only root
/// can read (and a panel's file that was 0644 rewritten as 0600).
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("no parent")?;
    let tmp = dir.join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let written = f
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|()| f.write_all(bytes))
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

/// The hook file as it was, to put back if an apply fails.
struct HookState {
    path: PathBuf,
    bytes: Vec<u8>,
    mode: u32,
}

fn hook_state(layout: &Layout) -> Option<HookState> {
    let path = layout.hook.clone()?;
    let bytes = fs::read(&path).ok()?;
    let mode = fs::metadata(&path).ok()?.mode() & 0o777;
    Some(HookState { path, bytes, mode })
}

/// Make the hook file include `live` (`want`) or not. A file that is already
/// right is not touched.
fn set_hook(h: &HookState, live: &Path, want: bool) -> Result<()> {
    let text = std::str::from_utf8(&h.bytes)
        .with_context(|| format!("{} is not text", h.path.display()))?;
    if !want && !text.contains(waf_conf::HOOK_BEGIN) {
        return Ok(());
    }
    let new = if want {
        waf_conf::with_hook(text, &live.to_string_lossy())
    } else {
        waf_conf::without_hook(text)
    };
    if new.as_bytes() == h.bytes.as_slice() {
        return Ok(());
    }
    write_conf_mode(&h.path, new.as_bytes(), h.mode)
}

fn restore_hook(h: &HookState) {
    if let Err(e) = write_conf_mode(&h.path, &h.bytes, h.mode) {
        eprintln!("waf: could not put {} back: {e:#}", h.path.display());
    }
}

/// Is the hook as it should be: including our file when `want`, not when not?
/// Always true where there is no hook.
fn hook_matches(layout: &Layout, live: &Path, want: bool) -> bool {
    let Some(h) = &layout.hook else {
        return true;
    };
    let Ok(text) = fs::read_to_string(h) else {
        return false;
    };
    if want {
        waf_conf::hook_in_place(&text, &live.to_string_lossy())
    } else {
        !text.contains(waf_conf::HOOK_BEGIN)
    }
}

/// Undo an apply that failed, in an order that never leaves an `Include` of a
/// file that is missing: when it added our file and then the line, the line goes
/// first; when it removed the line and then the file, the file comes back first.
fn undo(live: &Path, old: Option<&[u8]>, hook: Option<&HookState>, was_adding: bool) {
    if was_adding {
        if let Some(h) = hook {
            restore_hook(h);
        }
        restore(live, old);
    } else {
        restore(live, old);
        if let Some(h) = hook {
            restore_hook(h);
        }
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
    out.pending_hash.clear();
    if let Err(e) = save(state, APPLIED_FILE, out) {
        eprintln!("waf: {e:#}");
    }
}

/// After putting the old file back: reload, and if the server is still down,
/// restart it. Says how it ended.
fn recover(layout: &Layout, was_serving: bool) -> String {
    if let Some(reload) = &layout.reload {
        let _ = run(reload, RELOAD_TIMEOUT);
    }
    if !was_serving || wait_serving() {
        return "Đã trả lại file cũ và nạp lại.".into();
    }
    if let Some(restart) = &layout.restart {
        let (code, output) = run(restart, RELOAD_TIMEOUT);
        if wait_serving() {
            return "Đã trả lại file cũ; máy chủ web phải khởi động lại và đã chạy lại.".into();
        }
        return format!(
            "ĐÃ TRẢ LẠI FILE CŨ NHƯNG MÁY CHỦ WEB VẪN KHÔNG CHẠY ({} → {code:?}):\n{output}",
            restart.join(" ")
        );
    }
    "ĐÃ TRẢ LẠI FILE CŨ NHƯNG MÁY CHỦ WEB VẪN KHÔNG CHẠY: kiểm tra ngay.".into()
}

/// Write or remove the live file, test, reload, check; undo on any failure.
/// `Err` carries the message for the hub (the old file is back by then).
fn swap(
    layout: &Layout,
    live: &Path,
    old: Option<&[u8]>,
    text: Option<&str>,
) -> Result<(), String> {
    // Only LiteSpeed Enterprise has no test; anywhere else an untested
    // configuration could stop the server at its next restart.
    if layout.test.is_none() && layout.server != "litespeed" {
        return Err("không tìm thấy lệnh kiểm tra cấu hình của máy chủ web: không áp".into());
    }
    let Some(reload) = &layout.reload else {
        return Err("không biết cách nạp lại máy chủ web này: không áp".into());
    };
    let was_serving = serving();
    let adding = text.is_some();
    let hook = hook_state(layout);
    let put = (|| -> Result<()> {
        match text {
            // The file first, then the line that includes it...
            Some(t) => {
                write_conf(live, t.as_bytes())?;
                if let Some(h) = &hook {
                    set_hook(h, live, true)?;
                }
            }
            // ...and the line goes before the file.
            None => {
                if let Some(h) = &hook {
                    set_hook(h, live, false)?;
                }
                remove_if_exists(live)?;
            }
        }
        Ok(())
    })();
    if let Err(e) = put {
        undo(live, old, hook.as_ref(), adding);
        return Err(format!("không ghi được {}: {e:#}", live.display()));
    }
    if let Some(test) = &layout.test {
        let (code, output) = run(test, TEST_TIMEOUT);
        if !waf_conf::test_passed(&layout.server, code, &output, FILE_NAME) {
            undo(live, old, hook.as_ref(), adding);
            return Err(format!(
                "kiểm tra cấu hình ({}) báo lỗi, đã trả lại file cũ:\n{output}",
                test.join(" ")
            ));
        }
    }
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
                .filter(|l| l.contains(FILE_NAME) && !l.contains("[id \""))
                .take(5)
                .collect();
            format!("máy chủ web báo lỗi với file luật:\n{}", lines.join("\n"))
        })
    } else {
        None
    };
    if let Some(why) = why {
        undo(live, old, hook.as_ref(), adding);
        let how = recover(layout, was_serving);
        return Err(format!("{why}\n{how}"));
    }
    Ok(())
}

/// Keep the CustomBuild copy in step: written when there are rules, removed
/// when there are none. A file of that name that is not ours is left alone.
fn keep_persist(p: &Path, text: Option<&str>) -> Result<(), String> {
    let existing = fs::read(p).ok();
    if existing.as_deref().is_some_and(|b| !ours(b)) {
        return Err(format!(
            "{} có sẵn và không phải file của SN Secure: không ghi đè",
            p.display()
        ));
    }
    let r = match text {
        Some(t) if existing.as_deref() == Some(t.as_bytes()) => Ok(()),
        Some(t) => fs::create_dir_all(p.parent().unwrap_or(Path::new("/")))
            .map_err(anyhow::Error::from)
            .and_then(|()| write_conf(p, t.as_bytes())),
        None if existing.is_some() => remove_if_exists(p),
        None => Ok(()),
    };
    r.map_err(|e| {
        format!(
            "không giữ được bản sao cho DirectAdmin {}: {e:#}",
            p.display()
        )
    })
}

/// `sn waf-apply` (the apply unit, unconfined root): put the rules the watch
/// cycle left in place, test, reload, and undo on any failure.
///
/// # Errors
/// Only when the outcome cannot be recorded.
pub fn apply_now(state: &State, enforce: bool) -> Result<()> {
    let Some(rules) = hub_rules(state) else {
        return Ok(());
    };
    if switched_off(state) {
        return Ok(());
    }
    let now = util::now_secs();
    let layout = detect();
    let w = wanted(&rules, &layout.taken, enforce);
    let mut out: Applied = load(state, APPLIED_FILE);
    out.refused.clone_from(&w.refused);
    let Some(live) = layout.live.clone() else {
        if w.text.is_some() {
            let msg = format!("không đặt được luật: {}", layout.why_none);
            fail(state, &mut out, &w.hash, now, &msg);
        }
        return Ok(());
    };
    let mut old = fs::read(&live).ok();
    if old.as_deref().is_some_and(|o| !ours(o)) {
        let msg = format!(
            "{} có sẵn và không phải file của SN Secure: không ghi đè",
            live.display()
        );
        fail(state, &mut out, &w.hash, now, &msg);
        return Ok(());
    }
    let mut have = old.as_deref().map_or_else(|| NO_FILE.to_string(), sha);
    // An earlier apply stopped between writing and testing: what is in place
    // is untested. Start again from the file before it.
    let interrupted = !out.pending_hash.is_empty() && out.pending_hash == have;
    if interrupted {
        old = fs::read(state.dir.join(BACKUP_FILE))
            .ok()
            .filter(|b| ours(b));
        have = String::from("untested");
    }
    let hook_wrong = !hook_matches(&layout, &live, w.text.is_some());
    if have != w.hash || hook_wrong {
        // Remember where we were, in case this run is cut short.
        let backup = match &old {
            Some(b) => state.save_file(BACKUP_FILE, b),
            None => remove_if_exists(&state.dir.join(BACKUP_FILE)),
        };
        out.pending_hash.clone_from(&w.hash);
        if let Err(e) = backup.and_then(|()| save(state, APPLIED_FILE, &out)) {
            fail(
                state,
                &mut out,
                &w.hash,
                now,
                &format!("không ghi được trạng thái: {e:#}"),
            );
            return Ok(());
        }
        if let Err(msg) = swap(&layout, &live, old.as_deref(), w.text.as_deref()) {
            fail(state, &mut out, &w.hash, now, &msg);
            return Ok(());
        }
        eprintln!(
            "waf: {} rule(s) in force ({} blocking)",
            w.applied, w.blocking
        );
    }
    let mut note = String::new();
    if let Some(p) = &layout.persist
        && let Err(e) = keep_persist(p, w.text.as_deref())
    {
        eprintln!("waf: {e}");
        note = e;
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
    out.error = note;
    out.error_at = if out.error.is_empty() { 0 } else { now };
    out.failed_hash.clear();
    out.failed_at = 0;
    out.pending_hash.clear();
    let _ = remove_if_exists(&state.dir.join(BACKUP_FILE));
    save(state, APPLIED_FILE, &out)
}

/// `sn disable`: take our rules out of the web server (and the DirectAdmin
/// copy) and keep them out until `sn waf-on`. Looks wherever a file of ours
/// can be, even when ModSecurity is no longer found. Returns what it did.
pub fn remove_all(state: &State) -> String {
    // Kept out from now on, and no apply runs alongside.
    let _ = state.save_file(OFF_FILE, b"sn disable\n");
    if let Some(sc) = util::find_bin("systemctl") {
        let _ = Command::new(sc)
            .args(["stop", "sn-waf-apply.service"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let layout = detect();
    let applied: Applied = load(state, APPLIED_FILE);
    let mut places: Vec<PathBuf> = vec![
        Path::new(DA_CUSTOM_DIR).join(FILE_NAME),
        Path::new(DA_RULES_DIR).join(FILE_NAME),
    ];
    places.extend(layout.persist.clone());
    places.extend(layout.live.clone());
    if !applied.rules_file.is_empty() {
        places.push(PathBuf::from(&applied.rules_file));
    }
    places.sort();
    places.dedup();
    let mut removed: Vec<String> = Vec::new();
    let mut live_removed = false;
    for p in &places {
        if p.file_name().and_then(|n| n.to_str()) != Some(FILE_NAME) {
            continue;
        }
        let Ok(b) = fs::read(p) else { continue };
        if !ours(&b) {
            continue;
        }
        let is_copy = p.starts_with(DA_CUSTOMBUILD);
        let r = if is_copy {
            remove_if_exists(p).map_err(|e| format!("{e:#}"))
        } else {
            live_removed = true;
            remove_live(&layout, p, &b)
        };
        match r {
            Ok(()) => removed.push(p.display().to_string()),
            Err(e) => return format!("WAF rules NOT removed from {}: {e}", p.display()),
        }
    }
    // OPanel: a line of ours that includes a file that is not there (the file
    // was deleted by hand) would stop ModSecurity from loading.
    if let (Some(h), Some(live)) = (hook_state(&layout), layout.live.as_deref())
        && String::from_utf8_lossy(&h.bytes).contains(waf_conf::HOOK_BEGIN)
    {
        match set_hook(&h, live, false) {
            Ok(()) => {
                if let Some(reload) = &layout.reload {
                    let _ = run(reload, RELOAD_TIMEOUT);
                }
                removed.push(h.path.display().to_string());
            }
            Err(e) => return format!("WAF hook NOT removed from {}: {e:#}", h.path.display()),
        }
    }
    let out = Applied {
        hash: NO_FILE.into(),
        ..Applied::default()
    };
    let _ = save(state, APPLIED_FILE, &out);
    if removed.is_empty() {
        "WAF: no rules file of ours; kept off until `sn waf-on`".into()
    } else if live_removed {
        format!(
            "WAF rules removed ({}), web server reloaded; kept off until `sn waf-on`",
            removed.join(", ")
        )
    } else {
        format!(
            "WAF rules removed ({}); kept off until `sn waf-on`",
            removed.join(", ")
        )
    }
}

/// Take a live file of ours out and reload. Removing our own file cannot make
/// the configuration invalid, so no test is needed (and none may be found,
/// when ModSecurity itself is being taken away); a server that stops serving
/// gets the file back.
fn remove_live(layout: &Layout, p: &Path, old: &[u8]) -> Result<(), String> {
    // OPanel: the line that includes the file goes first.
    let hook = hook_state(layout);
    if let Some(h) = &hook {
        set_hook(h, p, false).map_err(|e| format!("{e:#}"))?;
    }
    let gone = |e: String| {
        if let Some(h) = &hook {
            restore_hook(h);
        }
        e
    };
    let Some(reload) = &layout.reload else {
        return remove_if_exists(p)
            .map_err(|e| gone(format!("{e:#}")))
            .map(|()| {
                eprintln!(
                    "waf: {} removed; reload the web server yourself",
                    p.display()
                )
            });
    };
    let was_serving = serving();
    remove_if_exists(p).map_err(|e| gone(format!("{e:#}")))?;
    let (code, output) = run(reload, RELOAD_TIMEOUT);
    if code == Some(0) && (!was_serving || wait_serving()) {
        return Ok(());
    }
    // The file comes back before the line that includes it.
    undo(p, Some(old), hook.as_ref(), false);
    let how = recover(layout, was_serving);
    Err(format!(
        "nạp lại ({}) lỗi:\n{output}\n{how}",
        reload.join(" ")
    ))
}

/// `sn waf-on`: let the hub's rules back in (the next watch cycle applies them).
pub fn switch_on(state: &State) -> String {
    match remove_if_exists(&state.dir.join(OFF_FILE)) {
        Ok(()) => "WAF rules from the hub will be applied again at the next watch cycle".into(),
        Err(e) => format!("could not switch the WAF back on: {e:#}"),
    }
}

/// Watch cycle: matches counted from this cycle's access-log lines, kept until
/// the next report.
pub fn add_hits(state: &State, tally: Tally) {
    if tally.rules.is_empty() {
        return;
    }
    let mut local: Local = load(state, LOCAL_FILE);
    local.tally.merge(tally);
    if let Err(e) = save(state, LOCAL_FILE, &local) {
        eprintln!("waf: {e:#}");
    }
}

/// Watch cycle (sandboxed): the state of the WAF for the report, with the
/// matches counted since the last report.
pub fn status(state: &State, enforce: bool) -> WafStatus {
    let layout = detect();
    let applied: Applied = load(state, APPLIED_FILE);
    let mut local: Local = load(state, LOCAL_FILE);
    let hits = local.tally.to_hits();
    if !hits.is_empty() {
        local.tally = Tally::default();
        if let Err(e) = save(state, LOCAL_FILE, &local) {
            eprintln!("waf: {e:#}");
        }
    }
    let rules = hub_rules(state).unwrap_or_default();
    let mut notes = layout.notes;
    if switched_off(state) {
        notes.push(
            "Đã tắt trên VPS bằng `sn disable`: luật không được đặt (bật lại: `sn waf-on`).".into(),
        );
    }
    if !enforce && rules.iter().any(|r| r.block) {
        notes.push(
            "VPS đang ở chế độ observe: mọi luật chỉ ghi nhận, kể cả luật đã bật chặn.".into(),
        );
    }
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
        "waf: server {} | modsecurity {} | rules file {}{} | test {} | reload {}",
        if l.server.is_empty() { "?" } else { &l.server },
        l.engine,
        l.live.as_ref().map_or_else(
            || format!("none ({})", l.why_none),
            |p| p.display().to_string()
        ),
        l.hook
            .as_ref()
            .map_or_else(String::new, |h| format!(" (included from {})", h.display())),
        l.test.map_or_else(|| "none".into(), |t| t.join(" ")),
        l.reload.map_or_else(|| "none".into(), |t| t.join(" ")),
    );
    for n in l.notes {
        s.push_str("\nwaf: ");
        s.push_str(&n);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::stat::{Mode, umask};

    fn mode_of(p: &Path) -> u32 {
        fs::metadata(p).unwrap().mode() & 0o777
    }

    #[test]
    fn a_file_gets_the_bits_asked_for_whatever_the_umask() {
        // The agent runs with umask 0077. The rules file must still be readable
        // by the web server, and a panel's file keeps the bits it had.
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("zz-sn-secure.conf");
        let panel = dir.path().join("opanel-custom.conf");
        let before = umask(Mode::S_IRWXG | Mode::S_IRWXO);
        let r1 = write_atomic(&rules, b"# rules\n", 0o644);
        let r2 = write_atomic(&panel, b"# panel\n", 0o640);
        // Rewritten in place, as a hook is: the bits stay.
        let r3 = write_atomic(&rules, b"# rules again\n", 0o644);
        umask(before);
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
        assert_eq!(mode_of(&rules), 0o644);
        assert_eq!(mode_of(&panel), 0o640);
        assert_eq!(fs::read_to_string(&rules).unwrap(), "# rules again\n");
        // No temporary file is left behind.
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }
}
