//! Read-only process inspection via `/proc`. No external binaries.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Clock ticks per second (USER_HZ). Almost universally 100 on Linux; we read
/// it once and fall back to 100 if the value is unavailable.
pub fn clock_ticks() -> u64 {
    // SC_CLK_TCK via nix::unistd::sysconf.
    match nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK) {
        Ok(Some(v)) if v > 0 => v as u64,
        _ => 100,
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code, reason = "pid/state parsed and retained for diagnostics")]
pub struct ProcStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub utime: u64,
    pub stime: u64,
    /// Start time in clock ticks since boot (field 22). Keys a process
    /// uniquely together with the pid, surviving PID reuse.
    pub starttime: u64,
}

/// Parse `/proc/<pid>/stat`. The `comm` field may contain spaces/parens, so we
/// split on the last `)` to isolate the fields after it.
pub fn read_stat(pid: i32) -> Option<ProcStat> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    let comm = raw.get(open + 1..close)?.to_string();
    let rest = raw.get(close + 2..)?; // skip ") "
    let f: Vec<&str> = rest.split_whitespace().collect();
    // rest[0] = state (field 3). utime=14, stime=15, starttime=22 -> rest idx
    // 11, 12, 19 (since field 3 is rest[0]).
    let state = f.first()?.chars().next()?;
    let ppid = f.get(1)?.parse().ok()?;
    let utime = f.get(11)?.parse().ok()?;
    let stime = f.get(12)?.parse().ok()?;
    let starttime = f.get(19)?.parse().ok()?;
    Some(ProcStat {
        pid,
        comm,
        state,
        ppid,
        utime,
        stime,
        starttime,
    })
}

/// All current PIDs.
pub fn list_pids() -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for ent in rd.flatten() {
            if let Ok(name) = ent.file_name().into_string() {
                if let Ok(pid) = name.parse::<i32>() {
                    out.push(pid);
                }
            }
        }
    }
    out
}

/// Resolve `/proc/<pid>/exe`. Returns `(path, deleted)`; `deleted` is true for
/// a binary unlinked after exec (a classic miner trick).
pub fn exe(pid: i32) -> (String, bool) {
    match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => {
            let s = p.to_string_lossy().to_string();
            let deleted = s.ends_with(" (deleted)");
            let clean = s.trim_end_matches(" (deleted)").to_string();
            (clean, deleted)
        }
        Err(_) => (String::new(), false),
    }
}

pub fn cwd(pid: i32) -> String {
    fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

pub fn cmdline(pid: i32) -> Vec<String> {
    match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Real UID from `/proc/<pid>/status` (the first value on the `Uid:` line).
pub fn uid(pid: i32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

pub fn username(uid: u32) -> String {
    match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
        Ok(Some(u)) => u.name,
        _ => uid.to_string(),
    }
}

/// Socket inodes held by a process (from `/proc/<pid>/fd` symlinks of the form
/// `socket:[12345]`).
pub fn socket_inodes(pid: i32) -> Vec<u64> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fd")) {
        for ent in rd.flatten() {
            if let Ok(target) = fs::read_link(ent.path()) {
                let s = target.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(num) = rest.strip_suffix(']') {
                        if let Ok(ino) = num.parse::<u64>() {
                            out.push(ino);
                        }
                    }
                }
            }
        }
    }
    out
}

/// `/proc/loadavg` 1-minute figure.
pub fn loadavg1() -> f64 {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0)
}

/// Aggregate CPU jiffies from `/proc/stat`: returns `(total, idle)` where idle
/// includes iowait. Sample twice to compute busy%.
pub fn cpu_total_idle() -> Option<(u64, u64)> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().next()?; // "cpu  u n s idle iowait irq softirq steal ..."
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
    if vals.len() < 5 {
        return None;
    }
    let idle = vals[3] + vals[4]; // idle + iowait
    let total: u64 = vals.iter().sum();
    Some((total, idle))
}

/// Number of online CPUs.
pub fn num_cpus() -> usize {
    match nix::unistd::sysconf(nix::unistd::SysconfVar::_NPROCESSORS_ONLN) {
        Ok(Some(v)) if v > 0 => v as usize,
        _ => 1,
    }
}

/// Snapshot of `utime+stime` per (pid, starttime), for delta CPU accounting
/// across cycles.
pub fn cpu_snapshot() -> HashMap<(i32, u64), u64> {
    let mut m = HashMap::new();
    for pid in list_pids() {
        if let Some(st) = read_stat(pid) {
            m.insert((pid, st.starttime), st.utime + st.stime);
        }
    }
    m
}

/// Does a path live under a suspicious directory (tmpfs / world-writable)?
pub fn is_suspicious_path(path: &str) -> bool {
    const BAD: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"];
    BAD.iter().any(|p| path.starts_with(p)) || path.contains("/.")
}

/// Candidate webroot markers used to flag code executing from a web directory.
pub fn is_webroot_path(path: &str) -> bool {
    const ROOTS: &[&str] = &[
        "/var/www/",
        "/home/",
        "/www/",
        "/usr/share/nginx/",
        "/srv/www/",
    ];
    ROOTS.iter().any(|p| path.starts_with(p))
}

/// Read a single-value sysfs/proc file as a trimmed string.
pub fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Collect crontab-like persistence files worth scanning.
pub fn persistence_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dirs = [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];
    for d in dirs {
        if let Ok(rd) = fs::read_dir(d) {
            for ent in rd.flatten() {
                out.push(ent.path());
            }
        }
    }
    for f in ["/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload"] {
        let p = PathBuf::from(f);
        if p.exists() {
            out.push(p);
        }
    }
    out
}
