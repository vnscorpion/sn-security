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
            if let Ok(name) = ent.file_name().into_string()
                && let Ok(pid) = name.parse::<i32>()
            {
                out.push(pid);
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
                if let Some(rest) = s.strip_prefix("socket:[")
                    && let Some(num) = rest.strip_suffix(']')
                    && let Ok(ino) = num.parse::<u64>()
                {
                    out.push(ino);
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
    // user nice system idle iowait irq softirq steal. The two guest columns that
    // follow are already counted inside user/nice, so adding them would inflate
    // the total and under-report the busy percentage on hosts running VMs.
    let total: u64 = vals.iter().take(8).sum();
    Some((total, idle))
}

/// Memory figures from `/proc/meminfo`, in kB.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MemInfo {
    pub total_kb: u64,
    /// `MemAvailable`: free + reclaimable cache, i.e. what apps can still get.
    pub available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

impl MemInfo {
    /// Percent of RAM in use, not counting reclaimable cache.
    pub fn used_pct(&self) -> f64 {
        if self.total_kb == 0 {
            return 0.0;
        }
        let used = self.total_kb.saturating_sub(self.available_kb);
        100.0 * used as f64 / self.total_kb as f64
    }

    pub fn swap_used_pct(&self) -> f64 {
        if self.swap_total_kb == 0 {
            return 0.0;
        }
        let used = self.swap_total_kb.saturating_sub(self.swap_free_kb);
        100.0 * used as f64 / self.swap_total_kb as f64
    }

    pub fn total_mb(&self) -> u64 {
        self.total_kb / 1024
    }
}

/// Parse the text of `/proc/meminfo`. Returns `None` if `MemTotal` is missing.
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let mut have_total = false;
    let mut have_avail = false;
    let mut mem_free = 0u64;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(kb) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "MemTotal" => {
                m.total_kb = kb;
                have_total = true;
            }
            "MemAvailable" => {
                m.available_kb = kb;
                have_avail = true;
            }
            "MemFree" => mem_free = kb,
            "SwapTotal" => m.swap_total_kb = kb,
            "SwapFree" => m.swap_free_kb = kb,
            _ => {}
        }
    }
    if !have_total {
        return None;
    }
    if !have_avail {
        // Very old kernels lack MemAvailable; fall back to MemFree.
        m.available_kb = mem_free;
    }
    Some(m)
}

pub fn meminfo() -> Option<MemInfo> {
    parse_meminfo(&fs::read_to_string("/proc/meminfo").ok()?)
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

/// Every process with its accumulated CPU time, for per-interval accounting.
pub fn cpu_procs() -> Vec<crate::watch::cpu::Proc> {
    list_pids()
        .into_iter()
        .filter_map(|pid| {
            let st = read_stat(pid)?;
            Some(crate::watch::cpu::Proc {
                pid,
                start: st.starttime,
                comm: st.comm,
                jiffies: st.utime + st.stime,
            })
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "MemTotal:        8000000 kB\n\
        MemFree:          500000 kB\n\
        MemAvailable:    2000000 kB\n\
        Buffers:          100000 kB\n\
        SwapTotal:       1000000 kB\n\
        SwapFree:         750000 kB\n";

    #[test]
    fn parses_meminfo() {
        let m = parse_meminfo(SAMPLE).unwrap();
        assert_eq!(m.total_kb, 8_000_000);
        assert_eq!(m.available_kb, 2_000_000);
        assert!((m.used_pct() - 75.0).abs() < 0.01);
        assert!((m.swap_used_pct() - 25.0).abs() < 0.01);
        assert_eq!(m.total_mb(), 7812);
    }

    #[test]
    fn no_swap_is_zero_not_nan() {
        let m = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 1000 kB\n").unwrap();
        assert_eq!(m.swap_used_pct(), 0.0);
        assert_eq!(m.used_pct(), 0.0);
    }

    #[test]
    fn missing_total_is_none() {
        assert!(parse_meminfo("MemFree: 5 kB\n").is_none());
        assert!(parse_meminfo("").is_none());
    }

    #[test]
    fn falls_back_to_memfree_without_available() {
        let m = parse_meminfo("MemTotal: 1000 kB\nMemFree: 400 kB\n").unwrap();
        assert_eq!(m.available_kb, 400);
    }

    #[test]
    fn skips_non_numeric_lines() {
        let m =
            parse_meminfo("garbage\nMemTotal: 2000 kB\nFoo: bar\nMemAvailable: 500 kB\n").unwrap();
        assert_eq!(m.total_kb, 2000);
        assert_eq!(m.available_kb, 500);
    }
}
