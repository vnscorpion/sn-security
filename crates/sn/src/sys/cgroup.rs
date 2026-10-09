//! cgroup containment with both v2 and v1 backends.
//!
//! `contain` throttles a suspicious process to a small CPU share (and can
//! freeze it) **without ever killing it**, so evidence survives and a
//! misidentified legitimate process is only slowed, not terminated. Freeze is
//! always available on v2 even when the cpu controller cannot be enabled under
//! systemd delegation, so a confirmed miner can still be stopped.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const JAIL: &str = "sn-jail";
const CPU_QUOTA_US: &str = "5000"; // of 100000 us period = 5% of one core
const CPU_PERIOD_US: &str = "100000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V2,
    V1,
    None,
}

/// Detect the cgroup layout by inspecting the filesystem type of
/// `/sys/fs/cgroup` (cgroup2fs = unified v2; tmpfs = v1/hybrid).
pub fn detect() -> Version {
    use nix::sys::statfs::{CGROUP2_SUPER_MAGIC, statfs};
    match statfs("/sys/fs/cgroup") {
        Ok(s) if s.filesystem_type() == CGROUP2_SUPER_MAGIC => Version::V2,
        Ok(_) => {
            // tmpfs root: confirm a v1 controller is actually mounted.
            if cpu_v1_root().is_some() {
                Version::V1
            } else {
                Version::None
            }
        }
        Err(_) => Version::None,
    }
}

#[must_use]
pub fn version_str() -> &'static str {
    match detect() {
        Version::V2 => "v2",
        Version::V1 => "v1",
        Version::None => "none",
    }
}

fn mem_total_bytes() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|n| n.parse::<u64>().ok())
            })
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

fn write(path: &Path, val: &str) -> Result<()> {
    fs::write(path, val).with_context(|| format!("write {}", path.display()))
}

// ---- v2 -------------------------------------------------------------------

fn v2_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

fn v2_jail() -> PathBuf {
    v2_root().join(JAIL)
}

fn v2_prepare() -> Result<()> {
    let jail = v2_jail();
    if !jail.exists() {
        fs::create_dir(&jail).with_context(|| format!("mkdir {}", jail.display()))?;
    }
    // Best effort: enable cpu/memory controllers for children. May fail under
    // strict systemd delegation; freeze still works without it.
    let _ = fs::write(v2_root().join("cgroup.subtree_control"), "+cpu +memory");
    // Throttle to 5% of one core; ignore if cpu controller unavailable.
    let _ = write(
        &jail.join("cpu.max"),
        &format!("{CPU_QUOTA_US} {CPU_PERIOD_US}"),
    );
    let mem = mem_total_bytes();
    if mem > 0 {
        let _ = write(&jail.join("memory.max"), &(mem / 10).to_string());
    }
    Ok(())
}

// ---- v1 -------------------------------------------------------------------

fn cpu_v1_root() -> Option<PathBuf> {
    for c in ["/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu"] {
        let p = PathBuf::from(c);
        if p.join("cgroup.procs").exists() || p.join("tasks").exists() {
            return Some(p);
        }
    }
    None
}

fn freezer_v1_root() -> Option<PathBuf> {
    let p = PathBuf::from("/sys/fs/cgroup/freezer");
    if p.exists() { Some(p) } else { None }
}

fn v1_prepare() -> Result<()> {
    let cpu = cpu_v1_root().context("no v1 cpu controller mounted")?;
    let jail = cpu.join(JAIL);
    if !jail.exists() {
        fs::create_dir(&jail).with_context(|| format!("mkdir {}", jail.display()))?;
    }
    write(&jail.join("cpu.cfs_period_us"), CPU_PERIOD_US)?;
    write(&jail.join("cpu.cfs_quota_us"), CPU_QUOTA_US)?;
    if let Some(fr) = freezer_v1_root() {
        let fjail = fr.join(JAIL);
        if !fjail.exists() {
            let _ = fs::create_dir(&fjail);
        }
    }
    Ok(())
}

// ---- public API -----------------------------------------------------------

/// Create the jail (idempotent) with the CPU/memory limits applied.
pub fn prepare() -> Result<()> {
    match detect() {
        Version::V2 => v2_prepare(),
        Version::V1 => v1_prepare(),
        Version::None => bail!("no usable cgroup controller (need v2 or v1 cpu/freezer)"),
    }
}

/// Move a process into the jail. Does not kill it.
pub fn adopt(pid: i32) -> Result<()> {
    match detect() {
        Version::V2 => write(&v2_jail().join("cgroup.procs"), &pid.to_string()),
        Version::V1 => {
            let cpu = cpu_v1_root().context("no v1 cpu controller")?;
            write(&cpu.join(JAIL).join("tasks"), &pid.to_string())?;
            if let Some(fr) = freezer_v1_root() {
                let _ = write(&fr.join(JAIL).join("tasks"), &pid.to_string());
            }
            Ok(())
        }
        Version::None => bail!("no usable cgroup controller"),
    }
}

/// Freeze (fully stop) everything in the jail. Use only for confirmed miners.
pub fn freeze() -> Result<()> {
    match detect() {
        Version::V2 => write(&v2_jail().join("cgroup.freeze"), "1"),
        Version::V1 => {
            let fr = freezer_v1_root().context("no v1 freezer controller")?;
            write(&fr.join(JAIL).join("freezer.state"), "FROZEN")
        }
        Version::None => bail!("no usable cgroup controller"),
    }
}

/// Thaw a frozen jail.
pub fn thaw() -> Result<()> {
    match detect() {
        Version::V2 => {
            let _ = write(&v2_jail().join("cgroup.freeze"), "0");
            Ok(())
        }
        Version::V1 => {
            if let Some(fr) = freezer_v1_root() {
                let _ = write(&fr.join(JAIL).join("freezer.state"), "THAWED");
            }
            Ok(())
        }
        Version::None => Ok(()),
    }
}

/// Release every process from the jail back to the root cgroup and remove it.
/// Processes keep running at full speed afterwards.
pub fn release() -> Result<()> {
    thaw()?;
    match detect() {
        Version::V2 => {
            let jail = v2_jail();
            move_all_to_root_v2(&jail);
            let _ = fs::remove_dir(&jail);
        }
        Version::V1 => {
            if let Some(cpu) = cpu_v1_root() {
                let jail = cpu.join(JAIL);
                move_all_to_root_v1(&cpu, &jail);
                let _ = fs::remove_dir(&jail);
            }
            if let Some(fr) = freezer_v1_root() {
                let jail = fr.join(JAIL);
                move_all_to_root_v1(&fr, &jail);
                let _ = fs::remove_dir(&jail);
            }
        }
        Version::None => {}
    }
    Ok(())
}

fn move_all_to_root_v2(jail: &Path) {
    if let Ok(procs) = fs::read_to_string(jail.join("cgroup.procs")) {
        let root = v2_root().join("cgroup.procs");
        for pid in procs.split_whitespace() {
            let _ = fs::write(&root, pid);
        }
    }
}

fn move_all_to_root_v1(controller_root: &Path, jail: &Path) {
    if let Ok(tasks) = fs::read_to_string(jail.join("tasks")) {
        let root = controller_root.join("tasks");
        for pid in tasks.split_whitespace() {
            let _ = fs::write(&root, pid);
        }
    }
}

/// Is a process currently in our jail? Used so `undo` knows whether to release.
pub fn jail_pids() -> Vec<i32> {
    let file = match detect() {
        Version::V2 => v2_jail().join("cgroup.procs"),
        Version::V1 => match cpu_v1_root() {
            Some(c) => c.join(JAIL).join("tasks"),
            None => return Vec::new(),
        },
        Version::None => return Vec::new(),
    };
    fs::read_to_string(file)
        .map(|s| {
            s.split_whitespace()
                .filter_map(|p| p.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}
