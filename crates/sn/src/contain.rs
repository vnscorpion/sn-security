//! `sn contain` — make the box breathe again, reversibly. Throttles suspicious
//! processes into a 5%-CPU cgroup jail (never kills), optionally freezes a
//! confirmed miner, and bans flood sources on the web ports only. Everything is
//! recorded to the structured undo log.

use std::collections::HashSet;

use anyhow::{Context, Result};
use snsec_common::labels::Label;
use snsec_common::net;

use crate::config::Config;
use crate::state::State;
use crate::sys::{cgroup, fw, netstat, proc};
use crate::undo::{self, UndoOp};
use crate::util;
use crate::whitelist;

pub struct Options {
    pub freeze: bool,
    pub dry_run: bool,
    /// Specific PIDs to contain (CLI `--pid` or a verified desired job).
    pub pids: Vec<i32>,
    pub ban_flood: bool,
}

/// Returns the number of processes contained.
pub fn run(state: &State, cfg: &Config, opts: &Options) -> Result<usize> {
    // Fresh triage to get current PIDs/starttimes and the label.
    let triage = crate::triage::run(state, false)?;
    let label: Label = parse_label(&triage.label);

    // Decide the target PIDs.
    let targets: Vec<(i32, u64)> = if !opts.pids.is_empty() {
        triage
            .top_processes
            .iter()
            .filter(|p| opts.pids.contains(&p.pid))
            .map(|p| (p.pid, p.starttime))
            .collect()
    } else {
        triage
            .top_processes
            .iter()
            .filter(|p| p.score >= 60)
            .map(|p| (p.pid, p.starttime))
            .collect()
    };

    let mut contained = 0usize;
    let mut jail_prepared = false;
    let mut undo_jail_recorded = false;

    for (pid, starttime) in targets {
        // Re-read to confirm identity (pid+starttime) and apply the guard.
        let st = match proc::read_stat(pid) {
            Some(s) if s.starttime == starttime => s,
            _ => {
                eprintln!("contain: pid {pid} changed identity, skipping");
                continue;
            }
        };
        let (exe, _deleted) = proc::exe(pid);
        if let Some(reason) = protected_reason(pid, &st, &exe) {
            eprintln!(
                "contain: refusing to jail pid {pid} ({}): {reason}",
                st.comm
            );
            continue;
        }

        if opts.dry_run {
            println!("[dry-run] would contain pid {pid} ({}) exe={exe}", st.comm);
            contained += 1;
            continue;
        }

        if !jail_prepared {
            cgroup::prepare().context("preparing cgroup jail")?;
            jail_prepared = true;
        }
        if !undo_jail_recorded {
            undo::record(&state.dir, &UndoOp::CgroupRelease)?;
            undo_jail_recorded = true;
        }

        match cgroup::adopt(pid) {
            Ok(()) => {
                println!("contained pid {pid} ({}) -> 5% CPU jail", st.comm);
                contained += 1;
            }
            Err(e) => eprintln!("contain: adopt pid {pid} failed: {e:#}"),
        }
    }

    if opts.freeze && !opts.dry_run && contained > 0 && label == Label::Miner {
        match cgroup::freeze() {
            Ok(()) => println!("froze jail (confirmed miner)"),
            Err(e) => eprintln!("contain: freeze failed: {e:#}"),
        }
    }

    if opts.ban_flood && label == Label::DdosL7 {
        let banned = ban_flood_sources(state, cfg, opts.dry_run)?;
        if banned > 0 {
            println!("banned {banned} flood source(s) on web ports (TTL 1h)");
        }
    }

    if contained == 0 {
        println!("no processes matched the containment criteria.");
    } else if !opts.dry_run {
        println!("release later with `sn undo` (restores full CPU, removes jail).");
    }
    Ok(contained)
}

fn parse_label(s: &str) -> Label {
    match s {
        "miner" => Label::Miner,
        "php-bot" => Label::PhpBot,
        "ddos-l7" => Label::DdosL7,
        "bruteforce" => Label::Bruteforce,
        "disk-full" => Label::DiskFull,
        "mixed" => Label::Mixed,
        _ => Label::Unknown,
    }
}

/// Reasons a process must never be jailed (SEC-7 / DET-4): PID 1, our own
/// process, core services identified by exe location + name, and web-server
/// *workers* (a webshell inside php-fpm is handled by maintenance, not a jail).
pub(crate) fn protected_reason(pid: i32, st: &proc::ProcStat, exe: &str) -> Option<&'static str> {
    if pid <= 1 {
        return Some("init");
    }
    if pid == std::process::id() as i32 {
        return Some("self");
    }
    const CRITICAL: &[&str] = &[
        "systemd",
        "sshd",
        "init",
        "dbus",
        "mysqld",
        "mariadbd",
        "postgres",
        "redis-server",
        "nginx",
        "apache2",
        "httpd",
        "lshttpd",
        "litespeed",
        "php-fpm",
        "lsphp",
        "containerd",
        "dockerd",
        "cron",
        "crond",
    ];
    // A process is protected if its name matches a critical service AND its exe
    // lives in a system location (so a /tmp binary calling itself "nginx" is
    // NOT protected).
    let system_exe = exe.starts_with("/usr/")
        || exe.starts_with("/sbin/")
        || exe.starts_with("/bin/")
        || exe.starts_with("/lib/")
        || exe.starts_with("/opt/");
    if CRITICAL.iter().any(|n| st.comm.contains(n)) && system_exe {
        return Some("critical service");
    }
    None
}

fn ban_flood_sources(state: &State, cfg: &Config, dry_run: bool) -> Result<usize> {
    let conns = netstat::all();
    let wl = whitelist::build(cfg, &conns);
    let trusted = cfg.trusted_cidrs();
    let per_remote = netstat::conns_per_remote(&conns);

    let mut adds: Vec<(String, u64)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (key, count) in per_remote {
        if count <= 80 {
            continue;
        }
        // key is a plain v4 or v6 /64; parse the representative ip for checks.
        let probe_ip = key.split('/').next().unwrap_or(&key);
        if let Ok(ip) = probe_ip.parse()
            && (wl.protects(ip) || net::in_any(&trusted, ip))
        {
            continue;
        }
        if seen.insert(key.clone()) {
            adds.push((key, 3600));
        }
    }
    if adds.is_empty() {
        return Ok(0);
    }
    if dry_run {
        for (k, _) in &adds {
            println!("[dry-run] would ban {k}");
        }
        return Ok(adds.len());
    }
    fw::ensure_table(&cfg.fw.web_ports)?;
    fw::apply_bans(&adds, &[])?;
    for (k, _) in &adds {
        undo::record(&state.dir, &UndoOp::Unban { key: k.clone() })?;
    }
    // Record in active bans for reporting continuity.
    let mut bans = state.bans();
    let now = util::now_secs();
    for (k, ttl) in &adds {
        bans.insert(
            k.clone(),
            crate::state::ActiveBan {
                reason: "ddos-l7-flood".into(),
                expires_ts: now + *ttl as i64,
                strike: 1,
                layer: "l3".into(),
            },
        );
    }
    state.save_bans(&bans)?;
    Ok(adds.len())
}
