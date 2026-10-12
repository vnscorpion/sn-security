//! `sn triage` — read-only incident snapshot. Never writes to the system (it
//! does persist its own JSON report under the state dir). Designed to return in
//! a few seconds on a box pinned at 100% CPU.

use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use snsec_common::labels::Label;
use snsec_common::schema::{ProcInfo, TriageSummary};

use crate::state::State;
use crate::sys::{netstat, proc};
use crate::util;

/// Ports strongly associated with mining pools / common C2.
pub(crate) const BAD_OUT_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 9999, 14444, 45700, 3357];

pub(crate) const MINER_HINTS: &[&str] = &[
    "stratum",
    "xmrig",
    "--donate",
    "randomx",
    "cryptonight",
    "nicehash",
    "minerd",
    "nanopool",
    "supportxmr",
    "hashvault",
];

struct Suspect {
    info: ProcInfo,
    label_hint: Option<Label>,
}

/// Build the triage summary. `sample_ms` is the CPU sampling window.
pub fn run(state: &State, print: bool) -> Result<TriageSummary> {
    let ticks = proc::clock_ticks() as f64;
    let sample_ms = 300u64;

    // Two CPU snapshots to measure per-process and machine busy%.
    let first = proc::cpu_snapshot();
    let (t0, i0) = proc::cpu_total_idle().unwrap_or((0, 0));
    sleep(Duration::from_millis(sample_ms));
    let second = proc::cpu_snapshot();
    let (t1, i1) = proc::cpu_total_idle().unwrap_or((0, 0));

    let elapsed = sample_ms as f64 / 1000.0;
    let cpu_busy_pct = if t1 > t0 {
        100.0 * (1.0 - (i1.saturating_sub(i0)) as f64 / (t1 - t0).max(1) as f64)
    } else {
        0.0
    };

    let conns = netstat::all();
    let by_inode = netstat::by_inode(&conns);

    let mut suspects: Vec<Suspect> = Vec::new();
    for (&(pid, start), &cum2) in &second {
        let cum1 = first.get(&(pid, start)).copied().unwrap_or(cum2);
        let dcpu = cum2.saturating_sub(cum1) as f64;
        let cpu_pct = 100.0 * (dcpu / ticks) / elapsed; // % of one core

        let st = match proc::read_stat(pid) {
            Some(s) => s,
            None => continue,
        };
        let (exe, deleted) = proc::exe(pid);
        let cwd = proc::cwd(pid);
        let uidn = proc::uid(pid).unwrap_or(0);
        let cmd = proc::cmdline(pid);

        // Outbound connections of this process.
        let mut out_conns = Vec::new();
        for ino in proc::socket_inodes(pid) {
            if let Some(c) = by_inode.get(&ino)
                && c.state == netstat::ST_ESTABLISHED
                && !c.remote.is_loopback()
            {
                out_conns.push(format!("{}:{}", c.remote, c.remote_port));
            }
        }

        let (score, hint) = score_process(&st, &exe, deleted, &cwd, &cmd, cpu_pct, &out_conns);
        if score == 0 && cpu_pct < 50.0 {
            continue; // not interesting
        }

        suspects.push(Suspect {
            info: ProcInfo {
                pid,
                starttime: start,
                comm: st.comm.clone(),
                exe,
                cwd,
                user: proc::username(uidn),
                cpu_pct: (cpu_pct * 10.0).round() / 10.0,
                out_conns,
                deleted_exe: deleted,
                score,
            },
            label_hint: hint,
        });
    }

    suspects.sort_by(|a, b| {
        b.info
            .score
            .cmp(&a.info.score)
            .then(b.info.cpu_pct.total_cmp(&a.info.cpu_pct))
    });
    suspects.truncate(10);

    let persistence = scan_persistence();
    let (disk_pct, inode_pct) = disk_usage("/");
    let label = decide_label(&suspects, &conns, disk_pct, inode_pct);

    let summary = TriageSummary {
        label: label.as_str().to_string(),
        top_processes: suspects.iter().map(|s| s.info.clone()).collect(),
        persistence,
        load1: proc::loadavg1(),
        disk_pct,
        inode_pct,
        mem_used_pct: (proc::meminfo().unwrap_or_default().used_pct() * 10.0).round() / 10.0,
    };

    // Persist JSON for the hub / later commands.
    let file = state.dir.join(format!(
        "triage-{}.json",
        util::ts_compact(util::now_secs())
    ));
    let _ = std::fs::write(&file, serde_json::to_vec_pretty(&summary)?);
    // Also write a stable "latest" pointer.
    let _ = std::fs::write(
        state.dir.join("triage-latest.json"),
        serde_json::to_vec_pretty(&summary)?,
    );

    if print {
        print_summary(&summary, cpu_busy_pct);
    }
    Ok(summary)
}

fn score_process(
    st: &proc::ProcStat,
    exe: &str,
    deleted: bool,
    cwd: &str,
    cmd: &[String],
    cpu_pct: f64,
    out_conns: &[String],
) -> (u32, Option<Label>) {
    let mut score = 0u32;
    let mut miner = false;

    if deleted {
        score += 40;
    }
    if proc::is_suspicious_path(exe) || (!cwd.is_empty() && proc::is_suspicious_path(cwd)) {
        score += 40;
    }
    // A non-web process executing from a webroot is a strong backdoor signal.
    if proc::is_webroot_path(exe) && !is_web_worker(&st.comm, exe) {
        score += 30;
    }
    // comm vs exe basename mismatch (name spoofing).
    if let Some(base) = exe.rsplit('/').next()
        && !base.is_empty()
        && !st.comm.is_empty()
        && !base.starts_with(&st.comm)
    {
        score += 20;
    }
    // kernel-thread-looking name with a real userspace exe.
    if st.comm.starts_with('[') && !exe.is_empty() && st.ppid != 2 {
        score += 40;
        miner = true;
    }
    // outbound to a mining/C2 port.
    for c in out_conns {
        if let Some(port) = c.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
            && BAD_OUT_PORTS.contains(&port)
        {
            score += 40;
            miner = true;
        }
    }
    // miner hints in cmdline/argv.
    let joined = cmd.join(" ").to_ascii_lowercase();
    if MINER_HINTS.iter().any(|h| joined.contains(h)) {
        score += 50;
        miner = true;
    }
    // sustained high CPU from a non-service exe.
    if cpu_pct > 80.0 {
        score += 15;
    }

    let hint = if miner {
        Some(Label::Miner)
    } else if is_web_worker(&st.comm, exe) && cpu_pct > 70.0 && !out_conns.is_empty() {
        Some(Label::PhpBot)
    } else {
        None
    };
    (score, hint)
}

fn is_web_worker(comm: &str, exe: &str) -> bool {
    const NAMES: &[&str] = &["php-fpm", "lsphp", "httpd", "apache2", "php"];
    NAMES.iter().any(|n| comm.contains(n) || exe.contains(n))
}

fn decide_label(
    suspects: &[Suspect],
    conns: &[netstat::Conn],
    disk_pct: u8,
    inode_pct: u8,
) -> Label {
    let mut labels: Vec<Label> = suspects.iter().filter_map(|s| s.label_hint).collect();

    if disk_pct >= 98 || inode_pct >= 98 {
        labels.push(Label::DiskFull);
    }

    // Many inbound established web connections concentrated in few IPs → L7.
    let per_remote = netstat::conns_per_remote(conns);
    if per_remote.values().any(|&n| n > 80) {
        labels.push(Label::DdosL7);
    }

    labels.sort_by_key(|l| l.as_str());
    labels.dedup_by_key(|l| l.as_str());
    match labels.len() {
        0 => Label::Unknown,
        1 => labels[0],
        _ => Label::Mixed,
    }
}

fn scan_persistence() -> Vec<String> {
    let mut hits = Vec::new();
    if Path::new("/etc/ld.so.preload").exists()
        && let Ok(c) = std::fs::read_to_string("/etc/ld.so.preload")
        && !c.trim().is_empty()
    {
        hits.push(format!("/etc/ld.so.preload: {}", c.trim()));
    }
    for path in proc::persistence_files() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                if is_suspicious_cron(line) {
                    hits.push(format!(
                        "{}: {}",
                        path.display(),
                        util::ellipsize(line.trim(), 100)
                    ));
                }
            }
        }
    }
    hits.truncate(30);
    hits
}

fn is_suspicious_cron(line: &str) -> bool {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return false;
    }
    const BAD: &[&str] = &[
        "curl",
        "wget",
        "tftp",
        "base64 -d",
        "base64 --decode",
        "/dev/tcp/",
        "python -c",
        "perl -e",
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "/tmp/",
        "/dev/shm/",
        ".onion",
        "pastebin",
        "transfer.sh",
    ];
    BAD.iter().any(|b| l.contains(b))
}

fn disk_usage(path: &str) -> (u8, u8) {
    use nix::sys::statvfs::statvfs;
    match statvfs(path) {
        Ok(s) => {
            let blocks = s.blocks() as f64;
            let bavail = s.blocks_available() as f64;
            let disk = if blocks > 0.0 {
                (100.0 * (1.0 - bavail / blocks)).round() as u8
            } else {
                0
            };
            let files = s.files() as f64;
            let favail = s.files_available() as f64;
            let inode = if files > 0.0 {
                (100.0 * (1.0 - favail / files)).round() as u8
            } else {
                0
            };
            (disk.min(100), inode.min(100))
        }
        Err(_) => (0, 0),
    }
}

fn print_summary(s: &TriageSummary, cpu_busy_pct: f64) {
    println!("== sn triage ==");
    println!(
        "label: {}   load1: {:.2}   cpu_busy: {:.0}%   ram: {:.0}%   disk: {}%   inode: {}%",
        s.label, s.load1, cpu_busy_pct, s.mem_used_pct, s.disk_pct, s.inode_pct
    );
    println!();
    println!(
        "{:<7} {:>6} {:<14} {:<26} {:<10} {:>5}",
        "PID", "CPU%", "COMM", "EXE", "USER", "SCORE"
    );
    for p in &s.top_processes {
        println!(
            "{:<7} {:>6.1} {:<14} {:<26} {:<10} {:>5}",
            p.pid,
            p.cpu_pct,
            util::ellipsize(&p.comm, 14),
            util::ellipsize(
                &if p.deleted_exe {
                    format!("{} (deleted)", p.exe)
                } else {
                    p.exe.clone()
                },
                26
            ),
            util::ellipsize(&p.user, 10),
            p.score
        );
        if !p.out_conns.is_empty() {
            println!(
                "        out: {}",
                util::ellipsize(&p.out_conns.join(", "), 80)
            );
        }
    }
    if !s.persistence.is_empty() {
        println!("\npersistence:");
        for h in &s.persistence {
            println!("  - {h}");
        }
    }
    println!("\nnext: review above, then `sn contain` to throttle suspects (reversible).");
}
