//! `sn evidence` — a read-only snapshot of what is wrong on the box, for the hub
//! (and the AI behind it) to read. It reuses `triage` for the processes and adds
//! what a human responder checks next: shell start-up files and cron for a
//! foothold, executables dropped in temp directories and hidden home dirs,
//! recent SSH logins, what listens on the network, and who can log in.
//!
//! Nothing here changes the system. Every walk is bounded in depth, entries and
//! opened files, and symlinks are never followed, so a hostile directory tree
//! cannot make it run long or leave the places it means to look at.

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Result;
use snsec_common::schema::{EvFile, EvListener, EvPersist, EvProc, EvUser, Evidence};

use crate::evidence_parse as parse;
use crate::state::State;
use crate::sys::{netstat, proc};
use crate::triage;
use crate::util;

const MAX_PROCS: usize = 15;
const MAX_TEMP_FILES: usize = 40;
const MAX_PERSIST: usize = 80;
const MAX_LISTENERS: usize = 40;
/// Largest start-up file read whole.
const RC_MAX_BYTES: u64 = 256 * 1024;
/// How much of the end of the auth log is read.
const AUTH_TAIL_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const RC_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
];
/// Temp roots and how deep to look in each.
const TEMP_ROOTS: &[(&str, usize)] = &[("/dev/shm", 3), ("/tmp", 2), ("/var/tmp", 2)];

fn latest_path(state: &State) -> PathBuf {
    state.dir.join("evidence-latest.json")
}

/// The most recent snapshot this agent took, if any.
pub fn latest(state: &State) -> Option<Evidence> {
    std::fs::read(latest_path(state))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// A fresh allowance for one directory tree. Each temp directory and each home
/// gets its own, so a flood of files in one place (or one account) cannot use up
/// the allowance meant for the others.
struct Budget {
    entries: usize,
    opens: usize,
}

impl Budget {
    fn temp_root() -> Self {
        Budget {
            entries: 8_000,
            opens: 1_500,
        }
    }

    fn home() -> Self {
        Budget {
            entries: 2_000,
            opens: 400,
        }
    }
}

/// Programs kept per scope before the global sort, so one scope cannot crowd out
/// the others.
const PER_SCOPE_FILES: usize = 15;
/// Foothold lines kept per account.
const PER_USER_PERSIST: usize = 8;

/// Take a snapshot, keep it in the state directory, and return it.
pub fn collect(state: &State) -> Result<Evidence> {
    let triage = triage::run(state, false)?;

    let processes: Vec<EvProc> = triage
        .top_processes
        .iter()
        .take(MAX_PROCS)
        .map(|p| {
            let ppid = proc::read_stat(p.pid).map_or(0, |s| s.ppid);
            let cmd = proc::cmdline(p.pid).join(" ");
            let lower = cmd.to_ascii_lowercase();
            let miner_hint = triage::MINER_HINTS.iter().any(|h| lower.contains(h))
                || p.out_conns.iter().any(|c| {
                    c.rsplit(':')
                        .next()
                        .and_then(|port| port.parse::<u16>().ok())
                        .is_some_and(|port| triage::BAD_OUT_PORTS.contains(&port))
                });
            EvProc {
                pid: p.pid,
                starttime: p.starttime,
                user: p.user.clone(),
                comm: util::ellipsize(&p.comm, 40),
                exe: util::ellipsize(&p.exe, 200),
                exe_deleted: p.deleted_exe,
                // Passwords typed on a command line must not travel to a model.
                cmdline: util::ellipsize(&parse::redact(&cmd), 240),
                cpu_pct: p.cpu_pct,
                out_conns: p.out_conns.iter().take(8).cloned().collect(),
                score: p.score,
                // Real kernel threads have no executable: a kernel-thread name on
                // a real program is a disguise.
                masquerade: parse::looks_like_kthread(&p.comm)
                    && !p.exe.is_empty()
                    && ppid != 2
                    && p.pid != 2,
                miner_hint,
            }
        })
        .collect();

    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let uid_min =
        parse::parse_uid_min(&std::fs::read_to_string("/etc/login.defs").unwrap_or_default());
    let admins = parse::admin_accounts(
        &passwd,
        &std::fs::read_to_string("/etc/group").unwrap_or_default(),
    );
    let mut shell_users: Vec<EvUser> = parse::parse_passwd(&passwd, uid_min)
        .into_iter()
        .filter(|u| Path::new(&u.home).is_dir())
        .collect();
    // Administrator = can use sudo. (An account being the only regular one proves
    // nothing: on a hosting server it is a customer, and the one most likely hacked.)
    for u in &mut shell_users {
        u.admin = admins.contains(&u.name);
    }

    let mut persistence = triage_persistence(&triage.persistence);
    persistence.extend(home_persistence(&shell_users));
    persistence.truncate(MAX_PERSIST);

    let temp_files = temp_files(&shell_users);

    let ev = Evidence {
        at: util::now_secs(),
        label: triage.label.clone(),
        load1: triage.load1,
        processes,
        persistence,
        temp_files,
        ssh_logins: ssh_logins(),
        listeners: listeners(),
        shell_users,
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&ev) {
        let _ = std::fs::write(latest_path(state), bytes);
    }
    Ok(ev)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Triage already finds cron and `ld.so.preload` hits as `path: line` strings.
fn triage_persistence(hits: &[String]) -> Vec<EvPersist> {
    hits.iter()
        .map(|h| {
            let (path, line) = h.split_once(": ").unwrap_or(("", h));
            let kind = if path.contains("ld.so.preload") {
                "ld_preload"
            } else {
                "cron"
            };
            EvPersist {
                kind: kind.into(),
                path: util::ellipsize(path, 200),
                line: util::ellipsize(&parse::redact(line), 240),
                sha256: parse::line_sha(line),
                reason: "suspicious scheduled or preloaded entry".into(),
                ..EvPersist::default()
            }
        })
        .collect()
}

/// A small regular file's text. A symlink, a device or a big file is skipped.
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > RC_MAX_BYTES {
        return None;
    }
    // Lossy: a single stray byte must not hide a whole start-up file from view.
    let mut bytes = Vec::new();
    open_regular(path)?
        .take(RC_MAX_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn home_persistence(users: &[EvUser]) -> Vec<EvPersist> {
    let mut out = Vec::new();
    // root's start-up files too: that is where miners like to persist.
    let mut homes: Vec<(String, String)> = vec![("root".into(), "/root".into())];
    homes.extend(users.iter().map(|u| (u.name.clone(), u.home.clone())));
    for (user, home) in homes {
        let home = Path::new(&home);
        let mut found: Vec<EvPersist> = Vec::new();
        for name in RC_FILES {
            let path = home.join(name);
            if let Some(text) = read_small(&path) {
                found.extend(parse::scan_rc(&text, &path.to_string_lossy(), &user, 10));
            }
        }
        let keys = home.join(".ssh/authorized_keys");
        if let Some(text) = read_small(&keys) {
            found.extend(parse::scan_authorized_keys(
                &text,
                &keys.to_string_lossy(),
                &user,
                10,
            ));
        }
        found.truncate(PER_USER_PERSIST);
        out.extend(found);
    }
    out
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Open a file for reading in a directory a user controls: never through a
/// symlink (`O_NOFOLLOW`) and never blocking on a FIFO or device someone swapped
/// in after the check (`O_NONBLOCK`; it has no effect on a regular file). The
/// handle is then checked to be a regular file.
fn open_regular(path: &Path) -> Option<File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}

fn head_is_elf(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    open_regular(path)
        .and_then(|mut f| f.read_exact(&mut buf).ok())
        .is_some()
        && parse::is_elf(&buf)
}

fn ev_file(path: &Path, meta: &Metadata, elf: bool) -> EvFile {
    EvFile {
        path: util::ellipsize(&path.to_string_lossy(), 300),
        size: meta.len(),
        owner: proc::username(meta.uid()),
        mode: meta.permissions().mode() & 0o7777,
        mtime: meta.mtime(),
        elf,
        executable: meta.permissions().mode() & 0o111 != 0,
    }
}

/// Walk `root` to `max_depth`, never following symlinks, calling `visit` for each
/// regular file. `descend` says whether to enter a directory.
fn walk(
    root: &Path,
    max_depth: usize,
    budget: &mut Budget,
    descend: &dyn Fn(&str, usize) -> bool,
    visit: &mut dyn FnMut(&Path, &Metadata, &mut Budget),
) {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            if budget.entries == 0 {
                return;
            }
            budget.entries -= 1;
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if ft.is_symlink() || ft.is_socket() || ft.is_fifo() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if ft.is_dir() {
                if depth + 1 < max_depth && descend(&name, depth + 1) {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file()
                && let Ok(meta) = entry.metadata()
            {
                visit(&path, &meta, budget);
            }
        }
    }
}

/// Sort strongest first and keep the best `n`.
fn best(mut v: Vec<EvFile>, n: usize) -> Vec<EvFile> {
    v.sort_by(|a, b| {
        b.elf
            .cmp(&a.elf)
            .then(b.executable.cmp(&a.executable))
            .then(b.mtime.cmp(&a.mtime))
            .then_with(|| a.path.cmp(&b.path))
    });
    v.dedup_by(|a, b| a.path == b.path);
    v.truncate(n);
    v
}

/// Executables and unusual files in temp directories, and compiled programs in
/// users' home directories (hidden dirs and the top level), strongest first.
/// Every temp directory and every home is walked with its own allowance and
/// contributes at most `PER_SCOPE_FILES`, so a flood in one place cannot hide
/// what is somewhere else.
fn temp_files(users: &[EvUser]) -> Vec<EvFile> {
    let mut found: Vec<EvFile> = Vec::new();

    for (root, depth) in TEMP_ROOTS {
        let skip_dir = |name: &str, _d: usize| {
            !(name.starts_with("systemd-private-")
                || name == ".X11-unix"
                || name == ".ICE-unix"
                || name == ".font-unix"
                || name == ".Test-unix"
                || name == ".XIM-unix")
        };
        let mut scope: Vec<EvFile> = Vec::new();
        let mut budget = Budget::temp_root();
        walk(
            Path::new(root),
            *depth,
            &mut budget,
            &skip_dir,
            &mut |p, m, b| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let executable = m.permissions().mode() & 0o111 != 0;
                let hidden = name.starts_with('.');
                let elf = if m.len() >= 64 && m.len() <= 200 * 1024 * 1024 && b.opens > 0 {
                    b.opens -= 1;
                    head_is_elf(p)
                } else {
                    false
                };
                if elf || executable || (hidden && m.len() > 0) {
                    scope.push(ev_file(p, m, elf));
                }
            },
        );
        found.extend(best(scope, PER_SCOPE_FILES));
    }

    // Compiled programs in homes. Top-level files, hidden dirs and non-trivial
    // directories (not the web root or caches) are looked at; the web root is
    // the hunt's job.
    for u in users.iter().take(30) {
        let home = Path::new(&u.home);
        let descend = |name: &str, _d: usize| !parse::skip_home_dir(name);
        let mut scope: Vec<EvFile> = Vec::new();
        let mut budget = Budget::home();
        walk(home, 3, &mut budget, &descend, &mut |p, m, b| {
            if m.len() < 64 || m.len() > 200 * 1024 * 1024 || b.opens == 0 {
                return;
            }
            b.opens -= 1;
            if head_is_elf(p) {
                scope.push(ev_file(p, m, true));
            }
        });
        found.extend(best(scope, PER_SCOPE_FILES));
    }

    best(found, MAX_TEMP_FILES)
}

// ---------------------------------------------------------------------------
// Logins and listeners
// ---------------------------------------------------------------------------

fn ssh_logins() -> Vec<snsec_common::schema::EvLogin> {
    // The newest of the usual auth logs.
    let best = ["/var/log/auth.log", "/var/log/secure"]
        .iter()
        .filter_map(|p| {
            let m = std::fs::metadata(p).ok()?;
            Some((m.modified().ok()?, *p))
        })
        .max_by_key(|(t, _)| *t)
        .map(|(_, p)| p);
    let Some(path) = best else {
        return Vec::new();
    };
    let Ok(mut f) = File::open(path) else {
        return Vec::new();
    };
    let len = f.metadata().map_or(0, |m| m.len());
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(AUTH_TAIL_BYTES)));
    let mut bytes = Vec::new();
    let _ = f.take(AUTH_TAIL_BYTES).read_to_end(&mut bytes);
    parse::parse_ssh_logins(&String::from_utf8_lossy(&bytes))
}

fn listeners() -> Vec<EvListener> {
    let conns = netstat::all();
    let listening: Vec<&netstat::Conn> = conns
        .iter()
        .filter(|c| c.state == netstat::ST_LISTEN && !c.local.is_loopback())
        .collect();
    if listening.is_empty() {
        return Vec::new();
    }
    let wanted: std::collections::HashSet<u64> = listening.iter().map(|c| c.inode).collect();
    // Which process owns each listening socket.
    let mut owner: std::collections::HashMap<u64, (i32, String)> = std::collections::HashMap::new();
    for pid in proc::list_pids() {
        for ino in proc::socket_inodes(pid) {
            if wanted.contains(&ino) && !owner.contains_key(&ino) {
                let comm = proc::read_stat(pid).map(|s| s.comm).unwrap_or_default();
                owner.insert(ino, (pid, comm));
            }
        }
    }
    let mut out: Vec<EvListener> = listening
        .iter()
        .map(|c| {
            let (pid, comm) = owner.get(&c.inode).cloned().unwrap_or((0, String::new()));
            EvListener {
                port: c.local_port,
                addr: c.local.to_string(),
                comm: util::ellipsize(&comm, 40),
                pid,
            }
        })
        .collect();
    out.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.addr.cmp(&b.addr)));
    out.dedup_by(|a, b| a.port == b.port && a.comm == b.comm);
    out.truncate(MAX_LISTENERS);
    out
}

/// `sn evidence`: print a short readable summary of a fresh snapshot.
pub fn print(ev: &Evidence) {
    println!("== sn evidence ==");
    println!("label: {}   load1: {:.2}", ev.label, ev.load1);
    println!("processes: {}", ev.processes.len());
    for p in &ev.processes {
        println!(
            "  pid {} ({}) user={} cpu={:.0}% exe={}{}{}",
            p.pid,
            p.comm,
            p.user,
            p.cpu_pct,
            p.exe,
            if p.exe_deleted { " (deleted)" } else { "" },
            if p.masquerade { "  [disguised]" } else { "" }
        );
    }
    println!("persistence: {}", ev.persistence.len());
    for p in ev.persistence.iter().take(20) {
        println!("  [{}] {}:{} {}", p.kind, p.path, p.line_no, p.line);
    }
    println!("temp/hidden programs: {}", ev.temp_files.len());
    for f in ev.temp_files.iter().take(20) {
        println!(
            "  {} owner={} elf={} exec={}",
            f.path, f.owner, f.elf, f.executable
        );
    }
    println!("ssh logins: {}", ev.ssh_logins.len());
    for l in ev.ssh_logins.iter().rev().take(10) {
        println!("  {} {} from {} ({})", l.when, l.user, l.ip, l.method);
    }
    println!("listening on non-loopback: {}", ev.listeners.len());
    for l in &ev.listeners {
        println!("  {}:{} {}", l.addr, l.port, l.comm);
    }
}
