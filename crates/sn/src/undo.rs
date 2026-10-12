//! Structured, append-only undo log at `<state>/undo.jsonl`.
//!
//! Unlike a generated `undo.sh`, this is never executed as a shell script
//! (the machine is, by assumption, compromised, and file names are attacker
//! controlled). Each op is a typed record replayed by `sn undo` through the
//! same safe syscalls/`nft` calls that created it. Quarantine is **not**
//! restored by a plain `undo` — that needs `sn restore <id>` explicitly.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::evidence_parse::is_safe_username;
use crate::sys::{cgroup, fw};
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum UndoOp {
    /// Release the cgroup jail (thaw + move everything back + rmdir).
    CgroupRelease,
    /// Remove a ban element we added.
    Unban { key: String },
    /// Remove the maintenance include we added for a vhost (path recorded).
    MaintenanceOff { path: String },
    /// Give a user back the login shell `sn remediate` took away.
    RestoreShell { user: String, shell: String },
    /// Put back a start-up file edited by `sn remediate` from its backup.
    RestoreFile {
        path: String,
        backup: String,
        uid: u32,
    },
    /// Enable and start a service `sn remediate` disabled.
    EnableService { unit: String },
}

fn undo_path(state_dir: &Path) -> PathBuf {
    state_dir.join("undo.jsonl")
}

/// Undo records of incident-response actions (`sn remediate`) live apart from
/// the containment log: a routine `sn undo` after a jail is released must not
/// quietly put an attacker's start-up line or login shell back.
fn remediation_path(state_dir: &Path) -> PathBuf {
    state_dir.join("remediation-undo.jsonl")
}

fn is_remediation(op: &UndoOp) -> bool {
    matches!(
        op,
        UndoOp::RestoreShell { .. } | UndoOp::RestoreFile { .. } | UndoOp::EnableService { .. }
    )
}

/// Append one op to the log it belongs to.
pub fn record(state_dir: &Path, op: &UndoOp) -> Result<()> {
    let path = if is_remediation(op) {
        remediation_path(state_dir)
    } else {
        undo_path(state_dir)
    };
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let line = serde_json::to_string(op)?;
    writeln!(f, "{line}").with_context(|| format!("append {}", path.display()))?;
    Ok(())
}

fn load_from(path: &Path) -> Vec<UndoOp> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Replay `ops` in reverse order and rewrite `log` to keep only those that
/// failed, so a record is never lost because one replay went wrong. Returns the
/// number applied.
fn replay(ops: &[UndoOp], log: &Path, state_dir: &Path) -> usize {
    let mut n = 0usize;
    let mut failed: Vec<&UndoOp> = Vec::new();
    for op in ops.iter().rev() {
        match apply(op, state_dir) {
            Ok(()) => n += 1,
            Err(e) => {
                eprintln!("undo: op {op:?} failed: {e:#}");
                failed.push(op);
            }
        }
    }
    if failed.is_empty() {
        let _ = std::fs::remove_file(log);
    } else {
        failed.reverse(); // back to oldest first
        let text: String = failed
            .iter()
            .filter_map(|o| serde_json::to_string(o).ok())
            .map(|l| l + "\n")
            .collect();
        let tmp = log.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, log);
        }
    }
    n
}

/// Reverse the containment actions (jail, bans). Does not touch what
/// `sn remediate` did; see [`run_remediation`].
pub fn run_all(state_dir: &Path) -> Result<usize> {
    let log = undo_path(state_dir);
    Ok(replay(&load_from(&log), &log, state_dir))
}

/// Reverse the incident-response actions: restore shells and start-up files,
/// re-enable services. Only on explicit request (`sn undo --remediation`).
pub fn run_remediation(state_dir: &Path) -> Result<usize> {
    let log = remediation_path(state_dir);
    Ok(replay(&load_from(&log), &log, state_dir))
}

fn systemctl(args: &[&str]) -> Result<()> {
    let sc = util::find_bin("systemctl").context("systemctl not found")?;
    let status = Command::new(sc)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .context("running systemctl")?;
    if !status.success() {
        bail!("systemctl {} exited with {status}", args.join(" "));
    }
    Ok(())
}

fn apply(op: &UndoOp, state_dir: &Path) -> Result<()> {
    match op {
        UndoOp::CgroupRelease => cgroup::release(),
        UndoOp::Unban { key } => fw::apply_bans(&[], std::slice::from_ref(key)),
        UndoOp::MaintenanceOff { path } => {
            let _ = std::fs::remove_file(path);
            Ok(())
        }
        UndoOp::RestoreShell { user, shell } => {
            // The log is a file on a machine that may be compromised: check what
            // it says before it reaches a command line.
            if !is_safe_username(user)
                || !shell.starts_with('/')
                || shell.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                bail!("refusing to restore an odd shell record");
            }
            let usermod = util::find_bin("usermod").context("usermod not found")?;
            let status = Command::new(usermod)
                .args(["-s", shell, user])
                .stdin(Stdio::null())
                .status()?;
            if !status.success() {
                bail!("usermod exited with {status}");
            }
            Ok(())
        }
        UndoOp::RestoreFile { path, backup, uid } => {
            // Only a backup inside our own directory, and only onto the file
            // that still belongs to the same user, through O_NOFOLLOW.
            let vault = state_dir.join("rc-backups");
            if !Path::new(backup).starts_with(&vault) || backup.contains("..") {
                bail!("refusing a backup outside the rc-backups directory");
            }
            if !is_rc_target(Path::new(path), *uid) {
                bail!("refusing {path}: not a start-up file in that user's home");
            }
            let data = std::fs::read(backup).context("reading the backup")?;
            rewrite_users_file(Path::new(path), &data, *uid)
        }
        UndoOp::EnableService { unit } => {
            if !snsec_common::ai::ALLOWED_UNITS.contains(&unit.as_str()) {
                bail!("refusing a service outside the allow-list");
            }
            systemctl(&["enable", "--now", unit])
        }
    }
}

/// `sn remediate` edits only `<home>/<start-up file>` of the file's owner (the
/// home of root is `/root`): a record naming anything else is not opened.
fn is_rc_target(path: &Path, uid: u32) -> bool {
    let name_ok = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| crate::evidence::RC_FILES.contains(&n));
    let home = if uid == 0 {
        Some(PathBuf::from("/root"))
    } else {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.dir)
    };
    name_ok
        && !path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        && home.is_some_and(|h| path.parent() == Some(h.as_path()))
}

/// Put `data` back into `path`, which must still be `uid`'s own regular file
/// with a single name. `O_NONBLOCK`: a FIFO the user left in its place makes the
/// open fail at once instead of blocking this record and every one behind it
/// (on the regular file it is checked to be, the flag changes nothing).
fn rewrite_users_file(path: &Path, data: &[u8], uid: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = f.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1 {
        bail!(
            "{} is no longer the user's own regular file",
            path.display()
        );
    }
    f.set_len(0)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn me() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    #[test]
    fn a_fifo_in_place_of_the_file_fails_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(".bashrc");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let (tx, rx) = mpsc::channel();
        let p = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(rewrite_users_file(&p, b"x", me()).is_err());
        });
        // Without O_NONBLOCK the open would wait for a reader forever.
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(true));
    }

    #[test]
    fn only_the_users_own_single_link_regular_file_is_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        std::fs::write(&rc, "edited\n").unwrap();
        rewrite_users_file(&rc, b"original\n", me()).unwrap();
        assert_eq!(std::fs::read(&rc).unwrap(), b"original\n");

        // Someone else's file.
        assert!(rewrite_users_file(&rc, b"x", me().wrapping_add(1)).is_err());
        // A second name for it.
        std::fs::hard_link(&rc, dir.path().join("other")).unwrap();
        assert!(rewrite_users_file(&rc, b"x", me()).is_err());
        assert_eq!(std::fs::read(&rc).unwrap(), b"original\n");
        // A symlink in its place.
        let target = dir.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.path().join(".profile");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(rewrite_users_file(&link, b"x", me()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn a_record_must_name_a_start_up_file_in_the_owners_home() {
        assert!(is_rc_target(Path::new("/root/.bashrc"), 0));
        assert!(!is_rc_target(Path::new("/etc/passwd"), 0));
        assert!(!is_rc_target(Path::new("/tmp/.bashrc"), 0));
        assert!(!is_rc_target(Path::new("/root/../etc/.bashrc"), 0));
        assert!(!is_rc_target(Path::new("/root/sub/.bashrc"), 0));
    }
}
