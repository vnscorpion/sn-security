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
            let data = std::fs::read(backup).context("reading the backup")?;
            let mut f = OpenOptions::new()
                .write(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(path)
                .with_context(|| format!("opening {path}"))?;
            let meta = f.metadata()?;
            if !meta.is_file() || meta.uid() != *uid {
                bail!("{path} is no longer the user's regular file");
            }
            f.set_len(0)?;
            f.write_all(&data)?;
            Ok(())
        }
        UndoOp::EnableService { unit } => {
            if !snsec_common::ai::ALLOWED_UNITS.contains(&unit.as_str()) {
                bail!("refusing a service outside the allow-list");
            }
            systemctl(&["enable", "--now", unit])
        }
    }
}
