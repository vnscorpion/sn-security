//! Structured, append-only undo log at `<state>/undo.jsonl`.
//!
//! Unlike a generated `undo.sh`, this is never executed as a shell script
//! (the machine is, by assumption, compromised, and file names are attacker
//! controlled). Each op is a typed record replayed by `sn undo` through the
//! same safe syscalls/`nft` calls that created it. Quarantine is **not**
//! restored by a plain `undo` — that needs `sn restore <id>` explicitly.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::sys::{cgroup, fw};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum UndoOp {
    /// Release the cgroup jail (thaw + move everything back + rmdir).
    CgroupRelease,
    /// Remove a ban element we added.
    Unban { key: String },
    /// Remove the maintenance include we added for a vhost (path recorded).
    MaintenanceOff { path: String },
}

fn undo_path(state_dir: &Path) -> PathBuf {
    state_dir.join("undo.jsonl")
}

/// Append one op to the log.
pub fn record(state_dir: &Path, op: &UndoOp) -> Result<()> {
    let path = undo_path(state_dir);
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let line = serde_json::to_string(op)?;
    writeln!(f, "{line}").with_context(|| format!("append {}", path.display()))?;
    Ok(())
}

/// Load all recorded ops (oldest first).
pub fn load(state_dir: &Path) -> Vec<UndoOp> {
    let path = undo_path(state_dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Replay every op in reverse order, then clear the log. Returns the number of
/// ops applied. Individual failures are logged and do not abort the rest.
pub fn run_all(state_dir: &Path) -> Result<usize> {
    let ops = load(state_dir);
    let mut n = 0usize;
    for op in ops.iter().rev() {
        match apply(op) {
            Ok(()) => n += 1,
            Err(e) => eprintln!("undo: op {op:?} failed: {e:#}"),
        }
    }
    let _ = std::fs::remove_file(undo_path(state_dir));
    Ok(n)
}

fn apply(op: &UndoOp) -> Result<()> {
    match op {
        UndoOp::CgroupRelease => cgroup::release(),
        UndoOp::Unban { key } => fw::apply_bans(&[], std::slice::from_ref(key)),
        UndoOp::MaintenanceOff { path } => {
            let _ = std::fs::remove_file(path);
            Ok(())
        }
    }
}
