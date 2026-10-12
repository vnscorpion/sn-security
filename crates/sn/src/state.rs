//! On-disk agent state under `/var/lib/sn` (override with `SN_STATE_DIR`).
//!
//! Storage is split into small, independently-written files so a crash or
//! power loss cannot corrupt a single giant `state.json`. Every write is
//! tmp-file + `fsync` + atomic `rename`. The report queue is a bounded spool
//! directory, one file per cycle, rather than an in-memory list.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use snsec_common::schema::{DesiredRef, Mode};

/// Max bytes of queued reports to keep before dropping the oldest.
const QUEUE_CAP_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct State {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    pub epoch: u64,
    /// Next report sequence number to assign.
    pub next_report_seq: u64,
    /// Highest desired `(epoch, seq)` applied — replay defence.
    pub applied_desired: DesiredRef,
    /// Highest desired seq *seen* (even if not applied), for monotonicity.
    pub last_desired: DesiredRef,
    /// Mode pushed from the hub, overriding the local config when set. `None`
    /// means "use `[watch] mode` from agent.toml".
    #[serde(default)]
    pub mode_override: Option<Mode>,
    /// Highest `jobs_seq` the agent has already executed.
    #[serde(default)]
    pub last_jobs_seq: u64,
    /// Consecutive cycles that read no log lines although web connections were
    /// open. One quiet cycle is normal (idle keep-alives); a streak is a symptom.
    #[serde(default)]
    pub blind_streak: u32,
    /// Consecutive cycles with CPU at or above `cpu_alert_pct`.
    #[serde(default)]
    pub cpu_streak: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Offset {
    pub dev: u64,
    pub inode: u64,
    pub pos: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strike {
    pub count: u32,
    pub last_ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBan {
    pub reason: String,
    pub expires_ts: i64,
    pub strike: u32,
    pub layer: String,
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("state file has no parent")?;
    fs::create_dir_all(dir).ok();
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    // Best effort: fsync the directory so the rename is durable.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn load_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> T {
    fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

impl State {
    /// Open (and create) the state directory.
    pub fn open() -> Result<State> {
        let dir = std::env::var_os("SN_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/sn"));
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating state dir {}", dir.display()))?;
        fs::create_dir_all(dir.join("queue")).ok();
        fs::create_dir_all(dir.join("quarantine")).ok();
        Ok(State { dir })
    }

    /// Open a state store at an explicit path (tests and tools).
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by tests and external tools")
    )]
    pub fn at(dir: PathBuf) -> State {
        State { dir }
    }

    fn p(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    // ---- meta -------------------------------------------------------------

    pub fn meta(&self) -> Meta {
        load_json(&self.p("meta.json"))
    }

    pub fn save_meta(&self, m: &Meta) -> Result<()> {
        atomic_write(&self.p("meta.json"), &serde_json::to_vec_pretty(m)?)
    }

    // ---- offsets ----------------------------------------------------------

    pub fn offsets(&self) -> HashMap<String, Offset> {
        load_json(&self.p("offsets.json"))
    }

    pub fn save_offsets(&self, o: &HashMap<String, Offset>) -> Result<()> {
        atomic_write(&self.p("offsets.json"), &serde_json::to_vec(o)?)
    }

    // ---- cpu counters and bot baseline ------------------------------------

    pub fn cpu_sample(&self) -> crate::watch::cpu::Sample {
        load_json(&self.p("cpu.json"))
    }

    pub fn save_cpu_sample(&self, s: &crate::watch::cpu::Sample) -> Result<()> {
        atomic_write(&self.p("cpu.json"), &serde_json::to_vec(s)?)
    }

    pub fn bot_baseline(&self) -> crate::watch::bots::BotBaseline {
        load_json(&self.p("bots.json"))
    }

    pub fn save_bot_baseline(&self, b: &crate::watch::bots::BotBaseline) -> Result<()> {
        atomic_write(&self.p("bots.json"), &serde_json::to_vec(b)?)
    }

    // ---- strikes ----------------------------------------------------------

    pub fn strikes(&self) -> HashMap<String, Strike> {
        load_json(&self.p("strikes.json"))
    }

    pub fn save_strikes(&self, s: &HashMap<String, Strike>) -> Result<()> {
        atomic_write(&self.p("strikes.json"), &serde_json::to_vec(s)?)
    }

    // ---- active bans ------------------------------------------------------

    pub fn bans(&self) -> HashMap<String, ActiveBan> {
        load_json(&self.p("bans.json"))
    }

    pub fn save_bans(&self, b: &HashMap<String, ActiveBan>) -> Result<()> {
        atomic_write(&self.p("bans.json"), &serde_json::to_vec(b)?)
    }

    // ---- report queue (spool) --------------------------------------------

    /// Push a serialized report body into the spool, enforcing the byte cap by
    /// dropping the oldest files. Returns the assigned sequence number.
    pub fn queue_report(&self, seq: u64, body_json: &[u8]) -> Result<()> {
        let qdir = self.p("queue");
        fs::create_dir_all(&qdir).ok();
        let file = qdir.join(format!("{seq:020}.json"));
        atomic_write(&file, body_json)?;
        self.trim_queue(&qdir)?;
        Ok(())
    }

    fn trim_queue(&self, qdir: &Path) -> Result<()> {
        let mut entries: Vec<(PathBuf, u64)> = fs::read_dir(qdir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let len = e.metadata().ok()?.len();
                        Some((e.path(), len))
                    })
                    .collect()
            })
            .unwrap_or_default();
        entries.sort_by(|a, b| a.0.cmp(&b.0)); // filenames are zero-padded seq
        let mut total: u64 = entries.iter().map(|(_, l)| *l).sum();
        let mut i = 0;
        while total > QUEUE_CAP_BYTES && i < entries.len() {
            let _ = fs::remove_file(&entries[i].0);
            total -= entries[i].1;
            i += 1;
        }
        Ok(())
    }

    /// All queued report files, oldest first, as `(path, seq)`.
    pub fn queued(&self) -> Vec<(PathBuf, u64)> {
        let qdir = self.p("queue");
        let mut v: Vec<(PathBuf, u64)> = fs::read_dir(&qdir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let name = e.file_name().into_string().ok()?;
                        let seq: u64 = name.trim_end_matches(".json").parse().ok()?;
                        Some((e.path(), seq))
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by_key(|(_, s)| *s);
        v
    }

    pub fn drop_queued(&self, path: &Path) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state() -> (tempfile::TempDir, State) {
        let d = tempfile::tempdir().unwrap();
        let s = State::at(d.path().to_path_buf());
        fs::create_dir_all(s.dir.join("queue")).unwrap();
        (d, s)
    }

    #[test]
    fn meta_roundtrip() {
        let (_g, s) = tmp_state();
        let mut m = s.meta();
        assert_eq!(m.next_report_seq, 0);
        m.next_report_seq = 7;
        m.epoch = 2;
        s.save_meta(&m).unwrap();
        assert_eq!(s.meta().next_report_seq, 7);
        assert_eq!(s.meta().epoch, 2);
    }

    #[test]
    fn queue_fifo_and_drop() {
        let (_g, s) = tmp_state();
        for seq in 0..5u64 {
            s.queue_report(seq, format!("body{seq}").as_bytes())
                .unwrap();
        }
        let q = s.queued();
        assert_eq!(q.len(), 5);
        assert_eq!(q[0].1, 0);
        assert_eq!(q[4].1, 4);
        s.drop_queued(&q[0].0);
        assert_eq!(s.queued().len(), 4);
    }
}
