//! On-disk agent state under `/var/lib/sn` (override with `SN_STATE_DIR`).
//!
//! Storage is split into small, independently-written files so a crash or
//! power loss cannot corrupt a single giant `state.json`. Every write is
//! tmp-file + `fsync` + atomic `rename`. The report queue is a bounded spool
//! directory, one file per cycle, rather than an in-memory list.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
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
    /// `at` of the evidence snapshot the hub already has.
    #[serde(default)]
    pub last_evidence_sent: i64,
    /// Id of the remediation result the hub already has.
    #[serde(default)]
    pub last_remediation_sent: String,
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
    static NEXT_TMP: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().context("state file has no parent")?;
    fs::create_dir_all(dir).ok();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    // A temp name no other writer uses (pid + a counter), created exclusively:
    // two processes saving the same file at once never write into one inode.
    let mut tries = 0u32;
    let (tmp, mut f) = loop {
        let n = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => break (tmp, f),
            // Left over by an earlier process that had the same pid.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 100 => tries += 1,
            Err(e) => return Err(e).with_context(|| format!("create {}", tmp.display())),
        }
    };
    let written = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .with_context(|| format!("write {}", tmp.display()))
        .and_then(|()| {
            fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))
        });
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
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
        Self::open_dir(dir)
    }

    /// Create the directory if needed and leave it to its owner alone (0700): it
    /// holds evidence (logins, command lines), scan results and pending orders.
    /// One left 0755 by an earlier run (`sn triage` from a plain root shell, as
    /// the runbook says) is tightened here. A symbolic link, or a directory some
    /// other user owns, is refused.
    fn open_dir(dir: PathBuf) -> Result<State> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating state dir {}", dir.display()))?;
        // O_NOFOLLOW: the checks and the chmod are about this directory itself,
        // never about wherever a link would lead.
        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(&dir)
            .with_context(|| {
                format!(
                    "opening state dir {} (a symbolic link is refused)",
                    dir.display()
                )
            })?;
        let meta = handle.metadata()?;
        let me = nix::unistd::geteuid().as_raw();
        if meta.uid() != me {
            bail!(
                "state dir {} belongs to uid {}, not to uid {me}; refusing to use it",
                dir.display(),
                meta.uid()
            );
        }
        if meta.mode() & 0o7777 != 0o700 {
            handle
                .set_permissions(fs::Permissions::from_mode(0o700))
                .with_context(|| format!("making state dir {} private", dir.display()))?;
        }
        for sub in ["queue", "quarantine"] {
            let _ = fs::DirBuilder::new().mode(0o700).create(dir.join(sub));
        }
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

    /// Change meta.json under an exclusive lock: re-read it, apply `f`, write it
    /// back (only if something changed), and return what `f` returned.
    ///
    /// Several processes keep fields in this one file: a watch cycle, an incident
    /// follow-up applying hub orders, `sn evidence`. Without the lock one could
    /// write an old copy back over another's change, and for instance roll back
    /// `last_jobs_seq` so a hub job ran twice. So every caller changes only its
    /// own fields, inside `f`. `f` must be quick and must not call `update_meta`
    /// (that second lock would wait for this one forever).
    pub fn update_meta<R>(&self, f: impl FnOnce(&mut Meta) -> R) -> Result<R> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.p("meta.lock"))
            .context("opening meta.lock")?;
        let guard = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, e)| anyhow::anyhow!("locking meta.lock: {e}"))?;
        let mut m = self.meta();
        let before = serde_json::to_vec_pretty(&m)?;
        let out = f(&mut m);
        let after = serde_json::to_vec_pretty(&m)?;
        if after != before {
            atomic_write(&self.p("meta.json"), &after)?;
        }
        // Released here (and if the process dies, by the kernel).
        drop(guard);
        Ok(out)
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
        assert_eq!(s.meta().next_report_seq, 0);
        s.update_meta(|m| {
            m.next_report_seq = 7;
            m.epoch = 2;
        })
        .unwrap();
        assert_eq!(s.meta().next_report_seq, 7);
        assert_eq!(s.meta().epoch, 2);
    }

    #[test]
    fn concurrent_meta_updates_lose_nothing() {
        // Each thread opens the lock file itself, as separate processes would.
        let (_g, s) = tmp_state();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        s.update_meta(|m| m.next_report_seq += 1).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(s.meta().next_report_seq, 200);
        // Every temp file was renamed into place or removed.
        let left: Vec<_> = fs::read_dir(&s.dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_meta_update_keeps_the_fields_it_did_not_touch() {
        // The bug this guards: a watch cycle saving its CPU streak from a copy
        // read before a hub order ran wrote back the old `last_jobs_seq`, and the
        // same job ran again.
        let (_g, s) = tmp_state();
        let stale = s.meta();
        s.update_meta(|m| {
            m.last_jobs_seq = 7;
            m.mode_override = Some(Mode::Enforce);
        })
        .unwrap();
        assert_eq!(stale.last_jobs_seq, 0);
        let seq = s
            .update_meta(|m| {
                m.cpu_streak = 3;
                m.next_report_seq
            })
            .unwrap();
        assert_eq!(seq, 0);
        let m = s.meta();
        assert_eq!(
            (m.last_jobs_seq, m.mode_override, m.cpu_streak),
            (7, Some(Mode::Enforce), 3)
        );
    }

    #[test]
    fn state_files_are_private() {
        let (_g, s) = tmp_state();
        s.update_meta(|m| m.epoch = 1).unwrap();
        s.queue_report(1, b"{}").unwrap();
        for f in [
            s.dir.join("meta.json"),
            s.dir.join("queue").join(format!("{:020}.json", 1)),
        ] {
            let mode = fs::metadata(&f).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", f.display());
        }
    }

    #[test]
    fn open_creates_a_private_dir_and_tightens_an_existing_one() {
        let d = tempfile::tempdir().unwrap();
        let fresh = d.path().join("fresh");
        let s = State::open_dir(fresh.clone()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&fresh), 0o700);
        assert!(s.dir.join("queue").is_dir() && s.dir.join("quarantine").is_dir());

        // Left 0755 by `sn triage` run from a root shell before the install.
        let old = d.path().join("old");
        fs::create_dir(&old).unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o755)).unwrap();
        State::open_dir(old.clone()).unwrap();
        assert_eq!(mode(&old), 0o700);
    }

    #[test]
    fn open_refuses_a_symlinked_state_dir() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let link = d.path().join("sn");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(State::open_dir(link).is_err());
        // And the place it pointed at was not touched.
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o755);
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
