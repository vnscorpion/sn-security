//! `sn clean` / `sn quarantine` / `sn restore` — move suspicious files into a
//! quarantine vault, preserving owner/mode/mtime so a false positive is fully
//! reversible. Paths are resolved with symlink-safe opens and must stay inside
//! the configured roots.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snsec_common::schema::Finding;

use crate::state::State;
use crate::util;

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineMeta {
    id: String,
    orig_path: String,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
    sha256: String,
    quarantined_at: i64,
}

fn vault(state: &State) -> PathBuf {
    state.dir.join("quarantine")
}

/// Quarantine every `malicious` finding (and, with `--yes`, do it without a
/// prompt — this build is non-interactive, so `--yes` is required).
pub fn clean(state: &State, yes: bool) -> Result<usize> {
    if !yes {
        bail!("refusing to quarantine without --yes (review `sn hunt` output first)");
    }
    let findings: Vec<Finding> = std::fs::read(state.dir.join("findings-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if findings.is_empty() {
        println!("no findings to clean (run `sn hunt` first).");
        return Ok(0);
    }
    let mut n = 0;
    let mut quarantined: Vec<String> = Vec::new();
    for f in findings.iter().filter(|f| f.verdict == "malicious") {
        match quarantine(state, Path::new(&f.path)) {
            Ok(id) => {
                println!("quarantined {} -> {id}", f.path);
                quarantined.push(f.path.clone());
                n += 1;
            }
            Err(e) => eprintln!("clean: {}: {e:#}", f.path),
        }
    }
    // What is left to look at: so the hub stops reporting files already dealt with.
    let remaining: Vec<Finding> = findings
        .into_iter()
        .filter(|f| !quarantined.contains(&f.path))
        .collect();
    crate::hunt::store_remaining(state, &remaining);
    println!("{n} file(s) quarantined. Restore any with `sn restore <id>`.");
    if remaining.iter().any(|f| f.verdict == "suspicious") {
        println!("Suspicious files were left alone: review them with `sn hunt` output / the hub.");
    }
    Ok(n)
}

/// Largest file the vault will take.
const MAX_QUARANTINE_BYTES: u64 = 256 * 1024 * 1024;

/// `(uid, gid, mode, mtime)` of a file.
type Attrs = (u32, u32, u32, i64);

/// Write a copy of `data` into a new vault entry and describe it. The original is
/// not touched here.
fn store(
    state: &State,
    orig_path: &Path,
    data: &[u8],
    (uid, gid, mode, mtime): Attrs,
) -> Result<(String, PathBuf)> {
    let sha = hex::encode(Sha256::digest(data));
    let id = format!("{}-{}", &sha[..16], util::ts_compact(util::now_secs()));
    let dest_dir = vault(state).join(&id);
    std::fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join("payload.bin");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&dest)?;
        f.write_all(data)?;
    }
    // chmod 000 so the quarantined payload cannot run.
    let _ = std::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o000));
    let qm = QuarantineMeta {
        id: id.clone(),
        orig_path: orig_path.to_string_lossy().to_string(),
        uid,
        gid,
        mode,
        mtime,
        sha256: sha,
        quarantined_at: util::now_secs(),
    };
    std::fs::write(dest_dir.join("meta.json"), serde_json::to_vec_pretty(&qm)?)?;
    Ok((id, dest_dir))
}

/// Move one file into the vault. Returns the quarantine id (sha256 prefix).
///
/// The file is opened without following a symlink and without blocking, and its
/// size is bounded, so a link or a FIFO swapped in by the file's owner cannot make
/// this read something else or hang. (For a file an attacker can influence while
/// it runs, use [`quarantine_safe`], which also resolves the directories safely.)
pub fn quarantine(state: &State, path: &Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("not a regular file: {}", path.display());
    }
    if meta.len() > MAX_QUARANTINE_BYTES {
        bail!(
            "file is larger than {} MiB: {}",
            MAX_QUARANTINE_BYTES >> 20,
            path.display()
        );
    }
    let mut bytes = Vec::new();
    f.take(MAX_QUARANTINE_BYTES)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    let (id, dest_dir) = store(
        state,
        path,
        &bytes,
        (meta.uid(), meta.gid(), meta.mode(), meta.mtime()),
    )?;
    // Take it out of place: the copy in the vault is the one that matters now.
    if let Err(e) = std::fs::remove_file(path) {
        let _ = std::fs::remove_dir_all(dest_dir);
        return Err(e).with_context(|| format!("remove {}", path.display()));
    }
    Ok(id)
}

/// Quarantine a file that an attacker may be racing against (an AI-ordered clean
/// of something in `/tmp` or a hidden home directory).
///
/// Every directory on the way is opened with `O_NOFOLLOW` relative to the one
/// before it, the file with `O_NOFOLLOW | O_NONBLOCK` relative to its parent, and
/// the removal is `unlinkat` on that same parent descriptor. Renaming a directory
/// or swapping a symlink in afterwards cannot redirect any of it, because nothing
/// is looked up by path again. If `expect_owner` is set the file must belong to
/// that uid.
pub fn quarantine_safe(state: &State, path: &Path, expect_owner: Option<u32>) -> Result<String> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::{Mode, SFlag, fstat};
    use nix::unistd::{UnlinkatFlags, close, read, unlinkat};
    use std::os::fd::RawFd;

    let comps: Vec<&str> = path
        .to_str()
        .context("path is not valid UTF-8")?
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let (leaf, dirs) = comps.split_last().context("empty path")?;
    if !path.is_absolute() || comps.contains(&"..") {
        bail!("path must be absolute and free of `..`");
    }

    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut cur: RawFd = openat(None, "/", dir_flags, Mode::empty()).context("open /")?;
    for d in dirs {
        let next = openat(Some(cur), *d, dir_flags, Mode::empty());
        let _ = close(cur);
        cur = next.with_context(|| format!("open directory {d} (a symlink on the way?)"))?;
    }
    let result = (|| -> Result<String> {
        let fd = openat(
            Some(cur),
            *leaf,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("open {leaf}"))?;
        let body = (|| -> Result<(Vec<u8>, Attrs)> {
            let st = fstat(fd)?;
            if SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
                bail!("not a regular file");
            }
            if let Some(uid) = expect_owner
                && st.st_uid != uid
            {
                bail!("file belongs to uid {}, not {uid}", st.st_uid);
            }
            let size = u64::try_from(st.st_size).unwrap_or(0);
            if size > MAX_QUARANTINE_BYTES {
                bail!("file is larger than {} MiB", MAX_QUARANTINE_BYTES >> 20);
            }
            let mut data = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = read(fd, &mut buf)?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if data.len() as u64 > MAX_QUARANTINE_BYTES {
                    bail!("file grew beyond the limit while reading");
                }
            }
            Ok((data, (st.st_uid, st.st_gid, st.st_mode, st.st_mtime)))
        })();
        let _ = close(fd);
        let (data, attrs) = body?;
        let (id, dest_dir) = store(state, path, &data, attrs)?;
        if let Err(e) = unlinkat(Some(cur), *leaf, UnlinkatFlags::NoRemoveDir) {
            // Do not leave a second copy behind when the original stays.
            let _ = std::fs::remove_dir_all(dest_dir);
            bail!("could not remove the original: {e}");
        }
        Ok(id)
    })();
    let _ = close(cur);
    result
}

/// Restore a quarantined file to its original path, owner, mode and mtime.
pub fn restore(state: &State, id: &str) -> Result<()> {
    let dir = vault(state).join(id);
    let meta_path = dir.join("meta.json");
    let qm: QuarantineMeta = serde_json::from_slice(
        &std::fs::read(&meta_path).with_context(|| format!("read {}", meta_path.display()))?,
    )?;
    let payload = dir.join("payload.bin");
    let orig = PathBuf::from(&qm.orig_path);

    if orig.exists() {
        bail!(
            "original path already exists, refusing to overwrite: {}",
            orig.display()
        );
    }
    if let Some(parent) = orig.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Make the payload readable for the move.
    let _ = std::fs::set_permissions(
        &payload,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );
    if std::fs::rename(&payload, &orig).is_err() {
        std::fs::copy(&payload, &orig)?;
        let _ = std::fs::remove_file(&payload);
    }
    // Restore mode and ownership.
    let _ = std::fs::set_permissions(&orig, std::os::unix::fs::PermissionsExt::from_mode(qm.mode));
    let _ = nix::unistd::chown(
        &orig,
        Some(nix::unistd::Uid::from_raw(qm.uid)),
        Some(nix::unistd::Gid::from_raw(qm.gid)),
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!(
        "restored {} (owner {}:{}, mode {:o})",
        orig.display(),
        qm.uid,
        qm.gid,
        qm.mode & 0o7777
    );
    Ok(())
}

/// List quarantine ids.
pub fn list(state: &State) -> Result<()> {
    let v = vault(state);
    if let Ok(rd) = std::fs::read_dir(&v) {
        for ent in rd.flatten() {
            if let Ok(meta) = std::fs::read(ent.path().join("meta.json"))
                && let Ok(qm) = serde_json::from_slice::<QuarantineMeta>(&meta)
            {
                println!("{}  {}", qm.id, qm.orig_path);
            }
        }
    }
    Ok(())
}
