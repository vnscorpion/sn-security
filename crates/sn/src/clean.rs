//! `sn clean` / `sn quarantine` / `sn restore` — move suspicious files into a
//! quarantine vault, preserving owner/mode/mtime so a false positive is fully
//! reversible. Paths are resolved with symlink-safe opens and must stay inside
//! the configured roots.
//!
//! The files dealt with here sit in directories their owner (often the attacker)
//! controls, so nothing is ever looked up by path as root: every directory is
//! opened with `O_NOFOLLOW` relative to the one before it, starting from `/`, and
//! the file itself is opened, created and removed relative to that last
//! descriptor.

use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, close, dup3, read, unlinkat};
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
/// prompt — this build is non-interactive, so `--yes` is required). Only files
/// inside `roots` (`hunt.allowed_roots`) are taken, and only while they still
/// hold the content the hunt hashed.
pub fn clean(state: &State, roots: &[String], yes: bool) -> Result<usize> {
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
    // `sn hunt` walks the real paths of its roots (a root reached through a
    // symlink is resolved first), so the findings name real paths: compare them
    // with the real roots too.
    let mut real_roots: Vec<String> = roots.to_vec();
    for r in roots {
        if let Ok(c) = std::fs::canonicalize(r)
            && let Some(s) = c.to_str()
            && !real_roots.iter().any(|x| x == s)
        {
            real_roots.push(s.to_string());
        }
    }
    let mut n = 0;
    let mut failed = 0;
    let mut quarantined: Vec<String> = Vec::new();
    for f in findings.iter().filter(|f| f.verdict == "malicious") {
        match clean_one(state, &real_roots, f) {
            Ok(id) => {
                println!("quarantined {} -> {id}", f.path);
                quarantined.push(f.path.clone());
                n += 1;
            }
            Err(e) => {
                eprintln!("clean: {}: {e:#}", f.path);
                failed += 1;
            }
        }
    }
    if failed > 0 {
        for r in roots {
            if std::fs::symlink_metadata(r).is_ok_and(|m| m.file_type().is_symlink()) {
                eprintln!(
                    "note: {r} is a symlink, and quarantine never goes through one: put the real \
                     directory in hunt.allowed_roots and run `sn hunt` again."
                );
            }
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

/// One finding from the last hunt, if it is still the file that was scanned.
fn clean_one(state: &State, roots: &[String], f: &Finding) -> Result<String> {
    let path = Path::new(&f.path);
    if !within_roots(path, roots) {
        bail!(
            "outside hunt.allowed_roots, not touched (if it really is meant, use `sn quarantine <path>`)"
        );
    }
    if f.sha256.is_empty() {
        bail!("the hunt recorded no hash for it; check it and use `sn quarantine <path>`");
    }
    quarantine_checked(state, path, None, Some(&f.sha256))
}

/// `path` is strictly below one of the absolute `roots`, without `..`.
fn within_roots(path: &Path, roots: &[String]) -> bool {
    path.is_absolute()
        && !path.components().any(|c| c == Component::ParentDir)
        && roots
            .iter()
            .map(Path::new)
            .filter(|r| r.is_absolute() && !r.components().any(|c| c == Component::ParentDir))
            .any(|r| path != r && path.starts_with(r))
}

/// Largest file the vault will take.
const MAX_QUARANTINE_BYTES: u64 = 256 * 1024 * 1024;

/// `(uid, gid, mode, mtime)` of a file.
type Attrs = (u32, u32, u32, i64);

/// A descriptor from nix's `openat` (a bare `RawFd` in nix 0.29), closed when
/// dropped.
struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

/// A `File` that owns `fd`. Wrapping a bare descriptor needs `unsafe`, so it is
/// moved (`dup3`) over one std already owns instead.
fn adopt(fd: Fd) -> Result<File> {
    let holder = File::open("/dev/null").context("open /dev/null")?;
    dup3(fd.0, holder.as_raw_fd(), OFlag::O_CLOEXEC).context("dup3")?;
    Ok(holder)
}

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// The directory that holds `path`, and the last name in it. Opened from `/`,
/// one component at a time with `O_NOFOLLOW`: a symlink anywhere on the way
/// makes this fail rather than lead somewhere else, and nothing is created.
fn open_parent(path: &Path) -> Result<(Fd, &str)> {
    let comps: Vec<&str> = path
        .to_str()
        .context("path is not valid UTF-8")?
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if !path.is_absolute() || comps.contains(&"..") {
        bail!("path must be absolute and free of `..`");
    }
    let (leaf, dirs) = comps.split_last().context("empty path")?;
    let mut cur = Fd(openat(None, "/", DIR_FLAGS, Mode::empty()).context("open /")?);
    for d in dirs {
        cur = Fd(
            openat(Some(cur.0), *d, DIR_FLAGS, Mode::empty()).map_err(|e| match e {
                Errno::ENOENT => anyhow!("directory {d} does not exist"),
                Errno::ELOOP | Errno::ENOTDIR => anyhow!("{d} is a symlink or not a directory"),
                e => anyhow!("open directory {d}: {e}"),
            })?,
        );
    }
    Ok((cur, leaf))
}

/// `unlinkat(dir, leaf)`, but only while the name still points at `st`: the
/// owner of `dir` may have put something else there since it was opened.
fn unlink_same(dir: &Fd, leaf: &str, st: &FileStat) -> Result<()> {
    let now = fstatat(Some(dir.0), leaf, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) {
        bail!("{leaf} was replaced while it was being handled");
    }
    unlinkat(Some(dir.0), leaf, UnlinkatFlags::NoRemoveDir)?;
    Ok(())
}

/// Write a copy of `data` (whose hash is `sha`) into a new vault entry and
/// describe it. The original is not touched here.
fn store(
    state: &State,
    orig_path: &Path,
    data: &[u8],
    sha: &str,
    (uid, gid, mode, mtime): Attrs,
) -> Result<(String, PathBuf)> {
    std::fs::create_dir_all(vault(state))?;
    // A directory of its own, created exclusively: the same payload quarantined
    // twice in one second (one dropper, many copies) must not share an entry,
    // or the first one could never be restored.
    let base = format!("{}-{}", &sha[..16], util::ts_compact(util::now_secs()));
    let mut n = 0u32;
    let (id, dest_dir) = loop {
        let id = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let dir = vault(state).join(&id);
        match std::fs::create_dir(&dir) {
            Ok(()) => break (id, dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => n += 1,
            Err(e) => return Err(e).context("creating the vault entry"),
        }
    };
    let dest = dest_dir.join("payload.bin");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
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
        sha256: sha.to_string(),
        quarantined_at: util::now_secs(),
    };
    if let Err(e) = std::fs::write(dest_dir.join("meta.json"), serde_json::to_vec_pretty(&qm)?) {
        let _ = std::fs::remove_dir_all(&dest_dir);
        return Err(e).context("writing the vault record");
    }
    Ok((id, dest_dir))
}

/// Quarantine a file that an attacker may be racing against (an AI-ordered clean
/// of something in `/tmp` or a hidden home directory, a hunt finding in a site's
/// directory, a path given to `sn quarantine`).
///
/// Every directory on the way is opened with `O_NOFOLLOW` relative to the one
/// before it, the file with `O_NOFOLLOW | O_NONBLOCK` relative to its parent, and
/// the removal is `unlinkat` on that same parent descriptor. Renaming a directory
/// or swapping a symlink in afterwards cannot redirect any of it, because nothing
/// is looked up by path again. If `expect_owner` is set the file must belong to
/// that uid.
pub fn quarantine_safe(state: &State, path: &Path, expect_owner: Option<u32>) -> Result<String> {
    quarantine_checked(state, path, expect_owner, None)
}

/// [`quarantine_safe`], and with `expect_sha256` the content read must also be
/// the one that was scanned: anything else is refused before it is stored or
/// removed.
fn quarantine_checked(
    state: &State,
    path: &Path,
    expect_owner: Option<u32>,
    expect_sha256: Option<&str>,
) -> Result<String> {
    let (dir, leaf) = open_parent(path)?;
    let fd = Fd(openat(
        Some(dir.0),
        leaf,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("open {leaf}"))?);
    let st = fstat(fd.0)?;
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
        let n = read(fd.0, &mut buf)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() as u64 > MAX_QUARANTINE_BYTES {
            bail!("file grew beyond the limit while reading");
        }
    }
    drop(fd);

    let sha = hex::encode(Sha256::digest(&data));
    if let Some(want) = expect_sha256
        && !sha.eq_ignore_ascii_case(want)
    {
        bail!(
            "content changed since it was scanned (sha256 {sha}, hunt saw {want}); run `sn hunt` again"
        );
    }
    let attrs = (st.st_uid, st.st_gid, st.st_mode, st.st_mtime);
    let (id, dest_dir) = store(state, path, &data, &sha, attrs)?;
    if let Err(e) = unlink_same(&dir, leaf, &st) {
        // Do not leave a second copy behind when the original stays.
        let _ = std::fs::remove_dir_all(dest_dir);
        return Err(e).context("could not remove the original");
    }
    Ok(id)
}

/// A vault id as [`store`] makes them: no separators, nothing that leaves the
/// vault.
fn is_vault_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Restore a quarantined file to its original path, owner, mode and mtime.
///
/// The original directory is usually one the file's owner controls, so this
/// works like [`quarantine_safe`] in reverse: the directories are opened from
/// `/` without following symlinks (a missing one is not recreated), the file is
/// created there with `O_EXCL` and written through its own descriptor, and owner,
/// mode and mtime are set on that descriptor. Set-id and sticky bits are not
/// given back. On any failure the half-made file is removed and the vault entry
/// is kept.
pub fn restore(state: &State, id: &str) -> Result<()> {
    if !is_vault_id(id) {
        bail!("not a quarantine id: {id} (see `sn list-quarantine`)");
    }
    let dir = vault(state).join(id);
    let meta_path = dir.join("meta.json");
    let qm: QuarantineMeta = serde_json::from_slice(
        &std::fs::read(&meta_path).with_context(|| format!("read {}", meta_path.display()))?,
    )?;
    let payload = dir.join("payload.bin");
    // Readable only for as long as it takes to copy it out.
    let _ = std::fs::set_permissions(
        &payload,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );
    let data = std::fs::read(&payload);
    let _ = std::fs::set_permissions(
        &payload,
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    );
    let data = data.with_context(|| format!("read {}", payload.display()))?;
    if hex::encode(Sha256::digest(&data)) != qm.sha256 {
        bail!("the vault copy does not match its record, not restoring it");
    }

    let orig = Path::new(&qm.orig_path);
    let (parent, leaf) = open_parent(orig).with_context(|| {
        format!(
            "cannot reach the folder of {} safely; sn restore neither creates folders nor follows \
             symlinks: recreate it as it was, then run `sn restore {id}` again",
            orig.display()
        )
    })?;
    let fd = match openat(
        Some(parent.0),
        leaf,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    ) {
        Ok(fd) => Fd(fd),
        Err(Errno::EEXIST) => bail!(
            "original path already exists, refusing to overwrite: {}",
            orig.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("create {}", orig.display())),
    };
    let st = match fstat(fd.0) {
        Ok(st) => st,
        Err(e) => {
            let _ = unlinkat(Some(parent.0), leaf, UnlinkatFlags::NoRemoveDir);
            return Err(e).context("fstat");
        }
    };
    let mode = qm.mode & 0o777;
    let written = (|| -> Result<()> {
        use std::io::Write;
        let mut f = adopt(fd)?;
        f.write_all(&data)?;
        f.sync_all()?;
        // Owner first, then the mode: the payload is never a root-owned file
        // with the recorded (possibly executable) mode, not even for a moment.
        std::os::unix::fs::fchown(&f, Some(qm.uid), Some(qm.gid)).context("fchown")?;
        f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))
            .context("fchmod")?;
        if let Ok(secs) = u64::try_from(qm.mtime) {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
            f.set_times(std::fs::FileTimes::new().set_modified(t))
                .context("futimens")?;
        }
        Ok(())
    })();
    if let Err(e) = written {
        let _ = unlink_same(&parent, leaf, &st);
        return Err(e).with_context(|| format!("restore {}", orig.display()));
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!(
        "restored {} (owner {}:{}, mode {mode:o})",
        orig.display(),
        qm.uid,
        qm.gid,
    );
    if qm.mode & 0o7000 != 0 {
        println!(
            "note: it had mode {:o}; the setuid/setgid/sticky bits were not given back.",
            qm.mode & 0o7777
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    const BODY: &[u8] = b"<?php /* test payload */ echo 1; ?>";

    /// A temporary directory reached without symlinks (the walk refuses them, and
    /// some systems keep the temp directory behind one).
    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    fn state() -> (tempfile::TempDir, State) {
        let d = tempfile::tempdir().unwrap();
        let s = State::at(d.path().to_path_buf());
        (d, s)
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn vault_ids(state: &State) -> Vec<String> {
        std::fs::read_dir(vault(state))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn put(path: &Path, body: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn quarantine_then_restore_gives_back_content_owner_and_mtime_but_not_setuid() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let file = root.join("site/x.php");
        put(&file, BODY);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(mtime))
            .unwrap();

        let id = quarantine_checked(&state, &file, None, Some(&sha(BODY))).unwrap();
        assert!(!file.exists());
        assert_eq!(vault_ids(&state), vec![id.clone()]);

        restore(&state, &id).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), BODY);
        let m = std::fs::symlink_metadata(&file).unwrap();
        assert!(m.is_file());
        assert_eq!(m.mode() & 0o7777, 0o755);
        assert_eq!(m.mtime(), 1_000_000_000);
        assert_eq!(m.uid(), nix::unistd::getuid().as_raw());
        assert!(vault_ids(&state).is_empty());
    }

    #[test]
    fn a_file_that_changed_since_the_hunt_is_left_alone() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let file = root.join("site/x.php");
        put(&file, b"something else now");
        assert!(quarantine_checked(&state, &file, None, Some(&sha(BODY))).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"something else now");
        assert!(vault_ids(&state).is_empty());
    }

    #[test]
    fn quarantine_does_not_go_through_a_symlinked_directory() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        put(&root.join("real/x.php"), BODY);
        symlink(root.join("real"), root.join("link")).unwrap();
        assert!(quarantine_safe(&state, &root.join("link/x.php"), None).is_err());
        assert!(root.join("real/x.php").exists());
        assert!(vault_ids(&state).is_empty());
    }

    #[test]
    fn restore_does_not_follow_a_folder_swapped_for_a_symlink() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let file = root.join("site/x.php");
        put(&file, BODY);
        let id = quarantine_safe(&state, &file, None).unwrap();

        // The owner moves the folder away and points its name somewhere else.
        std::fs::rename(root.join("site"), root.join("moved")).unwrap();
        std::fs::create_dir(root.join("elsewhere")).unwrap();
        symlink(root.join("elsewhere"), root.join("site")).unwrap();
        assert!(restore(&state, &id).is_err());
        assert!(!root.join("elsewhere/x.php").exists());
        assert!(!root.join("moved/x.php").exists());
        assert_eq!(vault_ids(&state), vec![id.clone()]);

        // Put right, the same entry restores.
        std::fs::remove_file(root.join("site")).unwrap();
        std::fs::rename(root.join("moved"), root.join("site")).unwrap();
        restore(&state, &id).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), BODY);
    }

    #[test]
    fn restore_does_not_create_missing_folders() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let file = root.join("a/b/x.php");
        put(&file, BODY);
        let id = quarantine_safe(&state, &file, None).unwrap();
        std::fs::remove_dir(root.join("a/b")).unwrap();
        std::fs::remove_dir(root.join("a")).unwrap();

        assert!(restore(&state, &id).is_err());
        assert!(!root.join("a").exists());
        assert_eq!(vault_ids(&state), vec![id]);
    }

    #[test]
    fn restore_never_writes_through_what_now_holds_the_name() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let file = root.join("site/x.php");
        put(&file, BODY);
        let id = quarantine_safe(&state, &file, None).unwrap();
        put(&root.join("target"), b"keep");
        symlink(root.join("target"), &file).unwrap();

        assert!(restore(&state, &id).is_err());
        assert_eq!(std::fs::read(root.join("target")).unwrap(), b"keep");
        assert!(
            std::fs::symlink_metadata(&file)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(vault_ids(&state), vec![id]);
    }

    #[test]
    fn restore_refuses_a_tampered_vault_copy_and_odd_ids() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let file = root.join("site/x.php");
        put(&file, BODY);
        let id = quarantine_safe(&state, &file, None).unwrap();
        let payload = vault(&state).join(&id).join("payload.bin");
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&payload, b"not what was taken").unwrap();
        assert!(restore(&state, &id).is_err());
        assert!(!file.exists());

        for bad in ["", "../x", "a/b", ".", &"a".repeat(65)] {
            assert!(restore(&state, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn identical_files_get_vault_entries_of_their_own() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let a = root.join("one/x.php");
        let b = root.join("two/x.php");
        put(&a, BODY);
        put(&b, BODY);
        let ia = quarantine_safe(&state, &a, None).unwrap();
        let ib = quarantine_safe(&state, &b, None).unwrap();
        assert_ne!(ia, ib);
        restore(&state, &ia).unwrap();
        restore(&state, &ib).unwrap();
        assert!(a.exists() && b.exists());
    }

    #[test]
    fn clean_takes_only_unchanged_malicious_files_inside_the_roots() {
        let (_t, root) = tmp();
        let (_s, state) = state();
        let www = root.join("www");
        let finding = |p: &Path, verdict: &str, sha256: String| Finding {
            path: p.to_string_lossy().to_string(),
            score: 100,
            verdict: verdict.into(),
            rules: vec!["test".into()],
            context: String::new(),
            sha256,
        };
        let taken = www.join("a.php");
        let changed = www.join("b.php");
        let outside = root.join("other/c.php");
        let suspicious = www.join("d.php");
        let no_hash = www.join("e.php");
        for p in [&taken, &changed, &outside, &suspicious, &no_hash] {
            put(p, BODY);
        }
        let findings = vec![
            finding(&taken, "malicious", sha(BODY)),
            finding(&changed, "malicious", sha(b"what the hunt saw")),
            finding(&outside, "malicious", sha(BODY)),
            finding(&suspicious, "suspicious", sha(BODY)),
            finding(&no_hash, "malicious", String::new()),
        ];
        std::fs::write(
            state.dir.join("findings-latest.json"),
            serde_json::to_vec(&findings).unwrap(),
        )
        .unwrap();
        let roots = vec![www.to_string_lossy().to_string()];

        assert!(clean(&state, &roots, false).is_err());
        assert_eq!(clean(&state, &roots, true).unwrap(), 1);
        assert!(!taken.exists());
        for p in [&changed, &outside, &suspicious, &no_hash] {
            assert!(p.exists(), "{}", p.display());
        }
        let left: Vec<Finding> =
            serde_json::from_slice(&std::fs::read(state.dir.join("findings-latest.json")).unwrap())
                .unwrap();
        assert_eq!(left.len(), 4);
        assert!(left.iter().all(|f| f.path != taken.to_string_lossy()));
    }

    #[test]
    fn roots_are_compared_by_component() {
        let roots = vec![
            "/home".to_string(),
            "/var/www/".to_string(),
            "rel".to_string(),
        ];
        assert!(within_roots(Path::new("/home/a/x.php"), &roots));
        assert!(within_roots(Path::new("/var/www/site/x.php"), &roots));
        assert!(!within_roots(Path::new("/homeX/a/x.php"), &roots));
        assert!(!within_roots(Path::new("/home/../etc/x"), &roots));
        assert!(!within_roots(Path::new("/home"), &roots));
        assert!(!within_roots(Path::new("rel/x.php"), &roots));
        assert!(!within_roots(Path::new("/etc/passwd"), &roots));
    }
}
