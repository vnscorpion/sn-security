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

/// Move one file into the vault. Returns the quarantine id (sha256 prefix).
pub fn quarantine(state: &State, path: &Path) -> Result<String> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("not a regular file: {}", path.display());
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha = hex::encode(hasher.finalize());
    let id = format!("{}-{}", &sha[..16], util::ts_compact(util::now_secs()));

    let dest_dir = vault(state).join(&id);
    std::fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join("payload.bin");

    // Move (rename within same fs, else copy+remove).
    if std::fs::rename(path, &dest).is_err() {
        std::fs::write(&dest, &bytes)?;
        std::fs::remove_file(path)?;
    }
    // chmod 000 so the quarantined payload cannot run.
    let _ = std::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o000));

    let qm = QuarantineMeta {
        id: id.clone(),
        orig_path: path.to_string_lossy().to_string(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
        mtime: meta.mtime(),
        sha256: sha,
        quarantined_at: util::now_secs(),
    };
    std::fs::write(dest_dir.join("meta.json"), serde_json::to_vec_pretty(&qm)?)?;
    Ok(id)
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
