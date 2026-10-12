//! Hub signing key management.
//!
//! The **hub key** signs desired-state and lives online (in `data_dir`). The
//! **root key** authorizes policy changes and epoch resets and must be kept
//! OFFLINE — `snhub init` generates it, prints it once, and does not require it
//! to run. A compromised hub can therefore not weaken a VPS's policy tier.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use snsec_common::crypto;

pub struct HubKey {
    pub signing: SigningKey,
}

impl HubKey {
    /// Load the hub signing key from `data_dir/hub.key`, creating it if absent.
    pub fn load_or_create(data_dir: &Path) -> Result<HubKey> {
        let path = key_path(data_dir);
        if path.exists() {
            let hexseed = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let signing = crypto::parse_secret(hexseed.trim()).context("parsing hub.key")?;
            Ok(HubKey { signing })
        } else {
            use rand::rngs::OsRng;
            let signing = SigningKey::generate(&mut OsRng);
            write_private(&path, crypto::encode_secret(&signing).as_bytes())?;
            Ok(HubKey { signing })
        }
    }

    pub fn pubkey_str(&self) -> String {
        crypto::encode_pubkey(&self.signing.verifying_key())
    }
}

fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("hub.key")
}

/// Generate a fresh root keypair and return `(secret_hex, pubkey_str)`.
pub fn generate_root() -> (String, String) {
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    (
        crypto::encode_secret(&sk),
        crypto::encode_pubkey(&sk.verifying_key()),
    )
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    use std::io::Write;
    f.write_all(bytes)?;
    Ok(())
}
