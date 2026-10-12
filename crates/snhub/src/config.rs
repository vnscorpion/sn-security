//! Hub configuration (`/etc/snhub/snhub.toml`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    /// Listen address. Default binds to localhost — put the UI behind a VPN or
    /// an IP allow-list / reverse proxy with TLS.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Where the SQLite DB and keys live.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Public base URL shown in generated install commands.
    #[serde(default)]
    pub public_url: String,
    /// Offline root public key (`ed25519:...`) handed to agents at enrollment.
    #[serde(default)]
    pub root_pubkey: String,
    /// Admin login: salted SHA-256 of the password (set via CLI).
    #[serde(default)]
    pub admin_salt: String,
    #[serde(default)]
    pub admin_password_sha256: String,
    /// Admin login: Argon2id hash (PHC string) of the password. Preferred over the
    /// SHA-256 pair above, and itself overridden by a password changed in the UI.
    #[serde(default)]
    pub admin_password_hash: String,
    /// Optional Telegram alerting.
    #[serde(default)]
    pub telegram: Option<Telegram>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Telegram {
    pub bot_token: String,
    pub chat_id: String,
}

fn default_bind() -> String {
    "127.0.0.1:8099".into()
}
fn default_data_dir() -> String {
    "/var/lib/snhub".into()
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            bind: default_bind(),
            data_dir: default_data_dir(),
            public_url: String::new(),
            root_pubkey: String::new(),
            admin_salt: String::new(),
            admin_password_sha256: String::new(),
            admin_password_hash: String::new(),
            telegram: None,
        }
    }
}

impl HubConfig {
    pub fn load(path: &Path) -> Result<HubConfig> {
        if !path.exists() {
            return Ok(HubConfig::default());
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }

    pub fn data_path(&self) -> PathBuf {
        PathBuf::from(&self.data_dir)
    }
}
