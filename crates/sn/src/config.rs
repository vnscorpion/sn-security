//! Agent configuration (`/etc/sn/agent.toml`) plus the embedded Cloudflare
//! ranges used to recover real client IPs and to keep the proxy's own address
//! out of every per-IP counter.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use snsec_common::net::Cidr;
use snsec_common::schema::Mode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub hub: HubCfg,
    #[serde(default)]
    pub watch: WatchCfg,
    #[serde(default)]
    pub fw: FwCfg,
    #[serde(default)]
    pub hunt: HuntCfg,
    #[serde(default)]
    pub remote: RemoteCfg,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HubCfg {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub agent_id: String,
    /// ed25519 secret seed (hex), mode 0600. Empty when running standalone.
    #[serde(default)]
    pub agent_key: String,
    /// Hub signing public keys (`ed25519:...`); accepts several for rotation.
    #[serde(default)]
    pub hub_pubkeys: Vec<String>,
    /// Offline root key(s) that authorize policy-tier changes and epoch resets.
    #[serde(default)]
    pub root_pubkeys: Vec<String>,
}

/// How the access logs to follow are chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourcesMode {
    /// The agent finds them itself, every cycle: it looks at which web server
    /// answers on :80/:443 and reads that server's logs. Survives a web-server
    /// switch and needs no per-host setup. A config written before this option
    /// existed has no value for it and so gets this, which replaces the guess an
    /// older installer made. The explicit `sources` below are used only as a
    /// fallback when nothing is found.
    #[default]
    Auto,
    /// Follow exactly `sources` / `logs` from this file (custom log locations).
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchCfg {
    /// Simple global globs (legacy). Prefer `sources`.
    #[serde(default)]
    pub logs: Vec<String>,
    #[serde(default = "default_format")]
    pub format: String,
    /// `auto` (default) detects the web server's logs; `manual` uses `sources`.
    #[serde(default)]
    pub sources_mode: SourcesMode,
    /// Explicit log definitions: what `manual` mode follows, and the fallback
    /// for `auto` when detection finds nothing.
    #[serde(default)]
    pub sources: Vec<LogSource>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_k")]
    pub k: f64,
    #[serde(default = "default_min_requests")]
    pub min_requests: u32,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Raise a `cpu_high` alert when the machine's average CPU since the last
    /// cycle reaches this percent (all cores together).
    #[serde(default = "default_cpu_alert")]
    pub cpu_alert_pct: f64,
    /// Detect distributed bots: one User-Agent or request shape that suddenly
    /// arrives from many different IPs. Alerts only; it never bans by itself.
    #[serde(default = "default_true")]
    pub bot_detection: bool,
    /// A pattern must come from at least this many distinct IPs in one cycle...
    #[serde(default = "default_bot_min_ips")]
    pub bot_min_ips: u32,
    /// ...make at least this many dynamic requests...
    #[serde(default = "default_bot_min_requests")]
    pub bot_min_requests: u32,
    /// ...and be at least this many times its usual volume.
    #[serde(default = "default_bot_surge")]
    pub bot_surge: f64,
}

impl Default for WatchCfg {
    fn default() -> Self {
        WatchCfg {
            logs: Vec::new(),
            format: default_format(),
            sources_mode: SourcesMode::Auto,
            sources: Vec::new(),
            mode: Mode::Observe,
            k: default_k(),
            min_requests: default_min_requests(),
            trusted_proxies: Vec::new(),
            cpu_alert_pct: default_cpu_alert(),
            bot_detection: true,
            bot_min_ips: default_bot_min_ips(),
            bot_min_requests: default_bot_min_requests(),
            bot_surge: default_bot_surge(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub glob: String,
    #[serde(default = "default_format")]
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FwCfg {
    /// Admin/office ranges that are never banned (local-only, never remote).
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_max_bans")]
    pub max_bans_per_cycle: u32,
    /// Ports a HTTP-derived ban is allowed to block. All-port bans need admin.
    #[serde(default = "default_web_ports")]
    pub web_ports: Vec<u16>,
}

impl Default for FwCfg {
    fn default() -> Self {
        FwCfg {
            whitelist: Vec::new(),
            max_bans_per_cycle: default_max_bans(),
            web_ports: default_web_ports(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntCfg {
    #[serde(default = "default_roots")]
    pub allowed_roots: Vec<String>,
    #[serde(default = "default_days")]
    pub days: u32,
    #[serde(default = "default_max_file_mb")]
    pub max_file_mb: u64,
}

impl Default for HuntCfg {
    fn default() -> Self {
        HuntCfg {
            allowed_roots: default_roots(),
            days: default_days(),
            max_file_mb: default_max_file_mb(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteCfg {
    /// Allow the hub to switch this VPS back to observe without a root policy.
    #[serde(default)]
    pub allow_mode_observe: bool,
    /// Allow the hub to trigger `undo` (jail release + sn-ban removal only).
    #[serde(default)]
    pub allow_undo: bool,
}

fn default_format() -> String {
    "combined".into()
}
fn default_k() -> f64 {
    5.0
}
fn default_min_requests() -> u32 {
    120
}
fn default_cpu_alert() -> f64 {
    85.0
}
fn default_true() -> bool {
    true
}
fn default_bot_min_ips() -> u32 {
    25
}
fn default_bot_min_requests() -> u32 {
    50
}
fn default_bot_surge() -> f64 {
    5.0
}
fn default_max_bans() -> u32 {
    200
}
fn default_web_ports() -> Vec<u16> {
    vec![80, 443]
}
fn default_roots() -> Vec<String> {
    vec!["/home".into(), "/var/www".into()]
}
fn default_days() -> u32 {
    7
}
fn default_max_file_mb() -> u64 {
    5
}

impl Config {
    /// Load from a TOML file. A missing file yields a safe standalone default.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            return Ok(Config::standalone_default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        Ok(cfg)
    }

    fn standalone_default() -> Config {
        Config {
            hub: HubCfg::default(),
            watch: WatchCfg::default(),
            fw: FwCfg::default(),
            hunt: HuntCfg::default(),
            remote: RemoteCfg::default(),
        }
    }

    /// Expand `trusted_proxies` (including the `cloudflare` alias) into CIDRs.
    #[must_use]
    pub fn trusted_cidrs(&self) -> Vec<Cidr> {
        expand_proxies(&self.watch.trusted_proxies)
    }
}

/// Expand proxy tokens: literal CIDRs plus the `cloudflare` alias.
#[must_use]
pub fn expand_proxies(tokens: &[String]) -> Vec<Cidr> {
    let mut out = Vec::new();
    for t in tokens {
        if t.eq_ignore_ascii_case("cloudflare") {
            for c in CLOUDFLARE_V4.iter().chain(CLOUDFLARE_V6.iter()) {
                if let Some(cidr) = Cidr::parse(c) {
                    out.push(cidr);
                }
            }
        } else if let Some(cidr) = Cidr::parse(t) {
            out.push(cidr);
        }
    }
    out
}

/// Cloudflare published IPv4 ranges (https://www.cloudflare.com/ips-v4).
pub const CLOUDFLARE_V4: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Cloudflare published IPv6 ranges (https://www.cloudflare.com/ips-v6).
pub const CLOUDFLARE_V6: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `[watch]` exactly as `deploy/install.sh` writes it: the keys first, the
    /// `[[watch.sources]]` tables last.
    const INSTALLER_CONFIG: &str = r#"
[hub]
url = "https://hub.example"

[watch]
mode         = "observe"
k            = 5.0
min_requests = 120
trusted_proxies = ["cloudflare"]

[[watch.sources]]
glob   = "/var/log/nginx/domains/*.log"
format = "combined"

[[watch.sources]]
glob   = "/var/log/httpd/domains/*.log"
format = "combined"

[fw]
whitelist = []
"#;

    #[test]
    fn installer_config_keeps_every_watch_setting() {
        let cfg: Config = toml::from_str(INSTALLER_CONFIG).unwrap();
        assert_eq!(cfg.watch.sources.len(), 2);
        assert_eq!(cfg.watch.sources[0].glob, "/var/log/nginx/domains/*.log");
        assert_eq!(cfg.watch.trusted_proxies, vec!["cloudflare".to_string()]);
        assert_eq!(cfg.watch.min_requests, 120);
        // "cloudflare" expands to the published ranges, so a Cloudflare IP is
        // recognised as a proxy rather than counted as a visitor.
        let cidrs = cfg.trusted_cidrs();
        assert!(snsec_common::net::in_any(
            &cidrs,
            "173.245.48.1".parse().unwrap()
        ));
    }

    #[test]
    fn keys_placed_after_a_sources_table_are_silently_lost() {
        // The old installer wrote the sources first. TOML then attaches every
        // later key to the last `[[watch.sources]]` entry, and the agent has no
        // error to show for it: `trusted_proxies` just comes back empty.
        let broken = r#"
[watch]
[[watch.sources]]
glob   = "/var/log/nginx/domains/*.log"
format = "combined"
mode = "observe"
trusted_proxies = ["cloudflare"]
"#;
        let cfg: Config = toml::from_str(broken).unwrap();
        assert_eq!(cfg.watch.sources.len(), 1);
        assert!(cfg.watch.trusted_proxies.is_empty());
    }

    #[test]
    fn a_config_written_before_sources_mode_existed_is_auto() {
        // Every install made so far has explicit sources and no `sources_mode`.
        // Defaulting to auto is what lets a plain agent upgrade replace a wrong
        // installer guess (e.g. Apache paths on an nginx server) with detection.
        let cfg: Config = toml::from_str(INSTALLER_CONFIG).unwrap();
        assert_eq!(cfg.watch.sources_mode, SourcesMode::Auto);
        assert_eq!(
            Config::standalone_default().watch.sources_mode,
            SourcesMode::Auto
        );
        // The explicit sources are kept: they are the fallback when nothing is found.
        assert_eq!(cfg.watch.sources.len(), 2);
    }

    #[test]
    fn manual_mode_is_opt_in_and_survives_a_save() {
        let text = "[watch]\nsources_mode = \"manual\"\n";
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.watch.sources_mode, SourcesMode::Manual);
        // `sn enroll` rewrites the file through serde: the choice must round-trip.
        let saved = toml::to_string_pretty(&cfg).unwrap();
        let again: Config = toml::from_str(&saved).unwrap();
        assert_eq!(again.watch.sources_mode, SourcesMode::Manual);
        assert!(saved.contains("sources_mode = \"manual\""));
    }
}
