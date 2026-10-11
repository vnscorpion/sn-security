//! Wire types for the agent <-> hub protocol.
//!
//! Every message travels inside a signed [`Signed`] wrapper whose `env` field
//! is the *exact* JSON text that was signed — we never re-serialize before
//! verifying, so there is no canonicalization ambiguity (see [`crate::crypto`]).

use serde::{Deserialize, Serialize};

/// Enforcement mode for a watched VPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Never writes to the system: only reports `would_ban`/`would_contain`.
    #[default]
    Observe,
    /// Applies bans and (for clear miner signatures) containment.
    Enforce,
}

impl Mode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        }
    }
}

/// The signed transport wrapper. `env` holds the JSON text of an
/// [`Envelope`]; `sig` is the hex ed25519 signature over `env`'s bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed {
    /// JSON text of the [`Envelope`]. Signed and verified as raw bytes.
    pub env: String,
    /// Hex-encoded ed25519 signature over `env.as_bytes()`.
    pub sig: String,
    /// Which key signed this (agent id for reports, hub key serial for desired).
    pub key_id: String,
}

/// Signed envelope around a message body of type `T`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub schema_version: u32,
    pub agent_id: String,
    /// Bumped only by a root-signed message (e.g. after a hub DB restore) so a
    /// legitimate counter reset is possible without weakening replay defence.
    pub epoch: u64,
    /// Strictly increasing per direction; receiver rejects `seq <= last_seen`.
    pub seq: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub body: T,
}

impl<T> Envelope<T> {
    /// A `(epoch, seq)` pair is newer iff epoch is greater, or epoch is equal
    /// and seq is strictly greater.
    #[must_use]
    pub fn is_newer_than(&self, epoch: u64, seq: u64) -> bool {
        self.epoch > epoch || (self.epoch == epoch && self.seq > seq)
    }
}

// ---------------------------------------------------------------------------
// Report: VPS -> hub
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBody {
    pub agent_version: String,
    /// Hostname and OS fingerprint, for the overview screen.
    #[serde(default)]
    pub host: HostInfo,
    pub cycle: CycleStats,
    #[serde(default)]
    pub bans: Vec<BanEvent>,
    #[serde(default)]
    pub would_ban: Vec<BanEvent>,
    #[serde(default)]
    pub alerts: Vec<Alert>,
    #[serde(default)]
    pub triage: Option<TriageSummary>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// The `(epoch, seq)` of the last desired-state this agent applied.
    #[serde(default)]
    pub applied_desired: DesiredRef,
    /// Features this agent supports; the hub only sends jobs within this set.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Every ban currently in force on the VPS, whoever set it (automatic
    /// detection, an admin from the hub, or `sn contain`). Older agents omit
    /// this, so the hub must tolerate it being empty.
    #[serde(default)]
    pub active_bans: Vec<ActiveBanInfo>,
    /// How many bans are really in force. `active_bans` is capped, so when this
    /// is larger the list is partial and the hub must not claim an address is
    /// unblocked just because it is absent from it.
    #[serde(default)]
    pub active_bans_total: u32,
}

/// One ban currently in force on a VPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBanInfo {
    pub ip: String,
    /// `hub` for admin-ordered bans, otherwise the detection reason.
    pub reason: String,
    /// Unix time the ban lapses.
    pub expires_at: i64,
    pub strike: u32,
    pub layer: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub cgroup: String,
    pub firewall: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CycleStats {
    pub started_at: i64,
    pub duration_ms: u64,
    pub lines_read: u64,
    pub parse_errors: u64,
    pub requests: u64,
    pub load1: f64,
    pub cpu_busy_pct: f64,
    /// Memory figures (new in schema 1.1; `default` keeps reports from older
    /// agents deserializable on the hub).
    #[serde(default)]
    pub mem_total_mb: u64,
    /// Percent of RAM in use, excluding reclaimable cache (`MemAvailable`).
    #[serde(default)]
    pub mem_used_pct: f64,
    #[serde(default)]
    pub swap_used_pct: f64,
    pub top_ips: Vec<IpCount>,
    /// True once the sliding baseline has enough data to be trusted.
    pub baseline_ready: bool,
    /// Set when the cycle could read no log lines though connections exist.
    pub watch_blind: bool,
    /// Set when the agent fell back to sampling under overload.
    pub overload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpCount {
    pub ip: String,
    pub requests: u64,
    pub err4xx: u64,
    pub sensitive_posts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEvent {
    pub ip: String,
    pub reason: String,
    pub ttl_secs: u64,
    pub strike: u32,
    /// Which enforcement layer applied it: `l3` (nftables) or `l7` (web server).
    pub layer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub kind: String,
    pub message: String,
    /// `info` | `warn` | `urgent`.
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageSummary {
    pub label: String,
    pub top_processes: Vec<ProcInfo>,
    pub persistence: Vec<String>,
    pub load1: f64,
    pub disk_pct: u8,
    pub inode_pct: u8,
    #[serde(default)]
    pub mem_used_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub starttime: u64,
    pub comm: String,
    pub exe: String,
    pub cwd: String,
    pub user: String,
    pub cpu_pct: f64,
    pub out_conns: Vec<String>,
    pub deleted_exe: bool,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub score: u32,
    pub verdict: String,
    pub rules: Vec<String>,
    pub context: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredRef {
    pub epoch: u64,
    pub seq: u64,
}

// ---------------------------------------------------------------------------
// Desired: hub -> VPS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredBody {
    pub mode: Mode,
    /// Threshold multiplier against the baseline p99.
    #[serde(default = "default_k")]
    pub k: f64,
    #[serde(default)]
    pub bans: Vec<DesiredBan>,
    #[serde(default)]
    pub unbans: Vec<String>,
    /// Short-lived operator allowances (TTL capped on the agent).
    #[serde(default)]
    pub allow_temp: Vec<TempAllow>,
    #[serde(default)]
    pub jobs: Vec<Job>,
    /// Monotonic marker: the agent runs `jobs` only when this exceeds the last
    /// job-seq it ran, so a job fires exactly once even though the body persists
    /// across unrelated desired edits (bans, mode).
    #[serde(default)]
    pub jobs_seq: u64,
    /// Cycle cadence hint; the systemd timer stays fixed, the agent only
    /// decides whether to skip a cycle. Clamped to [300, 900] on the agent.
    #[serde(default)]
    pub timer_interval_secs: u32,
    /// Policy-tier payload (patterns, trusted_proxies, mode->observe) that must
    /// carry a second, root/admin signature. `None` leaves policy unchanged.
    #[serde(default)]
    pub policy: Option<SignedPolicy>,
}

fn default_k() -> f64 {
    5.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesiredBan {
    pub ip: String,
    pub ttl_secs: u64,
    pub reason: String,
    /// Unix time the admin ordered the ban. Lets the agent apply only the
    /// *remaining* time (a later, unrelated desired change must not re-arm an
    /// old ban with a fresh TTL) and lets the hub show when it lapses.
    /// `0` for entries written before this field existed.
    #[serde(default)]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempAllow {
    pub ip: String,
    pub ttl_secs: u64,
}

/// Jobs the hub may ask the agent to run. Kept to a strict allow-list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Job {
    Hunt {
        days: u32,
    },
    /// Only honoured if the PID+starttime matches a process the agent itself
    /// labelled miner/php-bot in a triage within the last 30 minutes.
    Contain {
        pid: i32,
        starttime: u64,
    },
    Undo,
    /// Fetch one suspicious file that already appears in findings.
    Fetch {
        path: String,
    },
}

/// Policy changes carry their own root/admin signature, verified separately
/// from the online hub key, so a compromised hub cannot weaken a VPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// JSON text of a [`PolicyBody`], signed as raw bytes by the root key.
    pub env: String,
    pub sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyBody {
    pub agent_id: String,
    pub serial: u64,
    pub trusted_proxies: Vec<String>,
    pub patterns_yaml: Option<String>,
    /// Allow a remote switch back to observe (defaults off; agent config gates).
    pub allow_mode_observe: bool,
}
