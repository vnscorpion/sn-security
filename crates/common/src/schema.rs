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
    /// The most recent malware scan (`sn hunt`), so the hub can tell "scanned and
    /// clean" apart from "never scanned". `None` before the first scan.
    #[serde(default)]
    pub hunt: Option<HuntSummary>,
    /// State of the optional ClamAV engine on this VPS. `None` from agents that
    /// predate it.
    #[serde(default)]
    pub clamav: Option<ClamavInfo>,
    /// A fresh [`Evidence`] snapshot, present in the report that follows an
    /// `evidence` job.
    #[serde(default)]
    pub evidence: Option<Evidence>,
    /// Outcome of the last `remediate` job.
    #[serde(default)]
    pub remediation: Option<RemediationReport>,
}

/// What the hub needs to know about ClamAV on a VPS, to show its state and to
/// decide whether to offer "install".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClamavInfo {
    /// A `clamscan` or `clamdscan` binary is present.
    #[serde(default)]
    pub installed: bool,
    /// Hours since the signature database was last updated; `None` = no database.
    #[serde(default)]
    pub db_age_hours: Option<u32>,
    /// `""` (never tried), `running`, `ok` or `failed`.
    #[serde(default)]
    pub install_state: String,
    /// Short human-readable result of the last install attempt.
    #[serde(default)]
    pub install_message: String,
    /// This OS has an automatic install recipe.
    #[serde(default)]
    pub can_install: bool,
    /// The VPS obeys hub orders (`[remote] hub_orders`), so the install job will run.
    #[serde(default)]
    pub install_allowed: bool,
    /// `[hunt] clamav = "off"`: installed or not, hunts do not use it.
    #[serde(default)]
    pub disabled: bool,
    /// What the agent did with the last `install_clamav` order it received
    /// ("started", or why it ignored it), so a silent no-op is visible on the hub.
    #[serde(default)]
    pub last_order: String,
    /// Unix time of that order; 0 = none received.
    #[serde(default)]
    pub last_order_at: i64,
}

/// Outcome of one `sn hunt` run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HuntSummary {
    /// Which ClamAV engine scanned the files (`clamscan` / `clamdscan`), or empty.
    #[serde(default)]
    pub clamav_engine: String,
    /// Files ClamAV was asked to scan.
    #[serde(default)]
    pub clamav_scanned: u64,
    /// Why ClamAV did not run, or a problem it hit, or empty.
    #[serde(default)]
    pub clamav_note: String,
    /// Unix time the scan finished.
    pub at: i64,
    /// Files actually opened and scored.
    pub scanned: u64,
    pub duration_secs: u64,
    /// Files scoring "malicious" (>= 100): certain enough to quarantine.
    pub malicious: u32,
    /// Files scoring "suspicious" (70-99): for a human to look at.
    pub suspicious: u32,
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
    /// Web server answering on :80/:443 (`nginx`, `apache`, `litespeed`, or
    /// `unknown`). Empty from agents that predate this field.
    #[serde(default)]
    pub web_server: String,
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
    /// Access-log files the agent matched and is following. 0 means the
    /// configured globs match nothing, so the agent is blind.
    #[serde(default)]
    pub log_files: u32,
    /// Requests that are not static assets (pages, APIs, forms). The denominator
    /// for the shares below: images and scripts would drown the signal.
    #[serde(default)]
    pub dynamic_requests: u64,
    /// The busiest User-Agent strings this cycle, with how many distinct IPs
    /// sent them. A distributed bot shows up as one UA spread over many IPs.
    #[serde(default)]
    pub top_user_agents: Vec<PatternStat>,
    /// The busiest request *shapes* (method + path + parameter NAMES, never the
    /// values), e.g. `GET /?tss-sc&tsscat&tst10_filter`.
    #[serde(default)]
    pub top_shapes: Vec<PatternStat>,
    /// Who is using the CPU, grouped by user + program. Only filled while the
    /// server is notably busy (at least 50% over the interval); empty otherwise.
    #[serde(default)]
    pub top_cpu: Vec<CpuGroup>,
    pub top_ips: Vec<IpCount>,
    /// True once the sliding baseline has enough data to be trusted.
    pub baseline_ready: bool,
    /// Set when the cycle could read no log lines though connections exist.
    pub watch_blind: bool,
    /// Set when the agent fell back to sampling under overload.
    pub overload: bool,
}

/// One User-Agent or request shape as seen in a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStat {
    pub key: String,
    pub requests: u64,
    /// Distinct client addresses (IPv6 counted per /64). Saturates at the
    /// agent's tracking cap; see `ips_capped`.
    pub ips: u32,
    /// True when `ips` hit the tracking cap, so the real figure is higher.
    #[serde(default)]
    pub ips_capped: bool,
    /// The agent considers this a distributed-bot signature right now.
    #[serde(default)]
    pub flagged: bool,
    /// A few of the addresses involved (only for flagged patterns), for panels
    /// without a WAF where an IP block is the only tool left.
    #[serde(default)]
    pub sample_ips: Vec<String>,
}

/// CPU used by one program of one user (a hosted site's Linux user, usually).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuGroup {
    pub user: String,
    pub comm: String,
    /// Percent of the whole server (all cores), the same scale as
    /// `cpu_busy_pct`, so the groups add up to at most 100.
    pub cpu_pct: f64,
    pub procs: u32,
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
    /// Install ClamAV with the OS's package manager. Only honoured when the VPS
    /// obeys hub orders (`[remote] hub_orders`). An agent that predates this
    /// variant cannot parse a desired-state containing it, so the hub must send
    /// it only to agents that report the `clamav` capability.
    InstallClamav,
    /// Collect an [`Evidence`] snapshot and send it with the next report.
    /// Read-only. Only for agents that report the `evidence` capability.
    Evidence,
    /// Carry out a short list of [`Action`]s about an incident. Only honoured
    /// when the VPS obeys hub orders (`[remote] hub_orders`), and only for agents
    /// that report the `remediate` capability.
    Remediate {
        id: String,
        actions: Vec<Action>,
    },
    /// A job kind from a newer hub that this agent does not know: ignored, but
    /// the rest of the desired-state still applies.
    #[serde(other)]
    Unknown,
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

// ---------------------------------------------------------------------------
// Incident evidence, and what an operator or an AI may order done about it
// ---------------------------------------------------------------------------

/// A read-only snapshot of what is wrong on a VPS, collected on request and
/// sent to the hub. Every field comes from the (possibly compromised) machine,
/// so a consumer must treat the text in it as data, never as instructions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// Unix time it was collected.
    #[serde(default)]
    pub at: i64,
    /// The triage label (`miner`, `php-bot`, `ddos-l7`, ... or `unknown`).
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub load1: f64,
    /// The busiest or most suspicious processes.
    #[serde(default)]
    pub processes: Vec<EvProc>,
    /// Places a foothold can survive a reboot or a new login: shell start-up
    /// files, cron, `authorized_keys`, `ld.so.preload`.
    #[serde(default)]
    pub persistence: Vec<EvPersist>,
    /// Executables and unusual files in temp directories and users' hidden dirs.
    #[serde(default)]
    pub temp_files: Vec<EvFile>,
    /// Recent successful SSH logins.
    #[serde(default)]
    pub ssh_logins: Vec<EvLogin>,
    /// Services listening on a non-loopback address.
    #[serde(default)]
    pub listeners: Vec<EvListener>,
    /// Accounts that can log in with a shell.
    #[serde(default)]
    pub shell_users: Vec<EvUser>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvProc {
    pub pid: i32,
    /// With the pid, identifies one process even after pid reuse.
    pub starttime: u64,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub comm: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub exe_deleted: bool,
    /// Command line, cut short.
    #[serde(default)]
    pub cmdline: String,
    #[serde(default)]
    pub cpu_pct: f64,
    /// Established outbound connections as `ip:port`.
    #[serde(default)]
    pub out_conns: Vec<String>,
    #[serde(default)]
    pub score: u32,
    /// A kernel-thread-looking name (`[kworker/0:1]`) on a real user-space program.
    #[serde(default)]
    pub masquerade: bool,
    /// The command line or an outbound connection matches a known miner marker
    /// (stratum, xmrig, a mining-pool port...).
    #[serde(default)]
    pub miner_hint: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvPersist {
    /// `shell_rc`, `cron`, `authorized_keys`, `ld_preload`, `rc_local`.
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub user: String,
    /// 1-based line in the file.
    #[serde(default)]
    pub line_no: u32,
    /// The line, cut short.
    #[serde(default)]
    pub line: String,
    /// SHA-256 (hex) of the line with surrounding whitespace removed: lets a
    /// later action prove it is about this exact line.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvFile {
    pub path: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub mtime: i64,
    /// Starts with the ELF magic: a compiled program, not a script or data.
    #[serde(default)]
    pub elf: bool,
    #[serde(default)]
    pub executable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvLogin {
    pub user: String,
    pub ip: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub when: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvListener {
    pub port: u16,
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub comm: String,
    #[serde(default)]
    pub pid: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvUser {
    pub name: String,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub home: String,
    #[serde(default)]
    pub shell: String,
    /// Can administer the machine (group sudo, wheel, admin or adm, or the only
    /// regular account). Such an account is never locked automatically.
    #[serde(default)]
    pub admin: bool,
}

/// One thing the hub may order a VPS to do about an incident. A closed list:
/// there is deliberately no "run this command". The agent re-checks each action
/// against what it saw itself before it acts, and records how to undo it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// SIGKILL one process, identified by pid and start time.
    KillProcess { pid: i32, starttime: u64 },
    /// SIGKILL every live process of `user` running `exe` that is disguised (a
    /// kernel-thread name, a temp or hidden executable, a miner marker). For
    /// malware that respawns: by the time an order arrives the pid it had when
    /// the evidence was taken is usually gone, but the pattern is not.
    KillMatching { user: String, exe: String },
    /// Set a user's login shell to a non-login one (undoable).
    LockUserShell { user: String },
    /// Move a file into the quarantine vault (restorable with `sn restore`).
    QuarantineFile { path: String },
    /// Remove one line from a user's shell start-up file (backed up first).
    RemoveShellLine {
        path: String,
        line_no: u32,
        sha256: String,
    },
    /// `systemctl disable --now` a unit from a short allow-list (undoable).
    DisableService { unit: String },
}

/// What happened to each action of a remediation job.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionResult {
    /// Position in the job's action list.
    pub index: u32,
    pub ok: bool,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationReport {
    /// The job id the hub gave.
    pub id: String,
    pub at: i64,
    #[serde(default)]
    pub results: Vec<ActionResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_job_round_trips() {
        let j = serde_json::to_string(&Job::InstallClamav).unwrap();
        assert_eq!(j, r#"{"kind":"install_clamav"}"#);
        assert!(matches!(
            serde_json::from_str::<Job>(&j).unwrap(),
            Job::InstallClamav
        ));
    }

    #[test]
    fn a_job_kind_from_a_newer_hub_does_not_break_the_desired_state() {
        // Without the catch-all, one unknown job would make the whole
        // desired-state unparseable and the agent would stop obeying the hub.
        let j: Job = serde_json::from_str(r#"{"kind":"some_future_job","x":1}"#).unwrap();
        assert!(matches!(j, Job::Unknown));
    }

    #[test]
    fn a_report_and_a_hunt_summary_from_an_older_agent_still_parse() {
        // No `clamav` anywhere: what agents before this feature send.
        let s: HuntSummary = serde_json::from_str(
            r#"{"at":1,"scanned":2,"duration_secs":3,"malicious":0,"suspicious":0}"#,
        )
        .unwrap();
        assert_eq!(s.clamav_engine, "");
        assert_eq!(s.clamav_scanned, 0);
        let c: ClamavInfo = serde_json::from_str("{}").unwrap();
        assert!(!c.installed && c.db_age_hours.is_none() && !c.install_allowed);
    }
}
