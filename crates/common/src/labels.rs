//! Triage labels. `Mixed` exists so the AI/judgment path in the hub has a
//! defined value when more than one signature fires (referenced by the plan's
//! §6 but previously undefined).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Label {
    Miner,
    PhpBot,
    DdosL7,
    Bruteforce,
    DiskFull,
    Mixed,
    Unknown,
}

impl Label {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Miner => "miner",
            Label::PhpBot => "php-bot",
            Label::DdosL7 => "ddos-l7",
            Label::Bruteforce => "bruteforce",
            Label::DiskFull => "disk-full",
            Label::Mixed => "mixed",
            Label::Unknown => "unknown",
        }
    }

    /// Labels for which auto-containment (cgroup throttle, never kill) is
    /// allowed when the agent is in enforce mode — and only with corroborating
    /// evidence beyond CPU alone (outbound pool connection, deleted/foreign exe).
    #[must_use]
    pub fn auto_containable(self) -> bool {
        matches!(self, Label::Miner | Label::PhpBot)
    }
}
