//! Shared types, cryptographic envelope and parsers used by both the `sn`
//! agent and the `snhub` master.
//!
//! The protocol between agent and hub is deliberately small and append-only:
//! every message is wrapped in a signed [`Envelope`] that carries an explicit
//! `schema_version`, a monotonic `(epoch, seq)` and an `expires_at`, so that a
//! newer agent and an older hub (or vice versa) can still talk, replay is
//! rejected, and a stale desired-state never silently weakens a VPS.

pub mod crypto;
pub mod heuristic;
pub mod labels;
pub mod logfmt;
pub mod net;
pub mod schema;

/// Wire schema version. Bump the minor when adding optional fields (all new
/// fields must be `#[serde(default)]`), the major only for a breaking change.
pub const SCHEMA_VERSION: u32 = 1;

/// Agent/protocol version string, baked in at build time.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
