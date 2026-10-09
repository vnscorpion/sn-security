//! Build and sign desired-state envelopes for agents.

use anyhow::Result;
use snsec_common::SCHEMA_VERSION;
use snsec_common::crypto;
use snsec_common::schema::{DesiredBody, Envelope, Signed};

use crate::keys::HubKey;

/// Build a signed desired envelope. `version` is the monotonic seq the agent
/// uses for replay defence; `expires_at` is generous because the agent only
/// pulls every 5–15 minutes and may be briefly offline.
pub fn sign_desired(
    hubkey: &HubKey,
    agent_id: &str,
    epoch: u64,
    version: u64,
    body: DesiredBody,
    now: i64,
) -> Result<Signed> {
    let env = Envelope {
        schema_version: SCHEMA_VERSION,
        agent_id: agent_id.to_string(),
        epoch,
        seq: version,
        issued_at: now,
        expires_at: now + 7 * 86_400,
        body,
    };
    Ok(crypto::sign(&hubkey.signing, "hub", &env)?)
}
