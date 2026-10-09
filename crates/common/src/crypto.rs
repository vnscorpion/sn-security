//! ed25519 signing of protocol envelopes.
//!
//! We sign the *exact bytes* of the serialized envelope text and transmit those
//! same bytes, so verification never depends on canonical JSON. Keys are
//! ed25519 (32-byte). Public keys are serialized as `ed25519:<hex>`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::SCHEMA_VERSION;
use crate::schema::{Envelope, Signed};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("bad key encoding: {0}")]
    KeyEncoding(&'static str),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed")]
    BadSignature,
    #[error("no trusted key matched key_id {0}")]
    NoKeyMatch(String),
    #[error("message expired at {expires_at}, now {now}")]
    Expired { expires_at: i64, now: i64 },
    #[error("schema version {got} not supported (max {max})")]
    SchemaTooNew { got: u32, max: u32 },
}

/// Parse a `ed25519:<hex>` public key.
pub fn parse_pubkey(s: &str) -> Result<VerifyingKey, CryptoError> {
    let hexpart = s
        .strip_prefix("ed25519:")
        .ok_or(CryptoError::KeyEncoding("missing ed25519: prefix"))?;
    let bytes = hex::decode(hexpart)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::KeyEncoding("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CryptoError::KeyEncoding("invalid ed25519 point"))
}

/// Encode a verifying key as `ed25519:<hex>`.
#[must_use]
pub fn encode_pubkey(vk: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(vk.to_bytes()))
}

/// Encode a signing key's 32-byte seed as hex (store 0600, never transmit).
#[must_use]
pub fn encode_secret(sk: &SigningKey) -> String {
    hex::encode(sk.to_bytes())
}

/// Parse a hex 32-byte signing-key seed.
pub fn parse_secret(s: &str) -> Result<SigningKey, CryptoError> {
    let bytes = hex::decode(s.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::KeyEncoding("secret key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Sign an envelope body, producing the transport wrapper.
pub fn sign<T: Serialize>(
    sk: &SigningKey,
    key_id: &str,
    env: &Envelope<T>,
) -> Result<Signed, CryptoError> {
    let text = serde_json::to_string(env)?;
    let sig: Signature = sk.sign(text.as_bytes());
    Ok(Signed {
        env: text,
        sig: hex::encode(sig.to_bytes()),
        key_id: key_id.to_string(),
    })
}

/// Verify a transport wrapper against a set of trusted keys and open the body.
///
/// `now` is unix seconds. Checks (in order): signature over the raw `env`
/// bytes against every trusted key, schema version ceiling, and expiry. The
/// caller is still responsible for `(epoch, seq)` monotonicity against its own
/// stored state — that cannot be done here without persistent context.
pub fn open<T: DeserializeOwned>(
    trusted: &[VerifyingKey],
    signed: &Signed,
    now: i64,
) -> Result<Envelope<T>, CryptoError> {
    let sig_bytes = hex::decode(&signed.sig)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::KeyEncoding("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_arr);

    let mut matched = false;
    for vk in trusted {
        if vk.verify(signed.env.as_bytes(), &signature).is_ok() {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err(CryptoError::BadSignature);
    }

    let env: Envelope<T> = serde_json::from_str(&signed.env)?;
    if env.schema_version > SCHEMA_VERSION {
        return Err(CryptoError::SchemaTooNew {
            got: env.schema_version,
            max: SCHEMA_VERSION,
        });
    }
    if env.expires_at < now {
        return Err(CryptoError::Expired {
            expires_at: env.expires_at,
            now,
        });
    }
    Ok(env)
}

/// Verify a raw detached signature (hex) over `msg` with any trusted key.
/// Used for the root-signed policy tier, which is not an [`Envelope`].
pub fn verify_detached(
    trusted: &[VerifyingKey],
    msg: &[u8],
    sig_hex: &str,
) -> Result<(), CryptoError> {
    let sig_bytes = hex::decode(sig_hex)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::KeyEncoding("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_arr);
    for vk in trusted {
        if vk.verify(msg, &signature).is_ok() {
            return Ok(());
        }
    }
    Err(CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{DesiredBody, Mode};
    use rand::rngs::OsRng;

    fn mk_env(seq: u64) -> Envelope<DesiredBody> {
        Envelope {
            schema_version: SCHEMA_VERSION,
            agent_id: "vps-b".into(),
            epoch: 1,
            seq,
            issued_at: 1000,
            expires_at: 2000,
            body: DesiredBody {
                mode: Mode::Enforce,
                ..Default::default()
            },
        }
    }

    #[test]
    fn round_trip_ok() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let signed = sign(&sk, "hub:1", &mk_env(5)).unwrap();
        let env: Envelope<DesiredBody> = open(&[vk], &signed, 1500).unwrap();
        assert_eq!(env.seq, 5);
        assert_eq!(env.body.mode, Mode::Enforce);
    }

    #[test]
    fn rejects_wrong_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        let signed = sign(&sk, "hub:1", &mk_env(5)).unwrap();
        let r: Result<Envelope<DesiredBody>, _> = open(&[other], &signed, 1500);
        assert!(matches!(r, Err(CryptoError::BadSignature)));
    }

    #[test]
    fn rejects_tampered_body() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let mut signed = sign(&sk, "hub:1", &mk_env(5)).unwrap();
        signed.env = signed.env.replace("enforce", "observe");
        let r: Result<Envelope<DesiredBody>, _> = open(&[vk], &signed, 1500);
        assert!(matches!(r, Err(CryptoError::BadSignature)));
    }

    #[test]
    fn rejects_expired() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let signed = sign(&sk, "hub:1", &mk_env(5)).unwrap();
        let r: Result<Envelope<DesiredBody>, _> = open(&[vk], &signed, 9999);
        assert!(matches!(r, Err(CryptoError::Expired { .. })));
    }

    #[test]
    fn newer_than_logic() {
        let e = mk_env(5);
        assert!(e.is_newer_than(1, 4));
        assert!(!e.is_newer_than(1, 5));
        assert!(!e.is_newer_than(2, 0));
        assert!(e.is_newer_than(0, 999));
    }
}
