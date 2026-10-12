//! Passkeys (WebAuthn) for the admin login, just enough for one relying party and
//! one account: registration with `attestation: "none"` and assertion with ES256
//! (ECDSA P-256 with SHA-256), which every platform authenticator and security key
//! supports.
//!
//! What is checked, per the WebAuthn spec: the client data (`type`, the one-time
//! `challenge` this server issued, the `origin`), the authenticator data (the
//! SHA-256 of the relying-party id, the user-present flag), the signature over
//! `authenticatorData || SHA-256(clientDataJSON)`, and the signature counter
//! (which must only increase, if the authenticator keeps one). Attestation
//! statements are not verified: for a private admin login the passkey is trusted
//! because the admin, already signed in with a password, enrolled it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ciborium::value::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// COSE algorithm id for ES256.
pub const ALG_ES256: i64 = -7;
const FLAG_UP: u8 = 0x01;
const FLAG_AT: u8 = 0x40;
const MAX_CRED_ID: usize = 1023;

#[must_use]
pub fn b64e(data: &[u8]) -> String {
    B64.encode(data)
}

#[must_use]
pub fn b64d(s: &str) -> Option<Vec<u8>> {
    B64.decode(s.trim_end_matches('=')).ok()
}

/// A fresh one-time challenge: 256 random bits, base64url.
#[must_use]
pub fn new_challenge() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    b64e(&buf)
}

/// A registered passkey: its id and its P-256 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// base64url of the credential id.
    pub id: String,
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub sign_count: u32,
}

impl Credential {
    fn verifying_key(&self) -> Result<VerifyingKey, String> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&self.x);
        sec1[33..].copy_from_slice(&self.y);
        VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| "khoá công khai của passkey không hợp lệ".to_string())
    }
}

// ---------------------------------------------------------------------------
// Client data and authenticator data
// ---------------------------------------------------------------------------

fn check_client_data(
    client_data_json: &[u8],
    want_type: &str,
    challenge: &str,
    origin: &str,
) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|_| "clientDataJSON không phải JSON".to_string())?;
    let get = |k: &str| v.get(k).and_then(serde_json::Value::as_str).unwrap_or("");
    if get("type") != want_type {
        return Err("sai loại yêu cầu WebAuthn".into());
    }
    // The challenge is one-time and was issued by this server for this login.
    if get("challenge") != challenge {
        return Err("challenge không khớp (hết hạn hoặc dùng lại)".into());
    }
    if get("origin") != origin {
        return Err(format!("origin không khớp (cần {origin})"));
    }
    if v.get("crossOrigin").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err("yêu cầu từ trang khác (crossOrigin)".into());
    }
    Ok(())
}

struct AuthData<'a> {
    rp_hash: &'a [u8],
    flags: u8,
    counter: u32,
    rest: &'a [u8],
}

fn parse_auth_data(d: &[u8]) -> Option<AuthData<'_>> {
    if d.len() < 37 {
        return None;
    }
    Some(AuthData {
        rp_hash: &d[..32],
        flags: d[32],
        counter: u32::from_be_bytes([d[33], d[34], d[35], d[36]]),
        rest: &d[37..],
    })
}

fn check_rp_and_presence(a: &AuthData<'_>, rp_id: &str) -> Result<(), String> {
    if a.rp_hash != Sha256::digest(rp_id.as_bytes()).as_slice() {
        return Err("passkey này không dành cho tên miền của hub".into());
    }
    if a.flags & FLAG_UP == 0 {
        return Err("thiếu xác nhận người dùng có mặt (UP)".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

fn map_get<'a>(map: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn int_key(n: i64) -> Value {
    Value::Integer(n.into())
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

/// Read the credential a new passkey reports.
///
/// # Errors
/// A Vietnamese reason when anything the spec requires does not hold.
pub fn verify_registration(
    attestation_object: &[u8],
    client_data_json: &[u8],
    expected_challenge: &str,
    rp_id: &str,
    origin: &str,
    claimed_id: &[u8],
) -> Result<Credential, String> {
    check_client_data(
        client_data_json,
        "webauthn.create",
        expected_challenge,
        origin,
    )?;

    let att: Value = ciborium::de::from_reader(attestation_object)
        .map_err(|_| "attestationObject không đọc được".to_string())?;
    let Value::Map(att) = att else {
        return Err("attestationObject không phải bản đồ CBOR".into());
    };
    let Some(Value::Bytes(auth_data)) = map_get(&att, &Value::Text("authData".into())) else {
        return Err("attestationObject thiếu authData".into());
    };
    let a = parse_auth_data(auth_data).ok_or("authData quá ngắn")?;
    check_rp_and_presence(&a, rp_id)?;
    if a.flags & FLAG_AT == 0 {
        return Err("authData không chứa credential mới".into());
    }
    // attestedCredentialData: aaguid(16) | idLen(2) | id | COSE key
    let r = a.rest;
    if r.len() < 18 {
        return Err("attestedCredentialData quá ngắn".into());
    }
    let id_len = usize::from(u16::from_be_bytes([r[16], r[17]]));
    if id_len == 0 || id_len > MAX_CRED_ID || r.len() < 18 + id_len {
        return Err("độ dài credential id không hợp lệ".into());
    }
    let cred_id = &r[18..18 + id_len];
    if cred_id != claimed_id {
        return Err("credential id không khớp".into());
    }
    let mut cur = std::io::Cursor::new(&r[18 + id_len..]);
    let key: Value =
        ciborium::de::from_reader(&mut cur).map_err(|_| "khoá COSE không đọc được".to_string())?;
    let Value::Map(key) = key else {
        return Err("khoá COSE không phải bản đồ".into());
    };
    let get_i = |k: i64| map_get(&key, &int_key(k));
    if get_i(1).and_then(as_i64) != Some(2) {
        return Err("chỉ hỗ trợ khoá EC2 (loại 2)".into());
    }
    if get_i(3).and_then(as_i64) != Some(ALG_ES256) {
        return Err("chỉ hỗ trợ thuật toán ES256 (ECDSA P-256)".into());
    }
    if get_i(-1).and_then(as_i64) != Some(1) {
        return Err("chỉ hỗ trợ đường cong P-256".into());
    }
    let coord = |k: i64| -> Result<[u8; 32], String> {
        match get_i(k) {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(b);
                Ok(out)
            }
            _ => Err("toạ độ khoá không hợp lệ".into()),
        }
    };
    let cred = Credential {
        id: b64e(cred_id),
        x: coord(-2)?,
        y: coord(-3)?,
        sign_count: a.counter,
    };
    cred.verifying_key()?; // the point must be on the curve
    Ok(cred)
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/// Verify a sign-in with a registered passkey. Returns the new signature counter
/// to store.
///
/// # Errors
/// A Vietnamese reason: wrong challenge/origin/rp, no user presence, a bad
/// signature, or a counter that did not increase (a cloned authenticator).
pub fn verify_assertion(
    cred: &Credential,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
    expected_challenge: &str,
    rp_id: &str,
    origin: &str,
) -> Result<u32, String> {
    check_client_data(client_data_json, "webauthn.get", expected_challenge, origin)?;
    let a = parse_auth_data(authenticator_data).ok_or("authenticatorData quá ngắn")?;
    check_rp_and_presence(&a, rp_id)?;

    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    let sig = Signature::from_der(signature_der).map_err(|_| "chữ ký không hợp lệ".to_string())?;
    cred.verifying_key()?
        .verify(&signed, &sig)
        .map_err(|_| "chữ ký không khớp với passkey".to_string())?;

    // A counter that does not move forward means the key may have been cloned.
    // Authenticators that keep no counter report 0 every time: allow that.
    if (cred.sign_count != 0 || a.counter != 0) && a.counter <= cred.sign_count {
        return Err("bộ đếm chữ ký không tăng: passkey có thể đã bị sao chép".into());
    }
    Ok(a.counter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    const RP: &str = "sec.sgd.ovh";
    const ORIGIN: &str = "https://sec.sgd.ovh";

    /// A software authenticator: makes the bytes a browser would hand us.
    struct Authn {
        sk: SigningKey,
        id: Vec<u8>,
    }

    impl Authn {
        fn new() -> Self {
            use rand::RngCore;
            let mut id = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut id);
            Authn {
                sk: SigningKey::random(&mut rand::rngs::OsRng),
                id,
            }
        }

        fn cose_key(&self) -> Vec<u8> {
            let point = self.sk.verifying_key().to_encoded_point(false);
            let key = Value::Map(vec![
                (int_key(1), int_key(2)),
                (int_key(3), int_key(ALG_ES256)),
                (int_key(-1), int_key(1)),
                (int_key(-2), Value::Bytes(point.x().unwrap().to_vec())),
                (int_key(-3), Value::Bytes(point.y().unwrap().to_vec())),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&key, &mut out).unwrap();
            out
        }

        fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
            serde_json::json!({"type": kind, "challenge": challenge, "origin": origin})
                .to_string()
                .into_bytes()
        }

        fn auth_data(rp: &str, flags: u8, counter: u32, attested: Option<Vec<u8>>) -> Vec<u8> {
            let mut d = Sha256::digest(rp.as_bytes()).to_vec();
            d.push(flags);
            d.extend_from_slice(&counter.to_be_bytes());
            if let Some(a) = attested {
                d.extend_from_slice(&a);
            }
            d
        }

        fn attested(&self) -> Vec<u8> {
            let mut a = vec![0u8; 16]; // aaguid
            a.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
            a.extend_from_slice(&self.id);
            a.extend_from_slice(&self.cose_key());
            a
        }

        fn attestation_object(&self, rp: &str) -> Vec<u8> {
            let ad = Self::auth_data(rp, FLAG_UP | FLAG_AT, 0, Some(self.attested()));
            let obj = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (Value::Text("authData".into()), Value::Bytes(ad)),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&obj, &mut out).unwrap();
            out
        }

        fn register(&self, challenge: &str) -> Result<Credential, String> {
            verify_registration(
                &self.attestation_object(RP),
                &Self::client_data("webauthn.create", challenge, ORIGIN),
                challenge,
                RP,
                ORIGIN,
                &self.id,
            )
        }

        /// (authenticatorData, clientDataJSON, signature DER)
        fn assert(&self, challenge: &str, counter: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let ad = Self::auth_data(RP, FLAG_UP, counter, None);
            let cd = Self::client_data("webauthn.get", challenge, ORIGIN);
            let mut msg = ad.clone();
            msg.extend_from_slice(&Sha256::digest(&cd));
            let sig: Signature = self.sk.sign(&msg);
            (ad, cd, sig.to_der().as_bytes().to_vec())
        }
    }

    #[test]
    fn a_new_passkey_registers_and_then_signs_in() {
        let dev = Authn::new();
        let c1 = new_challenge();
        let cred = dev.register(&c1).unwrap();
        assert_eq!(cred.id, b64e(&dev.id));
        assert_eq!(cred.sign_count, 0);

        let c2 = new_challenge();
        let (ad, cd, sig) = dev.assert(&c2, 1);
        assert_eq!(
            verify_assertion(&cred, &ad, &cd, &sig, &c2, RP, ORIGIN),
            Ok(1)
        );
    }

    #[test]
    fn registration_refuses_the_wrong_challenge_origin_rp_or_id() {
        let dev = Authn::new();
        let ch = new_challenge();
        let obj = dev.attestation_object(RP);
        let cd = |c: &str, o: &str| Authn::client_data("webauthn.create", c, o);
        // Wrong challenge, wrong origin, wrong type.
        assert!(verify_registration(&obj, &cd("other", ORIGIN), &ch, RP, ORIGIN, &dev.id).is_err());
        assert!(
            verify_registration(
                &obj,
                &cd(&ch, "https://evil.example"),
                &ch,
                RP,
                ORIGIN,
                &dev.id
            )
            .is_err()
        );
        assert!(
            verify_registration(
                &obj,
                &Authn::client_data("webauthn.get", &ch, ORIGIN),
                &ch,
                RP,
                ORIGIN,
                &dev.id
            )
            .is_err()
        );
        // A passkey made for another site.
        let other_rp = dev.attestation_object("evil.example");
        let e =
            verify_registration(&other_rp, &cd(&ch, ORIGIN), &ch, RP, ORIGIN, &dev.id).unwrap_err();
        assert!(e.contains("tên miền"), "{e}");
        // The id the browser claims must be the one in the data.
        assert!(
            verify_registration(&obj, &cd(&ch, ORIGIN), &ch, RP, ORIGIN, b"different").is_err()
        );
        // Garbage.
        assert!(
            verify_registration(b"\xff\xff", &cd(&ch, ORIGIN), &ch, RP, ORIGIN, &dev.id).is_err()
        );
    }

    #[test]
    fn sign_in_refuses_every_way_it_can_be_forged_or_replayed() {
        let dev = Authn::new();
        let cred = dev.register(&new_challenge()).unwrap();
        let ch = new_challenge();
        let (ad, cd, sig) = dev.assert(&ch, 5);
        let ok = |c: &Credential, ad: &[u8], cd: &[u8], sig: &[u8], ch: &str| {
            verify_assertion(c, ad, cd, sig, ch, RP, ORIGIN)
        };
        assert_eq!(ok(&cred, &ad, &cd, &sig, &ch), Ok(5));
        // A different challenge (replay of an old response).
        assert!(ok(&cred, &ad, &cd, &sig, &new_challenge()).is_err());
        // A signature by another key.
        let (_, _, other_sig) = Authn::new().assert(&ch, 5);
        assert!(ok(&cred, &ad, &cd, &other_sig, &ch).is_err());
        // Tampered authenticator data (counter changed) breaks the signature.
        let mut bad_ad = ad.clone();
        bad_ad[36] ^= 1;
        assert!(ok(&cred, &bad_ad, &cd, &sig, &ch).is_err());
        // Right key, wrong site.
        let wrong_rp = Authn::auth_data("evil.example", FLAG_UP, 5, None);
        let mut msg = wrong_rp.clone();
        msg.extend_from_slice(&Sha256::digest(&cd));
        let s: Signature = dev.sk.sign(&msg);
        let e = ok(&cred, &wrong_rp, &cd, s.to_der().as_bytes(), &ch).unwrap_err();
        assert!(e.contains("tên miền"), "{e}");
        // Garbage signature.
        assert!(ok(&cred, &ad, &cd, b"nonsense", &ch).is_err());
    }

    #[test]
    fn the_counter_must_move_forward_unless_the_device_keeps_none() {
        let dev = Authn::new();
        let mut cred = dev.register(&new_challenge()).unwrap();
        let ch = new_challenge();
        let (ad, cd, sig) = dev.assert(&ch, 7);
        assert_eq!(
            verify_assertion(&cred, &ad, &cd, &sig, &ch, RP, ORIGIN),
            Ok(7)
        );
        cred.sign_count = 7;
        // The same counter again, or lower, is a sign of a clone.
        let (ad2, cd2, sig2) = dev.assert(&ch, 7);
        let e = verify_assertion(&cred, &ad2, &cd2, &sig2, &ch, RP, ORIGIN).unwrap_err();
        assert!(e.contains("sao chép"), "{e}");
        // A device without a counter reports 0 each time and is fine.
        cred.sign_count = 0;
        let (ad3, cd3, sig3) = dev.assert(&ch, 0);
        assert_eq!(
            verify_assertion(&cred, &ad3, &cd3, &sig3, &ch, RP, ORIGIN),
            Ok(0)
        );
    }

    #[test]
    fn user_presence_is_required() {
        let dev = Authn::new();
        let cred = dev.register(&new_challenge()).unwrap();
        let ch = new_challenge();
        let ad = Authn::auth_data(RP, 0, 1, None); // no UP flag
        let cd = Authn::client_data("webauthn.get", &ch, ORIGIN);
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(&cd));
        let sig: Signature = dev.sk.sign(&msg);
        let e = verify_assertion(&cred, &ad, &cd, sig.to_der().as_bytes(), &ch, RP, ORIGIN)
            .unwrap_err();
        assert!(e.contains("UP"), "{e}");
    }

    #[test]
    fn base64url_helpers_round_trip_and_reject_junk() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(b64d(&b64e(&data)).unwrap(), data);
        assert!(b64d("not base64!").is_none());
        assert_eq!(new_challenge().len(), 43);
        assert_ne!(new_challenge(), new_challenge());
    }
}
