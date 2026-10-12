//! Time-based one-time passwords (RFC 6238) for Google Authenticator, Authy,
//! 1Password and the like: HMAC-SHA1, 30-second steps, 6 digits.
//!
//! The secret is 160 random bits, shown once as base32 (and as a QR code) when the
//! admin enrols. A code is accepted for the current step and one step either side
//! (clock drift), and never twice: the last accepted step is remembered, so an
//! observed code cannot be replayed within its window.

use hmac::{Hmac, Mac};
use sha1::Sha1;

pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
/// Steps of clock drift tolerated on each side.
const DRIFT_STEPS: i64 = 1;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, upper case, no padding.
#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode base32, ignoring case, spaces, dashes and `=` padding. `None` on any
/// other character.
#[must_use]
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        if matches!(c, ' ' | '-' | '=') {
            continue;
        }
        let v = ALPHABET
            .iter()
            .position(|&a| a as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// A new random secret, base32.
#[must_use]
pub fn new_secret() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base32_encode(&buf)
}

/// The code for one time step.
#[must_use]
pub fn code_for_step(secret: &[u8], step: u64) -> String {
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = (u32::from(h[off] & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    format!(
        "{:0width$}",
        bin % 10u32.pow(DIGITS),
        width = DIGITS as usize
    )
}

/// Constant-time equality of two short strings.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Check a code typed by the admin. Returns the step it matched, which the caller
/// stores as the new "last used" step; `None` when it is wrong, malformed, or a
/// step that was already used (a replay).
#[cfg(test)]
#[must_use]
pub fn verify(secret_b32: &str, input: &str, now_secs: u64, last_used_step: u64) -> Option<u64> {
    verify_at(secret_b32, input, now_secs, 0, last_used_step)
}

/// Like [`verify`], around `now + offset_steps`: the drift between this server's
/// clock and the admin's authenticator, learned at enrolment (RFC 6238 §6), so a
/// server clock that is off by a minute or two does not lock the admin out.
#[must_use]
pub fn verify_at(
    secret_b32: &str,
    input: &str,
    now_secs: u64,
    offset_steps: i64,
    last_used_step: u64,
) -> Option<u64> {
    let digits = clean_code(input)?;
    let secret = base32_decode(secret_b32)?;
    let center = (now_secs / STEP_SECS).checked_add_signed(offset_steps)?;
    // Compare against every step in the window (no early exit on a match, so the
    // time taken does not say which step it was).
    let mut matched: Option<u64> = None;
    for d in -DRIFT_STEPS..=DRIFT_STEPS {
        let Some(step) = center.checked_add_signed(d) else {
            continue;
        };
        if ct_eq(&code_for_step(&secret, step), &digits) && step > last_used_step {
            matched = Some(matched.map_or(step, |m| m.max(step)));
        }
    }
    matched
}

/// The six digits of what was typed (spaces allowed), or `None`.
fn clean_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    (digits.len() == DIGITS as usize && digits.chars().all(|c| c.is_ascii_digit()))
        .then_some(digits)
}

/// Widest clock difference searched at enrolment: ten steps (five minutes) each way.
pub const ENROL_SEARCH_STEPS: i64 = 10;

/// At enrolment only: at which step offset from this server's clock does the
/// typed code match? `Some(0)` means the clocks agree; `Some(4)` means the
/// authenticator runs about two minutes ahead of this server; `None` means the
/// code fits this secret at no time within `max_steps` either way, i.e. the app
/// holds a different key (an old entry, a mistyped key). The offset nearest zero
/// wins.
#[must_use]
pub fn find_offset(secret_b32: &str, input: &str, now_secs: u64, max_steps: i64) -> Option<i64> {
    let digits = clean_code(input)?;
    let secret = base32_decode(secret_b32)?;
    let now_step = now_secs / STEP_SECS;
    let mut best: Option<i64> = None;
    for d in -max_steps..=max_steps {
        let Some(step) = now_step.checked_add_signed(d) else {
            continue;
        };
        if ct_eq(&code_for_step(&secret, step), &digits)
            && best.is_none_or(|b: i64| d.abs() < b.abs())
        {
            best = Some(d);
        }
    }
    best
}

/// The `otpauth://` link an authenticator app reads from the QR code.
#[must_use]
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    fn enc(s: &str) -> String {
        let mut o = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                o.push(b as char);
            } else {
                o.push_str(&format!("%{b:02X}"));
            }
        }
        o
    }
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        enc(issuer)
    )
}

/// The QR code of `data` as an inline SVG, or `None` if it does not fit.
#[must_use]
pub fn qr_svg(data: &str) -> Option<String> {
    use qrcode::{EcLevel, QrCode, render::svg};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1, secret "12345678901234567890". The RFC lists
    // 8-digit codes; ours are the last 6 of the same number.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        for (time, want) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(
                code_for_step(RFC_SECRET, time / STEP_SECS),
                want,
                "t={time}"
            );
        }
    }

    #[test]
    fn base32_round_trips_and_matches_known_values() {
        assert_eq!(
            base32_encode(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(
            base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            RFC_SECRET
        );
        // Case, spaces, dashes and padding are tolerated (people retype these).
        assert_eq!(
            base32_decode("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq====").unwrap(),
            RFC_SECRET
        );
        assert!(base32_decode("not*base32").is_none());
        for len in 0..40usize {
            let data: Vec<u8> = (0..len as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn a_new_secret_is_160_bits_and_different_each_time() {
        let a = new_secret();
        assert_eq!(base32_decode(&a).unwrap().len(), 20);
        assert_ne!(a, new_secret());
    }

    #[test]
    fn a_code_is_accepted_once_with_one_step_of_drift() {
        let secret = base32_encode(RFC_SECRET);
        let t = 1_111_111_111u64; // step 37037037
        let step = t / STEP_SECS;
        let code = code_for_step(RFC_SECRET, step);
        assert_eq!(verify(&secret, &code, t, 0), Some(step));
        // Spaces typed inside are fine.
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(verify(&secret, &spaced, t, 0), Some(step));
        // The same code again (replay) is refused once its step was used.
        assert_eq!(verify(&secret, &code, t, step), None);
        // Drift: the previous and next step's codes work, two steps off does not.
        let prev = code_for_step(RFC_SECRET, step - 1);
        let next = code_for_step(RFC_SECRET, step + 1);
        let far = code_for_step(RFC_SECRET, step + 3);
        assert_eq!(verify(&secret, &prev, t, 0), Some(step - 1));
        assert_eq!(verify(&secret, &next, t, 0), Some(step + 1));
        assert_eq!(verify(&secret, &far, t, 0), None);
    }

    #[test]
    fn a_learned_clock_offset_moves_the_window_and_enrolment_finds_it() {
        let secret = base32_encode(b"12345678901234567890");
        let key = base32_decode(&secret).unwrap();
        let t = 1_700_000_000u64;
        let step = t / STEP_SECS;
        // The phone runs four steps (two minutes) ahead of this server.
        let phone = code_for_step(&key, step + 4);
        assert_eq!(
            verify(&secret, &phone, t, 0),
            None,
            "plain window misses it"
        );
        assert_eq!(find_offset(&secret, &phone, t, ENROL_SEARCH_STEPS), Some(4));
        assert_eq!(verify_at(&secret, &phone, t, 4, 0), Some(step + 4));
        // And behind.
        let late = code_for_step(&key, step - 7);
        assert_eq!(find_offset(&secret, &late, t, ENROL_SEARCH_STEPS), Some(-7));
        assert_eq!(verify_at(&secret, &late, t, -7, 0), Some(step - 7));
        // Agreeing clocks give 0.
        let now = code_for_step(&key, step);
        assert_eq!(find_offset(&secret, &now, t, ENROL_SEARCH_STEPS), Some(0));
        // A code from another key fits at no offset (unless by a one-in-a-million
        // chance, which this fixed pair does not hit).
        let other = base32_encode(b"abcdefghijabcdefghij");
        let foreign = code_for_step(&base32_decode(&other).unwrap(), step);
        assert_eq!(find_offset(&secret, &foreign, t, ENROL_SEARCH_STEPS), None);
        // Too far is too far.
        let far = code_for_step(&key, step + 40);
        assert_eq!(find_offset(&secret, &far, t, ENROL_SEARCH_STEPS), None);
        assert_eq!(find_offset(&secret, "12x456", t, 10), None);
    }

    #[test]
    fn malformed_input_is_rejected_without_a_panic() {
        let secret = base32_encode(RFC_SECRET);
        for bad in ["", "12345", "1234567", "abcdef", "12 34 5", "١٢٣٤٥٦"] {
            assert_eq!(verify(&secret, bad, 1_111_111_111, 0), None, "{bad:?}");
        }
        assert_eq!(verify("!!!", "123456", 1_111_111_111, 0), None);
    }

    #[test]
    fn the_enrolment_link_carries_everything_an_app_needs() {
        let u = otpauth_uri("SN Secure", "admin@sec.sgd.ovh", "ABCDEF234567");
        assert!(u.starts_with("otpauth://totp/SN%20Secure:admin%40sec.sgd.ovh?"));
        for part in [
            "secret=ABCDEF234567",
            "issuer=SN%20Secure",
            "digits=6",
            "period=30",
            "algorithm=SHA1",
        ] {
            assert!(u.contains(part), "{u}");
        }
    }

    #[test]
    fn the_qr_code_is_an_svg() {
        let svg = qr_svg(&otpauth_uri("SN Secure", "admin", &new_secret())).unwrap();
        assert!(svg.contains("<svg") && svg.contains("</svg>"));
    }
}
