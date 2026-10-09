//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds.
#[must_use]
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current unix time in milliseconds.
#[must_use]
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format a unix timestamp as a compact UTC string for file names / display.
#[must_use]
pub fn ts_compact(secs: i64) -> String {
    use time::OffsetDateTime;
    match OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

/// Truncate a string to `n` chars for table display.
#[must_use]
pub fn ellipsize(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
