//! A lightweight self-tuning baseline: 96 fifteen-minute slots across the day,
//! each an EWMA of the per-cycle busiest-IP request count. This is deliberately
//! small (a few hundred bytes) and is a v1 approximation of a per-IP-rate
//! distribution — good enough to set a dynamic threshold with a cold-start
//! guard, honest about not being a true p99. A histogram-based baseline is a
//! planned v1.1 upgrade (review DET-10).

use serde::{Deserialize, Serialize};

const SLOTS: usize = 96;
/// Observations needed in a slot before its threshold is trusted.
const MIN_OBS: u32 = 24;
const ALPHA: f64 = 0.15;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    rate: Vec<f64>,
    n: Vec<u32>,
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            rate: vec![0.0; SLOTS],
            n: vec![0; SLOTS],
        }
    }
}

#[must_use]
pub fn slot_of(unix_secs: i64) -> usize {
    let day = unix_secs.rem_euclid(86_400) as usize;
    (day / 900).min(SLOTS - 1)
}

impl Baseline {
    /// Fold this cycle's busiest-IP request count into the slot's EWMA.
    pub fn observe(&mut self, slot: usize, busiest_ip_requests: u64) {
        let x = busiest_ip_requests as f64;
        if self.n[slot] == 0 {
            self.rate[slot] = x;
        } else {
            self.rate[slot] = ALPHA * x + (1.0 - ALPHA) * self.rate[slot];
        }
        self.n[slot] = self.n[slot].saturating_add(1);
    }

    #[must_use]
    pub fn ready(&self, slot: usize) -> bool {
        self.n[slot] >= MIN_OBS
    }

    /// Flagging threshold for a slot: `max(min_requests, k * ewma)`. Until the
    /// slot is warm, only `min_requests` (plus the fixed patterns) applies.
    #[must_use]
    pub fn threshold(&self, slot: usize, k: f64, min_requests: u32) -> u64 {
        if !self.ready(slot) {
            return u64::from(min_requests);
        }
        let dynamic = (k * self.rate[slot]).ceil() as u64;
        dynamic.max(u64::from(min_requests))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_uses_min_requests() {
        let b = Baseline::default();
        assert!(!b.ready(0));
        assert_eq!(b.threshold(0, 5.0, 120), 120);
    }

    #[test]
    fn warm_slot_scales_with_k() {
        let mut b = Baseline::default();
        for _ in 0..MIN_OBS {
            b.observe(10, 100);
        }
        assert!(b.ready(10));
        // ~5 * 100 = 500 > min 120
        assert!(b.threshold(10, 5.0, 120) >= 480);
    }

    #[test]
    fn slot_math() {
        assert_eq!(slot_of(0), 0);
        assert_eq!(slot_of(900), 1);
        assert_eq!(slot_of(86_400 - 1), 95);
    }
}
