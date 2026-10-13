//! A lightweight self-tuning baseline: 96 fifteen-minute slots across the day,
//! each an EWMA of the per-cycle busiest address's dynamic requests on one site,
//! plus one EWMA over every slot. This is deliberately small (a few hundred
//! bytes) and is a v1 approximation of a per-IP-rate distribution — good enough
//! to set a dynamic threshold with a cold-start guard, honest about not being a
//! true p99. A histogram-based baseline is a planned v1.1 upgrade (review
//! DET-10).
//!
//! Only cycles that look like ordinary traffic are learned from: not one that
//! read nothing, nor a backlog read after the agent was off (hours of traffic in
//! one cycle). A slot gets about three such cycles a day, so it takes some eight
//! days to be trusted on its own; until then the all-slot average stands in.

use serde::{Deserialize, Serialize};

const SLOTS: usize = 96;
/// Observations needed in a slot before its own threshold is used.
const MIN_OBS: u32 = 24;
/// Observations of the all-slot average before it stands in for a cold slot
/// (about two hours of traffic).
const GLOBAL_MIN_OBS: u32 = 24;
/// Observations of the all-slot average after which the baseline counts as
/// learned even where a slot is still cold (about one day of traffic), so a
/// quiet slot that never fills up does not keep `rate` report-only for ever.
const GLOBAL_READY_OBS: u32 = 288;
const ALPHA: f64 = 0.15;
/// What the counts are: a baseline stored by an agent that counted every log
/// line (assets too) has another unit, and is started again.
const COUNTS: &str = "dynamic";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    rate: Vec<f64>,
    n: Vec<u32>,
    #[serde(default)]
    global: f64,
    #[serde(default)]
    global_n: u32,
    #[serde(default)]
    counts: String,
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            rate: vec![0.0; SLOTS],
            n: vec![0; SLOTS],
            global: 0.0,
            global_n: 0,
            counts: COUNTS.into(),
        }
    }
}

#[must_use]
pub fn slot_of(unix_secs: i64) -> usize {
    let day = unix_secs.rem_euclid(86_400) as usize;
    (day / 900).min(SLOTS - 1)
}

fn ewma(old: f64, n: u32, x: f64) -> f64 {
    if n == 0 {
        x
    } else {
        ALPHA * x + (1.0 - ALPHA) * old
    }
}

impl Baseline {
    /// Take a stored baseline only if it counts what this agent counts and has
    /// the right shape; otherwise start again.
    #[must_use]
    pub fn checked(self) -> Baseline {
        if self.counts == COUNTS && self.rate.len() == SLOTS && self.n.len() == SLOTS {
            self
        } else {
            Baseline::default()
        }
    }

    /// Learn from one representative cycle: `value` (see
    /// `decide::robust_busiest`), clamped to twice what the slot's current
    /// threshold allows for one address (`threshold / k`), so even addresses
    /// that stay just under the bar for hours raise it only step by step. The
    /// caller skips idle and backlog cycles, and caps the threshold itself.
    pub fn learn(&mut self, slot: usize, value: u64, k: f64, min_requests: u32) {
        let per_address = self.threshold(slot, k, min_requests) as f64 / k.max(1.0);
        let cap = (2.0 * per_address).ceil() as u64;
        self.observe(slot, value.min(cap));
    }

    /// Fold one cycle's count into the slot's EWMA and the all-slot one.
    pub fn observe(&mut self, slot: usize, busiest_dynamic: u64) {
        let x = busiest_dynamic as f64;
        self.rate[slot] = ewma(self.rate[slot], self.n[slot], x);
        self.n[slot] = self.n[slot].saturating_add(1);
        self.global = ewma(self.global, self.global_n, x);
        self.global_n = self.global_n.saturating_add(1);
    }

    /// Has the baseline learned this server's traffic? The slot has, or about a
    /// day of traffic has been seen overall.
    #[must_use]
    pub fn ready(&self, slot: usize) -> bool {
        self.n[slot] >= MIN_OBS || self.global_n >= GLOBAL_READY_OBS
    }

    /// Flagging threshold for a slot: `max(min_requests, k * ewma)`, with the
    /// slot's own EWMA once it is warm, else the all-slot one once that has a
    /// couple of hours behind it, else just `min_requests`.
    #[must_use]
    pub fn threshold(&self, slot: usize, k: f64, min_requests: u32) -> u64 {
        let learned = if self.n[slot] >= MIN_OBS {
            self.rate[slot]
        } else if self.global_n >= GLOBAL_MIN_OBS {
            self.global
        } else {
            return u64::from(min_requests);
        };
        let dynamic = (k * learned).ceil() as u64;
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
        assert_eq!(b.threshold(0, 5.0, 300), 300);
    }

    #[test]
    fn warm_slot_scales_with_k() {
        let mut b = Baseline::default();
        for _ in 0..MIN_OBS {
            b.observe(10, 100);
        }
        assert!(b.ready(10));
        // ~5 * 100 = 500 > min 300
        assert!(b.threshold(10, 5.0, 300) >= 480);
    }

    #[test]
    fn a_cold_slot_borrows_the_all_slot_average_and_a_day_makes_it_ready() {
        let mut b = Baseline::default();
        // Two hours of traffic in other slots.
        for i in 0..GLOBAL_MIN_OBS {
            b.observe((i % 8) as usize, 200);
        }
        // A slot never seen uses the average, not the bare floor...
        assert_eq!(b.threshold(50, 5.0, 300), 1000);
        // ...but the baseline is not trusted to ban yet.
        assert!(!b.ready(50));
        for i in 0..GLOBAL_READY_OBS {
            b.observe((i % 8) as usize, 200);
        }
        assert!(b.ready(50), "a quiet slot does not stay cold for ever");
    }

    #[test]
    fn an_address_staying_just_under_the_bar_raises_it_only_step_by_step() {
        // The old baseline learned the busiest address as it was: a scraper
        // at 2999 dynamic requests per cycle for a day made the threshold
        // 5 x 2999. Each lesson is now at most twice what the bar allows one
        // address.
        let mut b = Baseline::default();
        for _ in 0..GLOBAL_MIN_OBS {
            b.learn(7, 2999, 5.0, 300);
        }
        // 300 / 5 = 60 per address, so at most 120 learned: still the floor.
        assert_eq!(b.threshold(7, 5.0, 300), 600);
        let mut b = Baseline::default();
        let mut last = b.threshold(7, 5.0, 300);
        for _ in 0..50 {
            b.learn(7, 1_000_000, 5.0, 300);
            let t = b.threshold(7, 5.0, 300);
            // At most +15% per cycle (ALPHA x doubling).
            assert!(t as f64 <= (last as f64 * 1.16).max(600.0), "{last} -> {t}");
            last = t;
        }
        // Ordinary traffic below the cap is learned as it is.
        let mut b = Baseline::default();
        for _ in 0..MIN_OBS {
            b.learn(10, 50, 5.0, 300);
        }
        assert_eq!(b.threshold(10, 5.0, 300), 300);
        assert!((b.rate[10] - 50.0).abs() < 1e-9);
    }

    #[test]
    fn a_baseline_from_an_agent_that_counted_every_line_starts_again() {
        let old = r#"{"rate":[500.0],"n":[30]}"#;
        let b: Baseline = serde_json::from_str::<Baseline>(old).unwrap().checked();
        assert!(!b.ready(0));
        assert_eq!(b.threshold(0, 5.0, 300), 300);
        // One of ours survives a save.
        let mut b = Baseline::default();
        b.observe(3, 40);
        let back: Baseline = serde_json::from_str::<Baseline>(&serde_json::to_string(&b).unwrap())
            .unwrap()
            .checked();
        assert_eq!(back.n[3], 1);
    }

    #[test]
    fn slot_math() {
        assert_eq!(slot_of(0), 0);
        assert_eq!(slot_of(900), 1);
        assert_eq!(slot_of(86_400 - 1), 95);
    }
}
