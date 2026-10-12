//! CPU alert with attribution: how busy the server was *since the last cycle*,
//! and which user and program account for it.
//!
//! The agent runs once per timer tick and exits, so "how busy" cannot be a
//! momentary sample (a 100 ms look says nothing about a 5-minute attack). Each
//! cycle stores the CPU counters, and the next one reports the difference, which
//! is the average over the whole interval. Processes are grouped by
//! `(user, program)` so one site's PHP workers show up as one line, not forty.
//!
//! Percentages are of the *whole server* (all cores), the same scale as
//! `cpu_busy_pct`, so the groups add up to at most the total. Processes that
//! started and ended between two cycles are not seen; the total still counts them.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use snsec_common::schema::CpuGroup;

/// Processes remembered between cycles; beyond it the oldest-seen are dropped.
const MAX_PROCS: usize = 20_000;
/// Groups reported.
const TOP_GROUPS: usize = 6;
/// A group below this share of the server is not worth a line.
const MIN_GROUP_PCT: f64 = 1.0;
/// Consecutive busy cycles before the alert (one is a normal burst).
pub const CPU_STREAK_ALERT: u32 = 2;
/// A sample older than this is not a fair baseline (the agent was off).
const MAX_SAMPLE_AGE_SECS: i64 = 30 * 60;

/// CPU counters at one moment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sample {
    pub at: i64,
    pub total: u64,
    pub idle: u64,
    /// `pid:starttime` -> utime+stime in clock ticks.
    pub procs: HashMap<String, u64>,
}

/// One process, as read from `/proc`.
#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: i32,
    pub start: u64,
    pub comm: String,
    pub jiffies: u64,
}

impl Proc {
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.pid, self.start)
    }
}

/// The sample to keep for next time. Bounded.
#[must_use]
pub fn make_sample(at: i64, total: u64, idle: u64, procs: &[Proc]) -> Sample {
    Sample {
        at,
        total,
        idle,
        procs: procs
            .iter()
            .take(MAX_PROCS)
            .map(|p| (p.key(), p.jiffies))
            .collect(),
    }
}

/// Longer than this since the previous cycle means the agent was off or stalled
/// (the timer is 5 minutes). The log read that follows covers far more than one
/// cycle's traffic, so per-cycle volume comparisons are not fair that time.
const MAX_CYCLE_GAP_SECS: i64 = 15 * 60;
/// Below this overall load nobody needs a per-program breakdown.
pub const GROUPS_MIN_BUSY: f64 = 50.0;

/// Did a long time pass since `prev` was taken? `false` on the first run.
#[must_use]
pub fn is_gap(prev: &Sample, now: i64) -> bool {
    prev.at > 0 && now - prev.at > MAX_CYCLE_GAP_SECS
}

/// Busy percentage between `prev` and now, or `None` when the two are not
/// comparable (first run, counters went backwards after a reboot, too old).
#[must_use]
pub fn busy_pct(prev: &Sample, now_at: i64, total: u64, idle: u64) -> Option<f64> {
    if prev.total == 0 || total <= prev.total || idle < prev.idle {
        return None;
    }
    if now_at - prev.at > MAX_SAMPLE_AGE_SECS || now_at < prev.at {
        return None;
    }
    let dt = (total - prev.total) as f64;
    let di = (idle - prev.idle) as f64;
    Some((100.0 * (1.0 - di / dt)).clamp(0.0, 100.0))
}

/// CPU ticks each process used since `prev`, only those that used any.
/// A process not in `prev` (started since) counts from zero.
#[must_use]
pub fn deltas<'a>(prev: &Sample, now: &'a [Proc]) -> Vec<(&'a Proc, u64)> {
    now.iter()
        .filter_map(|p| {
            let before = prev.procs.get(&p.key()).copied().unwrap_or(0);
            let d = p.jiffies.saturating_sub(before);
            (d > 0).then_some((p, d))
        })
        .collect()
}

/// Group per-process deltas by `(user, program)`; `total_delta` is the growth of
/// the all-CPU counter over the same interval.
#[must_use]
pub fn group(rows: &[(String, String, u64)], total_delta: u64) -> Vec<CpuGroup> {
    if total_delta == 0 {
        return Vec::new();
    }
    let mut acc: HashMap<(&str, &str), (u64, u32)> = HashMap::new();
    for (user, comm, d) in rows {
        let e = acc.entry((user.as_str(), comm.as_str())).or_insert((0, 0));
        e.0 += d;
        e.1 += 1;
    }
    let mut out: Vec<CpuGroup> = acc
        .into_iter()
        .map(|((user, comm), (d, n))| CpuGroup {
            user: user.to_string(),
            comm: comm.to_string(),
            cpu_pct: ((100.0 * d as f64 / total_delta as f64) * 10.0).round() / 10.0,
            procs: n,
        })
        .filter(|g| g.cpu_pct >= MIN_GROUP_PCT)
        .collect();
    out.sort_by(|a, b| {
        b.cpu_pct
            .total_cmp(&a.cpu_pct)
            .then_with(|| a.user.cmp(&b.user))
            .then_with(|| a.comm.cmp(&b.comm))
    });
    out.truncate(TOP_GROUPS);
    out
}

/// Consecutive-busy counter: grows while the server stays at or above
/// `threshold`, resets as soon as it does not. No measurement (first run, a gap,
/// an unreadable `/proc`) resets it too: "busy for N cycles in a row" cannot be
/// claimed across a hole.
#[must_use]
pub fn next_streak(prev: u32, busy: Option<f64>, threshold: f64) -> u32 {
    match busy {
        Some(b) if b >= threshold => prev.saturating_add(1),
        _ => 0,
    }
}

/// Alert text naming the busiest groups.
#[must_use]
pub fn describe(busy: f64, streak: u32, groups: &[CpuGroup]) -> String {
    let mut s = format!("CPU averaged {busy:.0}% over the last interval, {streak} cycles in a row");
    if groups.is_empty() {
        s.push_str("; no single program stands out");
    } else {
        s.push_str("; busiest: ");
        let parts: Vec<String> = groups
            .iter()
            .take(3)
            .map(|g| {
                format!(
                    "{} (user {}, {} proc) {:.0}%",
                    g.comm, g.user, g.procs, g.cpu_pct
                )
            })
            .collect();
        s.push_str(&parts.join(", "));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: i32, comm: &str, jiffies: u64) -> Proc {
        Proc {
            pid,
            start: 1000,
            comm: comm.into(),
            jiffies,
        }
    }

    #[test]
    fn busy_is_the_interval_average() {
        let prev = Sample {
            at: 1000,
            total: 10_000,
            idle: 9_000,
            procs: HashMap::new(),
        };
        // 4000 more ticks, 400 of them idle: 90% busy.
        let b = busy_pct(&prev, 1300, 14_000, 9_400).unwrap();
        assert!((b - 90.0).abs() < 0.01);
    }

    #[test]
    fn no_comparison_after_reboot_or_a_long_gap_or_first_run() {
        let prev = Sample {
            at: 1000,
            total: 10_000,
            idle: 9_000,
            procs: HashMap::new(),
        };
        assert!(busy_pct(&Sample::default(), 1300, 5_000, 1_000).is_none());
        assert!(busy_pct(&prev, 1300, 500, 100).is_none()); // counters reset
        assert!(busy_pct(&prev, 1000 + MAX_SAMPLE_AGE_SECS + 1, 14_000, 9_400).is_none());
        assert!(busy_pct(&prev, 900, 14_000, 9_400).is_none()); // clock went back
        assert!(busy_pct(&prev, 1300, 10_000, 9_000).is_none()); // no time passed
    }

    #[test]
    fn a_long_silence_is_a_gap_but_the_first_run_is_not() {
        let at = |t| Sample {
            at: t,
            ..Sample::default()
        };
        assert!(!is_gap(&Sample::default(), 5_000));
        assert!(!is_gap(&at(1000), 1000 + 300));
        assert!(is_gap(&at(1000), 1000 + MAX_CYCLE_GAP_SECS + 1));
    }

    #[test]
    fn only_processes_that_used_cpu_are_counted_and_new_ones_start_from_zero() {
        let before = [p(1, "lsphp", 100), p(2, "sleep", 5), p(3, "gone", 9)];
        let prev = make_sample(1000, 10_000, 9_000, &before);
        let now = [
            p(1, "lsphp", 1100),
            p(2, "sleep", 5),
            p(4, "new", 40), // appeared since
        ];
        let d = deltas(&prev, &now);
        let got: Vec<(i32, u64)> = d.iter().map(|(p, d)| (p.pid, *d)).collect();
        assert_eq!(got, [(1, 1000), (4, 40)]);
    }

    #[test]
    fn a_reused_pid_is_a_different_process() {
        let prev = make_sample(1000, 10, 5, &[p(7, "old", 5000)]);
        let reused = Proc {
            pid: 7,
            start: 2000,
            comm: "new".into(),
            jiffies: 30,
        };
        let d = deltas(&prev, std::slice::from_ref(&reused));
        assert_eq!(d[0].1, 30, "must not subtract the old process's time");
    }

    #[test]
    fn workers_of_one_user_become_one_line_sorted_by_cpu() {
        let rows = vec![
            ("tapsenior".to_string(), "lsphp".to_string(), 1000),
            ("tapsenior".to_string(), "lsphp".to_string(), 1500),
            ("mysql".to_string(), "mysqld".to_string(), 400),
            ("root".to_string(), "sn".to_string(), 10), // below 1%
        ];
        let g = group(&rows, 4000);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].user, "tapsenior");
        assert_eq!(g[0].procs, 2);
        assert!((g[0].cpu_pct - 62.5).abs() < 0.01);
        assert_eq!(g[1].comm, "mysqld");
        assert!((g[1].cpu_pct - 10.0).abs() < 0.01);
    }

    #[test]
    fn grouping_is_bounded_and_safe_on_zero() {
        assert!(group(&[("a".into(), "b".into(), 5)], 0).is_empty());
        let rows: Vec<(String, String, u64)> = (0..50)
            .map(|i| (format!("u{i}"), "php".to_string(), 100))
            .collect();
        assert_eq!(group(&rows, 1000).len(), TOP_GROUPS);
    }

    #[test]
    fn streak_counts_busy_cycles_and_resets_when_calm() {
        let mut s = 0;
        s = next_streak(s, Some(95.0), 85.0);
        assert_eq!(s, 1);
        s = next_streak(s, Some(90.0), 85.0);
        assert_eq!(s, 2);
        assert!(s >= CPU_STREAK_ALERT);
        // A hole in the measurements breaks the run.
        assert_eq!(next_streak(s, None, 85.0), 0);
        s = next_streak(s, Some(40.0), 85.0);
        assert_eq!(s, 0);
    }

    #[test]
    fn the_alert_names_the_busiest_programs() {
        let g = vec![
            CpuGroup {
                user: "tapsenior".into(),
                comm: "lsphp".into(),
                cpu_pct: 61.4,
                procs: 12,
            },
            CpuGroup {
                user: "mysql".into(),
                comm: "mysqld".into(),
                cpu_pct: 12.0,
                procs: 1,
            },
        ];
        let text = describe(92.0, 3, &g);
        assert!(text.contains("92%") && text.contains("3 cycles"));
        assert!(text.contains("lsphp (user tapsenior, 12 proc) 61%"));
        assert!(text.contains("mysqld"));
        assert!(describe(90.0, 2, &[]).contains("no single program"));
    }

    #[test]
    fn the_stored_sample_is_bounded() {
        let many: Vec<Proc> = (0..(MAX_PROCS as i32 + 500))
            .map(|i| p(i, "x", 1))
            .collect();
        assert_eq!(make_sample(0, 1, 1, &many).procs.len(), MAX_PROCS);
    }
}
