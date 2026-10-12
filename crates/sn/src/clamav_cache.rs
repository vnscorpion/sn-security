//! Incremental ClamAV scanning, pure part: which files a hunt hands to ClamAV this
//! time, in what order, and how ClamAV's per-file output updates the record of
//! what has been scanned. No process and no disk here; `clamav_run` does that.
//!
//! A big host has more PHP files than one ClamAV run can get through in the hunt's
//! time budget (`clamscan` is single-threaded). Without a record every run started
//! from the top again and never reached the end. Now:
//! * files ClamAV flagged before come first (to confirm or clear them),
//! * then files waiting for a first or new scan (new or changed), longest waiting
//!   first, interleaved with unchanged files due for a periodic rescan (new
//!   signatures arrive daily) so neither can starve the other,
//! * unchanged files scanned recently are skipped,
//! * a file that ClamAV failed on, or that it died on, is retried but moved to the
//!   back after a few attempts so it cannot block the rest.
//!
//! Only a clear answer ("OK", "Empty file", "<signature> FOUND") is recorded. An
//! error leaves the file waiting and keeps any earlier detection. A detection on a
//! file that was not rescanned this time is carried forward while the file is
//! unchanged (same device, inode, size and times to the nanosecond).

use std::collections::{HashMap, HashSet};

use crate::clamav::{Detection, UNRECOGNIZED_SIG, sanitize_sig};

/// A file the hunt selected, with what identifies its content cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub stamp: Stamp,
}

/// What is recorded per file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub stamp: Stamp,
    /// When ClamAV last gave a clear answer for this content; 0 = never.
    pub scanned_at: i64,
    /// Since when the file has been waiting for a (new) scan; 0 = not waiting.
    pub waiting_since: i64,
    /// Failed or crashed attempts since the last clear answer.
    pub attempts: u32,
    /// The signature ClamAV reported, or empty when clean.
    pub sig: String,
}

pub type Cache = HashMap<String, Entry>;

/// Entries kept at most.
pub const MAX_ENTRIES: usize = 250_000;
/// After this many failed attempts a file waits behind everything else.
pub const MAX_ATTEMPTS: u32 = 2;
/// Out of every this many places in the list, one goes to a periodic rescan.
const DUE_SHARE: usize = 5;
const HEADER: &str = "# sn clamav-scanned v2";

/// Read the record. Malformed lines are skipped; an unknown format gives an empty
/// record (everything is simply scanned again).
#[must_use]
pub fn parse(text: &str) -> Cache {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Cache::new();
    }
    let mut out = Cache::new();
    for line in lines {
        // The path comes last, so it may itself contain tabs.
        let f: Vec<&str> = line.splitn(13, '\t').collect();
        if f.len() != 13 || out.len() >= MAX_ENTRIES {
            continue;
        }
        let n = |i: usize| f[i].parse::<i64>().ok();
        let u = |i: usize| f[i].parse::<u64>().ok();
        let (
            Some(scanned_at),
            Some(waiting_since),
            Some(attempts),
            Some(dev),
            Some(ino),
            Some(size),
            Some(mtime),
            Some(mtime_nsec),
            Some(ctime),
            Some(ctime_nsec),
        ) = (
            n(0),
            n(1),
            f[2].parse::<u32>().ok(),
            u(3),
            u(4),
            u(5),
            n(6),
            n(7),
            n(8),
            n(9),
        )
        else {
            continue;
        };
        let (sig, path) = (f[10], f[12]);
        // f[11] is reserved (empty) for later use.
        if path.is_empty() {
            continue;
        }
        let sig = if sig.is_empty() {
            String::new()
        } else {
            sanitize_sig(sig).unwrap_or_else(|| UNRECOGNIZED_SIG.to_string())
        };
        out.insert(
            path.to_string(),
            Entry {
                stamp: Stamp {
                    dev,
                    ino,
                    size,
                    mtime,
                    mtime_nsec,
                    ctime,
                    ctime_nsec,
                },
                scanned_at,
                waiting_since,
                attempts,
                sig,
            },
        );
    }
    out
}

/// Write the record (sorted, so the file is stable between runs).
#[must_use]
pub fn render(cache: &Cache) -> String {
    let mut paths: Vec<&String> = cache.keys().collect();
    paths.sort();
    let mut out = String::with_capacity(cache.len() * 128 + HEADER.len() + 1);
    out.push_str(HEADER);
    out.push('\n');
    for p in paths {
        // A name with a line break never reaches ClamAV's list; never write one.
        if p.contains(['\n', '\r']) {
            continue;
        }
        let e = &cache[p];
        let s = &e.stamp;
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t\t{p}\n",
            e.scanned_at,
            e.waiting_since,
            e.attempts,
            s.dev,
            s.ino,
            s.size,
            s.mtime,
            s.mtime_nsec,
            s.ctime,
            s.ctime_nsec,
            e.sig
        ));
    }
    out
}

/// What to hand to ClamAV this time.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Indices into the hunt's file list, in the order to scan them.
    pub order: Vec<usize>,
    /// Unchanged files scanned within the rescan window: skipped this time.
    pub up_to_date: usize,
    /// Files moved to the back after failing `MAX_ATTEMPTS` times.
    pub stuck: Vec<usize>,
}

/// Choose and order the files for this run. `files` must not repeat a path.
#[must_use]
pub fn plan(files: &[FileInfo], cache: &Cache, now: i64, rescan_secs: i64) -> Plan {
    let mut flagged = Vec::new();
    let mut waiting: Vec<(i64, usize)> = Vec::new();
    let mut due: Vec<(i64, usize)> = Vec::new();
    let mut stuck = Vec::new();
    let mut up_to_date = 0;
    for (i, f) in files.iter().enumerate() {
        let Some(e) = cache.get(&f.path) else {
            // Never seen: waiting from now (behind files that waited longer).
            waiting.push((now, i));
            continue;
        };
        if e.stamp != f.stamp {
            // New content: earlier failures do not count against it.
            if e.sig.is_empty() {
                let since = if e.waiting_since > 0 {
                    e.waiting_since
                } else {
                    now
                };
                waiting.push((since, i));
            } else {
                flagged.push(i);
            }
        } else if e.attempts >= MAX_ATTEMPTS {
            stuck.push(i);
        } else if !e.sig.is_empty() {
            flagged.push(i);
        } else if e.scanned_at == 0 {
            let since = if e.waiting_since > 0 {
                e.waiting_since
            } else {
                now
            };
            waiting.push((since, i));
        } else if e.scanned_at > now || now - e.scanned_at >= rescan_secs {
            // A time in the future (the clock was wrong when it was taken) is due.
            due.push((e.scanned_at, i));
        } else {
            up_to_date += 1;
        }
    }
    waiting.sort_unstable();
    due.sort_unstable();
    let mut order = flagged;
    // Interleave: one due rescan in every DUE_SHARE places while both remain.
    let (mut w, mut d) = (waiting.into_iter().peekable(), due.into_iter().peekable());
    let mut slot = 0usize;
    while w.peek().is_some() || d.peek().is_some() {
        slot += 1;
        let take_due = slot.is_multiple_of(DUE_SHARE) || w.peek().is_none();
        let next = if take_due {
            d.next().or_else(|| w.next())
        } else {
            w.next()
        };
        if let Some((_, i)) = next {
            order.push(i);
        }
    }
    order.extend(stuck.iter().copied());
    Plan {
        order,
        up_to_date,
        stuck,
    }
}

/// ClamAV's answer for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Clean,
    Found(String),
    /// Anything that is not a clear answer (an error, no reply from clamd, a
    /// file that turned into a link or vanished): the file stays waiting.
    Failed,
}

/// One result line read back.
pub type Done = (String, Outcome);

/// The files a run was asked about, indexed for fast matching of output lines.
pub struct Asked<'a> {
    paths: HashSet<&'a str>,
    lengths: HashSet<usize>,
}

impl<'a> Asked<'a> {
    #[must_use]
    pub fn new(paths: impl IntoIterator<Item = &'a str>) -> Self {
        let paths: HashSet<&'a str> = paths.into_iter().collect();
        let lengths = paths.iter().map(|p| p.len()).collect();
        Asked { paths, lengths }
    }

    fn contains(&self, p: &str) -> bool {
        self.lengths.contains(&p.len()) && self.paths.contains(p)
    }
}

fn outcome(status: &str) -> Option<Outcome> {
    if status == "OK" || status == "Empty file" {
        return Some(Outcome::Clean);
    }
    if let Some(sig) = status.strip_suffix(" FOUND") {
        // A real signature name has no spaces; anything else is not this shape.
        return (!sig.is_empty() && !sig.contains([' ', ':']))
            .then(|| Outcome::Found(sanitize_sig(sig).unwrap_or_else(|| UNRECOGNIZED_SIG.into())));
    }
    None
}

/// Read one line of ClamAV's output (`path: OK`, `path: Sig.Name FOUND`, `path:
/// Empty file`, `path: <reason> ERROR`, `path: no reply from clamd`, ...).
///
/// Only files in `asked` count. A name can contain `": "`, and so can an error
/// message: every split point whose prefix is an asked file is tried, longest
/// first, and the first one followed by a clear answer wins; if none is, the
/// longest asked prefix gets `Failed`.
#[must_use]
pub fn parse_line(line: &str, asked: &Asked<'_>) -> Option<Done> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut cuts: Vec<usize> = Vec::new();
    let mut from = 0;
    while let Some(pos) = line[from..].find(": ") {
        let at = from + pos;
        if asked.contains(&line[..at]) {
            cuts.push(at);
        }
        from = at + 2;
    }
    for &at in cuts.iter().rev() {
        if let Some(o) = outcome(&line[at + 2..]) {
            return Some((line[..at].to_string(), o));
        }
    }
    cuts.last()
        .map(|&at| (line[..at].to_string(), Outcome::Failed))
}

/// One answer per file: a detection wins over a clean result, and both over a
/// failure (a duplicate path, or a directory that appeared where a file was).
#[must_use]
pub fn merge_results(done: Vec<Done>) -> Vec<Done> {
    let mut best: HashMap<String, Outcome> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for (p, o) in done {
        let rank = |o: &Outcome| match o {
            Outcome::Found(_) => 2,
            Outcome::Clean => 1,
            Outcome::Failed => 0,
        };
        match best.get(&p) {
            Some(prev) if rank(prev) >= rank(&o) => {}
            Some(_) => {
                best.insert(p, o);
            }
            None => {
                order.push(p.clone());
                best.insert(p, o);
            }
        }
    }
    order
        .into_iter()
        .map(|p| {
            let o = best.remove(&p).unwrap_or(Outcome::Failed);
            (p, o)
        })
        .collect()
}

/// Record this run. `done` must already be merged and limited to files whose
/// stamp was confirmed unchanged after the scan (`clamav_run` checks that);
/// `waiting` are the files planned but not answered; `crashed_on` is the file
/// ClamAV was on when it died, if it did.
pub fn update(
    cache: &mut Cache,
    files: &[FileInfo],
    done: &[Done],
    waiting: &[usize],
    crashed_on: Option<usize>,
    now: i64,
) {
    let by_path: HashMap<&str, &FileInfo> = files.iter().map(|f| (f.path.as_str(), f)).collect();
    let wait = |f: &FileInfo, failed: bool, cache: &mut Cache| {
        let e = cache.entry(f.path.clone()).or_insert(Entry {
            stamp: f.stamp,
            scanned_at: 0,
            waiting_since: now,
            attempts: 0,
            sig: String::new(),
        });
        if e.stamp != f.stamp {
            // New content: a fresh wait; an earlier detection stays until rescanned.
            e.stamp = f.stamp;
            e.scanned_at = 0;
            e.attempts = 0;
            e.waiting_since = now;
        } else if e.waiting_since == 0 && e.scanned_at == 0 {
            e.waiting_since = now;
        }
        if failed {
            e.attempts = e.attempts.saturating_add(1);
        }
    };
    for (path, o) in done {
        let Some(f) = by_path.get(path.as_str()) else {
            continue;
        };
        match o {
            Outcome::Clean | Outcome::Found(_) => {
                cache.insert(
                    path.clone(),
                    Entry {
                        stamp: f.stamp,
                        scanned_at: now,
                        waiting_since: 0,
                        attempts: 0,
                        sig: match o {
                            Outcome::Found(s) => s.clone(),
                            _ => String::new(),
                        },
                    },
                );
            }
            Outcome::Failed => wait(f, true, cache),
        }
    }
    for &i in waiting {
        if let Some(f) = files.get(i) {
            wait(f, crashed_on == Some(i), cache);
        }
    }
    if cache.len() > MAX_ENTRIES {
        // Keep the most recently scanned (cannot happen with capped hunts).
        let mut v: Vec<(String, Entry)> = cache.drain().collect();
        v.sort_by_key(|(_, e)| std::cmp::Reverse(e.scanned_at.max(e.waiting_since)));
        v.truncate(MAX_ENTRIES);
        cache.extend(v);
    }
}

/// Forget entries for files that are gone. Only entries under `roots` (what this
/// hunt walked) for which `exists` says no are dropped: a hunt over part of the
/// tree, or one that did not get to everything, never erases the rest.
pub fn prune(cache: &mut Cache, roots: &[String], exists: impl Fn(&str) -> bool) {
    let under = |p: &str| {
        roots.iter().any(|r| {
            let r = r.trim_end_matches('/');
            p.len() > r.len() && p.starts_with(r) && p.as_bytes()[r.len()] == b'/'
        })
    };
    cache.retain(|p, _| !under(p) || exists(p));
}

/// Detections to report: this run's, plus earlier ones on files this run did not
/// answer for and that have not changed since.
#[must_use]
pub fn detections(files: &[FileInfo], cache_before: &Cache, done: &[Done]) -> Vec<Detection> {
    let answered: HashSet<&str> = done
        .iter()
        .filter(|(_, o)| *o != Outcome::Failed)
        .map(|(p, _)| p.as_str())
        .collect();
    let mut out: Vec<Detection> = done
        .iter()
        .filter_map(|(p, o)| match o {
            Outcome::Found(sig) => Some(Detection {
                path: p.clone(),
                sig: sig.clone(),
            }),
            _ => None,
        })
        .collect();
    for f in files {
        if answered.contains(f.path.as_str()) {
            continue;
        }
        if let Some(e) = cache_before.get(&f.path)
            && !e.sig.is_empty()
            && e.stamp == f.stamp
        {
            out.push(Detection {
                path: f.path.clone(),
                sig: e.sig.clone(),
            });
        }
    }
    out.truncate(crate::clamav::MAX_DETECTIONS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(size: u64, t: i64) -> Stamp {
        Stamp {
            dev: 1,
            ino: size * 1000 + t as u64,
            size,
            mtime: t,
            mtime_nsec: 0,
            ctime: t,
            ctime_nsec: 0,
        }
    }

    fn f(path: &str, size: u64, t: i64) -> FileInfo {
        FileInfo {
            path: path.into(),
            stamp: st(size, t),
        }
    }

    fn scanned(file: &FileInfo, at: i64, sig: &str) -> Entry {
        Entry {
            stamp: file.stamp,
            scanned_at: at,
            waiting_since: 0,
            attempts: 0,
            sig: sig.into(),
        }
    }

    fn names<'a>(files: &'a [FileInfo], idx: &[usize]) -> Vec<&'a str> {
        idx.iter().map(|&i| files[i].path.as_str()).collect()
    }

    #[test]
    fn the_record_round_trips_and_tolerates_junk() {
        let mut c = Cache::new();
        let a = f("/var/www/a.php", 10, 100);
        let b = f("/var/www/tab\there.php", 20, 200);
        c.insert(a.path.clone(), scanned(&a, 1000, ""));
        let mut eb = scanned(&b, 2000, "Php.Webshell.Generic-1");
        eb.attempts = 1;
        eb.waiting_since = 5;
        c.insert(b.path.clone(), eb);
        let text = render(&c);
        assert_eq!(parse(&text), c);
        let mut text2 = text.clone();
        text2.push_str("garbage\n1\t2\t3\n");
        text2.push_str("5\t0\t0\t1\t2\t3\t4\t0\t4\t0\t<script>\t\t/x.php\n");
        let back = parse(&text2);
        assert_eq!(back["/x.php"].sig, UNRECOGNIZED_SIG);
        assert_eq!(back.len(), 3);
        // The first format (or anything else): start over rather than misread.
        assert!(parse("# sn clamav-scanned v1\n1\t2\t3\t4\t\t/a\n").is_empty());
    }

    #[test]
    fn flagged_first_then_waiting_longest_first_with_due_rescans_mixed_in() {
        let now = 100 * 86_400;
        let week = 7 * 86_400;
        let mut files = Vec::new();
        let mut c = Cache::new();
        // Eight never-scanned files, one waiting since long ago.
        for i in 0..8 {
            files.push(f(&format!("/new{i}.php"), 1, 1));
        }
        let mut old_wait = scanned(&files[7], 0, "");
        old_wait.waiting_since = now - 3 * 86_400;
        c.insert("/new7.php".into(), old_wait);
        // Two due for a rescan, one fresh, one flagged.
        files.push(f("/due-older.php", 1, 1));
        c.insert(
            "/due-older.php".into(),
            scanned(&files[8], now - 20 * 86_400, ""),
        );
        files.push(f("/due.php", 1, 1));
        c.insert("/due.php".into(), scanned(&files[9], now - 9 * 86_400, ""));
        files.push(f("/fresh.php", 1, 1));
        c.insert("/fresh.php".into(), scanned(&files[10], now - 86_400, ""));
        files.push(f("/flagged.php", 1, 1));
        c.insert(
            "/flagged.php".into(),
            scanned(&files[11], now - 60, "Php.X"),
        );
        let p = plan(&files, &c, now, week);
        let n = names(&files, &p.order);
        assert_eq!(n[0], "/flagged.php");
        assert_eq!(n[1], "/new7.php", "the longest wait goes first");
        // A due rescan gets every fifth place even though new files remain.
        assert_eq!(n[5], "/due-older.php");
        assert_eq!(n[10], "/due.php");
        assert_eq!(p.order.len(), 11);
        assert_eq!(p.up_to_date, 1);
    }

    #[test]
    fn a_clock_that_went_back_does_not_freeze_rescans() {
        let now = 1_000_000;
        let files = vec![f("/a.php", 1, 1)];
        let mut c = Cache::new();
        c.insert("/a.php".into(), scanned(&files[0], now + 30 * 86_400, ""));
        assert_eq!(plan(&files, &c, now, 7 * 86_400).order, vec![0]);
    }

    #[test]
    fn output_lines_give_clear_answers_failures_and_nothing_else() {
        let asked = Asked::new(["/a.php", "/b: c.php", "/d.php", "/e.php"]);
        assert_eq!(
            parse_line("/a.php: OK\n", &asked),
            Some(("/a.php".into(), Outcome::Clean))
        );
        assert_eq!(
            parse_line("/b: c.php: Php.Trojan.Shell-1 FOUND", &asked),
            Some((
                "/b: c.php".into(),
                Outcome::Found("Php.Trojan.Shell-1".into())
            ))
        );
        assert_eq!(
            parse_line("/e.php: Empty file", &asked),
            Some(("/e.php".into(), Outcome::Clean))
        );
        // Errors and anything unclear are failures, never "clean".
        for bad in [
            "/d.php: lstat() failed: No such file or directory. ERROR",
            "/d.php: no reply from clamd",
            "/d.php: Access denied",
            "/d.php: Symbolic link",
            "/d.php: Excluded",
            "/d.php: Sig With Space FOUND",
        ] {
            assert_eq!(
                parse_line(bad, &asked),
                Some(("/d.php".into(), Outcome::Failed)),
                "{bad}"
            );
        }
        // A hostile but space-free signature is kept as an unrecognised detection.
        assert_eq!(
            parse_line("/a.php: <img/src=x> FOUND", &asked),
            Some(("/a.php".into(), Outcome::Found(UNRECOGNIZED_SIG.into())))
        );
        assert_eq!(parse_line("/etc/shadow: OK", &asked), None);
        assert_eq!(parse_line("LibClamAV Warning: something", &asked), None);
        assert_eq!(parse_line("", &asked), None);
    }

    #[test]
    fn a_name_with_the_separator_resolves_to_the_file_with_a_clear_answer() {
        // Both "/x" and "/x: OK" are files; the line is about the longer one.
        let asked = Asked::new(["/x", "/x: OK"]);
        assert_eq!(
            parse_line("/x: OK: OK", &asked),
            Some(("/x: OK".into(), Outcome::Clean))
        );
        assert_eq!(
            parse_line("/x: OK: Php.Y FOUND", &asked),
            Some(("/x: OK".into(), Outcome::Found("Php.Y".into())))
        );
        let name = "/home/a/we: ird FOUND.php";
        let one = Asked::new([name]);
        assert_eq!(
            parse_line(&format!("{name}: Php.X FOUND"), &one),
            Some((name.to_string(), Outcome::Found("Php.X".into())))
        );
    }

    #[test]
    fn a_detection_wins_over_a_clean_result_for_the_same_file() {
        let merged = merge_results(vec![
            ("/a.php".into(), Outcome::Found("Php.X".into())),
            ("/b.php".into(), Outcome::Failed),
            ("/a.php".into(), Outcome::Clean),
            ("/b.php".into(), Outcome::Clean),
        ]);
        assert_eq!(
            merged,
            vec![
                ("/a.php".to_string(), Outcome::Found("Php.X".into())),
                ("/b.php".to_string(), Outcome::Clean),
            ]
        );
    }

    #[test]
    fn a_failure_keeps_the_file_waiting_and_its_old_detection() {
        let now = 1_000_000;
        let files = vec![f("/a.php", 1, 1), f("/b.php", 1, 1), f("/c.php", 1, 1)];
        let mut before = Cache::new();
        before.insert("/a.php".into(), scanned(&files[0], now - 100, "Php.Old"));
        // clamd fell over on a; b was never reached; c is clean.
        let done = vec![
            ("/a.php".to_string(), Outcome::Failed),
            ("/c.php".to_string(), Outcome::Clean),
        ];
        let det = detections(&files, &before, &done);
        assert_eq!(det.len(), 1, "the earlier detection is still reported");
        assert_eq!(det[0].sig, "Php.Old");
        let mut cache = before.clone();
        update(&mut cache, &files, &done, &[1], None, now);
        assert_eq!(cache["/a.php"].sig, "Php.Old");
        assert_eq!(cache["/a.php"].attempts, 1);
        assert_eq!(cache["/b.php"].scanned_at, 0);
        assert_eq!(cache["/b.php"].waiting_since, now);
        assert_eq!(cache["/c.php"].scanned_at, now);
        // Next time a (flagged) goes first, then b; c is up to date.
        let p = plan(&files, &cache, now + 10, 7 * 86_400);
        assert_eq!(names(&files, &p.order), ["/a.php", "/b.php"]);
    }

    #[test]
    fn a_file_clamav_keeps_dying_on_goes_to_the_back() {
        let now = 1_000_000;
        let files = vec![f("/poison.php", 1, 1), f("/next.php", 1, 1)];
        let mut cache = Cache::new();
        for round in 0..MAX_ATTEMPTS {
            // ClamAV died on the first file both times.
            update(
                &mut cache,
                &files,
                &[],
                &[0, 1],
                Some(0),
                now + i64::from(round),
            );
        }
        assert_eq!(cache["/poison.php"].attempts, MAX_ATTEMPTS);
        let p = plan(&files, &cache, now + 10, 7 * 86_400);
        assert_eq!(names(&files, &p.order), ["/next.php", "/poison.php"]);
        assert_eq!(p.stuck, vec![0]);
        // A clear answer later clears it.
        update(
            &mut cache,
            &files,
            &[("/poison.php".into(), Outcome::Clean)],
            &[],
            None,
            now + 20,
        );
        assert_eq!(cache["/poison.php"].attempts, 0);
    }

    #[test]
    fn changed_content_waits_again_and_new_content_does_not_inherit_a_verdict() {
        let now = 1_000_000;
        let old = f("/a.php", 1, 1);
        let mut cache = Cache::new();
        cache.insert("/a.php".into(), scanned(&old, now - 10, ""));
        // Same size and second, different inode: not the same file.
        let mut swapped = old.clone();
        swapped.stamp.ino += 1;
        let p = plan(std::slice::from_ref(&swapped), &cache, now, 7 * 86_400);
        assert_eq!(p.order, vec![0]);
        // And its earlier detection is not carried to the new content.
        cache.get_mut("/a.php").unwrap().sig = "Php.X".into();
        assert!(detections(std::slice::from_ref(&swapped), &cache, &[]).is_empty());
        // Nanoseconds count too.
        let mut touched = old.clone();
        touched.stamp.ctime_nsec = 5;
        assert!(detections(std::slice::from_ref(&touched), &cache, &[]).is_empty());
        assert_eq!(detections(std::slice::from_ref(&old), &cache, &[]).len(), 1);
    }

    #[test]
    fn pruning_only_forgets_vanished_files_under_the_walked_roots() {
        let mut cache = Cache::new();
        for p in [
            "/var/www/a.php",
            "/var/www/gone.php",
            "/home/u/x.php",
            "/var/wwwold/y.php",
        ] {
            cache.insert(p.into(), scanned(&f(p, 1, 1), 1, ""));
        }
        prune(&mut cache, &["/var/www".into()], |p| {
            p != "/var/www/gone.php" && p != "/home/u/x.php"
        });
        let mut left: Vec<&String> = cache.keys().collect();
        left.sort();
        // /home/u was not walked; /var/wwwold is not under /var/www.
        assert_eq!(
            left,
            ["/home/u/x.php", "/var/www/a.php", "/var/wwwold/y.php"]
        );
    }

    #[test]
    fn the_number_of_detections_is_capped() {
        let files: Vec<FileInfo> = (0..crate::clamav::MAX_DETECTIONS + 50)
            .map(|i| f(&format!("/f/{i}.php"), 1, 1))
            .collect();
        let done: Vec<Done> = files
            .iter()
            .map(|x| (x.path.clone(), Outcome::Found("Php.X".into())))
            .collect();
        assert_eq!(
            detections(&files, &Cache::new(), &done).len(),
            crate::clamav::MAX_DETECTIONS
        );
        assert_eq!(
            crate::clamav::verdict_for(UNRECOGNIZED_SIG),
            ("suspicious", 70)
        );
        assert!(sanitize_sig(&"A".repeat(200)).is_none());
    }
}
