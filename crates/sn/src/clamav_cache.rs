//! Incremental ClamAV scanning, pure part: which files a hunt hands to ClamAV this
//! time, in what order, and how ClamAV's per-file output updates the record of
//! what has been scanned. No process and no disk here; `clamav_run` does that.
//!
//! A big host has more PHP files than one ClamAV run can get through in the hunt's
//! time budget (`clamscan` is single-threaded). Without a record every run started
//! from the top again and never reached the end. Now:
//! * files ClamAV flagged before come first (to confirm or clear them),
//! * then files that are new or changed since they were last scanned,
//! * then unchanged files due for a periodic rescan (new signatures arrive daily),
//!   oldest scan first;
//! * unchanged files scanned recently are skipped.
//!
//! Progress is read from ClamAV's output file by file, so a run that is stopped at
//! its time limit still keeps what it finished, and the next run carries on. A
//! detection on a file that was not rescanned this time is carried forward as
//! long as the file has not changed.

use std::collections::{HashMap, HashSet};

use crate::clamav::{Detection, UNRECOGNIZED_SIG, sanitize_sig};

/// A file the hunt selected, with what identifies its content cheaply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
}

/// What was recorded the last time ClamAV finished a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub scanned_at: i64,
    /// The signature ClamAV reported, or empty when clean.
    pub sig: String,
}

pub type Cache = HashMap<String, Entry>;

impl Entry {
    fn matches(&self, f: &FileInfo) -> bool {
        self.size == f.size && self.mtime == f.mtime && self.ctime == f.ctime
    }
}

/// Entries kept at most (one per file a hunt selects; hunts are capped below this).
pub const MAX_ENTRIES: usize = 250_000;
const HEADER: &str = "# sn clamav-scanned v1";

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
        let mut it = line.splitn(6, '\t');
        let (Some(at), Some(size), Some(mtime), Some(ctime), Some(sig), Some(path)) = (
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
        ) else {
            continue;
        };
        let (Ok(scanned_at), Ok(size), Ok(mtime), Ok(ctime)) =
            (at.parse(), size.parse(), mtime.parse(), ctime.parse())
        else {
            continue;
        };
        if path.is_empty() || out.len() >= MAX_ENTRIES {
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
                size,
                mtime,
                ctime,
                scanned_at,
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
    let mut out = String::with_capacity(cache.len() * 96 + HEADER.len() + 1);
    out.push_str(HEADER);
    out.push('\n');
    for p in paths {
        // A name with a line break never reaches ClamAV's list; never write one.
        if p.contains(['\n', '\r']) {
            continue;
        }
        let e = &cache[p];
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{p}\n",
            e.scanned_at, e.size, e.mtime, e.ctime, e.sig
        ));
    }
    out
}

/// What to hand to ClamAV this time.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Indices into the hunt's file list, in the order to scan them.
    pub order: Vec<usize>,
    /// Of those, how many are new or changed (or flagged before).
    pub urgent: usize,
    /// Unchanged files scanned within the rescan window: skipped this time.
    pub up_to_date: usize,
}

/// Choose and order the files for this run.
#[must_use]
pub fn plan(files: &[FileInfo], cache: &Cache, now: i64, rescan_secs: i64) -> Plan {
    let mut flagged = Vec::new();
    let mut changed = Vec::new();
    let mut due: Vec<(i64, usize)> = Vec::new();
    let mut up_to_date = 0;
    for (i, f) in files.iter().enumerate() {
        match cache.get(&f.path) {
            Some(e) if !e.sig.is_empty() => flagged.push(i),
            Some(e) if e.matches(f) => {
                if now - e.scanned_at >= rescan_secs {
                    due.push((e.scanned_at, i));
                } else {
                    up_to_date += 1;
                }
            }
            _ => changed.push(i),
        }
    }
    due.sort_unstable();
    let urgent = flagged.len() + changed.len();
    let mut order = flagged;
    order.extend(changed);
    order.extend(due.into_iter().map(|(_, i)| i));
    Plan {
        order,
        urgent,
        up_to_date,
    }
}

/// One file ClamAV finished: `Some(signature)` when it reported a detection.
pub type Done = (String, Option<String>);

/// Read ClamAV's full output (`path: OK`, `path: Sig.Name FOUND`, `path: Empty
/// file`, `path: <reason> ERROR`, ...), one line at a time, and return the files it
/// finished. Only files in `asked` count. A name can contain `": "`, and so can an
/// error message, so the path is the longest prefix ending before a `": "` that is
/// one of the files asked about.
#[must_use]
pub fn parse_line(line: &str, asked: &HashSet<&str>) -> Option<Done> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut best: Option<usize> = None;
    let mut from = 0;
    while let Some(pos) = line[from..].find(": ") {
        let at = from + pos;
        if asked.contains(&line[..at]) {
            best = Some(at);
        }
        from = at + 2;
    }
    let at = best?;
    let path = &line[..at];
    let status = &line[at + 2..];
    let sig = status
        .strip_suffix(" FOUND")
        .map(|s| sanitize_sig(s.trim()).unwrap_or_else(|| UNRECOGNIZED_SIG.to_string()));
    Some((path.to_string(), sig))
}

/// Record what this run finished. Files that are no longer selected are dropped.
pub fn update(cache: &mut Cache, files: &[FileInfo], done: &[Done], now: i64) {
    let by_path: HashMap<&str, &FileInfo> = files.iter().map(|f| (f.path.as_str(), f)).collect();
    for (path, sig) in done {
        if let Some(f) = by_path.get(path.as_str()) {
            cache.insert(
                path.clone(),
                Entry {
                    size: f.size,
                    mtime: f.mtime,
                    ctime: f.ctime,
                    scanned_at: now,
                    sig: sig.clone().unwrap_or_default(),
                },
            );
        }
    }
    cache.retain(|p, _| by_path.contains_key(p.as_str()));
    if cache.len() > MAX_ENTRIES {
        // Keep the most recently scanned (cannot happen with capped hunts).
        let mut v: Vec<(String, Entry)> = cache.drain().collect();
        v.sort_by_key(|(_, e)| std::cmp::Reverse(e.scanned_at));
        v.truncate(MAX_ENTRIES);
        cache.extend(v);
    }
}

/// Detections to report: this run's, plus earlier ones on files this run did not
/// get to and that have not changed since.
#[must_use]
pub fn detections(files: &[FileInfo], cache_before: &Cache, done: &[Done]) -> Vec<Detection> {
    let finished: HashSet<&str> = done.iter().map(|(p, _)| p.as_str()).collect();
    let mut out: Vec<Detection> = done
        .iter()
        .filter_map(|(p, s)| {
            s.as_ref().map(|sig| Detection {
                path: p.clone(),
                sig: sig.clone(),
            })
        })
        .collect();
    for f in files {
        if finished.contains(f.path.as_str()) {
            continue;
        }
        if let Some(e) = cache_before.get(&f.path)
            && !e.sig.is_empty()
            && e.matches(f)
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

    fn f(path: &str, size: u64, mtime: i64) -> FileInfo {
        FileInfo {
            path: path.into(),
            size,
            mtime,
            ctime: mtime,
        }
    }

    fn entry(file: &FileInfo, scanned_at: i64, sig: &str) -> Entry {
        Entry {
            size: file.size,
            mtime: file.mtime,
            ctime: file.ctime,
            scanned_at,
            sig: sig.into(),
        }
    }

    #[test]
    fn the_record_round_trips_and_tolerates_junk() {
        let mut c = Cache::new();
        let a = f("/var/www/a.php", 10, 100);
        let b = f("/var/www/tab\there.php", 20, 200);
        c.insert(a.path.clone(), entry(&a, 1000, ""));
        c.insert(b.path.clone(), entry(&b, 2000, "Php.Webshell.Generic-1"));
        let text = render(&c);
        assert_eq!(parse(&text), c);
        // Junk lines and a hostile signature field do not break it.
        let mut text2 = text.clone();
        text2.push_str("garbage\n1\t2\t3\n5\t6\t7\t8\t<script>\t/x.php\n");
        let back = parse(&text2);
        assert_eq!(back["/x.php"].sig, UNRECOGNIZED_SIG);
        assert_eq!(back.len(), 3);
        // Another format: start over rather than misread.
        assert!(parse("something else\n1\t2\t3\t4\t\t/a\n").is_empty());
    }

    #[test]
    fn flagged_then_changed_then_due_oldest_first_and_fresh_files_skipped() {
        let now = 10 * 86_400;
        let week = 7 * 86_400;
        let files = vec![
            f("/fresh.php", 1, 1),   // scanned yesterday, unchanged: skip
            f("/old2.php", 1, 1),    // scanned 9 days ago: due
            f("/new.php", 1, 1),     // never scanned: urgent
            f("/changed.php", 2, 5), // size/mtime differ: urgent
            f("/old1.php", 1, 1),    // scanned 10 days ago: due, before old2
            f("/flagged.php", 1, 1), // detection before: first
        ];
        let mut c = Cache::new();
        c.insert("/fresh.php".into(), entry(&files[0], now - 86_400, ""));
        c.insert("/old2.php".into(), entry(&files[1], now - 9 * 86_400, ""));
        c.insert(
            "/changed.php".into(),
            entry(&f("/changed.php", 1, 1), now - 3600, ""),
        );
        c.insert("/old1.php".into(), entry(&files[4], now - 10 * 86_400, ""));
        c.insert(
            "/flagged.php".into(),
            entry(&files[5], now - 60, "Php.Malware.X"),
        );
        let p = plan(&files, &c, now, week);
        let names: Vec<&str> = p.order.iter().map(|&i| files[i].path.as_str()).collect();
        assert_eq!(
            names,
            [
                "/flagged.php",
                "/new.php",
                "/changed.php",
                "/old1.php",
                "/old2.php"
            ]
        );
        assert_eq!((p.urgent, p.up_to_date), (3, 1));
    }

    #[test]
    fn output_lines_give_the_finished_files_and_their_signatures() {
        let asked: HashSet<&str> = ["/a.php", "/b: c.php", "/d.php", "/e.php"]
            .into_iter()
            .collect();
        assert_eq!(
            parse_line("/a.php: OK", &asked),
            Some(("/a.php".into(), None))
        );
        assert_eq!(
            parse_line("/b: c.php: Php.Trojan.Shell-1 FOUND", &asked),
            Some(("/b: c.php".into(), Some("Php.Trojan.Shell-1".into())))
        );
        // An error message with its own ": " still maps to the file.
        assert_eq!(
            parse_line(
                "/d.php: lstat() failed: No such file or directory. ERROR",
                &asked
            ),
            Some(("/d.php".into(), None))
        );
        assert_eq!(
            parse_line("/e.php: Empty file", &asked),
            Some(("/e.php".into(), None))
        );
        // A hostile signature name is kept as a detection, not as text.
        assert_eq!(
            parse_line("/a.php: <img src=x> FOUND", &asked),
            Some(("/a.php".into(), Some(UNRECOGNIZED_SIG.into())))
        );
        // Not a file we asked about, or not a result line at all.
        assert_eq!(parse_line("/etc/shadow: OK", &asked), None);
        assert_eq!(parse_line("LibClamAV Warning: something", &asked), None);
        assert_eq!(parse_line("", &asked), None);
    }

    #[test]
    fn names_with_the_separator_and_odd_signatures_are_handled() {
        // A file name can contain ": " and even " FOUND".
        let name = "/home/a/we: ird FOUND.php";
        let asked: HashSet<&str> = [name].into_iter().collect();
        assert_eq!(
            parse_line(&format!("{name}: Php.X FOUND"), &asked),
            Some((name.to_string(), Some("Php.X".into())))
        );
        assert_eq!(
            parse_line(&format!("{name}: OK"), &asked),
            Some((name.to_string(), None))
        );
        // Signature names are restricted; an unreadable one is weaker evidence.
        let one: HashSet<&str> = ["/a.php"].into_iter().collect();
        let (_, sig) = parse_line("/a.php: Sig With Space FOUND", &one).unwrap();
        assert_eq!(sig.as_deref(), Some(UNRECOGNIZED_SIG));
        assert_eq!(
            crate::clamav::verdict_for(UNRECOGNIZED_SIG),
            ("suspicious", 70)
        );
        assert!(sanitize_sig(&"A".repeat(200)).is_none());
        assert!(sanitize_sig("").is_none());
    }

    #[test]
    fn the_number_of_detections_is_capped() {
        let files: Vec<FileInfo> = (0..crate::clamav::MAX_DETECTIONS + 50)
            .map(|i| f(&format!("/f/{i}.php"), 1, 1))
            .collect();
        let done: Vec<Done> = files
            .iter()
            .map(|x| (x.path.clone(), Some("Php.X".to_string())))
            .collect();
        assert_eq!(
            detections(&files, &Cache::new(), &done).len(),
            crate::clamav::MAX_DETECTIONS
        );
    }

    #[test]
    fn a_stopped_run_keeps_what_it_finished_and_carries_old_detections() {
        let now = 1_000_000;
        let files = vec![
            f("/a.php", 1, 1),
            f("/b.php", 1, 1),
            f("/c.php", 1, 1),
            f("/d.php", 2, 2),
        ];
        let mut before = Cache::new();
        // b was flagged earlier and is unchanged; d was flagged but has changed.
        before.insert("/b.php".into(), entry(&files[1], now - 100, "Php.Old.Sig"));
        before.insert(
            "/d.php".into(),
            entry(&f("/d.php", 9, 9), now - 100, "Php.Old.D"),
        );
        before.insert(
            "/gone.php".into(),
            entry(&f("/gone.php", 1, 1), now - 100, ""),
        );
        // The run was stopped after a and c.
        let done: Vec<Done> = vec![
            ("/a.php".into(), Some("Php.New.A".into())),
            ("/c.php".into(), None),
        ];
        let det = detections(&files, &before, &done);
        let pairs: Vec<(&str, &str)> = det
            .iter()
            .map(|d| (d.path.as_str(), d.sig.as_str()))
            .collect();
        assert_eq!(pairs, [("/a.php", "Php.New.A"), ("/b.php", "Php.Old.Sig")]);

        let mut cache = before.clone();
        update(&mut cache, &files, &done, now);
        assert_eq!(cache["/a.php"].sig, "Php.New.A");
        assert_eq!(cache["/c.php"].scanned_at, now);
        assert_eq!(cache["/b.php"].sig, "Php.Old.Sig", "not rescanned: kept");
        assert!(
            !cache.contains_key("/gone.php"),
            "deleted files are forgotten"
        );
        // Next time: b and d are flagged (first), then the never-scanned ones.
        let p = plan(&files, &cache, now + 10, 7 * 86_400);
        let names: Vec<&str> = p.order.iter().map(|&i| files[i].path.as_str()).collect();
        assert_eq!(names, ["/a.php", "/b.php", "/d.php"]);
        assert_eq!(p.up_to_date, 1);
    }
}
