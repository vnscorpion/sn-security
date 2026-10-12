//! `sn hunt` — walk the allowed roots and score PHP files for web-shell
//! signatures. Runs read-only; produces findings for review and for `sn clean`.
//! The systemd unit pins it to low CPU/IO priority; here we also cap file size
//! and total bytes so a hunt never starves a busy site.

use std::io::Read;
use std::path::Path;

use anyhow::Result;
use sha2::{Digest, Sha256};
use snsec_common::heuristic::{self, Verdict};
use snsec_common::schema::{Finding, HuntSummary};
use walkdir::WalkDir;

use crate::config::{ClamavMode, Config};
use crate::state::State;
use crate::util;

const PHP_EXTS: &[&str] = &[
    "php", "phtml", "php5", "php7", "php8", "pht", "phar", "inc", "phps",
];
const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "webp", "bmp", "ico", "svg"];
/// Files handed to ClamAV in one hunt.
const MAX_CLAM_FILES: usize = 200_000;
/// What a hunt may use in total, a little under the 30 minutes the systemd unit
/// allows. ClamAV only gets what the file walk leaves.
const HUNT_BUDGET_SECS: u64 = 28 * 60;

pub struct Options {
    pub days: u32,
    pub roots: Vec<String>,
    pub deep: bool,
    pub max_file_mb: u64,
    pub print: bool,
}

pub fn run(cfg: &Config, state: &State, opts: &Options) -> Result<Vec<Finding>> {
    let roots = if opts.roots.is_empty() {
        cfg.hunt.allowed_roots.clone()
    } else {
        opts.roots.clone()
    };
    let max_bytes = opts.max_file_mb.max(1) * 1024 * 1024;
    let window = opts.days as i64 * 86_400;
    let now = util::now_secs();
    let started = std::time::Instant::now();

    let mut findings = Vec::new();
    let mut scanned = 0u64;
    // The files the heuristic opened, handed to ClamAV afterwards as well.
    let mut clam_files: Vec<crate::clamav_cache::FileInfo> = Vec::new();
    let mut clam_skipped = 0u64;

    for root in &roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();

            let is_php = PHP_EXTS.contains(&ext.as_str());
            let is_image = IMAGE_EXTS.contains(&ext.as_str());
            let is_upload = is_upload_path(path);

            // Decide whether to open this file.
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > max_bytes {
                continue;
            }
            let recent = file_recent(&meta, now, window);

            // Always scan PHP; scan image-ext/no-ext in uploads; scan other
            // files only if recent (deep ignores the time filter).
            let should_scan = is_php
                || (is_upload && (is_image || ext.is_empty()))
                || (opts.deep && recent)
                || (recent && is_upload);
            if !should_scan {
                continue;
            }

            let Some(bytes) = read_capped(path, max_bytes) else {
                continue;
            };
            // For non-php candidates, require a PHP marker to avoid noise.
            if !is_php
                && memchr::memmem::find(&bytes, b"<?php").is_none()
                && memchr::memmem::find(&bytes, b"<?=").is_none()
            {
                continue;
            }

            scanned += 1;
            // ClamAV gets the same files. A name that is not valid UTF-8 cannot
            // go in its text list, and the list is capped: both are counted so
            // the summary can say the second engine saw fewer files.
            match path.to_str() {
                Some(p) if clam_files.len() < MAX_CLAM_FILES => {
                    use std::os::unix::fs::MetadataExt;
                    clam_files.push(crate::clamav_cache::FileInfo {
                        path: p.to_string(),
                        size: meta.size(),
                        mtime: meta.mtime(),
                        ctime: meta.ctime(),
                    });
                }
                _ => clam_skipped += 1,
            }
            let score = heuristic::score_php(&bytes, is_upload, is_image && !is_php);
            if score.verdict == Verdict::Clean {
                continue;
            }
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha = hex::encode(hasher.finalize());
            findings.push(Finding {
                path: path.to_string_lossy().to_string(),
                score: score.score,
                verdict: score.verdict.as_str().to_string(),
                rules: score.hits.iter().map(|h| h.rule.to_string()).collect(),
                context: score.context,
                sha256: sha,
            });
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.score));

    // The heuristic result is complete now: store it before ClamAV starts, so a
    // unit that is stopped (time limit, out of memory) during the second engine
    // still leaves today's result. The summary says ClamAV did not finish.
    let clam_present = crate::clamav_run::find_bin("clamscan").is_some()
        || crate::clamav_run::find_bin("clamdscan").is_some();
    let mut summary = summarize(
        &findings,
        scanned,
        util::now_secs(),
        started.elapsed().as_secs(),
    );
    if clam_present && cfg.hunt.clamav == ClamavMode::Auto && !clam_files.is_empty() {
        summary.clamav_note =
            "ClamAV chưa chạy xong (bị dừng giữa chừng hoặc quá thời gian)".into();
    }
    store_results(state, &findings, &summary)?;

    // Second opinion from ClamAV, when it is installed and can run. A problem
    // there never fails the hunt: it becomes a note on the summary. It gets what
    // is left of the unit's time budget.
    let budget = HUNT_BUDGET_SECS.saturating_sub(started.elapsed().as_secs());
    let clam = crate::clamav_run::scan(
        cfg,
        state,
        &clam_files,
        clam_skipped,
        opts.max_file_mb,
        budget,
    );
    if clam.engine.is_empty() && clam.note.is_empty() {
        // ClamAV did not take part and there is nothing to say about it.
        summary.clamav_note.clear();
    } else {
        crate::clamav::merge(&mut findings, &clam.detections, |p| {
            read_capped(Path::new(p), max_bytes)
                .map(|b| hex::encode(Sha256::digest(&b)))
                .unwrap_or_default()
        });
        findings.sort_by_key(|f| std::cmp::Reverse(f.score));
        summary = summarize(
            &findings,
            scanned,
            util::now_secs(),
            started.elapsed().as_secs(),
        );
        summary.clamav_engine = clam.engine.clone();
        summary.clamav_scanned = clam.scanned;
        summary.clamav_up_to_date = clam.up_to_date;
        summary.clamav_pending = clam.pending;
        summary.clamav_note = clam.note.clone();
    }
    store_results(state, &findings, &summary)?;

    if opts.print {
        print_findings(&findings, scanned);
        if !clam.engine.is_empty() {
            println!(
                "ClamAV ({}): {} file, {} phát hiện",
                clam.engine,
                clam.scanned,
                clam.detections.len()
            );
        }
        if !clam.note.is_empty() {
            println!("ClamAV: {}", clam.note);
        }
    }
    Ok(findings)
}

/// Write the findings and then the summary. The summary is what marks a scan as
/// finished, so the report never pairs a fresh summary with stale findings.
fn store_results(state: &State, findings: &[Finding], summary: &HuntSummary) -> Result<()> {
    let _ = std::fs::write(
        state.dir.join("findings-latest.json"),
        serde_json::to_vec_pretty(findings)?,
    );
    let _ = std::fs::write(
        state.dir.join("hunt-latest.json"),
        serde_json::to_vec_pretty(summary)?,
    );
    Ok(())
}

/// Count findings by verdict into the scan summary that goes to the hub.
pub fn summarize(findings: &[Finding], scanned: u64, at: i64, duration_secs: u64) -> HuntSummary {
    let count = |verdict: &str| {
        u32::try_from(findings.iter().filter(|f| f.verdict == verdict).count()).unwrap_or(u32::MAX)
    };
    HuntSummary {
        at,
        scanned,
        duration_secs,
        malicious: count("malicious"),
        suspicious: count("suspicious"),
        // Filled in by `run` once ClamAV has been consulted.
        ..HuntSummary::default()
    }
}

/// After `sn clean`, keep only the findings still outstanding and bring the
/// summary's counts in line, so the hub stops flagging files already handled.
/// The scan time and file count stay as they were: nothing was re-scanned.
pub fn store_remaining(state: &State, remaining: &[Finding]) {
    if let Ok(bytes) = serde_json::to_vec_pretty(remaining) {
        let _ = std::fs::write(state.dir.join("findings-latest.json"), bytes);
    }
    let path = state.dir.join("hunt-latest.json");
    let Some(mut summary) = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<HuntSummary>(&b).ok())
    else {
        return;
    };
    let fresh = summarize(
        remaining,
        summary.scanned,
        summary.at,
        summary.duration_secs,
    );
    summary.malicious = fresh.malicious;
    summary.suspicious = fresh.suspicious;
    if let Ok(bytes) = serde_json::to_vec_pretty(&summary) {
        let _ = std::fs::write(&path, bytes);
    }
}

fn is_upload_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/uploads/") || s.contains("/wp-content/uploads") || s.contains("/cache/")
}

fn file_recent(meta: &std::fs::Metadata, now: i64, window: i64) -> bool {
    use std::os::unix::fs::MetadataExt;
    // Use max(mtime, ctime): ctime cannot be forged from userspace, defeating
    // simple `touch -r` timestomping.
    let mtime = meta.mtime();
    let ctime = meta.ctime();
    let newest = mtime.max(ctime);
    now - newest <= window
}

fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn print_findings(findings: &[Finding], scanned: u64) {
    println!("== sn hunt ==");
    println!(
        "scanned {scanned} candidate file(s); {} finding(s)",
        findings.len()
    );
    if findings.is_empty() {
        return;
    }
    println!("\n{:<6} {:<12} {:<50}", "SCORE", "VERDICT", "PATH");
    for f in findings {
        println!(
            "{:<6} {:<12} {:<50}",
            f.score,
            f.verdict,
            util::ellipsize(&f.path, 50)
        );
        if !f.rules.is_empty() {
            println!("       rules: {}", f.rules.join(", "));
        }
        if !f.context.is_empty() {
            println!("       ctx: {}", util::ellipsize(&f.context, 80));
        }
    }
    println!(
        "\nScore >= 100 is \"malicious\" (certain enough to quarantine), 70-99 is \"suspicious\" \
         (look at it yourself)."
    );
    println!(
        "`sn clean --yes` quarantines ONLY the malicious ones (reversible with `sn restore <id>`). \
         A heuristic can be wrong: read the context above before you run it."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;

    fn fixture_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let w = |rel: &str, body: &str| {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        // A shell dropped into uploads (fragments keep the source AV-clean).
        w(
            "site/wp-content/uploads/2026/x.php",
            &["<?php sys", "tem($_", "GET['c']); ?>"].concat(),
        );
        // Ordinary WordPress code.
        w(
            "site/wp-content/themes/t/functions.php",
            "<?php add_action('init', 'my_init'); function my_init() { register_post_type('x'); }",
        );
        // Not PHP at all.
        w("site/readme.txt", "hello");
        dir
    }

    fn opts(root: &std::path::Path) -> Options {
        Options {
            days: 1,
            roots: vec![root.to_string_lossy().to_string()],
            deep: false,
            max_file_mb: 5,
            print: false,
        }
    }

    fn default_cfg() -> Config {
        // ClamAV off: these tests are about the heuristic and must not depend on
        // what happens to be installed on the machine running them.
        toml::from_str("[hunt]\nclamav = \"off\"").unwrap()
    }

    #[test]
    fn finds_the_shell_and_leaves_ordinary_code_alone() {
        let dir = fixture_root();
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());

        let findings = run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].path.ends_with("uploads/2026/x.php"));
        assert_eq!(findings[0].verdict, "malicious");
    }

    #[test]
    fn writes_findings_and_a_summary_the_hub_can_show() {
        let dir = fixture_root();
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());
        run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        let findings: Vec<Finding> =
            serde_json::from_slice(&std::fs::read(state.dir.join("findings-latest.json")).unwrap())
                .unwrap();
        assert_eq!(findings.len(), 1);
        let summary: HuntSummary =
            serde_json::from_slice(&std::fs::read(state.dir.join("hunt-latest.json")).unwrap())
                .unwrap();
        assert_eq!(summary.malicious, 1);
        assert_eq!(summary.suspicious, 0);
        // Both PHP files were opened; the .txt was not.
        assert_eq!(summary.scanned, 2);
        assert!(summary.at > 0);
    }

    #[test]
    fn a_clean_scan_still_records_that_it_ran() {
        // "Scanned and clean" must be distinguishable from "never scanned".
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.php"), "<?php echo 'hi';").unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());
        run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        let summary: HuntSummary =
            serde_json::from_slice(&std::fs::read(state.dir.join("hunt-latest.json")).unwrap())
                .unwrap();
        assert_eq!((summary.malicious, summary.suspicious), (0, 0));
        assert_eq!(summary.scanned, 1);
    }

    #[test]
    fn cleaning_updates_what_is_outstanding() {
        let dir = fixture_root();
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());
        let findings = run(&default_cfg(), &state, &opts(dir.path())).unwrap();
        assert_eq!(findings.len(), 1);

        // The only finding is handled: nothing left, and the counts follow.
        store_remaining(&state, &[]);
        let left: Vec<Finding> =
            serde_json::from_slice(&std::fs::read(state.dir.join("findings-latest.json")).unwrap())
                .unwrap();
        assert!(left.is_empty());
        let summary: HuntSummary =
            serde_json::from_slice(&std::fs::read(state.dir.join("hunt-latest.json")).unwrap())
                .unwrap();
        assert_eq!((summary.malicious, summary.suspicious), (0, 0));
        // It still says a scan ran, over the same number of files.
        assert_eq!(summary.scanned, 2);
        assert!(summary.at > 0);
    }

    #[test]
    fn summarize_counts_by_verdict() {
        let f = |verdict: &str| Finding {
            path: "/x".into(),
            score: 0,
            verdict: verdict.into(),
            rules: vec![],
            context: String::new(),
            sha256: String::new(),
        };
        let s = summarize(
            &[
                f("malicious"),
                f("suspicious"),
                f("suspicious"),
                f("encoded-commercial"),
            ],
            10,
            5,
            2,
        );
        assert_eq!((s.malicious, s.suspicious, s.scanned), (1, 2, 10));
    }
}
