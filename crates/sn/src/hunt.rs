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
    "php", "phtml", "php3", "php4", "php5", "php6", "php7", "php8", "pht", "phtm", "phar", "inc",
    "phps",
];
/// Files that make the web server run a picture as code.
const CONFIG_NAMES: &[&str] = &[".htaccess", ".user.ini", "php.ini", ".php.ini"];
const CONFIG_MAX_BYTES: u64 = 256 * 1024;
/// A picture up to this size is read whole; a larger one by its two ends, where
/// metadata and appended payloads sit, so a gallery of big photos costs little.
const IMAGE_WHOLE_BYTES: u64 = 2 * 1024 * 1024;
const IMAGE_EDGE_BYTES: u64 = 512 * 1024;
/// Pictures are read for this long at most. A media library can hold hundreds
/// of thousands, and the unit is stopped at 30 minutes without a result: PHP and
/// configuration files are always read, pictures are counted when left over.
const IMAGE_BUDGET_SECS: u64 = 18 * 60;
/// Files handed to ClamAV in one hunt.
const MAX_CLAM_FILES: usize = crate::clamav_cache::MAX_ENTRIES;
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
    let given = if opts.roots.is_empty() {
        cfg.hunt.allowed_roots.clone()
    } else {
        opts.roots.clone()
    };
    // Walk the real paths: ClamAV prints every file under its resolved name, and
    // a root reached through a symlink (/var/www -> /srv/www) would otherwise
    // never match. Interior links are not followed by the walk.
    let mut roots: Vec<String> = Vec::new();
    for r in &given {
        if let Ok(c) = std::fs::canonicalize(r)
            && let Some(s) = c.to_str()
            && !roots.iter().any(|x| x == s)
        {
            roots.push(s.to_string());
        }
    }
    let max_bytes = opts.max_file_mb.max(1) * 1024 * 1024;
    let window = opts.days as i64 * 86_400;
    let now = util::now_secs();
    let started = std::time::Instant::now();

    let mut findings = Vec::new();
    let mut scanned = 0u64;
    // The files the heuristic opened, handed to ClamAV afterwards as well.
    let mut clam_files: Vec<crate::clamav_cache::FileInfo> = Vec::new();
    let mut clam_skipped = 0u64;
    let mut images_skipped = 0u64;

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

            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            let is_php = PHP_EXTS.contains(&ext.as_str());
            let is_image = !is_php && heuristic::IMAGE_EXTS.contains(&ext.as_str());
            let is_config = CONFIG_NAMES.contains(&name.as_str());
            let is_upload = is_upload_path(path);

            // Decide whether to open this file.
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            // A picture of any size is looked at (by its ends when large): a
            // payload is no less dangerous for being in a big file.
            let cap = if is_config {
                CONFIG_MAX_BYTES
            } else {
                max_bytes
            };
            if !is_image && meta.len() > cap {
                continue;
            }
            let recent = file_recent(&meta, now, window);

            // Always scan PHP, pictures (wherever they are: a panel keeps them
            // in public_html/images, media, assets... not only in uploads) and
            // the files that turn pictures into code; scan other files without
            // an extension in uploads, and other recent files, only when they
            // hold a PHP tag (deep ignores the time filter).
            let should_scan = is_php
                || is_image
                || is_config
                || (is_upload && ext.is_empty())
                || (opts.deep && recent)
                || (recent && is_upload);
            if !should_scan {
                continue;
            }
            if is_image && started.elapsed().as_secs() >= IMAGE_BUDGET_SECS {
                images_skipped += 1;
                continue;
            }

            let bytes = if is_image {
                read_image(path, meta.len())
            } else {
                read_capped(path, cap)
            };
            let Some(bytes) = bytes else {
                continue;
            };
            let mut score = if is_php {
                heuristic::score_php(&bytes, is_upload, false)
            } else if is_config {
                heuristic::score_config(&name, &bytes)
            } else if is_image {
                heuristic::score_image(&name, &bytes)
            } else if heuristic::has_php_marker(&bytes) {
                // For other candidates, require a PHP tag to avoid noise.
                heuristic::score_php(&bytes, is_upload, false)
            } else {
                continue;
            };
            // PHPUnit and its phar run commands by design.
            if is_php && is_dev_tool(path, &ext) {
                heuristic::cap_without_strong_rule(&mut score);
            }

            scanned += 1;
            // ClamAV gets the PHP the heuristic opened, and any picture or
            // configuration file it flagged (a second opinion, with a family
            // name). Not every picture: that would crowd the PHP out of its
            // list. A name that is not valid UTF-8 cannot go in its text list,
            // and the list is capped: both are counted so the summary can say
            // the second engine saw fewer files.
            if (!is_image && !is_config) || score.verdict != Verdict::Clean {
                match path.to_str() {
                    Some(p) if clam_files.len() < MAX_CLAM_FILES => {
                        use std::os::unix::fs::MetadataExt;
                        clam_files.push(crate::clamav_cache::FileInfo {
                            path: p.to_string(),
                            stamp: crate::clamav_cache::Stamp {
                                dev: meta.dev(),
                                ino: meta.ino(),
                                size: meta.size(),
                                mtime: meta.mtime(),
                                mtime_nsec: meta.mtime_nsec(),
                                ctime: meta.ctime(),
                                ctime_nsec: meta.ctime_nsec(),
                            },
                        });
                    }
                    _ => clam_skipped += 1,
                }
            }
            // A file that merely names an encoder (a comment, a pattern) is no
            // finding: there is nothing to do about it, and a list full of them
            // hides what matters.
            if matches!(score.verdict, Verdict::Clean | Verdict::EncodedCommercial) {
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
    summary.images_skipped = images_skipped;
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
        &roots,
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
        summary.images_skipped = images_skipped;
        summary.clamav_engine = clam.engine.clone();
        summary.clamav_scanned = clam.scanned;
        summary.clamav_up_to_date = clam.up_to_date;
        summary.clamav_pending = clam.pending;
        summary.clamav_note = clam.note.clone();
    }
    store_results(state, &findings, &summary)?;

    if opts.print {
        print_findings(&findings, scanned);
        if images_skipped > 0 {
            println!(
                "{images_skipped} ảnh chưa đọc vì hết thời gian dành cho ảnh ({} phút); PHP và file cấu hình đã quét đủ",
                IMAGE_BUDGET_SECS / 60
            );
        }
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

/// Is the scan result in the state directory the work of older scoring rules
/// (see [`heuristic::SCORER_VERSION`])? Such a result is not reported, and
/// `sn clean` does not act on it: it could name ordinary pictures.
#[must_use]
pub fn result_is_stale(state: &State) -> bool {
    std::fs::read(state.dir.join("hunt-latest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<HuntSummary>(&b).ok())
        .is_some_and(|s| s.scorer < heuristic::SCORER_VERSION)
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
        scorer: heuristic::SCORER_VERSION,
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

/// Test tooling that runs commands by design: PHPUnit under `vendor`, and any
/// phar (PHPUnit is shipped as one).
fn is_dev_tool(path: &Path, ext: &str) -> bool {
    ext == "phar" || path.to_string_lossy().contains("/vendor/phpunit/")
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

/// A picture's bytes: the whole file when it is small, otherwise its first and
/// last parts joined. A payload sits in the metadata at the start or is appended
/// after the image at the end; the middle is compressed picture data.
fn read_image(path: &Path, len: u64) -> Option<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    if len <= IMAGE_WHOLE_BYTES {
        return read_capped(path, IMAGE_WHOLE_BYTES);
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(2 * IMAGE_EDGE_BYTES as usize);
    (&mut f).take(IMAGE_EDGE_BYTES).read_to_end(&mut buf).ok()?;
    f.seek(SeekFrom::End(-(IMAGE_EDGE_BYTES as i64))).ok()?;
    f.take(IMAGE_EDGE_BYTES).read_to_end(&mut buf).ok()?;
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

    /// A JPEG-looking file: header, picture-like bytes, `middle`, more bytes.
    fn jpeg(middle: &[u8], filler: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0];
        let mut x = 99u64;
        let mut noise = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    x = x
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (x >> 33) as u8
                })
                .collect()
        };
        v.extend(noise(filler));
        v.extend(middle);
        v.extend(noise(filler));
        v.extend([0xFF, 0xD9]);
        v
    }

    fn shell() -> Vec<u8> {
        ["<?php sys", "tem($_", "GET['c']); ?>"]
            .concat()
            .into_bytes()
    }

    fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    #[test]
    fn test_tooling_is_reported_but_not_called_malicious_and_encoder_mentions_are_no_finding() {
        // Weak signs that add up to "malicious": a command call, an argument from
        // `$_SERVER`, a write to disk.
        let weak = [
            "<?php $s = $_",
            "SERVER['argv']; $p = proc_open($this->cmd($s), $spec, $pipes); file_put_",
            "contents($_",
            "SERVER['x'], 'y');",
        ]
        .concat();
        // A strong sign: the request body run as code (CVE-2017-9841's file).
        let strong = [
            "<?php ev",
            "al('?>' . file_get_contents('php://",
            "input'));",
        ]
        .concat();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        write(
            p,
            "a/vendor/phpunit/phpunit/src/Util/PHP/DefaultPhpProcess.php",
            weak.as_bytes(),
        );
        write(
            p,
            "a/vendor/mercadopago/dx-php/phpunit.phar",
            weak.as_bytes(),
        );
        write(
            p,
            "a/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            strong.as_bytes(),
        );
        write(p, "b/app/weak.php", weak.as_bytes());
        write(
            p,
            "c/wp-content/plugins/x/Loader.php",
            b"<?php // works with the ionCube loader too\nfunction f() { return 1; }\n",
        );
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());

        let findings = run(&default_cfg(), &state, &opts(p)).unwrap();

        let verdict_of = |suffix: &str| {
            findings
                .iter()
                .find(|f| f.path.ends_with(suffix))
                .map(|f| f.verdict.clone())
        };
        // Reported, never "malicious": `sn clean` leaves them alone.
        assert_eq!(
            verdict_of("DefaultPhpProcess.php").as_deref(),
            Some("suspicious")
        );
        assert_eq!(verdict_of("phpunit.phar").as_deref(), Some("suspicious"));
        let phar = findings
            .iter()
            .find(|f| f.path.ends_with("phpunit.phar"))
            .unwrap();
        assert!(phar.rules.iter().any(|r| r == "known-dev-tool") && phar.score == 99);
        // The same weak signs anywhere else stay "malicious"; a strong sign stays
        // "malicious" even in PHPUnit's folder.
        assert_eq!(verdict_of("weak.php").as_deref(), Some("malicious"));
        assert_eq!(verdict_of("eval-stdin.php").as_deref(), Some("malicious"));
        // A file that only names an encoder is not a finding.
        assert!(verdict_of("Loader.php").is_none(), "{findings:?}");
        // The summary counts follow.
        let summary: HuntSummary =
            serde_json::from_slice(&std::fs::read(state.dir.join("hunt-latest.json")).unwrap())
                .unwrap();
        assert_eq!((summary.malicious, summary.suspicious), (2, 2));
        assert_eq!(summary.scorer, heuristic::SCORER_VERSION);
    }

    #[test]
    fn finds_code_in_a_picture_wherever_the_panel_keeps_it() {
        // A panel's pictures are in public_html/images, media, assets: not only
        // in wp-content/uploads.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "public_html/images/banner.jpg",
            &jpeg(&shell(), 4000),
        );
        write(dir.path(), "public_html/media/ok.jpg", &jpeg(b"", 4000));
        write(
            dir.path(),
            "public_html/assets/logo.png",
            b"\x89PNG\r\n\x1a\nxx",
        );
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());

        let findings = run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].path.ends_with("images/banner.jpg"));
        assert_eq!(findings[0].verdict, "malicious");
        assert!(findings[0].rules.iter().any(|r| r == "php-in-image"));
        // The clean pictures were opened too: "scanned, nothing" is not "skipped".
        let summary: HuntSummary =
            serde_json::from_slice(&std::fs::read(state.dir.join("hunt-latest.json")).unwrap())
                .unwrap();
        assert_eq!(summary.scanned, 3);
    }

    #[test]
    fn finds_a_payload_appended_to_a_large_picture() {
        // Over the size read whole: only its two ends are read, and the payload
        // is at the end.
        let dir = tempfile::tempdir().unwrap();
        let mut big = jpeg(b"", 2_000_000);
        big.extend(shell());
        write(dir.path(), "site/gallery/big.jpg", &big);
        let mut clean = jpeg(b"", 2_000_000);
        clean.extend([0u8; 16]);
        write(dir.path(), "site/gallery/clean.jpg", &clean);
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());

        let findings = run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].path.ends_with("gallery/big.jpg"));
    }

    #[test]
    fn finds_the_files_that_turn_pictures_into_code() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "public_html/.htaccess",
            b"AddHandler application/x-httpd-php .jpg\n",
        );
        write(
            dir.path(),
            "public_html/blog/.user.ini",
            b"auto_prepend_file = /home/u/public_html/blog/logo.png\n",
        );
        write(
            dir.path(),
            "public_html/shop/.htaccess",
            b"RewriteEngine On\nRewriteRule . /index.php [L]\n",
        );
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());

        let findings = run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        let mut paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths.len(), 2, "{findings:?}");
        assert!(paths[0].ends_with("public_html/.htaccess"));
        assert!(paths[1].ends_with("blog/.user.ini"));
        assert!(findings.iter().all(|f| f.verdict == "malicious"));
    }

    #[test]
    fn a_file_with_the_tag_in_capitals_is_found_too() {
        let dir = tempfile::tempdir().unwrap();
        // Not a PHP name and not a picture, in uploads: opened because of the tag.
        write(
            dir.path(),
            "site/wp-content/uploads/notes.txt",
            ["<?PHP SYS", "TEM($_", "GET['c']); ?>"].concat().as_bytes(),
        );
        let state_dir = tempfile::tempdir().unwrap();
        let state = State::at(state_dir.path().to_path_buf());

        let findings = run(&default_cfg(), &state, &opts(dir.path())).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
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
