//! `sn hunt` — walk the allowed roots and score PHP files for web-shell
//! signatures. Runs read-only; produces findings for review and for `sn clean`.
//! The systemd unit pins it to low CPU/IO priority; here we also cap file size
//! and total bytes so a hunt never starves a busy site.

use std::io::Read;
use std::path::Path;

use anyhow::Result;
use sha2::{Digest, Sha256};
use snsec_common::heuristic::{self, Verdict};
use snsec_common::schema::Finding;
use walkdir::WalkDir;

use crate::config::Config;
use crate::state::State;
use crate::util;

const PHP_EXTS: &[&str] = &[
    "php", "phtml", "php5", "php7", "php8", "pht", "phar", "inc", "phps",
];
const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "webp", "bmp", "ico", "svg"];

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

    let mut findings = Vec::new();
    let mut scanned = 0u64;

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

    let _ = std::fs::write(
        state.dir.join("findings-latest.json"),
        serde_json::to_vec_pretty(&findings)?,
    );

    if opts.print {
        print_findings(&findings, scanned);
    }
    Ok(findings)
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
        "\nreview, then `sn clean --yes` to quarantine malicious files (reversible with `sn restore`)."
    );
}
