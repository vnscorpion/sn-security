//! Development tool: run the shipped PHP heuristic over every PHP file under a
//! directory and list what it would flag. Used to measure false positives on
//! real, legitimate code (WordPress core, popular plugins) before trusting a
//! change to the scorer.
//!
//!     cargo run -p snsec-common --release --example scan_dir -- <dir>
//!
//! Not shipped in any binary.

use std::path::Path;

use snsec_common::heuristic::{Verdict, score_php};
use walkdir::WalkDir;

const PHP_EXTS: &[&str] = &["php", "phtml", "inc", "php5", "php7", "pht", "phar"];

fn main() {
    let Some(root) = std::env::args().nth(1) else {
        eprintln!("usage: scan_dir <directory>");
        std::process::exit(2);
    };
    let root = Path::new(&root);

    let (mut files, mut flagged, mut malicious) = (0u64, 0u64, 0u64);
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !PHP_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        files += 1;

        let score = score_php(&bytes, false, false);
        if score.verdict == Verdict::Clean {
            continue;
        }
        flagged += 1;
        if score.verdict == Verdict::Malicious {
            malicious += 1;
        }
        let rules: Vec<&str> = score.hits.iter().map(|h| h.rule).collect();
        let rel = path.strip_prefix(root).unwrap_or(path);
        println!(
            "{:>4} {:<18} {}  [{}]",
            score.score,
            score.verdict.as_str(),
            rel.display(),
            rules.join(",")
        );
        if !score.context.is_empty() {
            println!("       ctx: {}", score.context);
        }
    }
    println!("\nPHP files scanned: {files}   flagged: {flagged}   malicious: {malicious}");
}
