//! Development tool: run the shipped heuristics over a directory and list what
//! they would flag: PHP files, pictures, and the configuration files that can
//! turn pictures into code. Used to measure false positives on real, legitimate
//! files (WordPress core, popular plugins, a site's media library) before
//! trusting a change to a scorer.
//!
//!     cargo run -p snsec-common --release --example scan_dir -- <dir>
//!
//! Not shipped in any binary.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use snsec_common::heuristic::{IMAGE_EXTS, Score, Verdict, score_config, score_image, score_php};
use walkdir::WalkDir;

const PHP_EXTS: &[&str] = &["php", "phtml", "inc", "php5", "php7", "pht", "phar"];
const CONFIG_NAMES: &[&str] = &[".htaccess", ".user.ini", "php.ini", ".php.ini"];
/// The same limits `sn hunt` uses: a picture is read whole up to 2 MB, and by
/// its first and last 512 KB beyond that.
const IMAGE_WHOLE: u64 = 2 * 1024 * 1024;
const IMAGE_EDGE: u64 = 512 * 1024;

fn read_image(path: &Path) -> Option<Vec<u8>> {
    let len = std::fs::metadata(path).ok()?.len();
    if len <= IMAGE_WHOLE {
        return std::fs::read(path).ok();
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    (&mut f).take(IMAGE_EDGE).read_to_end(&mut buf).ok()?;
    f.seek(SeekFrom::End(-(IMAGE_EDGE as i64))).ok()?;
    f.take(IMAGE_EDGE).read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[derive(Default)]
struct Tally {
    files: u64,
    flagged: u64,
    malicious: u64,
}

impl Tally {
    fn add(&mut self, score: &Score, shown: &Path, root: &Path) {
        self.files += 1;
        if score.verdict == Verdict::Clean {
            return;
        }
        self.flagged += 1;
        if score.verdict == Verdict::Malicious {
            self.malicious += 1;
        }
        let rules: Vec<&str> = score.hits.iter().map(|h| h.rule).collect();
        let rel = shown.strip_prefix(root).unwrap_or(shown);
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

    fn line(&self, what: &str) {
        println!(
            "{what:<10} scanned: {:>7}   flagged: {:>5}   malicious: {:>5}",
            self.files, self.flagged, self.malicious
        );
    }
}

fn main() {
    let Some(root) = std::env::args().nth(1) else {
        eprintln!("usage: scan_dir <directory>");
        std::process::exit(2);
    };
    let root = Path::new(&root);

    let (mut php, mut images, mut configs) = (Tally::default(), Tally::default(), Tally::default());
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if PHP_EXTS.contains(&ext.as_str()) {
            if let Ok(bytes) = std::fs::read(path) {
                php.add(&score_php(&bytes, false, false), path, root);
            }
        } else if IMAGE_EXTS.contains(&ext.as_str()) {
            if let Some(bytes) = read_image(path) {
                images.add(&score_image(&name, &bytes), path, root);
            }
        } else if CONFIG_NAMES.contains(&name.as_str())
            && let Ok(bytes) = std::fs::read(path)
        {
            configs.add(&score_config(&name, &bytes), path, root);
        }
    }
    println!();
    php.line("PHP");
    images.line("pictures");
    configs.line("config");
}
