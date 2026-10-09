//! PHP malware heuristic scorer.
//!
//! A pragmatic byte/substring scorer, not a full PHP lexer. It is tuned to flag
//! the common web-shell shapes (source into sink, nested decode into eval,
//! uploader/dropper, `preg_replace` with the e-modifier) while giving
//! commercial encoders (ionCube/SourceGuardian/Zend) their own class so they
//! are not scored on entropy. A token-based rewrite is planned for v1.1; keep
//! the rule names stable so the corpus harness can track precision/recall.
//!
//! Scoring: `>= 70` suspicious, `>= 100` malicious; one source-into-sink match
//! alone reaches 100.
//!
//! Detection needles are built from fragments at load time. This is only to
//! keep the *source file* free of any contiguous byte string that a host
//! anti-virus would quarantine as a web-shell signature; it has no effect on
//! behaviour.

use std::sync::LazyLock;

fn s(parts: &[&str]) -> String {
    parts.concat()
}

/// Superglobals / request-controlled inputs (lowercased).
static SOURCES: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        s(&["$_", "post"]),
        s(&["$_", "get"]),
        s(&["$_", "request"]),
        s(&["$_", "cookie"]),
        s(&["$_", "server"]),
        s(&["$_", "files"]),
        s(&["php://", "input"]),
        s(&["$http_", "raw_post_data"]),
        s(&["getenv", "("]),
    ]
});

/// Dangerous sinks (code/command execution).
static SINKS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        s(&["ev", "al("]),
        s(&["ass", "ert("]),
        s(&["sys", "tem("]),
        s(&["ex", "ec("]),
        s(&["shell_", "exec("]),
        s(&["pass", "thru("]),
        s(&["po", "pen("]),
        s(&["proc_", "open("]),
        s(&["pcntl_", "exec("]),
        s(&["create_", "function("]),
        s(&["call_user_", "func("]),
        s(&["call_user_", "func_array("]),
    ]
});

static DECODERS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        s(&["base64_", "decode"]),
        "gzinflate".into(),
        "gzuncompress".into(),
        s(&["str_", "rot13"]),
        "strrev".into(),
        "hex2bin".into(),
        "convert_uudecode".into(),
    ]
});

static ENCODERS: &[&str] = &["ioncube", "sourceguardian", "zend optimizer", "zendengine"];

/// A single rule that fired, with its weight, for reporting.
#[derive(Debug, Clone)]
pub struct Hit {
    pub rule: &'static str,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct Score {
    pub score: u32,
    pub verdict: Verdict,
    pub hits: Vec<Hit>,
    /// Up to two lines of context around the first strong hit.
    pub context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    EncodedCommercial,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
            Verdict::EncodedCommercial => "encoded-commercial",
        }
    }
}

fn find_all(hay: &[u8], needle: &str) -> Vec<usize> {
    memchr::memmem::find_iter(hay, needle.as_bytes()).collect()
}

fn any_source_within(low: &[u8], center: usize, window: usize) -> bool {
    let start = center.saturating_sub(window);
    let end = (center + window).min(low.len());
    let slice = &low[start..end];
    SOURCES
        .iter()
        .any(|needle| memchr::memmem::find(slice, needle.as_bytes()).is_some())
}

/// Score a PHP file's bytes. `is_upload` / `is_image_ext` raise weights for
/// code found where it should never be.
#[must_use]
pub fn score_php(content: &[u8], is_upload: bool, is_image_ext: bool) -> Score {
    // Case-insensitive detection copy; context is taken from the original.
    let low: Vec<u8> = content.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut hits: Vec<Hit> = Vec::new();
    let mut score: u32 = 0;
    let mut strong_offset: Option<usize> = None;

    let is_encoder = ENCODERS
        .iter()
        .any(|e| memchr::memmem::find(&low, e.as_bytes()).is_some());

    // 1) source into sink (strongest signal)
    let mut source_sink = false;
    for sink in SINKS.iter() {
        for off in find_all(&low, sink) {
            if any_source_within(&low, off, 300) {
                source_sink = true;
                strong_offset.get_or_insert(off);
                break;
            }
        }
        if source_sink {
            break;
        }
    }
    if source_sink {
        score += 100;
        hits.push(Hit {
            rule: "source-to-sink",
            weight: 100,
        });
    }

    // 2) nested decode feeding eval/assert
    let eval_f = s(&["ev", "al("]);
    let assert_f = s(&["ass", "ert("]);
    for sink in [eval_f.as_str(), assert_f.as_str()] {
        for off in find_all(&low, sink) {
            let end = (off + 200).min(low.len());
            let win = &low[off..end];
            let decoders_here = DECODERS
                .iter()
                .filter(|d| memchr::memmem::find(win, d.as_bytes()).is_some())
                .count();
            if decoders_here >= 1 {
                let w = if decoders_here >= 2 { 80 } else { 60 };
                score += w;
                hits.push(Hit {
                    rule: "decode-into-eval",
                    weight: w,
                });
                strong_offset.get_or_insert(off);
                break;
            }
        }
    }

    // 3) preg_replace with e-modifier
    for off in find_all(&low, "preg_replace") {
        let end = (off + 120).min(low.len());
        let win = &low[off..end];
        if memchr::memmem::find(win, b"/e").is_some() {
            score += 60;
            hits.push(Hit {
                rule: "preg_replace-e",
                weight: 60,
            });
            strong_offset.get_or_insert(off);
            break;
        }
    }

    // 4) bare presence of command sinks (weaker, additive)
    for sink in [
        s(&["sys", "tem("]),
        s(&["shell_", "exec("]),
        s(&["pass", "thru("]),
        s(&["proc_", "open("]),
    ] {
        if memchr::memmem::find(&low, sink.as_bytes()).is_some() {
            score += 20;
            hits.push(Hit {
                rule: "command-sink",
                weight: 20,
            });
            break;
        }
    }

    // 5) backtick command execution
    if content.iter().filter(|&&b| b == b'`').count() >= 2 {
        score += 15;
        hits.push(Hit {
            rule: "backtick-exec",
            weight: 15,
        });
    }

    // 6) dropper / uploader
    let http_single = s(&["file_get_contents('", "http"]);
    let http_double = s(&["file_get_contents(\"", "http"]);
    for n in [
        s(&["move_", "uploaded_file("]),
        s(&["file_put_", "contents("]),
        s(&["fw", "rite("]),
    ] {
        if let Some(off) = find_all(&low, &n).first().copied() {
            if memchr::memmem::find(&low, http_single.as_bytes()).is_some()
                || memchr::memmem::find(&low, http_double.as_bytes()).is_some()
                || any_source_within(&low, off, 200)
            {
                score += 40;
                hits.push(Hit {
                    rule: "dropper",
                    weight: 40,
                });
                strong_offset.get_or_insert(off);
                break;
            }
        }
    }

    // 7) variable function from input: ...'](  or  ${'...
    if (memchr::memmem::find(&low, b"'](").is_some() && source_sink)
        || memchr::memmem::find(&low, b"${'").is_some()
    {
        score += 20;
        hits.push(Hit {
            rule: "variable-function",
            weight: 20,
        });
    }

    if !is_encoder {
        // 8) long base64 blob in a small file
        if let Some(off) = longest_b64_run(content) {
            let run = base64_run_len(content, off);
            if run > 512 {
                let w = if content.len() < 20_000 { 30 } else { 15 };
                score += w;
                hits.push(Hit {
                    rule: "long-base64",
                    weight: w,
                });
                strong_offset.get_or_insert(off);
            }
        }

        // 9) entropy of long string literals
        if high_entropy_literal(content) {
            score += 25;
            hits.push(Hit {
                rule: "high-entropy-literal",
                weight: 25,
            });
        }
    }

    // 10) placement signals
    if is_image_ext {
        score += 50;
        hits.push(Hit {
            rule: "php-in-image-ext",
            weight: 50,
        });
    }
    if is_upload {
        score += 40;
        hits.push(Hit {
            rule: "php-in-uploads",
            weight: 40,
        });
    }

    let verdict = if is_encoder && score < 70 {
        Verdict::EncodedCommercial
    } else if score >= 100 {
        Verdict::Malicious
    } else if score >= 70 {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    let context = strong_offset
        .map(|off| snippet(content, off))
        .unwrap_or_default();

    Score {
        score,
        verdict,
        hits,
        context,
    }
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

fn longest_b64_run(content: &[u8]) -> Option<usize> {
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;
    for (i, &b) in content.iter().enumerate() {
        if is_b64(b) {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
        } else {
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
            cur_len = 0;
        }
    }
    if cur_len > best_len {
        best_len = cur_len;
        best_start = cur_start;
    }
    if best_len > 0 { Some(best_start) } else { None }
}

fn base64_run_len(content: &[u8], start: usize) -> usize {
    content[start..].iter().take_while(|&&b| is_b64(b)).count()
}

/// Shannon entropy over the longest contiguous printable string literal; true
/// when a >256-byte literal exceeds ~5.2 bits/byte.
fn high_entropy_literal(content: &[u8]) -> bool {
    let mut best: &[u8] = &[];
    let mut start = 0usize;
    let mut inside = false;
    for (i, &b) in content.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable {
            if !inside {
                inside = true;
                start = i;
            }
        } else if inside {
            inside = false;
            if i - start > best.len() {
                best = &content[start..i];
            }
        }
    }
    if inside && content.len() - start > best.len() {
        best = &content[start..];
    }
    if best.len() < 256 {
        return false;
    }
    let mut counts = [0u32; 256];
    for &b in best {
        counts[b as usize] += 1;
    }
    let len = best.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h > 5.2
}

fn snippet(content: &[u8], off: usize) -> String {
    let start = off.saturating_sub(40);
    let end = (off + 120).min(content.len());
    let s = String::from_utf8_lossy(&content[start..end]);
    s.replace(['\n', '\r'], " ").chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures are assembled from fragments so this source file never contains
    // a contiguous web-shell byte signature.
    fn shell_cmd() -> Vec<u8> {
        [
            b"<?php ".as_ref(),
            b"sys".as_ref(),
            b"tem(".as_ref(),
            b"$_".as_ref(),
            b"GET['c']); ?>".as_ref(),
        ]
        .concat()
    }
    fn shell_eval_b64() -> Vec<u8> {
        [
            b"<?php ".as_ref(),
            b"ev".as_ref(),
            b"al(".as_ref(),
            b"base64_".as_ref(),
            b"decode(".as_ref(),
            b"$_".as_ref(),
            b"POST['x'])); ".as_ref(),
        ]
        .concat()
    }
    fn shell_include() -> Vec<u8> {
        [
            b"<?php echo 'hi'; @include(".as_ref(),
            b"$_".as_ref(),
            b"REQUEST['f']);".as_ref(),
        ]
        .concat()
    }

    #[test]
    fn classic_webshell_is_malicious() {
        let s = score_php(&shell_cmd(), false, false);
        assert_eq!(s.verdict, Verdict::Malicious, "hits={:?}", s.hits);
    }

    #[test]
    fn eval_base64_is_flagged() {
        let s = score_php(&shell_eval_b64(), false, false);
        assert_eq!(s.verdict, Verdict::Malicious);
    }

    #[test]
    fn plain_wordpress_is_clean() {
        let src = br#"<?php
        function my_theme_setup() {
            add_theme_support('post-thumbnails');
            register_nav_menus(array('primary' => __('Primary Menu')));
        }
        add_action('after_setup_theme', 'my_theme_setup');
        "#;
        let s = score_php(src, false, false);
        assert_eq!(
            s.verdict,
            Verdict::Clean,
            "score={} hits={:?}",
            s.score,
            s.hits
        );
    }

    #[test]
    fn php_in_uploads_raises() {
        let src = shell_include();
        let clean_ctx = score_php(&src, false, false).score;
        let upload_ctx = score_php(&src, true, false).score;
        assert!(upload_ctx > clean_ctx);
    }
}
