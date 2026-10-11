//! PHP malware heuristic scorer.
//!
//! A pragmatic byte scorer, not a PHP parser. The aim is a *low false-positive
//! rate on legitimate code* first (a "malicious" verdict can be auto-quarantined
//! by `sn clean`, and a quarantined WordPress core file breaks a site), and
//! detection of the common web-shell shapes second.
//!
//! What that means in practice:
//! * A dangerous call only counts when it is a **bare call** (`name(`): not a
//!   longer identifier (`WP_Filesystem(` is not `system(`), not a method or
//!   static call (`$pdo->exec(`), not a definition (`function exec(`).
//! * Request input only counts when it is **inside the call's arguments**, or in
//!   a variable that was assigned from request input. "Appears somewhere nearby"
//!   is how WordPress's own callback dispatch (`call_user_func( $cb )` next to a
//!   `$_POST` check) used to be flagged.
//! * Direct input→call and input-called-as-a-function are **malicious** on their
//!   own. Indirect evidence (a variable assigned from input, one decoder, an
//!   encoded blob) is only **suspicious** by itself: reported for a human, never
//!   auto-quarantined. Several independent signs together (for example a packed
//!   `eval(gzinflate(base64_decode(...)))` with a large blob) can still add up.
//!
//! Scoring: `>= 70` suspicious, `>= 100` malicious. Commercial encoders
//! (ionCube/SourceGuardian/Zend) get their own class and are not scored on
//! entropy.
//!
//! Detection needles are built from fragments at load time. This only keeps the
//! *source file* free of contiguous byte strings that a host anti-virus would
//! quarantine as a web-shell signature; it has no effect on behaviour.
//!
//! Tune against real code with `cargo run -p snsec-common --release --example
//! scan_dir -- <dir>` (WordPress core + popular plugins is the regression set).

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
    ]
});

/// Calls that run code or commands.
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

/// Commands that are suspicious to merely be present (weak, additive).
static COMMAND_SINKS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        s(&["sys", "tem("]),
        s(&["shell_", "exec("]),
        s(&["pass", "thru("]),
        s(&["proc_", "open("]),
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
    /// A short excerpt around the first strong hit.
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

// ---------------------------------------------------------------------------
// Small scanners
// ---------------------------------------------------------------------------

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn contains_any(hay: &[u8], needles: &[String]) -> bool {
    needles
        .iter()
        .any(|n| memchr::memmem::find(hay, n.as_bytes()).is_some())
}

/// Offsets just past the `(` of every **bare call** to `needle` (which ends in
/// `(`): not the tail of a longer identifier, not a method/static call, not a
/// function definition.
fn bare_calls(low: &[u8], needle: &str) -> Vec<usize> {
    memchr::memmem::find_iter(low, needle.as_bytes())
        .filter(|&off| {
            if let Some(&prev) = off.checked_sub(1).and_then(|i| low.get(i)) {
                // `WP_Filesystem(`, `$o->exec(`, `Foo::exec(`, `$exec(`.
                if is_ident(prev) || matches!(prev, b'>' | b':' | b'$') {
                    return false;
                }
            }
            // `function exec(` declares, it does not call.
            let before = &low[off.saturating_sub(9)..off];
            !before.ends_with(b"function ")
        })
        .map(|off| off + needle.len())
        .collect()
}

/// The argument text of a call: from just after `(` to the end of the
/// statement (`;`) or 240 bytes, whichever comes first.
fn args_window(low: &[u8], start: usize) -> &[u8] {
    let end = (start + 240).min(low.len());
    let w = &low[start..end];
    match memchr::memchr(b';', w) {
        Some(i) => &w[..i],
        None => w,
    }
}

/// Names of variables assigned directly from request input
/// (`$cmd = $_GET['c'];`). Capped so a hostile file cannot make this expensive.
fn tainted_vars(low: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while let Some(rel) = memchr::memchr(b'$', &low[i..]) {
        let start = i + rel + 1;
        let mut j = start;
        while j < low.len() && is_ident(low[j]) {
            j += 1;
        }
        i = j.max(start);
        if j == start {
            continue;
        }
        let mut k = j;
        while k < low.len() && matches!(low[k], b' ' | b'\t') {
            k += 1;
        }
        // A plain `=`: not `==`, `===`, `=>`.
        if low.get(k) != Some(&b'=') || matches!(low.get(k + 1), Some(b'=' | b'>')) {
            continue;
        }
        let name = &low[start..j];
        if assigned_from_input(&low[k + 1..(k + 201).min(low.len())])
            && !out.iter().any(|n| n == name)
        {
            out.push(name.to_vec());
            if out.len() >= 64 {
                break;
            }
        }
    }
    out
}

/// Native PHP functions that merely tidy or decode a value, so the result is
/// still the attacker's data. Sanitizers (`intval`, `sanitize_*`, `esc_*`) are
/// deliberately absent: a sanitized value is not a command.
const PASS_THROUGH: &[&[u8]] = &[
    b"trim",
    b"ltrim",
    b"rtrim",
    b"stripslashes",
    b"urldecode",
    b"rawurldecode",
    b"base64_decode",
    b"strval",
    b"hex2bin",
    b"gzinflate",
    b"str_rot13",
    b"strrev",
    b"html_entity_decode",
    b"htmlspecialchars_decode",
];

/// Does the right-hand side of an assignment *begin with* request input, bare or
/// through a pass-through function: `$_GET['c']`, `trim($_POST['c'])`? Starting
/// with is the point: `isset($_GET['x']) ? 1 : 2` is a check, not a hand-over.
fn assigned_from_input(rhs: &[u8]) -> bool {
    let skip = |s: &[u8]| -> usize {
        s.iter()
            .take_while(|b| matches!(**b, b' ' | b'\t' | b'@'))
            .count()
    };
    let rhs = &rhs[skip(rhs)..];
    let starts_with_source = |s: &[u8]| SOURCES.iter().any(|n| s.starts_with(n.as_bytes()));
    if starts_with_source(rhs) {
        return true;
    }
    let name_len = rhs.iter().take_while(|&&b| is_ident(b)).count();
    if name_len == 0 || rhs.get(name_len) != Some(&b'(') {
        return false;
    }
    if !PASS_THROUGH.contains(&&rhs[..name_len]) {
        return false;
    }
    let inner = &rhs[name_len + 1..];
    starts_with_source(&inner[skip(inner)..])
}

/// Does an argument use one of the tainted variables as a *value*? A variable
/// used as an array key (`$registry[ $name ]`) is a lookup in a fixed table, not
/// a hand-over, so it does not count.
fn has_tainted(args: &[u8], tainted: &[Vec<u8>]) -> bool {
    tainted.iter().any(|name| {
        let mut pat = Vec::with_capacity(name.len() + 1);
        pat.push(b'$');
        pat.extend_from_slice(name);
        memchr::memmem::find_iter(args, &pat).any(|p| {
            if args.get(p + pat.len()).is_some_and(|&b| is_ident(b)) {
                return false; // `$cmdline` is not `$cmd`
            }
            let before = args[..p].iter().rev().find(|b| !b.is_ascii_whitespace());
            before != Some(&b'[')
        })
    })
}

/// `$_POST['f'](...)`: request input used as the *name of the function to call*.
fn input_called_as_function(low: &[u8]) -> Option<usize> {
    for src in SOURCES.iter().filter(|x| x.starts_with("$_")) {
        for off in memchr::memmem::find_iter(low, src.as_bytes()) {
            let from = off + src.len();
            let tail = &low[from..(from + 40).min(low.len())];
            let Some(close) = memchr::memchr(b']', tail) else {
                continue;
            };
            // The bracket holds a plain key: no calls, no statements.
            if tail[..close]
                .iter()
                .any(|b| matches!(b, b'(' | b')' | b';'))
            {
                continue;
            }
            let mut k = close + 1;
            while k < tail.len() && tail[k] == b' ' {
                k += 1;
            }
            if tail.get(k) == Some(&b'(') {
                return Some(off);
            }
        }
    }
    None
}

/// `preg_replace` whose pattern carries the `e` modifier (evaluates the
/// replacement as code). Only a real pattern string counts: not
/// `preg_replace_callback(`, and not the letters `/e` somewhere in a name.
fn preg_replace_e(low: &[u8]) -> Option<usize> {
    let check = |after: usize| -> Option<bool> {
        let mut i = after;
        while low.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        let quote = *low.get(i)?;
        if quote != b'\'' && quote != b'"' {
            return Some(false);
        }
        i += 1;
        let window = &low[i..(i + 200).min(low.len())];
        let end = window.iter().position(|&b| b == quote)?;
        let pat = &window[..end];
        let delim = *pat.first()?;
        if delim.is_ascii_alphanumeric() {
            return Some(false);
        }
        let last = pat.iter().rposition(|&b| b == delim)?;
        if last == 0 {
            return Some(false);
        }
        let mods = &pat[last + 1..];
        Some(mods.contains(&b'e') && mods.iter().all(u8::is_ascii_alphabetic))
    };
    bare_calls(low, "preg_replace(")
        .into_iter()
        .find(|&after| check(after) == Some(true))
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Score a PHP file's bytes. `is_upload` / `is_image_ext` raise weights for
/// code found where it should never be.
#[must_use]
pub fn score_php(content: &[u8], is_upload: bool, is_image_ext: bool) -> Score {
    // Case-insensitive detection copy; context is taken from the original.
    let low: Vec<u8> = content.iter().map(u8::to_ascii_lowercase).collect();
    let mut hits: Vec<Hit> = Vec::new();
    let mut score: u32 = 0;
    let mut strong_offset: Option<usize> = None;
    let mut add = |rule: &'static str, weight: u32, offset: Option<usize>| {
        score += weight;
        hits.push(Hit { rule, weight });
        if let (Some(off), None) = (offset, strong_offset) {
            strong_offset = Some(off);
        }
    };

    let is_encoder = ENCODERS
        .iter()
        .any(|e| memchr::memmem::find(&low, e.as_bytes()).is_some());

    // 1) Request input passed straight into a code/command call.
    let tainted = tainted_vars(&low);
    let mut direct: Option<usize> = None;
    let mut via_var: Option<usize> = None;
    for sink in SINKS.iter() {
        // For call_user_func*, only the FIRST argument (the function to run)
        // matters; the rest is data handed to a callback, which legitimate code
        // does with form values all the time.
        let callback_style = sink.starts_with("call_user_");
        for after in bare_calls(&low, sink) {
            let mut args = args_window(&low, after);
            if callback_style && let Some(comma) = memchr::memchr(b',', args) {
                args = &args[..comma];
            }
            if direct.is_none() && contains_any(args, &SOURCES) {
                direct = Some(after);
            } else if via_var.is_none() && has_tainted(args, &tainted) {
                via_var = Some(after);
            }
        }
    }
    if let Some(off) = direct {
        add("source-to-sink", 100, Some(off));
    } else if let Some(off) = via_var {
        // Probably a shell, but legitimate code does this too (a backup plugin
        // running a command built from a form field). On its own it lands at
        // "suspicious": reported for a human, never auto-quarantined.
        add("tainted-to-sink", 70, Some(off));
    }

    // 2) `$_POST['f'](...)`: the request chooses which function runs.
    if let Some(off) = input_called_as_function(&low) {
        add("input-as-function", 100, Some(off));
    }

    // 3) Decoders feeding eval/assert: the classic packed web shell.
    for sink in [s(&["ev", "al("]), s(&["ass", "ert("])] {
        for after in bare_calls(&low, &sink) {
            let win = &low[after..(after + 200).min(low.len())];
            let n = DECODERS
                .iter()
                .filter(|d| memchr::memmem::find(win, d.as_bytes()).is_some())
                .count();
            if n >= 1 {
                add(
                    "decode-into-eval",
                    if n >= 2 { 80 } else { 60 },
                    Some(after),
                );
                break;
            }
        }
    }

    // 4) preg_replace with the e modifier.
    if let Some(off) = preg_replace_e(&low) {
        add("preg_replace-e", 60, Some(off));
    }

    // 5) A bare command call is weak evidence on its own.
    if COMMAND_SINKS
        .iter()
        .any(|n| !bare_calls(&low, n).is_empty())
    {
        add("command-sink", 20, None);
    }

    // 6) Dropper / uploader: writes request data or fetched content to disk.
    let fetch_single = s(&["file_get_contents('", "http"]);
    let fetch_double = s(&["file_get_contents(\"", "http"]);
    for name in [
        s(&["move_", "uploaded_file("]),
        s(&["file_put_", "contents("]),
        s(&["fw", "rite("]),
    ] {
        let Some(after) = bare_calls(&low, &name).first().copied() else {
            continue;
        };
        if memchr::memmem::find(&low, fetch_single.as_bytes()).is_some()
            || memchr::memmem::find(&low, fetch_double.as_bytes()).is_some()
            || contains_any(args_window(&low, after), &SOURCES)
        {
            add("dropper", 40, Some(after));
            break;
        }
    }

    // 7) Variable-variable built from string pieces: ${'_PO'.'ST'}.
    if memchr::memmem::find(&low, b"${'").is_some() || memchr::memmem::find(&low, b"${\"").is_some()
    {
        add("obfuscated-variable", 20, None);
    }

    if !is_encoder {
        // 8) A long base64 blob in a small file.
        if let Some(off) = longest_b64_run(content) {
            let run = base64_run_len(content, off);
            if run > 512 {
                add(
                    "long-base64",
                    if content.len() < 20_000 { 30 } else { 15 },
                    Some(off),
                );
            }
        }
        // 9) Entropy of a long string literal.
        if high_entropy_literal(content) {
            add("high-entropy-literal", 25, None);
        }
    }

    // 10) Placement: code where only media should be.
    if is_image_ext {
        add("php-in-image-ext", 50, None);
    }
    if is_upload {
        add("php-in-uploads", 40, None);
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
    fn cat(parts: &[&str]) -> Vec<u8> {
        parts.concat().into_bytes()
    }
    fn verdict(src: &[u8]) -> Verdict {
        score_php(src, false, false).verdict
    }

    // ---- things that must be caught ------------------------------------

    #[test]
    fn classic_one_line_shell_is_malicious() {
        let src = cat(&["<?php ", "sys", "tem(", "$_", "GET['c']); ?>"]);
        let s = score_php(&src, false, false);
        assert_eq!(s.verdict, Verdict::Malicious, "hits={:?}", s.hits);
    }

    #[test]
    fn eval_of_decoded_input_is_malicious() {
        let src = cat(&[
            "<?php ",
            "ev",
            "al(",
            "base64_",
            "decode(",
            "$_",
            "POST['x'])); ",
        ]);
        assert_eq!(verdict(&src), Verdict::Malicious);
    }

    #[test]
    fn input_chosen_as_the_function_name_is_malicious() {
        // The request supplies both the function and its argument.
        let src = cat(&["<?php ", "$_", "POST['f'](", "$_", "POST['a']); ?>"]);
        let s = score_php(&src, false, false);
        assert_eq!(s.verdict, Verdict::Malicious, "hits={:?}", s.hits);
        assert!(s.hits.iter().any(|h| h.rule == "input-as-function"));
    }

    #[test]
    fn input_via_a_variable_is_suspicious_but_not_auto_cleanable() {
        let src = cat(&["<?php $c = ", "$_", "GET['c']; ", "sys", "tem($c);"]);
        let s = score_php(&src, false, false);
        assert_eq!(s.verdict, Verdict::Suspicious, "hits={:?}", s.hits);
        assert!(s.hits.iter().any(|h| h.rule == "tainted-to-sink"));
    }

    #[test]
    fn preg_replace_with_the_e_modifier_is_flagged() {
        let src = cat(&["<?php ", "preg_replace('/.*/e', ", "$_", "POST['x'], '');"]);
        assert!(
            score_php(&src, false, false)
                .hits
                .iter()
                .any(|h| h.rule == "preg_replace-e")
        );
    }

    #[test]
    fn php_in_uploads_raises_the_score() {
        let src = cat(&["<?php echo 'hi'; @include(", "$_", "REQUEST['f']);"]);
        let base = score_php(&src, false, false).score;
        let upload = score_php(&src, true, false).score;
        assert!(upload > base);
    }

    // ---- false positives seen on real WordPress/WooCommerce/Elementor code --

    #[test]
    fn wordpress_callback_dispatch_next_to_a_post_check_is_clean() {
        // The pattern that flagged wp-admin/includes/ajax-actions.php: a callback
        // registry called with call_user_func_array, and $_POST nearby.
        let src = br#"<?php
		ob_start();
			call_user_func_array( $control['callback'], $control['params'] );
		ob_end_clean();
		break;
	}
	if ( isset( $_POST['sidebar'] ) ) { $x = sanitize_text_field( $_POST['sidebar'] ); }
"#;
        assert_eq!(verdict(src), Verdict::Clean);
    }

    #[test]
    fn only_the_function_to_call_matters_for_call_user_func() {
        // WooCommerce: a value read from the form is passed to a registered
        // callback as DATA. Legitimate.
        let data = cat(&[
            "<?php $value = $_",
            "POST['v']; call_user_func( $field['update_callback'], $field['id'], $value );",
        ]);
        assert_eq!(verdict(&data), Verdict::Clean);
        // ...but when the request names the function to run, it is a shell.
        let shell = cat(&["<?php call_user_", "func(", "$_", "GET['f'], 1);"]);
        assert_eq!(verdict(&shell), Verdict::Malicious);
        let via_var = cat(&["<?php $f = $_", "GET['f']; call_user_", "func($f, 1);"]);
        assert_eq!(verdict(&via_var), Verdict::Suspicious);
    }

    #[test]
    fn a_tainted_variable_used_as_a_table_key_is_clean() {
        // WordPress/Elementor: the request picks an entry of a registered table.
        let src = cat(&[
            "<?php $name = $_",
            "GET['import']; call_user_func( $registry[ $name ][2] );",
        ]);
        assert_eq!(verdict(&src), Verdict::Clean);
    }

    #[test]
    fn taint_follows_simple_wrappers_and_indexing_of_the_tainted_array() {
        let wrapped = cat(&["<?php $c = trim($_", "POST['c']); ", "sys", "tem($c);"]);
        assert_eq!(verdict(&wrapped), Verdict::Suspicious);
        let whole = cat(&["<?php $d = $_", "POST; ", "sys", "tem($d['cmd']);"]);
        assert_eq!(verdict(&whole), Verdict::Suspicious);
    }

    #[test]
    fn a_check_or_sanitized_value_does_not_taint() {
        // `isset(...) ? ..` is a test, `intval(...)` is a number.
        let check = cat(&[
            "<?php $v = isset($_",
            "GET['x']) ? 1 : 2; call_user_func( $v );",
        ]);
        assert_eq!(verdict(&check), Verdict::Clean);
        let num = cat(&["<?php $n = intval($_", "GET['n']); ", "sys", "tem($n);"]);
        assert_eq!(verdict(&num), Verdict::Clean);
    }

    #[test]
    fn wp_filesystem_is_not_the_system_call() {
        let src = cat(&[
            "<?php if ( ! WP_Filesystem( $credentials ) ) { ",
            "$h = $_",
            "POST['hostname']; request_filesystem_credentials( $url ); }",
        ]);
        assert_eq!(verdict(&src), Verdict::Clean);
    }

    #[test]
    fn method_calls_are_not_sinks() {
        let src = cat(&["<?php $pdo->", "ex", "ec($sql); $v = $_", "POST['a'];"]);
        assert_eq!(verdict(&src), Verdict::Clean);
        let src = cat(&["<?php Foo::", "sys", "tem($_", "GET['x']);"]);
        assert_eq!(verdict(&src), Verdict::Clean);
    }

    #[test]
    fn a_function_definition_is_not_a_call() {
        let src = cat(&[
            "<?php function ",
            "ex",
            "ec($cmd) { return $_",
            "GET['a']; }",
        ]);
        assert_eq!(verdict(&src), Verdict::Clean);
    }

    #[test]
    fn preg_replace_callback_and_plain_modifiers_are_clean() {
        let cb = br#"<?php $x = preg_replace_callback( '/ELEMENTOR_([A-Z]+)/', function ( $m ) { return $m[1]; }, $css );"#;
        assert_eq!(verdict(cb), Verdict::Clean);
        let plain = br#"<?php $x = preg_replace( '/foo/i', 'bar', $s ); // the old preg_replace(//e) form is gone"#;
        assert_eq!(verdict(plain), Verdict::Clean);
    }

    #[test]
    fn backticks_in_comments_are_clean() {
        let src = b"<?php\n/**\n * Quotes `$text` and also `$other`.\n */\nfunction f() {}\n";
        assert_eq!(verdict(src), Verdict::Clean);
    }

    #[test]
    fn request_input_in_ordinary_code_is_clean() {
        let src = br#"<?php
		if ( isset( $_POST['action'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'save' ) ) {
			update_option( 'name', sanitize_text_field( $_POST['name'] ) );
			wp_redirect( add_query_arg( 'saved', 1, $_SERVER['REQUEST_URI'] ) );
		}"#;
        assert_eq!(verdict(src), Verdict::Clean);
    }

    #[test]
    fn plain_wordpress_theme_code_is_clean() {
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
    fn commercial_encoders_are_their_own_class() {
        let src = cat(&["<?php //ionCube Loader\n", "$data = 'AAAA';"]);
        // No decode/eval rules fire, so this is not malicious either way.
        assert_ne!(verdict(&src), Verdict::Malicious);
    }
}
