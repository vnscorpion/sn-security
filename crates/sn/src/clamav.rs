//! ClamAV integration, pure part: reading its output, merging its detections
//! with the heuristic findings, and choosing an install recipe for an OS. No
//! process is started and nothing touches the disk here, so all of it is tested
//! directly; `clamav_run` does the actual work.
//!
//! ClamAV is an optional second opinion. Its signatures know families of malware
//! the heuristic cannot name; the heuristic catches new variants no signature has
//! seen yet. They are reported side by side, never merged into one score blindly.
//!
//! Everything ClamAV prints is treated as untrusted text: a detection is only
//! accepted for a file we asked it to scan, and signature names are restricted to
//! a safe character set before they reach a report or a web page.

use serde::{Deserialize, Serialize};
use snsec_common::schema::Finding;

/// Detections kept per scan. A mass infection stops being useful as a list long
/// before this, and it bounds the report.
pub const MAX_DETECTIONS: usize = 1_000;
/// Longest signature name kept.
const SIG_MAX: usize = 80;
/// Stands in for a signature name that is not a plain identifier.
pub const UNRECOGNIZED_SIG: &str = "Unrecognized.Signature";

// ---------------------------------------------------------------------------
// Reading ClamAV's output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub path: String,
    pub sig: String,
}

/// A signature name is `Family.Type.Name-123`: letters, digits and `._-+/`.
/// Anything else (a hostile or garbled line) is refused rather than cleaned.
#[must_use]
pub fn sanitize_sig(sig: &str) -> Option<String> {
    let ok = !sig.is_empty()
        && sig.chars().count() <= SIG_MAX
        && sig
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/'));
    ok.then(|| sig.to_string())
}

/// How much to trust a signature: ClamAV's own heuristics and "potentially
/// unwanted application" signatures are weaker evidence than a named family.
/// Returns `(verdict, score)` on the same scale as the heuristic scorer.
#[must_use]
pub fn verdict_for(sig: &str) -> (&'static str, u32) {
    if sig.starts_with("Heuristics.") || sig.starts_with("PUA.") || sig == UNRECOGNIZED_SIG {
        ("suspicious", 70)
    } else {
        ("malicious", 100)
    }
}

fn rank(verdict: &str) -> u8 {
    match verdict {
        "malicious" => 3,
        "suspicious" => 2,
        _ => 1,
    }
}

/// Fold ClamAV's detections into the heuristic findings. A file both found
/// keeps the heuristic's evidence and gains the ClamAV rule (and a stronger
/// verdict if ClamAV's is stronger); a file only ClamAV found becomes a finding
/// of its own. `sha_of` supplies the hash for those.
pub fn merge(
    findings: &mut Vec<Finding>,
    detections: &[Detection],
    mut sha_of: impl FnMut(&str) -> String,
) {
    for d in detections {
        let rule = format!("clamav:{}", d.sig);
        let (verdict, score) = verdict_for(&d.sig);
        if let Some(f) = findings.iter_mut().find(|f| f.path == d.path) {
            if !f.rules.contains(&rule) {
                f.rules.push(rule);
            }
            if rank(verdict) > rank(&f.verdict) {
                f.verdict = verdict.to_string();
            }
            f.score = f.score.max(score);
            if !f.context.starts_with("ClamAV:") {
                f.context = format!("ClamAV: {}; {}", d.sig, f.context);
            }
        } else {
            findings.push(Finding {
                path: d.path.clone(),
                score,
                verdict: verdict.to_string(),
                rules: vec![rule],
                context: format!("ClamAV: {}", d.sig),
                sha256: sha_of(&d.path),
            });
        }
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.score));
}

/// Text from a child process, made safe to put in a report: control characters
/// (terminal escapes, NULs, stray newlines) become spaces.
#[must_use]
pub fn clean_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Last `n` non-empty lines of a log, for a short failure message. Control
/// characters inside the lines are neutralised (see [`clean_text`]).
#[must_use]
pub fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .map(|l| clean_text(l).trim().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Installing ClamAV
// ---------------------------------------------------------------------------

/// Outcome of the last install attempt, kept in the state directory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallState {
    pub at: i64,
    /// `running`, `ok` or `failed`.
    pub state: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Run a program. `argv[0]` is a bare name, resolved from fixed system
    /// directories (never `PATH`). An `optional` step may fail without failing
    /// the install.
    Run {
        argv: Vec<String>,
        optional: bool,
        timeout_secs: u64,
    },
    /// RPM packages ship `/etc/freshclam.conf` with an `Example` line that makes
    /// freshclam refuse to run until it is commented out.
    CommentExample(&'static str),
    /// Wait for the signature database to appear (Debian's service downloads it
    /// right after the package is installed).
    WaitDb,
    /// A daily signature update timer, for systems whose package has none.
    UpdateTimer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Short name of the recipe, for messages.
    pub label: String,
    pub steps: Vec<Step>,
}

/// Install steps are long: a package manager and then a database download.
const PKG_TIMEOUT: u64 = 20 * 60;
const DB_TIMEOUT: u64 = 30 * 60;

fn run(argv: &[&str], optional: bool, timeout_secs: u64) -> Step {
    Step::Run {
        argv: argv.iter().map(|s| (*s).to_string()).collect(),
        optional,
        timeout_secs,
    }
}

/// `KEY=value` lines of `/etc/os-release` as `(id, id_like)`, lower case.
#[must_use]
pub fn parse_os_release(text: &str) -> (String, Vec<String>) {
    let mut id = String::new();
    let mut like = Vec::new();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
        match k.trim() {
            "ID" => id = v,
            "ID_LIKE" => like = v.split_whitespace().map(str::to_string).collect(),
            _ => {}
        }
    }
    (id, like)
}

/// The install recipe for this OS, or the reason there is none.
///
/// Deliberately a short allow-list of systems whose ClamAV packaging is known:
/// a wrong guess would run package-manager commands as root on a production
/// server. `has` says whether a program exists (so dnf vs yum is not assumed).
///
/// # Errors
/// A message naming the OS when no recipe applies.
pub fn plan_for(os_release: &str, has: &dyn Fn(&str) -> bool) -> Result<Plan, String> {
    let (id, like) = parse_os_release(os_release);
    let is = |name: &str| id == name || like.iter().any(|l| l == name);
    let unsupported = || {
        format!(
            "Hệ điều hành “{}” chưa có công thức cài tự động (hỗ trợ: Debian, Ubuntu, AlmaLinux, Rocky, CentOS, Fedora). Hãy cài ClamAV thủ công.",
            if id.is_empty() { "không rõ" } else { &id }
        )
    };

    if is("debian") || is("ubuntu") {
        // No daemon: only the scanner and the signature updater the package
        // already runs. The daemon would keep ~1 GB of RAM in use around the clock.
        if !has("apt-get") {
            return Err("Không tìm thấy apt-get.".into());
        }
        return Ok(Plan {
            label: "Debian/Ubuntu (apt)".into(),
            steps: vec![
                run(
                    &["apt-get", "-o", "DPkg::Lock::Timeout=600", "update"],
                    true,
                    PKG_TIMEOUT,
                ),
                // Wait (up to 10 min) for another apt run such as
                // unattended-upgrades instead of failing at once, and keep the
                // admin's own config files if a prompt would have come up.
                run(
                    &[
                        "apt-get",
                        "-o",
                        "DPkg::Lock::Timeout=600",
                        "-o",
                        "Dpkg::Options::=--force-confold",
                        "-o",
                        "Dpkg::Options::=--force-confdef",
                        "install",
                        "-y",
                        "--no-install-recommends",
                        "clamav",
                    ],
                    false,
                    PKG_TIMEOUT,
                ),
                run(
                    &["systemctl", "enable", "--now", "clamav-freshclam"],
                    true,
                    120,
                ),
                Step::WaitDb,
            ],
        });
    }

    let rpm_ok = matches!(id.as_str(), "almalinux" | "rocky" | "centos" | "fedora");
    if rpm_ok {
        let pm = if has("dnf") {
            "dnf"
        } else if has("yum") {
            "yum"
        } else {
            return Err("Không tìm thấy dnf hoặc yum.".into());
        };
        let mut steps = Vec::new();
        // ClamAV is in EPEL on the RHEL family; Fedora has it in its own repos.
        if id != "fedora" {
            steps.push(run(
                &[pm, "install", "-y", "epel-release"],
                false,
                PKG_TIMEOUT,
            ));
        }
        steps.push(run(
            &[pm, "install", "-y", "clamav", "clamav-update"],
            false,
            PKG_TIMEOUT,
        ));
        steps.push(Step::CommentExample("/etc/freshclam.conf"));
        steps.push(run(&["freshclam"], false, DB_TIMEOUT));
        steps.push(Step::UpdateTimer);
        return Ok(Plan {
            label: format!("{id} ({pm})"),
            steps,
        });
    }

    Err(unsupported())
}

/// `text` with every bare `Example` line commented out, or `None` when there was
/// none (already fixed, or a package that does not have it).
#[must_use]
pub fn comment_example(text: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len() + 8);
    for line in text.split_inclusive('\n') {
        if line.trim() == "Example" {
            out.push_str("# ");
            changed = true;
        }
        out.push_str(line);
    }
    changed.then_some(out)
}

/// The systemd service and timer that update the signatures daily.
/// `freshclam` is an absolute path chosen by us, never user input.
#[must_use]
pub fn update_units(freshclam: &str) -> (String, String) {
    let service = format!(
        "[Unit]\nDescription=SN Secure: update ClamAV signatures\n\n\
         [Service]\nType=oneshot\nExecStart={freshclam} --quiet\nNice=10\n\
         IOSchedulingClass=idle\nTimeoutStartSec=30min\n"
    );
    let timer = "[Unit]\nDescription=SN Secure: daily ClamAV signature update\n\n\
                 [Timer]\nOnCalendar=daily\nRandomizedDelaySec=2h\nPersistent=true\n\n\
                 [Install]\nWantedBy=timers.target\n"
        .to_string();
    (service, timer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_process_text_loses_its_control_characters() {
        assert_eq!(clean_text("a\u{1b}[31mb\0c\nd"), "a [31mb c d");
        assert_eq!(tail_lines("ok\n\u{1b}[2Jboom\n", 1), "[2Jboom");
    }

    #[test]
    fn heuristic_and_pua_signatures_are_only_suspicious() {
        assert_eq!(verdict_for("Php.Webshell.C99-7"), ("malicious", 100));
        assert_eq!(verdict_for("Heuristics.PHP.Obfuscated"), ("suspicious", 70));
        assert_eq!(verdict_for("PUA.Php.Tool"), ("suspicious", 70));
    }

    fn finding(path: &str, verdict: &str, score: u32) -> Finding {
        Finding {
            path: path.into(),
            score,
            verdict: verdict.into(),
            rules: vec!["dropper".into()],
            context: "ctx".into(),
            sha256: "h".into(),
        }
    }

    #[test]
    fn a_file_both_engines_found_keeps_both_kinds_of_evidence() {
        let mut f = vec![finding("/a.php", "suspicious", 75)];
        merge(
            &mut f,
            &[Detection {
                path: "/a.php".into(),
                sig: "Php.Webshell.X".into(),
            }],
            |_| unreachable!("hash already known"),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].verdict, "malicious");
        assert_eq!(f[0].score, 100);
        assert_eq!(f[0].rules, ["dropper", "clamav:Php.Webshell.X"]);
        assert!(f[0].context.starts_with("ClamAV: Php.Webshell.X; ctx"));
    }

    #[test]
    fn clamav_never_weakens_a_heuristic_verdict() {
        let mut f = vec![finding("/a.php", "malicious", 140)];
        merge(
            &mut f,
            &[Detection {
                path: "/a.php".into(),
                sig: "Heuristics.PHP.Weak".into(),
            }],
            |_| String::new(),
        );
        assert_eq!(f[0].verdict, "malicious");
        assert_eq!(f[0].score, 140);
    }

    #[test]
    fn a_file_only_clamav_found_becomes_a_finding_with_a_hash() {
        let mut f = vec![finding("/a.php", "suspicious", 75)];
        merge(
            &mut f,
            &[Detection {
                path: "/b.php".into(),
                sig: "Php.Trojan.Z".into(),
            }],
            |p| format!("sha-of-{p}"),
        );
        assert_eq!(f.len(), 2);
        // Strongest first.
        assert_eq!(f[0].path, "/b.php");
        assert_eq!(f[0].sha256, "sha-of-/b.php");
        assert_eq!(f[0].context, "ClamAV: Php.Trojan.Z");
        // Merging the same detection twice does not duplicate the rule.
        merge(
            &mut f,
            &[Detection {
                path: "/b.php".into(),
                sig: "Php.Trojan.Z".into(),
            }],
            |_| String::new(),
        );
        assert_eq!(f[0].rules.len(), 1);
    }

    #[test]
    fn os_release_is_read_with_or_without_quotes() {
        let (id, like) = parse_os_release(
            "NAME=\"AlmaLinux\"\nID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
        );
        assert_eq!(id, "almalinux");
        assert_eq!(like, ["rhel", "centos", "fedora"]);
        let (id, like) = parse_os_release("ID=ubuntu\nID_LIKE=debian\n");
        assert_eq!((id.as_str(), like.len()), ("ubuntu", 1));
    }

    fn has_all(_: &str) -> bool {
        true
    }

    #[test]
    fn debian_and_ubuntu_install_only_the_scanner() {
        for os in ["ID=ubuntu\nID_LIKE=debian\n", "ID=debian\n"] {
            let p = plan_for(os, &has_all).unwrap();
            let argvs: Vec<String> = p
                .steps
                .iter()
                .filter_map(|s| match s {
                    Step::Run { argv, .. } => Some(argv.join(" ")),
                    _ => None,
                })
                .collect();
            assert!(argvs.iter().any(|a| a.starts_with("apt-get ")
                && a.contains("DPkg::Lock::Timeout=")
                && a.ends_with("install -y --no-install-recommends clamav")));
            // No daemon package: it would hold ~1 GB of RAM permanently.
            assert!(argvs.iter().all(|a| !a.contains("clamav-daemon")));
            assert_eq!(p.steps.last(), Some(&Step::WaitDb));
        }
    }

    #[test]
    fn the_rhel_family_gets_epel_a_fixed_config_and_an_update_timer() {
        let p = plan_for(
            "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
            &has_all,
        )
        .unwrap();
        let first = &p.steps[0];
        assert_eq!(
            first,
            &Step::Run {
                argv: vec![
                    "dnf".into(),
                    "install".into(),
                    "-y".into(),
                    "epel-release".into()
                ],
                optional: false,
                timeout_secs: PKG_TIMEOUT
            }
        );
        assert!(
            p.steps
                .contains(&Step::CommentExample("/etc/freshclam.conf"))
        );
        assert_eq!(p.steps.last(), Some(&Step::UpdateTimer));
        // Fedora needs no EPEL; yum is used when dnf is absent.
        let f = plan_for("ID=fedora\n", &has_all).unwrap();
        assert!(!format!("{:?}", f.steps).contains("epel"));
        let y = plan_for("ID=centos\n", &|n| n == "yum").unwrap();
        assert!(format!("{:?}", y.steps).contains("\"yum\""));
    }

    #[test]
    fn other_systems_get_a_clear_refusal_not_a_guess() {
        let e = plan_for("ID=alpine\n", &has_all).unwrap_err();
        assert!(e.contains("alpine") && e.contains("thủ công"), "{e}");
        assert!(plan_for("", &has_all).is_err());
        // RHEL proper and Oracle need different repositories: not guessed.
        assert!(plan_for("ID=rhel\nID_LIKE=\"fedora\"\n", &has_all).is_err());
        assert!(plan_for("ID=ol\nID_LIKE=\"fedora\"\n", &has_all).is_err());
        // No package manager, no plan.
        assert!(plan_for("ID=ubuntu\n", &|_| false).is_err());
        assert!(plan_for("ID=rocky\n", &|_| false).is_err());
    }

    #[test]
    fn the_example_line_is_commented_out_and_only_that_line() {
        let conf = "# header\nExample\nDatabaseMirror x\n  Example  \nExampleKey 1\n";
        let fixed = comment_example(conf).unwrap();
        assert_eq!(
            fixed,
            "# header\n# Example\nDatabaseMirror x\n#   Example  \nExampleKey 1\n"
        );
        assert!(comment_example(&fixed).is_none());
        assert!(comment_example("DatabaseMirror x\n").is_none());
    }

    #[test]
    fn the_update_units_run_the_given_freshclam_daily() {
        let (svc, timer) = update_units("/usr/bin/freshclam");
        assert!(svc.contains("ExecStart=/usr/bin/freshclam --quiet"));
        assert!(timer.contains("OnCalendar=daily") && timer.contains("WantedBy=timers.target"));
    }

    #[test]
    fn the_tail_of_a_log_skips_blank_lines() {
        assert_eq!(tail_lines("a\n\nb\nc\n\n", 2), "b\nc");
        assert_eq!(tail_lines("", 3), "");
    }
}
