//! `sn remediate` — carry out the short list of actions a hub (an operator, or an
//! AI the operator approved) ordered about an incident.
//!
//! The list is closed (`snsec_common::schema::Action`) and every action is
//! checked twice before it runs: against the evidence this agent collected itself
//! (`snsec_common::ai::ground`, the same rules the hub applied) and against the
//! live system (the process still has that start time, the line still has that
//! hash, the file is still a regular file owned by that user). A file is edited
//! through a descriptor opened with `O_NOFOLLOW`, so a symlink swapped in by the
//! account being cleaned cannot redirect a root write.
//!
//! Everything but a kill can be undone (`sn undo`): the shell is restored, the
//! edited file is put back from its backup, the service is re-enabled, and a
//! quarantined file comes back with `sn restore <id>`.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use snsec_common::ai;
use snsec_common::schema::{Action, ActionResult, Evidence, RemediationReport};

use crate::config::Config;

use crate::evidence;
use crate::evidence_parse::{is_safe_username, line_sha};
use crate::state::State;
use crate::sys::proc;
use crate::undo::{self, UndoOp};
use crate::util;

/// Evidence older than this is not a safe basis for acting.
const MAX_EVIDENCE_AGE_SECS: i64 = 2 * 3600;
/// Largest start-up file that is edited.
const RC_MAX_BYTES: u64 = 256 * 1024;
/// Shells that mean "cannot log in", best first.
const LOCKED_SHELLS: &[&str] = &["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"];

/// A job id is used in a file name: keep it plain.
#[must_use]
pub fn is_valid_job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

pub fn job_path(state: &State, id: &str) -> PathBuf {
    state.dir.join(format!("remediate-{id}.json"))
}

pub fn result_path(state: &State) -> PathBuf {
    state.dir.join("remediation-latest.json")
}

/// The outcome of the last job, for the next report.
pub fn latest_result(state: &State) -> Option<RemediationReport> {
    std::fs::read(result_path(state))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// `sn remediate --job <id>`: run the job file the agent wrote when it received
/// the order, then remove the file.
pub fn run_job(cfg: &Config, state: &State, id: &str) -> Result<()> {
    if !cfg.remote.hub_orders {
        bail!("hub orders are off on this VPS ([remote] hub_orders = false)");
    }
    if !is_valid_job_id(id) {
        bail!("invalid job id");
    }
    let path = job_path(state, id);
    let actions: Vec<Action> = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .context("parsing the job file")?;
    let report = execute(state, id, &actions);
    let _ = std::fs::remove_file(&path);
    for r in &report.results {
        println!(
            "{} #{}: {}",
            if r.ok { "ok  " } else { "FAIL" },
            r.index,
            r.message
        );
    }
    Ok(())
}

/// Carry out `actions` and record the result. Never panics on bad input: every
/// problem becomes a failed [`ActionResult`].
pub fn execute(state: &State, id: &str, actions: &[Action]) -> RemediationReport {
    let now = util::now_secs();
    let mut report = RemediationReport {
        id: id.to_string(),
        at: now,
        results: Vec::new(),
    };
    let evidence = evidence::latest(state);
    for (i, action) in actions.iter().take(ai::MAX_ACTIONS).enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let outcome = match &evidence {
            None => Err("chưa có bằng chứng do agent tự thu thập".to_string()),
            Some(ev) if now - ev.at > MAX_EVIDENCE_AGE_SECS => {
                Err("bằng chứng đã cũ (quá 2 giờ), cần thu thập lại".to_string())
            }
            Some(ev) => ai::ground(action, ev)
                .map_err(|e| format!("agent từ chối: {e}"))
                .and_then(|_| apply(state, action, ev).map_err(|e| format!("{e:#}"))),
        };
        report.results.push(match outcome {
            Ok(message) => ActionResult {
                index,
                ok: true,
                message,
            },
            Err(message) => ActionResult {
                index,
                ok: false,
                message: util::ellipsize(&crate::clamav::clean_text(&message), 300),
            },
        });
        // After every action, not only at the end: if the unit is stopped part
        // way (time limit, a hung action) the hub still learns what was done.
        save_result(state, &report);
    }
    save_result(state, &report);
    report
}

fn save_result(state: &State, report: &RemediationReport) {
    if let Ok(bytes) = serde_json::to_vec_pretty(report) {
        let _ = std::fs::write(result_path(state), bytes);
    }
}

fn apply(state: &State, action: &Action, ev: &Evidence) -> Result<String> {
    match action {
        Action::KillProcess { pid, starttime } => kill_process(*pid, *starttime),
        Action::KillMatching { user, exe } => kill_matching(user, exe),
        Action::LockUserShell { user } => lock_user_shell(state, user),
        Action::QuarantineFile { path } => {
            // The owner the evidence recorded: a file that has since been replaced
            // by someone else's is refused.
            let owner = ev
                .temp_files
                .iter()
                .find(|f| f.path == *path)
                .and_then(|f| nix::unistd::User::from_name(&f.owner).ok().flatten())
                .map(|u| u.uid.as_raw());
            let id = crate::clean::quarantine_safe(state, Path::new(path), owner)?;
            Ok(format!("đã cách ly {path} (khôi phục: sn restore {id})"))
        }
        Action::RemoveShellLine {
            path,
            line_no,
            sha256,
        } => remove_shell_line(state, ev, path, *line_no, sha256),
        Action::DisableService { unit } => disable_service(state, unit),
    }
}

// ---------------------------------------------------------------------------
// The actions
// ---------------------------------------------------------------------------

/// Why a process must not be killed here, if so: pid 1, the agent itself, or the
/// system's own service of that name. A process that merely *wears* a service
/// name (perl called `httpd`) is not protected by it.
fn protected(pid: i32, comm: &str, exe: &str) -> Option<&'static str> {
    if pid <= 1 {
        Some("init")
    } else if pid == std::process::id() as i32 {
        Some("chính agent")
    } else if ai::is_genuine_service(comm, exe) {
        Some("dịch vụ hệ thống")
    } else {
        None
    }
}

fn kill_process(pid: i32, starttime: u64) -> Result<String> {
    let Some(st) = proc::read_stat(pid) else {
        bail!("tiến trình {pid} đã thoát (mã độc có thể tự khởi động lại: dùng kill_matching)");
    };
    if st.starttime != starttime {
        bail!("pid {pid} nay là một tiến trình khác (đã bị dùng lại)");
    }
    let (exe, _deleted) = proc::exe(pid);
    if let Some(why) = protected(pid, &st.comm, &exe) {
        bail!("không dừng pid {pid} ({}): {why}", st.comm);
    }
    kill(Pid::from_raw(pid), Signal::SIGKILL).with_context(|| format!("kill {pid}"))?;
    Ok(format!("đã dừng pid {pid} ({}, {exe})", st.comm))
}

/// Most processes one `kill_matching` will stop.
const MAX_KILL_MATCHING: usize = 200;

/// Stop every live process of `user` running `exe` that is disguised *right now*
/// (a kernel-thread name on a real program, a temp or hidden executable, or a
/// miner marker in its command line). The pid in the evidence is not needed: the
/// pattern is what matters for malware that respawns.
fn kill_matching(user: &str, exe: &str) -> Result<String> {
    if !is_safe_username(user) {
        bail!("tên tài khoản không hợp lệ");
    }
    let uid = nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .with_context(|| format!("không tìm thấy tài khoản {user}"))?
        .uid
        .as_raw();
    let mut killed: Vec<i32> = Vec::new();
    let mut spared = 0usize;
    for pid in proc::list_pids() {
        if proc::uid(pid) != Some(uid) {
            continue;
        }
        let Some(st) = proc::read_stat(pid) else {
            continue;
        };
        let (pexe, _deleted) = proc::exe(pid);
        if pexe != exe {
            continue;
        }
        let cmd = proc::cmdline(pid).join(" ").to_ascii_lowercase();
        let miner = crate::triage::MINER_HINTS.iter().any(|h| cmd.contains(h));
        let disguised =
            (crate::evidence_parse::looks_like_kthread(&st.comm) && st.ppid != 2 && pid != 2)
                || miner
                || pexe.starts_with("/dev/shm/")
                || pexe.starts_with("/tmp/")
                || pexe.starts_with("/var/tmp/");
        if !disguised {
            spared += 1;
            continue;
        }
        if protected(pid, &st.comm, &pexe).is_some() {
            spared += 1;
            continue;
        }
        if killed.len() >= MAX_KILL_MATCHING {
            break;
        }
        if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
            killed.push(pid);
        }
    }
    Ok(if killed.is_empty() {
        format!(
            "không còn tiến trình nào của {user} chạy {exe} đang giả danh (đã thoát hoặc đã bị dừng); {spared} tiến trình khác của chương trình này được giữ nguyên"
        )
    } else {
        format!(
            "đã dừng {} tiến trình của {user} chạy {exe} (pid {}); {spared} tiến trình khác được giữ nguyên",
            killed.len(),
            killed
                .iter()
                .take(10)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// The current login shell of `user` from `/etc/passwd`.
fn current_shell(user: &str) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7 && f[0] == user).then(|| f[6].trim().to_string())
        })
}

fn lock_user_shell(state: &State, user: &str) -> Result<String> {
    if !is_safe_username(user) {
        bail!("tên tài khoản không hợp lệ");
    }
    let Some(old) = current_shell(user) else {
        bail!("không tìm thấy tài khoản {user}");
    };
    // Re-checked on the live system: group membership may have changed since the
    // evidence was collected, and an administrator is never locked out here.
    let admins = crate::evidence_parse::admin_accounts(
        &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
        &std::fs::read_to_string("/etc/group").unwrap_or_default(),
    );
    if admins.contains(user) {
        bail!("{user} là tài khoản quản trị (sudo/wheel), không khoá tự động");
    }
    if LOCKED_SHELLS.contains(&old.as_str()) || old.ends_with("/nologin") || old.ends_with("/false")
    {
        return Ok(format!("{user} đã bị khoá shell từ trước ({old})"));
    }
    let Some(new) = LOCKED_SHELLS.iter().find(|s| Path::new(s).exists()) else {
        bail!("không có shell khoá (nologin/false) trên máy này");
    };
    let Some(usermod) = util::find_bin("usermod") else {
        bail!("không tìm thấy usermod");
    };
    let status = Command::new(usermod)
        .args(["-s", new, user])
        .stdin(Stdio::null())
        .status()
        .context("chạy usermod")?;
    if !status.success() {
        bail!("usermod kết thúc với {status}");
    }
    // Recorded after the change, so a failed change is not "undone".
    undo::record(
        &state.dir,
        &UndoOp::RestoreShell {
            user: user.to_string(),
            shell: old.clone(),
        },
    )?;
    Ok(format!("đã đổi shell của {user} từ {old} sang {new}"))
}

fn remove_shell_line(
    state: &State,
    ev: &Evidence,
    path: &str,
    line_no: u32,
    sha256: &str,
) -> Result<String> {
    // The account the file belongs to, from the evidence entry the action matched.
    let entry = ev
        .persistence
        .iter()
        .find(|p| p.kind == "shell_rc" && p.path == path && p.line_no == line_no)
        .context("không có mục bằng chứng tương ứng")?;
    let owner = nix::unistd::User::from_name(&entry.user)
        .ok()
        .flatten()
        .with_context(|| format!("không tìm thấy tài khoản {}", entry.user))?;
    // Only the account's own start-up file, directly in its home: the path must
    // be `<home>/<known name>`, with the home taken from the account list (or
    // /root), not from the model or the order.
    let home = if entry.user == "root" {
        "/root".to_string()
    } else {
        ev.shell_users
            .iter()
            .find(|u| u.name == entry.user)
            .map(|u| u.home.clone())
            .context("tài khoản không có trong danh sách bằng chứng")?
    };
    let name_ok = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| crate::evidence::RC_FILES.contains(&n));
    if Path::new(path).parent() != Some(Path::new(&home)) || !name_ok {
        bail!("{path} không phải file khởi động shell trực tiếp trong {home}");
    }

    // O_NOFOLLOW: if the last component was swapped for a symlink, this fails
    // instead of following it into some other file.
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("mở {path} (có thể đã bị đổi thành liên kết)"))?;
    let meta = f.metadata()?;
    if !meta.is_file() || meta.len() > RC_MAX_BYTES {
        bail!("{path} không phải file thường hoặc quá lớn");
    }
    if meta.uid() != owner.uid.as_raw() {
        bail!("{path} không thuộc về {}", entry.user);
    }
    let mut text = String::new();
    f.read_to_string(&mut text).context("đọc file")?;

    let idx = (line_no as usize)
        .checked_sub(1)
        .context("số dòng không hợp lệ")?;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let Some(target) = lines.get(idx) else {
        bail!("file không còn dòng {line_no}");
    };
    if line_sha(target) != sha256 {
        bail!("dòng {line_no} đã thay đổi so với bằng chứng, không sửa");
    }
    let new_text: String = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != idx)
        .map(|(_, l)| *l)
        .collect();

    // Back the original up first (root-only), so the edit can be undone.
    let dir = state.dir.join("rc-backups");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let base = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rc");
    // A name that cannot collide (two edits of one file in the same second must
    // not overwrite the first backup): created exclusively, retried with a counter.
    let stamp = util::ts_compact(util::now_secs());
    let mut n = 0u32;
    let backup = loop {
        let candidate = dir.join(format!("{stamp}-{n}-{}-{base}.bak", entry.user));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(mut bf) => {
                bf.write_all(text.as_bytes()).context("ghi bản sao lưu")?;
                break candidate;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => n += 1,
            Err(e) => return Err(e).context("tạo bản sao lưu"),
        }
    };

    // Same descriptor: rewrite in place, keeping owner and mode.
    f.set_len(0)?;
    f.seek(SeekFrom::Start(0))?;
    f.write_all(new_text.as_bytes())?;
    f.flush()?;

    undo::record(
        &state.dir,
        &UndoOp::RestoreFile {
            path: path.to_string(),
            backup: backup.to_string_lossy().to_string(),
            uid: owner.uid.as_raw(),
        },
    )?;
    Ok(format!(
        "đã gỡ dòng {line_no} khỏi {path} (bản sao lưu: {})",
        backup.display()
    ))
}

fn disable_service(state: &State, unit: &str) -> Result<String> {
    if !ai::ALLOWED_UNITS.contains(&unit) {
        bail!("{unit} không nằm trong danh sách cho phép");
    }
    let Some(sc) = util::find_bin("systemctl") else {
        bail!("không tìm thấy systemctl");
    };
    let status = Command::new(sc)
        .args(["disable", "--now", unit])
        .stdin(Stdio::null())
        .status()
        .context("chạy systemctl")?;
    if !status.success() {
        bail!("systemctl disable {unit} kết thúc với {status}");
    }
    undo::record(
        &state.dir,
        &UndoOp::EnableService {
            unit: unit.to_string(),
        },
    )?;
    Ok(format!("đã tắt và vô hiệu hoá {unit}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_ids_are_plain() {
        assert!(is_valid_job_id("a1-b_2"));
        for bad in ["", "../x", "a b", "a/b", &"a".repeat(41)] {
            assert!(!is_valid_job_id(bad), "{bad}");
        }
    }

    #[test]
    fn without_evidence_nothing_runs() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let r = execute(
            &state,
            "j1",
            &[Action::DisableService {
                unit: "rpcbind.service".into(),
            }],
        );
        assert_eq!(r.results.len(), 1);
        assert!(!r.results[0].ok);
        assert!(r.results[0].message.contains("bằng chứng"));
        // And the outcome is stored for the next report.
        assert_eq!(latest_result(&state).unwrap().id, "j1");
    }

    #[test]
    fn stale_evidence_is_not_a_basis_for_acting() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let ev = Evidence {
            at: util::now_secs() - 3 * 3600,
            ..Evidence::default()
        };
        std::fs::write(
            dir.path().join("evidence-latest.json"),
            serde_json::to_vec(&ev).unwrap(),
        )
        .unwrap();
        let r = execute(
            &state,
            "j2",
            &[Action::DisableService {
                unit: "rpcbind.service".into(),
            }],
        );
        assert!(!r.results[0].ok && r.results[0].message.contains("cũ"));
    }

    #[test]
    fn an_action_the_evidence_does_not_support_is_refused_by_the_agent_itself() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let ev = Evidence {
            at: util::now_secs(),
            ..Evidence::default()
        };
        std::fs::write(
            dir.path().join("evidence-latest.json"),
            serde_json::to_vec(&ev).unwrap(),
        )
        .unwrap();
        let r = execute(
            &state,
            "j3",
            &[
                Action::KillProcess {
                    pid: 4242,
                    starttime: 1,
                },
                Action::QuarantineFile {
                    path: "/etc/passwd".into(),
                },
            ],
        );
        assert!(r.results.iter().all(|x| !x.ok));
        assert!(r.results[0].message.contains("agent từ chối"));
    }

    #[test]
    fn the_number_of_actions_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::at(dir.path().to_path_buf());
        let many: Vec<Action> = (0..50)
            .map(|_| Action::DisableService {
                unit: "rpcbind.service".into(),
            })
            .collect();
        assert_eq!(execute(&state, "j4", &many).results.len(), ai::MAX_ACTIONS);
    }
}
