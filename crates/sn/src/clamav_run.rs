//! ClamAV integration, running part: find the engine, scan the files `sn hunt`
//! picked, and install ClamAV on request. The parsing, merging and per-OS recipes
//! are in `clamav` (pure, tested); this file starts the processes.
//!
//! * Programs are looked up in fixed system directories, never through `PATH`.
//! * Every process has a timeout, runs in its own process group, and the whole
//!   group is stopped when it runs over (apt-get -> dpkg -> maintainer scripts).
//! * Output goes to files in the state directory, never into memory unbounded.
//! * `clamdscan` (a running daemon) is preferred; otherwise `clamscan`, which
//!   loads the whole signature database, only when enough RAM is free.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, bail};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use snsec_common::schema::ClamavInfo;

use crate::clamav::{self, Detection, InstallState, Step};
use crate::config::{ClamavMode, Config};
use crate::state::State;
use crate::sys::proc;
use crate::util;

const BIN_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"];
const DB_DIR: &str = "/var/lib/clamav";
/// `clamscan` with the full database does not fit comfortably below this.
const MIN_INSTALL_RAM_MB: u64 = 1800;
/// The packages plus the three signature files need room under /var/lib.
const MIN_INSTALL_DISK_MB: u64 = 1500;
/// Files handed to one scan.
const MAX_LIST_FILES: usize = 200_000;
/// Scan output read back, at most.
const OUT_CAP: u64 = 8 * 1024 * 1024;
/// An install "running" for longer than this is taken to have died (the unit is
/// limited to 90 minutes, so a live one never gets here).
const STALE_INSTALL_SECS: i64 = 100 * 60;
/// How long to wait for the first signature download after installing.
const DB_WAIT_SECS: u64 = 15 * 60;
/// Less time than this left in a hunt's budget is not worth starting ClamAV for.
const MIN_SCAN_BUDGET_SECS: u64 = 120;
/// After SIGTERM, how long a timed-out process gets before SIGKILL.
const TERM_GRACE: Duration = Duration::from_secs(20);

/// An absolute path to `name` in a system directory, if it is installed.
pub fn find_bin(name: &str) -> Option<PathBuf> {
    BIN_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

fn newest_mtime(stem: &str, exts: &[&str]) -> Option<SystemTime> {
    exts.iter()
        .filter_map(|e| std::fs::metadata(Path::new(DB_DIR).join(format!("{stem}.{e}"))).ok())
        .filter(|m| m.len() > 0)
        .filter_map(|m| m.modified().ok())
        .max()
}

/// Hours since the signatures were last updated; `None` = no usable database.
///
/// Usable means both `main` and `daily` are present: a download that stopped
/// after `main` would otherwise look finished, and scans would run with a
/// database that is months out of date.
pub fn db_age_hours(now: i64) -> Option<u32> {
    newest_mtime("main", &["cvd", "cld"])?;
    let daily = newest_mtime("daily", &["cvd", "cld", "cud"])?;
    let mtime = daily
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)?;
    Some(u32::try_from(((now - mtime).max(0)) / 3600).unwrap_or(u32::MAX))
}

/// Run `cmd` for at most `secs`. `Ok(None)` means it ran over and was stopped.
fn run_with_timeout(cmd: &mut Command, secs: u64) -> Result<Option<ExitStatus>> {
    // Its own process group, so a timeout reaches every process it started.
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let group = i32::try_from(child.id())
        .ok()
        .filter(|id| *id > 0)
        .map(Pid::from_raw);
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            if let Some(g) = group {
                let _ = killpg(g, Signal::SIGTERM);
                let grace = Instant::now() + TERM_GRACE;
                while Instant::now() < grace && child.try_wait()?.is_none() {
                    std::thread::sleep(Duration::from_millis(500));
                }
                let _ = killpg(g, Signal::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn private_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

fn read_capped(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(f) = File::open(path) {
        let _ = f.take(OUT_CAP).read_to_string(&mut s);
    }
    s
}

fn free_mb(path: &str) -> Option<u64> {
    let st = nix::sys::statvfs::statvfs(path).ok()?;
    // Both are 64-bit on the x86_64 and aarch64 targets this agent ships for.
    let bytes = st.blocks_available().checked_mul(st.fragment_size())?;
    Some(bytes / (1024 * 1024))
}

// ---------------------------------------------------------------------------
// Choosing an engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Engine {
    /// `clamdscan`: asks the running daemon, which already holds the database.
    Clamdscan(PathBuf),
    /// `clamscan`: loads the database itself, so it needs RAM.
    Clamscan(PathBuf),
}

impl Engine {
    fn name(&self) -> &'static str {
        match self {
            Engine::Clamdscan(_) => "clamdscan",
            Engine::Clamscan(_) => "clamscan",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    Use(Engine),
    /// Nothing installed: ordinary, not worth a note on every scan.
    NotInstalled,
    /// `[hunt] clamav = "off"`.
    Disabled,
    /// Installed but cannot run now, with the reason to show.
    Cannot(String),
}

/// `clamscan` if it can run now: installed, with signatures and enough RAM.
fn usable_clamscan(cfg: &Config, avail_mb: u64, now: i64) -> Result<PathBuf, String> {
    let Some(bin) = find_bin("clamscan") else {
        return Err("có clamdscan nhưng clamd không chạy".into());
    };
    if db_age_hours(now).is_none() {
        return Err(
            "ClamAV chưa có CSDL chữ ký (đợi cập nhật đầu tiên hoặc chạy freshclam)".into(),
        );
    }
    if avail_mb < cfg.hunt.clamav_min_ram_mb {
        return Err(format!(
            "RAM còn trống {avail_mb} MB, clamscan cần ≥ {} MB nên bỏ qua",
            cfg.hunt.clamav_min_ram_mb
        ));
    }
    Ok(bin)
}

/// Decide which engine to use. `avail_mb` is the RAM currently available.
pub fn pick_engine(cfg: &Config, avail_mb: u64, now: i64) -> Pick {
    if cfg.hunt.clamav == ClamavMode::Off {
        return Pick::Disabled;
    }
    let clamdscan = find_bin("clamdscan");
    if clamdscan.is_none() && find_bin("clamscan").is_none() {
        return Pick::NotInstalled;
    }
    if let Some(bin) = &clamdscan {
        // `--ping` is the real "is clamd answering" check. (`--version` prints
        // the client's own version and exits 0 even with no daemon.)
        let up = run_with_timeout(
            Command::new(bin)
                .args(["--ping", "1:1"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            15,
        )
        .ok()
        .flatten()
        .is_some_and(|s| s.success());
        if up {
            return Pick::Use(Engine::Clamdscan(bin.clone()));
        }
    }
    match usable_clamscan(cfg, avail_mb, now) {
        Ok(bin) => Pick::Use(Engine::Clamscan(bin)),
        Err(why) => Pick::Cannot(why),
    }
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ClamScan {
    pub engine: String,
    pub scanned: u64,
    pub detections: Vec<Detection>,
    /// Why it did not run, or what went wrong; empty when all is well.
    pub note: String,
}

fn scan_command(engine: &Engine, mb: u64, list: &Path) -> Command {
    let mut cmd = match engine {
        Engine::Clamscan(bin) => {
            let mut c = Command::new(bin);
            c.args(["--infected", "--no-summary"])
                .arg(format!("--max-filesize={mb}M"))
                .arg(format!("--max-scansize={}M", mb * 2));
            c
        }
        Engine::Clamdscan(bin) => {
            let mut c = Command::new(bin);
            // The daemon runs as its own user: pass it open files instead of paths.
            c.args(["--fdpass", "--infected", "--no-summary"]);
            c
        }
    };
    cmd.arg("-f").arg(list).stdin(Stdio::null());
    cmd
}

struct ScanRun {
    status: Result<Option<ExitStatus>>,
    stdout: String,
    stderr: String,
}

impl ScanRun {
    /// 0 = clean, 1 = something found: both are a finished scan.
    fn finished(&self) -> bool {
        matches!(&self.status, Ok(Some(s)) if matches!(s.code(), Some(0 | 1)))
    }

    fn found_something(&self) -> bool {
        matches!(&self.status, Ok(Some(s)) if s.code() == Some(1))
    }
}

fn run_scan(
    engine: &Engine,
    list: &Path,
    out_path: &Path,
    err_path: &Path,
    mb: u64,
    timeout_secs: u64,
) -> Option<ScanRun> {
    let mut cmd = scan_command(engine, mb, list);
    match (private_file(out_path), private_file(err_path)) {
        (Ok(o), Ok(e)) => {
            cmd.stdout(o).stderr(e);
        }
        _ => return None,
    }
    let status = run_with_timeout(&mut cmd, timeout_secs);
    Some(ScanRun {
        status,
        stdout: read_capped(out_path),
        stderr: clamav::tail_lines(&read_capped(err_path), 1),
    })
}

/// Scan the files `sn hunt` selected. Never fails the hunt: any problem becomes
/// a note and the heuristic results stand on their own.
///
/// `skipped` counts files the caller could not hand over (a name that is not
/// valid UTF-8, or past the cap), so partial coverage is said out loud.
/// `budget_secs` is what is left of the hunt's overall time budget.
pub fn scan(
    cfg: &Config,
    state: &State,
    files: &[String],
    skipped: u64,
    max_file_mb: u64,
    budget_secs: u64,
) -> ClamScan {
    let mut out = ClamScan::default();
    if files.is_empty() {
        return out;
    }
    let started = Instant::now();
    let now = util::now_secs();
    let avail_mb = proc::meminfo().map_or(0, |m| m.available_kb / 1024);
    let engine = match pick_engine(cfg, avail_mb, now) {
        Pick::Use(e) => e,
        Pick::NotInstalled => return out,
        Pick::Disabled => {
            out.note = "ClamAV tắt trong cấu hình ([hunt] clamav = \"off\")".into();
            return out;
        }
        Pick::Cannot(why) => {
            out.note = why;
            return out;
        }
    };
    if budget_secs < MIN_SCAN_BUDGET_SECS {
        out.note = "Không còn đủ thời gian trong lần quét này để chạy ClamAV".into();
        return out;
    }
    let timeout = cfg.hunt.clamav_timeout_secs.max(60).min(budget_secs);
    out.engine = engine.name().into();

    // The list of files, one per line. A name with a newline cannot be listed.
    let mut dropped = skipped;
    let mut listed: Vec<&String> = Vec::with_capacity(files.len().min(MAX_LIST_FILES));
    for f in files {
        if f.contains(['\n', '\r']) || listed.len() >= MAX_LIST_FILES {
            dropped += 1;
        } else {
            listed.push(f);
        }
    }
    // A name per run, so two hunts at once (timer + hub button) cannot trample
    // each other's files.
    let pid = std::process::id();
    let list_path = state.dir.join(format!("clamav-{pid}-files.txt"));
    let out_path = state.dir.join(format!("clamav-{pid}-out.txt"));
    let err_path = state.dir.join(format!("clamav-{pid}-err.txt"));
    let cleanup = || {
        for p in [&list_path, &out_path, &err_path] {
            let _ = std::fs::remove_file(p);
        }
    };
    let written = private_file(&list_path).and_then(|mut f| {
        for p in &listed {
            writeln!(f, "{p}")?;
        }
        f.flush()
    });
    if let Err(e) = written {
        out.note = format!("không ghi được danh sách file cho ClamAV: {e}");
        cleanup();
        return out;
    }
    out.scanned = listed.len() as u64;

    let mb = max_file_mb.max(1);
    let Some(mut run) = run_scan(&engine, &list_path, &out_path, &err_path, mb, timeout) else {
        out.note = "không tạo được file kết quả cho ClamAV".into();
        cleanup();
        return out;
    };
    let mut notes: Vec<String> = Vec::new();

    // A daemon that was up a moment ago can still fail (socket permissions under
    // the unit's sandbox, clamd reloading). Fall back to clamscan if it can run.
    if matches!(engine, Engine::Clamdscan(_)) && !run.finished() {
        let left = timeout.saturating_sub(started.elapsed().as_secs());
        if left >= MIN_SCAN_BUDGET_SECS
            && let Ok(bin) = usable_clamscan(cfg, avail_mb, now)
        {
            notes.push("clamdscan lỗi nên đã chuyển sang clamscan".into());
            let fallback = Engine::Clamscan(bin);
            if let Some(r) = run_scan(&fallback, &list_path, &out_path, &err_path, mb, left) {
                out.engine = fallback.name().into();
                run = r;
            }
        }
    }

    let asked: HashSet<&str> = listed.iter().map(|s| s.as_str()).collect();
    out.detections = clamav::parse_detections(&run.stdout, &asked);

    match &run.status {
        Ok(Some(s)) if run.finished() => {
            if run.found_something() && out.detections.is_empty() {
                notes.push(format!(
                    "ClamAV báo có file nhiễm (mã {}) nhưng không đọc được kết quả",
                    s.code().unwrap_or(1)
                ));
            }
        }
        Ok(Some(s)) => {
            notes.push(format!(
                "ClamAV báo lỗi (mã {}){}",
                s.code().map_or_else(|| "?".to_string(), |c| c.to_string()),
                if run.stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {}", util::ellipsize(&run.stderr, 160))
                }
            ));
        }
        Ok(None) => notes.push(format!(
            "ClamAV chạy quá {timeout} giây nên bị dừng; kết quả có thể chưa đủ"
        )),
        Err(e) => notes.push(format!("không chạy được ClamAV: {e}")),
    }
    if dropped > 0 {
        notes.push(format!(
            "ClamAV bỏ qua {dropped} file (tên không hợp lệ hoặc vượt giới hạn {MAX_LIST_FILES})"
        ));
    }
    out.note = clamav::clean_text(&notes.join("; "));
    cleanup();
    out
}

// ---------------------------------------------------------------------------
// Status for the hub
// ---------------------------------------------------------------------------

fn install_state_path(state: &State) -> PathBuf {
    state.dir.join("clamav-install.json")
}

fn read_install_state(state: &State) -> InstallState {
    std::fs::read(install_state_path(state))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_install_state(state: &State, st: &str, message: &str) {
    let s = InstallState {
        at: util::now_secs(),
        state: st.into(),
        message: clamav::clean_text(&util::ellipsize(message, 300)),
    };
    if let Ok(bytes) = serde_json::to_vec(&s) {
        let _ = std::fs::write(install_state_path(state), bytes);
    }
}

fn os_release() -> String {
    std::fs::read_to_string("/etc/os-release").unwrap_or_default()
}

/// What the hub shows about ClamAV on this VPS. Cheap: file checks only.
pub fn info(cfg: &Config, state: &State) -> ClamavInfo {
    let now = util::now_secs();
    let mut inst = read_install_state(state);
    if inst.state == "running" && now - inst.at > STALE_INSTALL_SECS {
        inst.state = "failed".into();
        inst.message = "Lần cài trước không kết thúc (quá lâu không có kết quả).".into();
    }
    ClamavInfo {
        installed: find_bin("clamscan").is_some() || find_bin("clamdscan").is_some(),
        db_age_hours: db_age_hours(now),
        install_state: inst.state,
        install_message: inst.message,
        can_install: clamav::plan_for(&os_release(), &|n| find_bin(n).is_some()).is_ok(),
        install_allowed: cfg.remote.allow_install_clamav,
        disabled: cfg.hunt.clamav == ClamavMode::Off,
    }
}

// ---------------------------------------------------------------------------
// Installing
// ---------------------------------------------------------------------------

fn log_line(log: &mut File, line: &str) {
    let _ = writeln!(log, "{line}");
}

fn systemctl(args: &[&str], log: &mut File) -> Result<()> {
    let Some(sc) = find_bin("systemctl") else {
        bail!("không tìm thấy systemctl");
    };
    log_line(log, &format!("== systemctl {}", args.join(" ")));
    let mut cmd = Command::new(sc);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?);
    match run_with_timeout(&mut cmd, 90)? {
        Some(s) if s.success() => Ok(()),
        Some(s) => bail!("systemctl {} kết thúc với {s}", args.join(" ")),
        None => bail!("systemctl {} chạy quá 90 giây", args.join(" ")),
    }
}

/// Run one install step. `Err` carries the reason; an optional step's failure is
/// logged and ignored.
fn run_step(step: &Step, log: &mut File, log_path: &Path) -> Result<()> {
    match step {
        Step::Run {
            argv,
            optional,
            timeout_secs,
        } => {
            let Some(bin) = argv.first().and_then(|n| find_bin(n)) else {
                let name = argv.first().map_or("?", String::as_str);
                if *optional {
                    log_line(log, &format!("== bỏ qua (không có {name})"));
                    return Ok(());
                }
                bail!("không tìm thấy chương trình {name}");
            };
            log_line(log, &format!("== {}", argv.join(" ")));
            let mut cmd = Command::new(bin);
            cmd.args(&argv[1..])
                // Nothing may stop and ask: no debconf dialog, no needrestart menu.
                .env("DEBIAN_FRONTEND", "noninteractive")
                .env("NEEDRESTART_MODE", "a")
                .env("NEEDRESTART_SUSPEND", "1")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log.try_clone()?);
            match run_with_timeout(&mut cmd, *timeout_secs)? {
                Some(s) if s.success() => Ok(()),
                Some(s) if *optional => {
                    log_line(log, &format!("== (không bắt buộc) kết thúc với {s}"));
                    Ok(())
                }
                Some(s) => bail!(
                    "{} kết thúc với {s}: {}",
                    argv.join(" "),
                    clamav::tail_lines(&read_capped(log_path), 3)
                ),
                None if *optional => Ok(()),
                None => bail!(
                    "{} chạy quá {timeout_secs} giây (có thể cần `dpkg --configure -a` hoặc kiểm tra `dnf history`)",
                    argv.join(" ")
                ),
            }
        }
        Step::CommentExample(path) => {
            if let Ok(text) = std::fs::read_to_string(path)
                && let Some(fixed) = clamav::comment_example(&text)
            {
                std::fs::write(path, fixed)?;
                log_line(log, &format!("== đã tắt dòng Example trong {path}"));
            }
            Ok(())
        }
        Step::WaitDb => {
            let deadline = Instant::now() + Duration::from_secs(DB_WAIT_SECS);
            let started = Instant::now();
            let mut tried_freshclam = false;
            while Instant::now() < deadline {
                if db_age_hours(util::now_secs()).is_some() {
                    return Ok(());
                }
                // The package's own service normally downloads it; if nothing has
                // appeared after a while, ask freshclam directly (it may find the
                // service holding its lock, which is harmless).
                if !tried_freshclam && started.elapsed() > Duration::from_secs(90) {
                    tried_freshclam = true;
                    if let Some(fc) = find_bin("freshclam") {
                        log_line(log, "== freshclam");
                        let mut cmd = Command::new(fc);
                        cmd.stdin(Stdio::null())
                            .stdout(log.try_clone()?)
                            .stderr(log.try_clone()?);
                        let _ = run_with_timeout(&mut cmd, 20 * 60);
                    }
                }
                std::thread::sleep(Duration::from_secs(10));
            }
            bail!(
                "chưa tải được CSDL chữ ký sau {} phút (kiểm tra mạng tới database.clamav.net)",
                DB_WAIT_SECS / 60
            )
        }
        Step::UpdateTimer => {
            let Some(fc) = find_bin("freshclam") else {
                bail!("không tìm thấy freshclam để đặt lịch cập nhật chữ ký");
            };
            let (service, timer) = clamav::update_units(&fc.to_string_lossy());
            std::fs::write("/etc/systemd/system/sn-clamav-update.service", service)?;
            std::fs::write("/etc/systemd/system/sn-clamav-update.timer", timer)?;
            // Without the timer the signatures would never update again, so a
            // failure here fails the install instead of passing quietly.
            systemctl(&["daemon-reload"], log)?;
            systemctl(&["enable", "--now", "sn-clamav-update.timer"], log)?;
            log_line(log, "== đã đặt lịch cập nhật chữ ký hằng ngày");
            Ok(())
        }
    }
}

/// `sn install-clamav`: install ClamAV for this OS. Records its progress in the
/// state directory so the hub can show it, and never leaves "running" behind on
/// a normal exit. (Two at once are prevented by the fixed systemd unit name the
/// hub starts it under; a killed run is reported failed once it is stale.)
pub fn install(state: &State) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("cần chạy bằng root");
    }
    let fail = |msg: String| -> anyhow::Error {
        write_install_state(state, "failed", &msg);
        anyhow::anyhow!(msg)
    };

    let now = util::now_secs();
    if (find_bin("clamscan").is_some() || find_bin("clamdscan").is_some())
        && db_age_hours(now).is_some()
    {
        write_install_state(state, "ok", "ClamAV đã có sẵn trên VPS này.");
        println!("ClamAV is already installed.");
        return Ok(());
    }
    let total_mb = proc::meminfo().map_or(0, |m| m.total_mb());
    if total_mb < MIN_INSTALL_RAM_MB {
        return Err(fail(format!(
            "VPS chỉ có {total_mb} MB RAM; ClamAV cần ít nhất {MIN_INSTALL_RAM_MB} MB để quét."
        )));
    }
    if let Some(free) = free_mb("/var/lib")
        && free < MIN_INSTALL_DISK_MB
    {
        return Err(fail(format!(
            "Chỉ còn {free} MB trống ở /var/lib; ClamAV cần khoảng {MIN_INSTALL_DISK_MB} MB (gói + chữ ký)."
        )));
    }
    let plan = match clamav::plan_for(&os_release(), &|n| find_bin(n).is_some()) {
        Ok(p) => p,
        Err(e) => return Err(fail(e)),
    };

    write_install_state(
        state,
        "running",
        &format!("Đang cài theo công thức {}", plan.label),
    );
    let log_path = state.dir.join("clamav-install.log");
    let mut log = match private_file(&log_path) {
        Ok(f) => f,
        Err(e) => return Err(fail(format!("không tạo được log cài đặt: {e}"))),
    };
    println!("installing ClamAV: {}", plan.label);
    for step in &plan.steps {
        if let Err(e) = run_step(step, &mut log, &log_path) {
            return Err(fail(format!("{e:#}")));
        }
    }

    let now = util::now_secs();
    match (find_bin("clamscan"), db_age_hours(now)) {
        (Some(_), Some(h)) => {
            let msg = format!(
                "Đã cài ClamAV ({}); CSDL chữ ký cập nhật {h} giờ trước.",
                plan.label
            );
            write_install_state(state, "ok", &msg);
            println!("{msg}");
            Ok(())
        }
        (None, _) => Err(fail("cài xong nhưng không thấy clamscan".into())),
        (_, None) => Err(fail("cài xong nhưng chưa có CSDL chữ ký".into())),
    }
}
