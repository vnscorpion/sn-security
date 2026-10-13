// SN Secure agent. Linux-only; cross-compiled to static musl.
#![forbid(unsafe_code)]

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod clamav;
mod clamav_cache;
mod clamav_run;
mod clean;
mod config;
mod contain;
mod discover;
mod evidence;
mod evidence_parse;
mod hub;
mod hunt;
mod remediate;
mod state;
mod sys;
mod triage;
mod undo;
mod util;
mod watch;
mod whitelist;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nix::sys::stat::{Mode, umask};

use config::Config;
use state::State;

const DEFAULT_CONFIG: &str = "/etc/sn/agent.toml";

#[derive(Parser)]
#[command(
    name = "sn",
    version,
    about = "SN Secure agent: rescue + long-term traffic watch"
)]
struct Cli {
    /// Path to agent.toml.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read-only incident snapshot (processes, connections, persistence).
    Triage,
    /// Throttle suspicious processes into a 5% CPU jail (reversible).
    Contain {
        /// Freeze a confirmed miner fully (only with the `miner` label).
        #[arg(long)]
        freeze: bool,
        /// Show what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Contain specific PID(s) instead of auto-selecting.
        #[arg(long)]
        pid: Vec<i32>,
        /// Also ban flood sources on the web ports (for the ddos-l7 label).
        #[arg(long)]
        ban_flood: bool,
    },
    /// Scan allowed roots for PHP web-shells.
    Hunt {
        #[arg(long)]
        days: Option<u32>,
        /// Override the roots to scan.
        #[arg(long)]
        root: Vec<String>,
        /// Ignore the time filter and scan everything.
        #[arg(long)]
        deep: bool,
    },
    /// Install ClamAV for this OS (root). Used by the hub's "Install ClamAV" button.
    InstallClamav,
    /// Take a read-only incident snapshot (processes, start-up files, temp
    /// executables, SSH logins, open ports) and keep it for the hub.
    Evidence {
        /// After collecting, send the report at once and keep asking the hub for
        /// orders for a few minutes (used by the hub-requested snapshot).
        #[arg(long)]
        follow: bool,
    },
    /// Carry out an incident-response order the hub gave (root). Reads the job
    /// file the agent wrote when it received the order.
    Remediate {
        /// Job id (the name of the job file in the state directory).
        #[arg(long)]
        job: String,
    },
    /// Quarantine malicious findings from the last hunt (requires --yes).
    Clean {
        #[arg(long)]
        yes: bool,
    },
    /// Quarantine one file by path.
    Quarantine { path: PathBuf },
    /// Restore a quarantined file by id.
    Restore { id: String },
    /// List quarantined files.
    ListQuarantine,
    /// Reverse the recorded containment (release the jail, remove bans). With
    /// `--remediation`, reverse what `sn remediate` did instead (restore shells and
    /// start-up files, re-enable services).
    Undo {
        #[arg(long)]
        remediation: bool,
    },
    /// One watch cycle: read logs, count, ban/observe, report to hub.
    Watch {
        /// Replay a captured log file (no firewall or hub side effects).
        #[arg(long)]
        replay: Option<PathBuf>,
    },
    /// Print the most recent report.
    Report,
    /// Register this VPS with a hub and write the config.
    Enroll {
        #[arg(long)]
        url: String,
        #[arg(long)]
        name: String,
        /// Enrollment token. Better given in the SN_ENROLL_TOKEN environment
        /// variable: a command line is visible to every local user.
        #[arg(long)]
        token: Option<String>,
    },
    /// Kill switch: remove the sn firewall table and release any jail.
    Disable,
    /// Print detected environment facts.
    Env,
}

fn main() -> std::process::ExitCode {
    private_umask();
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Everything the agent creates (state, evidence, the vault, config) is root's
/// alone, whatever umask it was started with: a rescue shell's or systemd's 022
/// would leave incident data readable by every local account. Returns the
/// previous mask.
fn private_umask() -> Mode {
    umask(Mode::S_IRWXG | Mode::S_IRWXO)
}

/// The enrollment token: `--token` if given, else `SN_ENROLL_TOKEN` (where the
/// installer puts it, out of the process list).
fn enroll_token(flag: Option<String>, env: Option<std::ffi::OsString>) -> Result<String> {
    let token = match flag {
        Some(t) => t,
        None => env
            .context("no enrollment token: set SN_ENROLL_TOKEN (or pass --token)")?
            .into_string()
            .map_err(|_| anyhow::anyhow!("SN_ENROLL_TOKEN is not valid UTF-8"))?
            .trim()
            .to_string(),
    };
    if token.is_empty() {
        anyhow::bail!("the enrollment token is empty");
    }
    Ok(token)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;

    match cli.cmd {
        Cmd::Triage => {
            let state = State::open()?;
            triage::run(&state, true)?;
        }
        Cmd::Contain {
            freeze,
            dry_run,
            pid,
            ban_flood,
        } => {
            let state = State::open()?;
            let opts = contain::Options {
                freeze,
                dry_run,
                pids: pid,
                ban_flood,
            };
            contain::run(&state, &cfg, &opts)?;
        }
        Cmd::Hunt { days, root, deep } => {
            let state = State::open()?;
            let opts = hunt::Options {
                days: days.unwrap_or(cfg.hunt.days),
                roots: root,
                deep,
                max_file_mb: cfg.hunt.max_file_mb,
                print: true,
            };
            hunt::run(&cfg, &state, &opts)?;
        }
        Cmd::Evidence { follow } => {
            let state = State::open()?;
            let ev = evidence::collect(&state)?;
            evidence::print(&ev);
            if follow {
                hub::follow_incident(&cfg, &state);
            }
        }
        Cmd::Remediate { job } => {
            let state = State::open()?;
            remediate::run_job(&cfg, &state, &job)?;
        }
        Cmd::InstallClamav => {
            let state = State::open()?;
            // System packages: their install scripts and the update timer's unit
            // files are meant to have the system's usual modes.
            umask(Mode::S_IWGRP | Mode::S_IWOTH);
            clamav_run::install(&state)?;
        }
        Cmd::Clean { yes } => {
            let state = State::open()?;
            clean::clean(&state, &cfg.hunt.allowed_roots, yes)?;
        }
        Cmd::Quarantine { path } => {
            let state = State::open()?;
            // Walked from `/`: a relative path is made absolute first, without
            // resolving any symlink in it.
            let path = std::path::absolute(&path)?;
            let id = clean::quarantine_safe(&state, &path, None)?;
            println!("quarantined -> {id}");
        }
        Cmd::Restore { id } => {
            let state = State::open()?;
            clean::restore(&state, &id)?;
        }
        Cmd::ListQuarantine => {
            let state = State::open()?;
            clean::list(&state)?;
        }
        Cmd::Undo { remediation } => {
            let state = State::open()?;
            let n = if remediation {
                undo::run_remediation(&state.dir)?
            } else {
                undo::run_all(&state.dir)?
            };
            println!("reversed {n} recorded action(s).");
        }
        Cmd::Watch { replay } => {
            let state = State::open()?;
            let opts = watch::Options {
                replay,
                force: false,
            };
            watch::run(&cfg, &state, &opts)?;
        }
        Cmd::Report => {
            let state = State::open()?;
            match std::fs::read_to_string(state.dir.join("last-report.json")) {
                Ok(s) => println!("{s}"),
                Err(_) => println!("no report yet; run `sn watch` first."),
            }
        }
        Cmd::Enroll { url, name, token } => {
            let token = enroll_token(token, std::env::var_os("SN_ENROLL_TOKEN"))?;
            hub::enroll(&cli.config, &url, &name, &token)?;
        }
        Cmd::Disable => {
            let _ = sys::fw::delete_table();
            let _ = sys::cgroup::release();
            println!("sn firewall table removed and jail released (kill switch).");
        }
        Cmd::Env => {
            println!("sn {}", snsec_common::AGENT_VERSION);
            println!("cpus: {}", sys::proc::num_cpus());
            println!("cgroup: {}", sys::cgroup::version_str());
            let jailed = sys::cgroup::jail_pids();
            if !jailed.is_empty() {
                println!("contained pids: {jailed:?}");
            }
            println!("nftables: {}", sys::fw::available());
            if sys::fw::available() {
                match sys::fw::list_ban_keys() {
                    Ok(keys) => println!("active bans: {}", keys.len()),
                    Err(_) => println!("active bans: (sn table not present)"),
                }
            }
            let conns = sys::netstat::all();
            println!("tcp connections: {}", conns.len());
            let state = State::open().ok();
            let wl = whitelist::build(&cfg, &conns, state.as_ref());
            println!("whitelist entries: {}", wl.keys().len());
            if let Some(s) = &state {
                let own = s.meta().self_ips;
                if !own.is_empty() {
                    println!(
                        "own public address (as the hub sees it): {}",
                        own.join(", ")
                    );
                }
            }
            println!("mode: {}", cfg.watch.mode.as_str());
            println!("trusted proxies: {}", cfg.watch.trusted_proxies.join(", "));
            println!(
                "cloudflare never banned: {}",
                if cfg.watch.protect_cloudflare {
                    "yes"
                } else {
                    "no"
                }
            );
            let misplaced = cfg.misplaced_keys();
            if !misplaced.is_empty() {
                println!(
                    "WARNING: key(s) under a [[watch.sources]] entry do nothing there: {}",
                    misplaced.join(", ")
                );
            }
            let (resolved, sources) = watch::describe_sources(&cfg);
            match resolved.listener {
                Some(l) => println!("log sources (auto-detected; web server: {}):", l.name()),
                None => println!("log sources (manual, from agent.toml):"),
            }
            if sources.is_empty() {
                println!("  (none found; looked for:)");
                for g in &resolved.tried {
                    println!("    {g}");
                }
            }
            for (src, files) in &sources {
                println!("  {} [{}] -> {} file(s)", src.glob, src.format, files.len());
                for f in files.iter().take(5) {
                    // The same checks the watcher applies, so a refused log says why.
                    let (size, how) = match watch::tail::open_log(f) {
                        Ok(file) => (
                            file.metadata().map(|m| m.len()).unwrap_or(0),
                            "readable".to_string(),
                        ),
                        Err(e) => (0, format!("NOT read: {e}")),
                    };
                    println!("    - {} ({size} bytes, {how})", f.display());
                }
                if files.len() > 5 {
                    println!("    ... and {} more", files.len() - 5);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_runs_with_a_private_umask() {
        // Put straight back: the mask is process-wide and other tests run
        // alongside this one.
        let before = private_umask();
        let set = umask(before);
        assert_eq!(set.bits() & 0o777, 0o077);
    }

    #[test]
    fn enroll_takes_the_token_from_the_environment() {
        // No token on the command line...
        let cli =
            Cli::try_parse_from(["sn", "enroll", "--url", "https://h", "--name", "v"]).unwrap();
        let Cmd::Enroll { token, .. } = cli.cmd else {
            panic!("not enroll");
        };
        assert_eq!(token, None);
        assert_eq!(enroll_token(None, Some("tok\n".into())).unwrap(), "tok");
        assert!(enroll_token(None, None).is_err());
        assert!(enroll_token(None, Some(" ".into())).is_err());
        // ...but an older installer's --token still works, and wins.
        let cli = Cli::try_parse_from([
            "sn",
            "enroll",
            "--url",
            "https://h",
            "--name",
            "v",
            "--token",
            "old",
        ])
        .unwrap();
        let Cmd::Enroll { token, .. } = cli.cmd else {
            panic!("not enroll");
        };
        assert_eq!(enroll_token(token, Some("env".into())).unwrap(), "old");
    }
}
