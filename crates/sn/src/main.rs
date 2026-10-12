// SN Secure agent. Linux-only; cross-compiled to static musl.
#![forbid(unsafe_code)]

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod clamav;
mod clamav_run;
mod clean;
mod config;
mod contain;
mod discover;
mod hub;
mod hunt;
mod state;
mod sys;
mod triage;
mod undo;
mod util;
mod watch;
mod whitelist;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Reverse everything recorded in the undo log (release jail, remove bans).
    Undo,
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
        #[arg(long)]
        token: String,
    },
    /// Kill switch: remove the sn firewall table and release any jail.
    Disable,
    /// Print detected environment facts.
    Env,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
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
        Cmd::InstallClamav => {
            let state = State::open()?;
            clamav_run::install(&state)?;
        }
        Cmd::Clean { yes } => {
            let state = State::open()?;
            clean::clean(&state, yes)?;
        }
        Cmd::Quarantine { path } => {
            let state = State::open()?;
            let id = clean::quarantine(&state, &path)?;
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
        Cmd::Undo => {
            let state = State::open()?;
            let n = undo::run_all(&state.dir)?;
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
            let wl = whitelist::build(&cfg, &conns);
            println!("whitelist entries: {}", wl.keys().len());
            println!("mode: {}", cfg.watch.mode.as_str());
            println!("trusted proxies: {}", cfg.watch.trusted_proxies.join(", "));
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
                    let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
                    let readable = std::fs::File::open(f).is_ok();
                    println!(
                        "    - {} ({size} bytes, {})",
                        f.display(),
                        if readable { "readable" } else { "NOT readable" }
                    );
                }
                if files.len() > 5 {
                    println!("    ... and {} more", files.len() - 5);
                }
            }
        }
    }
    Ok(())
}
