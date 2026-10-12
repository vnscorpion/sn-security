// SN Secure hub (master). Runs on the central Ubuntu server.
#![forbid(unsafe_code)]

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod ai_client;
mod analysis;
mod api;
mod auth;
mod config;
mod db;
mod db_ai;
mod db_auth;
mod desired;
mod keys;
mod totp;
mod web;
mod web_ai;
mod web_auth;
mod webauthn;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::extract::{Path as AxPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, body::Body};
use clap::{Parser, Subcommand};

use config::HubConfig;
use db::Db;
use keys::HubKey;

const DEFAULT_CONFIG: &str = "/etc/snhub/snhub.toml";

pub struct AppState {
    pub db: Mutex<Db>,
    pub hubkey: HubKey,
    pub cfg: HubConfig,
    pub sessions: auth::Sessions,
    /// Logins that passed the password and wait for their second factor.
    pub pending: auth::Pending,
    pub limiter: auth::Limiter,
}

#[derive(Parser)]
#[command(
    name = "snhub",
    version,
    about = "SN Secure hub: enrollment, reports, desired-state, UI"
)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create config, hub key and DB; print the offline root key once.
    Init {
        /// Public base URL shown in install commands (e.g. https://a.example.net).
        #[arg(long, default_value = "")]
        public_url: String,
        /// Bind address.
        #[arg(long, default_value = "127.0.0.1:8099")]
        bind: String,
        #[arg(long, default_value = "/var/lib/snhub")]
        data_dir: String,
    },
    /// Run the server.
    Serve,
    /// Create a one-time enrollment token and print the install command.
    AddVps {
        #[arg(long)]
        name: String,
    },
    /// Set the admin UI password (from --password or $SNHUB_ADMIN_PASSWORD).
    SetAdminPassword {
        #[arg(long)]
        password: Option<String>,
    },
    /// Forget the authenticator app, every passkey and the recovery codes (when
    /// the second factor is lost). The password stays; sign in with it, then
    /// enrol again on the Bảo mật page.
    Reset2fa,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn main() -> std::process::ExitCode {
    match real_main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init {
            public_url,
            bind,
            data_dir,
        } => cmd_init(&cli.config, public_url, bind, data_dir),
        Cmd::Serve => cmd_serve(&cli.config),
        Cmd::AddVps { name } => cmd_add_vps(&cli.config, &name),
        Cmd::SetAdminPassword { password } => cmd_set_password(&cli.config, password),
        Cmd::Reset2fa => cmd_reset_2fa(&cli.config),
    }
}

fn cmd_init(config_path: &Path, public_url: String, bind: String, data_dir: String) -> Result<()> {
    let mut cfg = HubConfig::load(config_path).unwrap_or_default();
    cfg.bind = bind;
    cfg.data_dir = data_dir;
    if !public_url.is_empty() {
        cfg.public_url = public_url;
    }
    std::fs::create_dir_all(cfg.data_path()).context("creating data dir")?;
    std::fs::create_dir_all(cfg.data_path().join("public")).ok();

    // Hub key (online) + DB.
    let hubkey = HubKey::load_or_create(&cfg.data_path())?;
    let _db = Db::open(&cfg.data_path().join("snhub.sqlite"))?;

    // Root key (offline) — generate only if not already configured.
    if cfg.root_pubkey.is_empty() {
        let (root_secret, root_pub) = keys::generate_root();
        cfg.root_pubkey = root_pub.clone();
        println!("================= SN Secure hub initialised =================");
        println!("Hub public key : {}", hubkey.pubkey_str());
        println!("Root public key: {root_pub}");
        println!();
        println!("OFFLINE ROOT SECRET (store it off this server, then forget it):");
        println!("  {root_secret}");
        println!();
        println!("This secret authorizes policy/epoch changes. It is NOT needed to");
        println!("run the hub. Keep it on a YubiKey or an air-gapped machine.");
        println!("============================================================");
    } else {
        println!("Hub public key : {}", hubkey.pubkey_str());
        println!("Root public key: {} (unchanged)", cfg.root_pubkey);
    }

    cfg.save(config_path)?;
    println!("Config written to {}", config_path.display());
    println!("Next: snhub set-admin-password --password '<pw>' ; then snhub serve");
    Ok(())
}

fn cmd_set_password(config_path: &Path, password: Option<String>) -> Result<()> {
    let mut cfg = HubConfig::load(config_path)?;
    let pw = password
        .or_else(|| std::env::var("SNHUB_ADMIN_PASSWORD").ok())
        .context("provide --password or set SNHUB_ADMIN_PASSWORD")?;
    if let Some(problem) = auth::password_problem(&pw) {
        anyhow::bail!("{problem}");
    }
    let hash = auth::hash_password_argon2(&pw);
    if hash.is_empty() {
        anyhow::bail!("could not hash the password");
    }
    // Argon2id from now on; the old salted SHA-256 pair is dropped.
    cfg.admin_password_hash = hash.clone();
    cfg.admin_password_sha256.clear();
    cfg.admin_salt.clear();
    cfg.save(config_path)?;
    // A password changed from the web UI lives in the database and would
    // otherwise win over this one: replace it too. No restart needed.
    let db = Db::open(&cfg.data_path().join("snhub.sqlite"))?;
    db.set_admin_pw_hash(&hash, now())?;
    println!("admin password set (Argon2id).");
    Ok(())
}

fn cmd_reset_2fa(config_path: &Path) -> Result<()> {
    let cfg = HubConfig::load(config_path)?;
    let db = Db::open(&cfg.data_path().join("snhub.sqlite"))?;
    db.reset_2fa()?;
    db.log_login(
        now(),
        "console",
        true,
        "reset 2FA",
        "bằng dòng lệnh trên máy chủ",
    );
    println!(
        "Two-factor sign-in removed (app, passkeys, recovery codes). The password is unchanged."
    );
    Ok(())
}

fn cmd_add_vps(config_path: &Path, name: &str) -> Result<()> {
    let cfg = HubConfig::load(config_path)?;
    let db = Db::open(&cfg.data_path().join("snhub.sqlite"))?;
    let token = db.create_enroll_token(name, now(), 900)?;
    let base = if cfg.public_url.is_empty() {
        format!("http://{}", cfg.bind)
    } else {
        cfg.public_url.trim_end_matches('/').to_string()
    };
    println!("Install command (token valid 15 minutes):\n");
    println!(
        "curl -fsSL {base}/install.sh | sudo sh -s -- --hub {base} --name {name} --token {token}"
    );
    Ok(())
}

fn cmd_serve(config_path: &Path) -> Result<()> {
    let cfg = HubConfig::load(config_path)?;
    std::fs::create_dir_all(cfg.data_path()).ok();
    let hubkey = HubKey::load_or_create(&cfg.data_path())?;
    let db = Db::open(&cfg.data_path().join("snhub.sqlite"))?;

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        hubkey,
        cfg: cfg.clone(),
        sessions: auth::Sessions::default(),
        pending: auth::Pending::default(),
        limiter: auth::Limiter::default(),
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(async move { serve(cfg, state).await })
}

/// Every route, with the browser guard in front. Separate from `serve` so tests can
/// drive the whole app without a socket.
fn router(state: Arc<AppState>) -> Router {
    let base = Router::new()
        // agent API
        .route("/v1/report", post(api::post_report))
        .route("/v1/desired", get(api::get_desired))
        .route("/v1/enroll", post(api::post_enroll))
        // admin UI
        .route("/", get(web::overview))
        .route(
            "/login",
            get(web_auth::login_page).post(web_auth::login_post),
        )
        .route("/logout", get(web_auth::logout))
        .route("/security", get(web_auth::security_page))
        .route("/security/password", post(web_auth::change_password))
        .route("/security/session/{id}/end", post(web_auth::session_end))
        .route(
            "/security/sessions/others",
            post(web_auth::sessions_end_others),
        )
        .route("/agent/{id}", get(web::agent_detail))
        .route("/agent/{id}/ban", post(web::ban_post))
        .route("/agent/{id}/unban", post(web::unban_post))
        .route("/agent/{id}/mode", post(web::mode_post))
        .route("/agent/{id}/job", post(web::job_post))
        .route("/agent/{id}/findings.csv", get(web::findings_csv_download))
        .route("/agent/{id}/findings.txt", get(web::findings_txt_download))
        .route("/agent/{id}/evidence.json", get(web_ai::evidence_download))
        .route("/agent/{id}/ai/analyze", post(web_ai::ai_analyze_post))
        .route("/agent/{id}/ai/autonomy", post(web_ai::ai_autonomy_post))
        .route("/agent/{id}/ai/{pid}/apply", post(web_ai::ai_apply_post))
        .route("/agent/{id}/ai/{pid}/reject", post(web_ai::ai_reject_post))
        .route("/settings", get(web_ai::settings_page))
        .route("/settings/provider", post(web_ai::provider_save_post))
        .route(
            "/settings/provider/{pid}/default",
            post(web_ai::provider_default_post),
        )
        .route(
            "/settings/provider/{pid}/delete",
            post(web_ai::provider_delete_post),
        )
        .route(
            "/settings/provider/{pid}/test",
            post(web_ai::provider_test_post),
        )
        .route("/add-vps", get(web::add_vps_page).post(web::add_vps_post))
        .route("/log", get(web::log_page))
        .route("/check-ip", get(web::check_ip))
        // static distribution of the installer + agent binary
        .route("/install.sh", get(serve_install))
        .route("/sn/{file}", get(serve_sn))
        .route("/healthz", get(|| async { "ok" }));
    // Two-factor sign-in is off unless `two_factor = true` in the config: its pages
    // and endpoints do not exist at all otherwise.
    let app = if state.cfg.two_factor {
        base.merge(two_factor_routes())
    } else {
        base
    };
    app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        web_auth::browser_guard,
    ))
    .with_state(state)
}

/// The second-factor pages and endpoints (authenticator app, passkeys, recovery
/// codes). Registered only when `two_factor` is on.
fn two_factor_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/login/2fa",
            get(web_auth::login_2fa_page).post(web_auth::login_2fa_post),
        )
        .route(
            "/login/passkey/options",
            post(web_auth::login_passkey_options),
        )
        .route(
            "/login/passkey/verify",
            post(web_auth::login_passkey_verify),
        )
        .route("/security/totp/start", post(web_auth::totp_start))
        .route("/security/totp/confirm", post(web_auth::totp_confirm))
        .route("/security/totp/disable", post(web_auth::totp_disable))
        .route("/security/recovery/new", post(web_auth::recovery_new))
        .route(
            "/security/passkey/options",
            post(web_auth::passkey_register_options),
        )
        .route(
            "/security/passkey/register",
            post(web_auth::passkey_register),
        )
        .route(
            "/security/passkey/{id}/delete",
            post(web_auth::passkey_delete),
        )
}

async fn serve(cfg: HubConfig, state: Arc<AppState>) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    tracing::info!("snhub listening on {}", cfg.bind);

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("server error")?;
    Ok(())
}

async fn serve_install(State(st): State<Arc<AppState>>) -> Response {
    serve_file(
        &st.cfg.data_path().join("public").join("install.sh"),
        "text/x-shellscript",
    )
    .await
}

async fn serve_sn(State(st): State<Arc<AppState>>, AxPath(file): AxPath<String>) -> Response {
    // Reject any path traversal; only a bare filename is allowed.
    if file.contains('/') || file.contains('\\') || file.contains("..") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    serve_file(
        &st.cfg.data_path().join("public").join(&file),
        "application/octet-stream",
    )
    .await
}

async fn serve_file(path: &Path, content_type: &str) -> Response {
    match tokio::fs::read(path).await {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[cfg(test)]
mod flow_tests;
