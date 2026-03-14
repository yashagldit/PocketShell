use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use host_core::api::{derive_access_expiry, BackendClient};
use host_core::audit::{write_audit_event, AuditEvent};
use host_core::config::AppConfig;
use host_core::daemon;
use host_core::discovery::SessionDiscovery;
use host_core::models::{AuthState, HostIdentity, PairingValidateRequest};
use host_core::secure::{clear_private_key, clear_tokens, parse_jwt_exp, persist_private_key};
use host_core::stats::StatsCollector;
use host_core::store::StateStore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use rand::rngs::OsRng;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "myapp")]
#[command(about = "PocketShell host agent")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        otp: Option<String>,
        #[arg(long)]
        pairing_code: Option<String>,
    },
    Logout {
        #[arg(long)]
        reset: bool,
    },
    Status,
    Devices {
        #[command(subcommand)]
        command: DeviceCommands,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
    Stats {
        #[arg(long)]
        watch: bool,
    },
    /// Expose a terminal session for mobile access.
    /// Creates a named tmux session that the daemon auto-discovers.
    #[command(alias = "rc")]
    Remote {
        /// Session name (default: "remote")
        #[arg(long, short, default_value = "remote")]
        name: String,
        /// Don't attach to the session — just create it in the background
        #[arg(long)]
        detached: bool,
        /// List currently discoverable sessions instead of creating one
        #[arg(long, short)]
        list: bool,
        /// Remove an exposed session
        #[arg(long, short)]
        remove: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCommands {
    List,
    ListPending,
    Approve { device_id: String },
    Revoke { device_id: String },
}

#[derive(Subcommand, Debug)]
enum DaemonCommands {
    Start,
    Stop,
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    ensure_supported_platform()?;
    let config = AppConfig::from_env();

    match cli.command {
        Commands::Login {
            email,
            otp,
            pairing_code,
        } => login(config, email, otp, pairing_code).await,
        Commands::Logout { reset } => logout(reset),
        Commands::Status => status(config).await,
        Commands::Devices { command } => devices(config, command).await,
        Commands::Daemon { command } => daemon_cmd(config, command).await,
        Commands::Stats { watch } => stats_cmd(watch).await,
        Commands::Remote { name, detached, list, remove } => remote_cmd(name, detached, list, remove),
    }
}

fn ensure_supported_platform() -> Result<()> {
    if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
        return Ok(());
    }
    Err(anyhow!("unsupported host OS; only linux and macos are supported"))
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn login(
    config: AppConfig,
    email: Option<String>,
    otp: Option<String>,
    pairing_code: Option<String>,
) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;
    let email = email.unwrap_or_else(|| prompt("Email: "));

    let backend = BackendClient::new(config.backend_base_url.clone());

    // Skip OTP request when OTP is already provided (non-interactive usage)
    let otp = if let Some(code) = otp {
        code
    } else {
        backend
            .request_otp(&email)
            .await
            .context("requesting OTP")?;
        prompt("OTP code: ")
    };
    let tokens = backend
        .verify_otp(&email, &otp)
        .await
        .context("verifying OTP")?;

    let pairing_code = pairing_code.unwrap_or_else(|| prompt("Pairing code: "));

    let hostname = std::env::var("HOSTNAME")
        .unwrap_or_else(|_| whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()));
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    let (public_key, private_key) = generate_keypair();
    persist_private_key(&private_key);

    let host = backend
        .validate_pairing_code(
            &tokens.access_token,
            &PairingValidateRequest {
                code: pairing_code,
                hostname: hostname.clone(),
                platform: platform.clone(),
                public_key: public_key.clone(),
                app_version: Some(config.app_version.clone()),
            },
        )
        .await
        .context("validating pairing code")?;

    store.state.auth = Some(AuthState {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        access_expires_at: derive_access_expiry(&tokens.access_token)
            .or_else(|| parse_jwt_exp(&tokens.access_token)),
    });
    store.state.host = Some(HostIdentity {
        host_id: host.id.clone(),
        user_id: host.user_id,
        hostname,
        platform,
        app_version: config.app_version,
        public_key,
        registered_at: chrono::Utc::now(),
    });
    store.save().context("persisting local state")?;

    let _ = write_audit_event(AuditEvent {
        event_type: "login_success".to_string(),
        host_id: Some(host.id),
        ..AuditEvent::new("login_success")
    });

    println!("login successful");
    Ok(())
}

fn logout(reset: bool) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;

    clear_tokens();
    if reset {
        clear_private_key();
        store.state = Default::default();
    } else {
        store.state.auth = None;
    }

    store.save().context("persisting state")?;

    let _ = write_audit_event(AuditEvent::new(if reset { "logout_reset" } else { "logout" }));

    println!("logged out");
    Ok(())
}

async fn status(config: AppConfig) -> Result<()> {
    let store = StateStore::load().context("loading local state")?;
    if let Some(ref host) = store.state.host {
        println!("host_id: {}", host.host_id);
        println!("hostname: {}", host.hostname);
        println!("platform: {}", host.platform);
        println!("trusted_devices: {}", store.state.trusted_devices.len());
        println!("pending_devices: {}", store.state.pending_devices.len());

        if let Ok(token) = store.access_token() {
            let backend = BackendClient::new(config.backend_base_url);
            match backend.send_heartbeat(token, &host_core::models::HeartbeatRequest {
                host_id: host.host_id.clone(),
                active_sessions: 0,
                pending_devices: store.state.pending_devices.len(),
            }).await {
                Ok(_) => println!("connection_health: reachable"),
                Err(_) => println!("connection_health: degraded"),
            }
        }
    } else {
        println!("not logged in");
    }

    let pid_path = AppConfig::paths()?.pid_file;
    if let Some(pid) = read_pid(&pid_path) {
        if pid_running(pid) {
            println!("daemon: running (pid {})", pid);
        } else {
            println!("daemon: stale pid file ({})", pid);
        }
    } else {
        println!("daemon: stopped");
    }

    Ok(())
}

async fn devices(config: AppConfig, command: DeviceCommands) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;
    store.require_logged_in().map_err(|e| anyhow!(e.to_string()))?;

    let token = store.access_token()?.to_string();
    let host_id = store.host_id()?;
    let backend = BackendClient::new(config.backend_base_url);

    match command {
        DeviceCommands::List => {
            let trusted = backend
                .list_trusted_devices(&token, &host_id)
                .await
                .context("fetching trusted devices")?;
            store.set_trusted_devices(trusted);
            store.save().context("saving state")?;

            if store.state.trusted_devices.is_empty() {
                println!("no trusted devices");
            } else {
                for d in &store.state.trusted_devices {
                    println!("{}\tapproved={}\tcreated={} ", d.mobile_device_id, d.approved_at.is_some(), d.created_at);
                }
            }
        }
        DeviceCommands::ListPending => {
            let all = backend
                .list_trusted_devices(&token, &host_id)
                .await
                .context("fetching pending devices")?;
            store.set_trusted_devices(all);
            store.save().context("saving state")?;

            if store.state.pending_devices.is_empty() {
                println!("no pending devices");
            } else {
                for d in &store.state.pending_devices {
                    println!("{}\tpending_since={}", d.mobile_device_id, d.created_at);
                }
            }
        }
        DeviceCommands::Approve { device_id } => {
            let approved = backend
                .approve_device(&token, &host_id, &device_id)
                .await
                .context("syncing approval with backend")?;

            let all = backend
                .list_trusted_devices(&token, &host_id)
                .await
                .context("refreshing trusted devices")?;
            store.set_trusted_devices(all);
            store.save().context("saving state")?;

            let _ = write_audit_event(AuditEvent {
                event_type: "device_approved".to_string(),
                mobile_device_id: Some(approved.mobile_device_id.clone()),
                host_id: Some(host_id.clone()),
                ..AuditEvent::new("device_approved")
            });

            println!("approved device {}", approved.mobile_device_id);
        }
        DeviceCommands::Revoke { device_id } => {
            let revoked = backend
                .revoke_device(&token, &host_id, &device_id)
                .await
                .context("syncing revocation with backend")?;

            store.remove_trusted_device(&revoked.mobile_device_id);
            store.save().context("saving state")?;

            let _ = write_audit_event(AuditEvent {
                event_type: "device_revoked".to_string(),
                mobile_device_id: Some(revoked.mobile_device_id.clone()),
                host_id: Some(host_id.clone()),
                ..AuditEvent::new("device_revoked")
            });

            println!("revoked device {}", revoked.mobile_device_id);
        }
    }

    Ok(())
}

async fn daemon_cmd(config: AppConfig, command: DaemonCommands) -> Result<()> {
    match command {
        DaemonCommands::Start => daemon_start(),
        DaemonCommands::Stop => daemon_stop(),
        DaemonCommands::Run => daemon::run_foreground(config)
            .await
            .map_err(|e| anyhow!(e.to_string())),
    }
}

fn daemon_start() -> Result<()> {
    let paths = AppConfig::paths()?;

    if let Some(pid) = read_pid(&paths.pid_file) {
        if pid_running(pid) {
            println!("daemon already running (pid {})", pid);
            return Ok(());
        }
    }

    fs::create_dir_all(&paths.state_dir)?;

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)
        .context("opening daemon log file")?;

    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)
        .context("opening daemon log file")?;

    let exe = std::env::current_exe().context("resolving current executable")?;
    let child = Command::new(exe)
        .arg("daemon")
        .arg("run")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("spawning daemon")?;

    fs::write(&paths.pid_file, child.id().to_string()).context("writing pid file")?;

    let _ = write_audit_event(AuditEvent::new("daemon_start_command"));

    println!("daemon started (pid {})", child.id());
    Ok(())
}

fn daemon_stop() -> Result<()> {
    let paths = AppConfig::paths()?;
    let Some(pid) = read_pid(&paths.pid_file) else {
        println!("daemon not running");
        return Ok(());
    };

    kill(Pid::from_raw(pid), Signal::SIGTERM).context("sending SIGTERM")?;

    for _ in 0..20 {
        if !pid_running(pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if paths.pid_file.exists() {
        let _ = fs::remove_file(&paths.pid_file);
    }

    let _ = write_audit_event(AuditEvent::new("daemon_stop_command"));

    println!("daemon stopped");
    Ok(())
}

async fn stats_cmd(watch: bool) -> Result<()> {
    let mut collector = StatsCollector::new();

    if watch {
        loop {
            let s = collector.snapshot();
            println!(
                "cpu={:.1}% mem={}/{} disk={}/{} uptime={}s load={:.2}/{:.2}/{:.2}",
                s.cpu_usage_percent,
                s.memory_used_bytes,
                s.memory_total_bytes,
                s.disk_used_bytes,
                s.disk_total_bytes,
                s.uptime_secs,
                s.load_one,
                s.load_five,
                s.load_fifteen,
            );
            sleep(Duration::from_secs(2)).await;
        }
    } else {
        let s = collector.snapshot();
        println!("{}", serde_json::to_string_pretty(&s)?);
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn remote_cmd(name: String, detached: bool, list: bool, remove: bool) -> Result<()> {
    if remove {
        SessionDiscovery::unregister_exposed(&name)?;
        println!("removed exposed session '{}'", name);
        return Ok(());
    }

    if list {
        let sessions = SessionDiscovery::discover();
        if sessions.is_empty() {
            println!("no exposed sessions found");
        } else {
            println!("{:<12} {:<20} {:<10} {}", "TYPE", "NAME", "STATUS", "WINDOWS");
            for s in &sessions {
                println!(
                    "{:<12} {:<20} {:<10} {}",
                    s.session_type,
                    s.name,
                    if s.attached { "attached" } else { "available" },
                    s.windows,
                );
            }
        }
        return Ok(());
    }

    // Expose current terminal's PTY for mobile access
    SessionDiscovery::register_exposed(&name)?;
    println!("exposed session '{}' for mobile access.", name);
    println!("mobile can connect via SessionPicker.");
    println!("press Enter or Ctrl+C to stop sharing.\n");

    // Block — the terminal stays shared while this runs
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);

    // Clean up
    SessionDiscovery::unregister_exposed(&name)?;
    println!("stopped sharing session '{}'.", name);

    Ok(())
}

fn prompt(label: &str) -> String {
    print!("{label}");
    let _ = io::stdout().flush();

    let mut buf = String::new();
    if io::stdin().read_line(&mut buf).is_ok() {
        return buf.trim().to_string();
    }

    String::new()
}

fn generate_keypair() -> (String, String) {
    use base64::Engine;
    use ed25519_dalek::SigningKey;

    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();

    (
        base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(sk.to_bytes()),
    )
}

fn read_pid(path: &PathBuf) -> Option<i32> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<i32>().ok()
}

fn pid_running(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}
