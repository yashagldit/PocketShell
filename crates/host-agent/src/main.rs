use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use host_core::api::BackendClient;
use host_core::audit::{write_audit_event, AuditEvent};
use host_core::config::AppConfig;
use host_core::daemon;
use host_core::discovery::SessionDiscovery;
use host_core::models::{AuthState, HostIdentity, PairingValidateRequest};
use host_core::secure::parse_jwt_exp;
use host_core::stats::StatsCollector;
use host_core::store::StateStore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use rand::rngs::OsRng;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "pocketshell")]
#[command(about = "PocketShell host agent")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Register this host using a pairing code from the mobile app.
    /// If already paired, adds the new device to this host.
    /// Use --reset to wipe existing pairing and start fresh (e.g. switching accounts).
    Pair {
        /// Pairing code displayed in the mobile app
        code: Option<String>,
        /// Clear existing host identity before pairing (use when switching accounts)
        #[arg(long)]
        reset: bool,
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
    /// List and manage terminal sessions on this host
    Sessions {
        #[command(subcommand)]
        command: Option<SessionCommands>,
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
enum SessionCommands {
    /// Attach to a persistent tmux session locally on this host
    Attach {
        /// Session ID (or prefix) to attach to
        session_id: String,
    },
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
        Commands::Pair { code, reset } => pair(config, code, reset).await,
        Commands::Logout { reset } => logout(reset),
        Commands::Status => status(config).await,
        Commands::Devices { command } => devices(config, command).await,
        Commands::Daemon { command } => daemon_cmd(config, command).await,
        Commands::Stats { watch } => stats_cmd(watch).await,
        Commands::Sessions { command } => sessions_cmd(config, command).await,
        Commands::Remote {
            name,
            detached,
            list,
            remove,
        } => remote_cmd(name, detached, list, remove),
    }
}

fn ensure_supported_platform() -> Result<()> {
    if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
        return Ok(());
    }
    Err(anyhow!(
        "unsupported host OS; only linux and macos are supported"
    ))
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn pair(config: AppConfig, code: Option<String>, reset: bool) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;

    // --reset: wipe existing identity so the host can pair with a different account
    if reset {
        if store.state.host.is_some() {
            println!("resetting existing host identity...");
        }
        store.state = Default::default();
        store.save().context("persisting reset state")?;
    }

    let pairing_code = code.unwrap_or_else(|| prompt("Pairing code: "));

    let hostname = std::env::var("HOSTNAME")
        .unwrap_or_else(|_| whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()));
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    // If the host is already registered, send host_id so the backend adds the
    // mobile device's trust instead of creating a new host (device-add flow).
    let existing_host_id = store.state.host.as_ref().map(|h| h.host_id.clone());
    let is_new_host = existing_host_id.is_none();

    // Only generate a new keypair for new-host registration; device-add flow
    // doesn't need one since the host identity already exists.
    let (public_key, private_key) = if is_new_host {
        generate_keypair()
    } else {
        let h = store.state.host.as_ref().unwrap();
        (h.public_key.clone(), h.private_key.clone())
    };

    let backend = BackendClient::new(config.backend_base_url.clone());
    let result = backend
        .validate_pairing_code(&PairingValidateRequest {
            code: pairing_code,
            hostname: hostname.clone(),
            platform: platform.clone(),
            public_key: public_key.clone(),
            app_version: Some(config.app_version.clone()),
            host_id: existing_host_id.clone(),
        })
        .await;

    let response = match result {
        Ok(r) => r,
        Err(e) if existing_host_id.is_some() => {
            // Device-add failed — likely the pairing code belongs to a different account
            eprintln!("error: {e}");
            eprintln!();
            eprintln!("this host is already paired with a different account.");
            eprintln!("to switch accounts, run:");
            eprintln!("  pocketshell pair --reset <CODE>");
            return Err(anyhow!("pairing failed — account mismatch"));
        }
        Err(e) => return Err(e).context("validating pairing code"),
    };

    // Always update auth tokens — the backend returns fresh tokens for both
    // new-host and device-add flows.  This ensures `pair` recovers from
    // expired/revoked auth without needing `--reset`.
    store.state.auth = Some(AuthState {
        access_token: response.access_token.clone(),
        refresh_token: response.refresh_token.clone(),
        access_expires_at: parse_jwt_exp(&response.access_token),
    });

    if response.already_paired {
        // Device-add flow: host identity already exists locally.
        store.save().context("persisting refreshed auth")?;
        println!("new mobile device approved on this host");
        println!("the device can now connect to this host");

        let _ = write_audit_event(AuditEvent {
            event_type: "device_approved".to_string(),
            host_id: Some(response.host.id),
            ..AuditEvent::new("device_approved")
        });
    } else {
        // New-host flow: save host identity and tokens.
        store.state.host = Some(HostIdentity {
            host_id: response.host.id.clone(),
            user_id: response.host.user_id,
            hostname,
            platform,
            app_version: config.app_version,
            public_key,
            private_key,
            registered_at: chrono::Utc::now(),
        });
        store.save().context("persisting local state")?;

        let _ = write_audit_event(AuditEvent {
            event_type: "login_success".to_string(),
            host_id: Some(response.host.id),
            ..AuditEvent::new("login_success")
        });

        println!(
            "login successful — host registered as {}",
            response.host.hostname
        );
    }

    // Ensure daemon is running as a system service
    if !host_core::service::is_service_running() {
        print!("installing service...");
        let _ = io::stdout().flush();
        match host_core::service::install_and_start() {
            Ok(host_core::service::ServiceStatus::Installed) => {
                println!(" done");
                println!("daemon installed as a system service and started");
                println!("it will auto-start on boot and restart on crash");
            }
            Ok(host_core::service::ServiceStatus::AlreadyRunning) => {
                println!(" already running");
            }
            Ok(host_core::service::ServiceStatus::StartedDaemon) => {
                println!(" done");
                println!("daemon started in background");
                println!("note: service install was not available — daemon won't auto-start on reboot");
                println!("you can start it manually with: pocketshell daemon start");
            }
            Err(e) => {
                println!(" failed ({e})");
                println!("start the daemon manually with: pocketshell daemon start");
            }
        }
    }

    Ok(())
}

fn logout(reset: bool) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;

    // Always stop the daemon — it can't function without auth
    // --reset also uninstalls the service (removes auto-start)
    if reset {
        if let Err(e) = host_core::service::uninstall() {
            eprintln!("warning: could not uninstall service: {e}");
        }
    } else if host_core::service::is_service_running() {
        // Plain logout: stop but keep service installed — `daemon start` will re-enable
        if let Err(e) = host_core::service::stop() {
            eprintln!("warning: could not stop service: {e}");
        }
    }

    // Also stop any PID-based daemon
    let paths = AppConfig::paths()?;
    if let Some(pid) = read_pid(&paths.pid_file) {
        if pid_running(pid) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            for _ in 0..20 {
                if !pid_running(pid) { break; }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let _ = fs::remove_file(&paths.pid_file);
    }

    if reset {
        store.state = Default::default();
    } else {
        store.state.auth = None;
    }

    store.save().context("persisting state")?;

    let _ = write_audit_event(AuditEvent::new(if reset {
        "logout_reset"
    } else {
        "logout"
    }));

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
            match backend
                .send_heartbeat(
                    token,
                    &host_core::models::HeartbeatRequest {
                        host_id: host.host_id.clone(),
                        active_sessions: 0,
                        pending_devices: store.state.pending_devices.len(),
                    },
                )
                .await
            {
                Ok(_) => println!("connection_health: reachable"),
                Err(_) => println!("connection_health: degraded"),
            }
        }
    } else {
        println!("not logged in");
    }

    if host_core::service::is_service_running() {
        println!("daemon: running (system service)");
    } else {
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
    }

    Ok(())
}

async fn devices(config: AppConfig, command: DeviceCommands) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;
    store
        .require_logged_in()
        .map_err(|e| anyhow!(e.to_string()))?;

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
                    println!(
                        "{}\tapproved={}\tcreated={} ",
                        d.mobile_device_id,
                        d.approved_at.is_some(),
                        d.created_at
                    );
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
    // Check if already running via service or PID
    if host_core::service::is_service_running() {
        println!("daemon is running via system service");
        return Ok(());
    }
    let paths = AppConfig::paths()?;
    if let Some(pid) = read_pid(&paths.pid_file) {
        if pid_running(pid) {
            println!("daemon already running (pid {})", pid);
            return Ok(());
        }
    }

    // install_and_start tries service manager first, falls back to background process
    match host_core::service::install_and_start() {
        Ok(host_core::service::ServiceStatus::Installed) => {
            let _ = write_audit_event(AuditEvent::new("daemon_start_command"));
            println!("daemon started via system service (auto-starts on boot)");
        }
        Ok(host_core::service::ServiceStatus::AlreadyRunning) => {
            println!("daemon is already running via system service");
        }
        Ok(host_core::service::ServiceStatus::StartedDaemon) => {
            let _ = write_audit_event(AuditEvent::new("daemon_start_command"));
            println!("daemon started in background");
        }
        Err(e) => {
            return Err(anyhow!("failed to start daemon: {e}"));
        }
    }

    Ok(())
}

fn daemon_stop() -> Result<()> {
    let mut stopped = false;

    // Try stopping via service manager first (does not uninstall — keeps auto-start)
    if host_core::service::is_service_running() {
        host_core::service::uninstall()
            .map_err(|e| anyhow!("failed to stop service: {e}"))?;
        stopped = true;
    }

    // Also check for PID-based daemon
    let paths = AppConfig::paths()?;
    if let Some(pid) = read_pid(&paths.pid_file) {
        if pid_running(pid) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            for _ in 0..20 {
                if !pid_running(pid) { break; }
                std::thread::sleep(Duration::from_millis(100));
            }
            stopped = true;
        }
        let _ = fs::remove_file(&paths.pid_file);
    }

    if stopped {
        let _ = write_audit_event(AuditEvent::new("daemon_stop_command"));
        println!("daemon stopped");
    } else {
        println!("daemon not running");
    }

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

async fn sessions_cmd(config: AppConfig, command: Option<SessionCommands>) -> Result<()> {
    match command {
        Some(SessionCommands::Attach { session_id }) => sessions_attach(session_id),
        None => sessions_list(config).await,
    }
}

async fn sessions_list(config: AppConfig) -> Result<()> {
    let store = StateStore::load().context("loading local state")?;
    store
        .require_logged_in()
        .map_err(|e| anyhow!(e.to_string()))?;

    // Local discoverable sessions (tmux, screen, pocketshell persistent, exposed)
    let local_sessions = SessionDiscovery::discover();

    // Backend active sessions (CONNECTED / DETACHED)
    let backend_sessions = {
        let token = store.access_token()?.to_string();
        let host_id = store.host_id()?;
        let backend = BackendClient::new(config.backend_base_url);
        backend
            .list_active_sessions_full(&token, &host_id)
            .await
            .unwrap_or_else(|e| {
                eprintln!("warning: could not fetch backend sessions: {e}");
                Vec::new()
            })
    };

    // Print backend (active/detached) sessions
    if !backend_sessions.is_empty() {
        println!("Active Sessions (backend):");
        println!(
            "{:<38} {:<12} {:<8} {}",
            "SESSION ID", "STATE", "MODE", "STARTED"
        );
        for s in &backend_sessions {
            let started = s.started_at.as_deref().unwrap_or("-");
            let mode = s.connection_mode.as_deref().unwrap_or("-");
            println!("{:<38} {:<12} {:<8} {}", s.id, s.state, mode, started);
        }
        println!();
    }

    // Print local discoverable sessions
    if !local_sessions.is_empty() {
        println!("Local Sessions (discoverable):");
        println!(
            "{:<12} {:<24} {:<12} {}",
            "TYPE", "NAME", "STATUS", "WINDOWS"
        );
        for s in &local_sessions {
            let status = if s.attached { "attached" } else { "available" };
            println!(
                "{:<12} {:<24} {:<12} {}",
                s.session_type, s.name, status, s.windows
            );
        }
        println!();
    }

    if backend_sessions.is_empty() && local_sessions.is_empty() {
        println!("no sessions found");
        return Ok(());
    }

    // Show hint for resumable sessions
    let ps_sessions: Vec<_> = local_sessions
        .iter()
        .filter(|s| s.session_type == "pocketshell")
        .collect();
    if !ps_sessions.is_empty() {
        println!("Tip: PocketShell persistent sessions can be resumed from mobile.");
        println!("Local CLI attach is still only available for tmux sessions.");
    }

    Ok(())
}

fn sessions_attach(session_id: String) -> Result<()> {
    let tmux_name = if session_id.starts_with("ps-") {
        session_id.clone()
    } else {
        format!("ps-{session_id}")
    };

    // Check if the tmux session exists
    if !SessionDiscovery::tmux_session_exists(&tmux_name) {
        // Also try as a plain tmux session name (non-pocketshell)
        if SessionDiscovery::tmux_session_exists(&session_id) {
            println!("attaching to tmux session '{}'...", session_id);
            let status = Command::new("tmux")
                .args(["attach-session", "-t", &session_id])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .context("failed to run tmux attach")?;
            if !status.success() {
                return Err(anyhow!("tmux attach exited with {}", status));
            }
            return Ok(());
        }
        if SessionDiscovery::discover()
            .iter()
            .any(|s| s.session_type == "pocketshell" && s.name == session_id)
        {
            return Err(anyhow!(
                "local attach is not implemented yet for native PocketShell sessions; resume it from the mobile app instead"
            ));
        }
        return Err(anyhow!(
            "session '{}' not found. Run `pocketshell sessions` to see available sessions.",
            session_id
        ));
    }

    println!("attaching to PocketShell session '{}'...", session_id);
    let status = Command::new("tmux")
        .args(["attach-session", "-t", &tmux_name])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to run tmux attach")?;

    if !status.success() {
        return Err(anyhow!("tmux attach exited with {}", status));
    }

    Ok(())
}

fn remote_cmd(name: String, _detached: bool, list: bool, remove: bool) -> Result<()> {
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
            println!(
                "{:<12} {:<20} {:<10} {}",
                "TYPE", "NAME", "STATUS", "WINDOWS"
            );
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
