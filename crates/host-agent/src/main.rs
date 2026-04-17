use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use host_core::api::BackendClient;
use host_core::audit::{write_audit_event, AuditEvent};
use host_core::config::AppConfig;
use host_core::daemon;
use host_core::discovery::SessionDiscovery;
use host_core::models::{AuthState, HostIdentity, HostInitiatedPollOutcome, PairingValidateRequest};
use host_core::secure::{parse_jwt_exp, require_refresh_token, token_is_expiring};
use host_core::stats::StatsCollector;
use host_core::store::StateStore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use rand::rngs::OsRng;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
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
    /// Pair this host with the mobile app.
    ///
    /// With no args: displays a QR code for the mobile app to scan (new-host if
    /// not yet paired, device-add if already paired).
    /// With a code: validates the pairing code from the mobile app (legacy flow;
    /// also auto-detects new-host vs device-add from local state).
    /// Use --reset to wipe existing pairing and start fresh (e.g. switching accounts).
    Pair {
        /// Pairing code displayed in the mobile app (optional — omit for QR flow)
        code: Option<String>,
        /// Clear existing host identity before pairing (use when switching accounts)
        #[arg(long)]
        reset: bool,
        /// Deprecated: QR is now the default. Accepted for backward compatibility.
        #[arg(long, hide = true)]
        show_qr: bool,
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
    /// Attach locally to an active terminal session on this host
    Attach {
        /// Session ID to attach to
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
        Commands::Pair { code, reset, show_qr: _ } => {
            // QR is now the default. --show-qr is accepted (no-op) for backward compat.
            // `code.is_some()` → legacy code-entry flow (preserves existing behavior).
            // Otherwise → QR flow, which auto-picks new-host vs device-add from state.
            if code.is_some() {
                pair(config, code, reset).await
            } else {
                pair_qr(config, reset).await
            }
        }
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
            host_id: Some(response.host.id.clone()),
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
            host_id: Some(response.host.id.clone()),
            ..AuditEvent::new("login_success")
        });

        println!(
            "login successful — host registered as {}",
            response.host.hostname
        );
    }

    // Add ONLY the device from this pairing to the local trust store.
    // This is the sole path for adding trusted devices — the daemon's periodic
    // sync only handles revocations, never adds new devices.
    let host_id = response.host.id.clone();
    let token = response.access_token.clone();
    if let (Some(ref device_key), Some(ref mid)) =
        (&response.device_public_key, &response.mobile_device_id)
    {
        if let Ok(devices) = backend.list_trusted_devices(&token, &host_id).await {
            // Find the exact device record that was just paired
            if let Some(mut paired_device) = devices.into_iter().find(|d| {
                d.mobile_device_id == *mid
                    && d.approved_at.is_some()
                    && d.revoked_at.is_none()
            }) {
                paired_device.device_public_key = Some(device_key.clone());
                store.add_trusted_device(paired_device);
                store.save().context("persisting paired device with pinned key")?;
            }
        }
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

/// Dispatcher for the QR-based pairing flow. Picks new-host vs device-add based
/// on local state and the `--reset` flag:
///   reset → wipe identity, then new-host
///   paired → device-add
///   not paired → new-host
async fn pair_qr(config: AppConfig, reset: bool) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;

    if reset && store.state.host.is_some() {
        println!("resetting existing host identity...");
        store.state = Default::default();
        store.save().context("persisting reset state")?;
    }

    if store.state.host.is_some() {
        pair_qr_device_add(config, store).await
    } else {
        pair_qr_new_host(config, store).await
    }
}

async fn pair_qr_new_host(config: AppConfig, mut store: StateStore) -> Result<()> {
    use qrcode::render::unicode;
    use qrcode::{EcLevel, QrCode};

    // Always new-host: generate a fresh keypair
    let (public_key, private_key) = generate_keypair();

    let hostname = std::env::var("HOSTNAME")
        .unwrap_or_else(|_| whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()));
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    println!("Requesting pairing claim from backend...");
    let backend = BackendClient::new(config.backend_base_url.clone());
    let claim = backend
        .start_host_initiated(&hostname, &platform, &public_key, &config.app_version)
        .await
        .context("starting host-initiated pairing")?;

    // Build QR payload. Short keys used to keep QR small for low EC level.
    let payload = serde_json::json!({
        "v": 1,
        "mode": "host_init",
        "token": claim.claim_token,
        "pubkey": public_key,
        "hostname": hostname,
        "platform": platform,
        "bu": config.backend_base_url,
    });
    let payload_str = serde_json::to_string(&payload)?;

    let code = QrCode::with_error_correction_level(payload_str.as_bytes(), EcLevel::L)
        .context("rendering QR code")?;
    let rendered = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();

    println!();
    println!("{rendered}");
    println!();
    println!(
        "QR expires at {}. Scan from the PocketShell mobile app (Hosts -> Add via QR).",
        claim.expires_at
    );
    println!();

    // Poll every 2s up to 5 minutes
    const POLL_INTERVAL: Duration = Duration::from_secs(2);
    const MAX_ATTEMPTS: usize = 150; // 5 minutes / 2s

    print!("Waiting for mobile device to scan");
    let _ = io::stdout().flush();

    let mut claimed: Option<host_core::models::HostInitiatedStatusResponse> = None;
    for _ in 0..MAX_ATTEMPTS {
        sleep(POLL_INTERVAL).await;
        match backend.poll_host_initiated_status(&claim.claim_token).await {
            Ok(HostInitiatedPollOutcome::Pending) => {
                print!(".");
                let _ = io::stdout().flush();
            }
            Ok(HostInitiatedPollOutcome::Claimed(body)) => {
                println!();
                claimed = Some(*body);
                break;
            }
            Ok(HostInitiatedPollOutcome::AlreadyDelivered) => {
                println!();
                return Err(anyhow!(
                    "pairing claim was already delivered (possible race or replay)"
                ));
            }
            Ok(HostInitiatedPollOutcome::Expired) => {
                println!();
                return Err(anyhow!(
                    "pairing claim expired or is invalid — please retry"
                ));
            }
            Err(e) => {
                // Transient errors: keep trying until timeout
                tracing::debug!("poll error: {e}");
                print!("?");
                let _ = io::stdout().flush();
            }
        }
    }

    let response = claimed.ok_or_else(|| {
        anyhow!("timed out waiting for mobile device to scan — please retry")
    })?;

    let host = response
        .host
        .ok_or_else(|| anyhow!("claimed response missing host"))?;
    let access_token = response
        .access_token
        .ok_or_else(|| anyhow!("claimed response missing access_token"))?;
    let refresh_token = response
        .refresh_token
        .ok_or_else(|| anyhow!("claimed response missing refresh_token"))?;

    // Persist auth + host identity
    store.state.auth = Some(AuthState {
        access_token: access_token.clone(),
        refresh_token,
        access_expires_at: parse_jwt_exp(&access_token),
    });
    store.state.host = Some(HostIdentity {
        host_id: host.id.clone(),
        user_id: host.user_id.clone(),
        hostname,
        platform,
        app_version: config.app_version.clone(),
        public_key,
        private_key,
        registered_at: chrono::Utc::now(),
    });
    store.save().context("persisting local state")?;

    let _ = write_audit_event(AuditEvent {
        event_type: "login_success".to_string(),
        host_id: Some(host.id.clone()),
        ..AuditEvent::new("login_success")
    });

    // Add the trusted device (mirror existing pair flow)
    let host_id = host.id.clone();
    if let (Some(device_key), Some(mid)) = (
        response.device_public_key.as_ref(),
        response.mobile_device_id.as_ref(),
    ) {
        if let Ok(devices) = backend.list_trusted_devices(&access_token, &host_id).await {
            if let Some(mut paired_device) = devices.into_iter().find(|d| {
                d.mobile_device_id == *mid
                    && d.approved_at.is_some()
                    && d.revoked_at.is_none()
            }) {
                paired_device.device_public_key = Some(device_key.clone());
                store.add_trusted_device(paired_device);
                store
                    .save()
                    .context("persisting paired device with pinned key")?;
            }
        }
    }

    println!("pairing successful — host registered as {}", host.hostname);
    println!("host_id: {}", host.id);

    // Ensure daemon is running
    if !host_core::service::is_service_running() {
        print!("installing service...");
        let _ = io::stdout().flush();
        match host_core::service::install_and_start() {
            Ok(host_core::service::ServiceStatus::Installed) => {
                println!(" done");
                println!("daemon installed as a system service and started");
            }
            Ok(host_core::service::ServiceStatus::AlreadyRunning) => {
                println!(" already running");
            }
            Ok(host_core::service::ServiceStatus::StartedDaemon) => {
                println!(" done");
                println!("daemon started in background");
            }
            Err(e) => {
                println!(" failed ({e})");
                println!("start the daemon manually with: pocketshell daemon start");
            }
        }
    }

    Ok(())
}

/// Device-add QR flow: an already-paired host displays a QR to enroll a new
/// mobile device. Uses the host's existing keypair + access token.
async fn pair_qr_device_add(config: AppConfig, mut store: StateStore) -> Result<()> {
    use qrcode::render::unicode;
    use qrcode::{EcLevel, QrCode};

    let backend = BackendClient::new(config.backend_base_url.clone());

    // Refresh host access token if it's expiring — mirrors daemon logic.
    refresh_auth_if_needed(&backend, &mut store).await.map_err(|e| {
        anyhow!(
            "host auth expired — re-pair with: pocketshell pair --reset (detail: {e})"
        )
    })?;

    let host = store
        .state
        .host
        .clone()
        .ok_or_else(|| anyhow!("no host identity — cannot run device-add flow"))?;
    let access_token = store.access_token()?.to_string();

    println!("Requesting device-add pairing claim from backend...");
    let claim = backend
        .start_host_initiated_device_add(&access_token, &host.host_id)
        .await
        .context("starting host-initiated device-add")?;

    // QR payload includes host_id (device-add marker) and the existing host's
    // pubkey so mobile can verify continuity with any previously pinned key.
    let payload = serde_json::json!({
        "v": 1,
        "mode": "host_init",
        "token": claim.claim_token,
        "pubkey": host.public_key,
        "hostname": host.hostname,
        "platform": host.platform,
        "bu": config.backend_base_url,
        "host_id": host.host_id,
    });
    let payload_str = serde_json::to_string(&payload)?;

    let code = QrCode::with_error_correction_level(payload_str.as_bytes(), EcLevel::L)
        .context("rendering QR code")?;
    let rendered = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();

    println!();
    println!("{rendered}");
    println!();
    println!(
        "Scan to add this device to existing host {}. Device will be approved automatically.",
        host.hostname
    );
    println!("QR expires at {}.", claim.expires_at);
    println!();

    const POLL_INTERVAL: Duration = Duration::from_secs(2);
    const MAX_ATTEMPTS: usize = 150; // 5 minutes / 2s

    print!("Waiting for mobile device to scan");
    let _ = io::stdout().flush();

    let mut claimed: Option<host_core::models::HostInitiatedStatusResponse> = None;
    for _ in 0..MAX_ATTEMPTS {
        sleep(POLL_INTERVAL).await;
        match backend.poll_host_initiated_status(&claim.claim_token).await {
            Ok(HostInitiatedPollOutcome::Pending) => {
                print!(".");
                let _ = io::stdout().flush();
            }
            Ok(HostInitiatedPollOutcome::Claimed(body)) => {
                println!();
                claimed = Some(*body);
                break;
            }
            Ok(HostInitiatedPollOutcome::AlreadyDelivered) => {
                println!();
                return Err(anyhow!(
                    "pairing claim was already delivered (possible race or replay)"
                ));
            }
            Ok(HostInitiatedPollOutcome::Expired) => {
                println!();
                return Err(anyhow!(
                    "pairing claim expired or is invalid — please retry"
                ));
            }
            Err(e) => {
                tracing::debug!("poll error: {e}");
                print!("?");
                let _ = io::stdout().flush();
            }
        }
    }

    let response = claimed
        .ok_or_else(|| anyhow!("timed out waiting for mobile device to scan — please retry"))?;

    // Sanity-check the claim mode — device-add claims must not come back as new_host.
    if let Some(ref mode) = response.mode {
        if mode != "device_add" {
            return Err(anyhow!(
                "backend returned unexpected claim mode '{}' for device-add flow",
                mode
            ));
        }
    }

    let mobile_device_id = response
        .mobile_device_id
        .ok_or_else(|| anyhow!("claimed response missing mobile_device_id"))?;
    let device_public_key = response.device_public_key.clone();

    // Sync trusted-device list from backend and persist the newly added device.
    if let Ok(devices) = backend
        .list_trusted_devices(&access_token, &host.host_id)
        .await
    {
        if let Some(mut paired_device) = devices.into_iter().find(|d| {
            d.mobile_device_id == mobile_device_id
                && d.approved_at.is_some()
                && d.revoked_at.is_none()
        }) {
            if let Some(ref key) = device_public_key {
                paired_device.device_public_key = Some(key.clone());
            }
            store.add_trusted_device(paired_device);
            store
                .save()
                .context("persisting paired device with pinned key")?;
        }
    }

    let _ = write_audit_event(AuditEvent {
        event_type: "device_approved".to_string(),
        mobile_device_id: Some(mobile_device_id.clone()),
        host_id: Some(host.host_id.clone()),
        ..AuditEvent::new("device_approved")
    });

    println!("device added: {mobile_device_id}");
    println!("the device can now connect to this host");

    Ok(())
}

/// Refresh the host's access token if it's close to expiring. Mirrors the
/// daemon's `refresh_auth_if_needed` so CLI device-add works when the daemon
/// isn't the one driving refresh.
async fn refresh_auth_if_needed(
    backend: &BackendClient,
    store: &mut StateStore,
) -> Result<()> {
    let Some(auth) = store.state.auth.clone() else {
        return Err(anyhow!("not logged in"));
    };
    if !token_is_expiring(auth.access_expires_at, 60) {
        return Ok(());
    }
    let refresh = require_refresh_token(&auth).map_err(|e| anyhow!(e.to_string()))?;
    let tokens = backend
        .refresh_tokens(&refresh)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    let expires = parse_jwt_exp(&tokens.access_token);
    store.state.auth = Some(AuthState {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        access_expires_at: expires,
    });
    store.save().context("persisting refreshed tokens")?;
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
            // Show locally trusted devices (only devices paired via `pocketshell pair`)
            if store.state.trusted_devices.is_empty() {
                println!("no trusted devices");
            } else {
                for d in &store.state.trusted_devices {
                    let has_key = if d.device_public_key.is_some() {
                        "key=yes"
                    } else {
                        "key=no"
                    };
                    println!(
                        "{}\t{}\tcreated={}",
                        d.mobile_device_id, has_key, d.created_at
                    );
                }
            }
        }
        DeviceCommands::ListPending => {
            // Pending devices on backend — these must be paired via `pocketshell pair`
            let all = backend
                .list_trusted_devices(&token, &host_id)
                .await
                .context("fetching devices from backend")?;
            let pending: Vec<_> = all
                .iter()
                .filter(|d| d.approved_at.is_none() && d.revoked_at.is_none())
                .collect();

            if pending.is_empty() {
                println!("no pending devices");
            } else {
                for d in &pending {
                    println!("{}\tpending_since={}", d.mobile_device_id, d.created_at);
                }
            }
        }
        DeviceCommands::Approve { device_id: _ } => {
            // In the new security model, devices can only be approved via `pocketshell pair`.
            // The approve command is kept for backward compatibility but now instructs the user.
            println!("device approval is now done via `pocketshell pair <CODE>`");
            println!("have the mobile user generate a new pairing code, then run pair on this host");
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
        Some(SessionCommands::Attach { session_id }) => sessions_attach(session_id).await,
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
        println!("Tip: Use `pocketshell sessions attach <session-id>` to attach locally.");
        println!("     Sessions can also be resumed from the mobile app.");
    }

    Ok(())
}

async fn sessions_attach(session_id: String) -> Result<()> {
    use host_core::local_attach;
    use nix::sys::termios;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let sock_path = local_attach::socket_path()
        .map_err(|e| anyhow!("failed to determine socket path: {e}"))?;

    let stream = UnixStream::connect(&sock_path)
        .await
        .context("failed to connect to daemon — is it running? (`pocketshell daemon run`)")?;

    let (mut reader, mut writer) = stream.into_split();

    // Send ATTACH frame with session_id
    let frame = local_attach::encode_frame(
        local_attach::FRAME_ATTACH,
        session_id.as_bytes(),
    );
    writer.write_all(&frame).await.context("failed to send attach request")?;

    // Read response frame
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await.context("daemon closed connection")?;
    let frame_type = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > local_attach::MAX_FRAME_SIZE {
        return Err(anyhow!("daemon sent oversized frame ({} bytes)", len));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await.context("daemon closed connection")?;
    }

    if frame_type == local_attach::FRAME_ERROR {
        let msg = String::from_utf8_lossy(&payload);
        return Err(anyhow!("{}", msg));
    }
    if frame_type != local_attach::FRAME_ATTACHED_OK {
        return Err(anyhow!("unexpected response from daemon"));
    }

    // Put terminal in raw mode
    let stdin_handle = std::io::stdin();
    let original_termios = termios::tcgetattr(&stdin_handle).context("failed to get terminal attributes")?;
    let mut raw = original_termios.clone();
    termios::cfmakeraw(&mut raw);
    termios::tcsetattr(&stdin_handle, termios::SetArg::TCSANOW, &raw)
        .context("failed to set raw mode")?;

    // Write scrollback (the payload of ATTACHED_OK) to stdout
    if !payload.is_empty() {
        let mut stdout = tokio::io::stdout();
        let _ = stdout.write_all(&payload).await;
        let _ = stdout.flush().await;
    }

    eprintln!("\r\x1b[2K[attached to session {}. Press Ctrl+\\ to detach]", session_id);

    // Send initial terminal size
    {
        let (cols, rows) = term_size();
        let mut resize_payload = [0u8; 4];
        resize_payload[0..2].copy_from_slice(&cols.to_be_bytes());
        resize_payload[2..4].copy_from_slice(&rows.to_be_bytes());
        let frame = local_attach::encode_frame(local_attach::FRAME_RESIZE, &resize_payload);
        let _ = writer.write_all(&frame).await;
    }

    // Set up SIGWINCH handler
    let mut sigwinch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .context("failed to register SIGWINCH handler")?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_buf = vec![0u8; 4096];
    let mut read_header = [0u8; 5];

    let result: Result<()> = async {
        loop {
            tokio::select! {
                // Read from daemon → write to stdout
                res = reader.read_exact(&mut read_header) => {
                    res.context("daemon disconnected")?;
                    let ft = read_header[0];
                    let plen = u32::from_be_bytes([read_header[1], read_header[2], read_header[3], read_header[4]]) as usize;
                    if plen > local_attach::MAX_FRAME_SIZE {
                        return Err(anyhow!("daemon sent oversized frame"));
                    }
                    let mut pbuf = vec![0u8; plen];
                    if plen > 0 {
                        reader.read_exact(&mut pbuf).await.context("daemon disconnected")?;
                    }
                    match ft {
                        local_attach::FRAME_TERMINAL_DATA => {
                            stdout.write_all(&pbuf).await?;
                            stdout.flush().await?;
                        }
                        local_attach::FRAME_ERROR => {
                            let msg = String::from_utf8_lossy(&pbuf);
                            return Err(anyhow!("daemon error: {}", msg));
                        }
                        _ => {}
                    }
                }
                // Read from stdin → send to daemon
                res = stdin.read(&mut stdin_buf) => {
                    let n = res.context("stdin read failed")?;
                    if n == 0 { break; }
                    let data = &stdin_buf[..n];

                    // Check for Ctrl+\ (0x1c) to detach
                    if data.contains(&0x1c) {
                        let detach_frame = local_attach::encode_frame(local_attach::FRAME_DETACH, &[]);
                        let _ = writer.write_all(&detach_frame).await;
                        break;
                    }

                    let frame = local_attach::encode_frame(local_attach::FRAME_TERMINAL_DATA, data);
                    writer.write_all(&frame).await.context("failed to send input to daemon")?;
                }
                // Handle SIGWINCH
                _ = sigwinch.recv() => {
                    let (cols, rows) = term_size();
                    let mut resize_payload = [0u8; 4];
                    resize_payload[0..2].copy_from_slice(&cols.to_be_bytes());
                    resize_payload[2..4].copy_from_slice(&rows.to_be_bytes());
                    let frame = local_attach::encode_frame(local_attach::FRAME_RESIZE, &resize_payload);
                    let _ = writer.write_all(&frame).await;
                }
            }
        }
        Ok(())
    }.await;

    // Restore terminal
    let _ = termios::tcsetattr(&stdin_handle, termios::SetArg::TCSANOW, &original_termios);
    eprintln!("\r\n[detached from session {}]", session_id);

    result
}

fn term_size() -> (u16, u16) {
    use nix::libc;
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
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
