use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use host_core::api::BackendClient;
use host_core::audit::{write_audit_event, AuditEvent};
use host_core::auth::safe_refresh_if_needed;
use host_core::config::AppConfig;
use host_core::daemon;
use host_core::discovery::SessionDiscovery;
use host_core::models::{
    AuthState, HostIdentity, HostInitiatedPollOutcome, PairingValidateRequest,
};
use host_core::secure::parse_jwt_exp;
use host_core::signaling_crypto::sign_pair_attestation;
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
#[command(name = "pocketshell", version)]
#[command(about = "PocketShell host agent")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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
    /// Restart the daemon. Kills the running daemon (service or PID-based)
    /// and starts a fresh one — used to reload state after pairing changes
    /// or after `pocketshell update` swaps the binary on disk.
    Restart,
    /// Update the host agent to the latest release (or `--version`).
    /// Verifies the SHA-256 checksum, the Sigstore cosign keyless signature
    /// (pinned to this repo's release workflow), and on macOS the Developer
    /// ID code signature, then replaces the binary in-place and restarts the
    /// daemon if it's running.
    Update {
        /// Don't apply the update — just report whether one is available.
        #[arg(long)]
        check: bool,
        /// Apply the update even if the local version already matches.
        #[arg(long)]
        force: bool,
        /// Install a specific version (e.g. `0.1.0` or `v0.1.0`) instead of latest.
        #[arg(long)]
        version: Option<String>,
        /// Override the release host base URL (must match the directory
        /// layout described in `host_core::update`).
        #[arg(long, default_value = host_core::update::DEFAULT_BASE_URL)]
        base_url: String,
        /// Skip cosign keyless signature verification. Use only when you have
        /// manually verified the artifact out of band — the SHA-256 check
        /// alone proves integrity against the release origin, not
        /// authenticity. macOS Developer ID verification still runs.
        #[arg(long)]
        insecure_skip_verify: bool,
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
    /// Stop the daemon (if running) and start it again.
    Restart,
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    ensure_supported_platform()?;
    let config = AppConfig::from_env();

    match cli.command {
        None => interactive_menu(config).await,
        Some(Commands::Pair {
            code,
            reset,
            show_qr: _,
        }) => {
            // QR is now the default. --show-qr is accepted (no-op) for backward compat.
            // `code.is_some()` → legacy code-entry flow (preserves existing behavior).
            // Otherwise → QR flow, which auto-picks new-host vs device-add from state.
            if code.is_some() {
                pair(config, code, reset).await
            } else {
                pair_qr(config, reset).await
            }
        }
        Some(Commands::Logout { reset }) => logout(reset),
        Some(Commands::Status) => status(config).await,
        Some(Commands::Devices { command }) => devices(config, command).await,
        Some(Commands::Daemon { command }) => daemon_cmd(config, command).await,
        Some(Commands::Stats { watch }) => stats_cmd(watch).await,
        Some(Commands::Sessions { command }) => sessions_cmd(config, command).await,
        Some(Commands::Restart) => daemon_restart(),
        Some(Commands::Update {
            check,
            force,
            version,
            base_url,
            insecure_skip_verify,
        }) => update_cmd(check, force, version, base_url, insecure_skip_verify).await,
        Some(Commands::Remote {
            name,
            detached,
            list,
            remove,
        }) => remote_cmd(name, detached, list, remove),
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
    if !confirm_root_install() {
        eprintln!("aborted.");
        return Ok(());
    }
    let mut store = StateStore::load().context("loading local state")?;

    // --reset: wipe existing identity so the host can pair with a different account
    if reset {
        if store.state.host.is_some() {
            println!("resetting existing host identity...");
        }
        // Also clear the keyring — otherwise the surviving private key would
        // make the next pair silently reattach to the same backend host record.
        store.clear_secrets();
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

    // Three-way keypair source:
    //   1. state.host present  → reuse persisted keypair (true device-add).
    //   2. state wiped but keyring still holds a private key → reuse it so the
    //      backend can match `(user_id, pubkey)` and reattach to the existing
    //      host instead of creating a duplicate.
    //   3. otherwise            → fresh keypair, fresh host registration.
    let (public_key, private_key) = if let Some(h) = store.state.host.as_ref() {
        (h.public_key.clone(), h.private_key.clone())
    } else if let Some(kp) = store.try_load_host_keypair() {
        println!(
            "reusing existing host keypair from keyring — will reattach if backend recognizes it"
        );
        kp
    } else {
        generate_keypair()
    };

    // Strategy A: a bad-faith backend that swaps `public_key` in the DB
    // cannot forge a fresh signature against the new key without re-signing
    // through the live validate endpoint — that's the threat boundary this
    // attestation tightens. Failure is non-fatal: the legacy "pin-as-backend"
    // path still works, just without the trust upgrade on the mobile side.
    let pair_attestation = sign_pair_attestation(&private_key, &pairing_code, &public_key)
        .map_err(|e| {
            eprintln!("warning: failed to produce pair attestation: {e}");
        })
        .ok();

    let backend = BackendClient::new(config.backend_base_url.clone());
    let result = backend
        .validate_pairing_code(&PairingValidateRequest {
            code: pairing_code,
            hostname: hostname.clone(),
            platform: platform.clone(),
            public_key: public_key.clone(),
            app_version: Some(config.app_version.clone()),
            host_id: existing_host_id.clone(),
            pair_attestation,
        })
        .await;

    let response = match result {
        Ok(r) => r,
        Err(e) if existing_host_id.is_some() => {
            // Legacy code-pair device-add was removed; the backend now 400s on
            // any /codes/validate with host_id set. The other failure mode is
            // a code that belongs to a different account — message covers both.
            eprintln!("error: {e}");
            eprintln!();
            eprintln!("this host is already paired.");
            eprintln!();
            eprintln!("to add another mobile device, open the mobile app and use");
            eprintln!("\"add device\" — it will generate a claim this host approves");
            eprintln!("with its existing credentials (no pairing code required).");
            eprintln!();
            eprintln!("to repair this host onto a different account, run:");
            eprintln!("  pocketshell pair --reset <CODE>");
            return Err(anyhow!("pairing failed — device-add via code is no longer supported; use the mobile app's add-device flow"));
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

    let was_device_add = response.already_paired;
    // Reconnect: backend matched the host by `(user_id, public_key)` even
    // though we sent no host_id. The CLI must persist the rediscovered host
    // identity even though the response is flagged `already_paired`.
    let was_reconnect = response.already_paired && is_new_host;

    if response.already_paired && !was_reconnect {
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
        // New-host flow OR reconnect (state lost, keypair recovered): save
        // host identity and tokens.
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

        if was_reconnect {
            println!(
                "host reattached to existing record {} ({})",
                response.host.hostname, response.host.id
            );
        } else {
            println!(
                "login successful — host registered as {}",
                response.host.hostname
            );
        }
    }

    let host_id = response.host.id.clone();
    let token = response.access_token.clone();
    persist_paired_device(
        &mut store,
        &backend,
        &token,
        &host_id,
        response.mobile_device_id.as_deref(),
        response.device_public_key.as_deref(),
    )
    .await?;

    // Device-add: a daemon is already running with stale in-memory trust.
    // Restart it so it picks up the device we just added.
    if was_device_add && host_core::service::is_service_running() {
        match host_core::service::restart() {
            Ok(_) => println!("daemon restarted to load new trusted device"),
            Err(e) => eprintln!(
                "warning: could not restart daemon ({e}); run `pocketshell daemon stop && pocketshell daemon start` manually"
            ),
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
            Ok(host_core::service::ServiceStatus::InstalledSystem) => {
                println!(" done");
                println!("daemon installed as a boot service and started");
                println!("it will auto-start on boot and restart on crash");
            }
            Ok(host_core::service::ServiceStatus::InstalledWithoutBootPersistence) => {
                println!(" done");
                println!("daemon installed as a systemd user service and started");
                print_boot_persistence_warning();
            }
            Ok(host_core::service::ServiceStatus::InstalledButStartedDaemon) => {
                println!(" done");
                println!("daemon service installed and enabled");
                println!(
                    "daemon started in background because the systemd user bus is unavailable"
                );
                print_boot_persistence_warning();
            }
            Ok(host_core::service::ServiceStatus::AlreadyRunning) => {
                println!(" already running");
            }
            Ok(host_core::service::ServiceStatus::StartedDaemon) => {
                println!(" done");
                println!("daemon started in background");
                println!(
                    "note: service install was not available — daemon won't auto-start on reboot"
                );
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

/// Add only the mobile device from this pairing to the local trust store.
/// The daemon's periodic backend sync never adds devices; it only revokes or
/// updates already-pinned records. If this step fails, pairing must fail
/// visibly instead of leaving a host that is registered but unusable.
async fn persist_paired_device(
    store: &mut StateStore,
    backend: &BackendClient,
    token: &str,
    host_id: &str,
    mobile_device_id: Option<&str>,
    device_public_key: Option<&str>,
) -> Result<String> {
    let mobile_device_id = mobile_device_id.ok_or_else(|| {
        anyhow!(
            "pairing response did not include a mobile_device_id; regenerate the code in the mobile app and retry"
        )
    })?;
    let device_public_key = device_public_key.ok_or_else(|| {
        anyhow!(
            "pairing response did not include the mobile device public key; regenerate the code in the mobile app and retry"
        )
    })?;

    let devices = backend
        .list_trusted_devices(token, host_id)
        .await
        .context("fetching trusted devices after pairing")?;
    let mut paired_device = devices
        .into_iter()
        .find(|d| {
            d.mobile_device_id == mobile_device_id
                && d.approved_at.is_some()
                && d.revoked_at.is_none()
        })
        .ok_or_else(|| {
            anyhow!(
                "backend did not approve mobile device {mobile_device_id} for this host; regenerate the code in the mobile app and retry"
            )
        })?;

    paired_device.device_public_key = Some(device_public_key.to_string());
    store.add_trusted_device(paired_device);
    store
        .save_full()
        .context("persisting paired device with pinned key")?;
    Ok(mobile_device_id.to_string())
}

/// Dispatcher for the QR-based pairing flow. Picks new-host vs device-add based
/// on local state and the `--reset` flag:
///   reset → wipe identity, then new-host
///   paired → device-add
///   not paired → new-host
async fn pair_qr(config: AppConfig, reset: bool) -> Result<()> {
    if !confirm_root_install() {
        eprintln!("aborted.");
        return Ok(());
    }
    let mut store = StateStore::load().context("loading local state")?;

    if reset {
        if store.state.host.is_some() {
            println!("resetting existing host identity...");
        }
        // Also clear the keyring — otherwise the surviving private key would
        // make the next pair silently reattach to the same backend host record.
        store.clear_secrets();
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

    // Try to reuse an existing keypair from the keyring before generating a
    // fresh one. If `state.json` was wiped (reinstall, FS corruption) but the
    // OS keyring still holds the host's private key, sending the matching
    // pubkey lets the backend reattach this host to its existing record by
    // `(user_id, pubkey)` instead of duplicating it.
    let (public_key, private_key) = match store.try_load_host_keypair() {
        Some(kp) => {
            println!("reusing existing host keypair from keyring — will reattach if backend recognizes it");
            kp
        }
        None => generate_keypair(),
    };

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

    let response = claimed
        .ok_or_else(|| anyhow!("timed out waiting for mobile device to scan — please retry"))?;

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

    let host_id = host.id.clone();
    persist_paired_device(
        &mut store,
        &backend,
        &access_token,
        &host_id,
        response.mobile_device_id.as_deref(),
        response.device_public_key.as_deref(),
    )
    .await?;

    println!("pairing successful — host registered as {}", host.hostname);
    println!("host_id: {}", host.id);

    // New-host pairing writes a fresh host id/keypair. If a daemon is already
    // running, it still has the old identity in memory and will reject signed
    // mobile messages with host_id mismatch until restarted.
    if host_core::service::is_service_running() {
        match host_core::service::restart() {
            Ok(_) => println!("daemon restarted to load new host identity"),
            Err(e) => eprintln!(
                "warning: could not restart daemon ({e}); run `pocketshell daemon stop && pocketshell daemon start` manually"
            ),
        }
    }

    // Ensure daemon is running
    if !host_core::service::is_service_running() {
        print!("installing service...");
        let _ = io::stdout().flush();
        match host_core::service::install_and_start() {
            Ok(host_core::service::ServiceStatus::Installed) => {
                println!(" done");
                println!("daemon installed as a system service and started");
            }
            Ok(host_core::service::ServiceStatus::InstalledSystem) => {
                println!(" done");
                println!("daemon installed as a boot service and started");
                println!("it will auto-start on boot and restart on crash");
            }
            Ok(host_core::service::ServiceStatus::InstalledWithoutBootPersistence) => {
                println!(" done");
                println!("daemon installed as a systemd user service and started");
                print_boot_persistence_warning();
            }
            Ok(host_core::service::ServiceStatus::InstalledButStartedDaemon) => {
                println!(" done");
                println!("daemon service installed and enabled");
                println!(
                    "daemon started in background because the systemd user bus is unavailable"
                );
                print_boot_persistence_warning();
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

    // Refresh host access token if it's expiring. Uses the cross-process lock
    // so a CLI invocation while the daemon is also refreshing can't burn the
    // rotation.
    safe_refresh_if_needed(&backend, &mut store)
        .await
        .map_err(|e| {
            anyhow!("host auth expired — re-pair with: pocketshell pair --reset (detail: {e})")
        })?;

    let host = store
        .state
        .host
        .clone()
        .ok_or_else(|| anyhow!("no host identity — cannot run device-add flow"))?;
    let access_token = store.access_token()?.to_string();

    println!("Requesting device-add pairing claim from backend...");
    let claim = match backend
        .start_host_initiated_device_add(&access_token, &host.host_id)
        .await
    {
        Ok(c) => c,
        Err(host_core::error::HostError::HostGone) => {
            // The backend doesn't recognize this host_id under the
            // authenticated user. Don't silently wipe state and re-register
            // — that path was creating duplicate hosts. Force the user to
            // make the choice explicitly via `--reset`.
            return Err(anyhow!(
                "this host's identity is no longer recognized by the backend. \
                 to register as a new host (this will create a fresh host record), \
                 run: pocketshell pair --reset"
            ));
        }
        Err(e) => return Err(e).context("starting host-initiated device-add"),
    };

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

    let mobile_device_id = persist_paired_device(
        &mut store,
        &backend,
        &access_token,
        &host.host_id,
        response.mobile_device_id.as_deref(),
        response.device_public_key.as_deref(),
    )
    .await?;

    let _ = write_audit_event(AuditEvent {
        event_type: "device_approved".to_string(),
        mobile_device_id: Some(mobile_device_id.clone()),
        host_id: Some(host.host_id.clone()),
        ..AuditEvent::new("device_approved")
    });

    println!("device added: {mobile_device_id}");

    // Restart the running daemon so it reloads trusted_devices from disk.
    // Without this, the daemon's in-memory trust list lacks the new device
    // and rejects all signaling from it until the next manual restart.
    if host_core::service::is_service_running() {
        match host_core::service::restart() {
            Ok(_) => println!("daemon restarted to load new trusted device"),
            Err(e) => eprintln!(
                "warning: could not restart daemon ({e}); run `pocketshell daemon stop && pocketshell daemon start` manually"
            ),
        }
    }

    println!("the device can now connect to this host");

    Ok(())
}

fn logout(reset: bool) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;

    // Best-effort server-side revocation BEFORE we wipe local state.
    // Without this the host's 365-day refresh token would remain valid
    // on the backend until natural expiry, defeating the point of
    // logging out. Network failures are non-fatal — the user asked to
    // log out and we should honor that locally regardless.
    if let Some(refresh) = store.state.auth.as_ref().map(|a| a.refresh_token.clone()) {
        if !refresh.is_empty() {
            let cfg = AppConfig::from_env();
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                let api = host_core::api::BackendClient::new(cfg.backend_base_url.clone());
                if let Err(e) = rt.block_on(api.logout(&refresh)) {
                    eprintln!("warning: server-side logout failed: {e}");
                }
            }
        }
    }

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
                if !pid_running(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let _ = fs::remove_file(&paths.pid_file);
    }

    if reset {
        store.state = Default::default();
        // --reset wipes the host identity entirely; clear both long-lived
        // secrets from the keychain so a future re-pair doesn't pick up a
        // stale private key or refresh token.
        store.clear_secrets();
    } else {
        store.state.auth = None;
        // Plain logout: forget the refresh token but keep the host
        // identity (private key) so a re-login from the same host
        // doesn't need a fresh pairing code.
        if let Err(e) = store.clear_refresh_token() {
            eprintln!("warning: could not clear refresh token from keyring: {e}");
        }
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
                        app_version: Some(config.app_version.clone()),
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
            println!(
                "have the mobile user generate a new pairing code, then run pair on this host"
            );
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
        DaemonCommands::Restart => daemon_restart(),
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
        Ok(host_core::service::ServiceStatus::InstalledSystem) => {
            let _ = write_audit_event(AuditEvent::new("daemon_start_command"));
            println!("daemon installed as a boot service and started");
            println!("it will auto-start on boot and restart on crash");
        }
        Ok(host_core::service::ServiceStatus::InstalledWithoutBootPersistence) => {
            let _ = write_audit_event(AuditEvent::new("daemon_start_command"));
            println!("daemon started via systemd user service");
            print_boot_persistence_warning();
        }
        Ok(host_core::service::ServiceStatus::InstalledButStartedDaemon) => {
            let _ = write_audit_event(AuditEvent::new("daemon_start_command"));
            println!("daemon service installed and enabled");
            println!("daemon started in background because the systemd user bus is unavailable");
            print_boot_persistence_warning();
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
        host_core::service::uninstall().map_err(|e| anyhow!("failed to stop service: {e}"))?;
        stopped = true;
    }

    // Also check for PID-based daemon
    let paths = AppConfig::paths()?;
    if let Some(pid) = read_pid(&paths.pid_file) {
        if pid_running(pid) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            for _ in 0..20 {
                if !pid_running(pid) {
                    break;
                }
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

/// Restart the daemon regardless of how it's running. Reuses the service
/// manager when available (launchctl kickstart / systemctl restart) so the
/// auto-start config is preserved; otherwise falls back to killing the
/// PID-based daemon and spawning a fresh detached process.
fn daemon_restart() -> Result<()> {
    use host_core::service::RestartStatus;

    // 1. If a PID-based daemon is alive AND no service is supervising it,
    //    SIGTERM it first. `service::restart()` won't know about it and
    //    would otherwise leave a duplicate running.
    let paths = AppConfig::paths()?;
    let pid = read_pid(&paths.pid_file).filter(|&p| pid_running(p));
    let service_running = host_core::service::is_service_running();
    if let Some(p) = pid {
        if !service_running {
            let _ = kill(Pid::from_raw(p), Signal::SIGTERM);
            for _ in 0..50 {
                if !pid_running(p) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = fs::remove_file(&paths.pid_file);
        }
    }

    let status =
        host_core::service::restart().map_err(|e| anyhow!("failed to restart daemon: {e}"))?;

    let _ = write_audit_event(AuditEvent::new("daemon_restart_command"));

    match status {
        RestartStatus::RestartedService => println!("daemon restarted via system service"),
        RestartStatus::StartedDaemon => println!("daemon restarted as background process"),
    }
    Ok(())
}

async fn update_cmd(
    check_only: bool,
    force: bool,
    version: Option<String>,
    base_url: String,
    insecure_skip_verify: bool,
) -> Result<()> {
    use host_core::update;

    let current_version = env!("CARGO_PKG_VERSION");

    print!("checking for updates ({base_url})...");
    let _ = io::stdout().flush();
    let info = update::check(&base_url, current_version, version.as_deref())
        .await
        .context("checking for update")?;
    println!(" done");

    println!(
        "  current: v{}\n  target:  {}\n  arch:    {}",
        info.current_version, info.target_version, info.target_triple
    );

    if info.up_to_date && !force {
        println!("✓ already on the latest version");
        return Ok(());
    }

    if check_only {
        if info.up_to_date {
            println!("(up to date — pass --force to reinstall)");
        } else {
            println!("update available — run `pocketshell update` to install");
        }
        return Ok(());
    }

    if insecure_skip_verify {
        eprintln!(
            "WARNING: --insecure-skip-verify is set; cosign signature check will be skipped. \
             Only the SHA-256 (same-origin as the release) will be verified."
        );
    }

    println!("downloading and installing...");
    let installed = update::download_and_install_with(
        &info,
        &update::InstallOptions {
            skip_cosign: insecure_skip_verify,
        },
    )
    .await
    .context("installing update")?;

    let _ = write_audit_event(AuditEvent::new("self_update"));

    println!(
        "✓ installed {} → {}",
        info.target_version,
        installed.display()
    );
    println!("  previous binary saved at {}.old", installed.display());

    // The currently-running CLI process is still using the OLD binary in
    // memory; the daemon (separate process) is too. Restart the daemon so
    // it picks up the new code immediately.
    let pid = AppConfig::paths()
        .ok()
        .and_then(|p| read_pid(&p.pid_file))
        .filter(|&p| pid_running(p));
    if host_core::service::is_service_running() || pid.is_some() {
        print!("restarting daemon to load new binary...");
        let _ = io::stdout().flush();
        match daemon_restart() {
            Ok(()) => {}
            Err(e) => {
                println!(" failed");
                eprintln!(
                    "warning: could not auto-restart daemon ({e}); run `pocketshell restart` manually"
                );
            }
        }
    } else {
        println!("(daemon is not running — start it with `pocketshell daemon start`)");
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

    let local_sessions = SessionDiscovery::discover();
    let backend_sessions = fetch_backend_sessions(&config, &store).await;
    print_sessions_overview(&local_sessions, &backend_sessions, true);
    Ok(())
}

async fn fetch_backend_sessions(
    config: &AppConfig,
    store: &StateStore,
) -> Vec<host_core::models::BackendSessionInfo> {
    let Ok(token) = store.access_token() else {
        return Vec::new();
    };
    let Ok(host_id) = store.host_id() else {
        return Vec::new();
    };
    let backend = BackendClient::new(config.backend_base_url.clone());
    backend
        .list_active_sessions_full(token, &host_id)
        .await
        .unwrap_or_else(|e| {
            eprintln!("warning: could not fetch backend sessions: {e}");
            Vec::new()
        })
}

fn print_sessions_overview(
    local: &[host_core::discovery::AvailableSession],
    backend: &[host_core::models::BackendSessionInfo],
    show_attach_tip: bool,
) {
    if !backend.is_empty() {
        println!("Active Sessions (backend):");
        println!(
            "{:<38} {:<12} {:<8} {}",
            "SESSION ID", "STATE", "MODE", "STARTED"
        );
        for s in backend {
            let started = s.started_at.as_deref().unwrap_or("-");
            let mode = s.connection_mode.as_deref().unwrap_or("-");
            println!("{:<38} {:<12} {:<8} {}", s.id, s.state, mode, started);
        }
        println!();
    }

    if !local.is_empty() {
        println!("Local Sessions (discoverable):");
        println!(
            "{:<12} {:<24} {:<12} {}",
            "TYPE", "NAME", "STATUS", "WINDOWS"
        );
        for s in local {
            let status = if s.attached { "attached" } else { "available" };
            println!(
                "{:<12} {:<24} {:<12} {}",
                s.session_type, s.name, status, s.windows
            );
        }
        println!();
    }

    if backend.is_empty() && local.is_empty() {
        println!("no sessions found");
        return;
    }

    if show_attach_tip && local.iter().any(|s| s.session_type == "pocketshell") {
        println!("Tip: Use `pocketshell sessions attach <session-id>` to attach locally.");
        println!("     Sessions can also be resumed from the mobile app.");
    }
}

async fn sessions_attach(session_id: String) -> Result<()> {
    use host_core::local_attach;
    use nix::sys::termios;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let sock_path =
        local_attach::socket_path().map_err(|e| anyhow!("failed to determine socket path: {e}"))?;

    let stream = UnixStream::connect(&sock_path)
        .await
        .context("failed to connect to daemon — is it running? (`pocketshell daemon run`)")?;

    let (mut reader, mut writer) = stream.into_split();

    // Send ATTACH frame with session_id
    let frame = local_attach::encode_frame(local_attach::FRAME_ATTACH, session_id.as_bytes());
    writer
        .write_all(&frame)
        .await
        .context("failed to send attach request")?;

    // Read response frame
    let mut header = [0u8; 5];
    reader
        .read_exact(&mut header)
        .await
        .context("daemon closed connection")?;
    let frame_type = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > local_attach::MAX_FRAME_SIZE {
        return Err(anyhow!("daemon sent oversized frame ({} bytes)", len));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("daemon closed connection")?;
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
    let original_termios =
        termios::tcgetattr(&stdin_handle).context("failed to get terminal attributes")?;
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

    eprintln!(
        "\r\x1b[2K[attached to session {}. Press Ctrl+\\ to detach]",
        session_id
    );

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
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
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

#[derive(Clone, Copy, PartialEq)]
enum MenuAction {
    PairQr,
    TrustedDevices,
    PendingDevices,
    Sessions,
    Status,
    DaemonStart,
    DaemonStop,
    DaemonRestart,
    CheckForUpdate,
    Update,
    Logout,
    Quit,
}

impl MenuAction {
    fn label(self) -> &'static str {
        match self {
            Self::PairQr => "Pair (QR)",
            Self::TrustedDevices => "Trusted devices",
            Self::PendingDevices => "Pending devices",
            Self::Sessions => "Active terminal sessions",
            Self::Status => "Show status",
            Self::DaemonStart => "Daemon: start",
            Self::DaemonStop => "Daemon: stop",
            Self::DaemonRestart => "Daemon: restart",
            Self::CheckForUpdate => "Check for updates",
            Self::Update => "Update host agent",
            Self::Logout => "Logout",
            Self::Quit => "Quit",
        }
    }
}

/// Top-level interactive menu shown when `pocketshell` is run with no
/// subcommand. Every action here is also reachable as an explicit subcommand.
async fn interactive_menu(config: AppConfig) -> Result<()> {
    use console::style;
    use dialoguer::theme::ColorfulTheme;
    use dialoguer::Select;

    let theme = ColorfulTheme::default();
    let backend = BackendClient::new(config.backend_base_url.clone());
    let mut cached_profile: Option<host_core::models::UserProfile> = None;

    loop {
        let store = StateStore::load().context("loading local state")?;

        // Refresh cached profile lazily once per session — avoids a network
        // round-trip on every menu redraw.
        if cached_profile.is_none() && store.state.host.is_some() {
            if let Ok(token) = store.access_token() {
                cached_profile = backend.get_me(token).await.ok();
            }
        }
        print_header(&store, cached_profile.as_ref());

        let actions: &[MenuAction] = if store.state.host.is_some() {
            &[
                MenuAction::PairQr,
                MenuAction::TrustedDevices,
                MenuAction::PendingDevices,
                MenuAction::Sessions,
                MenuAction::Status,
                MenuAction::DaemonStart,
                MenuAction::DaemonStop,
                MenuAction::DaemonRestart,
                MenuAction::CheckForUpdate,
                MenuAction::Update,
                MenuAction::Logout,
                MenuAction::Quit,
            ]
        } else {
            // Pre-pairing menu still gets `Update` so users can self-upgrade
            // before finishing setup (e.g. install.sh ran a stale version).
            &[
                MenuAction::PairQr,
                MenuAction::Status,
                MenuAction::CheckForUpdate,
                MenuAction::Update,
                MenuAction::Quit,
            ]
        };
        let labels: Vec<&str> = actions.iter().map(|a| a.label()).collect();

        let selection = Select::with_theme(&theme)
            .with_prompt("What would you like to do?")
            .items(&labels)
            .default(0)
            .interact_opt()
            .map_err(|e| anyhow!("menu error: {e}"))?;

        let Some(idx) = selection else { return Ok(()) };
        let action = actions[idx];
        if action == MenuAction::Quit {
            return Ok(());
        }

        println!();
        let result: Result<()> = match action {
            MenuAction::PairQr => pair_qr(config.clone(), false).await,
            MenuAction::TrustedDevices => {
                menu_trusted_devices(&theme, config.clone(), &store).await
            }
            MenuAction::PendingDevices => {
                devices(config.clone(), DeviceCommands::ListPending).await
            }
            MenuAction::Sessions => menu_sessions(&theme, &config, &store).await,
            MenuAction::Status => status(config.clone()).await,
            MenuAction::DaemonStart => daemon_start(),
            MenuAction::DaemonStop => daemon_stop(),
            MenuAction::DaemonRestart => daemon_restart(),
            MenuAction::CheckForUpdate => {
                update_cmd(
                    true,
                    false,
                    None,
                    host_core::update::DEFAULT_BASE_URL.to_string(),
                    false,
                )
                .await
            }
            MenuAction::Update => menu_update(&theme).await,
            MenuAction::Logout => menu_logout(&theme),
            MenuAction::Quit => unreachable!(),
        };

        // Logout/pair changes account context — invalidate cached profile.
        if matches!(action, MenuAction::Logout | MenuAction::PairQr) {
            cached_profile = None;
        }

        if let Err(e) = result {
            eprintln!("{} {}", style("error:").red().bold(), e);
        }

        println!();
        prompt(
            &style(format!(
                "[{}] complete — press Enter to return to menu",
                action.label()
            ))
            .dim()
            .to_string(),
        );
    }
}

fn print_header(store: &StateStore, profile: Option<&host_core::models::UserProfile>) {
    use console::style;

    println!();
    println!(
        "{} {}",
        style("PocketShell").cyan().bold(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim()
    );

    let Some(host) = &store.state.host else {
        println!(
            "  {}",
            style("not paired — pair this host to get started").yellow()
        );
        println!();
        return;
    };

    println!(
        "  host: {}  ({})",
        style(&host.hostname).bold(),
        style(&host.platform).dim()
    );
    println!("  host_id: {}", style(&host.host_id).dim());
    match profile {
        Some(p) => println!("  account: {}", style(&p.email).green()),
        None => println!(
            "  account: {} {}",
            style(&host.user_id).dim(),
            style("(offline)").yellow()
        ),
    }
    println!("  daemon: {}", daemon_status_label());
    println!("  trusted devices: {}", store.state.trusted_devices.len());
    println!();
}

fn daemon_status_label() -> String {
    use console::style;

    if host_core::service::is_service_running() {
        return style("running (service)").green().to_string();
    }
    let Ok(paths) = AppConfig::paths() else {
        return style("unknown").dim().to_string();
    };
    match read_pid(&paths.pid_file) {
        Some(pid) if pid_running(pid) => style(format!("running (pid {pid})")).green().to_string(),
        _ => style("stopped").red().to_string(),
    }
}

/// Render a `Select` with a trailing "← back" row. Returns `Ok(None)` when the
/// user picks back, presses Esc, or sends Ctrl+C.
fn select_with_back(
    theme: &dialoguer::theme::ColorfulTheme,
    prompt: &str,
    items: &[String],
) -> Result<Option<usize>> {
    use console::style;
    use dialoguer::Select;

    let mut with_back = items.to_vec();
    with_back.push(style("← back").dim().to_string());

    let pick = Select::with_theme(theme)
        .with_prompt(prompt)
        .items(&with_back)
        .default(with_back.len() - 1)
        .interact_opt()
        .map_err(|e| anyhow!("menu error: {e}"))?;

    Ok(pick.filter(|&i| i < items.len()))
}

async fn menu_trusted_devices(
    theme: &dialoguer::theme::ColorfulTheme,
    config: AppConfig,
    store: &StateStore,
) -> Result<()> {
    use dialoguer::Confirm;

    let trusted = &store.state.trusted_devices;
    if trusted.is_empty() {
        println!("no trusted devices");
        return Ok(());
    }

    let items: Vec<String> = trusted
        .iter()
        .map(|d| {
            let key = if d.device_public_key.is_some() {
                "key=yes"
            } else {
                "key=no"
            };
            format!("{}  {}  created={}", d.mobile_device_id, key, d.created_at)
        })
        .collect();

    let Some(idx) = select_with_back(theme, "Select a device to revoke", &items)? else {
        return Ok(());
    };

    let device_id = trusted[idx].mobile_device_id.clone();
    let confirm = Confirm::with_theme(theme)
        .with_prompt(format!("Revoke device {device_id}?"))
        .default(false)
        .interact_opt()
        .map_err(|e| anyhow!("confirm error: {e}"))?;

    if confirm != Some(true) {
        return Ok(());
    }
    devices(config, DeviceCommands::Revoke { device_id }).await
}

async fn menu_sessions(
    theme: &dialoguer::theme::ColorfulTheme,
    config: &AppConfig,
    store: &StateStore,
) -> Result<()> {
    let local = SessionDiscovery::discover();
    let backend = fetch_backend_sessions(config, store).await;
    print_sessions_overview(&local, &backend, false);

    // Only `pocketshell` sessions are attachable via the local Unix socket.
    let attachable: Vec<&host_core::discovery::AvailableSession> = local
        .iter()
        .filter(|s| s.session_type == "pocketshell")
        .collect();
    if attachable.is_empty() {
        return Ok(());
    }

    let items: Vec<String> = attachable
        .iter()
        .map(|s| {
            let status = if s.attached { "attached" } else { "available" };
            format!("{} ({})", s.name, status)
        })
        .collect();

    let Some(idx) = select_with_back(theme, "Attach to a session?", &items)? else {
        return Ok(());
    };
    sessions_attach(attachable[idx].name.clone()).await
}

async fn menu_update(theme: &dialoguer::theme::ColorfulTheme) -> Result<()> {
    use dialoguer::Confirm;
    use host_core::update;

    let current = env!("CARGO_PKG_VERSION");
    let info = update::check(update::DEFAULT_BASE_URL, current, None)
        .await
        .context("checking for update")?;

    println!(
        "  current: v{}\n  latest:  {}\n  arch:    {}",
        info.current_version, info.target_version, info.target_triple
    );

    if info.up_to_date {
        let force = Confirm::with_theme(theme)
            .with_prompt("Already up to date — reinstall anyway?")
            .default(false)
            .interact_opt()
            .map_err(|e| anyhow!("confirm error: {e}"))?
            .unwrap_or(false);
        if !force {
            return Ok(());
        }
        return update_cmd(
            false,
            true,
            None,
            update::DEFAULT_BASE_URL.to_string(),
            false,
        )
        .await;
    }

    let proceed = Confirm::with_theme(theme)
        .with_prompt(format!(
            "Install {} (will replace this binary and restart the daemon)?",
            info.target_version
        ))
        .default(true)
        .interact_opt()
        .map_err(|e| anyhow!("confirm error: {e}"))?
        .unwrap_or(false);
    if !proceed {
        println!("update cancelled");
        return Ok(());
    }
    update_cmd(
        false,
        false,
        None,
        update::DEFAULT_BASE_URL.to_string(),
        false,
    )
    .await
}

fn menu_logout(theme: &dialoguer::theme::ColorfulTheme) -> Result<()> {
    use dialoguer::Confirm;

    let reset = Confirm::with_theme(theme)
        .with_prompt("Also reset host identity? (use this to switch accounts)")
        .default(false)
        .interact_opt()
        .map_err(|e| anyhow!("confirm error: {e}"))?
        .unwrap_or(false);

    logout(reset)
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

fn print_boot_persistence_warning() {
    let user = whoami::fallible::username().unwrap_or_else(|_| "<this-user>".to_string());
    println!(
        "warning: boot/logout auto-start was not confirmed; run: sudo loginctl enable-linger {user}"
    );
}

/// If invoked as root (sudo), ask the user whether to continue. Returns true
/// to proceed, false if the user declined.
fn confirm_root_install() -> bool {
    use nix::unistd::Uid;
    if !Uid::effective().is_root() {
        return true;
    }
    eprintln!("warning: you are running PocketShell as root.");
    let answer = prompt("Do you want to continue? [y/N]: ");
    let proceed = matches!(answer.to_lowercase().as_str(), "y" | "yes");
    if proceed {
        std::env::set_var("POCKETSHELL_ALLOW_ROOT", "1");
    }
    proceed
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
