use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use host_core::api::BackendClient;
use host_core::config::AppConfig;
use host_core::daemon;
use host_core::models::{AuthState, HostIdentity, LoginRequest};
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
        pairing_code: Option<String>,
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
    let config = AppConfig::from_env();

    match cli.command {
        Commands::Login { email, pairing_code } => login(config, email, pairing_code).await,
        Commands::Status => status(),
        Commands::Devices { command } => devices(config, command).await,
        Commands::Daemon { command } => daemon_cmd(config, command).await,
        Commands::Stats { watch } => stats_cmd(watch).await,
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn login(config: AppConfig, email: Option<String>, pairing_code: Option<String>) -> Result<()> {
    let mut store = StateStore::load().context("loading local state")?;
    let email = email.unwrap_or_else(|| prompt("Email: "));
    let pairing_code = pairing_code.unwrap_or_else(|| prompt("Pairing code: "));

    let hostname =
        std::env::var("HOSTNAME").unwrap_or_else(|_| whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()));
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    let (public_key, private_key) = if let Some(host) = &store.state.host {
        (host.public_key.clone(), host.private_key.clone())
    } else {
        generate_keypair()
    };

    let req = LoginRequest {
        email,
        pairing_code,
        hostname: hostname.clone(),
        platform: platform.clone(),
        app_version: config.app_version.clone(),
        public_key: public_key.clone(),
    };

    let backend = BackendClient::new(config.backend_base_url);
    let res = backend
        .login_host(&req)
        .await
        .context("backend login request failed")?;

    store.state.auth = Some(AuthState {
        access_token: res.access_token,
        refresh_token: res.refresh_token,
        expires_at: res.expires_at,
    });
    store.state.host = Some(HostIdentity {
        host_id: res.host_id,
        hostname,
        platform,
        app_version: config.app_version,
        public_key,
        private_key,
        registered_at: chrono::Utc::now(),
    });
    store.save().context("persisting local state")?;

    println!("login successful");
    Ok(())
}

fn status() -> Result<()> {
    let store = StateStore::load().context("loading local state")?;
    if let Some(host) = store.state.host {
        println!("host_id: {}", host.host_id);
        println!("hostname: {}", host.hostname);
        println!("platform: {}", host.platform);
        println!("trusted_devices: {}", store.state.trusted_devices.len());
        println!("pending_devices: {}", store.state.pending_devices.len());
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
    let backend = BackendClient::new(config.backend_base_url);

    match command {
        DeviceCommands::List => {
            if store.state.trusted_devices.is_empty() {
                println!("no trusted devices");
            } else {
                for d in &store.state.trusted_devices {
                    println!("{}\t{}\t{}", d.device_id, d.device_name, d.platform);
                }
            }
        }
        DeviceCommands::ListPending => {
            if let Ok(pending) = backend.fetch_pending_devices(&token).await {
                store.state.pending_devices = pending;
                let _ = store.save();
            }
            if store.state.pending_devices.is_empty() {
                println!("no pending devices");
            } else {
                for d in &store.state.pending_devices {
                    println!("{}\t{}\t{}", d.device_id, d.device_name, d.platform);
                }
            }
        }
        DeviceCommands::Approve { device_id } => {
            let approved = store
                .approve_device(&device_id)
                .map_err(|e| anyhow!(e.to_string()))?;
            store.save().context("saving state")?;
            backend
                .sync_device_approval(&token, &approved.device_id)
                .await
                .context("syncing approval with backend")?;
            println!("approved device {}", approved.device_id);
        }
        DeviceCommands::Revoke { device_id } => {
            let revoked = store
                .revoke_device(&device_id)
                .map_err(|e| anyhow!(e.to_string()))?;
            store.save().context("saving state")?;
            backend
                .sync_device_revocation(&token, &revoked.device_id)
                .await
                .context("syncing revocation with backend")?;
            println!("revoked device {}", revoked.device_id);
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
