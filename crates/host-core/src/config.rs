use crate::error::{HostError, Result};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub backend_base_url: String,
    pub ws_url: String,
    pub app_version: String,
    pub min_backend_host_version: Option<String>,
    pub heartbeat_interval_secs: u64,
    pub stats_interval_secs: u64,
    pub session_limit: usize,
    pub stale_session_secs: u64,
    pub detach_max_secs: u64,
    pub alert_check_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
    pub audit_file: PathBuf,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let backend_base_url = env::var("POCKETSHELL_BACKEND_URL")
            .unwrap_or_else(|_| "https://tapi.pocketshell.app".to_string());
        let ws_url = env::var("POCKETSHELL_WS_URL")
            .unwrap_or_else(|_| "wss://tapi.pocketshell.app/ws/host".to_string());
        let app_version =
            env::var("POCKETSHELL_APP_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
        let min_backend_host_version = env::var("POCKETSHELL_MIN_HOST_VERSION").ok();

        let heartbeat_interval_secs = env::var("POCKETSHELL_HEARTBEAT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);

        let stats_interval_secs = env::var("POCKETSHELL_STATS_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);

        let session_limit = env::var("POCKETSHELL_SESSION_LIMIT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(8);

        let stale_session_secs = env::var("POCKETSHELL_STALE_SESSION_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300);

        let detach_max_secs = env::var("POCKETSHELL_DETACH_MAX_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(86400); // 24 hours default

        let alert_check_interval_secs = env::var("POCKETSHELL_ALERT_CHECK_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);

        Self {
            backend_base_url,
            ws_url,
            app_version,
            min_backend_host_version,
            heartbeat_interval_secs,
            stats_interval_secs,
            session_limit,
            stale_session_secs,
            detach_max_secs,
            alert_check_interval_secs,
        }
    }

    pub fn paths() -> Result<AppPaths> {
        let home = dirs::home_dir()
            .ok_or_else(|| HostError::Config("unable to resolve home directory".to_string()))?;

        let state_dir = home.join(".pocketshell");
        let state_file = state_dir.join("state.json");
        let pid_file = state_dir.join("daemon.pid");
        let log_file = state_dir.join("daemon.log");
        let audit_file = state_dir.join("audit.log");

        Ok(AppPaths {
            state_dir,
            state_file,
            pid_file,
            log_file,
            audit_file,
        })
    }

    pub fn default_shell() -> String {
        std::env::var("SHELL").unwrap_or_else(|_| {
            if cfg!(target_os = "macos") {
                "/bin/zsh".to_string()
            } else {
                "/bin/bash".to_string()
            }
        })
    }
}
