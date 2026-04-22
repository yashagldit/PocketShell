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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::HOME_LOCK as ENV_LOCK;

    const ALL_VARS: &[&str] = &[
        "POCKETSHELL_BACKEND_URL",
        "POCKETSHELL_WS_URL",
        "POCKETSHELL_APP_VERSION",
        "POCKETSHELL_MIN_HOST_VERSION",
        "POCKETSHELL_HEARTBEAT_SECS",
        "POCKETSHELL_STATS_SECS",
        "POCKETSHELL_SESSION_LIMIT",
        "POCKETSHELL_STALE_SESSION_SECS",
        "POCKETSHELL_DETACH_MAX_SECS",
        "POCKETSHELL_ALERT_CHECK_SECS",
    ];

    fn clear_all() {
        for v in ALL_VARS {
            // SAFETY: tests serialize via ENV_LOCK.
            unsafe { env::remove_var(v) };
        }
    }

    #[test]
    fn from_env_uses_documented_defaults() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        let cfg = AppConfig::from_env();
        assert_eq!(cfg.backend_base_url, "https://tapi.pocketshell.app");
        assert_eq!(cfg.ws_url, "wss://tapi.pocketshell.app/ws/host");
        assert_eq!(cfg.app_version, "0.1.0");
        assert!(cfg.min_backend_host_version.is_none());
        assert_eq!(cfg.heartbeat_interval_secs, 20);
        assert_eq!(cfg.stats_interval_secs, 5);
        assert_eq!(cfg.session_limit, 8);
        assert_eq!(cfg.stale_session_secs, 300);
        assert_eq!(cfg.detach_max_secs, 86400);
        assert_eq!(cfg.alert_check_interval_secs, 60);
    }

    #[test]
    fn from_env_custom_overrides() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("POCKETSHELL_BACKEND_URL", "https://example.test");
            env::set_var("POCKETSHELL_WS_URL", "wss://example.test/ws");
            env::set_var("POCKETSHELL_APP_VERSION", "9.9.9");
            env::set_var("POCKETSHELL_MIN_HOST_VERSION", "1.2.3");
            env::set_var("POCKETSHELL_HEARTBEAT_SECS", "7");
            env::set_var("POCKETSHELL_STATS_SECS", "11");
            env::set_var("POCKETSHELL_SESSION_LIMIT", "42");
            env::set_var("POCKETSHELL_STALE_SESSION_SECS", "600");
            env::set_var("POCKETSHELL_DETACH_MAX_SECS", "100");
            env::set_var("POCKETSHELL_ALERT_CHECK_SECS", "30");
        }
        let cfg = AppConfig::from_env();
        assert_eq!(cfg.backend_base_url, "https://example.test");
        assert_eq!(cfg.ws_url, "wss://example.test/ws");
        assert_eq!(cfg.app_version, "9.9.9");
        assert_eq!(cfg.min_backend_host_version.as_deref(), Some("1.2.3"));
        assert_eq!(cfg.heartbeat_interval_secs, 7);
        assert_eq!(cfg.stats_interval_secs, 11);
        assert_eq!(cfg.session_limit, 42);
        assert_eq!(cfg.stale_session_secs, 600);
        assert_eq!(cfg.detach_max_secs, 100);
        assert_eq!(cfg.alert_check_interval_secs, 30);
        clear_all();
    }

    #[test]
    fn from_env_invalid_numeric_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        unsafe {
            env::set_var("POCKETSHELL_HEARTBEAT_SECS", "not-a-number");
            env::set_var("POCKETSHELL_SESSION_LIMIT", "-5"); // invalid for usize
        }
        let cfg = AppConfig::from_env();
        assert_eq!(cfg.heartbeat_interval_secs, 20);
        assert_eq!(cfg.session_limit, 8);
        clear_all();
    }

    #[test]
    fn paths_builds_under_home_dir() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        // dirs::home_dir() on unix respects $HOME.
        let prev_home = env::var_os("HOME");
        unsafe { env::set_var("HOME", tmp.path()) };

        let paths = AppConfig::paths().expect("paths should resolve");
        assert_eq!(paths.state_dir, tmp.path().join(".pocketshell"));
        assert_eq!(
            paths.state_file,
            tmp.path().join(".pocketshell").join("state.json")
        );
        assert_eq!(
            paths.pid_file,
            tmp.path().join(".pocketshell").join("daemon.pid")
        );
        assert_eq!(
            paths.log_file,
            tmp.path().join(".pocketshell").join("daemon.log")
        );
        assert_eq!(
            paths.audit_file,
            tmp.path().join(".pocketshell").join("audit.log")
        );

        // restore
        unsafe {
            match prev_home {
                Some(v) => env::set_var("HOME", v),
                None => env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn default_shell_honors_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let prev = env::var_os("SHELL");
        unsafe { env::set_var("SHELL", "/opt/custom/fish") };
        assert_eq!(AppConfig::default_shell(), "/opt/custom/fish");

        unsafe { env::remove_var("SHELL") };
        let fallback = AppConfig::default_shell();
        if cfg!(target_os = "macos") {
            assert_eq!(fallback, "/bin/zsh");
        } else {
            assert_eq!(fallback, "/bin/bash");
        }

        unsafe {
            match prev {
                Some(v) => env::set_var("SHELL", v),
                None => env::remove_var("SHELL"),
            }
        }
    }
}
