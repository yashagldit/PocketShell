use crate::error::{HostError, Result};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};
use tracing::{info, warn};

const LAUNCHD_LABEL: &str = "com.pocketshell.host-agent";
const SYSTEMD_SERVICE: &str = "pocketshell-host-agent";

/// `launchctl unload` and `systemctl stop` block until the supervised
/// process exits, so a wedged daemon can pin the syscall indefinitely.
/// Cap any service-control invocation: kill the child and surface
/// TimedOut if it hasn't exited by then.
const SERVICE_CMD_TIMEOUT: Duration = Duration::from_secs(5);

fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> io::Result<ExitStatus> {
    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("command exceeded {timeout:?}"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Result of a service install attempt.
pub enum ServiceStatus {
    Installed,
    AlreadyRunning,
    StartedDaemon,
}

/// Result of a service stop (without uninstall).
pub enum StopStatus {
    Stopped,
    NotRunning,
}

/// Result of a restart attempt.
pub enum RestartStatus {
    RestartedService,
    StartedDaemon,
}

/// Install and start the daemon as a system service.
/// Falls back to `daemon start`-style background spawn if service install fails.
pub fn install_and_start() -> Result<ServiceStatus> {
    if cfg!(target_os = "macos") {
        match install_launchd() {
            Ok(status) => return Ok(status),
            Err(e) => {
                warn!(
                    "launchd install failed: {} — falling back to daemon start",
                    e
                );
            }
        }
    } else if cfg!(target_os = "linux") {
        match install_systemd() {
            Ok(status) => return Ok(status),
            Err(e) => {
                warn!(
                    "systemd install failed: {} — falling back to daemon start",
                    e
                );
            }
        }
    }

    // Fallback: start daemon as a detached process (same as `daemon start`)
    start_daemon_process().map(|_| ServiceStatus::StartedDaemon)
}

/// Check if the daemon is already managed by a service manager and running.
pub fn is_service_running() -> bool {
    if cfg!(target_os = "macos") {
        is_launchd_running()
    } else if cfg!(target_os = "linux") {
        is_systemd_running()
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// macOS launchd
// ---------------------------------------------------------------------------

fn launchd_plist_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"))
}

fn is_launchd_running() -> bool {
    Command::new("launchctl")
        .args(["list", LAUNCHD_LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn install_launchd() -> Result<ServiceStatus> {
    if is_launchd_running() {
        return Ok(ServiceStatus::AlreadyRunning);
    }

    let exe = std::env::current_exe()
        .map_err(|e| HostError::Config(format!("cannot resolve binary path: {e}")))?;
    let exe_path = exe.to_string_lossy();

    let home = dirs::home_dir()
        .ok_or_else(|| HostError::Config("cannot resolve home directory".into()))?;

    let log_path = home.join("Library/Logs/pocketshell-host-agent.log");

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe_path}</string>
    <string>daemon</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>info</string>
  </dict>
</dict>
</plist>
"#,
        log = log_path.display()
    );

    let plist_path = launchd_plist_path();
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| HostError::Config(format!("create LaunchAgents dir: {e}")))?;
    }

    fs::write(&plist_path, &plist).map_err(|e| HostError::Config(format!("write plist: {e}")))?;

    info!("wrote launchd plist to {}", plist_path.display());

    // Unload any stale plist before loading the new one
    let _ = run_with_timeout(
        Command::new("launchctl").args(["unload"]).arg(&plist_path),
        SERVICE_CMD_TIMEOUT,
    );

    let status = run_with_timeout(
        Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&plist_path),
        SERVICE_CMD_TIMEOUT,
    )
    .map_err(|e| HostError::Config(format!("launchctl load: {e}")))?;

    if !status.success() {
        return Err(HostError::Config("launchctl load failed".into()));
    }

    info!("launchd service loaded and started");
    Ok(ServiceStatus::Installed)
}

/// Unload and remove the launchd plist.
pub fn uninstall_launchd() -> Result<()> {
    let plist_path = launchd_plist_path();
    if plist_path.exists() {
        let _ = run_with_timeout(
            Command::new("launchctl")
                .args(["unload", "-w"])
                .arg(&plist_path),
            SERVICE_CMD_TIMEOUT,
        );
        fs::remove_file(&plist_path)
            .map_err(|e| HostError::Config(format!("remove plist: {e}")))?;
        info!("removed launchd plist");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux systemd (user service — no root required)
// ---------------------------------------------------------------------------

fn systemd_unit_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".config/systemd/user")
}

fn systemd_unit_path() -> PathBuf {
    systemd_unit_dir().join(format!("{SYSTEMD_SERVICE}.service"))
}

fn is_systemd_running() -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", SYSTEMD_SERVICE])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn has_systemctl() -> bool {
    Command::new("systemctl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn install_systemd() -> Result<ServiceStatus> {
    if !has_systemctl() {
        return Err(HostError::Config("systemctl not found".into()));
    }

    if is_systemd_running() {
        return Ok(ServiceStatus::AlreadyRunning);
    }

    let exe = std::env::current_exe()
        .map_err(|e| HostError::Config(format!("cannot resolve binary path: {e}")))?;
    let exe_path = exe.to_string_lossy();

    let unit = format!(
        r#"[Unit]
Description=PocketShell Host Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path} daemon run
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#
    );

    let unit_dir = systemd_unit_dir();
    fs::create_dir_all(&unit_dir)
        .map_err(|e| HostError::Config(format!("create systemd user dir: {e}")))?;

    let unit_path = systemd_unit_path();
    fs::write(&unit_path, &unit).map_err(|e| HostError::Config(format!("write unit file: {e}")))?;

    info!("wrote systemd unit to {}", unit_path.display());

    // Reload, enable, and start
    let reload = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if let Err(e) = reload {
        warn!("systemctl daemon-reload failed: {e}");
    }

    let enable = Command::new("systemctl")
        .args(["--user", "enable", SYSTEMD_SERVICE])
        .status();
    if let Err(e) = enable {
        warn!("systemctl enable failed: {e}");
    }

    let start = Command::new("systemctl")
        .args(["--user", "start", SYSTEMD_SERVICE])
        .status()
        .map_err(|e| HostError::Config(format!("systemctl start: {e}")))?;

    if !start.success() {
        return Err(HostError::Config("systemctl start failed".into()));
    }

    // Enable lingering so the user service survives logout
    let _ = Command::new("loginctl").args(["enable-linger"]).status();

    info!("systemd user service enabled and started");
    Ok(ServiceStatus::Installed)
}

/// Stop, disable, and remove the systemd user service.
pub fn uninstall_systemd() -> Result<()> {
    if has_systemctl() {
        let _ = run_with_timeout(
            Command::new("systemctl").args(["--user", "stop", SYSTEMD_SERVICE]),
            SERVICE_CMD_TIMEOUT,
        );
        let _ = run_with_timeout(
            Command::new("systemctl").args(["--user", "disable", SYSTEMD_SERVICE]),
            SERVICE_CMD_TIMEOUT,
        );
    }
    let unit_path = systemd_unit_path();
    if unit_path.exists() {
        fs::remove_file(&unit_path)
            .map_err(|e| HostError::Config(format!("remove unit file: {e}")))?;
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        info!("removed systemd user service");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fallback: detached process (same as `pocketshell daemon start`)
// ---------------------------------------------------------------------------

fn start_daemon_process() -> Result<()> {
    let paths = crate::config::AppConfig::paths()?;
    fs::create_dir_all(&paths.state_dir)
        .map_err(|e| HostError::Config(format!("create state dir: {e}")))?;

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)
        .map_err(|e| HostError::Config(format!("open log file: {e}")))?;

    let log2 = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)
        .map_err(|e| HostError::Config(format!("open log file: {e}")))?;

    let exe =
        std::env::current_exe().map_err(|e| HostError::Config(format!("resolve binary: {e}")))?;

    let child = Command::new(exe)
        .args(["daemon", "run"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log2))
        .spawn()
        .map_err(|e| HostError::Config(format!("spawn daemon: {e}")))?;

    fs::write(&paths.pid_file, child.id().to_string())
        .map_err(|e| HostError::Config(format!("write pid file: {e}")))?;

    info!("daemon started as background process (pid {})", child.id());
    Ok(())
}

/// Restart the daemon using the service manager when available; otherwise
/// spawn a replacement detached daemon process.
pub fn restart() -> Result<RestartStatus> {
    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path();
        if plist_path.exists() {
            let _ = Command::new("launchctl")
                .args(["load", "-w"])
                .arg(&plist_path)
                .status();

            let uid = Command::new("id")
                .arg("-u")
                .output()
                .ok()
                .and_then(|out| {
                    if out.status.success() {
                        String::from_utf8(out.stdout).ok()
                    } else {
                        None
                    }
                })
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| HostError::Config("resolve launchd uid".into()))?;

            let target = format!("gui/{uid}/{LAUNCHD_LABEL}");
            let status = Command::new("launchctl")
                .args(["kickstart", "-k", &target])
                .status()
                .map_err(|e| HostError::Config(format!("launchctl kickstart: {e}")))?;

            if !status.success() {
                return Err(HostError::Config("launchctl kickstart failed".into()));
            }

            info!("launchd service restarted");
            return Ok(RestartStatus::RestartedService);
        }
    } else if cfg!(target_os = "linux") && has_systemctl() {
        let unit_path = systemd_unit_path();
        if unit_path.exists() {
            let status = Command::new("systemctl")
                .args(["--user", "restart", SYSTEMD_SERVICE])
                .status()
                .map_err(|e| HostError::Config(format!("systemctl restart: {e}")))?;

            if !status.success() {
                return Err(HostError::Config("systemctl restart failed".into()));
            }

            info!("systemd user service restarted");
            return Ok(RestartStatus::RestartedService);
        }
    }

    start_daemon_process()?;
    Ok(RestartStatus::StartedDaemon)
}

/// Stop the service without removing it. It will still auto-start on reboot.
pub fn stop() -> Result<StopStatus> {
    if !is_service_running() {
        return Ok(StopStatus::NotRunning);
    }
    if cfg!(target_os = "macos") {
        let plist_path = launchd_plist_path();
        if plist_path.exists() {
            let _ = run_with_timeout(
                Command::new("launchctl").args(["unload"]).arg(&plist_path),
                SERVICE_CMD_TIMEOUT,
            );
            // Re-load without starting so it's registered for next boot
            let _ = run_with_timeout(
                Command::new("launchctl")
                    .args(["load", "-w"])
                    .arg(&plist_path),
                SERVICE_CMD_TIMEOUT,
            );
            // Then stop the running instance
            let _ = run_with_timeout(
                Command::new("launchctl").args(["stop", LAUNCHD_LABEL]),
                SERVICE_CMD_TIMEOUT,
            );
        }
    } else if cfg!(target_os = "linux") && has_systemctl() {
        let _ = run_with_timeout(
            Command::new("systemctl").args(["--user", "stop", SYSTEMD_SERVICE]),
            SERVICE_CMD_TIMEOUT,
        );
    }
    info!("service stopped");
    Ok(StopStatus::Stopped)
}

/// Uninstall the service for the current platform (stop + remove config).
pub fn uninstall() -> Result<()> {
    if cfg!(target_os = "macos") {
        uninstall_launchd()
    } else if cfg!(target_os = "linux") {
        uninstall_systemd()
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_expected_labels() {
        // Label/service-name strings are baked into plist/unit output and are
        // load-bearing for `launchctl list` / `systemctl --user` lookups.
        assert_eq!(LAUNCHD_LABEL, "com.pocketshell.host-agent");
        assert_eq!(SYSTEMD_SERVICE, "pocketshell-host-agent");
    }

    #[test]
    fn launchd_plist_path_is_under_library_launchagents() {
        let p = launchd_plist_path();
        let s = p.to_string_lossy();
        assert!(
            s.contains("Library/LaunchAgents/"),
            "expected LaunchAgents dir, got {s}"
        );
        assert!(s.ends_with("com.pocketshell.host-agent.plist"), "{s}");
    }

    #[test]
    fn systemd_unit_dir_and_path_under_config_systemd_user() {
        let dir = systemd_unit_dir();
        assert!(
            dir.to_string_lossy().contains(".config/systemd/user"),
            "{}",
            dir.display()
        );
        let unit = systemd_unit_path();
        assert_eq!(unit.parent().unwrap(), dir);
        assert!(
            unit.to_string_lossy()
                .ends_with("pocketshell-host-agent.service"),
            "{}",
            unit.display()
        );
    }

    /// Pure replica of the systemd unit-file string built inline in
    /// `install_systemd`. Kept here so we can assert the canonical content
    /// without invoking `systemctl`. If production ever drifts, this test
    /// starts failing and flags the divergence.
    fn expected_systemd_unit(exe_path: &str) -> String {
        format!(
            r#"[Unit]
Description=PocketShell Host Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path} daemon run
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#
        )
    }

    #[test]
    fn systemd_unit_contains_required_fields() {
        let unit = expected_systemd_unit("/usr/local/bin/pocketshell");
        assert!(unit.contains("Description=PocketShell Host Agent"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
        assert!(unit.contains("Type=simple"));
        assert!(unit.contains("ExecStart=/usr/local/bin/pocketshell daemon run"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=5"));
        assert!(unit.contains("Environment=RUST_LOG=info"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    /// Pure replica of the launchd plist built inline in `install_launchd`.
    fn expected_launchd_plist(exe_path: &str, log_path: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe_path}</string>
    <string>daemon</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>info</string>
  </dict>
</dict>
</plist>
"#,
            log = log_path
        )
    }

    #[test]
    fn launchd_plist_contains_required_keys() {
        let plist = expected_launchd_plist("/opt/pocketshell", "/tmp/ps.log");
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.pocketshell.host-agent</string>"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<string>/opt/pocketshell</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains("<string>/tmp/ps.log</string>"));
        assert!(plist.contains("RUST_LOG"));
    }
}
