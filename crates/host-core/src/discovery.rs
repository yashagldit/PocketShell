use crate::config::AppConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableSession {
    pub name: String,
    pub session_type: String, // "tmux", "screen", or "shell"
    pub attached: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub windows: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pty_path: Option<String>,
}

pub struct SessionDiscovery;

impl SessionDiscovery {
    /// Return session IDs (without "ps-" prefix) of all PocketShell tmux sessions.
    pub fn discover_pocketshell_names() -> Vec<String> {
        let output = Command::new("tmux")
            .args(["list-sessions", "-F", "#{session_name}"])
            .output();
        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("ps-").map(|s| s.to_string()))
            .collect()
    }

    /// Check if a specific tmux session exists by name.
    pub fn tmux_session_exists(name: &str) -> bool {
        Command::new("tmux")
            .args(["has-session", "-t", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Discover all tmux, screen, manually exposed, and PocketShell persistent sessions on this host.
    pub fn discover() -> Vec<AvailableSession> {
        let mut sessions = Vec::new();
        sessions.extend(Self::discover_pocketshell());
        sessions.extend(Self::discover_exposed());
        sessions.extend(Self::discover_tmux());
        sessions.extend(Self::discover_screen());
        sessions
    }

    /// Discover PocketShell-managed persistent tmux sessions (prefixed with "ps-").
    fn discover_pocketshell() -> Vec<AvailableSession> {
        let output = Command::new("tmux")
            .args(["list-sessions", "-F", "#{session_name}\t#{session_attached}\t#{session_created}\t#{session_windows}"])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 4 {
                    return None;
                }
                let name = parts[0];
                // Only include PocketShell-managed sessions
                if !name.starts_with("ps-") {
                    return None;
                }
                let display_name = name.strip_prefix("ps-").unwrap_or(name).to_string();
                let attached = parts[1] == "1";
                let created_at = parts[2]
                    .parse::<i64>()
                    .ok()
                    .and_then(|ts| DateTime::from_timestamp(ts, 0));
                let windows = parts[3].parse::<u32>().unwrap_or(1);

                Some(AvailableSession {
                    name: display_name,
                    session_type: "pocketshell".to_string(),
                    attached,
                    created_at,
                    windows,
                    pty_path: None,
                })
            })
            .collect()
    }

    /// Register a named shell session via marker file with the current PTY path.
    pub fn register_exposed(name: &str) -> Result<(), std::io::Error> {
        let dir = Self::exposed_dir();
        fs::create_dir_all(&dir)?;
        let marker = dir.join(name);
        // Store PTY device path so the daemon can attach to this terminal
        let tty = Self::current_tty().unwrap_or_default();
        let content = format!("{}\n{}", Utc::now().to_rfc3339(), tty);
        fs::write(&marker, content)?;
        Ok(())
    }

    /// Get the PTY device path of the current terminal.
    fn current_tty() -> Option<String> {
        #[cfg(unix)]
        {
            // Use the `tty` command which is available on macOS and Linux
            let output = Command::new("tty").output().ok()?;
            if output.status.success() {
                let tty = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if tty.starts_with('/') {
                    return Some(tty);
                }
            }
            None
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// Remove an exposed session marker.
    pub fn unregister_exposed(name: &str) -> Result<(), std::io::Error> {
        let marker = Self::exposed_dir().join(name);
        if marker.exists() {
            fs::remove_file(&marker)?;
        }
        Ok(())
    }

    fn exposed_dir() -> std::path::PathBuf {
        AppConfig::paths()
            .map(|p| p.state_dir.join("exposed"))
            .unwrap_or_else(|_| {
                dirs::home_dir()
                    .unwrap_or_default()
                    .join(".pocketshell")
                    .join("exposed")
            })
    }

    fn discover_exposed() -> Vec<AvailableSession> {
        let dir = Self::exposed_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                let content = fs::read_to_string(entry.path()).ok()?;
                let mut lines = content.lines();
                let created_at = lines
                    .next()
                    .and_then(|s| DateTime::parse_from_rfc3339(s.trim()).ok())
                    .map(|dt| dt.with_timezone(&Utc));
                let pty_path = lines.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

                Some(AvailableSession {
                    name,
                    session_type: "shell".to_string(),
                    attached: false,
                    created_at,
                    windows: 1,
                    pty_path,
                })
            })
            .collect()
    }

    fn discover_tmux() -> Vec<AvailableSession> {
        let output = Command::new("tmux")
            .args(["list-sessions", "-F", "#{session_name}\t#{session_attached}\t#{session_created}\t#{session_windows}"])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // "no server running" is normal when tmux isn't active
                if !stderr.contains("no server running") && !stderr.contains("no current") {
                    warn!("tmux list-sessions failed: {}", stderr.trim());
                }
                return Vec::new();
            }
            Err(_) => return Vec::new(), // tmux not installed
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 4 {
                    return None;
                }
                let name = parts[0].to_string();
                // Skip PocketShell-managed sessions — they appear under "pocketshell" type
                if name.starts_with("ps-") {
                    return None;
                }
                let attached = parts[1] == "1";
                let created_at = parts[2]
                    .parse::<i64>()
                    .ok()
                    .and_then(|ts| DateTime::from_timestamp(ts, 0));
                let windows = parts[3].parse::<u32>().unwrap_or(1);

                Some(AvailableSession {
                    name,
                    session_type: "tmux".to_string(),
                    attached,
                    created_at,
                    windows,
                    pty_path: None,
                })
            })
            .collect()
    }

    fn discover_screen() -> Vec<AvailableSession> {
        let output = Command::new("screen").args(["-ls"]).output();

        let output = match output {
            Ok(o) => o,
            Err(_) => return Vec::new(), // screen not installed
        };

        // screen -ls exits with 1 when sessions exist, so we parse stdout regardless
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                // Lines look like: "12345.session_name\t(Attached)" or "(Detached)"
                if !trimmed.contains('.') || (!trimmed.contains("Attached") && !trimmed.contains("Detached")) {
                    return None;
                }
                let dot_pos = trimmed.find('.')?;
                let name_end = trimmed.find('\t').or_else(|| trimmed.find(' ')).unwrap_or(trimmed.len());
                let name = trimmed[dot_pos + 1..name_end].trim().to_string();
                let attached = trimmed.contains("Attached");

                Some(AvailableSession {
                    name,
                    session_type: "screen".to_string(),
                    attached,
                    created_at: None,
                    windows: 1,
                    pty_path: None,
                })
            })
            .collect()
    }
}
