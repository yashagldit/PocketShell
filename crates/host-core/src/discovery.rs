use crate::config::AppConfig;
use crate::models::{SessionRecord, SessionState};
use crate::store::StateStore;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    /// Return active PocketShell-managed session IDs from local state.
    pub fn discover_pocketshell_names() -> Vec<String> {
        Self::load_pocketshell_sessions()
            .into_iter()
            .map(|session| session.session_id)
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

    /// Discover PocketShell-managed persistent sessions from local state.
    fn discover_pocketshell() -> Vec<AvailableSession> {
        let mut seen = HashSet::new();
        Self::load_pocketshell_sessions()
            .into_iter()
            .filter(|session| seen.insert(session.session_id.clone()))
            .map(|session| AvailableSession {
                name: session.session_id,
                session_type: "pocketshell".to_string(),
                attached: !matches!(session.state, SessionState::Detached),
                created_at: Some(session.updated_at),
                windows: 1,
                pty_path: None,
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
                let pty_path = lines
                    .next()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());

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
            .args([
                "list-sessions",
                "-F",
                "#{session_name}\t#{session_attached}\t#{session_created}\t#{session_windows}",
            ])
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
                if !trimmed.contains('.')
                    || (!trimmed.contains("Attached") && !trimmed.contains("Detached"))
                {
                    return None;
                }
                let dot_pos = trimmed.find('.')?;
                let name_end = trimmed
                    .find('\t')
                    .or_else(|| trimmed.find(' '))
                    .unwrap_or(trimmed.len());
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

    fn load_pocketshell_sessions() -> Vec<SessionRecord> {
        let store = match StateStore::load() {
            Ok(store) => store,
            Err(_) => return Vec::new(),
        };

        let mut sessions: Vec<_> = store
            .state
            .sessions
            .into_iter()
            .filter(|session| {
                session.persistent
                    && matches!(
                        session.state,
                        SessionState::Approved
                            | SessionState::Connecting
                            | SessionState::Connected
                            | SessionState::Detached
                    )
            })
            .collect();
        sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::HOME_LOCK;
    use chrono::TimeZone;

    fn sample_session(name: &str, attached: bool) -> AvailableSession {
        AvailableSession {
            name: name.to_string(),
            session_type: "tmux".to_string(),
            attached,
            created_at: Some(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()),
            windows: 3,
            pty_path: None,
        }
    }

    #[test]
    fn available_session_serde_roundtrip() {
        let s = sample_session("dev", true);
        let json = serde_json::to_string(&s).unwrap();
        let back: AvailableSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "dev");
        assert_eq!(back.session_type, "tmux");
        assert!(back.attached);
        assert_eq!(back.windows, 3);
        assert_eq!(back.pty_path, None);
    }

    #[test]
    fn available_session_skips_none_pty_path() {
        let s = sample_session("dev", false);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("pty_path"));
    }

    #[test]
    fn available_session_includes_some_pty_path() {
        let mut s = sample_session("shellA", false);
        s.session_type = "shell".to_string();
        s.pty_path = Some("/dev/ttys004".to_string());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("/dev/ttys004"));
        let back: AvailableSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pty_path.as_deref(), Some("/dev/ttys004"));
    }

    #[test]
    fn available_session_accepts_missing_pty_path_on_deserialize() {
        // Deserialize JSON that omits the optional pty_path field.
        let json = r#"{
            "name": "s1",
            "session_type": "screen",
            "attached": false,
            "created_at": null,
            "windows": 1
        }"#;
        let s: AvailableSession = serde_json::from_str(json).unwrap();
        assert_eq!(s.name, "s1");
        assert_eq!(s.session_type, "screen");
        assert!(!s.attached);
        assert!(s.created_at.is_none());
        assert_eq!(s.windows, 1);
        assert!(s.pty_path.is_none());
    }

    #[test]
    fn tmux_session_exists_returns_false_for_unlikely_name() {
        // An implausibly named session should not exist. Even if tmux is not
        // installed, the helper swallows the error and returns false.
        let name = "ps-nonexistent-test-session-xyz-9999";
        assert!(!SessionDiscovery::tmux_session_exists(name));
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn register_and_discover_exposed_roundtrip() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Redirect $HOME to a temp dir so exposed_dir points somewhere isolated.
        let tmp = tempfile::tempdir().expect("tempdir");
        // SAFETY: tests run in-process; setting HOME is acceptable for this
        // single-threaded read path inside exposed_dir(). Tests that depend on
        // the real HOME are not present in this module.
        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }

        let name = "ps-test-register-roundtrip-unique";
        // register_exposed creates $HOME/.pocketshell/exposed/<name>
        SessionDiscovery::register_exposed(name).expect("register");

        let marker = tmp.path().join(".pocketshell").join("exposed").join(name);
        assert!(marker.exists(), "marker file should exist at {:?}", marker);

        let content = std::fs::read_to_string(&marker).unwrap();
        let mut lines = content.lines();
        let first = lines.next().unwrap();
        // First line is an RFC3339 timestamp.
        assert!(
            DateTime::parse_from_rfc3339(first).is_ok(),
            "first line should parse as rfc3339, got {:?}",
            first
        );

        // Unregister removes the marker.
        SessionDiscovery::unregister_exposed(name).expect("unregister");
        assert!(!marker.exists());

        // Unregister is idempotent: calling again should not error.
        SessionDiscovery::unregister_exposed(name).expect("unregister idempotent");

        // Restore HOME.
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn discover_exposed_parses_marker_files() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }

        // Manually create the exposed dir + two marker files with distinct contents.
        let dir = tmp.path().join(".pocketshell").join("exposed");
        std::fs::create_dir_all(&dir).unwrap();

        // Marker 1: timestamp + pty path
        let m1 = dir.join("ps-test-parse-alpha");
        std::fs::write(&m1, "2026-01-15T12:00:00+00:00\n/dev/ttys007\n").unwrap();

        // Marker 2: timestamp only (no pty path)
        let m2 = dir.join("ps-test-parse-beta");
        std::fs::write(&m2, "2026-02-20T08:30:00+00:00\n").unwrap();

        let all = SessionDiscovery::discover();
        let alpha = all
            .iter()
            .find(|s| s.name == "ps-test-parse-alpha")
            .expect("alpha");
        assert_eq!(alpha.session_type, "shell");
        assert!(!alpha.attached);
        assert_eq!(alpha.windows, 1);
        assert_eq!(alpha.pty_path.as_deref(), Some("/dev/ttys007"));
        assert!(alpha.created_at.is_some());

        let beta = all
            .iter()
            .find(|s| s.name == "ps-test-parse-beta")
            .expect("beta");
        assert_eq!(beta.session_type, "shell");
        assert!(beta.pty_path.is_none());
        assert!(beta.created_at.is_some());

        // Cleanup markers so other tests using the shared HOME don't see them.
        let _ = std::fs::remove_file(&m1);
        let _ = std::fs::remove_file(&m2);

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn discover_exposed_returns_empty_when_dir_missing() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }

        // With a fresh HOME and no .pocketshell/exposed dir, discover() should
        // return an empty list of "shell"-type sessions.
        let all = SessionDiscovery::discover();
        let shells: Vec<_> = all.iter().filter(|s| s.session_type == "shell").collect();
        assert!(
            shells.is_empty(),
            "expected no shell sessions, got {:?}",
            shells
        );

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}
