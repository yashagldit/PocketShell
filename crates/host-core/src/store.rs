use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::{AgentState, SessionRecord, TrustedDeviceRecord};
use chrono::Utc;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug)]
pub struct StateStore {
    pub path: PathBuf,
    pub state: AgentState,
}

impl StateStore {
    pub fn load() -> Result<Self> {
        let paths = AppConfig::paths()?;
        if !paths.state_dir.exists() {
            fs::create_dir_all(&paths.state_dir)?;
            set_dir_permissions(&paths.state_dir)?;
        }

        if !paths.state_file.exists() {
            let mut file = fs::File::create(&paths.state_file)?;
            file.write_all(
                b"{\n  \"pending_devices\": [],\n  \"trusted_devices\": [],\n  \"sessions\": []\n}\n",
            )?;
            set_file_permissions(&paths.state_file)?;
        }

        let raw = fs::read_to_string(&paths.state_file)?;
        let state = serde_json::from_str::<AgentState>(&raw).unwrap_or_default();

        Ok(Self {
            path: paths.state_file,
            state,
        })
    }

    pub fn save(&self) -> Result<()> {
        let raw = serde_json::to_string_pretty(&self.state)?;
        fs::write(&self.path, raw)?;
        set_file_permissions(&self.path)?;
        Ok(())
    }

    pub fn require_logged_in(&self) -> Result<()> {
        if self.state.auth.is_none() || self.state.host.is_none() {
            return Err(HostError::NotLoggedIn);
        }
        Ok(())
    }

    pub fn upsert_pending_device(&mut self, device: TrustedDeviceRecord) {
        self.state
            .pending_devices
            .retain(|d| d.mobile_device_id != device.mobile_device_id);
        self.state.pending_devices.push(device);
    }

    pub fn set_trusted_devices(&mut self, devices: Vec<TrustedDeviceRecord>) {
        self.state.pending_devices = devices
            .iter()
            .filter(|d| d.approved_at.is_none() && d.revoked_at.is_none())
            .cloned()
            .collect();
        self.state.trusted_devices = devices
            .into_iter()
            .filter(|d| d.approved_at.is_some() && d.revoked_at.is_none())
            .collect();
    }

    pub fn remove_trusted_device(&mut self, mobile_device_id: &str) {
        self.state
            .trusted_devices
            .retain(|d| d.mobile_device_id != mobile_device_id);
    }

    pub fn is_trusted(&self, device_id: &str) -> bool {
        self.state
            .trusted_devices
            .iter()
            .any(|d| d.mobile_device_id == device_id && d.revoked_at.is_none() && d.approved_at.is_some())
    }

    pub fn upsert_session(&mut self, session: SessionRecord) {
        self.state
            .sessions
            .retain(|s| s.session_id != session.session_id);
        self.state.sessions.push(session);
    }

    pub fn touch_session_state(&mut self, session_id: &str, state: crate::models::SessionState) {
        let now = Utc::now();
        if let Some(session) = self
            .state
            .sessions
            .iter_mut()
            .find(|s| s.session_id == session_id)
        {
            session.state = state;
            session.updated_at = now;
            return;
        }

        self.state.sessions.push(SessionRecord {
            session_id: session_id.to_string(),
            mobile_device_id: "unknown".to_string(),
            state,
            updated_at: now,
            persistent: false,
            tmux_session_name: None,
        });
    }

    pub fn clear_ended_sessions(&mut self, stale_after_secs: i64, detach_max_secs: i64) {
        let now = Utc::now();
        self.state.sessions.retain(|s| {
            let age = (now - s.updated_at).num_seconds();
            // Clear ended/failed sessions after stale threshold
            if age > stale_after_secs && matches!(s.state, crate::models::SessionState::Ended | crate::models::SessionState::Failed) {
                return false;
            }
            // Clear detached sessions older than max detach time (and kill their tmux session)
            if age > detach_max_secs && matches!(s.state, crate::models::SessionState::Detached) {
                if let Some(ref tmux_name) = s.tmux_session_name {
                    let _ = std::process::Command::new("tmux")
                        .args(["kill-session", "-t", tmux_name])
                        .status();
                }
                return false;
            }
            true
        });
    }

    pub fn host_id(&self) -> Result<String> {
        Ok(self
            .state
            .host
            .as_ref()
            .ok_or(HostError::NotLoggedIn)?
            .host_id
            .clone())
    }

    pub fn access_token(&self) -> Result<&str> {
        self.state
            .auth
            .as_ref()
            .map(|a| a.access_token.as_str())
            .ok_or(HostError::NotLoggedIn)
    }
}

#[cfg(unix)]
fn set_file_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &PathBuf) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &PathBuf) -> Result<()> {
    Ok(())
}
