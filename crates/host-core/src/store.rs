use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::{AgentState, DeviceRecord, HostIdentity};
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
            file.write_all(b"{\n  \"pending_devices\": [],\n  \"trusted_devices\": []\n}\n")?;
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

    pub fn upsert_pending_device(&mut self, device: DeviceRecord) {
        self.state
            .pending_devices
            .retain(|d| d.device_id != device.device_id);
        self.state.pending_devices.push(device);
    }

    pub fn approve_device(&mut self, device_id: &str) -> Result<DeviceRecord> {
        let Some(idx) = self
            .state
            .pending_devices
            .iter()
            .position(|d| d.device_id == device_id)
        else {
            return Err(HostError::Config(format!("device not pending: {device_id}")));
        };

        let mut device = self.state.pending_devices.remove(idx);
        device.pending_since = None;
        device.approved_at = Some(Utc::now());
        device.revoked_at = None;

        self.state
            .trusted_devices
            .retain(|d| d.device_id != device.device_id);
        self.state.trusted_devices.push(device.clone());
        Ok(device)
    }

    pub fn revoke_device(&mut self, device_id: &str) -> Result<DeviceRecord> {
        let Some(idx) = self
            .state
            .trusted_devices
            .iter()
            .position(|d| d.device_id == device_id)
        else {
            return Err(HostError::Config(format!("device not trusted: {device_id}")));
        };

        let mut device = self.state.trusted_devices.remove(idx);
        device.revoked_at = Some(Utc::now());
        Ok(device)
    }

    pub fn is_trusted(&self, device_id: &str) -> bool {
        self.state
            .trusted_devices
            .iter()
            .any(|d| d.device_id == device_id && d.revoked_at.is_none())
    }

    pub fn host(&self) -> Result<&HostIdentity> {
        self.state.host.as_ref().ok_or(HostError::NotLoggedIn)
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
