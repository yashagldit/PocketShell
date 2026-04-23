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

    /// Revocation-only sync: remove locally trusted devices that the backend
    /// reports as revoked.  Never adds new devices — those only arrive via
    /// `pocketshell pair`.  Returns the list of revoked mobile_device_ids that
    /// were actually removed.
    pub fn apply_revocations(&mut self, backend_devices: &[TrustedDeviceRecord]) -> Vec<String> {
        let revoked_ids: std::collections::HashSet<String> = backend_devices
            .iter()
            .filter(|d| d.revoked_at.is_some())
            .map(|d| d.mobile_device_id.clone())
            .collect();

        let mut removed = Vec::new();
        self.state.trusted_devices.retain(|d| {
            if revoked_ids.contains(&d.mobile_device_id) {
                removed.push(d.mobile_device_id.clone());
                false
            } else {
                true
            }
        });
        // Also clear any pending devices that were revoked
        self.state
            .pending_devices
            .retain(|d| !revoked_ids.contains(&d.mobile_device_id));
        removed
    }

    /// Add a single trusted device (called only from the `pair` command).
    pub fn add_trusted_device(&mut self, device: TrustedDeviceRecord) {
        // Remove any existing entry for this mobile_device_id, then add
        self.state
            .trusted_devices
            .retain(|d| d.mobile_device_id != device.mobile_device_id);
        self.state
            .pending_devices
            .retain(|d| d.mobile_device_id != device.mobile_device_id);
        self.state.trusted_devices.push(device);
    }

    pub fn remove_trusted_device(&mut self, mobile_device_id: &str) {
        self.state
            .trusted_devices
            .retain(|d| d.mobile_device_id != mobile_device_id);
    }

    pub fn is_trusted(&self, device_id: &str) -> bool {
        self.state.trusted_devices.iter().any(|d| {
            d.mobile_device_id == device_id && d.revoked_at.is_none() && d.approved_at.is_some()
        })
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

    /// Remove stale sessions from local state.
    ///
    /// Returns `(native_detached_to_close, all_expired_session_ids)`:
    /// - `native_detached_to_close`: persistent native sessions whose PTY should be killed
    /// - `all_expired_session_ids`: all expired detached sessions that should be ended on the backend
    pub fn clear_ended_sessions(
        &mut self,
        stale_after_secs: i64,
        detach_max_secs: i64,
    ) -> (Vec<String>, Vec<String>) {
        let now = Utc::now();
        let mut native_detached_to_close = Vec::new();
        let mut all_expired = Vec::new();
        self.state.sessions.retain(|s| {
            let age = (now - s.updated_at).num_seconds();
            // Clear ended/failed sessions after stale threshold
            if age > stale_after_secs
                && matches!(
                    s.state,
                    crate::models::SessionState::Ended | crate::models::SessionState::Failed
                )
            {
                return false;
            }
            // Clear detached sessions older than max detach time.
            if age > detach_max_secs && matches!(s.state, crate::models::SessionState::Detached) {
                all_expired.push(s.session_id.clone());
                if let Some(ref tmux_name) = s.tmux_session_name {
                    let _ = std::process::Command::new("tmux")
                        .args(["kill-session", "-t", tmux_name])
                        .status();
                } else if s.persistent {
                    native_detached_to_close.push(s.session_id.clone());
                }
                return false;
            }
            true
        });
        (native_detached_to_close, all_expired)
    }

    pub fn get_device_public_key(&self, mobile_device_id: &str) -> Option<&str> {
        self.state
            .trusted_devices
            .iter()
            .find(|d| d.mobile_device_id == mobile_device_id)
            .and_then(|d| d.device_public_key.as_deref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthState, HostIdentity, SessionState};
    use chrono::{Duration, Utc};

    fn make_store(path: PathBuf) -> StateStore {
        StateStore {
            path,
            state: AgentState::default(),
        }
    }

    fn trusted_device(mobile_id: &str) -> TrustedDeviceRecord {
        TrustedDeviceRecord {
            id: format!("td-{mobile_id}"),
            host_id: "host-1".into(),
            mobile_device_id: mobile_id.into(),
            approved_at: Some(Utc::now()),
            revoked_at: None,
            permissions_json: None,
            device_public_key: Some("pubkey".into()),
            created_at: Utc::now(),
        }
    }

    fn session_record(id: &str, state: SessionState, age_secs: i64) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            mobile_device_id: "m".into(),
            state,
            updated_at: Utc::now() - Duration::seconds(age_secs),
            persistent: false,
            tmux_session_name: None,
        }
    }

    #[test]
    fn save_writes_pretty_json_to_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");
        let mut store = make_store(path.clone());
        store.state.auth = Some(AuthState {
            access_token: "A".into(),
            refresh_token: "R".into(),
            access_expires_at: None,
        });
        store.save().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"access_token\""));
        assert!(raw.contains("\"A\""));
        // serde_json::to_string_pretty emits newlines
        assert!(raw.contains('\n'));
    }

    #[test]
    fn save_then_deserialize_roundtrips_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");
        let mut store = make_store(path.clone());
        store.add_trusted_device(trusted_device("m1"));
        store.save().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let parsed: AgentState = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.trusted_devices.len(), 1);
        assert_eq!(parsed.trusted_devices[0].mobile_device_id, "m1");
    }

    #[test]
    fn require_logged_in_errors_when_missing() {
        let store = make_store(PathBuf::from("/tmp/unused"));
        let err = store.require_logged_in().unwrap_err();
        assert!(matches!(err, HostError::NotLoggedIn));
    }

    #[test]
    fn require_logged_in_ok_when_auth_and_host_present() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.state.auth = Some(AuthState {
            access_token: "a".into(),
            refresh_token: "r".into(),
            access_expires_at: None,
        });
        store.state.host = Some(HostIdentity {
            host_id: "h".into(),
            user_id: "u".into(),
            hostname: "n".into(),
            platform: "p".into(),
            app_version: "v".into(),
            public_key: "pk".into(),
            private_key: String::new(),
            registered_at: Utc::now(),
        });
        assert!(store.require_logged_in().is_ok());
        assert_eq!(store.host_id().unwrap(), "h");
        assert_eq!(store.access_token().unwrap(), "a");
    }

    #[test]
    fn host_id_and_access_token_error_without_login() {
        let store = make_store(PathBuf::from("/tmp/unused"));
        assert!(matches!(
            store.host_id().unwrap_err(),
            HostError::NotLoggedIn
        ));
        assert!(matches!(
            store.access_token().unwrap_err(),
            HostError::NotLoggedIn
        ));
    }

    #[test]
    fn upsert_pending_device_replaces_duplicate() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        let mut d1 = trusted_device("m1");
        d1.id = "first".into();
        store.upsert_pending_device(d1);
        let mut d2 = trusted_device("m1");
        d2.id = "second".into();
        store.upsert_pending_device(d2);
        assert_eq!(store.state.pending_devices.len(), 1);
        assert_eq!(store.state.pending_devices[0].id, "second");
    }

    #[test]
    fn add_trusted_device_replaces_and_clears_pending() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.upsert_pending_device(trusted_device("m1"));
        assert_eq!(store.state.pending_devices.len(), 1);

        store.add_trusted_device(trusted_device("m1"));
        assert_eq!(store.state.trusted_devices.len(), 1);
        assert!(store.state.pending_devices.is_empty());

        // Re-adding same mobile id does not grow the list
        store.add_trusted_device(trusted_device("m1"));
        assert_eq!(store.state.trusted_devices.len(), 1);
    }

    #[test]
    fn remove_trusted_device_filters_by_mobile_id() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("m1"));
        store.add_trusted_device(trusted_device("m2"));
        store.remove_trusted_device("m1");
        assert_eq!(store.state.trusted_devices.len(), 1);
        assert_eq!(store.state.trusted_devices[0].mobile_device_id, "m2");
    }

    #[test]
    fn is_trusted_requires_approved_and_not_revoked() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        let mut approved = trusted_device("ok");
        approved.approved_at = Some(Utc::now());
        approved.revoked_at = None;
        store.add_trusted_device(approved);

        let mut pending = trusted_device("pending");
        pending.approved_at = None;
        store.add_trusted_device(pending);

        let mut revoked = trusted_device("revoked");
        revoked.approved_at = Some(Utc::now());
        revoked.revoked_at = Some(Utc::now());
        store.add_trusted_device(revoked);

        assert!(store.is_trusted("ok"));
        assert!(!store.is_trusted("pending"));
        assert!(!store.is_trusted("revoked"));
        assert!(!store.is_trusted("nonexistent"));
    }

    #[test]
    fn apply_revocations_removes_revoked_and_clears_pending() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("keep"));
        store.add_trusted_device(trusted_device("gone"));
        store.upsert_pending_device(trusted_device("gone"));

        let mut revoked = trusted_device("gone");
        revoked.revoked_at = Some(Utc::now());
        let backend = vec![trusted_device("keep"), revoked];

        let removed = store.apply_revocations(&backend);
        assert_eq!(removed, vec!["gone".to_string()]);
        assert_eq!(store.state.trusted_devices.len(), 1);
        assert_eq!(store.state.trusted_devices[0].mobile_device_id, "keep");
        assert!(store.state.pending_devices.is_empty());
    }

    #[test]
    fn apply_revocations_no_op_when_backend_all_active() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("a"));
        let removed = store.apply_revocations(&[trusted_device("a")]);
        assert!(removed.is_empty());
        assert_eq!(store.state.trusted_devices.len(), 1);
    }

    #[test]
    fn upsert_session_replaces_existing() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.upsert_session(session_record("s1", SessionState::Connected, 0));
        store.upsert_session(session_record("s1", SessionState::Ended, 0));
        assert_eq!(store.state.sessions.len(), 1);
        assert_eq!(store.state.sessions[0].state, SessionState::Ended);
    }

    #[test]
    fn touch_session_state_updates_existing() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.upsert_session(session_record("s1", SessionState::Connected, 100));
        let before = store.state.sessions[0].updated_at;
        store.touch_session_state("s1", SessionState::Detached);
        assert_eq!(store.state.sessions.len(), 1);
        assert_eq!(store.state.sessions[0].state, SessionState::Detached);
        assert!(store.state.sessions[0].updated_at > before);
    }

    #[test]
    fn touch_session_state_inserts_when_unknown() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.touch_session_state("new", SessionState::Requested);
        assert_eq!(store.state.sessions.len(), 1);
        let s = &store.state.sessions[0];
        assert_eq!(s.session_id, "new");
        assert_eq!(s.mobile_device_id, "unknown");
        assert_eq!(s.state, SessionState::Requested);
        assert!(!s.persistent);
    }

    #[test]
    fn clear_ended_sessions_drops_old_ended_but_keeps_recent() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.upsert_session(session_record("old-ended", SessionState::Ended, 1000));
        store.upsert_session(session_record("recent-ended", SessionState::Ended, 10));
        store.upsert_session(session_record(
            "old-connected",
            SessionState::Connected,
            1000,
        ));

        let (native, expired) = store.clear_ended_sessions(300, 100_000);
        assert!(native.is_empty());
        assert!(expired.is_empty());
        let ids: Vec<_> = store
            .state
            .sessions
            .iter()
            .map(|s| s.session_id.clone())
            .collect();
        assert!(!ids.contains(&"old-ended".to_string()));
        assert!(ids.contains(&"recent-ended".to_string()));
        assert!(ids.contains(&"old-connected".to_string()));
    }

    #[test]
    fn clear_ended_sessions_expires_old_detached_non_persistent() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        let mut s = session_record("det", SessionState::Detached, 500);
        s.persistent = false;
        store.upsert_session(s);

        let (native, expired) = store.clear_ended_sessions(300, 100);
        assert!(
            native.is_empty(),
            "non-persistent should not request PTY kill"
        );
        assert_eq!(expired, vec!["det".to_string()]);
        assert!(store.state.sessions.is_empty());
    }

    #[test]
    fn clear_ended_sessions_expires_old_detached_persistent_native() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        let mut s = session_record("det", SessionState::Detached, 500);
        s.persistent = true;
        s.tmux_session_name = None;
        store.upsert_session(s);

        let (native, expired) = store.clear_ended_sessions(300, 100);
        assert_eq!(native, vec!["det".to_string()]);
        assert_eq!(expired, vec!["det".to_string()]);
    }

    #[test]
    fn get_device_public_key_returns_stored_key() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("m1"));
        assert_eq!(store.get_device_public_key("m1"), Some("pubkey"));
        assert!(store.get_device_public_key("missing").is_none());
    }
}
