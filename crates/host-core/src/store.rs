use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::{AgentState, SessionRecord, TrustedDeviceRecord};
use crate::secret_store::{SecretStore, KEY_HOST_PRIVATE, KEY_REFRESH_TOKEN};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
pub struct StateStore {
    pub path: PathBuf,
    pub state: AgentState,
    secrets: SecretStore,
}

impl StateStore {
    pub fn load() -> Result<Self> {
        let paths = AppConfig::paths()?;
        if !paths.state_dir.exists() {
            fs::create_dir_all(&paths.state_dir)?;
        }
        harden_dir_permissions(&paths.state_dir)?;

        if !paths.state_file.exists() {
            // Atomic write so a crash mid-create can't leave a half-written
            // state.json that the parse path below would treat as corrupt.
            atomic_write(
                &paths.state_file,
                b"{\n  \"pending_devices\": [],\n  \"trusted_devices\": [],\n  \"sessions\": []\n}\n",
            )?;
        }
        harden_file_permissions(&paths.state_file)?;

        let raw = fs::read_to_string(&paths.state_file)?;
        // Refuse to start on a non-empty but unparseable state.json. The old
        // `unwrap_or_default()` path silently reset to an empty state on parse
        // failure, which then made `require_logged_in` shut the daemon down
        // a few moments later — a confusing crash loop. An empty file is a
        // legitimate fresh-install signal; non-empty + parse error means a
        // disk corruption or partial write that the operator must look at.
        let mut state = if raw.trim().is_empty() {
            AgentState::default()
        } else {
            match serde_json::from_str::<AgentState>(&raw) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "state.json at {} is corrupt and cannot be parsed: {}. \
                         Refusing to start to prevent identity loss. \
                         Backup and remove the file to start fresh.",
                        paths.state_file.display(),
                        e
                    );
                    std::process::exit(2);
                }
            }
        };

        let secrets = SecretStore::new(paths.state_dir.clone());

        // Hydrate secrets from the OS keyring when state.json no longer
        // carries them (post-migration). If state.json still has plaintext
        // values (legacy), leave them in place — `save` will migrate on the
        // next write.
        if let Some(host) = state.host.as_mut() {
            if host.private_key.is_empty() {
                if let Ok(Some(value)) = secrets.get(KEY_HOST_PRIVATE) {
                    host.private_key = value;
                }
            }
        }
        if let Some(auth) = state.auth.as_mut() {
            if auth.refresh_token.is_empty() {
                if let Ok(Some(value)) = secrets.get(KEY_REFRESH_TOKEN) {
                    auth.refresh_token = value;
                }
            }
        }

        Ok(Self {
            path: paths.state_file,
            state,
            secrets,
        })
    }

    /// Persist state to disk, preserving `trusted_devices` and `pending_devices`
    /// from the on-disk copy. The daemon and the `pocketshell pair` CLI both
    /// load and write this file from separate processes; without preserving
    /// trust fields, the daemon's incidental saves (auth refresh, sessions,
    /// alerts) would clobber a trust addition the CLI just wrote.
    /// Use [`save_full`] when in-memory trust must win (CLI pair, revocation).
    pub fn save(&self) -> Result<()> {
        let mut to_write = self.state.clone();
        if self.path.exists() {
            if let Ok(raw) = fs::read_to_string(&self.path) {
                if let Ok(disk) = serde_json::from_str::<AgentState>(&raw) {
                    to_write.trusted_devices = disk.trusted_devices;
                    to_write.pending_devices = disk.pending_devices;
                }
            }
        }
        self.persist_secrets_and_redact(&mut to_write)?;
        let raw = serde_json::to_string_pretty(&to_write)?;
        atomic_write(&self.path, raw.as_bytes())?;
        Ok(())
    }

    /// Write the full in-memory state to disk, including trust fields.
    /// Caller is responsible for ensuring trust fields are up-to-date with
    /// disk first (typically via [`reload_trust`]) so this doesn't undo a
    /// concurrent CLI write.
    pub fn save_full(&self) -> Result<()> {
        let mut to_write = self.state.clone();
        self.persist_secrets_and_redact(&mut to_write)?;
        let raw = serde_json::to_string_pretty(&to_write)?;
        atomic_write(&self.path, raw.as_bytes())?;
        Ok(())
    }

    /// Move long-lived secrets out of the about-to-be-serialized snapshot
    /// and into the OS keyring. Replaces the plaintext fields with empty
    /// strings so `state.json` on disk never holds them after the first
    /// save post-upgrade. Best-effort — if the keyring is unavailable,
    /// `SecretStore` falls back to a 0o600 file under the state dir, and
    /// the JSON itself still gets redacted to keep a single source of
    /// truth.
    fn persist_secrets_and_redact(&self, snapshot: &mut AgentState) -> Result<()> {
        if let Some(host) = snapshot.host.as_mut() {
            if !host.private_key.is_empty() {
                self.secrets.put(KEY_HOST_PRIVATE, &host.private_key)?;
                host.private_key.clear();
            }
        }
        if let Some(auth) = snapshot.auth.as_mut() {
            if !auth.refresh_token.is_empty() {
                self.secrets.put(KEY_REFRESH_TOKEN, &auth.refresh_token)?;
                auth.refresh_token.clear();
            }
        }
        Ok(())
    }

    /// Wipe ALL long-lived secrets from both the OS keyring and any file
    /// fallback. Called from `pocketshell logout --reset` and account
    /// deletion — the host identity itself is being destroyed.
    /// Best-effort; underlying clears swallow "missing" errors.
    pub fn clear_secrets(&self) {
        let _ = self.secrets.clear(KEY_HOST_PRIVATE);
        let _ = self.secrets.clear(KEY_REFRESH_TOKEN);
    }

    /// Clear only the refresh token. Plain `logout` (no --reset) keeps
    /// the host's pinned identity so re-login can reuse it.
    pub fn clear_refresh_token(&self) -> Result<()> {
        self.secrets.clear(KEY_REFRESH_TOKEN)
    }

    /// Try to recover an Ed25519 host keypair from the OS keyring even when
    /// `state.host` is no longer present on disk. Returns `(public_key_b64,
    /// private_key_b64)` if a stored private key was found and parses as a
    /// valid 32-byte Ed25519 seed. The backend pairs by `(user_id, public_key)`,
    /// so reusing the same keypair lets a host that lost its `state.json`
    /// reattach to its existing backend record instead of duplicating it.
    pub fn try_load_host_keypair(&self) -> Option<(String, String)> {
        use base64::Engine;
        use ed25519_dalek::SigningKey;

        let private_key_b64 = self.secrets.get(KEY_HOST_PRIVATE).ok().flatten()?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&private_key_b64)
            .ok()?;
        let bytes_arr: [u8; 32] = bytes.try_into().ok()?;
        let sk = SigningKey::from_bytes(&bytes_arr);
        let vk = sk.verifying_key();
        Some((
            base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()),
            private_key_b64,
        ))
    }

    /// Re-read `trusted_devices` and `pending_devices` from disk into memory.
    /// Daemon's revocation path uses this to rebase on the latest CLI writes
    /// before applying backend-driven revocations.
    pub fn reload_trust(&mut self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let raw = fs::read_to_string(&self.path)?;
        let disk: AgentState = serde_json::from_str(&raw).unwrap_or_default();
        self.state.trusted_devices = disk.trusted_devices;
        self.state.pending_devices = disk.pending_devices;
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

    /// Sync mutable authorization metadata for devices that are already trusted
    /// locally. This deliberately does not add backend-only devices and does
    /// not replace pinned device public keys.
    pub fn apply_trusted_device_permission_updates(
        &mut self,
        backend_devices: &[TrustedDeviceRecord],
    ) -> Vec<String> {
        let backend_by_mobile_id = backend_devices
            .iter()
            .filter(|d| d.revoked_at.is_none() && d.approved_at.is_some())
            .map(|d| (d.mobile_device_id.as_str(), d))
            .collect::<std::collections::HashMap<_, _>>();

        let mut updated = Vec::new();
        for local in &mut self.state.trusted_devices {
            let Some(backend) = backend_by_mobile_id.get(local.mobile_device_id.as_str()) else {
                continue;
            };
            if local.permissions_json != backend.permissions_json {
                local.permissions_json = backend.permissions_json.clone();
                updated.push(local.mobile_device_id.clone());
            }
        }
        updated
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

    pub fn device_has_permission(&self, device_id: &str, permission: &str) -> bool {
        let Some(device) = self.state.trusted_devices.iter().find(|d| {
            d.mobile_device_id == device_id && d.revoked_at.is_none() && d.approved_at.is_some()
        }) else {
            return false;
        };
        let Some(permissions) = device.permissions_json.as_ref() else {
            return true;
        };
        permission_value(permissions, permission)
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

    /// Remove stale terminal-state records from local state.
    ///
    /// Detached sessions are intentionally kept indefinitely: they represent
    /// user-resumable work and must only be ended by an explicit close/kill
    /// command (or host-wide close-all/restart).
    pub fn clear_ended_sessions(
        &mut self,
        stale_after_secs: i64,
        _detach_max_secs: i64,
    ) -> (Vec<String>, Vec<String>) {
        let now = Utc::now();
        let native_detached_to_close = Vec::new();
        let all_expired = Vec::new();
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

    /// Test-only constructor: builds an in-memory StateStore rooted at `path`'s
    /// parent (used as the SecretStore fallback dir). Lets other modules in the
    /// crate exercise StateStore-coupled logic without going through the
    /// HOME-redirected `load()` dance.
    #[cfg(test)]
    pub(crate) fn new_for_test(path: PathBuf, state: AgentState) -> Self {
        let parent = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        Self {
            path,
            state,
            secrets: SecretStore::new(parent),
        }
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

/// Write `bytes` to `path` atomically: write to a sibling tempfile, fsync, rename.
/// Prevents partial writes from a killed/crashing process leaving the destination
/// in a half-state — the rename is atomic on POSIX, so readers either see the old
/// contents or the new contents but never a truncation. The 0o600 mode is set
/// on the tempfile before the rename so the destination is never world-readable.
pub(crate) fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| HostError::Config(format!("path has no parent: {path:?}")))?;
    let pid = std::process::id();
    let nonce = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("state"),
        pid,
        nonce
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    set_file_permissions_path(&tmp)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    set_file_permissions_path(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions_path(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions_path(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn permission_value(
    permissions: &std::collections::HashMap<String, serde_json::Value>,
    permission: &str,
) -> bool {
    // `terminal` is the pre-1.x wire name for the `shell` capability; keep
    // the alias so trusted-device records minted by older clients still grant
    // shell access after a host upgrade.
    let aliases: &[&str] = match permission {
        "shell" => &["shell", "terminal"],
        "stats" => &["stats"],
        "sessions" => &["sessions"],
        other => &[other],
    };
    aliases.iter().any(|key| {
        permissions
            .get(*key)
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    })
}

#[cfg(unix)]
fn ensure_owned_by_current_user(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    // SAFETY: geteuid has no preconditions and returns the effective uid.
    let current_uid = unsafe { nix::libc::geteuid() };
    if metadata.uid() != current_uid {
        return Err(HostError::Config(format!(
            "refusing to use {}: owned by uid {}, expected uid {}",
            path.display(),
            metadata.uid(),
            current_uid
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owned_by_current_user(_path: &PathBuf) -> Result<()> {
    Ok(())
}

fn harden_file_permissions(path: &PathBuf) -> Result<()> {
    ensure_owned_by_current_user(path)?;
    set_file_permissions(path)
}

fn harden_dir_permissions(path: &PathBuf) -> Result<()> {
    ensure_owned_by_current_user(path)?;
    set_dir_permissions(path)
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
        let parent = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        StateStore {
            path,
            state: AgentState::default(),
            secrets: SecretStore::new(parent),
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

    #[cfg(unix)]
    #[test]
    fn load_hardens_existing_state_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };

        let state_dir = tmp.path().join(".pocketshell");
        let state_file = state_dir.join("state.json");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            &state_file,
            b"{\n  \"pending_devices\": [],\n  \"trusted_devices\": [],\n  \"sessions\": []\n}\n",
        )
        .unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o644)).unwrap();

        let loaded = StateStore::load();

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        loaded.unwrap();
        assert_eq!(
            fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&state_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
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
    fn save_preserves_trusted_devices_from_disk() {
        // Simulates the daemon saving auth/sessions while a CLI `pocketshell
        // pair` has just written a new trusted device to disk. The daemon's
        // save() must not clobber that device.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        // CLI process: add device m_cli to disk
        let mut cli = make_store(path.clone());
        cli.add_trusted_device(trusted_device("m_cli"));
        cli.save_full().unwrap();

        // Daemon process: stale in-memory view (no devices), saves auth change
        let mut daemon = make_store(path.clone());
        daemon.state.auth = Some(AuthState {
            access_token: "fresh".into(),
            refresh_token: "R".into(),
            access_expires_at: None,
        });
        daemon.save().unwrap();

        // Disk should still contain m_cli AND the daemon's auth update
        let raw = fs::read_to_string(&path).unwrap();
        let parsed: AgentState = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.trusted_devices.len(), 1);
        assert_eq!(parsed.trusted_devices[0].mobile_device_id, "m_cli");
        assert_eq!(parsed.auth.unwrap().access_token, "fresh");
    }

    #[test]
    fn save_full_writes_in_memory_trust_overriding_disk() {
        // Revocation path: daemon reloads trust, removes a revoked device,
        // and must persist that removal via save_full.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        let mut writer = make_store(path.clone());
        writer.add_trusted_device(trusted_device("keep"));
        writer.add_trusted_device(trusted_device("revoke_me"));
        writer.save_full().unwrap();

        let mut daemon = make_store(path.clone());
        daemon.reload_trust().unwrap();
        daemon
            .state
            .trusted_devices
            .retain(|d| d.mobile_device_id != "revoke_me");
        daemon.save_full().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let parsed: AgentState = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.trusted_devices.len(), 1);
        assert_eq!(parsed.trusted_devices[0].mobile_device_id, "keep");
    }

    #[test]
    fn reload_trust_picks_up_disk_changes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        // Initial: empty
        let initial = make_store(path.clone());
        initial.save_full().unwrap();

        // External process writes a trusted device
        let mut external = make_store(path.clone());
        external.add_trusted_device(trusted_device("late_arrival"));
        external.save_full().unwrap();

        // Stale in-memory daemon reloads
        let mut daemon = make_store(path.clone());
        assert!(daemon.state.trusted_devices.is_empty());
        daemon.reload_trust().unwrap();
        assert_eq!(daemon.state.trusted_devices.len(), 1);
        assert_eq!(
            daemon.state.trusted_devices[0].mobile_device_id,
            "late_arrival"
        );
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
    fn device_has_permission_enforces_explicit_permissions_with_legacy_default() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("legacy"));

        let mut restricted = trusted_device("restricted");
        restricted.permissions_json = Some(std::collections::HashMap::from([
            ("shell".to_string(), serde_json::json!(true)),
            ("stats".to_string(), serde_json::json!(false)),
        ]));
        store.add_trusted_device(restricted);

        let mut terminal_alias = trusted_device("terminal-alias");
        terminal_alias.permissions_json = Some(std::collections::HashMap::from([(
            "terminal".to_string(),
            serde_json::json!(true),
        )]));
        store.add_trusted_device(terminal_alias);

        assert!(store.device_has_permission("legacy", "shell"));
        assert!(store.device_has_permission("restricted", "shell"));
        assert!(!store.device_has_permission("restricted", "stats"));
        assert!(!store.device_has_permission("restricted", "sessions"));
        assert!(store.device_has_permission("terminal-alias", "shell"));
        assert!(!store.device_has_permission("missing", "shell"));
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
    fn apply_trusted_device_permission_updates_only_updates_existing_devices() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("existing"));

        let mut existing = trusted_device("existing");
        existing.permissions_json = Some(std::collections::HashMap::from([(
            "stats".to_string(),
            serde_json::json!(true),
        )]));
        let mut backend_only = trusted_device("backend-only");
        backend_only.permissions_json = Some(std::collections::HashMap::from([(
            "shell".to_string(),
            serde_json::json!(true),
        )]));

        let updated = store.apply_trusted_device_permission_updates(&[existing, backend_only]);

        assert_eq!(updated, vec!["existing".to_string()]);
        assert_eq!(store.state.trusted_devices.len(), 1);
        assert!(store.device_has_permission("existing", "stats"));
        assert!(!store.device_has_permission("backend-only", "shell"));
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
    fn clear_ended_sessions_keeps_old_detached_non_persistent() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        let mut s = session_record("det", SessionState::Detached, 500);
        s.persistent = false;
        store.upsert_session(s);

        let (native, expired) = store.clear_ended_sessions(300, 100);
        assert!(native.is_empty());
        assert!(expired.is_empty());
        assert_eq!(store.state.sessions.len(), 1);
        assert_eq!(store.state.sessions[0].session_id, "det");
    }

    #[test]
    fn clear_ended_sessions_keeps_old_detached_persistent_native() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        let mut s = session_record("det", SessionState::Detached, 500);
        s.persistent = true;
        s.tmux_session_name = None;
        store.upsert_session(s);

        let (native, expired) = store.clear_ended_sessions(300, 100);
        assert!(native.is_empty());
        assert!(expired.is_empty());
        assert_eq!(store.state.sessions.len(), 1);
        assert_eq!(store.state.sessions[0].session_id, "det");
    }

    #[test]
    fn get_device_public_key_returns_stored_key() {
        let mut store = make_store(PathBuf::from("/tmp/unused"));
        store.add_trusted_device(trusted_device("m1"));
        assert_eq!(store.get_device_public_key("m1"), Some("pubkey"));
        assert!(store.get_device_public_key("missing").is_none());
    }
}
