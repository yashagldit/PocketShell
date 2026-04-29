//! OS-keyring secret storage with file-based fallback.
//!
//! Long-lived host secrets (the ED25519 private key and the refresh token)
//! used to live in plaintext in `~/.pocketshell/state.json`. Mode 0o600 made
//! that *acceptable* but not great: any backup/sync tool, disk image, or
//! user-mode process running as the same UID could lift them. This module
//! pushes those secrets into the platform-native keychain (macOS Keychain,
//! Windows Credential Manager, libsecret/kwallet on Linux) and falls back to
//! a 0o600-protected file only when the keyring is unavailable (typical on
//! headless Linux servers without secret-service).
//!
//! The module is intentionally narrow: callers see `get` / `put` / `clear`
//! and don't have to care which backend served the value.
//!
//! Migration: on first save after upgrade, plaintext fields in `state.json`
//! are moved into the keyring and replaced with empty strings. On read, an
//! empty field falls through to the keyring.

use crate::error::{HostError, Result};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, warn};

const SERVICE: &str = "pocketshell-host-agent";

/// Key under which the host's ED25519 private key is stored.
pub const KEY_HOST_PRIVATE: &str = "host-private-key";
/// Key under which the long-lived refresh token is stored.
pub const KEY_REFRESH_TOKEN: &str = "host-refresh-token";

/// Try the OS keyring first; fall back to a 0o600 file on failure.
#[derive(Debug)]
pub struct SecretStore {
    fallback_dir: PathBuf,
}

impl SecretStore {
    /// `fallback_dir` should be the daemon's state dir (already 0o700).
    pub fn new(fallback_dir: PathBuf) -> Self {
        Self { fallback_dir }
    }

    /// Read a secret. Returns `Ok(None)` if neither the keyring nor the
    /// fallback file holds a value (first-run case).
    pub fn get(&self, name: &str) -> Result<Option<String>> {
        match keyring::Entry::new(SERVICE, name) {
            Ok(entry) => match entry.get_password() {
                Ok(v) => return Ok(Some(v)),
                Err(keyring::Error::NoEntry) => {}
                Err(e) => {
                    debug!(
                        "keyring get({}/{}) unavailable: {} — falling back to file",
                        SERVICE, name, e
                    );
                }
            },
            Err(e) => {
                debug!(
                    "keyring entry construct failed for {}/{}: {} — using file fallback",
                    SERVICE, name, e
                );
            }
        }
        self.get_file(name)
    }

    /// Write a secret. Prefers the OS keyring; falls back to a 0o600 file
    /// only if the keyring rejects the write (e.g., headless Linux).
    pub fn put(&self, name: &str, value: &str) -> Result<()> {
        match keyring::Entry::new(SERVICE, name) {
            Ok(entry) => match entry.set_password(value) {
                Ok(()) => {
                    // Successfully stored in keyring — wipe any stale file
                    // copy so disk state never has the secret again.
                    let _ = fs::remove_file(self.fallback_path(name));
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "keyring set({}/{}) failed: {} — falling back to 0o600 file",
                        SERVICE, name, e
                    );
                }
            },
            Err(e) => {
                warn!(
                    "keyring entry construct failed for {}/{}: {} — using 0o600 file",
                    SERVICE, name, e
                );
            }
        }
        self.put_file(name, value)
    }

    /// Remove a secret from both backends — used on logout and account
    /// deletion. Best-effort; ignores "not found" errors.
    pub fn clear(&self, name: &str) -> Result<()> {
        if let Ok(entry) = keyring::Entry::new(SERVICE, name) {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => debug!("keyring delete({}/{}) error: {}", SERVICE, name, e),
            }
        }
        let _ = fs::remove_file(self.fallback_path(name));
        Ok(())
    }

    fn fallback_path(&self, name: &str) -> PathBuf {
        // Filename is just the key — the parent dir is already 0o700.
        self.fallback_dir.join(format!("secret_{name}"))
    }

    fn get_file(&self, name: &str) -> Result<Option<String>> {
        let p = self.fallback_path(name);
        if !p.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&p)?;
        Ok(Some(raw))
    }

    fn put_file(&self, name: &str, value: &str) -> Result<()> {
        if !self.fallback_dir.exists() {
            fs::create_dir_all(&self.fallback_dir)?;
        }
        let p = self.fallback_path(name);
        fs::write(&p, value)?;
        harden_secret_file(&p)?;
        Ok(())
    }
}

#[cfg(unix)]
fn harden_secret_file(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).map_err(|e| {
        HostError::Backend(format!(
            "could not chmod 0600 secret file {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn harden_secret_file(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Tests use a per-test fallback dir; OS keyring may or may not be
    /// available in CI, so all tests force the file path by using a
    /// throwaway service name unlikely to clash with the host's real
    /// keychain. The underlying `keyring` crate's mock backend is not
    /// public, so we just exercise the file fallback paths directly.
    #[test]
    fn put_and_get_via_file_fallback() {
        let dir = tempdir().unwrap();
        let store = SecretStore::new(dir.path().to_path_buf());
        // Force file fallback by writing through put_file directly.
        store.put_file("test-key", "secret-value").unwrap();
        let got = store.get_file("test-key").unwrap();
        assert_eq!(got.as_deref(), Some("secret-value"));
    }

    #[test]
    fn get_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        let store = SecretStore::new(dir.path().to_path_buf());
        // Use a name that's almost certainly not in the host keyring.
        let got = store.get("absent-test-secret-9b7c4a").unwrap();
        assert!(got.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn fallback_file_is_chmod_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let store = SecretStore::new(dir.path().to_path_buf());
        store.put_file("perm-test", "x").unwrap();
        let mode = fs::metadata(store.fallback_path("perm-test"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
