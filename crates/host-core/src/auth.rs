//! Cross-process safe token refresh.
//!
//! The host agent runs as a long-lived daemon, but short-lived CLI commands
//! (e.g. `pocketshell pair-qr`) also touch the same `state.json` and can
//! issue refresh requests. Without coordination two processes can both load
//! the same refresh token and fire `/token/refresh` concurrently — the first
//! wins, the server marks the JTI `used` in Redis, and the loser is now
//! holding a token that will never work again. If the loser is the daemon and
//! the winner crashes before persisting (or is killed mid-rotation), the
//! daemon ends up stuck on a permanently-blacklisted token.
//!
//! [`safe_refresh_if_needed`] solves this with a file-lock around the
//! read/refresh/write window so only one process at a time can rotate, and an
//! intra-window reload to adopt fresh tokens that another process wrote
//! between the time we loaded state and the time we acquired the lock.

use crate::api::BackendClient;
use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::AuthState;
use crate::secure::{parse_jwt_exp, require_refresh_token, token_is_expiring};
use crate::store::StateStore;
use chrono::Utc;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use tracing::warn;

/// RAII guard for the cross-process refresh lock. Releases via `flock(LOCK_UN)`
/// (implicit when the file descriptor is closed on drop).
pub struct RefreshLock {
    _file: File,
}

fn lock_path() -> Result<PathBuf> {
    let paths = AppConfig::paths()?;
    if !paths.state_dir.exists() {
        std::fs::create_dir_all(&paths.state_dir)?;
    }
    Ok(paths.state_dir.join("refresh.lock"))
}

/// Acquire the exclusive refresh lock, blocking until it's available.
/// Synchronous; callers in async contexts should use [`acquire_refresh_lock_async`].
pub fn acquire_refresh_lock() -> Result<RefreshLock> {
    let path = lock_path()?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;

    // SAFETY: `flock` only inspects the fd we pass; `file` outlives the call.
    let rc = unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX) };
    if rc != 0 {
        return Err(HostError::Io(std::io::Error::last_os_error()));
    }
    Ok(RefreshLock { _file: file })
}

/// Async-safe lock acquisition. The actual `flock` syscall is blocking, so we
/// run it on tokio's blocking pool to avoid stalling the runtime if another
/// process is holding the lock for a long time.
pub async fn acquire_refresh_lock_async() -> Result<RefreshLock> {
    tokio::task::spawn_blocking(acquire_refresh_lock)
        .await
        .map_err(|e| HostError::Backend(format!("refresh lock task join error: {e}")))?
}

/// Returns true if the refresh-token JWT's `exp` claim has passed.
/// When this is true, no amount of retrying against the backend will succeed
/// — the only path forward is re-pairing.
pub fn refresh_token_jwt_expired(auth: &AuthState) -> bool {
    match parse_jwt_exp(&auth.refresh_token) {
        Some(exp) => exp <= Utc::now(),
        None => false, // can't decode → assume valid, let backend decide
    }
}

/// Refresh the access token if it's near expiry, with cross-process
/// coordination so concurrent callers can't burn the refresh token in a
/// rotation race.
///
/// Behavior on `AuthRevoked` (HTTP 401): leaves `state.auth` untouched on
/// disk and in `store`. The caller should retry later — another process may
/// have rotated successfully and persisted, or the access token may still
/// have life left for normal calls. The caller can use
/// [`refresh_token_jwt_expired`] to distinguish a transient race from a
/// genuinely-dead token (where re-pairing is required).
pub async fn safe_refresh_if_needed(
    backend: &BackendClient,
    store: &mut StateStore,
) -> Result<()> {
    store.require_logged_in()?;

    {
        let auth = store
            .state
            .auth
            .as_ref()
            .ok_or(HostError::NotLoggedIn)?;
        if !token_is_expiring(auth.access_expires_at, 60) {
            return Ok(());
        }
    }

    // Hold the lock across read → refresh → write. Anyone else trying to
    // refresh blocks here until we release.
    let _lock = acquire_refresh_lock_async().await?;

    // Re-read state inside the lock; another process that held the lock
    // before us may have already rotated the token.
    let reloaded = StateStore::load()?;
    let reloaded_auth = reloaded
        .state
        .auth
        .clone()
        .ok_or(HostError::NotLoggedIn)?;
    if !token_is_expiring(reloaded_auth.access_expires_at, 60) {
        *store = reloaded;
        return Ok(());
    }

    let refresh = require_refresh_token(&reloaded_auth)?;
    let tokens = match backend.refresh_tokens(&refresh).await {
        Ok(t) => t,
        Err(HostError::AuthRevoked) => {
            // Inside the lock our snapshot is authoritative for this host's
            // refresh attempts. A 401 here means the JTI was blacklisted —
            // either the JWT exp passed, the host record was deleted, or an
            // unlocked legacy caller (older binary version) raced us. We do
            // NOT touch persisted state: keep the refresh token on disk so a
            // later retry can recover if circumstances change, and so the
            // user gets a clean diagnostic (`refresh_token_jwt_expired`) to
            // decide whether to re-pair.
            return Err(HostError::AuthRevoked);
        }
        Err(e) => return Err(e),
    };

    let new_auth = AuthState {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        access_expires_at: parse_jwt_exp(&tokens.access_token),
    };

    let mut to_persist = reloaded;
    to_persist.state.auth = Some(new_auth.clone());
    if let Err(e) = to_persist.save() {
        // Persistence failed — the new tokens are valid in memory but the
        // server has marked the old refresh JTI used. If we crash now, the
        // next startup will be stuck. Surface loudly.
        warn!(
            "CRITICAL: refreshed tokens but failed to persist: {} — daemon will retry but may need re-pair if it restarts before next refresh",
            e
        );
        return Err(e);
    }
    *store = to_persist;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_token(exp_offset_secs: i64) -> String {
        let exp = (Utc::now() + chrono::Duration::seconds(exp_offset_secs)).timestamp();
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload = serde_json::json!({"exp": exp, "sub": "u", "type": "refresh"});
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{body}.sig")
    }

    #[test]
    fn refresh_token_jwt_expired_true_when_past() {
        let auth = AuthState {
            access_token: "a".into(),
            refresh_token: make_token(-10),
            access_expires_at: None,
        };
        assert!(refresh_token_jwt_expired(&auth));
    }

    #[test]
    fn refresh_token_jwt_expired_false_when_future() {
        let auth = AuthState {
            access_token: "a".into(),
            refresh_token: make_token(3600),
            access_expires_at: None,
        };
        assert!(!refresh_token_jwt_expired(&auth));
    }

    #[test]
    fn refresh_token_jwt_expired_false_when_unparseable() {
        let auth = AuthState {
            access_token: "a".into(),
            refresh_token: "not-a-jwt".into(),
            access_expires_at: None,
        };
        // Defensive: don't lie about expiry when we can't decode.
        assert!(!refresh_token_jwt_expired(&auth));
    }
}
