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

use crate::api::{build_reauth_payload, BackendClient};
use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::AuthState;
use crate::secure::{parse_jwt_exp, require_refresh_token, token_is_expiring};
use crate::signaling_crypto::parse_ed25519_signing_key;
use crate::store::StateStore;
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use tracing::{info, warn};

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
pub async fn safe_refresh_if_needed(backend: &BackendClient, store: &mut StateStore) -> Result<()> {
    store.require_logged_in()?;

    {
        let auth = store.state.auth.as_ref().ok_or(HostError::NotLoggedIn)?;
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
    let reloaded_auth = reloaded.state.auth.clone().ok_or(HostError::NotLoggedIn)?;
    if !token_is_expiring(reloaded_auth.access_expires_at, 60) {
        *store = reloaded;
        return Ok(());
    }

    let refresh = require_refresh_token(&reloaded_auth)?;
    let tokens = match backend.refresh_tokens(&refresh).await {
        Ok(t) => t,
        Err(HostError::AuthRevoked) => {
            // The rotating refresh-token path is dead (Redis JTI lost,
            // rotation race, manual revocation, …). Before surfacing
            // AuthRevoked — which forces the user to re-pair — try the
            // permanent Ed25519 signing key. The backend verifies the
            // signature against `hosts.public_key` in Postgres, so this
            // path survives Redis outages and is the whole reason the
            // host has a permanent identity keypair.
            //
            // If signing-key reauth ALSO fails with AuthRevoked, the
            // signing key itself is no longer trusted (host deleted,
            // disabled, …) — only then do we propagate AuthRevoked.
            return reauth_with_signing_key(backend, store, reloaded).await;
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

/// Recovery path: re-authenticate the host using its permanent Ed25519
/// signing key against `POST /auth/host/reauth`. Called when refresh-token
/// rotation has been broken by a Redis outage, persistence-after-rotation
/// race, or manual revocation. Persists the new token pair just like the
/// refresh path.
///
/// `reloaded` is the freshly-loaded store snapshot from inside the refresh
/// lock — we re-use it as the destination for the new tokens so any other
/// fields written by a concurrent process (trust changes, sessions) survive.
async fn reauth_with_signing_key(
    backend: &BackendClient,
    store: &mut StateStore,
    reloaded: StateStore,
) -> Result<()> {
    let host_state = reloaded.state.host.as_ref().ok_or(HostError::NotLoggedIn)?;
    let host_id = host_state.host_id.clone();
    let private_key_b64 = host_state.private_key.clone();
    if private_key_b64.is_empty() {
        // No signing key on this install — there's no recovery path. This
        // should not happen for a paired host (the keyring or fallback file
        // is hydrated at load time), but if state is corrupted we surface
        // AuthRevoked so the caller's "re-pair" branch fires.
        warn!("signing-key reauth unavailable: no private key in store");
        return Err(HostError::AuthRevoked);
    }

    let signing = parse_ed25519_signing_key(&private_key_b64).map_err(|e| {
        warn!("signing-key reauth aborted: stored private key failed to decode: {e}");
        HostError::AuthRevoked
    })?;

    let tokens = sign_and_reauth(backend, &host_id, &signing).await?;
    info!("recovered host auth via signing key (host_id={})", host_id);

    let new_auth = AuthState {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token,
        access_expires_at: parse_jwt_exp(&tokens.access_token),
    };
    let mut to_persist = reloaded;
    to_persist.state.auth = Some(new_auth);
    if let Err(e) = to_persist.save() {
        warn!(
            "CRITICAL: signing-key reauth succeeded but persistence failed: {} — next process restart will need to reauth again",
            e
        );
        return Err(e);
    }
    *store = to_persist;
    Ok(())
}

/// The pure network+crypto half of the signing-key reauth. Split out from
/// [`reauth_with_signing_key`] so it can be tested without disk / keyring
/// access — those tests would otherwise clobber the real `pocketshell`
/// keychain entry when run on a developer's machine.
///
/// Signed payload uses an RFC 3339 timestamp with seconds precision and an
/// explicit `+00:00` offset. The same string we sign is sent on the wire so
/// the server reconstructs the byte sequence verbatim — any reformatting
/// on either side breaks verification.
async fn sign_and_reauth(
    backend: &BackendClient,
    host_id: &str,
    signing: &SigningKey,
) -> Result<crate::models::TokenPairResponse> {
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, false);
    let payload = build_reauth_payload(host_id, &issued_at);
    let sig_b64 =
        base64::engine::general_purpose::STANDARD.encode(signing.sign(&payload).to_bytes());
    backend.host_reauth(host_id, &issued_at, &sig_b64).await
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

    // -----------------------------------------------------------------
    // Signing-key reauth — see `sign_and_reauth` for the split-out
    // network/crypto core. These tests deliberately avoid going through
    // `StateStore::save()` (which would write to the real macOS Keychain
    // under the same SERVICE name as the running daemon) and instead
    // exercise the pure-function boundary.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn sign_and_reauth_signs_payload_and_sends_to_backend() {
        use rand::rngs::OsRng;
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // We can't predict `issued_at` (it's `now()`), so match only on the
        // structure: the backend got a host_id, an issued_at, and a
        // signature, all non-empty. The byte-level signing format is
        // pinned separately by `build_reauth_payload_format_is_stable`.
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/host/reauth"))
            .and(body_partial_json(serde_json::json!({"host_id": "h-1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-a",
                "refresh_token": "fresh-r",
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let backend = BackendClient::new(server.uri());
        let signing = SigningKey::generate(&mut OsRng);
        let resp = sign_and_reauth(&backend, "h-1", &signing).await.unwrap();
        assert_eq!(resp.access_token, "fresh-a");
        assert_eq!(resp.refresh_token, "fresh-r");
    }

    #[tokio::test]
    async fn sign_and_reauth_propagates_auth_revoked_when_backend_rejects() {
        use rand::rngs::OsRng;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 401 from the reauth endpoint means the signing key itself is no
        // longer trusted (host record deleted, disabled, …). The daemon's
        // outer-loop branch on AuthRevoked will then warn "re-pair via
        // pocketshell pair <CODE>" — which is the only correct response
        // when permanent identity is gone.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/host/reauth"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let backend = BackendClient::new(server.uri());
        let signing = SigningKey::generate(&mut OsRng);
        let err = sign_and_reauth(&backend, "h-1", &signing)
            .await
            .unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked), "got {err:?}");
    }

    #[tokio::test]
    async fn sign_and_reauth_returns_transient_error_on_5xx() {
        use rand::rngs::OsRng;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 500 / network errors should NOT escalate to AuthRevoked — the
        // caller will retry on the next tick. Only 401 means the key
        // itself is dead.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/host/reauth"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let backend = BackendClient::new(server.uri());
        let signing = SigningKey::generate(&mut OsRng);
        let err = sign_and_reauth(&backend, "h-1", &signing)
            .await
            .unwrap_err();
        assert!(matches!(err, HostError::Backend(_)), "got {err:?}");
    }
}
