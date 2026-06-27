use crate::api::BackendClient;
use crate::error::Result;
use tokio::time::{Duration, Instant};

/// Safety margin subtracted from the TURN cred TTL so we re-fetch slightly
/// before they actually expire and never hand the WebRTC stack creds that
/// die mid-handshake.
pub(super) const TURN_CACHE_SAFETY_MARGIN_SECS: u64 = 30;
/// Floor for cached TTL so a backend that returns 0 doesn't put us back
/// into a fetch-on-every-offer loop. Cloudflare typically returns 1h+.
pub(super) const TURN_CACHE_MIN_TTL_SECS: u64 = 60;

#[derive(Clone)]
pub(super) struct CachedTurnCreds {
    username: String,
    credential: String,
    uris: Vec<String>,
    expires_at: Instant,
}

/// In-process cache for TURN credentials issued by the backend.
///
/// The backend's `/webrtc/turn-credentials` endpoint is rate-limited
/// (default 30/hour per user). The host previously fetched fresh creds
/// on every `files_offer`/`agent_offer`/`stats_offer`/`session_offer` and
/// direct-host-transfer, which blew through the limit during normal use
/// (each of the 4 peer types × mobile reconnects/StrictMode remounts) and
/// left the host unable to answer with `Rate limit exceeded`. The mobile
/// already caches creds for the full TTL — this mirrors that behavior.
pub(super) struct TurnCredsCache {
    inner: tokio::sync::Mutex<Option<CachedTurnCreds>>,
}

impl TurnCredsCache {
    pub(super) fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(None),
        }
    }

    pub(super) async fn get(
        &self,
        backend: &BackendClient,
        token: &str,
    ) -> Result<(String, String, i64, Vec<String>)> {
        let mut guard = self.inner.lock().await;
        if let Some(cached) = guard.as_ref() {
            if Instant::now() < cached.expires_at {
                return Ok((
                    cached.username.clone(),
                    cached.credential.clone(),
                    0,
                    cached.uris.clone(),
                ));
            }
        }
        let (username, credential, ttl, uris) = backend.turn_credentials(token).await?;
        let lifetime = (ttl.max(0) as u64)
            .max(TURN_CACHE_MIN_TTL_SECS)
            .saturating_sub(TURN_CACHE_SAFETY_MARGIN_SECS);
        let expires_at = Instant::now() + Duration::from_secs(lifetime);
        *guard = Some(CachedTurnCreds {
            username: username.clone(),
            credential: credential.clone(),
            uris: uris.clone(),
            expires_at,
        });
        Ok((username, credential, ttl, uris))
    }
}
