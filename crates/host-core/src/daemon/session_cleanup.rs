use crate::agent_session::AgentRouter;
use crate::api::BackendClient;
use crate::models::SessionState;
use crate::pty::SessionManager;
use crate::signaling_crypto::SessionCipher;
use crate::store::StateStore;
use crate::webrtc_manager::WebRtcManager;
use std::collections::HashMap;
use std::sync::Arc;

/// Tear down every active session on this host: kill PTYs, drop WebRTC
/// peers, stop agent pumps, and mark the corresponding backend rows
/// `ended`. Shared by the legacy `signal → channel=control` path and
/// the newer `host_control` REST-driven path.
pub(super) async fn close_all_active_sessions(
    store: &mut StateStore,
    backend: &BackendClient,
    peer_session_routes: &mut HashMap<String, String>,
    session_ciphers: &mut HashMap<String, SessionCipher>,
    sessions: &mut SessionManager,
    webrtc_mgr: &mut WebRtcManager,
    agent_ws_pumps: &mut HashMap<String, tokio::task::JoinHandle<()>>,
    agent_router: &Arc<AgentRouter>,
) {
    let daemon_host_id = store.host_id().unwrap_or_default();
    let active_backend_sessions = match store.access_token().map(|s| s.to_string()) {
        Ok(token) => backend
            .list_active_sessions_full(&token, &daemon_host_id)
            .await
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    peer_session_routes.clear();
    session_ciphers.clear();
    sessions.close_all();
    webrtc_mgr.close_all().await;

    for (_, handle) in agent_ws_pumps.drain() {
        handle.abort();
    }
    agent_router.close_all().await;

    if let Ok(token) = store.access_token().map(|s| s.to_string()) {
        for session in active_backend_sessions {
            let _ = backend
                .transition_session(&token, &session.id, SessionState::Ended, None)
                .await;
            store.touch_session_state(&session.id, SessionState::Ended);
        }
    }

    let _ = store.save();
}
