use crate::api::{derive_access_expiry, BackendClient, HeartbeatAction};
use crate::audit::{write_audit_event, AuditEvent};
use crate::config::AppConfig;
use crate::discovery::SessionDiscovery;
use crate::error::{HostError, Result};
use crate::models::{AttachTarget, HeartbeatRequest, SessionRecord, SessionRequest, SessionState, SignalEnvelope};
use crate::pty::SessionManager;
use crate::secure::{require_refresh_token, token_is_expiring};
use crate::session::accept_session;
use crate::models::StatsSnapshot;
use crate::stats::StatsCollector;
use crate::store::StateStore;
use crate::transport::{connect_host_ws, recv_signal, send_signal};
use crate::webrtc_manager::{WebRtcEvent, WebRtcManager};
use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;
use tokio::time::{interval, sleep, Duration, Instant};
use tracing::{error, info, warn};

/// Whether the backend kill-action is honored. Set to false during testing.
const HONOR_KILL_ACTION: bool = false;

/// In-progress file transfer from a mobile device.
struct PendingFileTransfer {
    name: String,
    chunks: Vec<String>,
}

/// Handle a file transfer protocol message (sentinel already stripped).
fn handle_file_transfer_msg(
    transfers: &mut HashMap<String, PendingFileTransfer>,
    session_id: &str,
    json_str: &str,
    sessions: &mut crate::pty::SessionManager,
) {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        warn!("invalid file transfer JSON");
        return;
    };

    let op = val.get("op").and_then(|v| v.as_str()).unwrap_or_default();
    let id = val.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();

    match op {
        "start" => {
            let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("clipboard.jpg").to_string();
            let chunks = val.get("chunks").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            transfers.insert(id, PendingFileTransfer {
                name,
                chunks: Vec::with_capacity(chunks),
            });
        }
        "chunk" => {
            if let Some(transfer) = transfers.get_mut(&id) {
                let data = val.get("d").and_then(|v| v.as_str()).unwrap_or_default();
                transfer.chunks.push(data.to_string());
            }
        }
        "end" => {
            if let Some(transfer) = transfers.remove(&id) {
                let full_b64: String = transfer.chunks.concat();
                match base64::engine::general_purpose::STANDARD.decode(&full_b64) {
                    Ok(image_bytes) => {
                        // Determine extension from name
                        let ext = transfer.name
                            .rsplit('.')
                            .next()
                            .unwrap_or("jpg");
                        let temp_name = format!(
                            "pocketshell-paste-{}.{}",
                            chrono::Utc::now().format("%Y%m%d-%H%M%S-%3f"),
                            ext,
                        );
                        let temp_path = format!("/tmp/{}", temp_name);

                        match std::fs::write(&temp_path, &image_bytes) {
                            Ok(_) => {
                                info!(
                                    "file transfer complete: {} ({} bytes) -> {}",
                                    transfer.name,
                                    image_bytes.len(),
                                    temp_path,
                                );
                                // Inject the file path into the PTY as terminal input
                                let path_bytes = temp_path.as_bytes().to_vec();
                                if let Err(e) = sessions.write_input(session_id, path_bytes) {
                                    warn!("failed to inject file path into PTY: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("failed to write temp file {}: {}", temp_path, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("file transfer base64 decode failed: {}", e);
                    }
                }
            }
        }
        _ => {
            warn!("unknown file transfer op: {}", op);
        }
    }
}

pub async fn run_foreground(config: AppConfig) -> Result<()> {
    if let Some(min) = &config.min_backend_host_version {
        if !version_gte(&config.app_version, min) {
            return Err(HostError::Version(format!(
                "current={} minimum={}",
                config.app_version, min
            )));
        }
    }

    let mut store = StateStore::load()?;
    store.require_logged_in()?;

    let host_id = store.host_id()?;
    let backend = BackendClient::new(config.backend_base_url.clone());

    let mut stats = StatsCollector::new();
    let mut stats_active = false;
    let mut stats_deadline: Option<Instant> = None;
    let mut sessions = SessionManager::new(config.session_limit);
    let (webrtc_event_tx, mut webrtc_event_rx) = tokio::sync::mpsc::unbounded_channel::<WebRtcEvent>();
    let mut webrtc_mgr = WebRtcManager::new(webrtc_event_tx);
    let shell = AppConfig::default_shell();

    let mut file_transfers: HashMap<String, PendingFileTransfer> = HashMap::new();
    let mut minute_stats_buffer: Vec<StatsSnapshot> = Vec::with_capacity(5);

    info!("daemon starting for host_id={}", host_id);
    let _ = write_audit_event(AuditEvent {
        event_type: "daemon_started".to_string(),
        host_id: Some(host_id.clone()),
        ..AuditEvent::new("daemon_started")
    });

    let mut backoff_secs = 1_u64;

    loop {
        match refresh_auth_if_needed(&backend, &mut store).await {
            Ok(()) => {}
            Err(HostError::AuthRevoked) => {
                warn!("authentication expired — waiting for re-pairing via `pocketshell pair`");
                sleep(Duration::from_secs(60)).await;
                // Reload state in case user ran `pocketshell login` in another terminal
                store = StateStore::load()?;
                continue;
            }
            Err(err) => {
                warn!("auth refresh failed: {} — retrying in 30s", err);
                sleep(Duration::from_secs(30)).await;
                store = StateStore::load()?;
                continue;
            }
        }
        let token = store.access_token()?.to_string();
        let mut last_tick;
        let mut ws = match connect_host_ws(&config.ws_url, &host_id, &token).await {
            Ok(socket) => {
                info!("control-plane connected");
                backoff_secs = 1;
                last_tick = Instant::now();
                socket
            }
            Err(err) => {
                warn!("control-plane connect error: {}", err);
                sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
                continue;
            }
        };

        let mut heartbeat_tick = interval(Duration::from_secs(config.heartbeat_interval_secs));
        let mut stats_tick = interval(Duration::from_secs(config.stats_interval_secs));
        let mut stats_bg_tick = interval(Duration::from_secs(30 * 60));
        stats_bg_tick.tick().await; // skip immediate first tick
        let mut output_tick = interval(Duration::from_millis(40));
        let mut trusted_devices_tick = interval(Duration::from_secs(30));
        let mut stats_minute_tick = interval(Duration::from_secs(60));
        stats_minute_tick.tick().await; // skip immediate first tick
        let mut stats_minute_flush_tick = interval(Duration::from_secs(5 * 60));
        stats_minute_flush_tick.tick().await; // skip immediate first tick
        let mut alert_tick = interval(Duration::from_secs(config.alert_check_interval_secs));
        let mut alert_checker = crate::alerts::AlertChecker::new();
        let mut discovery_tick = interval(Duration::from_secs(15));
        let mut webrtc_poll_tick = interval(Duration::from_millis(50));

        loop {
            tokio::select! {
                _ = heartbeat_tick.tick() => {
                    let now = Instant::now();
                    if now.duration_since(last_tick) > Duration::from_secs(config.heartbeat_interval_secs * 3) {
                        warn!("possible sleep/wake detected; forcing reconnect");
                        break;
                    }
                    last_tick = now;

                    match refresh_auth_if_needed(&backend, &mut store).await {
                        Ok(()) => {}
                        Err(HostError::AuthRevoked) => {
                            warn!("authentication expired — run `pocketshell pair` to re-authenticate");
                            break; // reconnect loop will retry after reload
                        }
                        Err(err) => {
                            warn!("token refresh failed: {} — will retry next tick", err);
                            continue;
                        }
                    }

                    let payload = HeartbeatRequest {
                        host_id: host_id.clone(),
                        active_sessions: sessions.active_count(),
                        pending_devices: store.state.pending_devices.len(),
                    };

                    let token = store.access_token()?.to_string();
                    match backend.send_heartbeat(&token, &payload).await {
                        Ok(HeartbeatAction::Kill) if HONOR_KILL_ACTION => {
                            info!("backend requested shutdown — stopping daemon");
                            sessions.close_all();
                            webrtc_mgr.close_all().await;
                            let _ = write_audit_event(AuditEvent {
                                event_type: "daemon_stopped".to_string(),
                                host_id: Some(host_id.clone()),
                                ..AuditEvent::new("daemon_stopped")
                            });
                            store.save()?;
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(err) => {
                            warn!("heartbeat failed: {}", err);
                        }
                    }

                    store.clear_ended_sessions(config.stale_session_secs as i64);
                    let _ = store.save();
                }
                _ = trusted_devices_tick.tick() => {
                    if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                        if let Ok(devices) = backend.list_trusted_devices(&token, &host_id).await {
                            let revoked_ids = devices
                                .iter()
                                .filter(|d| d.revoked_at.is_some())
                                .map(|d| d.mobile_device_id.clone())
                                .collect::<Vec<_>>();

                            store.set_trusted_devices(devices);
                            for revoked_id in revoked_ids {
                                let affected_sessions = store
                                    .state
                                    .sessions
                                    .iter()
                                    .filter(|s| s.mobile_device_id == revoked_id)
                                    .map(|s| s.session_id.clone())
                                    .collect::<Vec<_>>();
                                for session_id in affected_sessions {
                                    let _ = sessions.close_session(&session_id);
                                    store.touch_session_state(&session_id, SessionState::Failed);
                                    let _ = backend
                                        .transition_session(&token, &session_id, SessionState::Failed, None)
                                        .await;
                                }
                            }
                            let _ = store.save();
                        }
                    }
                }
                _ = stats_tick.tick() => {
                    // Auto-expire subscription after deadline
                    if stats_active {
                        if let Some(deadline) = stats_deadline {
                            if Instant::now() > deadline {
                                stats_active = false;
                                stats_deadline = None;
                                info!("stats subscription expired, pausing");
                            }
                        }
                    }

                    if stats_active {
                        let snapshot = stats.snapshot();
                        let msg = SignalEnvelope {
                            message_type: "stats".to_string(),
                            session_id: None,
                            payload: Some(serde_json::to_value(snapshot).unwrap_or(serde_json::json!({}))),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra: std::collections::HashMap::new(),
                        };
                        if let Err(err) = send_signal(&mut ws, &msg).await {
                            warn!("stats send failed: {}", err);
                            break;
                        }
                    }
                }
                _ = stats_bg_tick.tick() => {
                    // Low-frequency background snapshot — persisted to DB
                    if !stats_active {
                        let snapshot = stats.snapshot();
                        let msg = SignalEnvelope {
                            message_type: "stats_snapshot".to_string(),
                            session_id: None,
                            payload: Some(serde_json::to_value(snapshot).unwrap_or(serde_json::json!({}))),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra: std::collections::HashMap::new(),
                        };
                        if let Err(err) = send_signal(&mut ws, &msg).await {
                            warn!("stats bg send failed: {}", err);
                            break;
                        }
                    }
                }
                _ = stats_minute_tick.tick() => {
                    let snapshot = stats.snapshot();
                    minute_stats_buffer.push(snapshot);
                    // Cap buffer to avoid unbounded growth if flush fails
                    if minute_stats_buffer.len() > 5 {
                        minute_stats_buffer.drain(..minute_stats_buffer.len() - 5);
                    }
                }
                _ = stats_minute_flush_tick.tick() => {
                    if !minute_stats_buffer.is_empty() {
                        let batch: Vec<StatsSnapshot> = minute_stats_buffer.drain(..).collect();
                        let msg = SignalEnvelope {
                            message_type: "stats_minute_batch".to_string(),
                            session_id: None,
                            payload: Some(serde_json::to_value(&batch).unwrap_or(serde_json::json!([]))),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra: std::collections::HashMap::new(),
                        };
                        if let Err(err) = send_signal(&mut ws, &msg).await {
                            warn!("stats minute batch send failed: {}", err);
                            break;
                        }
                        info!("sent stats_minute_batch with {} snapshots", batch.len());
                    }
                }
                _ = output_tick.tick() => {
                    for chunk in sessions.drain_output() {
                        if webrtc_mgr.send_output(&chunk.session_id, &chunk.bytes).await {
                            continue;
                        }
                        let msg = SignalEnvelope {
                            message_type: "signal".to_string(),
                            session_id: Some(chunk.session_id),
                            payload: Some(serde_json::json!({
                                "channel": "terminal",
                                "data_b64": base64::engine::general_purpose::STANDARD.encode(chunk.bytes)
                            })),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra: std::collections::HashMap::new(),
                        };
                        if let Err(err) = send_signal(&mut ws, &msg).await {
                            warn!("session output send failed: {}", err);
                            break;
                        }
                    }
                }
                _ = alert_tick.tick() => {
                    if !store.state.alert_thresholds.is_empty() {
                        let snapshot = stats.snapshot();
                        let triggered = alert_checker.check(&snapshot, &store.state.alert_thresholds);
                        for alert in triggered {
                            let msg = SignalEnvelope {
                                message_type: "alert".to_string(),
                                session_id: None,
                                payload: Some(serde_json::to_value(&alert).unwrap_or(serde_json::json!({}))),
                                state: None,
                                accepted: None,
                                reason: None,
                                extra: std::collections::HashMap::new(),
                            };
                            if let Err(err) = send_signal(&mut ws, &msg).await {
                                warn!("alert send failed: {}", err);
                                break;
                            }
                        }
                    }
                }
                _ = discovery_tick.tick() => {
                    let discovered = SessionDiscovery::discover();
                    info!("discovery tick: found {} sessions", discovered.len());
                    if !discovered.is_empty() {
                        let msg = SignalEnvelope {
                            message_type: "available_sessions".to_string(),
                            session_id: None,
                            payload: Some(serde_json::to_value(&discovered).unwrap_or(serde_json::json!([]))),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra: std::collections::HashMap::new(),
                        };
                        if let Err(err) = send_signal(&mut ws, &msg).await {
                            warn!("discovery send failed: {}", err);
                            break;
                        }
                    }
                }
                _ = webrtc_poll_tick.tick() => {
                    webrtc_mgr.poll_events().await;
                }

                Some(webrtc_event) = webrtc_event_rx.recv() => {
                    match webrtc_event {
                        WebRtcEvent::Input { session_id, data } => {
                            // Check for file transfer sentinel: \x00PSFT
                            if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSFT" {
                                if let Ok(json_str) = std::str::from_utf8(&data[5..]) {
                                    handle_file_transfer_msg(&mut file_transfers, &session_id, json_str, &mut sessions);
                                }
                            } else if let Err(e) = sessions.write_input(&session_id, data) {
                                warn!("webrtc input write failed: {}", e);
                            }
                        }
                        WebRtcEvent::ChannelOpened { session_id } => {
                            info!("webrtc data channel opened for session {}", session_id);
                        }
                        WebRtcEvent::ChannelClosed { session_id } => {
                            info!("webrtc data channel closed for session {}", session_id);
                        }
                        WebRtcEvent::IceCandidate { mobile_device_id: _, candidate_json } => {
                            if let Ok(candidate_value) = serde_json::from_str::<serde_json::Value>(&candidate_json) {
                                let ice_msg = SignalEnvelope {
                                    message_type: "ice_candidate".to_string(),
                                    session_id: None,
                                    payload: Some(candidate_value),
                                    state: None,
                                    accepted: None,
                                    reason: None,
                                    extra: std::collections::HashMap::new(),
                                };
                                let _ = send_signal(&mut ws, &ice_msg).await;
                            }
                        }
                    }
                }

                incoming = recv_signal(&mut ws) => {
                    match incoming {
                        Ok(Some(msg)) => {
                            info!("ws received: type={} session_id={:?}", msg.message_type, msg.session_id);
                            if msg.message_type == "stats_subscribe" {
                                if !stats_active {
                                    info!("stats subscription activated");
                                }
                                stats_active = true;
                                stats_deadline = Some(Instant::now() + Duration::from_secs(20));
                            } else if let Err(err) = handle_signal(
                                &mut store,
                                &backend,
                                &shell,
                                &mut sessions,
                                msg,
                                &mut ws,
                                &mut webrtc_mgr,
                                &mut file_transfers,
                            ).await {
                                error!("control message handling failed: {}", err);
                            }
                        }
                        Ok(None) => {
                            // ping/pong or binary frame — keep going
                        }
                        Err(err) => {
                            warn!("control-plane read failed: {}", err);
                            break;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("daemon shutting down from signal");
                    sessions.close_all();
                    webrtc_mgr.close_all().await;
                    let _ = write_audit_event(AuditEvent {
                        event_type: "daemon_stopped".to_string(),
                        host_id: Some(host_id.clone()),
                        ..AuditEvent::new("daemon_stopped")
                    });
                    store.save()?;
                    return Ok(());
                }
            }
        }

        // Reset stats subscription on disconnect.
        stats_active = false;
        stats_deadline = None;
        minute_stats_buffer.clear();

        // Reconcile stale local session resources after disconnects.
        sessions.close_all();
        webrtc_mgr.close_all().await;
        for session in &mut store.state.sessions {
            if !matches!(session.state, SessionState::Ended | SessionState::Failed) {
                session.state = SessionState::Failed;
                session.updated_at = Utc::now();
            }
        }
        let _ = store.save();
    }
}

async fn refresh_auth_if_needed(backend: &BackendClient, store: &mut StateStore) -> Result<()> {
    store.require_logged_in()?;
    let Some(auth) = store.state.auth.clone() else {
        return Err(HostError::NotLoggedIn);
    };

    if !token_is_expiring(auth.access_expires_at, 60) {
        return Ok(());
    }

    let refresh = require_refresh_token(&auth)?;
    let tokens = match backend.refresh_tokens(&refresh).await {
        Ok(t) => t,
        Err(HostError::AuthRevoked) => {
            // Before giving up, reload state — another process may have refreshed
            let reloaded = StateStore::load()?;
            if let Some(ref reloaded_auth) = reloaded.state.auth {
                if !token_is_expiring(reloaded_auth.access_expires_at, 60) {
                    // Another process already refreshed the token
                    *store = reloaded;
                    return Ok(());
                }
            }
            return Err(HostError::AuthRevoked);
        }
        Err(e) => return Err(e),
    };

    let expires = derive_access_expiry(&tokens.access_token);
    store.state.auth = Some(crate::models::AuthState {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        access_expires_at: expires,
    });
    // Persist immediately — losing the new refresh token means auth death
    if let Err(e) = store.save() {
        warn!("failed to persist refreshed tokens: {}", e);
        return Err(e);
    }
    Ok(())
}

async fn handle_signal(
    store: &mut StateStore,
    backend: &BackendClient,
    shell: &str,
    sessions: &mut SessionManager,
    msg: SignalEnvelope,
    ws: &mut crate::transport::WsStream,
    webrtc_mgr: &mut WebRtcManager,
    file_transfers: &mut HashMap<String, PendingFileTransfer>,
) -> Result<()> {
    match msg.message_type.as_str() {
        "session_request" => {
            let Some(session_id) = msg.session_id else {
                return Ok(());
            };
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let cols = msg
                .extra
                .get("cols")
                .and_then(|v| v.as_u64())
                .unwrap_or(120) as u16;
            let rows = msg
                .extra
                .get("rows")
                .and_then(|v| v.as_u64())
                .unwrap_or(30) as u16;

            if !store.is_trusted(&mobile_device_id) {
                let reject = SignalEnvelope {
                    message_type: "session_ack".to_string(),
                    session_id: Some(session_id.clone()),
                    payload: None,
                    state: Some("failed".to_string()),
                    accepted: Some(false),
                    reason: Some("device_not_trusted".to_string()),
                    extra: std::collections::HashMap::new(),
                };
                send_signal(ws, &reject).await?;
                return Ok(());
            }

            let mut attach_target = msg
                .extra
                .get("attach_target")
                .and_then(|v| serde_json::from_value::<AttachTarget>(v.clone()).ok());

            // For "shell" type, resolve the PTY path from discovered sessions
            if let Some(ref mut target) = attach_target {
                if target.session_type == "shell" {
                    let discovered = SessionDiscovery::discover();
                    if let Some(session) = discovered.iter().find(|s| s.name == target.name && s.session_type == "shell") {
                        if let Some(ref pty_path) = session.pty_path {
                            target.name = pty_path.clone();
                        }
                    }
                }
            }

            let req = SessionRequest {
                session_id: session_id.clone(),
                mobile_device_id: mobile_device_id.clone(),
                cols,
                rows,
                attach_target,
            };

            let accept = accept_session(sessions, &req, shell).is_ok();
            let ack = SignalEnvelope {
                message_type: "session_ack".to_string(),
                session_id: Some(session_id.clone()),
                payload: None,
                state: Some(if accept { "approved" } else { "failed" }.to_string()),
                accepted: Some(accept),
                reason: if accept { None } else { Some("pty_failed".to_string()) },
                extra: std::collections::HashMap::new(),
            };
            send_signal(ws, &ack).await?;

            if accept {
                let event = SignalEnvelope {
                    message_type: "session_event".to_string(),
                    session_id: Some(session_id.clone()),
                    payload: None,
                    state: Some("connected".to_string()),
                    accepted: None,
                    reason: None,
                    extra: std::collections::HashMap::new(),
                };
                let _ = send_signal(ws, &event).await;
            }

            let token = store.access_token()?.to_string();
            if accept {
                backend
                    .transition_session(&token, &session_id, SessionState::Connected, None)
                    .await?;

                store.upsert_session(SessionRecord {
                    session_id: session_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    state: SessionState::Connected,
                    updated_at: Utc::now(),
                });
                let _ = write_audit_event(AuditEvent {
                    event_type: "session_started".to_string(),
                    mobile_device_id: Some(mobile_device_id),
                    session_id: Some(session_id),
                    ..AuditEvent::new("session_started")
                });
            } else {
                let _ = backend
                    .transition_session(&token, &session_id, SessionState::Failed, None)
                    .await;
            }
            store.save()?;
        }
        "signal" => {
            let Some(session_id) = msg.session_id else {
                return Ok(());
            };
            let Some(payload) = msg.payload else {
                return Ok(());
            };

            let channel = payload
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or_default();

            match channel {
                "terminal" => {
                    let bytes = if let Some(data_b64) = payload.get("data_b64").and_then(|v| v.as_str()) {
                        base64::engine::general_purpose::STANDARD
                            .decode(data_b64)
                            .map_err(|e| HostError::Backend(format!("invalid terminal payload: {e}")))?
                    } else if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
                        text.as_bytes().to_vec()
                    } else {
                        return Err(HostError::Backend("missing terminal data".to_string()));
                    };

                    // Check for file transfer sentinel via signaling relay
                    if bytes.len() > 5 && bytes[0] == 0x00 && &bytes[1..5] == b"PSFT" {
                        if let Ok(json_str) = std::str::from_utf8(&bytes[5..]) {
                            handle_file_transfer_msg(file_transfers, &session_id, json_str, sessions);
                        }
                    } else {
                        sessions.write_input(&session_id, bytes)?;
                    }

                    if let Some(record) = store.state.sessions.iter().find(|s| s.session_id == session_id) {
                        if matches!(record.state, SessionState::Approved | SessionState::Connecting) {
                            let connected_msg = SignalEnvelope {
                                message_type: "session_event".to_string(),
                                session_id: Some(session_id.clone()),
                                payload: None,
                                state: Some("connected".to_string()),
                                accepted: None,
                                reason: None,
                                extra: std::collections::HashMap::new(),
                            };
                            let _ = send_signal(ws, &connected_msg).await;
                            let token = store.access_token()?.to_string();
                            let _ = backend
                                .transition_session(&token, &session_id, SessionState::Connected, Some("p2p"))
                                .await;
                            store.touch_session_state(&session_id, SessionState::Connected);
                        }
                    }
                }
                "control" => {
                    let action = payload
                        .get("action")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    match action {
                        "resize" => {
                            let cols = payload.get("cols").and_then(|v| v.as_u64()).unwrap_or(120) as u16;
                            let rows = payload.get("rows").and_then(|v| v.as_u64()).unwrap_or(30) as u16;
                            sessions.resize(&session_id, cols, rows)?;
                        }
                        "disconnect" | "session_close" => {
                            sessions.close_session(&session_id)?;
                            store.touch_session_state(&session_id, SessionState::Ended);
                            let ended_event = SignalEnvelope {
                                message_type: "session_event".to_string(),
                                session_id: Some(session_id.clone()),
                                payload: None,
                                state: Some("ended".to_string()),
                                accepted: None,
                                reason: None,
                                extra: std::collections::HashMap::new(),
                            };
                            let _ = send_signal(ws, &ended_event).await;
                            let token = store.access_token()?.to_string();
                            let _ = backend
                                .transition_session(&token, &session_id, SessionState::Ended, None)
                                .await;
                            let _ = write_audit_event(AuditEvent {
                                event_type: "session_ended".to_string(),
                                session_id: Some(session_id),
                                ..AuditEvent::new("session_ended")
                            });
                        }
                        _ => {}
                    }
                }
                "files" => {
                    let request_id = payload
                        .get("request_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();

                    let result = crate::files::handle_files_action(&payload).await;
                    let response_payload = match result {
                        Ok(data) => serde_json::json!({
                            "channel": "files",
                            "response_to": request_id,
                            "status": "ok",
                            "data": data
                        }),
                        Err(err) => serde_json::json!({
                            "channel": "files",
                            "response_to": request_id,
                            "status": "error",
                            "error": err.to_string(),
                            "error_code": "operation_failed"
                        }),
                    };

                    let response = SignalEnvelope {
                        message_type: "signal".to_string(),
                        session_id: Some(session_id),
                        payload: Some(response_payload),
                        state: None,
                        accepted: None,
                        reason: None,
                        extra: std::collections::HashMap::new(),
                    };
                    send_signal(ws, &response).await?;
                }
                _ => {}
            }
            store.save()?;
        }
        "session_event" => {
            if let (Some(session_id), Some(state)) = (msg.session_id, msg.state) {
                let mapped = match state.as_str() {
                    "connecting" => SessionState::Connecting,
                    "connected" => SessionState::Connected,
                    "ended" => SessionState::Ended,
                    "failed" => SessionState::Failed,
                    _ => SessionState::Requested,
                };
                store.touch_session_state(&session_id, mapped);
                store.save()?;
            }
        }
        "session_offer" => {
            let sid = msg.session_id.as_deref().unwrap_or_default();
            let mobile_device_id = store
                .state
                .sessions
                .iter()
                .find(|s| s.session_id == sid)
                .map(|s| s.mobile_device_id.clone())
                .unwrap_or_default();

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    match backend.turn_credentials(&token).await {
                        Ok((username, credential, _ttl, uris)) => {
                            match webrtc_mgr
                                .handle_offer(&mobile_device_id, uris, username, credential, offer_sdp)
                                .await
                            {
                                Ok(answer_sdp) => {
                                    let answer_msg = SignalEnvelope {
                                        message_type: "session_answer".to_string(),
                                        session_id: msg.session_id.clone(),
                                        payload: Some(serde_json::json!({ "sdp": answer_sdp })),
                                        state: None,
                                        accepted: None,
                                        reason: None,
                                        extra: std::collections::HashMap::new(),
                                    };
                                    let _ = send_signal(ws, &answer_msg).await;
                                }
                                Err(e) => {
                                    warn!("webrtc handle_offer failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("failed to fetch TURN credentials: {}", e);
                        }
                    }
                }
            }
        }
        "ice_candidate" => {
            let sid = msg.session_id.as_deref().unwrap_or_default();
            let mobile_device_id = store
                .state
                .sessions
                .iter()
                .find(|s| s.session_id == sid)
                .map(|s| s.mobile_device_id.clone())
                .unwrap_or_default();

            if let Some(payload) = &msg.payload {
                if let Ok(candidate) =
                    serde_json::from_value::<webrtc::ice_transport::ice_candidate::RTCIceCandidateInit>(
                        payload.clone(),
                    )
                {
                    if let Err(e) = webrtc_mgr.add_ice_candidate(&mobile_device_id, candidate).await {
                        warn!("webrtc add_ice_candidate failed: {}", e);
                    }
                }
            }
        }
        "alert_preferences_sync" => {
            if let Some(payload) = msg.payload {
                if let Some(prefs) = payload.get("preferences") {
                    if let Ok(thresholds) = serde_json::from_value::<Vec<crate::models::AlertThreshold>>(prefs.clone()) {
                        info!("received {} alert thresholds", thresholds.len());
                        store.state.alert_thresholds = thresholds;
                        store.save()?;
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn version_gte(current: &str, required: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|v| v.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };

    let a = parse(current);
    let b = parse(required);
    let len = a.len().max(b.len());

    for i in 0..len {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        if av > bv {
            return true;
        }
        if av < bv {
            return false;
        }
    }

    true
}
