use crate::api::{derive_access_expiry, BackendClient};
use crate::audit::{write_audit_event, AuditEvent};
use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::{HeartbeatRequest, SessionRecord, SessionRequest, SessionState, SignalEnvelope};
use crate::pty::SessionManager;
use crate::secure::{require_refresh_token, token_is_expiring};
use crate::session::accept_session;
use crate::stats::StatsCollector;
use crate::store::StateStore;
use crate::transport::{connect_host_ws, recv_signal, send_signal};
use base64::Engine;
use chrono::Utc;
use tokio::time::{interval, sleep, Duration, Instant};
use tracing::{error, info, warn};

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
    let shell = AppConfig::default_shell();

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
                warn!("authentication expired — waiting for re-login via `myapp login`");
                sleep(Duration::from_secs(30)).await;
                // Reload state in case user ran `myapp login` in another terminal
                store = StateStore::load()?;
                continue;
            }
            Err(err) => return Err(err),
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
        let mut alert_tick = interval(Duration::from_secs(config.alert_check_interval_secs));
        let mut alert_checker = crate::alerts::AlertChecker::new();

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
                            warn!("authentication expired — run `myapp login` to re-authenticate");
                            break; // reconnect loop will retry after reload
                        }
                        Err(err) => {
                            warn!("token refresh failed: {}", err);
                            break;
                        }
                    }

                    let payload = HeartbeatRequest {
                        host_id: host_id.clone(),
                        active_sessions: sessions.active_count(),
                        pending_devices: store.state.pending_devices.len(),
                    };

                    let token = store.access_token()?.to_string();
                    if let Err(err) = backend.send_heartbeat(&token, &payload).await {
                        warn!("heartbeat failed: {}", err);
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
                _ = output_tick.tick() => {
                    for chunk in sessions.drain_output() {
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
                            } else if let Err(err) = handle_signal(&mut store, &backend, &shell, &mut sessions, msg, &mut ws).await {
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

        // Reconcile stale local session resources after disconnects.
        sessions.close_all();
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
    let tokens = backend.refresh_tokens(&refresh).await?;

    let expires = derive_access_expiry(&tokens.access_token);
    store.state.auth = Some(crate::models::AuthState {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        access_expires_at: expires,
    });
    store.save()?;
    Ok(())
}

async fn handle_signal(
    store: &mut StateStore,
    backend: &BackendClient,
    shell: &str,
    sessions: &mut SessionManager,
    msg: SignalEnvelope,
    ws: &mut crate::transport::WsStream,
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

            let req = SessionRequest {
                session_id: session_id.clone(),
                mobile_device_id: mobile_device_id.clone(),
                cols,
                rows,
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
                    sessions.write_input(&session_id, bytes)?;

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
        "session_offer" | "ice_candidate" => {
            // WebRTC signaling — host uses relay, not P2P. Ignore silently.
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
