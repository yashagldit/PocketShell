use crate::api::BackendClient;
use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::models::{ControlMessage, DeviceRecord, HeartbeatRequest, SessionRequest};
use crate::pty::SessionManager;
use crate::session::accept_session;
use crate::stats::StatsCollector;
use crate::store::StateStore;
use crate::transport::{connect_control_plane, recv_msg, send_msg};
use base64::Engine;
use chrono::Utc;
use tokio::time::{interval, sleep, Duration};
use tracing::{error, info, warn};

pub async fn run_foreground(config: AppConfig) -> Result<()> {
    let mut store = StateStore::load()?;
    store.require_logged_in()?;

    let host_id = store.host()?.host_id.clone();
    let token = store.access_token()?.to_string();
    let backend = BackendClient::new(config.backend_base_url.clone());

    let mut stats = StatsCollector::new();
    let mut sessions = SessionManager::new(config.session_limit);
    let shell = AppConfig::default_shell();

    info!("daemon starting for host_id={}", host_id);

    let mut backoff_secs = 1_u64;

    loop {
        let connect = connect_control_plane(&config.ws_url, &token).await;
        let mut ws = match connect {
            Ok(socket) => {
                info!("control-plane connected");
                backoff_secs = 1;
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
        let mut output_tick = interval(Duration::from_millis(40));

        loop {
            tokio::select! {
                _ = heartbeat_tick.tick() => {
                    let payload = HeartbeatRequest {
                        host_id: host_id.clone(),
                        active_sessions: sessions.active_count(),
                        pending_devices: store.state.pending_devices.len(),
                    };

                    if let Err(err) = backend.send_heartbeat(&token, &payload).await {
                        warn!("heartbeat failed: {}", err);
                    }
                }
                _ = stats_tick.tick() => {
                    let snapshot = stats.snapshot();
                    if let Err(err) = send_msg(&mut ws, &ControlMessage::Stats { payload: snapshot }).await {
                        warn!("stats send failed: {}", err);
                        break;
                    }
                }
                _ = output_tick.tick() => {
                    for chunk in sessions.drain_output() {
                        let data_b64 = base64::engine::general_purpose::STANDARD.encode(chunk.bytes);
                        let msg = ControlMessage::SessionOutput { session_id: chunk.session_id, data_b64 };
                        if let Err(err) = send_msg(&mut ws, &msg).await {
                            warn!("session output send failed: {}", err);
                            break;
                        }
                    }
                }
                incoming = recv_msg(&mut ws) => {
                    match incoming {
                        Ok(Some(msg)) => {
                            if let Err(err) = handle_message(&mut store, &backend, &token, &shell, &mut sessions, msg, &mut ws).await {
                                error!("control message handling failed: {}", err);
                            }
                        }
                        Ok(None) => {
                            warn!("control-plane disconnected");
                            break;
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
                    store.save()?;
                    return Ok(());
                }
            }
        }
    }
}

async fn handle_message(
    store: &mut StateStore,
    backend: &BackendClient,
    token: &str,
    shell: &str,
    sessions: &mut SessionManager,
    msg: ControlMessage,
    ws: &mut crate::transport::WsStream,
) -> Result<()> {
    match msg {
        ControlMessage::PairingPending {
            device_id,
            device_name,
            platform,
            public_key,
        } => {
            store.upsert_pending_device(DeviceRecord {
                device_id,
                device_name,
                platform,
                public_key,
                pending_since: Some(Utc::now()),
                approved_at: None,
                revoked_at: None,
            });
            store.save()?;
        }
        ControlMessage::SessionRequest {
            session_id,
            mobile_device_id,
            cols,
            rows,
        } => {
            if !store.is_trusted(&mobile_device_id) {
                send_msg(
                    ws,
                    &ControlMessage::SessionAck {
                        session_id,
                        accepted: false,
                        reason: Some("device_not_trusted".to_string()),
                    },
                )
                .await?;
                return Ok(());
            }

            let req = SessionRequest {
                session_id: session_id.clone(),
                mobile_device_id,
                cols,
                rows,
            };

            match accept_session(sessions, &req, shell) {
                Ok(_) => {
                    send_msg(
                        ws,
                        &ControlMessage::SessionAck {
                            session_id,
                            accepted: true,
                            reason: None,
                        },
                    )
                    .await?;
                }
                Err(err) => {
                    send_msg(
                        ws,
                        &ControlMessage::SessionAck {
                            session_id,
                            accepted: false,
                            reason: Some(err.to_string()),
                        },
                    )
                    .await?;
                }
            }
        }
        ControlMessage::SessionInput { session_id, data_b64 } => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .map_err(|e| HostError::Backend(format!("invalid session input payload: {e}")))?;
            sessions.write_input(&session_id, bytes)?;
        }
        ControlMessage::SessionResize {
            session_id,
            cols,
            rows,
        } => {
            sessions.resize(&session_id, cols, rows)?;
        }
        ControlMessage::SessionClose { session_id } => {
            sessions.close_session(&session_id)?;
        }
        ControlMessage::SessionAck { .. }
        | ControlMessage::SessionOutput { .. }
        | ControlMessage::Stats { .. }
        | ControlMessage::Presence { .. } => {}
    }

    // Reconcile pending devices with backend snapshot opportunistically.
    if let Ok(pending) = backend.fetch_pending_devices(token).await {
        store.state.pending_devices = pending;
        store.save()?;
    }

    Ok(())
}
