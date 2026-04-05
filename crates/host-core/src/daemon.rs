use crate::api::{derive_access_expiry, BackendClient, HeartbeatAction};
use crate::audit::{write_audit_event, AuditEvent};
use crate::config::AppConfig;
use crate::discovery::SessionDiscovery;
use crate::error::{HostError, Result};
use crate::local_attach;
use crate::models::StatsSnapshot;
use crate::models::{
    AttachTarget, HeartbeatRequest, SessionRecord, SessionRequest, SessionState, SignalEnvelope,
};
use crate::pty::SessionManager;
use crate::secure::{require_refresh_token, token_is_expiring};
use crate::session::accept_session;
use crate::stats::StatsCollector;
use crate::store::StateStore;
use crate::transport::{connect_host_ws, recv_signal, send_signal};
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::webrtc_manager::{WebRtcEvent, WebRtcManager};
use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::time::{interval, sleep, Duration, Instant};
use tracing::{debug, error, info, warn};

/// Whether the backend kill-action is honored. Set to false during testing.
const HONOR_KILL_ACTION: bool = false;

/// In-progress file transfer from a mobile device.
struct PendingFileTransfer {
    request_id: String,
    name: String,
    expected_chunks: usize,
    chunks: Vec<String>,
    created_at: Instant,
}

struct PendingFilesChannelMessage {
    expected_chunks: usize,
    chunks: Vec<String>,
    created_at: Instant,
}

struct PendingFilesBinaryUpload {
    final_path: PathBuf,
    tmp_path: PathBuf,
    file: File,
    bytes_written: usize,
    created_at: Instant,
}

/// File transfers older than this are expired to prevent memory leaks.
const FILE_TRANSFER_TIMEOUT_SECS: u64 = 300;
const FILES_MESSAGE_TIMEOUT_SECS: u64 = 300;
const FILES_MESSAGE_CHUNK_SIZE: usize = 12 * 1024;
const FILES_STREAM_CHUNK_SIZE: usize = 48 * 1024;
/// Per-send timeout for streaming downloads to detect dead channels.
const DOWNLOAD_SEND_TIMEOUT: Duration = Duration::from_secs(10);

struct DecodedFilesStreamFrame {
    header: serde_json::Value,
    payload: Vec<u8>,
}

enum FileTransferUpdate {
    Progress { request_id: String, progress: u8 },
    Complete { request_id: String, path: String },
    Error { request_id: String, message: String },
}

/// Events from locally-attached CLI clients over the Unix socket.
enum LocalClientEvent {
    /// Client wants to attach to a session.
    Attach {
        client_id: u64,
        session_id: String,
    },
    /// Terminal input from a local client.
    Input {
        session_id: String,
        data: Vec<u8>,
    },
    /// Resize from a local client.
    Resize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    /// Client disconnected.
    Disconnected {
        client_id: u64,
    },
}

/// Tracks write halves of locally attached clients, keyed by session_id.
struct LocalAttachClients {
    clients: HashMap<u64, (String, tokio::net::unix::OwnedWriteHalf)>,
}

impl LocalAttachClients {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    fn add(&mut self, client_id: u64, session_id: String, writer: tokio::net::unix::OwnedWriteHalf) {
        self.clients.insert(client_id, (session_id, writer));
    }

    fn remove(&mut self, client_id: u64) {
        self.clients.remove(&client_id);
    }

    /// Send terminal output to all local clients attached to this session.
    async fn send_output(&mut self, session_id: &str, data: &[u8]) {
        let frame = local_attach::encode_frame(local_attach::FRAME_TERMINAL_DATA, data);
        let mut dead = Vec::new();
        for (id, (sid, writer)) in &mut self.clients {
            if sid == session_id {
                if writer.write_all(&frame).await.is_err() {
                    dead.push(*id);
                }
            }
        }
        for id in dead {
            self.clients.remove(&id);
        }
    }

    /// Notify all clients attached to a session that it ended, then remove them.
    async fn end_session(&mut self, session_id: &str) {
        let frame = local_attach::encode_frame(
            local_attach::FRAME_ERROR,
            b"session ended",
        );
        for (_, (sid, writer)) in &mut self.clients {
            if sid == session_id {
                let _ = writer.write_all(&frame).await;
            }
        }
        self.clients.retain(|_, (sid, _)| sid != session_id);
    }
}

fn decode_framed_files_message(
    messages: &mut HashMap<String, PendingFilesChannelMessage>,
    mobile_device_id: &str,
    data: &[u8],
) -> Option<String> {
    if !(data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSFC") {
        return std::str::from_utf8(data).ok().map(ToString::to_string);
    }

    let json_str = std::str::from_utf8(&data[5..]).ok()?;
    let val = serde_json::from_str::<serde_json::Value>(json_str).ok()?;
    let op = val.get("op").and_then(|v| v.as_str()).unwrap_or_default();
    let id = val.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    if id.is_empty() {
        return None;
    }
    let key = format!("{mobile_device_id}:{id}");

    match op {
        "start" => {
            let chunks = val.get("chunks").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            messages.insert(
                key,
                PendingFilesChannelMessage {
                    expected_chunks: chunks,
                    chunks: vec![String::new(); chunks],
                    created_at: Instant::now(),
                },
            );
            None
        }
        "chunk" => {
            let index = val.get("i").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let data = val.get("d").and_then(|v| v.as_str()).unwrap_or_default();
            if let Some(message) = messages.get_mut(&key) {
                if index < message.expected_chunks {
                    message.chunks[index] = data.to_string();
                }
            }
            None
        }
        "end" => messages.remove(&key).map(|message| message.chunks.concat()),
        _ => None,
    }
}

fn decode_files_stream_frame(data: &[u8]) -> Option<DecodedFilesStreamFrame> {
    if !(data.len() > 6 && data[0] == 0x00 && &data[1..5] == b"PSFB") {
        return None;
    }

    let header_start = 5;
    let newline_rel = data[header_start..].iter().position(|b| *b == b'\n')?;
    let newline = header_start + newline_rel;
    let header_str = std::str::from_utf8(&data[header_start..newline]).ok()?;
    let header = serde_json::from_str::<serde_json::Value>(header_str).ok()?;
    Some(DecodedFilesStreamFrame {
        header,
        payload: data[(newline + 1)..].to_vec(),
    })
}

fn encode_files_stream_frame(header: &serde_json::Value, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + 256 + payload.len());
    out.extend_from_slice(b"\x00PSFB");
    out.extend_from_slice(serde_json::to_string(header).unwrap_or_default().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}

async fn send_files_stream_frame(
    channel: std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    header: &serde_json::Value,
    payload: &[u8],
) -> Result<()> {
    let bytes = bytes::Bytes::from(encode_files_stream_frame(header, payload));
    channel
        .send(&bytes)
        .await
        .map_err(|e| HostError::Backend(format!("files stream send failed: {e}")))?;
    Ok(())
}

async fn send_framed_files_response(
    channel: std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    response: &serde_json::Value,
) -> Result<()> {
    let json = serde_json::to_string(response)
        .map_err(|e| HostError::Backend(format!("files response encode failed: {e}")))?;
    let message_id = format!(
        "fm_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let total_chunks = std::cmp::max(1, json.len().div_ceil(FILES_MESSAGE_CHUNK_SIZE));
    let response_to = response
        .get("response_to")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    info!(
        "files WebRTC frame send start response_to={} bytes={} chunks={}",
        response_to,
        json.len(),
        total_chunks
    );

    let start = serde_json::json!({
        "op": "start",
        "id": message_id,
        "chunks": total_chunks,
    });
    let start_bytes = bytes::Bytes::from(
        [
            &b"\x00PSFC"[..],
            serde_json::to_string(&start).unwrap_or_default().as_bytes(),
        ]
        .concat(),
    );
    channel
        .send(&start_bytes)
        .await
        .map_err(|e| HostError::Backend(format!("files response start send failed: {e}")))?;

    for (index, chunk) in json.as_bytes().chunks(FILES_MESSAGE_CHUNK_SIZE).enumerate() {
        let chunk_value = serde_json::json!({
            "op": "chunk",
            "id": message_id,
            "i": index,
            "d": String::from_utf8_lossy(chunk),
        });
        let chunk_bytes = bytes::Bytes::from(
            [
                &b"\x00PSFC"[..],
                serde_json::to_string(&chunk_value)
                    .unwrap_or_default()
                    .as_bytes(),
            ]
            .concat(),
        );
        channel
            .send(&chunk_bytes)
            .await
            .map_err(|e| HostError::Backend(format!("files response chunk send failed: {e}")))?;
        if index == 0 || index + 1 == total_chunks {
            info!(
                "files WebRTC frame send chunk response_to={} chunk={}/{} bytes={}",
                response_to,
                index + 1,
                total_chunks,
                chunk.len()
            );
        }
    }

    let end = serde_json::json!({
        "op": "end",
        "id": message_id,
    });
    let end_bytes = bytes::Bytes::from(
        [
            &b"\x00PSFC"[..],
            serde_json::to_string(&end).unwrap_or_default().as_bytes(),
        ]
        .concat(),
    );
    channel
        .send(&end_bytes)
        .await
        .map_err(|e| HostError::Backend(format!("files response end send failed: {e}")))?;
    info!(
        "files WebRTC frame send end response_to={} chunks={}",
        response_to,
        total_chunks
    );

    Ok(())
}

/// Handle a file transfer protocol message (sentinel already stripped).
fn handle_file_transfer_msg(
    transfers: &mut HashMap<String, PendingFileTransfer>,
    session_id: &str,
    json_str: &str,
    sessions: &mut crate::pty::SessionManager,
) -> Option<FileTransferUpdate> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        warn!("invalid file transfer JSON");
        return None;
    };

    let op = val.get("op").and_then(|v| v.as_str()).unwrap_or_default();
    let id = val
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    match op {
        "start" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("clipboard.jpg")
                .to_string();
            let chunks = val.get("chunks").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            transfers.insert(
                id.clone(),
                PendingFileTransfer {
                    request_id: id.clone(),
                    name,
                    expected_chunks: chunks,
                    chunks: Vec::with_capacity(chunks),
                    created_at: Instant::now(),
                },
            );
            Some(FileTransferUpdate::Progress {
                request_id: id,
                progress: 0,
            })
        }
        "chunk" => {
            if let Some(transfer) = transfers.get_mut(&id) {
                let data = val.get("d").and_then(|v| v.as_str()).unwrap_or_default();
                transfer.chunks.push(data.to_string());
                let progress = if transfer.expected_chunks == 0 {
                    100
                } else {
                    (((transfer.chunks.len() * 100) as f32) / transfer.expected_chunks as f32)
                        .round()
                        .clamp(0.0, 100.0) as u8
                };
                Some(FileTransferUpdate::Progress {
                    request_id: transfer.request_id.clone(),
                    progress,
                })
            } else {
                Some(FileTransferUpdate::Error {
                    request_id: id,
                    message: "upload_state_missing".to_string(),
                })
            }
        }
        "end" => {
            if let Some(transfer) = transfers.remove(&id) {
                let full_b64: String = transfer.chunks.concat();
                match base64::engine::general_purpose::STANDARD.decode(&full_b64) {
                    Ok(image_bytes) => {
                        // Determine extension from name
                        let ext = transfer.name.rsplit('.').next().unwrap_or("jpg");
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
                                    return Some(FileTransferUpdate::Error {
                                        request_id: transfer.request_id,
                                        message: format!("pty_inject_failed: {e}"),
                                    });
                                }
                                Some(FileTransferUpdate::Complete {
                                    request_id: transfer.request_id,
                                    path: temp_path,
                                })
                            }
                            Err(e) => {
                                warn!("failed to write temp file {}: {}", temp_path, e);
                                Some(FileTransferUpdate::Error {
                                    request_id: transfer.request_id,
                                    message: format!("temp_write_failed: {e}"),
                                })
                            }
                        }
                    }
                    Err(e) => {
                        warn!("file transfer base64 decode failed: {}", e);
                        Some(FileTransferUpdate::Error {
                            request_id: transfer.request_id,
                            message: format!("decode_failed: {e}"),
                        })
                    }
                }
            } else {
                Some(FileTransferUpdate::Error {
                    request_id: id,
                    message: "upload_state_missing".to_string(),
                })
            }
        }
        _ => {
            warn!("unknown file transfer op: {}", op);
            None
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
    info!("PocketShell native session persistence enabled");
    let mut sessions = SessionManager::new(config.session_limit);
    let (webrtc_event_tx, mut webrtc_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<WebRtcEvent>();
    let mut webrtc_mgr = WebRtcManager::new(webrtc_event_tx);
    let shell = AppConfig::default_shell();

    let mut file_transfers: HashMap<String, PendingFileTransfer> = HashMap::new();
    let mut files_channel_messages: HashMap<String, PendingFilesChannelMessage> = HashMap::new();
    let mut files_binary_uploads: HashMap<String, PendingFilesBinaryUpload> = HashMap::new();
    let (files_response_tx, mut files_response_rx) =
        tokio::sync::mpsc::unbounded_channel::<SignalEnvelope>();
    let mut minute_stats_buffer: Vec<StatsSnapshot> = Vec::with_capacity(5);
    let mut peer_session_routes: HashMap<String, String> = HashMap::new();
    let mut files_peer_hosts: HashMap<String, String> = HashMap::new();
    let mut files_peer_offer_ids: HashMap<String, String> = HashMap::new();
    // Cancellation signals for active download_stream tasks per mobile device
    let mut files_download_cancels: HashMap<String, tokio::sync::watch::Sender<bool>> = HashMap::new();

    // Local attach via Unix socket
    let (local_event_tx, mut local_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<LocalClientEvent>();
    let mut local_clients = LocalAttachClients::new();
    let mut local_pending_writers: HashMap<u64, tokio::net::unix::OwnedWriteHalf> = HashMap::new();
    let mut local_client_counter: u64 = 0;

    let local_sock_path = local_attach::socket_path()
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/pocketshell-daemon.sock"));
    // Remove stale socket file from previous run
    let _ = std::fs::remove_file(&local_sock_path);
    let local_listener = match tokio::net::UnixListener::bind(&local_sock_path) {
        Ok(l) => {
            info!("local attach socket listening at {}", local_sock_path.display());
            // Make socket accessible only to current user
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&local_sock_path, std::fs::Permissions::from_mode(0o600));
            }
            Some(l)
        }
        Err(e) => {
            warn!("failed to bind local attach socket: {} — local attach will be unavailable", e);
            None
        }
    };

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
        let mut consecutive_heartbeat_failures: u32 = 0;
        let mut ws_ping_tick = interval(Duration::from_secs(30));
        let mut stats_tick = interval(Duration::from_secs(config.stats_interval_secs));
        let mut stats_bg_tick = interval(Duration::from_secs(10 * 60));
        stats_bg_tick.tick().await; // skip immediate first tick
        let mut output_tick = interval(Duration::from_millis(50));
        let mut trusted_devices_tick = interval(Duration::from_secs(30));
        let mut session_reap_tick = interval(Duration::from_secs(1));
        let mut stats_minute_tick = interval(Duration::from_secs(60));
        stats_minute_tick.tick().await; // skip immediate first tick
        let mut stats_minute_flush_tick = interval(Duration::from_secs(5 * 60));
        stats_minute_flush_tick.tick().await; // skip immediate first tick
        let mut alert_tick = interval(Duration::from_secs(config.alert_check_interval_secs));
        let mut alert_checker = crate::alerts::AlertChecker::new();
        let mut discovery_tick = interval(Duration::from_secs(15));
        let mut webrtc_poll_tick = interval(Duration::from_millis(50));
        let mut stats_stream_tick = interval(Duration::from_secs(2));

        let mut shutdown = Box::pin(async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate(),
                )
                .expect("failed to register SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => "SIGINT",
                    _ = sigterm.recv() => "SIGTERM",
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                "SIGINT"
            }
        });

        // Reconcile stale sessions: fetch active sessions from backend and end
        // any that no longer have a live PTY in this daemon.
        if let Ok(token) = store.access_token().map(|s| s.to_string()) {
            match backend.list_active_sessions(&token, &host_id).await {
                Ok(active) => {
                    for (session_id, state) in &active {
                        if !sessions.is_active(session_id) {
                            info!(
                                "reconcile: session {} (state={:?}) has no live process, ending",
                                session_id, state
                            );
                            match backend
                                .transition_session(&token, session_id, SessionState::Ended, None)
                                .await
                            {
                                Ok(_) => {
                                    info!("reconcile: session {} ended on backend", session_id)
                                }
                                Err(e) => warn!(
                                    "reconcile: failed to end session {} on backend: {}",
                                    session_id, e
                                ),
                            }
                        } else {
                            info!("reconcile: session {} has live PTY, keeping", session_id);
                        }
                    }
                }
                Err(err) => {
                    warn!("reconcile: failed to list active sessions: {}", err);
                }
            }
        } else {
            warn!("reconcile: no access token, skipping");
        }

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

                    let token = match store.access_token().map(|s| s.to_string()) {
                        Ok(t) => t,
                        Err(err) => {
                            warn!("heartbeat: no access token ({}), forcing reconnect", err);
                            break;
                        }
                    };
                    match backend.send_heartbeat(&token, &payload).await {
                        Ok(HeartbeatAction::Kill) if HONOR_KILL_ACTION => {
                            info!("backend requested shutdown — stopping daemon");
                            let _ = tokio::time::timeout(
                                Duration::from_secs(3),
                                backend.mark_offline(&token, &host_id),
                            ).await;
                            sessions.close_all();
                            webrtc_mgr.close_all().await;
                            let _ = write_audit_event(AuditEvent {
                                event_type: "daemon_stopped".to_string(),
                                host_id: Some(host_id.clone()),
                                ..AuditEvent::new("daemon_stopped")
                            });
                            let _ = store.save();
                            return Ok(());
                        }
                        Ok(_) => {
                            consecutive_heartbeat_failures = 0;
                        }
                        Err(err) => {
                            consecutive_heartbeat_failures += 1;
                            warn!("heartbeat failed ({}/3): {}", consecutive_heartbeat_failures, err);
                            if consecutive_heartbeat_failures >= 3 {
                                warn!("3 consecutive heartbeat failures — forcing reconnect");
                                break;
                            }
                        }
                    }

                    let (native_to_close, all_expired) =
                        store.clear_ended_sessions(config.stale_session_secs as i64, config.detach_max_secs as i64);
                    for session_id in &native_to_close {
                        let _ = sessions.close_session(session_id);
                    }
                    for session_id in &all_expired {
                        if let Err(e) = backend
                            .transition_session(&token, session_id, SessionState::Ended, None)
                            .await
                        {
                            warn!("failed to end expired session {} on backend: {}", session_id, e);
                        }
                    }
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
                                    peer_session_routes.retain(|_, sid| sid != &session_id);
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
                        debug!("sent stats_minute_batch with {} snapshots", batch.len());
                    }
                }
                // Accept new local attach connections
                result = async {
                    match local_listener.as_ref() {
                        Some(l) => l.accept().await.map(Some),
                        None => { std::future::pending::<()>().await; unreachable!() }
                    }
                } => {
                    if let Ok(Some((stream, _addr))) = result {
                        local_client_counter += 1;
                        let client_id = local_client_counter;
                        let tx = local_event_tx.clone();
                        let (read_half, write_half) = stream.into_split();
                        tokio::spawn(local_attach_reader(client_id, read_half, tx));
                        local_pending_writers.insert(client_id, write_half);
                    }
                }
                // Handle local client events (attach, input, resize, disconnect)
                Some(event) = local_event_rx.recv() => {
                    match event {
                        LocalClientEvent::Attach { client_id, session_id } => {
                            if let Some(mut writer) = local_pending_writers.remove(&client_id) {
                                if sessions.is_active(&session_id) {
                                    let scrollback = sessions.capture_scrollback(&session_id).unwrap_or_default();
                                    let frame = local_attach::encode_frame(
                                        local_attach::FRAME_ATTACHED_OK,
                                        &scrollback,
                                    );
                                    if writer.write_all(&frame).await.is_ok() {
                                        info!("local attach: client {} attached to session {}", client_id, session_id);
                                        local_clients.add(client_id, session_id, writer);
                                    }
                                } else {
                                    let err_msg = format!("session {} not active", session_id);
                                    let frame = local_attach::encode_frame(
                                        local_attach::FRAME_ERROR,
                                        err_msg.as_bytes(),
                                    );
                                    let _ = writer.write_all(&frame).await;
                                }
                            }
                        }
                        LocalClientEvent::Input { session_id, data } => {
                            let _ = sessions.write_input(&session_id, data);
                        }
                        LocalClientEvent::Resize { session_id, cols, rows } => {
                            let _ = sessions.resize(&session_id, cols, rows);
                        }
                        LocalClientEvent::Disconnected { client_id } => {
                            info!("local attach: client {} disconnected", client_id);
                            local_clients.remove(client_id);
                        }
                    }
                }
                _ = output_tick.tick() => {
                    let mut ws_failed = false;
                    for chunk in sessions.drain_output() {
                        // Fan out to locally attached CLI clients
                        local_clients.send_output(&chunk.session_id, &chunk.bytes).await;

                        // Always emit the signaling copy as well. WebRTC-connected
                        // viewers ignore signaling terminal output on the mobile side,
                        // but fallback viewers still need this path even when another
                        // viewer already has a live data channel.
                        let _ = webrtc_mgr.send_output(&chunk.session_id, &chunk.bytes).await;
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
                            ws_failed = true;
                            break;
                        }
                    }
                    if ws_failed {
                        break;
                    }
                }
                _ = session_reap_tick.tick() => {
                    // Expire stale file transfers to prevent memory leaks
                    file_transfers.retain(|_, t| t.created_at.elapsed().as_secs() < FILE_TRANSFER_TIMEOUT_SECS);

                    let ended_sessions = sessions.reap_exited_sessions();
                    if !ended_sessions.is_empty() {
                        let token = match store.access_token().map(|s| s.to_string()) {
                            Ok(t) => t,
                            Err(err) => {
                                warn!("session reap: no access token ({}), skipping", err);
                                continue;
                            }
                        };
                        for session_id in ended_sessions {
                            peer_session_routes.retain(|_, sid| sid != &session_id);
                            webrtc_mgr.close_session(&session_id);
                            local_clients.end_session(&session_id).await;
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
                            let _ = send_signal(&mut ws, &ended_event).await;
                            let _ = backend
                                .transition_session(&token, &session_id, SessionState::Ended, None)
                                .await;
                        }
                        let _ = store.save();
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
                    let now = Instant::now();
                    file_transfers.retain(|_, transfer| {
                        now.duration_since(transfer.created_at).as_secs() < FILE_TRANSFER_TIMEOUT_SECS
                    });
                    files_channel_messages.retain(|_, message| {
                        now.duration_since(message.created_at).as_secs() < FILES_MESSAGE_TIMEOUT_SECS
                    });
                    files_binary_uploads.retain(|key, upload| {
                        if now.duration_since(upload.created_at).as_secs() >= FILES_MESSAGE_TIMEOUT_SECS {
                            warn!("expiring stale upload {}: {}", key, upload.tmp_path.display());
                            // Temp file will be cleaned up when entry is dropped;
                            // also proactively delete it now in case the File handle outlives.
                            let _ = std::fs::remove_file(&upload.tmp_path);
                            false
                        } else {
                            true
                        }
                    });

                    let discovered = SessionDiscovery::discover();
                    debug!("discovery tick: found {} sessions", discovered.len());
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
                _ = webrtc_poll_tick.tick() => {
                    webrtc_mgr.poll_events().await;
                }
                _ = stats_stream_tick.tick() => {
                    if webrtc_mgr.has_stats_channel() {
                        let snapshot = stats.snapshot_with_processes();
                        if let Ok(json) = serde_json::to_vec(&snapshot) {
                            webrtc_mgr.send_stats(&json).await;
                        }
                    }
                }

                Some(response) = files_response_rx.recv() => {
                    if let Err(e) = send_signal(&mut ws, &response).await {
                        warn!("files signaling response send failed: {}", e);
                    }
                }

                Some(webrtc_event) = webrtc_event_rx.recv() => {
                    match webrtc_event {
                        WebRtcEvent::Input { session_id, mobile_device_id, data } => {
                            // Check for file transfer sentinel: \x00PSFT
                            if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSFT" {
                                if let Ok(json_str) = std::str::from_utf8(&data[5..]) {
                                    if let Some(update) =
                                        handle_file_transfer_msg(&mut file_transfers, &session_id, json_str, &mut sessions)
                                    {
                                        let mut extra = std::collections::HashMap::new();
                                        extra.insert(
                                            "target_mobile_device_id".to_string(),
                                            serde_json::json!(mobile_device_id),
                                        );

                                        let payload = match update {
                                            FileTransferUpdate::Progress { request_id, progress } => serde_json::json!({
                                                "channel": "files",
                                                "response_to": request_id,
                                                "status": "progress",
                                                "progress": progress,
                                            }),
                                            FileTransferUpdate::Complete { request_id, path } => serde_json::json!({
                                                "channel": "files",
                                                "response_to": request_id,
                                                "status": "ok",
                                                "path": path,
                                            }),
                                            FileTransferUpdate::Error { request_id, message } => serde_json::json!({
                                                "channel": "files",
                                                "response_to": request_id,
                                                "status": "error",
                                                "error": message,
                                                "error_code": "transfer_failed",
                                            }),
                                        };

                                        let response = SignalEnvelope {
                                            message_type: "signal".to_string(),
                                            session_id: Some(session_id.clone()),
                                            payload: Some(payload),
                                            state: None,
                                            accepted: None,
                                            reason: None,
                                            extra,
                                        };
                                        let _ = send_signal(&mut ws, &response).await;
                                    }
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
                        WebRtcEvent::StatsChannelOpened { host_id } => {
                            info!("stats WebRTC channel opened for host {}", host_id);
                        }
                        WebRtcEvent::StatsChannelClosed { host_id } => {
                            info!("stats WebRTC channel closed for host {}", host_id);
                            webrtc_mgr.prune_stats_channels();
                        }
                        WebRtcEvent::FilesChannelOpened {
                            mobile_device_id,
                            channel,
                        } => {
                            info!("files WebRTC channel opened for mobile {}", mobile_device_id);
                            let ready = serde_json::json!({
                                "channel": "files",
                                "event": "ready",
                            });
                            match serde_json::to_vec(&ready) {
                                Ok(bytes) => {
                                    if let Err(err) = channel.send(&bytes::Bytes::from(bytes)).await {
                                        warn!(
                                            "files WebRTC ready send failed for mobile {}: {}",
                                            mobile_device_id, err
                                        );
                                    } else {
                                        info!(
                                            "files WebRTC ready sent for mobile {}",
                                            mobile_device_id
                                        );
                                    }
                                }
                                Err(err) => warn!(
                                    "files WebRTC ready encode failed for mobile {}: {}",
                                    mobile_device_id, err
                                ),
                            }
                        }
                        WebRtcEvent::FilesChannelClosed { mobile_device_id } => {
                            info!("files WebRTC channel closed for mobile {}", mobile_device_id);
                            files_peer_offer_ids.remove(&format!("files:{mobile_device_id}"));
                            webrtc_mgr.prune_files_channels();
                            // Cancel any active download_stream tasks for this device
                            if let Some(cancel_tx) = files_download_cancels.remove(&mobile_device_id) {
                                let _ = cancel_tx.send(true);
                            }
                            // Clean up pending uploads and their temp files
                            let prefix = format!("{mobile_device_id}:");
                            let stale_keys: Vec<String> = files_binary_uploads
                                .keys()
                                .filter(|k| k.starts_with(&prefix))
                                .cloned()
                                .collect();
                            for key in stale_keys {
                                if let Some(upload) = files_binary_uploads.remove(&key) {
                                    drop(upload.file);
                                    if upload.tmp_path.exists() {
                                        let _ = std::fs::remove_file(&upload.tmp_path);
                                        info!("cleaned up partial upload tmp file: {}", upload.tmp_path.display());
                                    }
                                }
                            }
                        }
                        WebRtcEvent::FilesMessage { mobile_device_id, data, channel } => {
                            info!(
                                "files WebRTC raw message mobile={} bytes={} prefix={:02X?}",
                                mobile_device_id,
                                data.len(),
                                &data[..std::cmp::min(8, data.len())]
                            );
                            if let Some(frame) = decode_files_stream_frame(&data) {
                                let op = frame
                                    .header
                                    .get("op")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let request_id = frame
                                    .header
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let upload_key = format!("{mobile_device_id}:{request_id}");

                                match op.as_str() {
                                    "upload_start" => {
                                        let path = frame
                                            .header
                                            .get("path")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or_default();
                                        match crate::files::resolve_file_path_for_transfer(path) {
                                            Ok(file_path) => {
                                                if let Some(parent) = file_path.parent() {
                                                    std::fs::create_dir_all(parent).ok();
                                                }
                                                // Write to temp file; rename to final path on upload_end
                                                let tmp_path = match file_path.extension() {
                                                    Some(ext) => file_path.with_extension(format!("{}.pstmp", ext.to_string_lossy())),
                                                    None => file_path.with_extension("pstmp"),
                                                };
                                                match OpenOptions::new()
                                                    .create(true)
                                                    .write(true)
                                                    .truncate(true)
                                                    .open(&tmp_path)
                                                {
                                                    Ok(file) => {
                                                        files_binary_uploads.insert(
                                                            upload_key,
                                                            PendingFilesBinaryUpload {
                                                                final_path: file_path,
                                                                tmp_path,
                                                                file,
                                                                bytes_written: 0,
                                                                created_at: Instant::now(),
                                                            },
                                                        );
                                                    }
                                                    Err(err) => {
                                                        let response = serde_json::json!({
                                                            "channel": "files",
                                                            "response_to": request_id,
                                                            "status": "error",
                                                            "error": err.to_string(),
                                                            "error_code": "upload_open_failed"
                                                        });
                                                        if let Err(e) = send_framed_files_response(channel, &response).await {
                                                            warn!("files upload start error send failed: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                let response = serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": err.to_string(),
                                                    "error_code": "upload_path_failed"
                                                });
                                                if let Err(e) = send_framed_files_response(channel, &response).await {
                                                    warn!("files upload path error send failed: {}", e);
                                                }
                                            }
                                        }
                                        continue;
                                    }
                                    "upload_chunk" => {
                                        if let Some(upload) = files_binary_uploads.get_mut(&upload_key) {
                                            if let Err(err) = upload.file.write_all(&frame.payload) {
                                                let response = serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": err.to_string(),
                                                    "error_code": "upload_write_failed"
                                                });
                                                if let Err(e) = send_framed_files_response(channel, &response).await {
                                                    warn!("files upload write error send failed: {}", e);
                                                }
                                                if let Some(failed) = files_binary_uploads.remove(&upload_key) {
                                                    drop(failed.file);
                                                    let _ = std::fs::remove_file(&failed.tmp_path);
                                                }
                                            } else {
                                                upload.bytes_written += frame.payload.len();
                                                upload.created_at = Instant::now();
                                            }
                                        }
                                        continue;
                                    }
                                    "upload_end" => {
                                        let response = if let Some(mut upload) = files_binary_uploads.remove(&upload_key) {
                                            let _ = upload.file.flush();
                                            drop(upload.file);
                                            // Atomically move temp file to final path
                                            match std::fs::rename(&upload.tmp_path, &upload.final_path) {
                                                Ok(()) => {
                                                    serde_json::json!({
                                                        "channel": "files",
                                                        "response_to": request_id,
                                                        "status": "ok",
                                                        "data": {
                                                            "bytes_written": upload.bytes_written,
                                                            "path": upload.final_path.to_string_lossy()
                                                        }
                                                    })
                                                }
                                                Err(err) => {
                                                    // Clean up temp file on rename failure
                                                    let _ = std::fs::remove_file(&upload.tmp_path);
                                                    serde_json::json!({
                                                        "channel": "files",
                                                        "response_to": request_id,
                                                        "status": "error",
                                                        "error": format!("failed to finalize upload: {}", err),
                                                        "error_code": "upload_rename_failed"
                                                    })
                                                }
                                            }
                                        } else {
                                            serde_json::json!({
                                                "channel": "files",
                                                "response_to": request_id,
                                                "status": "error",
                                                "error": "upload_state_missing",
                                                "error_code": "upload_state_missing"
                                            })
                                        };
                                        if let Err(e) = send_framed_files_response(channel, &response).await {
                                            warn!("files upload end send failed: {}", e);
                                        }
                                        continue;
                                    }
                                    _ => {}
                                }
                            }

                            if let Some(json_str) = decode_framed_files_message(
                                &mut files_channel_messages,
                                &mobile_device_id,
                                &data,
                            ) {
                                info!(
                                    "files WebRTC framed message mobile={} json_bytes={}",
                                    mobile_device_id,
                                    json_str.len()
                                );
                                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&json_str) {
                                    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("?").to_string();
                                    let request_id = payload
                                        .get("request_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or_default()
                                        .to_string();
                                    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();

                                    info!("files WebRTC >> action={} req={} path={} mobile={}", action, request_id, path, mobile_device_id);

                                    if action == "download_stream" {
                                        let req_id_clone = request_id.clone();
                                        let path_clone = path.clone();
                                        // Create cancellation signal; replaces any previous one for this device
                                        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
                                        files_download_cancels.insert(mobile_device_id.clone(), cancel_tx);
                                        tokio::spawn(async move {
                                            let canonical = match crate::files::resolve_file_path_for_transfer(&path_clone) {
                                                Ok(path) => path,
                                                Err(err) => {
                                                    let response = serde_json::json!({
                                                        "channel": "files",
                                                        "response_to": req_id_clone,
                                                        "status": "error",
                                                        "error": err.to_string(),
                                                        "error_code": "download_path_failed"
                                                    });
                                                    let _ = send_framed_files_response(channel, &response).await;
                                                    return;
                                                }
                                            };
                                            let metadata = match std::fs::metadata(&canonical) {
                                                Ok(meta) => meta,
                                                Err(err) => {
                                                    let response = serde_json::json!({
                                                        "channel": "files",
                                                        "response_to": req_id_clone,
                                                        "status": "error",
                                                        "error": err.to_string(),
                                                        "error_code": "download_stat_failed"
                                                    });
                                                    let _ = send_framed_files_response(channel, &response).await;
                                                    return;
                                                }
                                            };
                                            if metadata.is_dir() {
                                                let response = serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": req_id_clone,
                                                    "status": "error",
                                                    "error": "cannot download a directory",
                                                    "error_code": "download_is_directory"
                                                });
                                                let _ = send_framed_files_response(channel, &response).await;
                                                return;
                                            }

                                            let name = canonical
                                                .file_name()
                                                .map(|n| n.to_string_lossy().to_string())
                                                .unwrap_or_default();
                                            let mime_type = crate::files::file_mime_type(&canonical);
                                            let start = serde_json::json!({
                                                "op": "download_start",
                                                "id": req_id_clone,
                                                "name": name,
                                                "size": metadata.len(),
                                                "mime_type": mime_type,
                                            });
                                            if let Err(e) = send_files_stream_frame(std::sync::Arc::clone(&channel), &start, &[]).await {
                                                warn!("files download start send failed: {}", e);
                                                return;
                                            }

                                            let file = match File::open(&canonical) {
                                                Ok(file) => file,
                                                Err(err) => {
                                                    let response = serde_json::json!({
                                                        "channel": "files",
                                                        "response_to": req_id_clone,
                                                        "status": "error",
                                                        "error": err.to_string(),
                                                        "error_code": "download_open_failed"
                                                    });
                                                    let _ = send_framed_files_response(channel, &response).await;
                                                    return;
                                                }
                                            };
                                            let mut reader = BufReader::new(file);
                                            let mut buf = vec![0u8; FILES_STREAM_CHUNK_SIZE];
                                            loop {
                                                // Check cancellation (mobile disconnected)
                                                if *cancel_rx.borrow() {
                                                    warn!("files download_stream cancelled (mobile disconnected) req={}", req_id_clone);
                                                    return;
                                                }
                                                let read = match reader.read(&mut buf) {
                                                    Ok(read) => read,
                                                    Err(err) => {
                                                        let response = serde_json::json!({
                                                            "channel": "files",
                                                            "response_to": req_id_clone,
                                                            "status": "error",
                                                            "error": err.to_string(),
                                                            "error_code": "download_read_failed"
                                                        });
                                                        let _ = send_framed_files_response(channel, &response).await;
                                                        return;
                                                    }
                                                };
                                                if read == 0 {
                                                    break;
                                                }
                                                let header = serde_json::json!({
                                                    "op": "download_chunk",
                                                    "id": req_id_clone,
                                                });
                                                // Timeout each send to detect dead channels
                                                match tokio::time::timeout(
                                                    DOWNLOAD_SEND_TIMEOUT,
                                                    send_files_stream_frame(std::sync::Arc::clone(&channel), &header, &buf[..read]),
                                                ).await {
                                                    Ok(Ok(())) => {}
                                                    Ok(Err(e)) => {
                                                        warn!("files download chunk send failed: {}", e);
                                                        return;
                                                    }
                                                    Err(_) => {
                                                        warn!("files download chunk send timed out (channel likely dead) req={}", req_id_clone);
                                                        return;
                                                    }
                                                }
                                            }
                                            let end = serde_json::json!({
                                                "op": "download_end",
                                                "id": req_id_clone,
                                            });
                                            let _ = tokio::time::timeout(
                                                DOWNLOAD_SEND_TIMEOUT,
                                                send_files_stream_frame(channel, &end, &[]),
                                            ).await;
                                        });
                                        continue;
                                    }

                                    // Spawn so file I/O doesn't block the event loop
                                    let action_clone = action.clone();
                                    let req_id_clone = request_id.clone();
                                    tokio::spawn(async move {
                                        let start = std::time::Instant::now();
                                        let result = crate::files::handle_files_action(&payload).await;
                                        let elapsed = start.elapsed();

                                        let (response, status) = match result {
                                            Ok(resp_data) => {
                                                let resp_size = serde_json::to_vec(&resp_data).map(|v| v.len()).unwrap_or(0);
                                                info!("files WebRTC << action={} req={} status=ok elapsed={:?} resp_bytes={}", action_clone, req_id_clone, elapsed, resp_size);
                                                (serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "ok",
                                                    "data": resp_data
                                                }), "ok")
                                            },
                                            Err(err) => {
                                                warn!("files WebRTC << action={} req={} status=error elapsed={:?} error={}", action_clone, req_id_clone, elapsed, err);
                                                (serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": err.to_string(),
                                                    "error_code": "operation_failed"
                                                }), "error")
                                            },
                                        };

                                        let response_size = serde_json::to_vec(&response).map(|v| v.len()).unwrap_or(0);
                                        info!("files WebRTC send action={} req={} status={} bytes={}", action_clone, req_id_clone, status, response_size);
                                        if let Err(e) = send_framed_files_response(channel, &response).await {
                                            warn!("files WebRTC send FAILED action={} req={}: {}", action_clone, req_id_clone, e);
                                        }
                                    });
                                } else {
                                    warn!("files WebRTC message: invalid JSON from mobile, raw_len={}", data.len());
                                }
                            }
                        }
                        WebRtcEvent::StatsMessage { data } => {
                            if let Ok(json_str) = std::str::from_utf8(&data) {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                                    let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                                    if msg_type == "kill_process" {
                                        let pid = val.get("pid").and_then(|v| v.as_i64());
                                        let signal = val.get("signal").and_then(|v| v.as_str()).unwrap_or("TERM");
                                        if let Some(pid) = pid {
                                            let sig_num = match signal {
                                                "KILL" | "9" => "9",
                                                _ => "15",
                                            };
                                            info!("kill_process request: pid={} signal={}", pid, sig_num);
                                            match std::process::Command::new("kill")
                                                .arg(format!("-{}", sig_num))
                                                .arg(pid.to_string())
                                                .output()
                                            {
                                                Ok(output) => {
                                                    if !output.status.success() {
                                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                                        warn!("kill_process failed for pid {}: {}", pid, stderr.trim());
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("kill_process command failed: {}", e);
                                                }
                                            }
                                        } else {
                                            warn!("kill_process message missing pid field");
                                        }
                                    } else if msg_type == "reboot" {
                                        info!("reboot request received from mobile");
                                        // Try sudo -n reboot first (non-interactive); fall back to plain reboot
                                        let sudo_ok = match std::process::Command::new("sudo")
                                            .args(["-n", "reboot"])
                                            .output()
                                        {
                                            Ok(output) if output.status.success() => true,
                                            Ok(output) => {
                                                let stderr = String::from_utf8_lossy(&output.stderr);
                                                warn!("sudo reboot failed ({}), trying plain reboot: {}", output.status, stderr.trim());
                                                false
                                            }
                                            Err(e) => {
                                                warn!("sudo not available ({}), trying plain reboot", e);
                                                false
                                            }
                                        };
                                        if !sudo_ok {
                                            match std::process::Command::new("reboot").output() {
                                                Ok(output) => {
                                                    if !output.status.success() {
                                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                                        warn!("reboot command failed: {}", stderr.trim());
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("reboot command failed: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        WebRtcEvent::IceCandidate { peer_key, mobile_device_id, candidate_json } => {
                            if let Ok(candidate_value) = serde_json::from_str::<serde_json::Value>(&candidate_json) {
                                if peer_key.starts_with("files:") {
                                    if let Some(host_id) = files_peer_hosts.get(&peer_key).cloned() {
                                        let mut payload = candidate_value;
                                        if let Some(offer_id) = files_peer_offer_ids.get(&peer_key).cloned() {
                                            if let Some(map) = payload.as_object_mut() {
                                                map.insert("offer_id".to_string(), serde_json::json!(offer_id));
                                            }
                                        }
                                        let mut extra = std::collections::HashMap::new();
                                        extra.insert("host_id".to_string(), serde_json::json!(host_id));
                                        let ice_msg = SignalEnvelope {
                                            message_type: "files_ice_candidate".to_string(),
                                            session_id: None,
                                            payload: Some(payload),
                                            state: None,
                                            accepted: None,
                                            reason: None,
                                            extra,
                                        };
                                        let _ = send_signal(&mut ws, &ice_msg).await;
                                    }
                                } else if let Some(session_id) = peer_session_routes.get(&mobile_device_id).cloned() {
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert(
                                        "target_mobile_device_id".to_string(),
                                        serde_json::json!(mobile_device_id),
                                    );
                                    let ice_msg = SignalEnvelope {
                                        message_type: "ice_candidate".to_string(),
                                        session_id: Some(session_id),
                                        payload: Some(candidate_value),
                                        state: None,
                                        accepted: None,
                                        reason: None,
                                        extra,
                                    };
                                    let _ = send_signal(&mut ws, &ice_msg).await;
                                } else {
                                    // Stats-only peer — route via stats_ice_candidate
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert("mobile_device_id".to_string(), serde_json::json!(mobile_device_id));
                                    let ice_msg = SignalEnvelope {
                                        message_type: "stats_ice_candidate".to_string(),
                                        session_id: None,
                                        payload: Some(candidate_value),
                                        state: None,
                                        accepted: None,
                                        reason: None,
                                        extra,
                                    };
                                    let _ = send_signal(&mut ws, &ice_msg).await;
                                }
                            }
                        }
                    }
                }

                _ = ws_ping_tick.tick() => {
                    // Send a WS ping to detect dead connections early.
                    // If the TCP send buffer is full (dead connection), this
                    // will time out and we force a reconnect.
                    let ping_result = tokio::time::timeout(
                        Duration::from_secs(10),
                        ws.send(Message::Ping(vec![].into())),
                    ).await;
                    match ping_result {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => {
                            warn!("ws ping send failed: {} — forcing reconnect", e);
                            break;
                        }
                        Err(_) => {
                            warn!("ws ping timed out (send blocked >10s) — forcing reconnect");
                            break;
                        }
                    }
                }

                incoming = recv_signal(&mut ws) => {
                    match incoming {
                        Ok(Some(msg)) => {
                            info!("ws received: type={} session_id={:?}", msg.message_type, msg.session_id);
                            if msg.message_type == "stats_subscribe" {
                                // stats_subscribe may arrive from the backend REST
                                // endpoint (no mobile_device_id) or from a mobile
                                // device via WebSocket.  Backend-originated subscribes
                                // are trusted because the backend already verified
                                // host ownership.  Device-originated ones must pass
                                // the trusted-device check.
                                let stats_device_id = msg
                                    .extra
                                    .get("mobile_device_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let allowed = stats_device_id.is_empty()
                                    || store.is_trusted(&stats_device_id);
                                if !allowed {
                                    warn!("stats_subscribe rejected: device {} is not trusted", stats_device_id);
                                } else {
                                    if !stats_active {
                                        info!("stats subscription activated");
                                    }
                                    stats_active = true;
                                    stats_deadline = Some(Instant::now() + Duration::from_secs(20));
                                }
                            } else if let Err(err) = handle_signal(
                                &mut store,
                                &backend,
                                &shell,
                                &mut sessions,
                                msg,
                                &mut ws,
                                &mut webrtc_mgr,
                                &mut file_transfers,
                                &mut peer_session_routes,
                                &mut files_peer_hosts,
                                &mut files_peer_offer_ids,
                                &files_response_tx,
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
                sig = &mut shutdown => {
                    info!("daemon shutting down from {}", sig);
                    if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                        if let Err(e) = tokio::time::timeout(
                            Duration::from_secs(3),
                            backend.mark_offline(&token, &host_id),
                        ).await {
                            warn!("failed to mark host offline: {}", e);
                        }
                    }
                    sessions.close_all();
                    webrtc_mgr.close_all().await;
                    drop(local_clients);
                    let _ = std::fs::remove_file(&local_sock_path);
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

        warn!(
            "control-plane disconnected — will reconnect in {}s",
            backoff_secs
        );

        // Reset stats subscription on disconnect.
        stats_active = false;
        stats_deadline = None;
        minute_stats_buffer.clear();

        // Reconcile session resources after WebSocket disconnect.
        // Persistent sessions survive; their PTYs stay alive for later rejoin.
        let detached_ids = sessions.detach_all();
        webrtc_mgr.close_all().await;
        for session in &mut store.state.sessions {
            if matches!(session.state, SessionState::Ended | SessionState::Failed) {
                continue;
            }
            if detached_ids.contains(&session.session_id) {
                session.state = SessionState::Detached;
            } else {
                session.state = SessionState::Failed;
            }
            session.updated_at = Utc::now();
        }
        let _ = store.save();

        sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(30);
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
    peer_session_routes: &mut HashMap<String, String>,
    files_peer_hosts: &mut HashMap<String, String>,
    files_peer_offer_ids: &mut HashMap<String, String>,
    files_response_tx: &tokio::sync::mpsc::UnboundedSender<SignalEnvelope>,
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
            let rows = msg.extra.get("rows").and_then(|v| v.as_u64()).unwrap_or(30) as u16;

            if !store.is_trusted(&mobile_device_id) {
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                let reject = SignalEnvelope {
                    message_type: "session_ack".to_string(),
                    session_id: Some(session_id.clone()),
                    payload: None,
                    state: Some("failed".to_string()),
                    accepted: Some(false),
                    reason: Some("device_not_trusted".to_string()),
                    extra,
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
                    if let Some(session) = discovered
                        .iter()
                        .find(|s| s.name == target.name && s.session_type == "shell")
                    {
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

            let mut accept_error: Option<String> = None;
            let mut accept = false;
            let first_accept = accept_session(sessions, &req, shell);
            if let Err(err) = first_accept {
                let first_error = err.to_string();
                accept_error = Some(first_error.clone());

                if first_error.contains("session limit reached") {
                    let mut detached_candidates = store
                        .state
                        .sessions
                        .iter()
                        .filter(|session| {
                            session.persistent && matches!(session.state, SessionState::Detached)
                        })
                        .map(|session| (session.session_id.clone(), session.updated_at))
                        .collect::<Vec<_>>();
                    detached_candidates.sort_by_key(|(_, updated_at)| *updated_at);

                    for (evicted_session_id, _) in detached_candidates {
                        info!(
                            "evicting detached session to free capacity: old_session={} new_session={} active_sessions={}",
                            evicted_session_id,
                            session_id,
                            sessions.active_count(),
                        );
                        let _ = sessions.close_session(&evicted_session_id);
                        store.touch_session_state(&evicted_session_id, SessionState::Ended);
                        if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                            let _ = backend
                                .transition_session(
                                    &token,
                                    &evicted_session_id,
                                    SessionState::Ended,
                                    None,
                                )
                                .await;
                        }

                        match accept_session(sessions, &req, shell) {
                            Ok(()) => {
                                accept = true;
                                accept_error = None;
                                break;
                            }
                            Err(err) => {
                                accept_error = Some(err.to_string());
                            }
                        }
                    }
                }
            } else {
                accept = true;
            }

            if let Some(ref err) = accept_error {
                warn!(
                    "session_request rejected: session={} mobile={} active_sessions={} reason={}",
                    session_id,
                    mobile_device_id,
                    sessions.active_count(),
                    err,
                );
            }
            let mut ack_extra = std::collections::HashMap::new();
            ack_extra.insert(
                "target_mobile_device_id".to_string(),
                serde_json::json!(mobile_device_id),
            );
            if let Some(ref err) = accept_error {
                ack_extra.insert("error".to_string(), serde_json::json!(err));
            }
            let ack = SignalEnvelope {
                message_type: "session_ack".to_string(),
                session_id: Some(session_id.clone()),
                payload: None,
                state: Some(if accept { "approved" } else { "failed" }.to_string()),
                accepted: Some(accept),
                reason: if accept {
                    None
                } else {
                    Some("pty_failed".to_string())
                },
                extra: ack_extra,
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

                let is_persistent = sessions.is_persistent(&session_id);
                let tmux_name = sessions.tmux_session_name(&session_id);
                store.upsert_session(SessionRecord {
                    session_id: session_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    state: SessionState::Connected,
                    updated_at: Utc::now(),
                    persistent: is_persistent,
                    tmux_session_name: tmux_name,
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

            // Verify the sending device is trusted on this host.
            // The backend ConnectionManager already validates viewer membership
            // before routing, so we only need the trust gate here.  This supports
            // the multi-viewer model where session_join adds additional viewers.
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "signal rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            let channel = payload
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or_default();

            match channel {
                "terminal" => {
                    let bytes =
                        if let Some(data_b64) = payload.get("data_b64").and_then(|v| v.as_str()) {
                            base64::engine::general_purpose::STANDARD
                                .decode(data_b64)
                                .map_err(|e| {
                                    HostError::Backend(format!("invalid terminal payload: {e}"))
                                })?
                        } else if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
                            text.as_bytes().to_vec()
                        } else {
                            return Err(HostError::Backend("missing terminal data".to_string()));
                        };

                    // Check for file transfer sentinel via signaling relay
                    if bytes.len() > 5 && bytes[0] == 0x00 && &bytes[1..5] == b"PSFT" {
                        if let Ok(json_str) = std::str::from_utf8(&bytes[5..]) {
                            handle_file_transfer_msg(
                                file_transfers,
                                &session_id,
                                json_str,
                                sessions,
                            );
                        }
                    } else {
                        sessions.write_input(&session_id, bytes)?;
                    }

                    if let Some(record) = store
                        .state
                        .sessions
                        .iter()
                        .find(|s| s.session_id == session_id)
                    {
                        if matches!(
                            record.state,
                            SessionState::Approved | SessionState::Connecting
                        ) {
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
                                .transition_session(
                                    &token,
                                    &session_id,
                                    SessionState::Connected,
                                    Some("p2p"),
                                )
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
                            let cols =
                                payload.get("cols").and_then(|v| v.as_u64()).unwrap_or(120) as u16;
                            let rows =
                                payload.get("rows").and_then(|v| v.as_u64()).unwrap_or(30) as u16;
                            sessions.resize(&session_id, cols, rows)?;
                        }
                        "session_detach" => {
                            // Mobile wants to detach (keep session alive for later).
                            let was_persistent =
                                sessions.detach_session(&session_id).unwrap_or(false);
                            if was_persistent {
                                peer_session_routes.retain(|_, sid| sid != &session_id);
                                webrtc_mgr.close_session(&session_id);
                                store.touch_session_state(&session_id, SessionState::Detached);
                                let detach_event = SignalEnvelope {
                                    message_type: "session_event".to_string(),
                                    session_id: Some(session_id.clone()),
                                    payload: None,
                                    state: Some("detached".to_string()),
                                    accepted: None,
                                    reason: None,
                                    extra: std::collections::HashMap::new(),
                                };
                                let _ = send_signal(ws, &detach_event).await;
                                let token = store.access_token()?.to_string();
                                let _ = backend
                                    .transition_session(
                                        &token,
                                        &session_id,
                                        SessionState::Detached,
                                        None,
                                    )
                                    .await;
                                let _ = write_audit_event(AuditEvent {
                                    event_type: "session_detached".to_string(),
                                    session_id: Some(session_id),
                                    ..AuditEvent::new("session_detached")
                                });
                            } else {
                                // Non-persistent session — detach acts as close
                                peer_session_routes.retain(|_, sid| sid != &session_id);
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
                                    .transition_session(
                                        &token,
                                        &session_id,
                                        SessionState::Ended,
                                        None,
                                    )
                                    .await;
                            }
                        }
                        "disconnect" | "session_close" => {
                            // Explicit close — kills the session.
                            peer_session_routes.retain(|_, sid| sid != &session_id);
                            webrtc_mgr.close_session(&session_id);
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
                    let target_mobile_device_id = msg
                        .extra
                        .get("mobile_device_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let request_id = payload
                        .get("request_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();

                    let action = payload
                        .get("action")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string();
                    let path = payload
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    info!(
                        "files signaling >> action={} req={} path={}",
                        action, request_id, path
                    );

                    // Spawn so file I/O doesn't block the event loop
                    let tx = files_response_tx.clone();
                    let action_clone = action.clone();
                    let req_id_clone = request_id.clone();
                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        let result = crate::files::handle_files_action(&payload).await;
                        let elapsed = start.elapsed();

                        let response_payload = match result {
                            Ok(data) => {
                                info!(
                                    "files signaling << action={} req={} status=ok elapsed={:?}",
                                    action_clone, req_id_clone, elapsed
                                );
                                serde_json::json!({
                                    "channel": "files",
                                    "response_to": request_id,
                                    "status": "ok",
                                    "data": data
                                })
                            }
                            Err(err) => {
                                warn!("files signaling << action={} req={} status=error elapsed={:?} error={}", action_clone, req_id_clone, elapsed, err);
                                serde_json::json!({
                                    "channel": "files",
                                    "response_to": request_id,
                                    "status": "error",
                                    "error": err.to_string(),
                                    "error_code": "operation_failed"
                                })
                            }
                        };

                        let mut extra = std::collections::HashMap::new();
                        if let Some(target) = target_mobile_device_id {
                            extra.insert(
                                "target_mobile_device_id".to_string(),
                                serde_json::json!(target),
                            );
                        }
                        let response = SignalEnvelope {
                            message_type: "signal".to_string(),
                            session_id: Some(session_id),
                            payload: Some(response_payload),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra,
                        };
                        let _ = tx.send(response);
                    });
                }
                _ => {}
            }
            store.save()?;
        }
        "session_join" => {
            // A device wants to join (reconnect to) an existing persistent session.
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
            let rows = msg.extra.get("rows").and_then(|v| v.as_u64()).unwrap_or(30) as u16;

            if !store.is_trusted(&mobile_device_id) {
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                let reject = SignalEnvelope {
                    message_type: "session_ack".to_string(),
                    session_id: Some(session_id.clone()),
                    payload: None,
                    state: Some("failed".to_string()),
                    accepted: Some(false),
                    reason: Some("device_not_trusted".to_string()),
                    extra,
                };
                send_signal(ws, &reject).await?;
                return Ok(());
            }

            // If session is already active in SessionManager (another device is using it),
            // we just need to ACK — the new WebRTC channel will be added via session_offer.
            // If it is no longer active, attempt a native reconnect.
            let needs_reconnect = !sessions.is_active(&session_id);
            let accept = if needs_reconnect {
                sessions
                    .reconnect_session(session_id.clone(), cols, rows)
                    .is_ok()
            } else {
                true
            };

            let mut ack_extra = std::collections::HashMap::new();
            ack_extra.insert(
                "target_mobile_device_id".to_string(),
                serde_json::json!(mobile_device_id),
            );
            let ack = SignalEnvelope {
                message_type: "session_ack".to_string(),
                session_id: Some(session_id.clone()),
                payload: None,
                state: Some(if accept { "approved" } else { "failed" }.to_string()),
                accepted: Some(accept),
                reason: if accept {
                    None
                } else {
                    Some("reconnect_failed".to_string())
                },
                extra: ack_extra,
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

                // Send scrollback replay ONLY to the joining device (not all viewers)
                if let Ok(scrollback) = sessions.capture_scrollback(&session_id) {
                    if !scrollback.is_empty() {
                        let mut extra = std::collections::HashMap::new();
                        extra.insert(
                            "target_mobile_device_id".to_string(),
                            serde_json::json!(mobile_device_id),
                        );
                        let replay_msg = SignalEnvelope {
                            message_type: "session_replay".to_string(),
                            session_id: Some(session_id.clone()),
                            payload: Some(serde_json::json!({
                                "data_b64": base64::engine::general_purpose::STANDARD.encode(&scrollback)
                            })),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra,
                        };
                        let _ = send_signal(ws, &replay_msg).await;
                    }
                }

                let token = store.access_token()?.to_string();
                let _ = backend
                    .transition_session(&token, &session_id, SessionState::Connected, None)
                    .await;

                store.upsert_session(SessionRecord {
                    session_id: session_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    state: SessionState::Connected,
                    updated_at: Utc::now(),
                    persistent: sessions.is_persistent(&session_id),
                    tmux_session_name: sessions.tmux_session_name(&session_id),
                });
                store.save()?;
            }
        }
        "session_event" => {
            if let (Some(session_id), Some(state)) = (msg.session_id, msg.state) {
                let mapped = match state.as_str() {
                    "connecting" => SessionState::Connecting,
                    "connected" => SessionState::Connected,
                    "ended" => SessionState::Ended,
                    "failed" => SessionState::Failed,
                    "detached" => SessionState::Detached,
                    _ => SessionState::Requested,
                };
                store.touch_session_state(&session_id, mapped);
                store.save()?;
            }
        }
        "session_offer" => {
            let sid = msg.session_id.as_deref().unwrap_or_default();
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if mobile_device_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                warn!(
                    "session_offer rejected: device {} is not trusted for session {}",
                    mobile_device_id, sid
                );
                return Ok(());
            }
            peer_session_routes.insert(mobile_device_id.clone(), sid.to_string());

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    match backend.turn_credentials(&token).await {
                        Ok((username, credential, _ttl, uris)) => {
                            match webrtc_mgr
                                .handle_offer(
                                    &mobile_device_id,
                                    uris,
                                    username,
                                    credential,
                                    offer_sdp,
                                    false, // session: reuse existing peer for renegotiation
                                )
                                .await
                            {
                                Ok(answer_sdp) if !answer_sdp.is_empty() => {
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert(
                                        "target_mobile_device_id".to_string(),
                                        serde_json::json!(mobile_device_id),
                                    );
                                    let answer_msg = SignalEnvelope {
                                        message_type: "session_answer".to_string(),
                                        session_id: msg.session_id.clone(),
                                        payload: Some(serde_json::json!({ "sdp": answer_sdp })),
                                        state: None,
                                        accepted: None,
                                        reason: None,
                                        extra,
                                    };
                                    let _ = send_signal(ws, &answer_msg).await;
                                }
                                Ok(_) => {
                                    // Empty answer — peer is still connecting, skip
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
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if mobile_device_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                warn!(
                    "ice_candidate rejected: device {} is not trusted for session {}",
                    mobile_device_id, sid
                );
                return Ok(());
            }
            peer_session_routes.insert(mobile_device_id.clone(), sid.to_string());

            if let Some(payload) = &msg.payload {
                if let Ok(candidate) = serde_json::from_value::<
                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                >(payload.clone())
                {
                    if let Err(e) = webrtc_mgr
                        .add_ice_candidate(&mobile_device_id, candidate)
                        .await
                    {
                        warn!("webrtc add_ice_candidate failed: {}", e);
                    }
                }
            }
        }
        "stats_offer" => {
            // WebRTC offer specifically for stats streaming — same flow as session_offer
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "stats_offer rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    match backend.turn_credentials(&token).await {
                        Ok((username, credential, _ttl, uris)) => {
                            match webrtc_mgr
                                .handle_offer(
                                    &mobile_device_id,
                                    uris,
                                    username,
                                    credential,
                                    offer_sdp,
                                    true, // stats: always fresh peer (mobile always creates new PC)
                                )
                                .await
                            {
                                Ok(answer_sdp) if !answer_sdp.is_empty() => {
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert(
                                        "mobile_device_id".to_string(),
                                        serde_json::json!(mobile_device_id),
                                    );
                                    let answer_msg = SignalEnvelope {
                                        message_type: "stats_answer".to_string(),
                                        session_id: None,
                                        payload: Some(serde_json::json!({ "sdp": answer_sdp })),
                                        state: None,
                                        accepted: None,
                                        reason: None,
                                        extra,
                                    };
                                    let _ = send_signal(ws, &answer_msg).await;
                                }
                                Ok(_) => {
                                    // Empty answer — peer is still connecting, skip
                                }
                                Err(e) => {
                                    warn!("webrtc stats handle_offer failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("failed to fetch TURN credentials for stats: {}", e);
                        }
                    }
                }
            }
        }
        "files_offer" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let host_id = msg
                .extra
                .get("host_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "files_offer rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            let peer_key = format!("files:{mobile_device_id}");
            files_peer_hosts.insert(peer_key.clone(), host_id.clone());
            let offer_id = msg
                .payload
                .as_ref()
                .and_then(|payload| payload.get("offer_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if !offer_id.is_empty() {
                files_peer_offer_ids.insert(peer_key.clone(), offer_id.clone());
            }

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    match backend.turn_credentials(&token).await {
                        Ok((username, credential, _ttl, uris)) => {
                            match webrtc_mgr
                                .handle_offer(
                                    &peer_key, uris, username, credential, offer_sdp, true,
                                )
                                .await
                            {
                                Ok(answer_sdp) if !answer_sdp.is_empty() => {
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert("host_id".to_string(), serde_json::json!(host_id));
                                    let answer_msg = SignalEnvelope {
                                        message_type: "files_answer".to_string(),
                                        session_id: None,
                                        payload: Some(serde_json::json!({
                                            "sdp": answer_sdp,
                                            "offer_id": offer_id,
                                        })),
                                        state: None,
                                        accepted: None,
                                        reason: None,
                                        extra,
                                    };
                                    let _ = send_signal(ws, &answer_msg).await;
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("webrtc files handle_offer failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("failed to fetch TURN credentials for files: {}", e);
                        }
                    }
                }
            }
        }
        "files_ice_candidate" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "files_ice_candidate rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            if let Some(payload) = &msg.payload {
                if let Ok(candidate) = serde_json::from_value::<
                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                >(payload.clone())
                {
                    let peer_key = format!("files:{mobile_device_id}");
                    if let Err(e) = webrtc_mgr.add_ice_candidate(&peer_key, candidate).await {
                        warn!("webrtc files add_ice_candidate failed: {}", e);
                    }
                }
            }
        }
        "stats_ice_candidate" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "stats_ice_candidate rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            if let Some(payload) = &msg.payload {
                if let Ok(candidate) = serde_json::from_value::<
                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                >(payload.clone())
                {
                    if let Err(e) = webrtc_mgr
                        .add_ice_candidate(&mobile_device_id, candidate)
                        .await
                    {
                        warn!("webrtc stats add_ice_candidate failed: {}", e);
                    }
                }
            }
        }
        "alert_preferences_sync" => {
            if let Some(payload) = msg.payload {
                if let Some(prefs) = payload.get("preferences") {
                    if let Ok(thresholds) =
                        serde_json::from_value::<Vec<crate::models::AlertThreshold>>(prefs.clone())
                    {
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

/// Reads framed messages from a local attach client and sends events to the daemon loop.
async fn local_attach_reader(
    client_id: u64,
    mut reader: tokio::net::unix::OwnedReadHalf,
    tx: tokio::sync::mpsc::UnboundedSender<LocalClientEvent>,
) {
    use tokio::io::AsyncReadExt;

    let mut session_id = String::new();
    let mut header = [0u8; 5]; // type(1) + len(4)

    loop {
        // Read frame header with idle timeout to detect crashed clients
        let read_result = tokio::time::timeout(
            Duration::from_secs(300),
            reader.read_exact(&mut header),
        )
        .await;
        match read_result {
            Ok(Ok(_)) => {}
            _ => break, // timeout, EOF, or error
        }
        let frame_type = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

        // Reject oversized frames to prevent OOM
        if len > local_attach::MAX_FRAME_SIZE {
            warn!(
                "local attach: client {} sent oversized frame ({} bytes), disconnecting",
                client_id, len
            );
            break;
        }

        // Read payload
        let mut payload = vec![0u8; len];
        if len > 0 && reader.read_exact(&mut payload).await.is_err() {
            break;
        }

        match frame_type {
            local_attach::FRAME_ATTACH => {
                // Validate session_id: must be valid UTF-8 and reasonable length
                match String::from_utf8(payload) {
                    Ok(sid) if !sid.is_empty() && sid.len() <= 256 => {
                        session_id = sid;
                        let _ = tx.send(LocalClientEvent::Attach {
                            client_id,
                            session_id: session_id.clone(),
                        });
                    }
                    _ => {
                        warn!("local attach: client {} sent invalid session_id", client_id);
                        break;
                    }
                }
            }
            local_attach::FRAME_TERMINAL_DATA => {
                let _ = tx.send(LocalClientEvent::Input {
                    session_id: session_id.clone(),
                    data: payload,
                });
            }
            local_attach::FRAME_RESIZE => {
                if payload.len() == 4 {
                    let cols = u16::from_be_bytes([payload[0], payload[1]]);
                    let rows = u16::from_be_bytes([payload[2], payload[3]]);
                    if cols > 0 && rows > 0 {
                        let _ = tx.send(LocalClientEvent::Resize {
                            session_id: session_id.clone(),
                            cols,
                            rows,
                        });
                    }
                }
            }
            local_attach::FRAME_DETACH => {
                break;
            }
            _ => {}
        }
    }

    let _ = tx.send(LocalClientEvent::Disconnected {
        client_id,
    });
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
