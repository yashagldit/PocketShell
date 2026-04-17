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
use crate::signaling_crypto::{self, EphemeralKeypair, SessionCipher};
use crate::session::accept_session;
use crate::stats::StatsCollector;
use crate::store::StateStore;
use crate::transport::{connect_host_ws, recv_signal, send_signal};
use crate::webrtc_peer::WebRtcPeer;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::webrtc_manager::{WebRtcEvent, WebRtcManager};
use base64::Engine;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time::{interval, sleep, Duration, Instant};
use tracing::{debug, error, info, warn};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;

/// Whether the backend kill-action is honored.
const HONOR_KILL_ACTION: bool = true;

/// Build a signaling payload JSON value for an outbound SDP, attaching an
/// ED25519 signature binding the SDP to the host's identity key so the mobile
/// client can detect a MITM rewriting the DTLS fingerprint.
///
/// `sdp_type` MUST be `"offer"` or `"answer"`. `extra` is merged into the
/// resulting JSON object (e.g. to carry `transfer_id`, `offer_id`, etc.).
///
/// If the host's private key is unavailable or signing fails, returns a plain
/// SDP payload (no signature) — preserves compatibility with legacy-paired
/// hosts where the private key may not be stored locally.
fn build_signed_sdp_payload(
    store: &StateStore,
    sdp: &str,
    sdp_type: &str,
    extra: Vec<(&str, serde_json::Value)>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("sdp".to_string(), serde_json::Value::String(sdp.to_string()));
    obj.insert(
        "type".to_string(),
        serde_json::Value::String(sdp_type.to_string()),
    );

    if let Some(host) = store.state.host.as_ref() {
        if !host.private_key.is_empty() {
            match signaling_crypto::sign_sdp(&host.private_key, sdp, sdp_type) {
                Ok(signed) => {
                    obj.insert(
                        "sdp_sig".to_string(),
                        serde_json::Value::String(signed.sig_b64),
                    );
                    obj.insert(
                        "sdp_sig_nonce".to_string(),
                        serde_json::Value::String(signed.nonce_b64),
                    );
                    obj.insert(
                        "sdp_sig_ts".to_string(),
                        serde_json::Value::Number(signed.ts.into()),
                    );
                }
                Err(e) => {
                    warn!("failed to sign SDP ({}): {}", sdp_type, e);
                }
            }
        }
    }

    for (k, v) in extra {
        obj.insert(k.to_string(), v);
    }

    serde_json::Value::Object(obj)
}

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

struct OutboundHostTransfer {
    peer: WebRtcPeer,
    target_host_id: String,
    mobile_device_id: String,
    offer_id: String,
    created_at: Instant,
}

struct InboundHostTransfer {
    peer: WebRtcPeer,
    source_host_id: String,
    mobile_device_id: String,
    offer_id: String,
    created_at: Instant,
}

enum DirectHostTransferEvent {
    Progress {
        transfer_id: String,
        mobile_device_id: String,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    Result {
        transfer_id: String,
        mobile_device_id: String,
        ok: bool,
        bytes_written: u64,
        error: Option<String>,
    },
    CleanupOutbound {
        transfer_id: String,
    },
    CleanupInbound {
        transfer_id: String,
    },
}

/// File transfers older than this are expired to prevent memory leaks.
const FILE_TRANSFER_TIMEOUT_SECS: u64 = 300;
const FILES_MESSAGE_TIMEOUT_SECS: u64 = 300;
const FILES_MESSAGE_CHUNK_SIZE: usize = 12 * 1024;
const FILES_STREAM_CHUNK_SIZE: usize = 48 * 1024;

/// Sentinel prefix for challenge-response authentication messages on WebRTC channels.
const AUTH_SENTINEL: &[u8] = b"\x00PSAU";
/// Per-send timeout for streaming downloads to detect dead channels.
const DOWNLOAD_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const DIRECT_TRANSFER_BUFFER_HIGH_WATER: usize = 256 * 1024;
const DIRECT_TRANSFER_BUFFER_POLL: Duration = Duration::from_millis(10);

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

async fn send_direct_transfer_result(
    channel: Arc<RTCDataChannel>,
    transfer_id: &str,
    ok: bool,
    bytes_written: u64,
    error: Option<String>,
) {
    let payload = if ok {
        serde_json::json!({
            "transfer_id": transfer_id,
            "status": "ok",
            "bytes_written": bytes_written,
        })
    } else {
        serde_json::json!({
            "transfer_id": transfer_id,
            "status": "error",
            "error": error.unwrap_or_else(|| "direct transfer failed".to_string()),
        })
    };

    if let Ok(bytes) = serde_json::to_vec(&payload) {
        let _ = channel.send(&bytes::Bytes::from(bytes)).await;
    }
}

fn bind_inbound_host_transfer_channel(
    transfer_id: String,
    channel: Arc<RTCDataChannel>,
    event_tx: tokio::sync::mpsc::UnboundedSender<DirectHostTransferEvent>,
) {
    let upload_state = Arc::new(tokio::sync::Mutex::new(None::<PendingFilesBinaryUpload>));

    {
        let transfer_id = transfer_id.clone();
        let message_channel = Arc::clone(&channel);
        let upload_state = Arc::clone(&upload_state);
        let event_tx = event_tx.clone();
        channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let transfer_id = transfer_id.clone();
            let channel = Arc::clone(&message_channel);
            let upload_state = Arc::clone(&upload_state);
            let event_tx = event_tx.clone();
            Box::pin(async move {
                let data = msg.data.to_vec();
                let Some(frame) = decode_files_stream_frame(&data) else {
                    return;
                };

                let op = frame
                    .header
                    .get("op")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();

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
                                let tmp_path = match file_path.extension() {
                                    Some(ext) => file_path.with_extension(format!(
                                        "{}.pstmp",
                                        ext.to_string_lossy()
                                    )),
                                    None => file_path.with_extension("pstmp"),
                                };
                                match OpenOptions::new()
                                    .create(true)
                                    .write(true)
                                    .truncate(true)
                                    .open(&tmp_path)
                                {
                                    Ok(file) => {
                                        *upload_state.lock().await = Some(PendingFilesBinaryUpload {
                                            final_path: file_path,
                                            tmp_path,
                                            file,
                                            bytes_written: 0,
                                            created_at: Instant::now(),
                                        });
                                    }
                                    Err(err) => {
                                        send_direct_transfer_result(
                                            Arc::clone(&channel),
                                            &transfer_id,
                                            false,
                                            0,
                                            Some(err.to_string()),
                                        )
                                        .await;
                                        let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                                            transfer_id: transfer_id.clone(),
                                        });
                                    }
                                }
                            }
                            Err(err) => {
                                send_direct_transfer_result(
                                    Arc::clone(&channel),
                                    &transfer_id,
                                    false,
                                    0,
                                    Some(err.to_string()),
                                )
                                .await;
                                let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                                    transfer_id: transfer_id.clone(),
                                });
                            }
                        }
                    }
                    "upload_chunk" => {
                        let mut guard = upload_state.lock().await;
                        if let Some(upload) = guard.as_mut() {
                            if let Err(err) = upload.file.write_all(&frame.payload) {
                                drop(guard);
                                send_direct_transfer_result(
                                    Arc::clone(&channel),
                                    &transfer_id,
                                    false,
                                    0,
                                    Some(err.to_string()),
                                )
                                .await;
                                let mut guard = upload_state.lock().await;
                                if let Some(upload) = guard.take() {
                                    drop(upload.file);
                                    let _ = std::fs::remove_file(&upload.tmp_path);
                                }
                                let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                                    transfer_id: transfer_id.clone(),
                                });
                            } else {
                                upload.bytes_written += frame.payload.len();
                                upload.created_at = Instant::now();
                            }
                        }
                    }
                    "upload_end" => {
                        let maybe_upload = upload_state.lock().await.take();
                        match maybe_upload {
                            Some(mut upload) => {
                                let _ = upload.file.flush();
                                let bytes_written = upload.bytes_written as u64;
                                drop(upload.file);
                                match std::fs::rename(&upload.tmp_path, &upload.final_path) {
                                    Ok(()) => {
                                        send_direct_transfer_result(
                                            Arc::clone(&channel),
                                            &transfer_id,
                                            true,
                                            bytes_written,
                                            None,
                                        )
                                        .await;
                                    }
                                    Err(err) => {
                                        let _ = std::fs::remove_file(&upload.tmp_path);
                                        send_direct_transfer_result(
                                            Arc::clone(&channel),
                                            &transfer_id,
                                            false,
                                            0,
                                            Some(format!("failed to finalize upload: {}", err)),
                                        )
                                        .await;
                                        let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                                            transfer_id: transfer_id.clone(),
                                        });
                                    }
                                }
                            }
                            None => {
                                send_direct_transfer_result(
                                    Arc::clone(&channel),
                                    &transfer_id,
                                    false,
                                    0,
                                    Some("upload_state_missing".to_string()),
                                )
                                .await;
                                let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                                    transfer_id: transfer_id.clone(),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            })
        }));
    }

    channel.on_close(Box::new(move || {
        let transfer_id = transfer_id.clone();
        let upload_state = Arc::clone(&upload_state);
        let event_tx = event_tx.clone();
        Box::pin(async move {
            if let Some(upload) = upload_state.lock().await.take() {
                drop(upload.file);
                let _ = std::fs::remove_file(&upload.tmp_path);
            }
            let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                transfer_id,
            });
        })
    }));
}

fn bind_outbound_host_transfer_channel(
    transfer_id: String,
    mobile_device_id: String,
    source_path: String,
    destination_path: String,
    total_size: u64,
    channel: Arc<RTCDataChannel>,
    event_tx: tokio::sync::mpsc::UnboundedSender<DirectHostTransferEvent>,
) {
    let started = Arc::new(AtomicBool::new(false));
    let (result_tx, result_rx) = oneshot::channel::<std::result::Result<u64, String>>();
    let result_tx = Arc::new(std::sync::Mutex::new(Some(result_tx)));

    {
        let result_tx = Arc::clone(&result_tx);
        channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let result_tx = Arc::clone(&result_tx);
            Box::pin(async move {
                let Ok(val) = serde_json::from_slice::<serde_json::Value>(&msg.data) else {
                    return;
                };
                let status = val.get("status").and_then(|v| v.as_str()).unwrap_or_default();
                let mut guard = result_tx.lock().expect("poisoned result sender");
                if let Some(sender) = guard.take() {
                    let _ = sender.send(if status == "ok" {
                        Ok(val
                            .get("bytes_written")
                            .and_then(|v| v.as_u64())
                            .unwrap_or_default())
                    } else {
                        Err(val
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("direct transfer failed")
                            .to_string())
                    });
                }
            })
        }));
    }

    {
        let transfer_id = transfer_id.clone();
        let result_tx = Arc::clone(&result_tx);
        let event_tx = event_tx.clone();
        channel.on_close(Box::new(move || {
            let transfer_id = transfer_id.clone();
            let result_tx = Arc::clone(&result_tx);
            let event_tx = event_tx.clone();
            Box::pin(async move {
                let mut guard = result_tx.lock().expect("poisoned result sender");
                if let Some(sender) = guard.take() {
                    let _ = sender.send(Err("direct transfer channel closed".to_string()));
                }
                let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                    transfer_id,
                });
            })
        }));
    }

    let open_channel = Arc::clone(&channel);
    channel.on_open(Box::new(move || {
        let channel = Arc::clone(&open_channel);
        let transfer_id = transfer_id.clone();
        let mobile_device_id = mobile_device_id.clone();
        let source_path = source_path.clone();
        let destination_path = destination_path.clone();
        let event_tx = event_tx.clone();
        let started = Arc::clone(&started);
        Box::pin(async move {
            if started.swap(true, Ordering::SeqCst) {
                return;
            }

            let timeout_ms =
                std::cmp::max(120_000_u64, 120_000_u64 + ((total_size / (1024 * 1024)) * 1_000));

            let source_file = match crate::files::resolve_file_path_for_transfer(&source_path) {
                Ok(path) => path,
                Err(err) => {
                    let _ = event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        ok: false,
                        bytes_written: 0,
                        error: Some(err.to_string()),
                    });
                    let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                        transfer_id: transfer_id.clone(),
                    });
                    return;
                }
            };

            let file = match File::open(&source_file) {
                Ok(file) => file,
                Err(err) => {
                    let _ = event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        ok: false,
                        bytes_written: 0,
                        error: Some(err.to_string()),
                    });
                    let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                        transfer_id: transfer_id.clone(),
                    });
                    return;
                }
            };

            if let Err(err) = send_files_stream_frame(
                Arc::clone(&channel),
                &serde_json::json!({
                    "op": "upload_start",
                    "id": transfer_id,
                    "path": destination_path,
                    "size": total_size,
                }),
                &[],
            )
            .await
            {
                let _ = event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id: transfer_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    ok: false,
                    bytes_written: 0,
                    error: Some(err.to_string()),
                });
                let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                    transfer_id: transfer_id.clone(),
                });
                return;
            }

            let mut reader = BufReader::new(file);
            let mut buf = vec![0u8; FILES_STREAM_CHUNK_SIZE];
            let mut bytes_sent = 0_u64;
            let mut last_emit = Instant::now();

            loop {
                let read = match reader.read(&mut buf) {
                    Ok(read) => read,
                    Err(err) => {
                        let _ = event_tx.send(DirectHostTransferEvent::Result {
                            transfer_id: transfer_id.clone(),
                            mobile_device_id: mobile_device_id.clone(),
                            ok: false,
                            bytes_written: 0,
                            error: Some(err.to_string()),
                        });
                        let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                            transfer_id: transfer_id.clone(),
                        });
                        return;
                    }
                };

                if read == 0 {
                    break;
                }

                while channel.buffered_amount().await > DIRECT_TRANSFER_BUFFER_HIGH_WATER {
                    tokio::time::sleep(DIRECT_TRANSFER_BUFFER_POLL).await;
                }

                let header = serde_json::json!({
                    "op": "upload_chunk",
                    "id": transfer_id,
                    "i": bytes_sent,
                });
                match tokio::time::timeout(
                    DOWNLOAD_SEND_TIMEOUT,
                    send_files_stream_frame(Arc::clone(&channel), &header, &buf[..read]),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        let _ = event_tx.send(DirectHostTransferEvent::Result {
                            transfer_id: transfer_id.clone(),
                            mobile_device_id: mobile_device_id.clone(),
                            ok: false,
                            bytes_written: 0,
                            error: Some(err.to_string()),
                        });
                        let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                            transfer_id: transfer_id.clone(),
                        });
                        return;
                    }
                    Err(_) => {
                        let _ = event_tx.send(DirectHostTransferEvent::Result {
                            transfer_id: transfer_id.clone(),
                            mobile_device_id: mobile_device_id.clone(),
                            ok: false,
                            bytes_written: 0,
                            error: Some("direct transfer send timed out".to_string()),
                        });
                        let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                            transfer_id: transfer_id.clone(),
                        });
                        return;
                    }
                }

                bytes_sent += read as u64;
                if last_emit.elapsed() >= Duration::from_millis(200) || bytes_sent == total_size {
                    let _ = event_tx.send(DirectHostTransferEvent::Progress {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        bytes_transferred: bytes_sent,
                        total_bytes: total_size,
                    });
                    last_emit = Instant::now();
                }
            }

            if let Err(err) = send_files_stream_frame(
                Arc::clone(&channel),
                &serde_json::json!({
                    "op": "upload_end",
                    "id": transfer_id,
                }),
                &[],
            )
            .await
            {
                let _ = event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id: transfer_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    ok: false,
                    bytes_written: 0,
                    error: Some(err.to_string()),
                });
                let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                    transfer_id: transfer_id.clone(),
                });
                return;
            }

            match tokio::time::timeout(Duration::from_millis(timeout_ms), result_rx).await {
                Ok(Ok(Ok(bytes_written))) => {
                    let _ = event_tx.send(DirectHostTransferEvent::Progress {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        bytes_transferred: total_size,
                        total_bytes: total_size,
                    });
                    let _ = event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        ok: true,
                        bytes_written,
                        error: None,
                    });
                }
                Ok(Ok(Err(err))) => {
                    let _ = event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        ok: false,
                        bytes_written: 0,
                        error: Some(err),
                    });
                }
                Ok(Err(_)) | Err(_) => {
                    let _ = event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id: transfer_id.clone(),
                        mobile_device_id: mobile_device_id.clone(),
                        ok: false,
                        bytes_written: 0,
                        error: Some("direct transfer acknowledgement timed out".to_string()),
                    });
                }
            }

            let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound {
                transfer_id: transfer_id.clone(),
            });
        })
    }));
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
    let (direct_transfer_event_tx, mut direct_transfer_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<DirectHostTransferEvent>();
    let mut outbound_host_transfers: HashMap<String, OutboundHostTransfer> = HashMap::new();
    let mut inbound_host_transfers: HashMap<String, InboundHostTransfer> = HashMap::new();
    // Per-session E2E encryption ciphers for signaling-based file operations
    let mut session_ciphers: HashMap<String, SessionCipher> = HashMap::new();
    // Cancellation signals for active download_stream tasks per mobile device
    let mut files_download_cancels: HashMap<String, tokio::sync::watch::Sender<bool>> = HashMap::new();

    // Challenge-response auth state for WebRTC channels
    let mut authenticated_channels: HashSet<String> = HashSet::new();
    // Maps channel_key -> (nonce_base64, expected_mobile_device_id)
    let mut pending_auth: HashMap<String, (String, String)> = HashMap::new();

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
                    // Revocation-only sync: check backend for revoked devices,
                    // remove them locally, and kill their sessions.
                    // New devices are NEVER added here — only via `pocketshell pair`.
                    if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                        if let Ok(devices) = backend.list_trusted_devices(&token, &host_id).await {
                            let removed = store.apply_revocations(&devices);
                            for revoked_id in &removed {
                                info!("device {} revoked via backend sync — closing sessions", revoked_id);
                                // Also remove from authenticated channels
                                authenticated_channels.retain(|k| !k.contains(revoked_id));
                                pending_auth.retain(|k, _| !k.contains(revoked_id));

                                let affected_sessions = store
                                    .state
                                    .sessions
                                    .iter()
                                    .filter(|s| s.mobile_device_id == *revoked_id)
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
                            if !removed.is_empty() {
                                let _ = store.save();
                            }
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
                            session_ciphers.remove(&session_id);
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
                    outbound_host_transfers.retain(|_, transfer| {
                        now.duration_since(transfer.created_at).as_secs() < FILE_TRANSFER_TIMEOUT_SECS
                    });
                    inbound_host_transfers.retain(|_, transfer| {
                        now.duration_since(transfer.created_at).as_secs() < FILE_TRANSFER_TIMEOUT_SECS
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
                    for (transfer_id, transfer) in &mut outbound_host_transfers {
                        while let Ok(candidate) = transfer.peer.ice_tx.try_recv() {
                            if let Ok(json) = candidate.to_json() {
                                if let Ok(mut payload) = serde_json::to_value(json) {
                                    if let Some(map) = payload.as_object_mut() {
                                        map.insert("transfer_id".to_string(), serde_json::json!(transfer_id));
                                        map.insert("offer_id".to_string(), serde_json::json!(transfer.offer_id));
                                    }
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert(
                                        "target_host_id".to_string(),
                                        serde_json::json!(transfer.target_host_id),
                                    );
                                    extra.insert(
                                        "mobile_device_id".to_string(),
                                        serde_json::json!(transfer.mobile_device_id),
                                    );
                                    let ice_msg = SignalEnvelope {
                                        message_type: "host_transfer_ice_candidate".to_string(),
                                        session_id: None,
                                        payload: Some(payload),
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
                    for (transfer_id, transfer) in &mut inbound_host_transfers {
                        while let Ok(candidate) = transfer.peer.ice_tx.try_recv() {
                            if let Ok(json) = candidate.to_json() {
                                if let Ok(mut payload) = serde_json::to_value(json) {
                                    if let Some(map) = payload.as_object_mut() {
                                        map.insert("transfer_id".to_string(), serde_json::json!(transfer_id));
                                        map.insert("offer_id".to_string(), serde_json::json!(transfer.offer_id));
                                    }
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert(
                                        "target_host_id".to_string(),
                                        serde_json::json!(transfer.source_host_id),
                                    );
                                    extra.insert(
                                        "mobile_device_id".to_string(),
                                        serde_json::json!(transfer.mobile_device_id),
                                    );
                                    let ice_msg = SignalEnvelope {
                                        message_type: "host_transfer_ice_candidate".to_string(),
                                        session_id: None,
                                        payload: Some(payload),
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

                Some(event) = direct_transfer_event_rx.recv() => {
                    match event {
                        DirectHostTransferEvent::Progress {
                            transfer_id,
                            mobile_device_id,
                            bytes_transferred,
                            total_bytes,
                        } => {
                            let mut extra = std::collections::HashMap::new();
                            extra.insert(
                                "target_mobile_device_id".to_string(),
                                serde_json::json!(mobile_device_id),
                            );
                            let msg = SignalEnvelope {
                                message_type: "host_transfer_progress".to_string(),
                                session_id: None,
                                payload: Some(serde_json::json!({
                                    "transfer_id": transfer_id,
                                    "bytes_transferred": bytes_transferred,
                                    "total_bytes": total_bytes,
                                })),
                                state: None,
                                accepted: None,
                                reason: None,
                                extra,
                            };
                            let _ = send_signal(&mut ws, &msg).await;
                        }
                        DirectHostTransferEvent::Result {
                            transfer_id,
                            mobile_device_id,
                            ok,
                            bytes_written,
                            error,
                        } => {
                            let mut extra = std::collections::HashMap::new();
                            extra.insert(
                                "target_mobile_device_id".to_string(),
                                serde_json::json!(mobile_device_id),
                            );
                            let msg = SignalEnvelope {
                                message_type: "host_transfer_result".to_string(),
                                session_id: None,
                                payload: Some(if ok {
                                    serde_json::json!({
                                        "transfer_id": transfer_id,
                                        "status": "ok",
                                        "bytes_written": bytes_written,
                                    })
                                } else {
                                    serde_json::json!({
                                        "transfer_id": transfer_id,
                                        "status": "error",
                                        "error": error.unwrap_or_else(|| "direct transfer failed".to_string()),
                                    })
                                }),
                                state: None,
                                accepted: None,
                                reason: None,
                                extra,
                            };
                            let _ = send_signal(&mut ws, &msg).await;
                        }
                        DirectHostTransferEvent::CleanupOutbound { transfer_id } => {
                            if let Some(transfer) = outbound_host_transfers.remove(&transfer_id) {
                                transfer.peer.close().await;
                            }
                        }
                        DirectHostTransferEvent::CleanupInbound { transfer_id } => {
                            if let Some(transfer) = inbound_host_transfers.remove(&transfer_id) {
                                transfer.peer.close().await;
                            }
                        }
                    }
                }

                Some(webrtc_event) = webrtc_event_rx.recv() => {
                    match webrtc_event {
                        WebRtcEvent::Input { session_id, mobile_device_id, data } => {
                            // Handle auth protocol messages (consumed, never passed to PTY)
                            if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSAU" {
                                if let Ok(json_str) = std::str::from_utf8(&data[5..]) {
                                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(json_str) {
                                        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                        if msg_type == "auth_response" {
                                            let result = verify_device_auth(
                                                &msg, &session_id, &mobile_device_id,
                                                &mut pending_auth, &store,
                                            );
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            webrtc_mgr.send_output(&session_id, &response).await;
                                            if result.is_ok() {
                                                authenticated_channels.insert(session_id.clone());
                                                info!("device {} authenticated for session {}", mobile_device_id, session_id);
                                            } else {
                                                warn!("auth failed for device {} session {}: {:?}", mobile_device_id, session_id, result.err());
                                            }
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&session_id) {
                                warn!("dropping unauthenticated input on session {} from device {}", session_id, mobile_device_id);
                            } else {
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
                        }
                        WebRtcEvent::ChannelOpened { session_id } => {
                            info!("webrtc data channel opened for session {}", session_id);
                            // Send auth challenge to the mobile device
                            let mobile_device_id = store.state.sessions.iter()
                                .find(|s| s.session_id == session_id)
                                .map(|s| s.mobile_device_id.clone())
                                .unwrap_or_default();
                            if !mobile_device_id.is_empty() {
                                let mut nonce_bytes = [0u8; 32];
                                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                                let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);
                                pending_auth.insert(session_id.clone(), (nonce_b64.clone(), mobile_device_id.clone()));
                                let challenge = build_auth_message(&serde_json::json!({
                                    "type": "auth_challenge",
                                    "nonce": nonce_b64,
                                }));
                                webrtc_mgr.send_output(&session_id, &challenge).await;
                                info!("sent auth challenge for session {} to device {}", session_id, mobile_device_id);
                            }
                        }
                        WebRtcEvent::ChannelClosed { session_id } => {
                            info!("webrtc data channel closed for session {}", session_id);
                            webrtc_mgr.prune_session_channels(&session_id);
                            authenticated_channels.remove(&session_id);
                            pending_auth.remove(&session_id);
                        }
                        WebRtcEvent::StatsChannelOpened { host_id, mobile_device_id, channel } => {
                            info!("stats WebRTC channel opened for host {} from device {}", host_id, mobile_device_id);
                            let stats_channel_key = format!("stats:{mobile_device_id}");
                            let mut nonce_bytes = [0u8; 32];
                            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                            let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);
                            pending_auth.insert(stats_channel_key.clone(), (nonce_b64.clone(), mobile_device_id.clone()));
                            let challenge = build_auth_message(&serde_json::json!({
                                "type": "auth_challenge",
                                "nonce": nonce_b64,
                            }));
                            if let Err(err) = channel.send(&bytes::Bytes::from(challenge)).await {
                                warn!("stats auth challenge send failed for device {}: {}", mobile_device_id, err);
                            } else {
                                info!("sent stats auth challenge for device {}", mobile_device_id);
                            }
                        }
                        WebRtcEvent::StatsChannelClosed { host_id, mobile_device_id } => {
                            info!("stats WebRTC channel closed for host {}", host_id);
                            let stats_channel_key = format!("stats:{mobile_device_id}");
                            authenticated_channels.remove(&stats_channel_key);
                            pending_auth.remove(&stats_channel_key);
                            webrtc_mgr.prune_stats_channels();
                        }
                        WebRtcEvent::FilesChannelOpened {
                            mobile_device_id,
                            channel,
                        } => {
                            info!("files WebRTC channel opened for mobile {}", mobile_device_id);
                            // Send auth challenge on files channel
                            let files_channel_key = format!("files:{mobile_device_id}");
                            let mut nonce_bytes = [0u8; 32];
                            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                            let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);
                            pending_auth.insert(files_channel_key.clone(), (nonce_b64.clone(), mobile_device_id.clone()));
                            let challenge = build_auth_message(&serde_json::json!({
                                "type": "auth_challenge",
                                "nonce": nonce_b64,
                            }));
                            if let Err(err) = channel.send(&bytes::Bytes::from(challenge)).await {
                                warn!("files auth challenge send failed for mobile {}: {}", mobile_device_id, err);
                            } else {
                                info!("sent files auth challenge for mobile {}", mobile_device_id);
                            }
                        }
                        WebRtcEvent::FilesChannelClosed { mobile_device_id } => {
                            info!("files WebRTC channel closed for mobile {}", mobile_device_id);
                            let files_channel_key = format!("files:{mobile_device_id}");
                            authenticated_channels.remove(&files_channel_key);
                            pending_auth.remove(&files_channel_key);
                            files_peer_offer_ids.remove(&files_channel_key);
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
                            let files_channel_key = format!("files:{mobile_device_id}");
                            // Handle auth protocol messages
                            if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSAU" {
                                if let Ok(json_str) = std::str::from_utf8(&data[5..]) {
                                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(json_str) {
                                        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                        if msg_type == "auth_response" {
                                            let result = verify_device_auth(
                                                &msg, &files_channel_key, &mobile_device_id,
                                                &mut pending_auth, &store,
                                            );
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                                warn!("files auth result send failed for mobile {}: {}", mobile_device_id, err);
                                            }
                                            if result.is_ok() {
                                                authenticated_channels.insert(files_channel_key.clone());
                                                info!("device {} authenticated for files channel", mobile_device_id);
                                                // Send ready after auth so the mobile doesn't drop it
                                                let ready = serde_json::json!({
                                                    "channel": "files",
                                                    "event": "ready",
                                                });
                                                match serde_json::to_vec(&ready) {
                                                    Ok(bytes) => {
                                                        if let Err(err) = channel.send(&bytes::Bytes::from(bytes)).await {
                                                            warn!("files WebRTC ready send failed for mobile {}: {}", mobile_device_id, err);
                                                        } else {
                                                            info!("files WebRTC ready sent for mobile {}", mobile_device_id);
                                                        }
                                                    }
                                                    Err(err) => warn!("files WebRTC ready encode failed for mobile {}: {}", mobile_device_id, err),
                                                }
                                            } else {
                                                warn!("files auth failed for device {}: {:?}", mobile_device_id, result.err());
                                            }
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&files_channel_key) {
                                warn!("dropping unauthenticated files message from device {}", mobile_device_id);
                            } else {
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
                                        } else {
                                            warn!("upload_chunk for unknown upload key: {}", upload_key);
                                            let response = serde_json::json!({
                                                "channel": "files",
                                                "response_to": request_id,
                                                "status": "error",
                                                "error": "no active upload for this key; upload may have expired or was never started",
                                                "error_code": "upload_not_found"
                                            });
                                            if let Err(e) = send_framed_files_response(channel, &response).await {
                                                warn!("files upload_not_found send failed: {}", e);
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
                            } // end files processing
                            } // end auth gate
                        }
                        WebRtcEvent::StatsMessage { mobile_device_id, data, channel } => {
                            let stats_channel_key = format!("stats:{mobile_device_id}");
                            // Handle auth protocol messages
                            if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSAU" {
                                if let Ok(json_str) = std::str::from_utf8(&data[5..]) {
                                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(json_str) {
                                        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                        if msg_type == "auth_response" {
                                            let result = verify_device_auth(
                                                &msg, &stats_channel_key, &mobile_device_id,
                                                &mut pending_auth, &store,
                                            );
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                                warn!("stats auth result send failed for device {}: {}", mobile_device_id, err);
                                            }
                                            if result.is_ok() {
                                                authenticated_channels.insert(stats_channel_key.clone());
                                                info!("device {} authenticated for stats channel", mobile_device_id);
                                            } else {
                                                warn!("stats auth failed for device {}: {:?}", mobile_device_id, result.err());
                                            }
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&stats_channel_key) {
                                warn!("dropping unauthenticated stats message from device {}", mobile_device_id);
                            } else if let Ok(json_str) = std::str::from_utf8(&data) {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                                    let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                                    if msg_type == "kill_process" {
                                        let pid = val.get("pid").and_then(|v| v.as_i64());
                                        let signal = val.get("signal").and_then(|v| v.as_str()).unwrap_or("TERM");
                                        if let Some(pid) = pid {
                                            if pid <= 0 {
                                                warn!("kill_process rejected: invalid pid {} (non-positive PIDs target process groups)", pid);
                                            } else if pid == 1 {
                                                warn!("kill_process rejected: refusing to signal pid 1 (init/systemd)");
                                            } else {
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
                        WebRtcEvent::ControlChannelOpened { mobile_device_id, channel } => {
                            info!("control WebRTC channel opened for mobile {}", mobile_device_id);
                            let control_channel_key = format!("control:{mobile_device_id}");
                            let mut nonce_bytes = [0u8; 32];
                            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                            let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);
                            pending_auth.insert(control_channel_key.clone(), (nonce_b64.clone(), mobile_device_id.clone()));
                            let challenge = build_auth_message(&serde_json::json!({
                                "type": "auth_challenge",
                                "nonce": nonce_b64,
                            }));
                            if let Err(err) = channel.send(&bytes::Bytes::from(challenge)).await {
                                warn!("control auth challenge send failed for device {}: {}", mobile_device_id, err);
                            } else {
                                info!("sent control auth challenge for device {}", mobile_device_id);
                            }
                        }
                        WebRtcEvent::ControlChannelClosed { mobile_device_id } => {
                            info!("control WebRTC channel closed for mobile {}", mobile_device_id);
                            let control_channel_key = format!("control:{mobile_device_id}");
                            authenticated_channels.remove(&control_channel_key);
                            pending_auth.remove(&control_channel_key);
                            webrtc_mgr.prune_control_channels();
                        }
                        WebRtcEvent::ControlMessage { mobile_device_id, data, channel } => {
                            let control_channel_key = format!("control:{mobile_device_id}");
                            // Handle \x00PSAU auth protocol messages.
                            if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSAU" {
                                if let Ok(json_str) = std::str::from_utf8(&data[5..]) {
                                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(json_str) {
                                        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                        if msg_type == "auth_response" {
                                            let result = verify_device_auth(
                                                &msg, &control_channel_key, &mobile_device_id,
                                                &mut pending_auth, &store,
                                            );
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                                warn!("control auth result send failed for device {}: {}", mobile_device_id, err);
                                            }
                                            if result.is_ok() {
                                                authenticated_channels.insert(control_channel_key.clone());
                                                info!("device {} authenticated for control channel", mobile_device_id);
                                                // Send ready so the mobile knows it can start issuing RPCs.
                                                let ready = serde_json::json!({
                                                    "channel": "control",
                                                    "event": "ready",
                                                });
                                                match serde_json::to_vec(&ready) {
                                                    Ok(bytes) => {
                                                        if let Err(err) = channel.send(&bytes::Bytes::from(bytes)).await {
                                                            warn!("control ready send failed for device {}: {}", mobile_device_id, err);
                                                        }
                                                    }
                                                    Err(err) => warn!("control ready encode failed: {}", err),
                                                }
                                            } else {
                                                warn!("control auth failed for device {}: {:?}", mobile_device_id, result.err());
                                            }
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&control_channel_key) {
                                warn!("dropping unauthenticated control message from device {}", mobile_device_id);
                            } else if let Some(req) = crate::rpc::parse_request(&data) {
                                let method = req.method.clone();
                                let req_id = req.id.clone();
                                // Dispatch on a blocking-friendly future; RPC handlers are cheap
                                // and synchronous, but spawn to avoid holding the event loop
                                // if future handlers block (e.g. on command execution).
                                let ch = Arc::clone(&channel);
                                tokio::spawn(async move {
                                    let resp = crate::rpc::dispatch(req).await;
                                    match serde_json::to_vec(&resp) {
                                        Ok(bytes) => {
                                            if let Err(err) = ch.send(&bytes::Bytes::from(bytes)).await {
                                                warn!("control RPC response send failed for method={} id={}: {}", method, req_id, err);
                                            }
                                        }
                                        Err(err) => warn!("control RPC response encode failed: {}", err),
                                    }
                                });
                            } else {
                                warn!("control RPC parse failed from device {} (bytes={})", mobile_device_id, data.len());
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
                                &mut outbound_host_transfers,
                                &mut inbound_host_transfers,
                                &files_response_tx,
                                &direct_transfer_event_tx,
                                &mut session_ciphers,
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
        session_ciphers.clear();
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
    outbound_host_transfers: &mut HashMap<String, OutboundHostTransfer>,
    inbound_host_transfers: &mut HashMap<String, InboundHostTransfer>,
    files_response_tx: &tokio::sync::mpsc::UnboundedSender<SignalEnvelope>,
    direct_transfer_event_tx: &tokio::sync::mpsc::UnboundedSender<DirectHostTransferEvent>,
    session_ciphers: &mut HashMap<String, SessionCipher>,
) -> Result<()> {
    match msg.message_type.as_str() {
        "host_transfer_request" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let Some(payload) = &msg.payload else {
                return Ok(());
            };
            if mobile_device_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id: payload
                        .get("transfer_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    mobile_device_id,
                    ok: false,
                    bytes_written: 0,
                    error: Some("device is not trusted on source host".to_string()),
                });
                return Ok(());
            }
            let transfer_id = payload
                .get("transfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let dst_host_id = payload
                .get("dst_host_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let src_path = payload
                .get("src_path")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let dst_path = payload
                .get("dst_path")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if transfer_id.is_empty() || dst_host_id.is_empty() || src_path.is_empty() || dst_path.is_empty() {
                let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id,
                    mobile_device_id,
                    ok: false,
                    bytes_written: 0,
                    error: Some("invalid direct transfer request".to_string()),
                });
                return Ok(());
            }

            let source_file = match crate::files::resolve_file_path_for_transfer(&src_path) {
                Ok(path) => path,
                Err(err) => {
                    let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id,
                        mobile_device_id,
                        ok: false,
                        bytes_written: 0,
                        error: Some(err.to_string()),
                    });
                    return Ok(());
                }
            };
            let metadata = match std::fs::metadata(&source_file) {
                Ok(meta) => meta,
                Err(err) => {
                    let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id,
                        mobile_device_id,
                        ok: false,
                        bytes_written: 0,
                        error: Some(err.to_string()),
                    });
                    return Ok(());
                }
            };
            if metadata.is_dir() {
                let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id,
                    mobile_device_id,
                    ok: false,
                    bytes_written: 0,
                    error: Some("cannot transfer a directory directly".to_string()),
                });
                return Ok(());
            }

            let token = store.access_token()?.to_string();
            let (username, credential, _ttl, uris) = match backend.turn_credentials(&token).await {
                Ok(creds) => creds,
                Err(err) => {
                    let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id,
                        mobile_device_id,
                        ok: false,
                        bytes_written: 0,
                        error: Some(format!("failed to fetch TURN credentials: {}", err)),
                    });
                    return Ok(());
                }
            };

            let peer = match WebRtcPeer::new(uris, username, credential).await {
                Ok(peer) => peer,
                Err(err) => {
                    let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id,
                        mobile_device_id,
                        ok: false,
                        bytes_written: 0,
                        error: Some(err.to_string()),
                    });
                    return Ok(());
                }
            };

            let offer_id = format!(
                "hto_{}_{}",
                transfer_id,
                chrono::Utc::now().timestamp_millis()
            );
            let label = format!("host-transfer-{}", transfer_id);
            let (channel, offer_sdp) = match peer.create_offer_with_data_channel(&label).await {
                Ok(result) => result,
                Err(err) => {
                    let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                        transfer_id,
                        mobile_device_id,
                        ok: false,
                        bytes_written: 0,
                        error: Some(err.to_string()),
                    });
                    return Ok(());
                }
            };

            let total_size = metadata.len();
            bind_outbound_host_transfer_channel(
                transfer_id.clone(),
                mobile_device_id.clone(),
                src_path,
                dst_path.clone(),
                total_size,
                channel,
                direct_transfer_event_tx.clone(),
            );

            outbound_host_transfers.insert(
                transfer_id.clone(),
                OutboundHostTransfer {
                    peer,
                    target_host_id: dst_host_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    offer_id: offer_id.clone(),
                    created_at: Instant::now(),
                },
            );

            let mut extra = std::collections::HashMap::new();
            extra.insert("target_host_id".to_string(), serde_json::json!(dst_host_id));
            extra.insert(
                "mobile_device_id".to_string(),
                serde_json::json!(mobile_device_id),
            );
            let offer_payload = build_signed_sdp_payload(
                store,
                &offer_sdp,
                "offer",
                vec![
                    ("transfer_id", serde_json::json!(transfer_id)),
                    ("offer_id", serde_json::json!(offer_id)),
                    ("dst_path", serde_json::json!(dst_path)),
                    ("total_size", serde_json::json!(total_size)),
                ],
            );
            let offer_msg = SignalEnvelope {
                message_type: "host_transfer_offer".to_string(),
                session_id: None,
                payload: Some(offer_payload),
                state: None,
                accepted: None,
                reason: None,
                extra,
            };
            let _ = send_signal(ws, &offer_msg).await;
        }
        "host_transfer_offer" => {
            let source_host_id = msg
                .extra
                .get("host_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let Some(payload) = &msg.payload else {
                return Ok(());
            };
            let transfer_id = payload
                .get("transfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let offer_id = payload
                .get("offer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let offer_sdp = payload
                .get("sdp")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if transfer_id.is_empty() || source_host_id.is_empty() || offer_sdp.is_empty() {
                return Ok(());
            }
            if mobile_device_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                let reject_msg = SignalEnvelope {
                    message_type: "host_transfer_result".to_string(),
                    session_id: None,
                    payload: Some(serde_json::json!({
                        "transfer_id": transfer_id,
                        "status": "error",
                        "error": "device is not trusted on destination host",
                    })),
                    state: None,
                    accepted: None,
                    reason: None,
                    extra,
                };
                let _ = send_signal(ws, &reject_msg).await;
                return Ok(());
            }

            let token = store.access_token()?.to_string();
            let (username, credential, _ttl, uris) = backend.turn_credentials(&token).await?;
            let peer = WebRtcPeer::new(uris, username, credential).await?;
            {
                let transfer_id = transfer_id.clone();
                let event_tx = direct_transfer_event_tx.clone();
                peer.peer.on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
                    let transfer_id = transfer_id.clone();
                    let event_tx = event_tx.clone();
                    Box::pin(async move {
                        bind_inbound_host_transfer_channel(transfer_id, channel, event_tx);
                    })
                }));
            }

            let answer_sdp = peer.apply_offer(&offer_sdp).await?;
            inbound_host_transfers.insert(
                transfer_id.clone(),
                InboundHostTransfer {
                    peer,
                    source_host_id: source_host_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    offer_id: offer_id.clone(),
                    created_at: Instant::now(),
                },
            );

            let mut extra = std::collections::HashMap::new();
            extra.insert("target_host_id".to_string(), serde_json::json!(source_host_id));
            extra.insert(
                "mobile_device_id".to_string(),
                serde_json::json!(mobile_device_id),
            );
            let answer_payload = build_signed_sdp_payload(
                store,
                &answer_sdp,
                "answer",
                vec![
                    ("transfer_id", serde_json::json!(transfer_id)),
                    ("offer_id", serde_json::json!(offer_id)),
                ],
            );
            let answer_msg = SignalEnvelope {
                message_type: "host_transfer_answer".to_string(),
                session_id: None,
                payload: Some(answer_payload),
                state: None,
                accepted: None,
                reason: None,
                extra,
            };
            let _ = send_signal(ws, &answer_msg).await;
        }
        "host_transfer_answer" => {
            let Some(payload) = &msg.payload else {
                return Ok(());
            };
            let transfer_id = payload
                .get("transfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let offer_id = payload
                .get("offer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let answer_sdp = payload
                .get("sdp")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if let Some(transfer) = outbound_host_transfers.get(&transfer_id) {
                if !offer_id.is_empty() && transfer.offer_id != offer_id {
                    return Ok(());
                }
                if let Some(mobile_device_id) = msg.extra.get("mobile_device_id").and_then(|v| v.as_str()) {
                    if transfer.mobile_device_id != mobile_device_id {
                        return Ok(());
                    }
                }
                transfer.peer.apply_answer(&answer_sdp).await?;
            }
        }
        "host_transfer_ice_candidate" => {
            let Some(payload) = &msg.payload else {
                return Ok(());
            };
            let transfer_id = payload
                .get("transfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if transfer_id.is_empty() {
                return Ok(());
            }
            if let Ok(candidate) = serde_json::from_value::<
                webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
            >(payload.clone())
            {
                if let Some(transfer) = outbound_host_transfers.get(&transfer_id) {
                    if let Some(mobile_device_id) = msg.extra.get("mobile_device_id").and_then(|v| v.as_str()) {
                        if transfer.mobile_device_id != mobile_device_id {
                            return Ok(());
                        }
                    }
                    let _ = transfer.peer.add_ice_candidate(candidate.clone()).await;
                } else if let Some(transfer) = inbound_host_transfers.get(&transfer_id) {
                    if let Some(mobile_device_id) = msg.extra.get("mobile_device_id").and_then(|v| v.as_str()) {
                        if transfer.mobile_device_id != mobile_device_id {
                            return Ok(());
                        }
                    }
                    let _ = transfer.peer.add_ice_candidate(candidate).await;
                }
            }
        }
        "host_transfer_cancel" => {
            let transfer_id = msg
                .payload
                .as_ref()
                .and_then(|payload| payload.get("transfer_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let reason = msg
                .payload
                .as_ref()
                .and_then(|payload| payload.get("reason"))
                .and_then(|v| v.as_str())
                .unwrap_or("direct transfer cancelled")
                .to_string();
            if transfer_id.is_empty() {
                return Ok(());
            }

            if let Some(transfer) = outbound_host_transfers.remove(&transfer_id) {
                let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id: transfer_id.clone(),
                    mobile_device_id: transfer.mobile_device_id.clone(),
                    ok: false,
                    bytes_written: 0,
                    error: Some(reason),
                });
                transfer.peer.close().await;
                return Ok(());
            }

            if let Some(transfer) = inbound_host_transfers.remove(&transfer_id) {
                transfer.peer.close().await;
            }
        }
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
                        session_ciphers.remove(&evicted_session_id);
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
                // Upsert session record BEFORE the async backend call so that
                // ChannelOpened (which looks up mobile_device_id from the store)
                // can find it even if the backend transition_session call is slow.
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
                store.save()?;

                backend
                    .transition_session(&token, &session_id, SessionState::Connected, None)
                    .await?;

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
            // Require device key — devices without a pinned key (not paired via
            // `pocketshell pair`) cannot use the signaling relay either.
            if store.get_device_public_key(&mobile_device_id).is_none() {
                warn!(
                    "signal rejected: device {} has no pinned public key",
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
                                session_ciphers.remove(&session_id);
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
                            session_ciphers.remove(&session_id);
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
                    // Reject unencrypted file ops when E2E encryption is established
                    if session_ciphers.contains_key(&session_id) {
                        warn!(
                            "rejecting unencrypted files request for session {} — use encrypted_file_payload",
                            session_id
                        );
                        return Ok(());
                    }

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
                    debug!(
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
                                debug!(
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

                // Upsert session record BEFORE the async backend call so that
                // ChannelOpened (which looks up mobile_device_id from the store)
                // can find it even if the backend transition_session call is slow.
                store.upsert_session(SessionRecord {
                    session_id: session_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    state: SessionState::Connected,
                    updated_at: Utc::now(),
                    persistent: sessions.is_persistent(&session_id),
                    tmux_session_name: sessions.tmux_session_name(&session_id),
                });
                store.save()?;

                let token = store.access_token()?.to_string();
                let _ = backend
                    .transition_session(&token, &session_id, SessionState::Connected, None)
                    .await;
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
                // Clean up session cipher when session ends or fails
                if matches!(mapped, SessionState::Ended | SessionState::Failed) {
                    if session_ciphers.remove(&session_id).is_some() {
                        info!("removed E2E cipher for ended session {}", session_id);
                    }
                }
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
                                    let answer_payload = build_signed_sdp_payload(
                                        store,
                                        &answer_sdp,
                                        "answer",
                                        vec![],
                                    );
                                    let answer_msg = SignalEnvelope {
                                        message_type: "session_answer".to_string(),
                                        session_id: msg.session_id.clone(),
                                        payload: Some(answer_payload),
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
                                    let answer_payload = build_signed_sdp_payload(
                                        store,
                                        &answer_sdp,
                                        "answer",
                                        vec![],
                                    );
                                    let answer_msg = SignalEnvelope {
                                        message_type: "stats_answer".to_string(),
                                        session_id: None,
                                        payload: Some(answer_payload),
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
                                    let answer_payload = build_signed_sdp_payload(
                                        store,
                                        &answer_sdp,
                                        "answer",
                                        vec![("offer_id", serde_json::json!(offer_id))],
                                    );
                                    let answer_msg = SignalEnvelope {
                                        message_type: "files_answer".to_string(),
                                        session_id: None,
                                        payload: Some(answer_payload),
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
        "encrypted_file_payload" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "encrypted_file_payload rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            let Some(payload) = msg.payload else {
                return Ok(());
            };

            let session_id = match payload.get("session_id").and_then(|v| v.as_str()) {
                Some(sid) => sid.to_string(),
                None => {
                    warn!("encrypted_file_payload: missing session_id");
                    return Ok(());
                }
            };

            let nonce_b64 = match payload.get("nonce").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => {
                    warn!("encrypted_file_payload: missing nonce");
                    return Ok(());
                }
            };
            let ciphertext_b64 = match payload.get("ciphertext").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => {
                    warn!("encrypted_file_payload: missing ciphertext");
                    return Ok(());
                }
            };

            let cipher = match session_ciphers.get_mut(&session_id) {
                Some(c) => c,
                None => {
                    warn!("encrypted_file_payload: no cipher for session {}", session_id);
                    return Ok(());
                }
            };

            let nonce_bytes = match base64::engine::general_purpose::STANDARD.decode(nonce_b64) {
                Ok(b) => b,
                Err(e) => {
                    warn!("encrypted_file_payload: invalid nonce base64: {}", e);
                    return Ok(());
                }
            };
            let ciphertext = match base64::engine::general_purpose::STANDARD.decode(ciphertext_b64)
            {
                Ok(b) => b,
                Err(e) => {
                    warn!("encrypted_file_payload: invalid ciphertext base64: {}", e);
                    return Ok(());
                }
            };

            // Reject oversized inbound payloads (200 KB ciphertext ceiling)
            const MAX_INBOUND_CIPHERTEXT: usize = 200 * 1024;
            if ciphertext.len() > MAX_INBOUND_CIPHERTEXT {
                warn!(
                    "encrypted_file_payload: inbound too large ({} bytes), rejecting",
                    ciphertext.len()
                );
                return Ok(());
            }

            // Decrypt the request
            let plaintext = match cipher.decrypt(&nonce_bytes, &ciphertext) {
                Ok(pt) => pt,
                Err(e) => {
                    warn!("encrypted_file_payload: decryption failed: {}", e);
                    return Ok(());
                }
            };

            let file_payload: serde_json::Value = match serde_json::from_slice(&plaintext) {
                Ok(v) => v,
                Err(e) => {
                    warn!("encrypted_file_payload: invalid JSON after decrypt: {}", e);
                    return Ok(());
                }
            };

            let request_id = file_payload
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let action = file_payload
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let path = file_payload
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            debug!(
                "encrypted files >> action={} req={} path={} session={}",
                action, request_id, path, session_id
            );

            // Helper: encrypt plaintext and build an encrypted signaling envelope
            let encrypt_and_build = |cipher: &mut SessionCipher,
                                      plaintext: &[u8],
                                      session_id: &str,
                                      mobile_device_id: &str|
                -> std::result::Result<SignalEnvelope, anyhow::Error> {
                let (nonce, ct) = cipher.encrypt(plaintext)?;
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                Ok(SignalEnvelope {
                    message_type: "encrypted_file_payload".to_string(),
                    session_id: None,
                    payload: Some(serde_json::json!({
                        "session_id": session_id,
                        "nonce": base64::engine::general_purpose::STANDARD.encode(&nonce),
                        "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ct),
                    })),
                    state: None,
                    accepted: None,
                    reason: None,
                    extra,
                })
            };

            // Spawn file I/O so it doesn't block the signaling event loop
            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            let action_clone = action.clone();
            let req_id_clone = request_id.clone();
            tokio::spawn(async move {
                let start = std::time::Instant::now();
                let result = crate::files::handle_files_action(&file_payload).await;
                let elapsed = start.elapsed();

                let response_json = match result {
                    Ok(data) => {
                        debug!(
                            "encrypted files << action={} req={} status=ok elapsed={:?}",
                            action_clone, req_id_clone, elapsed
                        );
                        serde_json::json!({
                            "channel": "files",
                            "response_to": req_id_clone,
                            "status": "ok",
                            "data": data
                        })
                    }
                    Err(err) => {
                        warn!(
                            "encrypted files << action={} req={} status=error elapsed={:?} error={}",
                            action_clone, req_id_clone, elapsed, err
                        );
                        serde_json::json!({
                            "channel": "files",
                            "response_to": req_id_clone,
                            "status": "error",
                            "error": err.to_string(),
                            "error_code": "operation_failed"
                        })
                    }
                };
                let _ = result_tx.send(response_json);
            });

            // Wait for the spawned task, then encrypt the result
            let response_json = match result_rx.await {
                Ok(v) => v,
                Err(_) => {
                    warn!("encrypted files: file op task dropped for req={}", request_id);
                    return Ok(());
                }
            };
            let response_plaintext = serde_json::to_vec(&response_json).unwrap_or_default();

            // Enforce 200 KB limit for signaling responses
            const MAX_SIGNALING_RESPONSE_BYTES: usize = 200 * 1024;
            let plaintext_to_encrypt = if response_plaintext.len() > MAX_SIGNALING_RESPONSE_BYTES {
                warn!(
                    "encrypted files: response too large ({} bytes), rejecting",
                    response_plaintext.len()
                );
                serde_json::to_vec(&serde_json::json!({
                    "channel": "files",
                    "response_to": request_id,
                    "status": "error",
                    "error": "Response exceeds signaling size limit",
                    "error_code": "payload_too_large"
                }))
                .unwrap_or_default()
            } else {
                response_plaintext
            };

            match encrypt_and_build(cipher, &plaintext_to_encrypt, &session_id, &mobile_device_id) {
                Ok(envelope) => {
                    let _ = send_signal(ws, &envelope).await;
                }
                Err(e) => {
                    warn!("encrypted files: failed to encrypt response: {}", e);
                }
            }
        }
        "x25519_public_key" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "x25519_public_key rejected: device {} is not trusted",
                    mobile_device_id
                );
                return Ok(());
            }

            let session_id = match msg.payload.as_ref().and_then(|p| p.get("session_id")).and_then(|v| v.as_str()) {
                Some(sid) => sid.to_string(),
                None => {
                    warn!("x25519_public_key: missing session_id");
                    return Ok(());
                }
            };

            let mobile_pub_b64 = match msg.payload.as_ref().and_then(|p| p.get("public_key")).and_then(|v| v.as_str()) {
                Some(k) => k,
                None => {
                    warn!("x25519_public_key: missing public_key");
                    return Ok(());
                }
            };

            let mobile_pub = match signaling_crypto::parse_x25519_public_key(mobile_pub_b64) {
                Ok(k) => k,
                Err(e) => {
                    warn!("x25519_public_key: invalid public key: {}", e);
                    return Ok(());
                }
            };

            // Generate ephemeral keypair for this session
            let host_kp = EphemeralKeypair::generate();
            let host_pub_bytes = host_kp.public_key_bytes();
            let host_pub_b64 = host_kp.public_key_base64();

            // Generate random salt for HKDF
            let mut salt = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
            let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);

            // Compute shared secret and derive session key (consumes host private key)
            let mobile_pub_bytes = mobile_pub.to_bytes();
            let shared = host_kp.diffie_hellman(&mobile_pub);
            let session_key = match signaling_crypto::derive_session_key(
                shared.as_bytes(),
                &salt,
                &mobile_pub_bytes,
                &host_pub_bytes,
                &session_id,
            ) {
                Ok(k) => k,
                Err(e) => {
                    warn!("x25519 key derivation failed: {}", e);
                    return Ok(());
                }
            };

            // Store cipher for this session
            let cipher = SessionCipher::new_host(session_key);
            session_ciphers.insert(session_id.clone(), cipher);
            info!("E2E encryption established for session {}", session_id);

            // Send response with host's ephemeral public key and salt
            let host_id = store.host_id()?.to_string();
            let mut extra = std::collections::HashMap::new();
            extra.insert("host_id".to_string(), serde_json::json!(host_id));
            extra.insert(
                "target_mobile_device_id".to_string(),
                serde_json::json!(mobile_device_id),
            );
            let response = SignalEnvelope {
                message_type: "x25519_key_response".to_string(),
                session_id: None,
                payload: Some(serde_json::json!({
                    "session_id": session_id,
                    "public_key": host_pub_b64,
                    "salt": salt_b64,
                })),
                state: None,
                accepted: None,
                reason: None,
                extra,
            };
            let _ = send_signal(ws, &response).await;
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

/// Build a WebRTC auth protocol message with the \x00PSAU sentinel prefix.
fn build_auth_message(json: &serde_json::Value) -> Vec<u8> {
    let json_bytes = serde_json::to_vec(json).unwrap_or_default();
    let mut msg = Vec::with_capacity(AUTH_SENTINEL.len() + json_bytes.len());
    msg.extend_from_slice(AUTH_SENTINEL);
    msg.extend_from_slice(&json_bytes);
    msg
}

/// Verify an auth_response message from a mobile device.
///
/// The mobile signs `nonce_bytes || session_id_bytes || mobile_device_id_bytes`
/// with its Ed25519 private key. We verify using the stored public key.
fn verify_device_auth(
    msg: &serde_json::Value,
    channel_key: &str,
    mobile_device_id: &str,
    pending_auth: &mut HashMap<String, (String, String)>,
    store: &StateStore,
) -> std::result::Result<(), String> {
    use base64::engine::general_purpose::STANDARD;

    // Get the pending nonce
    let (nonce_b64, expected_device) = pending_auth
        .remove(channel_key)
        .ok_or_else(|| "no pending auth challenge".to_string())?;

    if mobile_device_id != expected_device {
        return Err(format!(
            "device mismatch: expected {expected_device}, got {mobile_device_id}"
        ));
    }

    // Get stored public key
    let pub_key_b64 = store
        .get_device_public_key(mobile_device_id)
        .ok_or_else(|| "no device public key stored".to_string())?;

    // Decode public key
    let pub_key_bytes = STANDARD
        .decode(pub_key_b64)
        .map_err(|e| format!("invalid public key base64: {e}"))?;
    let pub_key_bytes: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .map_err(|e| format!("invalid ed25519 public key: {e}"))?;

    // Decode signature
    let sig_b64 = msg
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing signature".to_string())?;
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("invalid signature base64: {e}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("invalid ed25519 signature: {e}"))?;

    // Reconstruct signed payload: nonce || session_id || mobile_device_id
    let nonce_bytes = STANDARD
        .decode(&nonce_b64)
        .map_err(|e| format!("invalid nonce base64: {e}"))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(channel_key.as_bytes());
    payload.extend_from_slice(mobile_device_id.as_bytes());

    // Verify
    verifying_key
        .verify(&payload, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))?;

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
