use crate::error::{HostError, Result};
use crate::models::SignalEnvelope;
use crate::webrtc_peer::WebRtcPeer;
use base64::Engine;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

/// In-progress file transfer from a mobile device.
pub(super) struct PendingFileTransfer {
    pub(super) request_id: String,
    pub(super) name: String,
    pub(super) expected_chunks: usize,
    pub(super) chunks: Vec<String>,
    pub(super) received_b64_bytes: usize,
    pub(super) created_at: Instant,
}

pub(super) struct PendingFilesChannelMessage {
    pub(super) expected_chunks: usize,
    pub(super) chunks: Vec<String>,
    pub(super) received_bytes: usize,
    pub(super) created_at: Instant,
}

pub(super) struct PendingFilesBinaryUpload {
    pub(super) final_path: PathBuf,
    pub(super) tmp_path: PathBuf,
    pub(super) file: File,
    pub(super) bytes_written: usize,
    pub(super) expected_size: Option<usize>,
    pub(super) created_at: Instant,
}

pub(super) struct OutboundHostTransfer {
    pub(super) peer: WebRtcPeer,
    pub(super) target_host_id: String,
    pub(super) target_host_public_key: String,
    pub(super) mobile_device_id: String,
    pub(super) offer_id: String,
    pub(super) created_at: Instant,
}

pub(super) struct InboundHostTransfer {
    pub(super) peer: WebRtcPeer,
    pub(super) source_host_id: String,
    pub(super) mobile_device_id: String,
    pub(super) offer_id: String,
    pub(super) created_at: Instant,
}

pub(super) enum DirectHostTransferEvent {
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
pub(super) const FILE_TRANSFER_TIMEOUT_SECS: u64 = 300;
pub(super) const FILES_MESSAGE_TIMEOUT_SECS: u64 = 300;
pub(super) const FILES_MESSAGE_CHUNK_SIZE: usize = 12 * 1024;
pub(super) const FILES_SIGNALING_RESPONSE_CHUNK_SIZE: usize = 12 * 1024;
pub(super) const FILES_STREAM_CHUNK_SIZE: usize = 48 * 1024;
pub(super) const MAX_FILES_FRAMED_CHUNKS: usize = 128;
pub(super) const MAX_FILES_FRAMED_MESSAGE_BYTES: usize = 512 * 1024;
pub(super) const MAX_FILE_TRANSFER_CHUNKS: usize = 4096;
pub(super) const MAX_FILE_TRANSFER_B64_BYTES: usize = 140 * 1024 * 1024;
pub(super) const MAX_STREAM_UPLOAD_BYTES: usize = 100 * 1024 * 1024;
pub(super) const MAX_STREAM_UPLOAD_CHUNK_BYTES: usize = 1024 * 1024;
pub(super) const MAX_ACTIVE_UPLOADS_PER_DEVICE: usize = 3;

/// Per-send timeout for streaming downloads to detect dead channels.
pub(super) const DOWNLOAD_SEND_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const WEBRTC_POLL_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const DIRECT_TRANSFER_BUFFER_HIGH_WATER: usize = 256 * 1024;
pub(super) const DIRECT_TRANSFER_BUFFER_POLL: Duration = Duration::from_millis(10);

pub(super) struct DecodedFilesStreamFrame {
    pub(super) header: serde_json::Value,
    pub(super) payload: Vec<u8>,
}

pub(super) enum FileTransferUpdate {
    Progress { request_id: String, progress: u8 },
    Complete { request_id: String, path: String },
    Error { request_id: String, message: String },
}

pub(super) fn decode_framed_files_message(
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
    if data.len() > MAX_FILES_FRAMED_MESSAGE_BYTES {
        warn!(
            "files framed message rejected: frame too large from mobile={} bytes={}",
            mobile_device_id,
            data.len()
        );
        return None;
    }
    let key = format!("{mobile_device_id}:{id}");

    match op {
        "start" => {
            let chunks = val.get("chunks").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            if chunks == 0 || chunks > MAX_FILES_FRAMED_CHUNKS {
                warn!(
                    "files framed message rejected: invalid chunk count mobile={} id={} chunks={}",
                    mobile_device_id, id, chunks
                );
                return None;
            }
            messages.insert(
                key,
                PendingFilesChannelMessage {
                    expected_chunks: chunks,
                    chunks: vec![String::new(); chunks],
                    received_bytes: 0,
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
                    let previous = message.chunks[index].len();
                    let next_total = message
                        .received_bytes
                        .saturating_sub(previous)
                        .saturating_add(data.len());
                    if next_total > MAX_FILES_FRAMED_MESSAGE_BYTES {
                        warn!(
                            "files framed message rejected: assembled payload too large mobile={} id={} bytes={}",
                            mobile_device_id, id, next_total
                        );
                        messages.remove(&key);
                        return None;
                    }
                    message.chunks[index] = data.to_string();
                    message.received_bytes = next_total;
                }
            }
            None
        }
        "end" => messages.remove(&key).map(|message| message.chunks.concat()),
        _ => None,
    }
}

pub(super) fn decode_files_stream_frame(data: &[u8]) -> Option<DecodedFilesStreamFrame> {
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

pub(super) fn encode_files_stream_frame(header: &serde_json::Value, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + 256 + payload.len());
    out.extend_from_slice(b"\x00PSFB");
    out.extend_from_slice(serde_json::to_string(header).unwrap_or_default().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}

pub(super) fn upload_tmp_path(final_path: &PathBuf) -> PathBuf {
    let parent = final_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    let file_name = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload");
    let nonce = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    parent.join(format!(
        ".{}.{}.{}.pstmp",
        file_name,
        std::process::id(),
        nonce
    ))
}

pub(super) async fn send_files_stream_frame(
    channel: std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    header: &serde_json::Value,
    payload: &[u8],
) -> Result<()> {
    let bytes = bytes::Bytes::from(encode_files_stream_frame(header, payload));
    send_files_channel_bytes(&channel, bytes, "files stream send").await?;
    Ok(())
}

pub(super) async fn send_files_channel_bytes(
    channel: &std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    bytes: bytes::Bytes,
    label: &str,
) -> Result<()> {
    match tokio::time::timeout(DOWNLOAD_SEND_TIMEOUT, channel.send(&bytes)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(HostError::Backend(format!("{label} failed: {e}"))),
        Err(_) => Err(HostError::Backend(format!(
            "{label} timed out after {:?}",
            DOWNLOAD_SEND_TIMEOUT
        ))),
    }
}

pub(super) fn spawn_files_reply(
    channel: &std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    response: serde_json::Value,
) {
    let ch = std::sync::Arc::clone(channel);
    tokio::spawn(async move {
        let _ = send_framed_files_response(ch, &response).await;
    });
}

pub(super) async fn send_framed_files_response(
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
    send_files_channel_bytes(&channel, start_bytes, "files response start send").await?;

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
        send_files_channel_bytes(&channel, chunk_bytes, "files response chunk send").await?;
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
    send_files_channel_bytes(&channel, end_bytes, "files response end send").await?;
    info!(
        "files WebRTC frame send end response_to={} chunks={}",
        response_to, total_chunks
    );

    Ok(())
}

pub(super) fn split_str_for_signaling(input: &str, max_bytes: usize) -> Vec<&str> {
    if input.is_empty() {
        return vec![""];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut last_boundary = 0;
    for (idx, _) in input.char_indices() {
        if idx == start {
            last_boundary = idx;
            continue;
        }
        if idx - start > max_bytes {
            let end = if last_boundary > start {
                last_boundary
            } else {
                idx
            };
            chunks.push(&input[start..end]);
            start = end;
        }
        last_boundary = idx;
    }
    while start < input.len() {
        let end = std::cmp::min(input.len(), start + max_bytes);
        let mut safe_end = end;
        while safe_end > start && !input.is_char_boundary(safe_end) {
            safe_end -= 1;
        }
        if safe_end == start {
            safe_end = input.len();
        }
        chunks.push(&input[start..safe_end]);
        start = safe_end;
    }
    chunks
}

pub(super) fn build_files_signaling_frame_response(
    session_id: Option<String>,
    mobile_device_id: Option<&str>,
    response_to: &str,
    frame: serde_json::Value,
) -> SignalEnvelope {
    let mut extra = std::collections::HashMap::new();
    if let Some(target) = mobile_device_id {
        extra.insert(
            "target_mobile_device_id".to_string(),
            serde_json::json!(target),
        );
    }
    SignalEnvelope {
        message_type: "signal".to_string(),
        session_id,
        payload: Some(serde_json::json!({
            "channel": "files",
            "response_to": response_to,
            "frame": frame,
        })),
        state: None,
        accepted: None,
        reason: None,
        extra,
    }
}

pub(super) fn build_files_signaling_response_envelopes(
    session_id: Option<String>,
    mobile_device_id: Option<&str>,
    response: serde_json::Value,
) -> Vec<SignalEnvelope> {
    let response_to = response
        .get("response_to")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let Ok(json) = serde_json::to_string(&response) else {
        return vec![build_files_signaling_frame_response(
            session_id,
            mobile_device_id,
            &response_to,
            serde_json::json!({"op": "end", "id": "encode_failed"}),
        )];
    };
    if json.len() <= FILES_SIGNALING_RESPONSE_CHUNK_SIZE {
        let mut extra = std::collections::HashMap::new();
        if let Some(target) = mobile_device_id {
            extra.insert(
                "target_mobile_device_id".to_string(),
                serde_json::json!(target),
            );
        }
        return vec![SignalEnvelope {
            message_type: "signal".to_string(),
            session_id,
            payload: Some(response),
            state: None,
            accepted: None,
            reason: None,
            extra,
        }];
    }

    let message_id = format!(
        "fs_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let chunks = split_str_for_signaling(&json, FILES_SIGNALING_RESPONSE_CHUNK_SIZE);
    let total_chunks = chunks.len();
    let mut envelopes = Vec::with_capacity(total_chunks + 2);
    envelopes.push(build_files_signaling_frame_response(
        session_id.clone(),
        mobile_device_id,
        &response_to,
        serde_json::json!({
            "op": "start",
            "id": message_id,
            "chunks": total_chunks,
        }),
    ));
    for (index, chunk) in chunks.iter().enumerate() {
        envelopes.push(build_files_signaling_frame_response(
            session_id.clone(),
            mobile_device_id,
            &response_to,
            serde_json::json!({
                "op": "chunk",
                "id": message_id,
                "i": index,
                "d": chunk,
            }),
        ));
    }
    envelopes.push(build_files_signaling_frame_response(
        session_id,
        mobile_device_id,
        &response_to,
        serde_json::json!({
            "op": "end",
            "id": message_id,
        }),
    ));
    info!(
        "files signaling frame response response_to={} bytes={} chunks={}",
        response_to,
        json.len(),
        total_chunks
    );
    envelopes
}

pub(super) async fn send_direct_transfer_result(
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

pub(super) fn bind_inbound_host_transfer_channel(
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
                        let expected_size = frame
                            .header
                            .get("size")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as usize);
                        if expected_size.is_none_or(|size| size > MAX_STREAM_UPLOAD_BYTES) {
                            send_direct_transfer_result(
                                Arc::clone(&channel),
                                &transfer_id,
                                false,
                                0,
                                Some("upload size exceeds host limit".to_string()),
                            )
                            .await;
                            let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound {
                                transfer_id: transfer_id.clone(),
                            });
                            return;
                        }
                        match crate::files::resolve_file_path_for_transfer(path) {
                            Ok(file_path) => {
                                if let Some(parent) = file_path.parent() {
                                    std::fs::create_dir_all(parent).ok();
                                }
                                let tmp_path = upload_tmp_path(&file_path);
                                match OpenOptions::new()
                                    .create_new(true)
                                    .write(true)
                                    .open(&tmp_path)
                                {
                                    Ok(file) => {
                                        *upload_state.lock().await =
                                            Some(PendingFilesBinaryUpload {
                                                final_path: file_path,
                                                tmp_path,
                                                file,
                                                bytes_written: 0,
                                                expected_size,
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
                                        let _ = event_tx.send(
                                            DirectHostTransferEvent::CleanupInbound {
                                                transfer_id: transfer_id.clone(),
                                            },
                                        );
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
                        if frame.payload.len() > MAX_STREAM_UPLOAD_CHUNK_BYTES {
                            send_direct_transfer_result(
                                Arc::clone(&channel),
                                &transfer_id,
                                false,
                                0,
                                Some("upload chunk exceeds host limit".to_string()),
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
                            return;
                        }
                        let mut guard = upload_state.lock().await;
                        if let Some(upload) = guard.as_mut() {
                            let next_size =
                                upload.bytes_written.saturating_add(frame.payload.len());
                            if next_size > MAX_STREAM_UPLOAD_BYTES
                                || upload.expected_size.is_some_and(|size| next_size > size)
                            {
                                drop(guard);
                                send_direct_transfer_result(
                                    Arc::clone(&channel),
                                    &transfer_id,
                                    false,
                                    0,
                                    Some("upload exceeds declared or host size limit".to_string()),
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
                                return;
                            }
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
                                        let _ = event_tx.send(
                                            DirectHostTransferEvent::CleanupInbound {
                                                transfer_id: transfer_id.clone(),
                                            },
                                        );
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
            let _ = event_tx.send(DirectHostTransferEvent::CleanupInbound { transfer_id });
        })
    }));
}

pub(super) fn bind_outbound_host_transfer_channel(
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
                let status = val
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
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
                let _ = event_tx.send(DirectHostTransferEvent::CleanupOutbound { transfer_id });
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

            let timeout_ms = std::cmp::max(
                120_000_u64,
                120_000_u64 + ((total_size / (1024 * 1024)) * 1_000),
            );

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
pub(super) fn handle_file_transfer_msg(
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
            if id.is_empty() {
                return Some(FileTransferUpdate::Error {
                    request_id: id,
                    message: "missing_transfer_id".to_string(),
                });
            }
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("clipboard.jpg")
                .to_string();
            let chunks = val.get("chunks").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            if chunks == 0 || chunks > MAX_FILE_TRANSFER_CHUNKS {
                return Some(FileTransferUpdate::Error {
                    request_id: id,
                    message: "too_many_chunks".to_string(),
                });
            }
            transfers.insert(
                id.clone(),
                PendingFileTransfer {
                    request_id: id.clone(),
                    name,
                    expected_chunks: chunks,
                    chunks: Vec::with_capacity(chunks),
                    received_b64_bytes: 0,
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
                let next_len = transfer.received_b64_bytes.saturating_add(data.len());
                if transfer.chunks.len() >= transfer.expected_chunks
                    || next_len > MAX_FILE_TRANSFER_B64_BYTES
                {
                    transfers.remove(&id);
                    return Some(FileTransferUpdate::Error {
                        request_id: id,
                        message: "transfer_too_large".to_string(),
                    });
                }
                transfer.chunks.push(data.to_string());
                transfer.received_b64_bytes = next_len;
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
                        let temp_path = std::env::temp_dir().join(temp_name);

                        match std::fs::write(&temp_path, &image_bytes) {
                            Ok(_) => {
                                let temp_path_string = temp_path.to_string_lossy().into_owned();
                                info!(
                                    "file transfer complete: {} ({} bytes) -> {}",
                                    transfer.name,
                                    image_bytes.len(),
                                    temp_path.display(),
                                );
                                // Terminal sessions have a PTY — inject the path
                                // as stdin so it appears on the command line.
                                // Agent sessions (purpose="agent") have no PTY;
                                // the mobile inlines the path into the user
                                // message instead.
                                if sessions.is_active(session_id) {
                                    let path_bytes = temp_path_string.as_bytes().to_vec();
                                    if let Err(e) = sessions.write_input(session_id, path_bytes) {
                                        warn!("failed to inject file path into PTY: {}", e,);
                                        return Some(FileTransferUpdate::Error {
                                            request_id: transfer.request_id,
                                            message: format!("pty_inject_failed: {e}"),
                                        });
                                    }
                                }
                                Some(FileTransferUpdate::Complete {
                                    request_id: transfer.request_id,
                                    path: temp_path_string,
                                })
                            }
                            Err(e) => {
                                warn!("failed to write temp file {}: {}", temp_path.display(), e);
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
        "cancel" => {
            transfers.remove(&id);
            Some(FileTransferUpdate::Error {
                request_id: id,
                message: "transfer_cancelled".to_string(),
            })
        }
        _ => {
            warn!("unknown file transfer op: {}", op);
            None
        }
    }
}
