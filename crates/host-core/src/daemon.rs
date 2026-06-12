use crate::agent_session::{
    self, AgentExitWire, AgentRouter, AgentSession, Backend as AgentBackend,
    SpawnConfig as AgentSpawnConfig,
};
use crate::api::BackendClient;
use crate::audit::{write_audit_event_with_store, AuditEvent};
use crate::auth::{refresh_token_jwt_expired, safe_refresh_if_needed};
use crate::config::AppConfig;
use crate::discovery::SessionDiscovery;
use crate::error::{HostError, Result};
use crate::local_attach;
use crate::models::StatsSnapshot;
use crate::models::{
    AttachTarget, HostTransferAttestation, SessionRecord, SessionRequest, SessionState,
    SignalEnvelope,
};
use crate::pty::{SessionAttentionEvent, SessionManager};
use crate::session::accept_session;
use crate::signaling_crypto::{self, EphemeralKeypair, SessionCipher};
use crate::stats::StatsCollector;
use crate::store::StateStore;
use crate::terminal_marks::AttentionKind;
use crate::transport::{connect_host_ws, recv_signal, send_signal, WsRead};
use crate::webrtc_manager::{WebRtcEvent, WebRtcManager};
use crate::webrtc_peer::WebRtcPeer;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::SinkExt;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{debug, error, info, trace, warn};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

/// Safety margin subtracted from the TURN cred TTL so we re-fetch slightly
/// before they actually expire and never hand the WebRTC stack creds that
/// die mid-handshake.
const TURN_CACHE_SAFETY_MARGIN_SECS: u64 = 30;
/// Floor for cached TTL so a backend that returns 0 doesn't put us back
/// into a fetch-on-every-offer loop. Cloudflare typically returns 1h+.
const TURN_CACHE_MIN_TTL_SECS: u64 = 60;
const WS_SIGNING_PREFIX: &str = "pocketshell-ws-v1";
const WS_AUTH_MAX_SKEW_SECS: i64 = 60;
const WS_AUTH_NONCE_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct CachedTurnCreds {
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
struct TurnCredsCache {
    inner: tokio::sync::Mutex<Option<CachedTurnCreds>>,
}

impl TurnCredsCache {
    fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(None),
        }
    }

    async fn get(
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

/// Build a signaling payload JSON value for an outbound SDP, attaching an
/// ED25519 signature binding the SDP to the host's identity key so the mobile
/// client can detect a MITM rewriting the DTLS fingerprint.
///
/// `sdp_type` MUST be `"offer"` or `"answer"`. `extra` is merged into the
/// resulting JSON object (e.g. to carry `transfer_id`, `offer_id`, etc.).
///
/// Jitter a duration by ±25% so retry/backoff sleeps don't synchronise across
/// the fleet. Critical for reconnect storms — without this, 2K hosts hit the
/// backend at the same instant after every hiccup.
fn jittered(base: Duration) -> Duration {
    use rand::Rng;
    let base_ms = base.as_millis() as i64;
    if base_ms == 0 {
        return base;
    }
    let spread = (base_ms / 4).max(1);
    let delta = rand::thread_rng().gen_range(-spread..=spread);
    let final_ms = (base_ms + delta).max(0) as u64;
    Duration::from_millis(final_ms)
}

/// Build a `FileActionContext` populated with the current host identity so
/// file.* audit events carry host_id and user_id (AU-3 attribution) in
/// addition to the requesting mobile_device_id.
fn build_file_action_context(
    store: &StateStore,
    mobile_device_id: &str,
) -> crate::files::FileActionContext {
    let host = store.state.host.as_ref();
    crate::files::FileActionContext {
        mobile_device_id: mobile_device_id.to_string(),
        host_id: host.map(|h| h.host_id.clone()).unwrap_or_default(),
        user_id: host.map(|h| h.user_id.clone()).unwrap_or_default(),
    }
}

/// Classify a `verify_ws_message_auth` error string into a precise event type.
/// verify_ws_message_auth returns a fixed set of strings; matching by exact
/// prefix (not substring) avoids labelling structural errors like
/// "missing payload_hash" or "missing signature" as cryptographic failures.
fn classify_ws_auth_failure(reason: &str) -> &'static str {
    // Cryptographic failures: signature verification, hash mismatch, replay.
    if reason == "replayed nonce" {
        return "crypto.replay_detected";
    }
    if reason == "payload hash mismatch"
        || reason.starts_with("ed25519 signature did not verify")
        || reason.starts_with("invalid ed25519 signature")
        || reason.starts_with("invalid signature base64")
        || reason.starts_with("invalid ed25519 public key")
        || reason.starts_with("invalid public key base64")
        || reason == "public key must be 32 bytes"
    {
        return "crypto.signature_failed";
    }
    // Trust/policy and structural failures (missing fields, version mismatch,
    // host_id mismatch, no pinned key, timestamp skew) — all authz failures
    // from the perspective of the protocol: the request did not authenticate.
    "authz.denied"
}

/// Emit a channel.authenticated / channel.auth_failed / authz.denied audit
/// event for a WebRTC data-channel auth handshake (terminal session, control,
/// stats, files, agent).
///
/// The combined "verify_device_auth → device_permission_result" check can fail
/// for two distinct reasons that callers must NOT conflate: cryptographic
/// signature failure (real attack signal) and post-auth permission denial
/// (routine policy). This helper inspects the error string and emits:
///   - `channel.authenticated` on success
///   - `authz.denied` (operation=channel_kind, reason=permission_denied:*)
///     when the crypto check passed but the permission check failed
///   - `channel.auth_failed` for cryptographic / structural failures
///
/// `channel_target` is the channel-specific id (session_id for terminal,
/// agent_id for agent, None for control/stats/files).
fn audit_channel_auth(
    store: &StateStore,
    channel_kind: &str,
    mobile_device_id: &str,
    channel_target: Option<String>,
    result: std::result::Result<(), String>,
) {
    let session_id = if channel_kind == "terminal" {
        channel_target.clone()
    } else {
        None
    };
    match result {
        Ok(()) => {
            let _ = write_audit_event_with_store(
                AuditEvent {
                    mobile_device_id: Some(mobile_device_id.to_string()),
                    session_id,
                    target: channel_target,
                    details: Some(serde_json::json!({ "channel": channel_kind })),
                    ..AuditEvent::new("channel.authenticated")
                },
                store,
            );
        }
        Err(reason) if reason.starts_with("permission_denied:") => {
            // Crypto auth succeeded; policy denied. Route to authz.denied so
            // SOC dashboards don't misread it as a cryptographic failure.
            let _ = write_audit_event_with_store(
                AuditEvent {
                    mobile_device_id: Some(mobile_device_id.to_string()),
                    session_id,
                    target: channel_target,
                    details: Some(serde_json::json!({ "channel": channel_kind })),
                    ..AuditEvent::new("authz.denied").denied(reason)
                },
                store,
            );
        }
        Err(reason) => {
            let _ = write_audit_event_with_store(
                AuditEvent {
                    mobile_device_id: Some(mobile_device_id.to_string()),
                    session_id,
                    target: channel_target,
                    details: Some(serde_json::json!({ "channel": channel_kind })),
                    ..AuditEvent::new("channel.auth_failed").denied(reason)
                },
                store,
            );
        }
    }
}

/// Sentinel `mobile_device_id` for audit records where the requesting device
/// did not supply one (or supplied an empty string). Writing a literal value
/// instead of omitting the field lets SIEMs correlate anonymous probes —
/// `SELECT count(*) FROM audit GROUP BY mobile_device_id` will surface a
/// spike of `"(anonymous)"` entries when an attacker is enumerating without
/// presenting a device id.
const AUDIT_ANONYMOUS_DEVICE: &str = "(anonymous)";

/// Emit an `authz.denied` audit event. Use at every rejection path where a
/// mobile device was refused — untrusted, no permission, bad signature, etc.
/// `operation` is what the device was trying to do (the message_type, action,
/// or channel kind); `reason` is a short machine-readable cause.
fn audit_authz_denied(
    store: &StateStore,
    mobile_device_id: &str,
    operation: &str,
    reason: &str,
    session_id: Option<String>,
) {
    let mdi = if mobile_device_id.is_empty() {
        AUDIT_ANONYMOUS_DEVICE.to_string()
    } else {
        mobile_device_id.to_string()
    };
    let _ = write_audit_event_with_store(
        AuditEvent {
            mobile_device_id: Some(mdi),
            session_id,
            target: Some(operation.to_string()),
            ..AuditEvent::new("authz.denied").denied(reason)
        },
        store,
    );
}

/// Resolve `kill` to an absolute path so a poisoned PATH (e.g. attacker code
/// in `~/.local/bin/kill`) can't be invoked under the daemon's UID.
fn resolve_kill_binary() -> PathBuf {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &["/bin/kill"]
    } else if cfg!(target_os = "linux") {
        &["/bin/kill", "/usr/bin/kill"]
    } else {
        &[]
    };
    crate::stats::resolve_system_binary("kill", candidates)
}

/// Reject kill_process targets the daemon clearly does not own. Pragmatic
/// containment, not strict authorization:
///
/// * accept pids in the daemon's own process group (helpers spawned without
///   `setsid`),
/// * otherwise accept pids that share the daemon's effective UID — PTY
///   children get their own pgrp via `forkpty(3)` but stay under the same
///   UID, and the daemon already cannot signal another user's processes.
///
/// Anything from another user (root, a different login) is refused.
fn pid_is_in_daemon_pgrp(pid: i32) -> bool {
    #[cfg(unix)]
    {
        use nix::libc;
        // SAFETY: getpgrp / getpgid have no preconditions.
        let our_pgrp = unsafe { libc::getpgrp() };
        let target_pgrp = unsafe { libc::getpgid(pid) };
        if target_pgrp < 0 {
            // ESRCH or EPERM — treat as not-ours.
            return false;
        }
        if target_pgrp == our_pgrp {
            return true;
        }
        // Same-UID fallback: cover PTY children that called setsid.
        #[cfg(target_os = "linux")]
        {
            let our_euid = unsafe { libc::geteuid() };
            if let Ok(s) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                for line in s.lines() {
                    if let Some(rest) = line.strip_prefix("Uid:") {
                        if let Some(uid_str) = rest.split_whitespace().next() {
                            if let Ok(uid) = uid_str.parse::<u32>() {
                                return uid == our_euid;
                            }
                        }
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            // macOS: no procfs. kill(2) with signal 0 returns EPERM if the
            // target is owned by a different UID, and 0 if the daemon would
            // be allowed to signal it. That's a reasonable proxy for "same
            // UID" without pulling in libproc.
            let rc = unsafe { libc::kill(pid, 0) };
            rc == 0
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

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
    obj.insert(
        "sdp".to_string(),
        serde_json::Value::String(sdp.to_string()),
    );
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

fn verify_signed_sdp_payload(
    payload: &serde_json::Value,
    sdp: &str,
    sdp_type: &str,
    public_key_b64: &str,
) -> Result<()> {
    let protocol_err = |msg: &str| HostError::Backend(msg.to_string());
    let sig_b64 = payload
        .get("sdp_sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| protocol_err("signed SDP is missing signature"))?;
    let nonce_b64 = payload
        .get("sdp_sig_nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| protocol_err("signed SDP is missing nonce"))?;
    let ts = payload
        .get("sdp_sig_ts")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| protocol_err("signed SDP is missing timestamp"))?;

    let now = Utc::now().timestamp();
    if (now - ts).abs() > WS_AUTH_MAX_SKEW_SECS {
        return Err(protocol_err("signed SDP timestamp outside allowed skew"));
    }

    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|_| protocol_err("signed SDP public key is invalid base64"))?;
    let verify_key = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| protocol_err("signed SDP public key must be 32 bytes"))?,
    )
    .map_err(|_| protocol_err("signed SDP public key is invalid"))?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| protocol_err("signed SDP signature is invalid base64"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| protocol_err("signed SDP signature must be 64 bytes"))?;
    let signed = format!(
        "{}|{}|{}|{}|{}",
        signaling_crypto::SDP_SIGNING_PREFIX,
        sdp_type,
        nonce_b64,
        ts,
        sdp
    );
    verify_key
        .verify(signed.as_bytes(), &sig)
        .map_err(|_| protocol_err("signed SDP signature verification failed"))
}

fn extract_and_verify_mobile_attestation(
    store: &StateStore,
    mobile_device_id: &str,
    value: Option<&serde_json::Value>,
) -> Result<HostTransferAttestation> {
    let protocol_err = |msg: &str| HostError::Backend(msg.to_string());
    if mobile_device_id.is_empty() {
        return Err(protocol_err(
            "host transfer attestation missing mobile device id",
        ));
    }
    let value = value.ok_or_else(|| protocol_err("missing mobile transfer attestation"))?;
    let attestation: HostTransferAttestation = serde_json::from_value(value.clone())
        .map_err(|e| protocol_err(&format!("invalid mobile transfer attestation: {e}")))?;
    if attestation.mobile_device_id != mobile_device_id {
        return Err(protocol_err(
            "host transfer attestation mobile device id mismatch",
        ));
    }
    let mobile_public_key = store
        .get_device_public_key(mobile_device_id)
        .ok_or_else(|| protocol_err("no mobile public key stored for transfer attestation"))?;
    signaling_crypto::verify_host_transfer_attestation(&attestation, mobile_public_key)
        .map_err(|e| protocol_err(&format!("invalid mobile transfer attestation: {e}")))?;
    Ok(attestation)
}

fn local_host_matches_attestation(
    store: &StateStore,
    host_id: &str,
    host_public_key: &str,
) -> bool {
    store
        .state
        .host
        .as_ref()
        .is_some_and(|host| host.host_id == host_id && host.public_key == host_public_key)
}

/// In-progress file transfer from a mobile device.
struct PendingFileTransfer {
    request_id: String,
    name: String,
    expected_chunks: usize,
    chunks: Vec<String>,
    received_b64_bytes: usize,
    created_at: Instant,
}

struct PendingFilesChannelMessage {
    expected_chunks: usize,
    chunks: Vec<String>,
    received_bytes: usize,
    created_at: Instant,
}

struct PendingFilesBinaryUpload {
    final_path: PathBuf,
    tmp_path: PathBuf,
    file: File,
    bytes_written: usize,
    expected_size: Option<usize>,
    created_at: Instant,
}

struct OutboundHostTransfer {
    peer: WebRtcPeer,
    target_host_id: String,
    target_host_public_key: String,
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
const MAX_FILES_FRAMED_CHUNKS: usize = 128;
const MAX_FILES_FRAMED_MESSAGE_BYTES: usize = 512 * 1024;
const MAX_FILE_TRANSFER_CHUNKS: usize = 4096;
const MAX_FILE_TRANSFER_B64_BYTES: usize = 140 * 1024 * 1024;
const MAX_STREAM_UPLOAD_BYTES: usize = 100 * 1024 * 1024;
const MAX_STREAM_UPLOAD_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_ACTIVE_UPLOADS_PER_DEVICE: usize = 3;

/// Sentinel prefix for challenge-response authentication messages on WebRTC channels.
const AUTH_SENTINEL: &[u8] = b"\x00PSAU";
/// Sentinel prefix for terminal keepalive / latency messages.
const TERMINAL_KEEPALIVE_SENTINEL: &[u8] = b"\x00PSKA";
/// Per-send timeout for streaming downloads to detect dead channels.
const DOWNLOAD_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const WEBRTC_POLL_TIMEOUT: Duration = Duration::from_secs(5);
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
    Attach { client_id: u64, session_id: String },
    /// Terminal input from a local client.
    Input { session_id: String, data: Vec<u8> },
    /// Resize from a local client.
    Resize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    /// Client disconnected.
    Disconnected { client_id: u64 },
}

// Local-attach IPC transport. On Unix this is a Unix-domain socket; on other
// platforms (Windows) the local CLI-attach feature is not wired up yet, so the
// listener is always `None` and never accepts. The half types below only need
// to satisfy the `AsyncRead`/`AsyncWrite` bounds used by the shared daemon
// loop — on non-Unix they alias throwaway in-memory pipe halves that are never
// constructed. Mobile sessions over WebRTC are unaffected on every platform.
#[cfg(unix)]
type LocalReadHalf = tokio::net::unix::OwnedReadHalf;
#[cfg(unix)]
type LocalWriteHalf = tokio::net::unix::OwnedWriteHalf;
#[cfg(unix)]
type LocalAttachListener = tokio::net::UnixListener;

#[cfg(not(unix))]
type LocalReadHalf = tokio::io::ReadHalf<tokio::io::DuplexStream>;
#[cfg(not(unix))]
type LocalWriteHalf = tokio::io::WriteHalf<tokio::io::DuplexStream>;
#[cfg(not(unix))]
type LocalAttachListener = DisabledLocalListener;

/// Stand-in listener for platforms where local attach is not available.
#[cfg(not(unix))]
struct DisabledLocalListener;

/// Wait for the next local-attach client and return its split halves. On
/// platforms without a listener the returned future never resolves, so the
/// owning `select!` arm simply stays parked.
#[cfg(unix)]
async fn local_accept(
    listener: Option<&LocalAttachListener>,
) -> Option<(LocalReadHalf, LocalWriteHalf)> {
    match listener {
        Some(l) => match l.accept().await {
            Ok((stream, _addr)) => Some(stream.into_split()),
            Err(e) => {
                warn!("local attach accept failed: {e}");
                None
            }
        },
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn local_accept(
    _listener: Option<&LocalAttachListener>,
) -> Option<(LocalReadHalf, LocalWriteHalf)> {
    std::future::pending().await
}

/// Tracks write halves of locally attached clients, keyed by session_id.
struct LocalAttachClients {
    clients: HashMap<u64, (String, LocalWriteHalf)>,
}

impl LocalAttachClients {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    fn add(&mut self, client_id: u64, session_id: String, writer: LocalWriteHalf) {
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
        let frame = local_attach::encode_frame(local_attach::FRAME_ERROR, b"session ended");
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

fn upload_tmp_path(final_path: &PathBuf) -> PathBuf {
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

async fn send_files_stream_frame(
    channel: std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    header: &serde_json::Value,
    payload: &[u8],
) -> Result<()> {
    let bytes = bytes::Bytes::from(encode_files_stream_frame(header, payload));
    send_files_channel_bytes(&channel, bytes, "files stream send").await?;
    Ok(())
}

async fn send_files_channel_bytes(
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

/// Serialize an RPC response and send it on the control channel, logging
/// either failure mode. Shared between the inline (stateful) and spawned
/// (stateless) dispatch paths.
async fn send_control_rpc_response(
    channel: std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    resp: &crate::rpc::RpcResponse,
    method: &str,
    req_id: &str,
) {
    match serde_json::to_vec(resp) {
        Ok(bytes) => {
            if let Err(err) = channel.send(&bytes::Bytes::from(bytes)).await {
                warn!(
                    "control RPC response send failed for method={} id={}: {}",
                    method, req_id, err
                );
            }
        }
        Err(err) => warn!("control RPC response encode failed: {}", err),
    }
}

fn spawn_files_reply(
    channel: &std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    response: serde_json::Value,
) {
    let ch = std::sync::Arc::clone(channel);
    tokio::spawn(async move {
        let _ = send_framed_files_response(ch, &response).await;
    });
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
                        let temp_path = format!("/tmp/{}", temp_name);

                        match std::fs::write(&temp_path, &image_bytes) {
                            Ok(_) => {
                                info!(
                                    "file transfer complete: {} ({} bytes) -> {}",
                                    transfer.name,
                                    image_bytes.len(),
                                    temp_path,
                                );
                                // Terminal sessions have a PTY — inject the path
                                // as stdin so it appears on the command line.
                                // Agent sessions (purpose="agent") have no PTY;
                                // the mobile inlines the path into the user
                                // message instead.
                                if sessions.is_active(session_id) {
                                    let path_bytes = temp_path.as_bytes().to_vec();
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

/// Refuse to start the daemon if it's running with root privileges.
///
/// Rationale: the daemon's file channel grants any approved mobile peer
/// read/write access to the host's filesystem, scoped by a home-relative +
/// system-path denylist (see `files.rs`). Both layers assume the daemon
/// runs as the human user, so root effectively bypasses the user-scope
/// model — a single device approval becomes "approved to read /etc/shadow
/// and write /root/.ssh/authorized_keys".
///
/// Escape hatch: setting `POCKETSHELL_ALLOW_ROOT=1` skips the check for
/// the rare legitimate case (e.g. a kiosk box that has no non-root user).
/// We log a warning so it shows up in audit reviews.
#[cfg(unix)]
fn refuse_if_root() -> Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        if std::env::var("POCKETSHELL_ALLOW_ROOT").as_deref() == Ok("1") {
            warn!(
                "daemon is running as root because POCKETSHELL_ALLOW_ROOT=1 is set; \
                 file-channel callers can reach the entire filesystem subject only to \
                 the static denylist — strongly prefer running as a non-root user"
            );
            return Ok(());
        }
        return Err(HostError::Backend(
            "refusing to run as root: the file channel relies on user-scope to bound \
             filesystem access. Re-run as your normal user (e.g. via `systemctl --user`), \
             or set POCKETSHELL_ALLOW_ROOT=1 if you have an explicit reason."
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_if_root() -> Result<()> {
    // Non-Unix targets don't have a euid concept the same way; the file
    // channel's risk profile is also different (Windows ACLs etc.). No-op.
    Ok(())
}

pub async fn run_foreground(config: AppConfig) -> Result<()> {
    refuse_if_root()?;

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

    // A fresh daemon process can never have an active peer connection, so any
    // session record left in state.json from a previous run is dead by
    // definition. They'd otherwise show up in the mobile "Persistent Sessions"
    // list forever (issue: ghost ATTACHED cards). Wipe them on startup.
    let stale = store.state.sessions.len();
    if stale > 0 {
        store.state.sessions.clear();
        if let Err(e) = store.save() {
            warn!("failed to persist session cleanup on startup: {e}");
        } else {
            info!("cleared {stale} stale session(s) from previous run");
        }
    }

    let host_id = store.host_id()?;
    let backend = BackendClient::new(config.backend_base_url.clone());
    let turn_cache = TurnCredsCache::new();

    let mut stats = StatsCollector::new();
    let mut stats_active = false;
    let mut stats_deadline: Option<Instant> = None;
    // host_summary is sent every `summary_interval_secs` for mobile home-screen
    // tiles. Default true for backward compat with backends that don't send the
    // subscribe/unsubscribe gate — once the backend ships the gate, it sends
    // `summary_unsubscribe` on connect when no mobile is viewing.
    let mut summary_active = true;
    info!("PocketShell native session persistence enabled");
    // One-time startup reap: kill any conhost.exe ConPTY backend orphaned by a
    // previous daemon instance's ungraceful death (they busy-spin at ~100% CPU
    // forever and nothing else ever reaps them). New sessions are covered by
    // the SessionManager's job object; this catches leftovers from runs that
    // predate the guard or slipped past a failed assignment. No-op off-Windows.
    let reaped = crate::job_object::sweep_orphaned_conpty_backends();
    if reaped > 0 {
        warn!("reaped {reaped} orphaned ConPTY conhost.exe process(es) from a previous daemon death");
    }
    let mut sessions = SessionManager::new(config.session_limit);
    let (webrtc_event_tx, mut webrtc_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<WebRtcEvent>();
    let mut webrtc_mgr = WebRtcManager::new(webrtc_event_tx);
    let shell = AppConfig::default_shell();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ControlPlaneDisconnect {
        Reconnect,
        TokenRotated,
    }

    let mut file_transfers: HashMap<String, PendingFileTransfer> = HashMap::new();
    let mut files_channel_messages: HashMap<String, PendingFilesChannelMessage> = HashMap::new();
    let mut files_binary_uploads: HashMap<String, PendingFilesBinaryUpload> = HashMap::new();
    let (files_response_tx, mut files_response_rx) =
        tokio::sync::mpsc::unbounded_channel::<SignalEnvelope>();
    let mut minute_stats_buffer: Vec<StatsSnapshot> = Vec::with_capacity(5);
    let mut peer_session_routes: HashMap<String, String> = HashMap::new();
    let mut files_peer_hosts: HashMap<String, String> = HashMap::new();
    let mut files_peer_offer_ids: HashMap<String, String> = HashMap::new();
    let mut agent_peer_hosts: HashMap<String, String> = HashMap::new();
    let mut agent_peer_offer_ids: HashMap<String, String> = HashMap::new();
    let (direct_transfer_event_tx, mut direct_transfer_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<DirectHostTransferEvent>();
    let mut outbound_host_transfers: HashMap<String, OutboundHostTransfer> = HashMap::new();
    let mut inbound_host_transfers: HashMap<String, InboundHostTransfer> = HashMap::new();
    // Per-session E2E encryption ciphers for signaling-based file operations
    let mut session_ciphers: HashMap<String, SessionCipher> = HashMap::new();
    // Replay cache for end-to-end signed mobile-over-WS control messages.
    let mut ws_auth_nonces: HashMap<String, Instant> = HashMap::new();
    // Cancellation signals for active download_stream tasks per mobile device
    let mut files_download_cancels: HashMap<String, tokio::sync::watch::Sender<bool>> =
        HashMap::new();
    // Active JSONL tailers, keyed by (mobile_device_id, subscription_id).
    let mut files_watchers: HashMap<(String, String), tokio::task::JoinHandle<()>> = HashMap::new();

    // Challenge-response auth state for WebRTC channels
    let mut authenticated_channels: HashSet<String> = HashSet::new();
    // Maps channel_key -> (nonce_base64, expected_mobile_device_id)
    let mut pending_auth: HashMap<String, (String, String)> = HashMap::new();

    // Agent chat sessions (Codex / Claude). Codex multiplexes threads on one
    // shared `app-server` (singleton inside the router); Claude spawns one
    // process per `agent_id`. The router hides the split behind `bind` /
    // `send_line` / `detach`.
    let agent_router = Arc::new(AgentRouter::new());
    // Pump tasks forwarding stdout to data channels. Keyed by agent_id so we
    // can abort on channel close.
    let mut agent_pumps: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    // WS-fallback (phase 2) parallel registry: when the mobile can't bring up
    // WebRTC, we drive the same AgentSession over the signaling WS. These
    // pumps forward stdout lines out as `agent_output` signals. Separate map
    // from `agent_pumps` so lifecycle of the two transports stays independent.
    let mut agent_ws_pumps: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    // Pumps push outbound WS frames here; the main select loop drains and
    // forwards them on `ws` (since `send_signal` needs &mut access to ws and
    // the pumps are running in detached tokio tasks).
    let (agent_ws_out_tx, mut agent_ws_out_rx) =
        tokio::sync::mpsc::unbounded_channel::<SignalEnvelope>();

    // Local attach via Unix socket
    let (local_event_tx, mut local_event_rx) =
        tokio::sync::mpsc::unbounded_channel::<LocalClientEvent>();
    let mut local_clients = LocalAttachClients::new();
    let mut local_pending_writers: HashMap<u64, LocalWriteHalf> = HashMap::new();
    let mut local_client_counter: u64 = 0;

    // Singleton flock on pid_file so a second `daemon run` fails fast
    // instead of racing on the local-attach socket.
    let _pid_lock = match acquire_daemon_pid_lock() {
        Ok(g) => g,
        Err(e) => {
            error!(
                "another daemon appears to be running for this user (pid lock unavailable): {}",
                e
            );
            return Err(e);
        }
    };

    let local_sock_path = local_attach::socket_path()
        .unwrap_or_else(|_| std::env::temp_dir().join("pocketshell-daemon.sock"));

    #[cfg(unix)]
    let local_listener: Option<LocalAttachListener> = {
        // Safe to drop the stale socket: pid_lock above ensures we're the sole
        // owner. Unix-only — on other platforms nothing is ever bound here, so
        // removing a file at this path would only risk clobbering an unrelated
        // one.
        let _ = std::fs::remove_file(&local_sock_path);
        match tokio::net::UnixListener::bind(&local_sock_path) {
            Ok(l) => {
                info!(
                    "local attach socket listening at {}",
                    local_sock_path.display()
                );
                // Make socket accessible only to current user
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &local_sock_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                Some(l)
            }
            Err(e) => {
                warn!(
                    "failed to bind local attach socket: {} — local attach will be unavailable",
                    e
                );
                None
            }
        }
    };
    // Local CLI attach over a Unix-domain socket isn't available on non-Unix
    // platforms yet; the daemon runs normally and mobile WebRTC sessions are
    // unaffected. `local_sock_path` is still referenced by the shared cleanup
    // paths below, but nothing is created or removed at it here.
    #[cfg(not(unix))]
    let local_listener: Option<LocalAttachListener> = {
        let _ = &local_sock_path;
        debug!("local attach socket disabled on this platform");
        None
    };

    // Clear any stale graceful-stop sentinel from a previous run so it can't
    // immediately shut down this freshly-started daemon (Windows stop channel;
    // see the shutdown future below).
    #[cfg(not(unix))]
    if let Ok(p) = AppConfig::paths() {
        let _ = std::fs::remove_file(p.state_dir.join("daemon.stop"));
    }

    info!("daemon starting for host_id={}", host_id);
    let _ = write_audit_event_with_store(AuditEvent::new("daemon_started"), &store);

    let mut backoff_secs = 1_u64;

    loop {
        match safe_refresh_if_needed(&backend, &mut store).await {
            Ok(()) => {}
            Err(HostError::AuthRevoked) => {
                // AuthRevoked here means BOTH paths in `safe_refresh_if_needed`
                // failed: the rotating refresh token AND the permanent
                // signing-key reauth via `/auth/host/reauth`. The latter
                // verifies against `hosts.public_key` in Postgres, so a 401
                // there means our identity itself is no longer trusted —
                // host record deleted, disabled, or pubkey rotated. Only at
                // that point is re-pair the right answer.
                //
                // We still distinguish "transient race" from "permanent" via
                // the local refresh-JWT exp check: if the JWT itself has not
                // expired, a previous refresh from a concurrent CLI may have
                // landed and the next tick reloads state.json to pick it up.
                let permanent = store
                    .state
                    .auth
                    .as_ref()
                    .map(refresh_token_jwt_expired)
                    .unwrap_or(false);
                if permanent {
                    warn!("auth fully rejected (refresh + signing-key) — re-pair via `pocketshell pair` (scan QR with mobile)");
                } else {
                    warn!(
                        "token refresh rejected and signing-key reauth failed — retrying in ~30s"
                    );
                }
                sleep(jittered(Duration::from_secs(30))).await;
                store = StateStore::load()?;
                continue;
            }
            Err(err) => {
                warn!("auth refresh failed: {} — retrying in ~30s", err);
                sleep(jittered(Duration::from_secs(30))).await;
                store = StateStore::load()?;
                continue;
            }
        }
        let token = store.access_token()?.to_string();
        let mut last_tick;
        // Wall-clock catches suspends where the monotonic clock paused
        // (CLOCK_MONOTONIC behavior varies by OS); either gap exceeding
        // the stall threshold triggers reconnect.
        let mut last_tick_wall;
        let mut ws = match connect_host_ws(&config.ws_url, &host_id, &token).await {
            Ok(socket) => {
                info!("control-plane connected");
                backoff_secs = 1;
                last_tick = Instant::now();
                last_tick_wall = SystemTime::now();
                socket
            }
            Err(err) => {
                warn!("control-plane connect error: {}", err);
                // Jittered exponential backoff so 2K hosts don't reconnect in
                // lockstep after a backend hiccup. Spreads load across the
                // recovery window instead of a thundering herd.
                sleep(jittered(Duration::from_secs(backoff_secs))).await;
                backoff_secs = (backoff_secs * 2).min(30);
                continue;
            }
        };

        let mut heartbeat_tick = interval(Duration::from_secs(config.heartbeat_interval_secs));
        let mut ws_ping_tick = interval(Duration::from_secs(30));
        // Watchdog state: detect dead WS sockets that don't surface as read
        // errors (e.g. half-closed CLOSE_WAIT after a backend hiccup). The
        // read-deadline used to live inside `recv_signal` as a 90s
        // `tokio::time::timeout`, but that was reset on every select! loss
        // (50ms output/webrtc ticks) and so could never fire. We track these
        // externally and check them on `ws_watchdog_tick`.
        let mut last_ws_message_at = Instant::now();
        let mut pending_ping_deadline: Option<Instant> = None;
        let mut ws_watchdog_tick = interval(Duration::from_secs(5));
        ws_watchdog_tick.tick().await; // skip immediate first tick
        const WS_READ_IDLE_LIMIT: Duration = Duration::from_secs(90);
        const WS_PONG_DEADLINE: Duration = Duration::from_secs(15);
        let mut stats_tick = interval(Duration::from_secs(config.stats_interval_secs));
        let mut summary_tick = interval(Duration::from_secs(config.summary_interval_secs));
        let mut stats_bg_tick = interval(Duration::from_secs(10 * 60));
        stats_bg_tick.tick().await; // skip immediate first tick
        let mut output_tick = interval(Duration::from_millis(50));
        let mut trusted_devices_tick =
            interval(Duration::from_secs(config.trusted_devices_interval_secs));
        let mut session_reap_tick = interval(Duration::from_secs(1));
        let mut stats_minute_tick = interval(Duration::from_secs(60));
        stats_minute_tick.tick().await; // skip immediate first tick
        let mut stats_minute_flush_tick = interval(Duration::from_secs(5 * 60));
        stats_minute_flush_tick.tick().await; // skip immediate first tick
        let mut alert_tick = interval(Duration::from_secs(config.alert_check_interval_secs));
        let mut alert_checker = crate::alerts::AlertChecker::new();
        let mut discovery_tick = interval(Duration::from_secs(15));
        let mut claude_idle_tick = interval(Duration::from_secs(30));
        let claude_idle_ttl = Duration::from_secs(10 * 60);
        let mut webrtc_poll_tick = interval(Duration::from_millis(50));
        let mut stats_stream_tick = interval(Duration::from_secs(2));
        let mut turn_usage_tick = interval(Duration::from_secs(60));
        turn_usage_tick.tick().await; // skip immediate first tick

        let mut shutdown = Box::pin(async {
            #[cfg(unix)]
            {
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(mut sigterm) => {
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => "SIGINT",
                            _ = sigterm.recv() => "SIGTERM",
                        }
                    }
                    Err(err) => {
                        warn!(
                            "failed to register SIGTERM handler ({}), falling back to ctrl-c only",
                            err
                        );
                        tokio::signal::ctrl_c().await.ok();
                        "SIGINT"
                    }
                }
            }
            #[cfg(not(unix))]
            {
                // Windows has no SIGTERM. `pocketshell daemon stop` requests a
                // graceful shutdown by creating this sentinel file; poll for it
                // alongside Ctrl-C. Returning "SIGTERM" routes into the same
                // clean-shutdown arm (mark offline + audit + state save) the
                // Unix signal path uses.
                let stop_sentinel = AppConfig::paths()
                    .ok()
                    .map(|p| p.state_dir.join("daemon.stop"));
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => break "SIGINT",
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {
                            if stop_sentinel.as_ref().is_some_and(|s| s.exists()) {
                                break "SIGTERM";
                            }
                        }
                    }
                }
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

        let mut disconnect_reason = ControlPlaneDisconnect::Reconnect;
        loop {
            tokio::select! {
                _ = heartbeat_tick.tick() => {
                    let now = Instant::now();
                    let now_wall = SystemTime::now();
                    let mono_gap = now.duration_since(last_tick);
                    // `duration_since` errors when the wall clock moved backwards
                    // (NTP correction, manual reset). Treat the absolute jump as
                    // the gap so we still reconnect — a backwards leap is just as
                    // disruptive to long-lived sockets as a forward one.
                    let wall_gap = match now_wall.duration_since(last_tick_wall) {
                        Ok(d) => d,
                        Err(e) => e.duration(),
                    };
                    let stall_threshold =
                        Duration::from_secs(config.heartbeat_interval_secs * 3);
                    if mono_gap > stall_threshold || wall_gap > stall_threshold {
                        warn!(
                            "possible sleep/wake detected (mono_gap={:?}, wall_gap={:?}); forcing reconnect",
                            mono_gap, wall_gap
                        );
                        break;
                    }
                    last_tick = now;
                    last_tick_wall = now_wall;

                    // Detect rotation so we can reconnect — the WS is bound
                    // to the old JWT in its Authorization header until then.
                    let token_before = store.access_token().ok().map(str::to_owned);
                    match safe_refresh_if_needed(&backend, &mut store).await {
                        Ok(()) => {}
                        Err(HostError::AuthRevoked) => {
                            // Bounce out to the outer connect loop: it reloads
                            // state.json and decides whether the refresh token
                            // is genuinely past its JWT exp or just a transient
                            // race. Either way, do not clear in-memory tokens —
                            // the existing access token may still have life left
                            // for the heartbeat we'd otherwise skip.
                            break;
                        }
                        Err(err) => {
                            warn!("token refresh failed: {} — will retry next tick", err);
                            continue;
                        }
                    }
                    let token_after = store.access_token().ok().map(str::to_owned);
                    if token_before != token_after {
                        info!("access token rotated; reconnecting WS to bind new credentials");
                        disconnect_reason = ControlPlaneDisconnect::TokenRotated;
                        break;
                    }

                    let token = match store.access_token().map(|s| s.to_string()) {
                        Ok(t) => t,
                        Err(err) => {
                            warn!("heartbeat: no access token ({}), forcing reconnect", err);
                            break;
                        }
                    };
                    // Heartbeat rides the open WS instead of an HTTP POST per tick.
                    let hb_envelope = SignalEnvelope {
                        message_type: "heartbeat".to_string(),
                        session_id: None,
                        payload: Some(serde_json::json!({
                            "active_sessions": sessions.active_count(),
                            "pending_devices": store.state.pending_devices.len(),
                            "app_version": config.app_version,
                        })),
                        state: None,
                        accepted: None,
                        reason: None,
                        extra: std::collections::HashMap::new(),
                    };
                    if let Err(err) = send_signal(&mut ws, &hb_envelope).await {
                        warn!("heartbeat send failed: {} — forcing reconnect", err);
                        break;
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
                    // Trust sync: remove backend-revoked devices, and refresh
                    // permissions for devices already trusted locally. New
                    // devices are NEVER added here — only via `pocketshell pair`.
                    if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                        match backend.list_trusted_devices(&token, &host_id).await {
                        Ok(devices) => {
                            // Rebase trust on whatever the CLI may have written since we
                            // last loaded, so we don't drop a freshly paired device when
                            // we write our revocations back out.
                            if let Err(e) = store.reload_trust() {
                                warn!("reload_trust before revocation tick failed: {e}");
                            }
                            let removed = store.apply_revocations(&devices);
                            let permission_updates =
                                store.apply_trusted_device_permission_updates(&devices);
                            for mobile_device_id in &permission_updates {
                                info!(
                                    "device {} permissions updated via backend sync",
                                    mobile_device_id
                                );
                            }
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
                            if !removed.is_empty() || !permission_updates.is_empty() {
                                // Use save_full so the trust metadata actually persists; we
                                // already rebased trust from disk above.
                                let _ = store.save_full();
                            }

                            // Host abandonment check: if the user revoked the
                            // last trusted device, no mobile can reach this
                            // host anymore. Shut down so we stop hammering the
                            // backend with stale heartbeats. The user can
                            // re-pair via `pocketshell pair` (QR) to bring
                            // the host back — that flow re-installs and starts
                            // the service.
                            //
                            // Guarded on `!removed.is_empty()` to avoid a
                            // false positive during the initial pairing window
                            // where the host briefly has 0 trusted devices.
                            if !removed.is_empty()
                                && store.state.trusted_devices.is_empty()
                                && devices.iter().all(|d| d.revoked_at.is_some())
                            {
                                warn!(
                                    "all trusted devices revoked on backend — host abandoned, stopping daemon"
                                );
                                let _ = write_audit_event_with_store(
                                    AuditEvent::new("host_abandoned"),
                                    &store,
                                );
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(3),
                                    backend.mark_offline(&token, &host_id),
                                ).await;
                                sessions.close_all();
                                webrtc_mgr.close_all().await;
                                let _ = store.save();
                                // Uninstall (not just stop): KeepAlive=true on
                                // launchd / Restart=always on systemd would
                                // immediately resurrect the daemon if we only
                                // stopped. Re-pairing calls install_and_start
                                // which reinstates the service.
                                let _ = crate::service::uninstall();
                                return Ok(());
                            }
                        }
                        Err(HostError::HostGone) => {
                            // Backend doesn't recognize this host_id under the
                            // authenticated user — the user deleted the host
                            // from the mobile app. Wipe local identity so a
                            // subsequent `pocketshell pair` (without
                            // --reset) cleanly re-registers as a new host
                            // instead of replaying the now-gone host_id and
                            // tripping the "paired with a different account"
                            // guard.
                            warn!(
                                "host record removed on backend — wiping local state and stopping daemon (run `pocketshell pair` to re-add — scan QR with mobile app)"
                            );
                            let _ = write_audit_event_with_store(
                                AuditEvent::new("host_deleted_by_user"),
                                &store,
                            );
                            sessions.close_all();
                            webrtc_mgr.close_all().await;
                            store.state = crate::models::AgentState::default();
                            let _ = store.save_full();
                            let _ = crate::service::uninstall();
                            return Ok(());
                        }
                        Err(e) => {
                            // Transient errors (network, 5xx, AuthRevoked) —
                            // drop and try again next tick. AuthRevoked is
                            // handled by the heartbeat path which forces
                            // reconnect.
                            tracing::debug!("trusted-device sync skipped: {}", e);
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
                _ = summary_tick.tick() => {
                    // Lightweight presence + cpu/ram beat for the mobile hosts
                    // list. Gated on `summary_active` (toggled by backend via
                    // `summary_subscribe`/`summary_unsubscribe`) — the backend
                    // only enables it when a mobile viewer is actually
                    // connected. Independent of `stats_active`: those are
                    // separate subscriptions (live stats stream).
                    if !summary_active {
                        continue;
                    }
                    let snap = stats.snapshot();
                    let ram_percent = if snap.memory_total_bytes > 0 {
                        (snap.memory_used_bytes as f64 / snap.memory_total_bytes as f64 * 100.0) as f32
                    } else {
                        0.0
                    };
                    let msg = SignalEnvelope {
                        message_type: "host_summary".to_string(),
                        session_id: None,
                        payload: Some(serde_json::json!({
                            "cpu_percent": snap.cpu_usage_percent,
                            "ram_percent": ram_percent,
                            "collected_at": snap.collected_at,
                        })),
                        state: None,
                        accepted: None,
                        reason: None,
                        extra: std::collections::HashMap::new(),
                    };
                    if let Err(err) = send_signal(&mut ws, &msg).await {
                        warn!("host_summary send failed: {}", err);
                        break;
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
                // Accept new local attach connections (Unix only for now)
                maybe_client = local_accept(local_listener.as_ref()) => {
                    if let Some((read_half, write_half)) = maybe_client {
                        local_client_counter += 1;
                        let client_id = local_client_counter;
                        let tx = local_event_tx.clone();
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

                        // Primary path: deliver to any viewer with a live data channel.
                        // `delivered` is true only if the bytes were actually sent over
                        // at least one channel (send_output → broadcast returns false on
                        // empty/failed/timed-out sends and prunes dead channels).
                        let delivered =
                            webrtc_mgr.send_output(&chunk.session_id, &chunk.bytes).await;

                        // Skip the WS fallback only when the channel actually took the
                        // bytes AND the session has exactly one authenticated WebRTC
                        // channel. Previously the send result was ignored, so when a
                        // channel send failed or timed out the WS fallback was skipped
                        // too and the output was lost on every transport. Gating on
                        // `delivered` keeps WS flowing whenever the channel didn't take
                        // the bytes — with no duplication, since WS only fires on a
                        // channel miss. Multi-viewer sessions (Vec<RTCDataChannel> per
                        // session_id) keep WS flowing because `authenticated_channels` is
                        // session-keyed and can't tell us whether every viewer's channel
                        // is auth'd — a second viewer in the post-open/pre-auth window
                        // would otherwise be starved. Single-viewer is the 95% case.
                        if delivered
                            && webrtc_mgr.channel_count(&chunk.session_id) == 1
                            && authenticated_channels.contains(&chunk.session_id)
                        {
                            continue;
                        }

                        let msg = SignalEnvelope {
                            message_type: "signal".to_string(),
                            session_id: Some(chunk.session_id),
                            payload: Some(serde_json::json!({
                                "channel": "terminal",
                                // Absolute stream offset of these bytes. v2 clients
                                // dedup the snapshot→live seam against it; old
                                // clients ignore the unknown field.
                                "offset": chunk.offset,
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

                    // OSC 133 / BEL attention events fire after the parser's
                    // quiet-period debounce (see `DEFAULT_QUIET_PERIOD`).
                    for ev in sessions.drain_attention(std::time::Instant::now()) {
                        let SessionAttentionEvent { session_id, kind, command_duration } = ev;
                        let exit_code = match &kind {
                            AttentionKind::CommandDone { exit_code } => *exit_code,
                            AttentionKind::Bell
                            | AttentionKind::Notification { .. }
                            | AttentionKind::Idle => None,
                        };
                        let body = kind.body().map(|s| s.to_string());
                        let kind_str = kind.wire_str();
                        info!(
                            "terminal attention: session={} kind={} exit={:?} duration={:?} body={:?}",
                            session_id, kind_str, exit_code, command_duration, body
                        );
                        let msg = SignalEnvelope {
                            message_type: "terminal_attention".to_string(),
                            session_id: Some(session_id),
                            payload: Some(serde_json::json!({
                                "kind": kind_str,
                                "exit_code": exit_code,
                                "command_duration_ms": command_duration.map(|d| d.as_millis() as u64),
                                "body": body,
                            })),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra: std::collections::HashMap::new(),
                        };
                        if let Err(err) = send_signal(&mut ws, &msg).await {
                            warn!("terminal_attention send failed: {}", err);
                            break;
                        }
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
                _ = turn_usage_tick.tick() => {
                    let delta = match tokio::time::timeout(
                        WEBRTC_POLL_TIMEOUT,
                        webrtc_mgr.collect_relay_delta(),
                    )
                    .await
                    {
                        Ok(delta) => delta,
                        Err(_) => {
                            warn!(
                                "webrtc relay accounting timed out after {:?}; skipping this report",
                                WEBRTC_POLL_TIMEOUT
                            );
                            0
                        }
                    };
                    if delta > 0 {
                        if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                if let Err(err) = backend.report_turn_usage(&token, delta).await {
                                    warn!("turn usage report failed ({} bytes): {}", delta, err);
                                }
                            });
                        }
                    }
                }
                _ = webrtc_poll_tick.tick() => {
                    let poll_result =
                        tokio::time::timeout(WEBRTC_POLL_TIMEOUT, webrtc_mgr.poll_events()).await;
                    if poll_result.is_err() {
                        warn!(
                            "webrtc poll_events timed out after {:?}; continuing control loop",
                            WEBRTC_POLL_TIMEOUT
                        );
                    }
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

                Some(envelope) = agent_ws_out_rx.recv() => {
                    if let Err(e) = send_signal(&mut ws, &envelope).await {
                        warn!("agent ws signal send failed: {}", e);
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
                                            )
                                            .and_then(|_| {
                                                device_permission_result(&store, &mobile_device_id, "shell")
                                            });
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            webrtc_mgr.send_output(&session_id, &response).await;
                                            let result_for_audit = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
                                            if result.is_ok() {
                                                authenticated_channels.insert(session_id.clone());
                                                info!("device {} authenticated for session {}", mobile_device_id, session_id);
                                            } else {
                                                warn!("auth failed for device {} session {}: {:?}", mobile_device_id, session_id, result.err());
                                            }
                                            audit_channel_auth(
                                                &store,
                                                "terminal",
                                                &mobile_device_id,
                                                Some(session_id.clone()),
                                                result_for_audit,
                                            );
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&session_id) {
                                warn!("dropping unauthenticated input on session {} from device {}", session_id, mobile_device_id);
                            } else {
                                if data.starts_with(TERMINAL_KEEPALIVE_SENTINEL) {
                                    if let Some(response) = build_terminal_keepalive_pong(&data) {
                                        webrtc_mgr.send_output(&session_id, &response).await;
                                    } else {
                                        trace!("terminal keepalive received for session {}", session_id);
                                    }
                                } else if data.len() > 5 && data[0] == 0x00 && &data[1..5] == b"PSFT" {
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
                            if !webrtc_mgr.has_channel(&session_id) {
                                let should_detach = store.state.sessions.iter().any(|session| {
                                    session.session_id == session_id
                                        && !matches!(
                                            session.state,
                                            SessionState::Detached
                                                | SessionState::Ended
                                                | SessionState::Failed
                                        )
                                });
                                if should_detach {
                                    store.touch_session_state(&session_id, SessionState::Detached);
                                    store.save()?;
                                }
                            }
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
                            files_watchers.retain(|(dev, _), handle| {
                                if dev == &mobile_device_id {
                                    handle.abort();
                                    false
                                } else {
                                    true
                                }
                            });
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
                                            )
                                            .and_then(|_| {
                                                device_permission_result(&store, &mobile_device_id, "shell")
                                            });
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                                warn!("files auth result send failed for mobile {}: {}", mobile_device_id, err);
                                            }
                                            let result_for_audit = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
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
                                            audit_channel_auth(&store, "files", &mobile_device_id, None, result_for_audit);
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
                                            let expected_size = frame
                                                .header
                                                .get("size")
                                                .and_then(|v| v.as_u64())
                                                .map(|v| v as usize);
                                            let active_uploads = files_binary_uploads
                                                .keys()
                                                .filter(|key| key.starts_with(&format!("{mobile_device_id}:")))
                                                .count();
                                            if active_uploads >= MAX_ACTIVE_UPLOADS_PER_DEVICE {
                                                let response = serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": "too many active uploads for this device",
                                                    "error_code": "upload_limit_exceeded"
                                                });
                                                if let Err(e) = send_framed_files_response(channel, &response).await {
                                                    warn!("files upload limit send failed: {}", e);
                                                }
                                                continue;
                                            }
                                            if expected_size.is_none_or(|size| size > MAX_STREAM_UPLOAD_BYTES) {
                                                let response = serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": "upload size exceeds host limit",
                                                    "error_code": "upload_too_large"
                                                });
                                                if let Err(e) = send_framed_files_response(channel, &response).await {
                                                    warn!("files upload size error send failed: {}", e);
                                                }
                                                continue;
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
                                                            files_binary_uploads.insert(
                                                                upload_key,
                                                            PendingFilesBinaryUpload {
                                                                final_path: file_path,
                                                                    tmp_path,
                                                                    file,
                                                                    bytes_written: 0,
                                                                    expected_size,
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
                                            if frame.payload.len() > MAX_STREAM_UPLOAD_CHUNK_BYTES {
                                                let response = serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": "upload chunk exceeds host limit",
                                                    "error_code": "upload_chunk_too_large"
                                                });
                                                if let Err(e) = send_framed_files_response(channel, &response).await {
                                                    warn!("files upload chunk-too-large send failed: {}", e);
                                                }
                                                if let Some(failed) = files_binary_uploads.remove(&upload_key) {
                                                    drop(failed.file);
                                                    let _ = std::fs::remove_file(&failed.tmp_path);
                                                }
                                                continue;
                                            }
                                            if let Some(upload) = files_binary_uploads.get_mut(&upload_key) {
                                                let next_size = upload.bytes_written.saturating_add(frame.payload.len());
                                                if next_size > MAX_STREAM_UPLOAD_BYTES
                                                    || upload.expected_size.is_some_and(|size| next_size > size)
                                                {
                                                    let response = serde_json::json!({
                                                        "channel": "files",
                                                        "response_to": request_id,
                                                        "status": "error",
                                                        "error": "upload exceeds declared or host size limit",
                                                        "error_code": "upload_too_large"
                                                    });
                                                    if let Err(e) = send_framed_files_response(channel, &response).await {
                                                        warn!("files upload too-large send failed: {}", e);
                                                    }
                                                    if let Some(failed) = files_binary_uploads.remove(&upload_key) {
                                                        drop(failed.file);
                                                        let _ = std::fs::remove_file(&failed.tmp_path);
                                                    }
                                                    continue;
                                                }
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
                                    "upload_cancel" => {
                                        if let Some(upload) = files_binary_uploads.remove(&upload_key) {
                                            drop(upload.file);
                                            let _ = std::fs::remove_file(&upload.tmp_path);
                                            info!("files upload cancelled: {}", upload_key);
                                        }
                                        let response = serde_json::json!({
                                            "channel": "files",
                                            "response_to": request_id,
                                            "status": "error",
                                            "error": "upload cancelled",
                                            "error_code": "upload_cancelled"
                                        });
                                        if let Err(e) = send_framed_files_response(channel, &response).await {
                                            warn!("files upload cancel send failed: {}", e);
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

                                    if action == "read_file_stream" {
                                        // PSFB binary path to skip base64 — see read_file in
                                        // files.rs for the text (signaling-friendly) variant.
                                        let req_id_clone = request_id.clone();
                                        let path_clone = path.clone();
                                        let offset = payload
                                            .get("offset")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        // Match read_file's MAX_READ_SIZE cap (512 KB). The
                                        // mobile loader iterates, so a single request never
                                        // has to be unbounded.
                                        const MAX_READ_STREAM_SIZE: u64 = 512 * 1024;
                                        let limit = payload
                                            .get("limit")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(MAX_READ_STREAM_SIZE)
                                            .min(MAX_READ_STREAM_SIZE);

                                        tokio::spawn(async move {
                                            let send_error = |msg: String| {
                                                let channel = std::sync::Arc::clone(&channel);
                                                let req_id = req_id_clone.clone();
                                                async move {
                                                    let header = serde_json::json!({
                                                        "op": "read_stream_error",
                                                        "id": req_id,
                                                        "error": msg,
                                                    });
                                                    let _ = send_files_stream_frame(channel, &header, &[]).await;
                                                }
                                            };

                                            let canonical = match crate::files::resolve_file_path_for_transfer(&path_clone) {
                                                Ok(p) => p,
                                                Err(err) => {
                                                    send_error(err.to_string()).await;
                                                    return;
                                                }
                                            };
                                            let metadata = match std::fs::metadata(&canonical) {
                                                Ok(m) => m,
                                                Err(err) => {
                                                    send_error(err.to_string()).await;
                                                    return;
                                                }
                                            };
                                            if metadata.is_dir() {
                                                send_error("cannot read a directory".to_string()).await;
                                                return;
                                            }

                                            let size = metadata.len();
                                            let end_offset = offset.saturating_add(limit).min(size);
                                            let will_read = end_offset.saturating_sub(offset);
                                            let truncated = (offset + will_read) < size;

                                            let start_header = serde_json::json!({
                                                "op": "read_stream_start",
                                                "id": req_id_clone,
                                                "size": size,
                                                "truncated": truncated,
                                            });
                                            if let Err(e) = send_files_stream_frame(
                                                std::sync::Arc::clone(&channel),
                                                &start_header,
                                                &[],
                                            ).await {
                                                warn!("files read_stream start send failed: {}", e);
                                                return;
                                            }

                                            let mut file = match File::open(&canonical) {
                                                Ok(f) => f,
                                                Err(err) => {
                                                    send_error(err.to_string()).await;
                                                    return;
                                                }
                                            };
                                            if offset > 0 {
                                                if let Err(err) = file.seek(SeekFrom::Start(offset)) {
                                                    send_error(err.to_string()).await;
                                                    return;
                                                }
                                            }
                                            let mut reader = BufReader::new(file);
                                            let mut remaining = will_read;
                                            let mut buf = vec![0u8; FILES_STREAM_CHUNK_SIZE];
                                            while remaining > 0 {
                                                let want = std::cmp::min(remaining as usize, buf.len());
                                                let read = match reader.read(&mut buf[..want]) {
                                                    Ok(n) => n,
                                                    Err(err) => {
                                                        send_error(err.to_string()).await;
                                                        return;
                                                    }
                                                };
                                                if read == 0 {
                                                    break;
                                                }
                                                let header = serde_json::json!({
                                                    "op": "read_stream_chunk",
                                                    "id": req_id_clone,
                                                });
                                                match tokio::time::timeout(
                                                    DOWNLOAD_SEND_TIMEOUT,
                                                    send_files_stream_frame(std::sync::Arc::clone(&channel), &header, &buf[..read]),
                                                ).await {
                                                    Ok(Ok(())) => {}
                                                    Ok(Err(e)) => {
                                                        warn!("files read_stream chunk send failed: {}", e);
                                                        return;
                                                    }
                                                    Err(_) => {
                                                        warn!("files read_stream chunk send timed out req={}", req_id_clone);
                                                        return;
                                                    }
                                                }
                                                remaining -= read as u64;
                                            }

                                            let end_header = serde_json::json!({
                                                "op": "read_stream_end",
                                                "id": req_id_clone,
                                            });
                                            let _ = tokio::time::timeout(
                                                DOWNLOAD_SEND_TIMEOUT,
                                                send_files_stream_frame(channel, &end_header, &[]),
                                            ).await;
                                        });
                                        continue;
                                    }

                                    if action == "watch_file" {
                                        // Reap watchers whose task already exited (idle stop,
                                        // send failure) — they only get removed from the map here
                                        // or on FilesChannelClosed.
                                        files_watchers.retain(|_, h| !h.is_finished());

                                        let subscription_id = payload
                                            .get("subscription_id")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let poll_ms = payload
                                            .get("poll_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(crate::files_watch::DEFAULT_POLL_MS);
                                        let idle_ms = payload
                                            .get("idle_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(crate::files_watch::DEFAULT_IDLE_MS);
                                        let from_offset = payload
                                            .get("from_offset")
                                            .and_then(|v| v.as_u64());

                                        if subscription_id.is_empty() {
                                            spawn_files_reply(&channel, serde_json::json!({
                                                "channel": "files",
                                                "response_to": request_id,
                                                "status": "error",
                                                "error": "missing subscription_id",
                                                "error_code": "watch_bad_request",
                                            }));
                                            continue;
                                        }

                                        let canonical = match crate::files::resolve_file_path_for_transfer(&path) {
                                            Ok(p) => p,
                                            Err(err) => {
                                                spawn_files_reply(&channel, serde_json::json!({
                                                    "channel": "files",
                                                    "response_to": request_id,
                                                    "status": "error",
                                                    "error": err.to_string(),
                                                    "error_code": "watch_path_failed",
                                                }));
                                                continue;
                                            }
                                        };

                                        let key = (mobile_device_id.clone(), subscription_id.clone());
                                        if let Some(prev) = files_watchers.remove(&key) {
                                            prev.abort();
                                        }

                                        let initial_offset = from_offset
                                            .unwrap_or_else(|| crate::files_watch::initial_offset(&canonical));
                                        spawn_files_reply(&channel, serde_json::json!({
                                            "channel": "files",
                                            "response_to": request_id,
                                            "status": "ok",
                                            "data": {
                                                "subscription_id": subscription_id,
                                                "initial_offset": initial_offset,
                                            }
                                        }));

                                        let watcher_channel = std::sync::Arc::clone(&channel);
                                        let watcher_path = canonical.clone();
                                        let path_str = path.clone();
                                        let sub_id = subscription_id.clone();
                                        let handle = tokio::spawn(async move {
                                            use tokio::time::{interval, Duration, Instant};
                                            let mut state = crate::files_watch::TailState::starting_at(initial_offset);
                                            let mut ticker = interval(Duration::from_millis(poll_ms.max(100)));
                                            ticker.set_missed_tick_behavior(
                                                tokio::time::MissedTickBehavior::Delay,
                                            );
                                            let mut last_growth = Instant::now();
                                            let idle_stop_enabled = idle_ms > 0;
                                            loop {
                                                ticker.tick().await;
                                                let lines = match crate::files_watch::read_delta(
                                                    &watcher_path,
                                                    &mut state,
                                                ) {
                                                    Ok(l) => l,
                                                    Err(e) => {
                                                        warn!(
                                                            "files watch read_delta error sub={} path={}: {}",
                                                            sub_id,
                                                            watcher_path.display(),
                                                            e
                                                        );
                                                        continue;
                                                    }
                                                };
                                                if !lines.is_empty() {
                                                    last_growth = Instant::now();
                                                    let frame = serde_json::json!({
                                                        "channel": "files",
                                                        "event": "file_appended",
                                                        "subscription_id": sub_id,
                                                        "path": path_str,
                                                        "lines": lines,
                                                        "new_offset": state.last_size,
                                                    });
                                                    let ch = std::sync::Arc::clone(&watcher_channel);
                                                    if let Err(e) = send_framed_files_response(ch, &frame).await {
                                                        warn!(
                                                            "files watch frame send failed sub={}: {}",
                                                            sub_id, e
                                                        );
                                                        break;
                                                    }
                                                } else if idle_stop_enabled
                                                    && last_growth.elapsed()
                                                    >= Duration::from_millis(idle_ms)
                                                {
                                                    let stop = serde_json::json!({
                                                        "channel": "files",
                                                        "event": "watch_stopped",
                                                        "subscription_id": sub_id,
                                                        "reason": "idle",
                                                    });
                                                    let ch = std::sync::Arc::clone(&watcher_channel);
                                                    let _ = send_framed_files_response(ch, &stop).await;
                                                    break;
                                                }
                                            }
                                        });
                                        files_watchers.insert(key, handle);
                                        continue;
                                    }

                                    if action == "unwatch_file" {
                                        let subscription_id = payload
                                            .get("subscription_id")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let key = (mobile_device_id.clone(), subscription_id.clone());
                                        if let Some(handle) = files_watchers.remove(&key) {
                                            handle.abort();
                                        }
                                        spawn_files_reply(&channel, serde_json::json!({
                                            "channel": "files",
                                            "response_to": request_id,
                                            "status": "ok",
                                            "data": { "subscription_id": subscription_id },
                                        }));
                                        continue;
                                    }

                                    // Spawn so file I/O doesn't block the event loop
                                    let action_clone = action.clone();
                                    let req_id_clone = request_id.clone();
                                    let router = agent_router.clone();
                                    let ctx = build_file_action_context(&store, &mobile_device_id);
                                    tokio::spawn(async move {
                                        let start = std::time::Instant::now();
                                        let result = crate::files::handle_files_action_with_context(&payload, &router, &ctx).await;
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
                                            )
                                            .and_then(|_| {
                                                device_permission_result(&store, &mobile_device_id, "stats")
                                            });
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                                warn!("stats auth result send failed for device {}: {}", mobile_device_id, err);
                                            }
                                            let result_for_audit = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
                                            if result.is_ok() {
                                                authenticated_channels.insert(stats_channel_key.clone());
                                                info!("device {} authenticated for stats channel", mobile_device_id);
                                            } else {
                                                warn!("stats auth failed for device {}: {:?}", mobile_device_id, result.err());
                                            }
                                            audit_channel_auth(&store, "stats", &mobile_device_id, None, result_for_audit);
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&stats_channel_key) {
                                warn!("dropping unauthenticated stats message from device {}", mobile_device_id);
                            } else if let Ok(json_str) = std::str::from_utf8(&data) {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                                    let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                                    if msg_type == "kill_process" {
                                        if !require_device_permission(&store, &mobile_device_id, "shell", "kill_process") {
                                            continue;
                                        }
                                        let pid = val.get("pid").and_then(|v| v.as_i64());
                                        let signal = val.get("signal").and_then(|v| v.as_str()).unwrap_or("TERM");
                                        if let Some(pid) = pid {
                                            let sig_num_for_audit = match signal {
                                                "KILL" | "9" => "9",
                                                _ => "15",
                                            };
                                            // Record the device's RAW requested signal too — `signal`
                                            // is coerced to TERM/KILL above and a forensic reader
                                            // shouldn't be misled into thinking HUP/USR1/etc. were
                                            // never requested.
                                            let requested_signal = signal.to_string();
                                            let audit_kill = |outcome: AuditEvent| {
                                                let _ = write_audit_event_with_store(
                                                    AuditEvent {
                                                        mobile_device_id: Some(mobile_device_id.clone()),
                                                        target: Some(pid.to_string()),
                                                        details: Some(serde_json::json!({
                                                            "pid": pid,
                                                            "signal_sent": sig_num_for_audit,
                                                            "signal_requested": requested_signal,
                                                        })),
                                                        ..outcome
                                                    },
                                                    &store,
                                                );
                                            };
                                            if pid <= 0 {
                                                warn!("kill_process rejected: invalid pid {} (non-positive PIDs target process groups)", pid);
                                                // Refused attempts use a separate event_type so the
                                                // name does not imply the process was actually killed.
                                                audit_kill(AuditEvent::new("process.kill_rejected").denied("invalid_pid"));
                                            } else if pid == 1 {
                                                warn!("kill_process rejected: refusing to signal pid 1 (init/systemd)");
                                                audit_kill(AuditEvent::new("process.kill_rejected").denied("refused_init"));
                                            } else if !pid_is_in_daemon_pgrp(pid as i32) {
                                                warn!(
                                                    "kill_process rejected: pid {} not in daemon process group (refusing cross-pgrp kill)",
                                                    pid
                                                );
                                                audit_kill(AuditEvent::new("process.kill_rejected").denied("cross_pgrp"));
                                            } else {
                                                let kill_bin = resolve_kill_binary();
                                                info!(
                                                    "kill_process request: pid={} signal={} via {}",
                                                    pid,
                                                    sig_num_for_audit,
                                                    kill_bin.display()
                                                );
                                                match std::process::Command::new(&kill_bin)
                                                    .arg(format!("-{}", sig_num_for_audit))
                                                    .arg(pid.to_string())
                                                    .output()
                                                {
                                                    Ok(output) => {
                                                        if output.status.success() {
                                                            audit_kill(AuditEvent::new("process.killed"));
                                                        } else {
                                                            let stderr = String::from_utf8_lossy(&output.stderr);
                                                            warn!("kill_process failed for pid {}: {}", pid, stderr.trim());
                                                            audit_kill(AuditEvent::new("process.killed").failed(stderr.trim().to_string()));
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("kill_process command failed: {}", e);
                                                        audit_kill(AuditEvent::new("process.killed").failed(e.to_string()));
                                                    }
                                                }
                                            }
                                        } else {
                                            warn!("kill_process message missing pid field");
                                        }
                                    } else if msg_type == "reboot" {
                                        if !require_device_permission(&store, &mobile_device_id, "shell", "reboot") {
                                            continue;
                                        }
                                        info!("reboot request received from mobile");
                                        match crate::rpc::try_reboot() {
                                            Ok(_) => {
                                                let _ = write_audit_event_with_store(
                                                    AuditEvent {
                                                        mobile_device_id: Some(mobile_device_id.clone()),
                                                        ..AuditEvent::new("host.rebooted")
                                                    },
                                                    &store,
                                                );
                                            }
                                            Err((code, msg)) => {
                                                warn!("reboot failed ({}): {}", code, msg);
                                                let _ = write_audit_event_with_store(
                                                    AuditEvent {
                                                        mobile_device_id: Some(mobile_device_id.clone()),
                                                        details: Some(serde_json::json!({ "code": code })),
                                                        ..AuditEvent::new("host.rebooted").failed(msg)
                                                    },
                                                    &store,
                                                );
                                            }
                                        }
                                    } else if msg_type == "host_update_agent" {
                                        // Self-update over the Ed25519-authenticated stats
                                        // channel — same trust anchor as kill_process/reboot
                                        // above: the device proved key possession in the
                                        // channel auth handshake (verify_device_auth), so a
                                        // compromised backend cannot forge this. Origin and
                                        // version are pinned inside install_agent_update —
                                        // always the latest signed build from our own repo.
                                        if !require_device_permission(&store, &mobile_device_id, "shell", "host_update_agent") {
                                            continue;
                                        }
                                        info!(
                                            "host_update_agent request received from mobile {} (stats channel)",
                                            mobile_device_id
                                        );
                                        let current_version = config.app_version.clone();
                                        if try_spawn_self_update(current_version.clone()) {
                                            let _ = write_audit_event_with_store(
                                                AuditEvent {
                                                    mobile_device_id: Some(mobile_device_id.clone()),
                                                    details: Some(serde_json::json!({
                                                        "from_version": current_version,
                                                        "base_url": crate::update::DEFAULT_BASE_URL,
                                                        "target_version": "latest",
                                                        "channel": "stats",
                                                    })),
                                                    ..AuditEvent::new("self_update")
                                                },
                                                &store,
                                            );
                                        } else {
                                            warn!(
                                                "host_update_agent ignored: an update is already in progress (stats channel, mobile {})",
                                                mobile_device_id
                                            );
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
                                            )
                                            .and_then(|_| {
                                                device_permission_result(&store, &mobile_device_id, "shell")
                                            });
                                            let response = build_auth_message(&serde_json::json!({
                                                "type": "auth_result",
                                                "ok": result.is_ok(),
                                                "reason": result.as_ref().err(),
                                            }));
                                            if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                                warn!("control auth result send failed for device {}: {}", mobile_device_id, err);
                                            }
                                            let result_for_audit = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
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
                                            audit_channel_auth(&store, "control", &mobile_device_id, None, result_for_audit);
                                        }
                                    }
                                }
                            } else if !authenticated_channels.contains(&control_channel_key) {
                                warn!("dropping unauthenticated control message from device {}", mobile_device_id);
                            } else if let Some(req) = crate::rpc::parse_request(&data) {
                                let method = req.method.clone();
                                let req_id = req.id.clone();
                                let ch = Arc::clone(&channel);
                                if method == "host/update_agent" {
                                    // Self-update over the Ed25519-authenticated control
                                    // channel. The channel auth handshake already proved
                                    // device-key possession, but re-check the permission
                                    // per-call (auth is one-time at open, so a mid-session
                                    // revoke must still take effect — same reason audit/list
                                    // re-checks below). Origin/version are pinned inside
                                    // install_agent_update; the backend has no device key and
                                    // cannot forge this. Mirrors the reboot/kill trust model.
                                    let resp = if let Err(reason) =
                                        device_permission_result(&store, &mobile_device_id, "shell")
                                    {
                                        audit_authz_denied(
                                            &store,
                                            &mobile_device_id,
                                            "host/update_agent",
                                            &reason,
                                            None,
                                        );
                                        crate::rpc::RpcResponse::err(
                                            req_id.clone(),
                                            crate::rpc::RpcError::permission_denied(reason),
                                        )
                                    } else {
                                        let current_version = config.app_version.clone();
                                        if try_spawn_self_update(current_version.clone()) {
                                            let _ = write_audit_event_with_store(
                                                AuditEvent {
                                                    mobile_device_id: Some(mobile_device_id.clone()),
                                                    details: Some(serde_json::json!({
                                                        "from_version": current_version,
                                                        "base_url": crate::update::DEFAULT_BASE_URL,
                                                        "target_version": "latest",
                                                        "channel": "control",
                                                    })),
                                                    ..AuditEvent::new("self_update")
                                                },
                                                &store,
                                            );
                                            crate::rpc::RpcResponse::ok(
                                                req_id.clone(),
                                                serde_json::json!({ "scheduled": true }),
                                            )
                                        } else {
                                            // An update is already running — idempotent, not an
                                            // error. Report it so the client doesn't double-trigger.
                                            crate::rpc::RpcResponse::ok(
                                                req_id.clone(),
                                                serde_json::json!({
                                                    "scheduled": false,
                                                    "already_in_progress": true,
                                                }),
                                            )
                                        }
                                    };
                                    send_control_rpc_response(ch, &resp, &method, &req_id).await;
                                } else if crate::rpc::is_stateful_method(&method) {
                                    // Borrow the daemon's warm StatsCollector to keep CPU%
                                    // accurate (the 2s stream tick has just refreshed it).
                                    // Worst case ~30 ms on a 1000-process host briefly delays
                                    // the next stream tick and other select arms; terminal
                                    // I/O runs in spawned tasks so it is unaffected.
                                    let resp = match method.as_str() {
                                        "system/list_processes" => {
                                            crate::rpc::handle_list_processes(&mut stats, req)
                                        }
                                        "audit/list" => {
                                            // Re-check permission per RPC: the one-time channel
                                            // auth runs only at open, so revoking shell access
                                            // mid-session would otherwise leave the audit log
                                            // readable until the channel closes.
                                            if let Err(reason) = device_permission_result(
                                                &store,
                                                &mobile_device_id,
                                                "shell",
                                            ) {
                                                audit_authz_denied(
                                                    &store,
                                                    &mobile_device_id,
                                                    "audit/list",
                                                    &reason,
                                                    None,
                                                );
                                                crate::rpc::RpcResponse::err(
                                                    req_id.clone(),
                                                    crate::rpc::RpcError::permission_denied(
                                                        reason,
                                                    ),
                                                )
                                            } else {
                                                crate::rpc::handle_audit_list(
                                                    &store,
                                                    &mobile_device_id,
                                                    req,
                                                )
                                                .await
                                            }
                                        }
                                        other => crate::rpc::RpcResponse::err(
                                            req_id.clone(),
                                            crate::rpc::RpcError::internal(format!(
                                                "stateful method '{other}' has no inline handler"
                                            )),
                                        ),
                                    };
                                    send_control_rpc_response(ch, &resp, &method, &req_id).await;
                                } else {
                                    // Stateless dispatch: spawn so handlers that may block
                                    // (kill, reboot) don't stall the event loop.
                                    tokio::spawn(async move {
                                        let resp = crate::rpc::dispatch(req).await;
                                        send_control_rpc_response(ch, &resp, &method, &req_id).await;
                                    });
                                }
                            } else {
                                warn!("control RPC parse failed from device {} (bytes={})", mobile_device_id, data.len());
                            }
                        }
                        WebRtcEvent::AgentChannelOpened { agent_id, mobile_device_id, channel } => {
                            info!("agent channel opened agent={} mobile={}", agent_id, mobile_device_id);
                            let key = agent_session::agent_channel_key(&agent_id, &mobile_device_id);
                            let mut nonce_bytes = [0u8; 32];
                            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                            let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);
                            pending_auth.insert(key, (nonce_b64.clone(), mobile_device_id.clone()));
                            let challenge = build_auth_message(&serde_json::json!({
                                "type": "auth_challenge",
                                "nonce": nonce_b64,
                            }));
                            if let Err(err) = channel.send(&bytes::Bytes::from(challenge)).await {
                                warn!("agent auth challenge send failed agent={} mobile={}: {}", agent_id, mobile_device_id, err);
                            }
                        }
                        WebRtcEvent::AgentChannelClosed { agent_id, mobile_device_id } => {
                            info!("agent channel closed agent={} mobile={}", agent_id, mobile_device_id);
                            let key = agent_session::agent_channel_key(&agent_id, &mobile_device_id);
                            authenticated_channels.remove(&key);
                            pending_auth.remove(&key);
                            webrtc_mgr.prune_agent_channels();
                            if let Some(prev) = agent_pumps.remove(&agent_id) {
                                prev.abort();
                            }
                            agent_router.detach(&agent_id).await;
                        }
                        WebRtcEvent::AgentMessage { agent_id, mobile_device_id, data, channel } => {
                            let key = agent_session::agent_channel_key(&agent_id, &mobile_device_id);
                            let is_auth_frame = data.len() > agent_session::AGENT_AUTH_PREFIX.len()
                                && data.starts_with(agent_session::AGENT_AUTH_PREFIX);
                            if is_auth_frame {
                                let body = &data[agent_session::AGENT_AUTH_PREFIX.len()..];
                                let json_str = match std::str::from_utf8(body) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        warn!("agent auth non-UTF8 agent={}: {}", agent_id, e);
                                        continue;
                                    }
                                };
                                let msg: serde_json::Value = match serde_json::from_str(json_str) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        warn!("agent auth JSON parse failed agent={}: {}", agent_id, e);
                                        continue;
                                    }
                                };
                                if msg.get("type").and_then(|v| v.as_str()) != Some("auth_response") {
                                    warn!("agent unexpected auth frame agent={} type={:?}",
                                        agent_id, msg.get("type"));
                                    continue;
                                }
                                let result = verify_device_auth(
                                    &msg, &key, &mobile_device_id,
                                    &mut pending_auth, &store,
                                )
                                .and_then(|_| {
                                    device_permission_result(&store, &mobile_device_id, "shell")
                                });
                                let response = build_auth_message(&serde_json::json!({
                                    "type": "auth_result",
                                    "ok": result.is_ok(),
                                    "reason": result.as_ref().err(),
                                }));
                                if let Err(err) = channel.send(&bytes::Bytes::from(response)).await {
                                    warn!("agent auth result send failed agent={}: {}", agent_id, err);
                                }
                                let result_for_audit = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
                                if result.is_ok() {
                                    authenticated_channels.insert(key);
                                    info!("device {} authenticated for agent {}", mobile_device_id, agent_id);
                                } else {
                                    warn!("agent auth failed agent={} mobile={}: {:?}",
                                        agent_id, mobile_device_id, result.err());
                                }
                                audit_channel_auth(&store, "agent", &mobile_device_id, Some(agent_id.clone()), result_for_audit);
                                continue;
                            }
                            if !authenticated_channels.contains(&key) {
                                warn!("dropping unauthenticated agent message agent={} mobile={}", agent_id, mobile_device_id);
                                continue;
                            }

                            // After auth, the first message is the init frame;
                            // subsequent messages pass through as raw stdin.
                            // Gate: if a pump is already running for this
                            // agent_id, treat as stdin and route to the right
                            // session (Codex hub vs per-agent Claude proc).
                            if agent_pumps.contains_key(&agent_id) {
                                let line = match std::str::from_utf8(&data) {
                                    Ok(s) => s.trim().to_string(),
                                    Err(_) => {
                                        warn!("non-UTF8 agent message dropped agent={}", agent_id);
                                        continue;
                                    }
                                };
                                if let Err(e) = agent_router.send_line(&agent_id, line).await {
                                    warn!("agent send_line failed agent={}: {}", agent_id, e);
                                    // Tell the mobile peer the attachment was
                                    // rejected so its UI can surface the
                                    // reason instead of looking like a
                                    // silent message drop. Other errors
                                    // (SessionClosed, etc.) the channel pump
                                    // already surfaces via its lifecycle.
                                    if let agent_session::AgentSendError::AttachmentRejected(reason) = &e {
                                        let frame = serde_json::json!({
                                            "type": "agent_error",
                                            "stage": "attachment_rejected",
                                            "message": reason,
                                        });
                                        if let Ok(bytes) = serde_json::to_vec(&frame) {
                                            let ch = Arc::clone(&channel);
                                            tokio::spawn(async move {
                                                let _ = ch.send(&bytes::Bytes::from(bytes)).await;
                                            });
                                        }
                                    }
                                }
                                continue;
                            }

                            let send_err = |stage: &str, message: String| {
                                let frame = serde_json::json!({
                                    "type":"agent_error","stage": stage, "message": message,
                                });
                                let bytes = serde_json::to_vec(&frame).unwrap_or_default();
                                let ch = Arc::clone(&channel);
                                tokio::spawn(async move {
                                    let _ = ch.send(&bytes::Bytes::from(bytes)).await;
                                });
                            };

                            let init: serde_json::Value = match serde_json::from_slice(&data) {
                                Ok(v) => v,
                                Err(e) => {
                                    warn!("agent init parse failed agent={}: {}", agent_id, e);
                                    send_err("init", format!("invalid init: {e}"));
                                    continue;
                                }
                            };

                            let backend_str = init.get("backend").and_then(|v| v.as_str()).unwrap_or("");
                            let backend = match backend_str {
                                "codex" => AgentBackend::Codex,
                                "claude" => AgentBackend::Claude,
                                other => {
                                    warn!("agent init unknown backend agent={} backend={:?}", agent_id, other);
                                    send_err("init", format!("unknown backend '{other}' (expected 'codex' or 'claude')"));
                                    continue;
                                }
                            };
                            let cwd = init.get("cwd").and_then(|v| v.as_str())
                                .map(std::path::PathBuf::from);
                            let resume_id = init.get("resumeId")
                                .or_else(|| init.get("resume_id"))
                                .and_then(|v| v.as_str()).map(str::to_string);
                            let model = init.get("model").and_then(|v| v.as_str()).map(str::to_string);
                            let reasoning_effort = init.get("reasoningEffort")
                                .or_else(|| init.get("reasoning_effort"))
                                .and_then(|v| v.as_str()).map(str::to_string);

                            let cfg = AgentSpawnConfig {
                                backend,
                                cwd,
                                resume_id,
                                bundled_binary: agent_session::discover_bundled(backend),
                                id: Some(agent_id.clone()),
                                model,
                                reasoning_effort,
                                backend_session_id: peer_session_routes
                                    .get(&mobile_device_id)
                                    .cloned(),
                            };
                            let outcome = match agent_router.bind(agent_id.clone(), cfg).await {
                                Ok(o) => o,
                                Err(e) => {
                                    warn!("agent bind failed agent={}: {}", agent_id, e);
                                    send_err("spawn", e.to_string());
                                    continue;
                                }
                            };
                            let agent_session::BindOutcome { session, stdout_rx, reattached } = outcome;

                            let ready = serde_json::json!({
                                "type":"agent_ready",
                                "agent_id": agent_id,
                                "backend": backend_str,
                                "session_id": session.id(),
                                "launch": session.launch_description(),
                                "reattached": reattached,
                            });
                            if let Ok(bytes) = serde_json::to_vec(&ready) {
                                let _ = channel.send(&bytes::Bytes::from(bytes)).await;
                            }

                            let pump_channel = Arc::clone(&channel);
                            let pump_agent_id = agent_id.clone();
                            let pump_session = session.clone();
                            let pump_router = Arc::clone(&agent_router);
                            let handle = tokio::spawn(async move {
                                spawn_webrtc_agent_pump(
                                    stdout_rx,
                                    pump_channel,
                                    pump_session,
                                    pump_agent_id,
                                    pump_router,
                                )
                                .await;
                            });
                            agent_pumps.insert(agent_id, handle);
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
                                        extra.insert(
                                            "mobile_device_id".to_string(),
                                            serde_json::json!(mobile_device_id),
                                        );
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
                                } else if peer_key.starts_with("agent:") {
                                    if let Some(host_id) = agent_peer_hosts.get(&peer_key).cloned() {
                                        let mut payload = candidate_value;
                                        if let Some(offer_id) = agent_peer_offer_ids.get(&peer_key).cloned() {
                                            if let Some(map) = payload.as_object_mut() {
                                                map.insert("offer_id".to_string(), serde_json::json!(offer_id));
                                            }
                                        }
                                        let mut extra = std::collections::HashMap::new();
                                        extra.insert("host_id".to_string(), serde_json::json!(host_id));
                                        extra.insert(
                                            "mobile_device_id".to_string(),
                                            serde_json::json!(mobile_device_id),
                                        );
                                        let ice_msg = SignalEnvelope {
                                            message_type: "agent_ice_candidate".to_string(),
                                            session_id: None,
                                            payload: Some(payload),
                                            state: None,
                                            accepted: None,
                                            reason: None,
                                            extra,
                                        };
                                        let _ = send_signal(&mut ws, &ice_msg).await;
                                    }
                                } else if peer_key.starts_with("stats:") {
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
                                    warn!(
                                        "dropping ICE candidate: no route for peer_key={} mobile={}",
                                        peer_key, mobile_device_id
                                    );
                                }
                            }
                        }
                    }
                }

                _ = claude_idle_tick.tick() => {
                    agent_router.sweep_idle_claude(claude_idle_ttl).await;
                }

                _ = ws_ping_tick.tick() => {
                    // Send a WS ping and arm a Pong deadline. A successful
                    // send only proves the local TLS buffer accepted bytes
                    // — on a CLOSE_WAIT'd socket writes still succeed
                    // silently. The real liveness signal is whether the
                    // server replies with a Pong before `WS_PONG_DEADLINE`;
                    // the watchdog tick enforces that.
                    let ping_result = tokio::time::timeout(
                        Duration::from_secs(10),
                        ws.send(Message::Ping(vec![].into())),
                    ).await;
                    match ping_result {
                        Ok(Ok(_)) => {
                            // Don't overwrite an earlier still-pending
                            // deadline — that one is the one that should
                            // fire if the server has gone silent.
                            if pending_ping_deadline.is_none() {
                                pending_ping_deadline = Some(Instant::now() + WS_PONG_DEADLINE);
                            }
                        }
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
                _ = ws_watchdog_tick.tick() => {
                    let now = Instant::now();
                    if now.duration_since(last_ws_message_at) > WS_READ_IDLE_LIMIT {
                        warn!(
                            "no ws traffic for >{}s — forcing reconnect",
                            WS_READ_IDLE_LIMIT.as_secs()
                        );
                        break;
                    }
                    if let Some(deadline) = pending_ping_deadline {
                        if now >= deadline {
                            warn!(
                                "ws pong missing >{}s after ping — forcing reconnect",
                                WS_PONG_DEADLINE.as_secs()
                            );
                            break;
                        }
                    }
                }

                incoming = recv_signal(&mut ws) => {
                    // Any frame — Signal, Pong, server-Ping (auto-replied),
                    // binary, or raw — is evidence the connection is alive.
                    // The watchdog above checks this timestamp; the read
                    // deadline lives there rather than inside recv_signal
                    // because select! cancellation makes a per-call timeout
                    // unsound (see comment on `recv_signal`).
                    last_ws_message_at = Instant::now();
                    match incoming {
                        Ok(WsRead::Signal(msg)) => {
                            info!("ws received: type={} session_id={:?}", msg.message_type, msg.session_id);
                            if msg.message_type == "daemon_kill" {
                                // Server-initiated shutdown (free-tier enforcement,
                                // account revocation, abuse takedown). Replaces the
                                // old HeartbeatAction::Kill HTTP path.
                                let reason = msg
                                    .reason
                                    .as_deref()
                                    .or_else(|| msg.extra.get("reason").and_then(|v| v.as_str()))
                                    .unwrap_or("backend_kill")
                                    .to_string();
                                info!("backend requested shutdown ({}) — stopping daemon", reason);
                                close_all_active_sessions(
                                    &mut store,
                                    &backend,
                                    &mut peer_session_routes,
                                    &mut session_ciphers,
                                    &mut sessions,
                                    &mut webrtc_mgr,
                                    &mut agent_ws_pumps,
                                    &agent_router,
                                )
                                .await;
                                if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                                    let _ = tokio::time::timeout(
                                        Duration::from_secs(3),
                                        backend.mark_offline(&token, &host_id),
                                    ).await;
                                }
                                drop(local_clients);
                                let _ = std::fs::remove_file(&local_sock_path);
                                let _ = write_audit_event_with_store(
                                    AuditEvent {
                                        reason: Some(reason.to_string()),
                                        ..AuditEvent::new("daemon_stopped")
                                    },
                                    &store,
                                );
                                store.save()?;
                                // Server-initiated stops are policy decisions
                                // (free idle sleep, revocation, abuse). Disable
                                // the boot service before exiting, otherwise
                                // launchd/systemd Restart=always resurrects us.
                                let _ = crate::service::uninstall();
                                return Ok(());
                            } else if msg.message_type == "summary_subscribe" {
                                if !summary_active {
                                    info!("summary subscription activated");
                                }
                                summary_active = true;
                            } else if msg.message_type == "summary_unsubscribe" {
                                if summary_active {
                                    info!("summary subscription paused (no mobile viewers)");
                                }
                                summary_active = false;
                            } else if msg.message_type == "stats_subscribe" {
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
                                    || (store.is_trusted(&stats_device_id)
                                        && store.device_has_permission(&stats_device_id, "stats"));
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
                                &turn_cache,
                                &shell,
                                &mut sessions,
                                msg,
                                &mut ws,
                                &mut webrtc_mgr,
                                &mut file_transfers,
                                &mut peer_session_routes,
                                &mut files_peer_hosts,
                                &mut files_peer_offer_ids,
                                &mut agent_peer_hosts,
                                &mut agent_peer_offer_ids,
                                &mut outbound_host_transfers,
                                &mut inbound_host_transfers,
                                &files_response_tx,
                                &direct_transfer_event_tx,
                                &mut session_ciphers,
                                &mut ws_auth_nonces,
                                &agent_router,
                                &mut agent_ws_pumps,
                                &agent_ws_out_tx,
                            ).await {
                                error!("control message handling failed: {}", err);
                            }
                        }
                        Ok(WsRead::Pong) => {
                            pending_ping_deadline = None;
                        }
                        Ok(WsRead::KeepAlive) => {
                            // server Ping (auto-replied), binary, or raw frame
                        }
                        Err(err) => {
                            warn!("control-plane read failed: {}", err);
                            break;
                        }
                    }
                }
                sig = &mut shutdown => {
                    info!("shutdown signal received, closing sessions ({})", sig);
                    close_all_active_sessions(
                        &mut store,
                        &backend,
                        &mut peer_session_routes,
                        &mut session_ciphers,
                        &mut sessions,
                        &mut webrtc_mgr,
                        &mut agent_ws_pumps,
                        &agent_router,
                    )
                    .await;
                    if let Ok(token) = store.access_token().map(|s| s.to_string()) {
                        if let Err(e) = tokio::time::timeout(
                            Duration::from_secs(3),
                            backend.mark_offline(&token, &host_id),
                        ).await {
                            warn!("failed to mark host offline: {}", e);
                        }
                    }
                    drop(local_clients);
                    let _ = std::fs::remove_file(&local_sock_path);
                    let reason = if sig == "SIGTERM" { "sigterm" } else { "sigint" };
                    let _ = write_audit_event_with_store(
                        AuditEvent {
                            reason: Some(reason.to_string()),
                            ..AuditEvent::new("daemon_stopped")
                        },
                        &store,
                    );
                    store.save()?;
                    return Ok(());
                }
            }
        }

        // Token refresh only changes the Authorization header used by the
        // control-plane WebSocket. Existing WebRTC terminal channels can keep
        // carrying PTY data, so reconnect the WS without detaching sessions.
        if disconnect_reason == ControlPlaneDisconnect::TokenRotated {
            stats_active = false;
            stats_deadline = None;
            // Default back to always-on summaries; the new connection's
            // backend will send `summary_unsubscribe` if no mobile viewer.
            summary_active = true;
            minute_stats_buffer.clear();
            continue;
        }

        warn!(
            "control-plane disconnected — will reconnect in {}s",
            backoff_secs
        );

        // Reset subscriptions on disconnect — both default back to their
        // initial state so the next connection's backend can re-gate them.
        stats_active = false;
        stats_deadline = None;
        summary_active = true;
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

// Refresh logic now lives in `crate::auth::safe_refresh_if_needed`, which adds
// cross-process locking + atomic state writes so concurrent refreshes from
// short-lived CLI commands and the daemon can't burn the rotation.

/// RAII flock on `paths.pid_file` so a second `daemon run` fails fast
/// instead of racing on the local-attach socket.
struct DaemonPidLock {
    _file: File,
    path: PathBuf,
}

impl Drop for DaemonPidLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn acquire_daemon_pid_lock() -> Result<DaemonPidLock> {
    let paths = AppConfig::paths()?;
    if !paths.state_dir.exists() {
        std::fs::create_dir_all(&paths.state_dir)?;
    }
    let pid_path = paths.pid_file.clone();
    // Held mutably so the pid stamp below can write through this SAME handle
    // (avoids a try_clone() that would sit outside the per-handle lock on
    // Windows, where fs2 uses LockFileEx).
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&pid_path)?;

    // Non-blocking exclusive lock; if another daemon already holds it, fail
    // fast rather than racing on the local-attach socket. Released when the
    // handle inside the returned guard drops.
    if let Err(err) = crate::platform::try_lock_exclusive(&file) {
        return Err(HostError::Config(format!(
            "another pocketshell daemon is running (pid file {}): {}",
            pid_path.display(),
            err
        )));
    }

    // Stamp our pid so external tools (`daemon stop`, status checks) see the
    // live owner. Write through the SAME handle we locked: on Windows fs2 uses
    // LockFileEx, whose lock is per-handle, so a `try_clone()`d handle's writes
    // would sit outside the lock. Reusing `file` keeps lock + write on one
    // handle on every platform.
    let pid = std::process::id().to_string();
    {
        file.set_len(0)
            .map_err(|e| HostError::Config(format!("truncate pid_file: {e}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| HostError::Config(format!("seek pid_file: {e}")))?;
        file.write_all(pid.as_bytes())
            .map_err(|e| HostError::Config(format!("write pid_file: {e}")))?;
    }

    Ok(DaemonPidLock {
        _file: file,
        path: pid_path,
    })
}

/// Rewrite a Claude stdout line so that embedded `tool_result` payloads keep a
/// bounded preview instead of the full body. Raw tool results can be hundreds
/// of KB (file contents, bash stdout, base64 images) and blow past the SCTP
/// max message size, killing the data channel mid-turn.
/// Conservative cap that leaves SCTP headroom while allowing larger streamed
/// agent frames through before truncation kicks in. webrtc-rs defaults to
/// `SCTP_MAX_MESSAGE_SIZE = 65535`; keeping a few KB in reserve covers framing
/// overhead and avoids flirting with the hard ceiling.
const OUTBOUND_LINE_SAFE_MAX: usize = 60 * 1024;
/// Longest individual string value we'll keep verbatim before truncating.
/// 4 KB is more than enough for tool names, paths, short outputs, etc.
const TRUNCATE_STRING_OVER: usize = 4 * 1024;

/// Walk the JSON value and replace any string longer than
/// `TRUNCATE_STRING_OVER` with a placeholder. Also collapses arrays that look
/// like content-part lists when they're the obvious culprit. Mutates in place
/// and reports whether anything changed.
fn truncate_oversized_strings(val: &mut serde_json::Value) -> bool {
    let mut changed = false;
    match val {
        serde_json::Value::String(s) => {
            if s.len() > TRUNCATE_STRING_OVER {
                let placeholder = format!("[truncated by pocketshell: {} bytes]", s.len());
                *s = placeholder;
                changed = true;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                if truncate_oversized_strings(item) {
                    changed = true;
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                if truncate_oversized_strings(v) {
                    changed = true;
                }
            }
        }
        _ => {}
    }
    changed
}

/// Safety net: if a stdout line is about to blow the SCTP cap, forcibly
/// truncate any oversized string values inside it. Returns the rewritten line
/// only when the input actually exceeded `OUTBOUND_LINE_SAFE_MAX`.
fn truncate_outbound_line_if_too_large(line: &str) -> Option<String> {
    if line.len() <= OUTBOUND_LINE_SAFE_MAX {
        return None;
    }
    let mut val: serde_json::Value = serde_json::from_str(line).ok()?;
    truncate_oversized_strings(&mut val);
    let out = serde_json::to_string(&val).ok()?;
    if out.len() >= line.len() {
        // Nothing salvageable (e.g. massive number of small fields). Drop a
        // summary envelope so the turn doesn't stall waiting for a frame the
        // peer will never accept.
        return Some(
            serde_json::json!({
                "type": "system",
                "subtype": "notification",
                "key": "outbound_truncated",
                "text": format!("[pocketshell dropped a {}-byte frame]", line.len()),
            })
            .to_string(),
        );
    }
    Some(out)
}

fn sanitize_claude_outbound_line(line: &str) -> Option<String> {
    // Cheap pre-check — skip the JSON parse on frames that can't contain
    // tool_result (the vast majority of deltas).
    if !line.contains("\"tool_result\"") && !line.contains("\"tool_use_result\"") {
        return None;
    }
    let mut val: serde_json::Value = serde_json::from_str(line).ok()?;
    let ty = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if ty != "user" && ty != "assistant" {
        return None;
    }
    let mut changed = false;

    // Inside message.content[] — tool_result items can carry image base64,
    // file contents, or bash stdout. Preserve a bounded preview by truncating
    // only oversized string fields inside the result payload.
    if let Some(content) = val
        .get_mut("message")
        .and_then(|m| m.get_mut("content"))
        .and_then(|c| c.as_array_mut())
    {
        for item in content.iter_mut() {
            let Some(obj) = item.as_object_mut() else {
                continue;
            };
            if obj.get("type").and_then(|v| v.as_str()) != Some("tool_result") {
                continue;
            }
            if let Some(inner) = obj.get_mut("content") {
                if truncate_oversized_strings(inner) {
                    changed = true;
                }
            }
        }
    }

    // Sibling `tool_use_result` field on the frame (Claude -p emits the
    // tool's output here too — redundant copy of message.content[].content).
    if let Some(tool_use_result) = val.get_mut("tool_use_result") {
        if truncate_oversized_strings(tool_use_result) {
            changed = true;
        }
    }

    if !changed {
        return None;
    }
    serde_json::to_string(&val).ok()
}

/// WebRTC-transport agent stdout pump. Reads the child's stdout Receiver and
/// forwards each line to `channel`. On send failure the channel is gone — just
/// exit; `AgentChannelClosed` will tear down the child. On natural EOF (child
/// exited cleanly) emit `agent_exit` and close the channel.
async fn spawn_webrtc_agent_pump(
    mut stdout_rx: tokio::sync::mpsc::Receiver<String>,
    channel: Arc<RTCDataChannel>,
    session: Arc<AgentSession>,
    agent_id: String,
    router: Arc<AgentRouter>,
) {
    let mut pump_seq: u64 = 0;
    let mut reached_eof = false;
    let is_claude = session.backend() == AgentBackend::Claude;
    let mut resume_id_noted = !is_claude;
    loop {
        let Some(line) = stdout_rx.recv().await else {
            reached_eof = true;
            break;
        };
        pump_seq += 1;
        if is_claude {
            agent_session::maybe_note_claude_resume_id(
                &router,
                &agent_id,
                &line,
                &mut resume_id_noted,
            )
            .await;
        }
        let line = if is_claude {
            sanitize_claude_outbound_line(&line).unwrap_or(line)
        } else {
            line
        };
        let line = match truncate_outbound_line_if_too_large(&line) {
            Some(safe) => {
                warn!(
                    agent = %agent_id,
                    seq = pump_seq,
                    original_bytes = line.len(),
                    new_bytes = safe.len(),
                    "agent pump -> mobile: oversized frame truncated",
                );
                safe
            }
            None => line,
        };
        let line_bytes = line.len();
        let mut framed = line.into_bytes();
        framed.push(b'\n');
        match channel.send(&bytes::Bytes::from(framed)).await {
            Ok(_) => {
                info!(
                    agent = %agent_id,
                    seq = pump_seq,
                    bytes = line_bytes,
                    "agent pump -> mobile ok",
                );
            }
            Err(e) => {
                if session.shutdown_requested() {
                    debug!(agent = %agent_id, "agent pump send failed during shutdown: {}", e);
                } else {
                    warn!(
                        agent = %agent_id,
                        seq = pump_seq,
                        bytes = line_bytes,
                        "agent pump -> mobile send FAILED, exiting: {}",
                        e,
                    );
                }
                break;
            }
        }
    }
    if reached_eof {
        let exit = session.exit_reason().await;
        let exit_msg = serde_json::json!({
            "type":"agent_exit",
            "agent_id": agent_id,
            "reason": AgentExitWire::from(exit.as_ref()),
            "detail": exit.as_ref().map(|r| format!("{r:?}")),
        });
        if let Ok(bytes) = serde_json::to_vec(&exit_msg) {
            let _ = channel.send(&bytes::Bytes::from(bytes)).await;
        }
        let _ = channel.close().await;
    }
}

/// WS-transport agent stdout pump. Mirrors `spawn_webrtc_agent_pump` but emits
/// `agent_output` / `agent_exit` signals instead of raw channel sends. On
/// send failure to `pump_tx` (unbounded — shouldn't happen outside shutdown)
/// the task exits without marking detached; WS transport doesn't need the
/// same drain coordination because signals don't backpressure the child.
async fn spawn_ws_agent_pump(
    mut stdout_rx: tokio::sync::mpsc::Receiver<String>,
    session: Arc<AgentSession>,
    agent_id: String,
    mobile_device_id: String,
    backend_session_id: Option<String>,
    pump_tx: tokio::sync::mpsc::UnboundedSender<SignalEnvelope>,
    router: Arc<AgentRouter>,
) {
    let is_claude = session.backend() == AgentBackend::Claude;
    let mut resume_id_noted = !is_claude;
    while let Some(line) = stdout_rx.recv().await {
        if is_claude {
            agent_session::maybe_note_claude_resume_id(
                &router,
                &agent_id,
                &line,
                &mut resume_id_noted,
            )
            .await;
        }
        let line = if is_claude {
            sanitize_claude_outbound_line(&line).unwrap_or(line)
        } else {
            line
        };
        let line = match truncate_outbound_line_if_too_large(&line) {
            Some(safe) => {
                warn!(
                    agent = %agent_id,
                    original_bytes = line.len(),
                    new_bytes = safe.len(),
                    "agent pump (ws) -> mobile: oversized frame truncated",
                );
                safe
            }
            None => line,
        };
        let mut extra = std::collections::HashMap::new();
        extra.insert("agentId".to_string(), serde_json::json!(agent_id));
        extra.insert(
            "target_mobile_device_id".to_string(),
            serde_json::json!(mobile_device_id),
        );
        extra.insert("line".to_string(), serde_json::json!(line));
        let envelope = SignalEnvelope {
            message_type: "agent_output".to_string(),
            session_id: backend_session_id.clone(),
            payload: None,
            state: None,
            accepted: None,
            reason: None,
            extra,
        };
        if pump_tx.send(envelope).is_err() {
            break;
        }
    }
    let exit = session.exit_reason().await;
    let mut extra = std::collections::HashMap::new();
    extra.insert("agentId".to_string(), serde_json::json!(agent_id));
    extra.insert(
        "target_mobile_device_id".to_string(),
        serde_json::json!(mobile_device_id),
    );
    extra.insert(
        "reason".to_string(),
        serde_json::json!(AgentExitWire::from(exit.as_ref())),
    );
    if let Some(detail) = exit.as_ref().map(|r| format!("{r:?}")) {
        extra.insert("detail".to_string(), serde_json::json!(detail));
    }
    let envelope = SignalEnvelope {
        message_type: "agent_exit".to_string(),
        session_id: backend_session_id,
        payload: None,
        state: None,
        accepted: None,
        reason: None,
        extra,
    };
    let _ = pump_tx.send(envelope);
}

async fn handle_signal(
    store: &mut StateStore,
    backend: &BackendClient,
    turn_cache: &TurnCredsCache,
    shell: &str,
    sessions: &mut SessionManager,
    msg: SignalEnvelope,
    ws: &mut crate::transport::WsStream,
    webrtc_mgr: &mut WebRtcManager,
    file_transfers: &mut HashMap<String, PendingFileTransfer>,
    peer_session_routes: &mut HashMap<String, String>,
    files_peer_hosts: &mut HashMap<String, String>,
    files_peer_offer_ids: &mut HashMap<String, String>,
    agent_peer_hosts: &mut HashMap<String, String>,
    agent_peer_offer_ids: &mut HashMap<String, String>,
    outbound_host_transfers: &mut HashMap<String, OutboundHostTransfer>,
    inbound_host_transfers: &mut HashMap<String, InboundHostTransfer>,
    files_response_tx: &tokio::sync::mpsc::UnboundedSender<SignalEnvelope>,
    direct_transfer_event_tx: &tokio::sync::mpsc::UnboundedSender<DirectHostTransferEvent>,
    session_ciphers: &mut HashMap<String, SessionCipher>,
    ws_auth_nonces: &mut HashMap<String, Instant>,
    agent_router: &Arc<AgentRouter>,
    agent_ws_pumps: &mut HashMap<String, tokio::task::JoinHandle<()>>,
    agent_ws_out_tx: &tokio::sync::mpsc::UnboundedSender<SignalEnvelope>,
) -> Result<()> {
    if ws_auth_required(&msg.message_type) {
        let mobile_device_id = msg
            .extra
            .get("mobile_device_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if mobile_device_id.is_empty() {
            warn!(
                "{} rejected: missing mobile_device_id for signed WS auth",
                msg.message_type
            );
            audit_authz_denied(
                store,
                "",
                &msg.message_type,
                "missing_mobile_device_id",
                msg.session_id.clone(),
            );
            return Ok(());
        }
        if let Err(reason) = verify_ws_message_auth(&msg, store, mobile_device_id, ws_auth_nonces) {
            warn!(
                "{} rejected: invalid signed WS auth for device {}: {}",
                msg.message_type, mobile_device_id, reason
            );
            // Classify the failure precisely. verify_ws_message_auth returns
            // a finite set of strings (see its match arms); we map each to one
            // of three event types. Substring matches on "signature"/"hash"
            // would mis-classify structural "missing payload_hash" errors as
            // crypto failures, so we use exact-match prefixes here.
            let event_type = classify_ws_auth_failure(&reason);
            let _ = write_audit_event_with_store(
                AuditEvent {
                    mobile_device_id: Some(mobile_device_id.to_string()),
                    session_id: msg.session_id.clone(),
                    target: Some(msg.message_type.clone()),
                    ..AuditEvent::new(event_type).denied(reason)
                },
                store,
            );
            return Ok(());
        }
        if let Some(permission) = ws_message_permission(&msg) {
            if !require_device_permission(store, mobile_device_id, permission, &msg.message_type) {
                return Ok(());
            }
        }
    }

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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "host_transfer_request",
                    "device_not_trusted",
                    None,
                );
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

            if transfer_id.is_empty()
                || dst_host_id.is_empty()
                || src_path.is_empty()
                || dst_path.is_empty()
            {
                let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id,
                    mobile_device_id,
                    ok: false,
                    bytes_written: 0,
                    error: Some("invalid direct transfer request".to_string()),
                });
                return Ok(());
            }

            let mobile_attestation = match extract_and_verify_mobile_attestation(
                store,
                &mobile_device_id,
                payload.get("mobile_attestation"),
            ) {
                Ok(attestation) => attestation,
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
            if mobile_attestation.transfer_id != transfer_id
                || mobile_attestation.dst_host_id != dst_host_id
                || !local_host_matches_attestation(
                    store,
                    &mobile_attestation.src_host_id,
                    &mobile_attestation.src_host_public_key,
                )
            {
                let _ = direct_transfer_event_tx.send(DirectHostTransferEvent::Result {
                    transfer_id,
                    mobile_device_id,
                    ok: false,
                    bytes_written: 0,
                    error: Some("host transfer attestation does not match request".to_string()),
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
            let (username, credential, _ttl, uris) = match turn_cache.get(backend, &token).await {
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
                    target_host_public_key: mobile_attestation.dst_host_public_key.clone(),
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
            extra.insert(
                "mobile_attestation".to_string(),
                serde_json::to_value(&mobile_attestation).unwrap_or(serde_json::Value::Null),
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "host_transfer_offer",
                    "device_not_trusted",
                    None,
                );
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
            let mobile_attestation = match extract_and_verify_mobile_attestation(
                store,
                &mobile_device_id,
                msg.extra.get("mobile_attestation"),
            ) {
                Ok(attestation) => attestation,
                Err(err) => {
                    warn!(
                        "host_transfer_offer rejected: invalid mobile attestation (transfer_id={}): {}",
                        transfer_id, err
                    );
                    let _ = write_audit_event_with_store(
                        AuditEvent {
                            mobile_device_id: Some(mobile_device_id.clone()),
                            target: Some(transfer_id.clone()),
                            details: Some(serde_json::json!({
                                "operation": "host_transfer_offer",
                                "stage": "mobile_attestation",
                            })),
                            ..AuditEvent::new("crypto.signature_failed").failed(err.to_string())
                        },
                        store,
                    );
                    let mut extra = std::collections::HashMap::new();
                    extra.insert(
                        "mobile_device_id".to_string(),
                        serde_json::json!(mobile_device_id),
                    );
                    let reject_msg = SignalEnvelope {
                        message_type: "host_transfer_result".to_string(),
                        session_id: None,
                        payload: Some(serde_json::json!({
                            "transfer_id": transfer_id,
                            "status": "error",
                            "error": "invalid host transfer attestation",
                        })),
                        state: None,
                        accepted: None,
                        reason: None,
                        extra,
                    };
                    let _ = send_signal(ws, &reject_msg).await;
                    return Ok(());
                }
            };
            if mobile_attestation.transfer_id != transfer_id
                || mobile_attestation.src_host_id != source_host_id
                || !local_host_matches_attestation(
                    store,
                    &mobile_attestation.dst_host_id,
                    &mobile_attestation.dst_host_public_key,
                )
            {
                warn!(
                    "host_transfer_offer rejected: mobile attestation does not match transfer {}",
                    transfer_id
                );
                let _ = write_audit_event_with_store(
                    AuditEvent {
                        mobile_device_id: Some(mobile_device_id.clone()),
                        target: Some(transfer_id.clone()),
                        details: Some(serde_json::json!({
                            "operation": "host_transfer_offer",
                            "stage": "attestation_mismatch",
                        })),
                        ..AuditEvent::new("crypto.signature_failed").failed("attestation_mismatch")
                    },
                    store,
                );
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                let reject_msg = SignalEnvelope {
                    message_type: "host_transfer_result".to_string(),
                    session_id: None,
                    payload: Some(serde_json::json!({
                        "transfer_id": transfer_id,
                        "status": "error",
                        "error": "host transfer attestation mismatch",
                    })),
                    state: None,
                    accepted: None,
                    reason: None,
                    extra,
                };
                let _ = send_signal(ws, &reject_msg).await;
                return Ok(());
            }
            if let Err(err) = verify_signed_sdp_payload(
                payload,
                &offer_sdp,
                "offer",
                &mobile_attestation.src_host_public_key,
            ) {
                warn!(
                    "host_transfer_offer rejected: SDP signature failed for source host {}: {}",
                    source_host_id, err
                );
                let _ = write_audit_event_with_store(
                    AuditEvent {
                        mobile_device_id: Some(mobile_device_id.clone()),
                        target: Some(transfer_id.clone()),
                        details: Some(serde_json::json!({
                            "operation": "host_transfer_offer",
                            "stage": "sdp_signature",
                            "source_host_id": source_host_id,
                        })),
                        ..AuditEvent::new("crypto.signature_failed").failed(err.to_string())
                    },
                    store,
                );
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                let reject_msg = SignalEnvelope {
                    message_type: "host_transfer_result".to_string(),
                    session_id: None,
                    payload: Some(serde_json::json!({
                        "transfer_id": transfer_id,
                        "status": "error",
                        "error": "host transfer offer signature failed",
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
            let (username, credential, _ttl, uris) = turn_cache.get(backend, &token).await?;
            let peer = WebRtcPeer::new(uris, username, credential).await?;
            {
                let transfer_id = transfer_id.clone();
                let event_tx = direct_transfer_event_tx.clone();
                peer.peer
                    .on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
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
            extra.insert(
                "target_host_id".to_string(),
                serde_json::json!(source_host_id),
            );
            extra.insert(
                "mobile_device_id".to_string(),
                serde_json::json!(mobile_device_id),
            );
            extra.insert(
                "mobile_attestation".to_string(),
                serde_json::to_value(&mobile_attestation).unwrap_or(serde_json::Value::Null),
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
                if let Some(mobile_device_id) =
                    msg.extra.get("mobile_device_id").and_then(|v| v.as_str())
                {
                    if transfer.mobile_device_id != mobile_device_id {
                        return Ok(());
                    }
                }
                if let Err(err) = verify_signed_sdp_payload(
                    payload,
                    &answer_sdp,
                    "answer",
                    &transfer.target_host_public_key,
                ) {
                    warn!(
                        "host_transfer_answer rejected: SDP signature failed for target host {}: {}",
                        transfer.target_host_id, err
                    );
                    let _ = write_audit_event_with_store(
                        AuditEvent {
                            mobile_device_id: Some(transfer.mobile_device_id.clone()),
                            target: Some(transfer_id.clone()),
                            details: Some(serde_json::json!({
                                "operation": "host_transfer_answer",
                                "stage": "sdp_signature",
                                "target_host_id": transfer.target_host_id,
                            })),
                            ..AuditEvent::new("crypto.signature_failed").failed(err.to_string())
                        },
                        store,
                    );
                    return Ok(());
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
                    if let Some(mobile_device_id) =
                        msg.extra.get("mobile_device_id").and_then(|v| v.as_str())
                    {
                        if transfer.mobile_device_id != mobile_device_id {
                            return Ok(());
                        }
                    }
                    let _ = transfer.peer.add_ice_candidate(candidate.clone()).await;
                } else if let Some(transfer) = inbound_host_transfers.get(&transfer_id) {
                    if let Some(mobile_device_id) =
                        msg.extra.get("mobile_device_id").and_then(|v| v.as_str())
                    {
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
            // `purpose` is new in phase 1: the backend forwards what mobile
            // sent. Some session types are signaling/data-channel anchors only
            // and do not need a PTY on the host.
            let purpose = msg
                .extra
                .get("purpose")
                .and_then(|v| v.as_str())
                .unwrap_or("terminal")
                .to_string();
            let is_agent_purpose = purpose == "agent";
            let is_utility_purpose = purpose == "utility";
            let is_passthrough_purpose = is_agent_purpose || is_utility_purpose;

            if !store.is_trusted(&mobile_device_id) {
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "session_request",
                    "device_not_trusted",
                    Some(session_id.clone()),
                );
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
            let required_permission = if is_utility_purpose {
                "sessions"
            } else {
                "shell"
            };
            if !store.device_has_permission(&mobile_device_id, required_permission) {
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "session_request",
                    &format!("permission_denied:{required_permission}"),
                    Some(session_id.clone()),
                );
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
                    reason: Some("permission_denied".to_string()),
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
            // For passthrough purposes, skip PTY spawn entirely. These
            // sessions exist only to anchor signaling / extra data channels.
            // They must not consume the finite PTY session budget.
            if is_passthrough_purpose {
                info!(
                    "session_request accepted without PTY (purpose={}) session={} mobile={}",
                    purpose, session_id, mobile_device_id,
                );
                let mut ack_extra = std::collections::HashMap::new();
                ack_extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                ack_extra.insert("purpose".to_string(), serde_json::json!(purpose));
                let ack = SignalEnvelope {
                    message_type: "session_ack".to_string(),
                    session_id: Some(session_id.clone()),
                    payload: None,
                    state: Some("approved".to_string()),
                    accepted: Some(true),
                    reason: None,
                    extra: ack_extra,
                };
                send_signal(ws, &ack).await?;

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

                let token = store.access_token()?.to_string();
                // Track the session record so state transitions still work,
                // but mark it non-persistent with no tmux name — nothing to
                // reattach if the mobile reconnects.
                store.upsert_session(SessionRecord {
                    session_id: session_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    state: SessionState::Connected,
                    updated_at: Utc::now(),
                    persistent: false,
                    tmux_session_name: None,
                });
                store.save()?;
                backend
                    .transition_session(&token, &session_id, SessionState::Connected, None)
                    .await?;

                let _ = write_audit_event_with_store(
                    AuditEvent {
                        mobile_device_id: Some(mobile_device_id),
                        session_id: Some(session_id),
                        details: Some(serde_json::json!({
                            "purpose": purpose,
                            "persistent": false,
                        })),
                        ..AuditEvent::new("session_started")
                    },
                    store,
                );
                store.save()?;
                return Ok(());
            }

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

                let _ = write_audit_event_with_store(
                    AuditEvent {
                        mobile_device_id: Some(mobile_device_id),
                        session_id: Some(session_id),
                        details: Some(serde_json::json!({
                            "purpose": purpose,
                            "persistent": is_persistent,
                        })),
                        ..AuditEvent::new("session_started")
                    },
                    store,
                );
            } else {
                let _ = backend
                    .transition_session(&token, &session_id, SessionState::Failed, None)
                    .await;
            }
            store.save()?;
        }
        // ── Agent-chat WS fallback (phase 2) ────────────────────────────────
        // Mirrors the data-channel path in the WebRtcEvent::AgentMessage arm,
        // but talks to mobile via signaling WS frames instead. Used when the
        // WebRTC peer/channel fails to come up within the mobile's timeout.
        "agent_init" => {
            let payload = msg.payload.clone().unwrap_or(serde_json::Value::Null);
            let agent_id = payload
                .get("agentId")
                .or_else(|| payload.get("agent_id"))
                .or_else(|| msg.extra.get("agentId"))
                .or_else(|| msg.extra.get("agent_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if agent_id.is_empty() {
                warn!("agent_init missing agentId");
                return Ok(());
            }
            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "agent_init rejected: device {} not trusted",
                    mobile_device_id
                );
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "agent_init",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }

            // Reject duplicates so a retry doesn't double-spawn.
            if agent_ws_pumps.contains_key(&agent_id) {
                debug!("agent_init for existing agent {} — ignored", agent_id);
                return Ok(());
            }

            let backend_str = payload
                .get("backend")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let backend_kind = match backend_str.as_str() {
                "codex" => AgentBackend::Codex,
                "claude" => AgentBackend::Claude,
                other => {
                    warn!("agent_init unknown backend {}", other);
                    let mut extra = std::collections::HashMap::new();
                    extra.insert("agentId".to_string(), serde_json::json!(agent_id));
                    extra.insert(
                        "target_mobile_device_id".to_string(),
                        serde_json::json!(mobile_device_id),
                    );
                    extra.insert("reason".to_string(), serde_json::json!("spawn_failed"));
                    extra.insert(
                        "detail".to_string(),
                        serde_json::json!(format!("unknown backend '{other}'")),
                    );
                    let envelope = SignalEnvelope {
                        message_type: "agent_exit".to_string(),
                        session_id: msg.session_id.clone(),
                        payload: None,
                        state: None,
                        accepted: None,
                        reason: None,
                        extra,
                    };
                    let _ = agent_ws_out_tx.send(envelope);
                    return Ok(());
                }
            };
            let cwd = payload
                .get("cwd")
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from);
            let resume_id = payload
                .get("resumeId")
                .or_else(|| payload.get("resume_id"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let model = payload
                .get("model")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let reasoning_effort = payload
                .get("reasoningEffort")
                .or_else(|| payload.get("reasoning_effort"))
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let cfg = AgentSpawnConfig {
                backend: backend_kind,
                cwd,
                resume_id,
                bundled_binary: agent_session::discover_bundled(backend_kind),
                id: Some(agent_id.clone()),
                model,
                reasoning_effort,
                backend_session_id: msg.session_id.clone(),
            };

            let spawn_err_signal = |e: &dyn std::fmt::Display| {
                let mut extra = std::collections::HashMap::new();
                extra.insert("agentId".to_string(), serde_json::json!(agent_id));
                extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                extra.insert("reason".to_string(), serde_json::json!("spawn_failed"));
                extra.insert("detail".to_string(), serde_json::json!(e.to_string()));
                SignalEnvelope {
                    message_type: "agent_exit".to_string(),
                    session_id: msg.session_id.clone(),
                    payload: None,
                    state: None,
                    accepted: None,
                    reason: None,
                    extra,
                }
            };

            let outcome = match agent_router.bind(agent_id.clone(), cfg).await {
                Ok(o) => o,
                Err(e) => {
                    warn!("agent_init bind failed agent={}: {}", agent_id, e);
                    let _ = agent_ws_out_tx.send(spawn_err_signal(&e));
                    return Ok(());
                }
            };
            let agent_session::BindOutcome {
                session,
                stdout_rx,
                reattached,
            } = outcome;

            // Emit an `agent_ready` so the mobile can run its post-init wiring
            // the same way as over the data channel.
            {
                let mut extra = std::collections::HashMap::new();
                extra.insert("agentId".to_string(), serde_json::json!(agent_id));
                extra.insert(
                    "target_mobile_device_id".to_string(),
                    serde_json::json!(mobile_device_id),
                );
                extra.insert("backend".to_string(), serde_json::json!(backend_str));
                extra.insert(
                    "launch".to_string(),
                    serde_json::json!(session.launch_description()),
                );
                extra.insert(
                    "agent_session_id".to_string(),
                    serde_json::json!(session.id()),
                );
                extra.insert("reattached".to_string(), serde_json::json!(reattached));
                let ready = SignalEnvelope {
                    message_type: "agent_ready".to_string(),
                    session_id: msg.session_id.clone(),
                    payload: None,
                    state: None,
                    accepted: None,
                    reason: None,
                    extra,
                };
                let _ = agent_ws_out_tx.send(ready);
            }

            let handle = tokio::spawn(spawn_ws_agent_pump(
                stdout_rx,
                session.clone(),
                agent_id.clone(),
                mobile_device_id.clone(),
                msg.session_id.clone(),
                agent_ws_out_tx.clone(),
                Arc::clone(agent_router),
            ));
            agent_ws_pumps.insert(agent_id, handle);
        }
        "agent_input" => {
            let payload = msg.payload.clone().unwrap_or(serde_json::Value::Null);
            let agent_id = payload
                .get("agentId")
                .or_else(|| payload.get("agent_id"))
                .or_else(|| msg.extra.get("agentId"))
                .or_else(|| msg.extra.get("agent_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if agent_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                if !mobile_device_id.is_empty() && !store.is_trusted(&mobile_device_id) {
                    audit_authz_denied(
                        store,
                        &mobile_device_id,
                        "agent_input",
                        "device_not_trusted",
                        None,
                    );
                }
                return Ok(());
            }
            let line = payload
                .get("line")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if let Err(e) = agent_router.send_line(&agent_id, line).await {
                warn!("agent_input send_line failed agent={}: {}", agent_id, e);
            }
        }
        "agent_close" => {
            let payload = msg.payload.clone().unwrap_or(serde_json::Value::Null);
            let agent_id = payload
                .get("agentId")
                .or_else(|| payload.get("agent_id"))
                .or_else(|| msg.extra.get("agentId"))
                .or_else(|| msg.extra.get("agent_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if agent_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                if !mobile_device_id.is_empty() && !store.is_trusted(&mobile_device_id) {
                    audit_authz_denied(
                        store,
                        &mobile_device_id,
                        "agent_close",
                        "device_not_trusted",
                        None,
                    );
                }
                return Ok(());
            }
            if let Some(handle) = agent_ws_pumps.remove(&agent_id) {
                handle.abort();
            }
            agent_router.close(&agent_id).await;
        }
        "host_control" => {
            // Direct backend-pushed host-management action. The backend
            // has already verified host ownership, trusted-device status,
            // and the `sessions` permission before dispatching this
            // message — see `app/api/routes/host_control.py`. Mirror the
            // trusted-device check locally as defense in depth.
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if mobile_device_id.is_empty() || !store.is_trusted(&mobile_device_id) {
                warn!(
                    "host_control rejected: mobile_device_id missing or not trusted ({})",
                    mobile_device_id
                );
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "host_control",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }
            let action = msg
                .extra
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            match action {
                "host_close_all_sessions" => {
                    info!(
                        "host_close_all_sessions requested by mobile={} (host_control)",
                        mobile_device_id
                    );
                    close_all_active_sessions(
                        store,
                        backend,
                        peer_session_routes,
                        session_ciphers,
                        sessions,
                        webrtc_mgr,
                        agent_ws_pumps,
                        agent_router,
                    )
                    .await;
                }
                "host_restart_agent" => {
                    info!(
                        "host_restart_agent requested by mobile={} (host_control)",
                        mobile_device_id
                    );
                    close_all_active_sessions(
                        store,
                        backend,
                        peer_session_routes,
                        session_ciphers,
                        sessions,
                        webrtc_mgr,
                        agent_ws_pumps,
                        agent_router,
                    )
                    .await;
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        exit_for_restart(crate::service::restart());
                    });
                }
                "host_update_agent" => {
                    // Self-update has been REMOVED from this unsigned backend WS
                    // path. host_control is not Ed25519-signed (see
                    // `ws_auth_required`), so a compromised backend could forge
                    // it — and a binary swap is the one host_control action with a
                    // consequence beyond DoS. Updates now travel ONLY over the
                    // Ed25519-authenticated P2P stats/control channels (the
                    // `host_update_agent` stats handler and the
                    // `host/update_agent` control RPC), exactly like reboot and
                    // kill_process, so the command is cryptographically bound to
                    // the paired device and the backend cannot trigger a binary
                    // swap. Reject forged/legacy requests here instead of acting.
                    warn!(
                        "host_update_agent over host_control is no longer supported \
                         (moved to the authenticated P2P channel); ignoring request \
                         from mobile={}",
                        mobile_device_id
                    );
                }
                other => {
                    warn!("host_control rejected: unknown action {:?}", other);
                }
            }
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "signal",
                    "device_not_trusted",
                    Some(session_id.clone()),
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "signal",
                    "no_pinned_public_key",
                    Some(session_id.clone()),
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
                    if bytes.starts_with(TERMINAL_KEEPALIVE_SENTINEL) {
                        trace!(
                            "terminal keepalive received via signaling for session {}",
                            session_id
                        );
                    } else if bytes.len() > 5 && bytes[0] == 0x00 && &bytes[1..5] == b"PSFT" {
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
                        "host_close_all_sessions" => {
                            info!(
                                "host_close_all_sessions requested by mobile={} (legacy signal channel)",
                                mobile_device_id
                            );
                            close_all_active_sessions(
                                store,
                                backend,
                                peer_session_routes,
                                session_ciphers,
                                sessions,
                                webrtc_mgr,
                                agent_ws_pumps,
                                agent_router,
                            )
                            .await;
                        }
                        "host_restart_agent" => {
                            info!(
                                "host_restart_agent requested by mobile={} (legacy signal channel)",
                                mobile_device_id
                            );
                            close_all_active_sessions(
                                store,
                                backend,
                                peer_session_routes,
                                session_ciphers,
                                sessions,
                                webrtc_mgr,
                                agent_ws_pumps,
                                agent_router,
                            )
                            .await;

                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(250)).await;
                                exit_for_restart(crate::service::restart());
                            });
                        }
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
                                let detached_device = store
                                    .state
                                    .sessions
                                    .iter()
                                    .find(|s| s.session_id == session_id)
                                    .map(|s| s.mobile_device_id.clone());
                                let _ = write_audit_event_with_store(
                                    AuditEvent {
                                        mobile_device_id: detached_device,
                                        session_id: Some(session_id),
                                        ..AuditEvent::new("session_detached")
                                    },
                                    store,
                                );
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
                            let ended_device = store
                                .state
                                .sessions
                                .iter()
                                .find(|s| s.session_id == session_id)
                                .map(|s| s.mobile_device_id.clone());
                            let _ = write_audit_event_with_store(
                                AuditEvent {
                                    mobile_device_id: ended_device,
                                    session_id: Some(session_id),
                                    ..AuditEvent::new("session_ended")
                                },
                                store,
                            );
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
                    let router = agent_router.clone();
                    let ctx = build_file_action_context(
                        store,
                        target_mobile_device_id.as_deref().unwrap_or(""),
                    );
                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        let result =
                            crate::files::handle_files_action_with_context(&payload, &router, &ctx)
                                .await;
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
            // Capability negotiation: snapshot-resume clients advertise
            // `resume_protocol: 2` in `extra`. Absent (old clients) => 1 => the
            // legacy raw-scrollback replay path below.
            let resume_protocol = msg
                .extra
                .get("resume_protocol")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);

            if !store.is_trusted(&mobile_device_id) {
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "session_join",
                    "device_not_trusted",
                    Some(session_id.clone()),
                );
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

                // Resume payload, sent ONLY to the joining device (not all viewers).
                if resume_protocol >= 2 {
                    // v2: a canonical screen snapshot (recent scrollback + visible
                    // screen + cursor) from the terminal mirror. The client resets
                    // its terminal and writes this — correct for TUI apps, with no
                    // duplication or garbled escapes (unlike the raw blob below).
                    if let Ok(snap) = sessions.capture_snapshot(&session_id) {
                        info!(
                            "session_join: sending session_snapshot for {} ({} bytes, alt_screen={})",
                            session_id,
                            snap.data.len(),
                            snap.alt_screen
                        );
                        let mut extra = std::collections::HashMap::new();
                        extra.insert(
                            "target_mobile_device_id".to_string(),
                            serde_json::json!(mobile_device_id),
                        );
                        let snapshot_msg = SignalEnvelope {
                            message_type: "session_snapshot".to_string(),
                            session_id: Some(session_id.clone()),
                            payload: Some(serde_json::json!({
                                "version": snap.version,
                                "cols": snap.cols,
                                "rows": snap.rows,
                                "alt_screen": snap.alt_screen,
                                "base_offset": snap.base_offset,
                                "data_b64": base64::engine::general_purpose::STANDARD.encode(&snap.data),
                            })),
                            state: None,
                            accepted: None,
                            reason: None,
                            extra,
                        };
                        let _ = send_signal(ws, &snapshot_msg).await;
                    }
                } else if let Ok(scrollback) = sessions.capture_scrollback(&session_id) {
                    // Legacy clients: raw scrollback replay blob (unchanged).
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

                // PCI-DSS 10.2.5 / NIST AU-2 require auditing every successful
                // session establishment, including reconnects to long-lived
                // tmux sessions. session_request emits session_started on
                // first connect; session_join emits session_resumed here.
                let _ = write_audit_event_with_store(
                    AuditEvent {
                        mobile_device_id: Some(mobile_device_id.clone()),
                        session_id: Some(session_id.clone()),
                        details: Some(serde_json::json!({
                            "reconnected": needs_reconnect,
                        })),
                        ..AuditEvent::new("session_resumed")
                    },
                    store,
                );
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "session_offer",
                    "device_not_trusted",
                    Some(sid.to_string()),
                );
                return Ok(());
            }
            peer_session_routes.insert(mobile_device_id.clone(), sid.to_string());

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    match turn_cache.get(backend, &token).await {
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "ice_candidate",
                    "device_not_trusted",
                    Some(sid.to_string()),
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "stats_offer",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    let peer_key = format!("stats:{mobile_device_id}");
                    match turn_cache.get(backend, &token).await {
                        Ok((username, credential, _ttl, uris)) => {
                            match webrtc_mgr
                                .handle_offer(
                                    &peer_key, uris, username, credential, offer_sdp,
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "files_offer",
                    "device_not_trusted",
                    None,
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
                    match turn_cache.get(backend, &token).await {
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
                                    extra.insert(
                                        "mobile_device_id".to_string(),
                                        serde_json::json!(mobile_device_id),
                                    );
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
        "agent_offer" => {
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
                    "agent_offer rejected: device {} is not trusted",
                    mobile_device_id
                );
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "agent_offer",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }

            let peer_key = format!("agent:{mobile_device_id}");
            agent_peer_hosts.insert(peer_key.clone(), host_id.clone());
            let offer_id = msg
                .payload
                .as_ref()
                .and_then(|payload| payload.get("offer_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if !offer_id.is_empty() {
                agent_peer_offer_ids.insert(peer_key.clone(), offer_id.clone());
            }

            if let Some(payload) = &msg.payload {
                if let Some(offer_sdp) = payload.get("sdp").and_then(|v| v.as_str()) {
                    let token = store.access_token()?.to_string();
                    match turn_cache.get(backend, &token).await {
                        Ok((username, credential, _ttl, uris)) => {
                            match webrtc_mgr
                                .handle_offer(
                                    &peer_key, uris, username, credential, offer_sdp, false,
                                )
                                .await
                            {
                                Ok(answer_sdp) if !answer_sdp.is_empty() => {
                                    let mut extra = std::collections::HashMap::new();
                                    extra.insert("host_id".to_string(), serde_json::json!(host_id));
                                    extra.insert(
                                        "mobile_device_id".to_string(),
                                        serde_json::json!(mobile_device_id),
                                    );
                                    let answer_payload = build_signed_sdp_payload(
                                        store,
                                        &answer_sdp,
                                        "answer",
                                        vec![("offer_id", serde_json::json!(offer_id))],
                                    );
                                    let answer_msg = SignalEnvelope {
                                        message_type: "agent_answer".to_string(),
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
                                    warn!("webrtc agent handle_offer failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("failed to fetch TURN credentials for agent: {}", e);
                        }
                    }
                }
            }
        }
        "agent_ice_candidate" => {
            let mobile_device_id = msg
                .extra
                .get("mobile_device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !store.is_trusted(&mobile_device_id) {
                warn!(
                    "agent_ice_candidate rejected: device {} is not trusted",
                    mobile_device_id
                );
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "agent_ice_candidate",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }

            if let Some(payload) = &msg.payload {
                if let Ok(candidate) = serde_json::from_value::<
                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                >(payload.clone())
                {
                    let peer_key = format!("agent:{mobile_device_id}");
                    if let Err(e) = webrtc_mgr.add_ice_candidate(&peer_key, candidate).await {
                        warn!("webrtc agent add_ice_candidate failed: {}", e);
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "files_ice_candidate",
                    "device_not_trusted",
                    None,
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "stats_ice_candidate",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }

            if let Some(payload) = &msg.payload {
                if let Ok(candidate) = serde_json::from_value::<
                    webrtc::ice_transport::ice_candidate::RTCIceCandidateInit,
                >(payload.clone())
                {
                    let peer_key = format!("stats:{mobile_device_id}");
                    if let Err(e) = webrtc_mgr.add_ice_candidate(&peer_key, candidate).await {
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "encrypted_file_payload",
                    "device_not_trusted",
                    None,
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
                    warn!(
                        "encrypted_file_payload: no cipher for session {}",
                        session_id
                    );
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
            let encrypt_and_build =
                |cipher: &mut SessionCipher,
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
            let router = agent_router.clone();
            let ctx = build_file_action_context(store, &mobile_device_id);
            tokio::spawn(async move {
                let start = std::time::Instant::now();
                let result =
                    crate::files::handle_files_action_with_context(&file_payload, &router, &ctx)
                        .await;
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
                    warn!(
                        "encrypted files: file op task dropped for req={}",
                        request_id
                    );
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

            match encrypt_and_build(
                cipher,
                &plaintext_to_encrypt,
                &session_id,
                &mobile_device_id,
            ) {
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
                audit_authz_denied(
                    store,
                    &mobile_device_id,
                    "x25519_public_key",
                    "device_not_trusted",
                    None,
                );
                return Ok(());
            }

            let session_id = match msg
                .payload
                .as_ref()
                .and_then(|p| p.get("session_id"))
                .and_then(|v| v.as_str())
            {
                Some(sid) => sid.to_string(),
                None => {
                    warn!("x25519_public_key: missing session_id");
                    return Ok(());
                }
            };

            let mobile_pub_b64 = match msg
                .payload
                .as_ref()
                .and_then(|p| p.get("public_key"))
                .and_then(|v| v.as_str())
            {
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

            // Send response with host's ephemeral public key and salt, signed
            // by the host identity so signaling cannot substitute keys.
            let host = match store.state.host.as_ref() {
                Some(host) if !host.private_key.is_empty() => host,
                _ => {
                    warn!("x25519_public_key: host identity private key unavailable");
                    session_ciphers.remove(&session_id);
                    return Ok(());
                }
            };
            let host_id = host.host_id.clone();
            let signed = match signaling_crypto::sign_x25519_key_response(
                &host.private_key,
                &host_id,
                &mobile_device_id,
                &session_id,
                mobile_pub_b64,
                &host_pub_b64,
                &salt_b64,
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    warn!("x25519_public_key: failed to sign key response: {}", e);
                    session_ciphers.remove(&session_id);
                    return Ok(());
                }
            };
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
                    "sig": signed.sig_b64,
                    "sig_nonce": signed.nonce_b64,
                    "sig_ts": signed.ts,
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
    mut reader: LocalReadHalf,
    tx: tokio::sync::mpsc::UnboundedSender<LocalClientEvent>,
) {
    use tokio::io::AsyncReadExt;

    let mut session_id = String::new();
    let mut header = [0u8; 5]; // type(1) + len(4)

    loop {
        // Read frame header with idle timeout to detect crashed clients
        let read_result =
            tokio::time::timeout(Duration::from_secs(300), reader.read_exact(&mut header)).await;
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

    let _ = tx.send(LocalClientEvent::Disconnected { client_id });
}

/// Build a WebRTC auth protocol message with the \x00PSAU sentinel prefix.
fn build_auth_message(json: &serde_json::Value) -> Vec<u8> {
    let json_bytes = serde_json::to_vec(json).unwrap_or_default();
    let mut msg = Vec::with_capacity(AUTH_SENTINEL.len() + json_bytes.len());
    msg.extend_from_slice(AUTH_SENTINEL);
    msg.extend_from_slice(&json_bytes);
    msg
}

fn build_terminal_keepalive_pong(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() <= TERMINAL_KEEPALIVE_SENTINEL.len()
        || !data.starts_with(TERMINAL_KEEPALIVE_SENTINEL)
    {
        return None;
    }

    let msg =
        serde_json::from_slice::<serde_json::Value>(&data[TERMINAL_KEEPALIVE_SENTINEL.len()..])
            .ok()?;
    if msg.get("type").and_then(|v| v.as_str()) != Some("ping") {
        return None;
    }

    let response = serde_json::json!({
        "type": "pong",
        "id": msg.get("id").cloned().unwrap_or(serde_json::Value::Null),
    });
    let json_bytes = serde_json::to_vec(&response).ok()?;
    let mut out = Vec::with_capacity(TERMINAL_KEEPALIVE_SENTINEL.len() + json_bytes.len());
    out.extend_from_slice(TERMINAL_KEEPALIVE_SENTINEL);
    out.extend_from_slice(&json_bytes);
    Some(out)
}

/// Tear down every active session on this host: kill PTYs, drop WebRTC
/// peers, stop agent pumps, and mark the corresponding backend rows
/// `ended`. Shared by the legacy `signal → channel=control` path and
/// the newer `host_control` REST-driven path.
async fn close_all_active_sessions(
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

/// Final step of `host_restart_agent`: terminate this process so the host
/// comes back up fresh.
///
/// `service::restart()` looks like a one-shot "restart everything for me"
/// call but has three exits with very different semantics, and getting any
/// of them wrong leaves the daemon in a hollow state — `close_all_active_sessions`
/// has already killed every PTY, dropped every WebRTC peer, aborted every
/// agent pump, and marked every backend session `Ended`. If we don't
/// actually die after that, the mobile UI shows "restart requested" but the
/// host is a zombie until somebody SSHes in.
///
/// - `Ok(RestartedService)` is effectively unreachable in practice:
///   `systemctl restart` / `launchctl kickstart -k` send SIGTERM to *us*
///   while we're awaiting the subprocess, so we'd be dead before observing
///   the return. We still `exit(0)` here as belt-and-suspenders against
///   any platform where the subprocess returns before signaling us.
/// - `Ok(StartedDaemon)` means a detached replacement has been forked;
///   exit so it can take over the daemon socket and the backend WS.
/// - `Err(_)` means none of the restart paths worked. Exiting non-zero
///   lets a `Restart=always` supervisor (the systemd units our installers
///   write all set this) respawn us. On unmanaged hosts the daemon dies
///   and needs a manual start, but that's strictly better than leaving a
///   hollowed-out process serving stale state.
fn exit_for_restart(result: Result<crate::service::RestartStatus>) -> ! {
    match result {
        Ok(crate::service::RestartStatus::RestartedService) => std::process::exit(0),
        Ok(crate::service::RestartStatus::StartedDaemon) => std::process::exit(0),
        Err(err) => {
            warn!(
                "host_restart_agent failed: {} — exiting to let supervisor relaunch",
                err
            );
            std::process::exit(1);
        }
    }
}

/// Single-flight guard for self-update. The install (download → atomic binary
/// swap, see `update::download_and_install`) stages into a per-PID directory
/// and renames over the running executable; two concurrent installs in the same
/// process would race that swap and could leave a partial/absent binary. The
/// old code awaited the install inline on the daemon's main loop, which
/// serialized it for free; now that both the stats and control channels spawn it
/// as a detached task, this flag restores the one-at-a-time invariant.
static UPDATE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Acquire [`UPDATE_IN_FLIGHT`] and spawn the install on success. Returns
/// `false` (without spawning) if an update is already running, so callers can
/// reject the duplicate. On a *successful* install the spawned task never
/// returns (it `exit_for_restart`s); on failure / already-up-to-date it releases
/// the guard so a later update can be attempted. Origin and version are pinned
/// to the latest signed build from our own repo — never taken from the message.
fn try_spawn_self_update(current_version: String) -> bool {
    if UPDATE_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return false;
    }
    tokio::spawn(async move {
        if install_agent_update(
            current_version,
            crate::update::DEFAULT_BASE_URL.to_string(),
            None,
        )
        .await
        {
            exit_for_restart(crate::service::restart());
        }
        // Install failed or already up to date — release so a future request
        // can retry. (On success the line above never returns.)
        UPDATE_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
    true
}

async fn install_agent_update(
    current_version: String,
    base_url: String,
    requested_version: Option<String>,
) -> bool {
    let info = match crate::update::check(&base_url, &current_version, requested_version.as_deref())
        .await
    {
        Ok(info) => info,
        Err(err) => {
            warn!("host_update_agent check failed: {}", err);
            return false;
        }
    };

    if info.up_to_date {
        info!(
            "host_update_agent: already up to date at {}",
            info.current_version
        );
        return false;
    }

    match crate::update::download_and_install(&info).await {
        Ok(installed) => {
            info!(
                "host_update_agent installed {} at {}; restarting",
                info.target_version,
                installed.display()
            );
            true
        }
        Err(err) => {
            warn!("host_update_agent install failed: {}", err);
            false
        }
    }
}

fn ws_message_permission_for(message_type: &str) -> Option<&'static str> {
    match message_type {
        "stats_offer" | "stats_ice_candidate" => Some("stats"),
        "session_offer"
        | "ice_candidate"
        | "signal"
        | "files_offer"
        | "files_ice_candidate"
        | "agent_offer"
        | "agent_ice_candidate"
        | "host_transfer_request"
        | "host_transfer_cancel"
        | "x25519_public_key"
        | "encrypted_file_payload"
        | "agent_init"
        | "agent_input"
        | "agent_close"
        | "session_join"
        | "session_event" => Some("shell"),
        _ => None,
    }
}

fn ws_auth_required(message_type: &str) -> bool {
    ws_message_permission_for(message_type).is_some()
}

fn ws_message_permission(msg: &SignalEnvelope) -> Option<&'static str> {
    ws_message_permission_for(msg.message_type.as_str())
}

fn device_permission_result(
    store: &StateStore,
    mobile_device_id: &str,
    permission: &str,
) -> std::result::Result<(), String> {
    if store.device_has_permission(mobile_device_id, permission) {
        Ok(())
    } else {
        Err(format!("permission_denied:{permission}"))
    }
}

fn require_device_permission(
    store: &StateStore,
    mobile_device_id: &str,
    permission: &str,
    context: &str,
) -> bool {
    match device_permission_result(store, mobile_device_id, permission) {
        Ok(()) => true,
        Err(_) => {
            warn!(
                "{} rejected: device {} lacks {} permission",
                context, mobile_device_id, permission
            );
            let _ = write_audit_event_with_store(
                AuditEvent {
                    mobile_device_id: Some(mobile_device_id.to_string()),
                    target: Some(context.to_string()),
                    details: Some(serde_json::json!({ "permission": permission })),
                    ..AuditEvent::new("authz.denied").denied("permission_denied")
                },
                store,
            );
            false
        }
    }
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(v) => v.to_string(),
        serde_json::Value::String(v) => serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into()),
        serde_json::Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        }
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    let key_json = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into());
                    let value_json =
                        canonical_json(map.get(key).unwrap_or(&serde_json::Value::Null));
                    format!("{key_json}:{value_json}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
    }
}

fn ws_payload_hash(payload: Option<&serde_json::Value>) -> String {
    let payload = payload.unwrap_or(&serde_json::Value::Null);
    let digest = Sha256::digest(canonical_json(payload).as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

fn verify_ws_message_auth(
    msg: &SignalEnvelope,
    store: &StateStore,
    mobile_device_id: &str,
    nonce_cache: &mut HashMap<String, Instant>,
) -> std::result::Result<(), String> {
    use base64::engine::general_purpose::STANDARD;

    if !store.is_trusted(mobile_device_id) {
        return Err("device is not trusted".to_string());
    }

    let auth = msg
        .extra
        .get("ws_auth")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing ws_auth".to_string())?;
    let version = auth.get("v").and_then(|v| v.as_i64()).unwrap_or_default();
    if version != 1 {
        return Err(format!("unsupported ws_auth version {version}"));
    }
    let nonce = auth
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing nonce".to_string())?;
    let ts = auth
        .get("ts")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "missing ts".to_string())?;
    let payload_hash = auth
        .get("payload_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing payload_hash".to_string())?;
    let signature_b64 = auth
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing signature".to_string())?;

    let now_ts = Utc::now().timestamp();
    let skew = now_ts.saturating_sub(ts).abs();
    if skew > WS_AUTH_MAX_SKEW_SECS {
        return Err(format!("timestamp out of range (|delta|={skew}s)"));
    }

    let expected_hash = ws_payload_hash(msg.payload.as_ref());
    if payload_hash != expected_hash {
        return Err("payload hash mismatch".to_string());
    }

    let host_id = msg
        .extra
        .get("host_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !host_id.is_empty() {
        if let Some(host) = store.state.host.as_ref() {
            if host.host_id != host_id {
                return Err("host_id mismatch".to_string());
            }
        }
    }

    let pub_key_b64 = store
        .get_device_public_key(mobile_device_id)
        .ok_or_else(|| "no device public key stored".to_string())?;
    let pub_key_bytes = STANDARD
        .decode(pub_key_b64)
        .map_err(|e| format!("invalid public key base64: {e}"))?;
    let pub_key_bytes: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .map_err(|e| format!("invalid ed25519 public key: {e}"))?;

    let sig_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|e| format!("invalid signature base64: {e}"))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| format!("invalid ed25519 signature: {e}"))?;

    let canonical = vec![
        WS_SIGNING_PREFIX.to_string(),
        host_id.to_string(),
        mobile_device_id.to_string(),
        msg.message_type.clone(),
        msg.session_id.as_deref().unwrap_or("").to_string(),
        msg.state.as_deref().unwrap_or("").to_string(),
        nonce.to_string(),
        ts.to_string(),
        payload_hash.to_string(),
    ]
    .join("|");

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| format!("ed25519 signature did not verify: {e}"))?;

    let now = Instant::now();
    // Amortize the O(n) sweep: only run it once the cache has grown past a
    // threshold, otherwise every signed WS message walks the entire map.
    // Bound: at WS_AUTH_NONCE_TTL=120s, 128 outstanding entries comfortably
    // covers steady-state traffic from one peer (incl. ICE flurries).
    const NONCE_SWEEP_THRESHOLD: usize = 128;
    if nonce_cache.len() >= NONCE_SWEEP_THRESHOLD {
        nonce_cache.retain(|_, seen_at| now.duration_since(*seen_at) <= WS_AUTH_NONCE_TTL);
    }
    let cache_key = format!("{mobile_device_id}:{nonce}");
    match nonce_cache.entry(cache_key) {
        std::collections::hash_map::Entry::Occupied(mut slot) => {
            if now.duration_since(*slot.get()) <= WS_AUTH_NONCE_TTL {
                return Err("replayed nonce".to_string());
            }
            slot.insert(now);
        }
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(now);
        }
    }

    Ok(())
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
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| format!("invalid ed25519 signature: {e}"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_gte_equal() {
        assert!(version_gte("1.2.3", "1.2.3"));
    }

    #[test]
    fn version_gte_current_newer() {
        assert!(version_gte("1.2.4", "1.2.3"));
        assert!(version_gte("2.0.0", "1.9.9"));
        assert!(version_gte("1.2.3.1", "1.2.3"));
    }

    #[test]
    fn version_gte_current_older() {
        assert!(!version_gte("1.2.2", "1.2.3"));
        assert!(!version_gte("0.9.9", "1.0.0"));
        assert!(!version_gte("1.2", "1.2.1"));
    }

    #[test]
    fn version_gte_handles_nonnumeric_as_zero() {
        // "abc" parses to 0 per the impl — treat as missing component.
        assert!(version_gte("1.0.0", "1.0.abc"));
        assert!(version_gte("1.0.abc", "1.0.0"));
    }

    #[test]
    fn classify_ws_auth_failure_replay_is_crypto_replay() {
        assert_eq!(
            classify_ws_auth_failure("replayed nonce"),
            "crypto.replay_detected"
        );
    }

    #[test]
    fn classify_ws_auth_failure_signature_paths_are_crypto() {
        assert_eq!(
            classify_ws_auth_failure("payload hash mismatch"),
            "crypto.signature_failed"
        );
        assert_eq!(
            classify_ws_auth_failure("ed25519 signature did not verify: bad sig"),
            "crypto.signature_failed"
        );
        assert_eq!(
            classify_ws_auth_failure("invalid ed25519 signature: short"),
            "crypto.signature_failed"
        );
        assert_eq!(
            classify_ws_auth_failure("invalid ed25519 public key: bad encoding"),
            "crypto.signature_failed"
        );
    }

    #[test]
    fn classify_ws_auth_failure_structural_errors_are_authz() {
        // The bug this guards: substring matching on "signature"/"hash"
        // mis-labels these structural problems as crypto failures.
        assert_eq!(
            classify_ws_auth_failure("missing signature"),
            "authz.denied"
        );
        assert_eq!(
            classify_ws_auth_failure("missing payload_hash"),
            "authz.denied"
        );
        assert_eq!(classify_ws_auth_failure("missing nonce"), "authz.denied");
        assert_eq!(classify_ws_auth_failure("missing ts"), "authz.denied");
        assert_eq!(classify_ws_auth_failure("missing ws_auth"), "authz.denied");
        assert_eq!(
            classify_ws_auth_failure("unsupported ws_auth version 2"),
            "authz.denied"
        );
        assert_eq!(classify_ws_auth_failure("host_id mismatch"), "authz.denied");
        assert_eq!(
            classify_ws_auth_failure("no device public key stored"),
            "authz.denied"
        );
        assert_eq!(
            classify_ws_auth_failure("timestamp out of range (|delta|=300s)"),
            "authz.denied"
        );
    }

    #[test]
    fn build_auth_message_prefixes_sentinel() {
        let val = serde_json::json!({"type": "challenge", "nonce": "abc"});
        let out = build_auth_message(&val);
        assert_eq!(&out[..AUTH_SENTINEL.len()], AUTH_SENTINEL);
        let body = &out[AUTH_SENTINEL.len()..];
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(parsed, val);
    }

    #[test]
    fn encode_decode_files_stream_frame_roundtrip() {
        let header = serde_json::json!({"op": "upload_chunk", "id": "t1", "i": 42});
        let payload = b"\x01\x02\x03binary\xffpayload\n\nend";
        let encoded = encode_files_stream_frame(&header, payload);
        assert_eq!(&encoded[..5], b"\x00PSFB");

        let decoded = decode_files_stream_frame(&encoded).expect("decodes");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn decode_files_stream_frame_rejects_missing_sentinel() {
        assert!(decode_files_stream_frame(b"bogus").is_none());
        assert!(decode_files_stream_frame(b"\x00PSXX{}\nfoo").is_none());
    }

    #[test]
    fn decode_files_stream_frame_rejects_missing_newline() {
        // Header without a trailing newline separator is unparseable.
        let bad = b"\x00PSFB{\"op\":\"x\"}no-newline-before-payload";
        assert!(decode_files_stream_frame(bad).is_none());
    }

    #[test]
    fn decode_framed_files_message_returns_utf8_for_non_sentinel() {
        let mut messages = HashMap::new();
        let out = decode_framed_files_message(&mut messages, "m1", b"hello world");
        assert_eq!(out.as_deref(), Some("hello world"));
    }

    #[test]
    fn decode_framed_files_message_assembles_chunked_payload() {
        let mut messages = HashMap::new();

        let start = b"\x00PSFC{\"op\":\"start\",\"id\":\"msg1\",\"chunks\":2}";
        assert!(decode_framed_files_message(&mut messages, "dev", start).is_none());

        let chunk0 = b"\x00PSFC{\"op\":\"chunk\",\"id\":\"msg1\",\"i\":0,\"d\":\"hello \"}";
        assert!(decode_framed_files_message(&mut messages, "dev", chunk0).is_none());

        let chunk1 = b"\x00PSFC{\"op\":\"chunk\",\"id\":\"msg1\",\"i\":1,\"d\":\"world\"}";
        assert!(decode_framed_files_message(&mut messages, "dev", chunk1).is_none());

        let end = b"\x00PSFC{\"op\":\"end\",\"id\":\"msg1\"}";
        let result = decode_framed_files_message(&mut messages, "dev", end);
        assert_eq!(result.as_deref(), Some("hello world"));
        // `end` should have cleaned up the pending message.
        assert!(messages.is_empty());
    }

    #[test]
    fn decode_framed_files_message_scopes_by_device_id() {
        let mut messages = HashMap::new();
        let start = b"\x00PSFC{\"op\":\"start\",\"id\":\"x\",\"chunks\":1}";
        decode_framed_files_message(&mut messages, "devA", start);

        // Same message id from a *different* device should not find the entry.
        let end = b"\x00PSFC{\"op\":\"end\",\"id\":\"x\"}";
        assert!(decode_framed_files_message(&mut messages, "devB", end).is_none());
        // But the original device can finalize.
        let got = decode_framed_files_message(&mut messages, "devA", end);
        assert_eq!(got.as_deref(), Some(""));
    }

    #[test]
    fn truncate_oversized_strings_replaces_large_leaf() {
        let big = "x".repeat(TRUNCATE_STRING_OVER + 10);
        let mut val = serde_json::json!({
            "small": "ok",
            "big": big,
            "nested": { "arr": ["short", "y".repeat(TRUNCATE_STRING_OVER + 1)] }
        });
        let changed = truncate_oversized_strings(&mut val);
        assert!(changed);
        assert_eq!(val["small"], serde_json::json!("ok"));
        assert!(val["big"]
            .as_str()
            .unwrap()
            .starts_with("[truncated by pocketshell:"));
        assert!(val["nested"]["arr"][1]
            .as_str()
            .unwrap()
            .starts_with("[truncated by pocketshell:"));
        // Short sibling untouched.
        assert_eq!(val["nested"]["arr"][0], serde_json::json!("short"));
    }

    #[test]
    fn truncate_outbound_line_passthrough_when_small() {
        let line = r#"{"hello":"world"}"#;
        assert!(truncate_outbound_line_if_too_large(line).is_none());
    }

    #[test]
    fn truncate_outbound_line_allows_frames_under_new_safe_cap() {
        let payload_len = OUTBOUND_LINE_SAFE_MAX - 1_024;
        let big = "a".repeat(payload_len);
        let line = serde_json::json!({"type": "out", "text": big}).to_string();
        assert!(
            truncate_outbound_line_if_too_large(&line).is_none(),
            "frame unexpectedly truncated at {} bytes",
            line.len()
        );
    }

    #[test]
    fn truncate_outbound_line_shrinks_large_frame() {
        let big = "a".repeat(OUTBOUND_LINE_SAFE_MAX + 1_000);
        let line = serde_json::json!({"type": "out", "text": big}).to_string();
        let out = truncate_outbound_line_if_too_large(&line).expect("shrinks");
        assert!(out.len() < line.len());
        assert!(out.contains("[truncated by pocketshell:"));
    }

    #[test]
    fn sanitize_claude_skips_lines_without_tool_result() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}"#;
        assert!(sanitize_claude_outbound_line(line).is_none());
    }

    #[test]
    fn sanitize_claude_truncates_tool_result_content() {
        let large = "a".repeat(TRUNCATE_STRING_OVER + 32);
        let line = serde_json::json!({
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "content": large},
                    {"type": "text", "text": "keep me"}
                ]
            }
        })
        .to_string();
        let sanitized = sanitize_claude_outbound_line(&line).expect("rewritten");
        let val: serde_json::Value = serde_json::from_str(&sanitized).unwrap();
        assert!(val["message"]["content"][0]["content"]
            .as_str()
            .unwrap()
            .starts_with("[truncated by pocketshell:"));
        // Sibling text item untouched.
        assert_eq!(
            val["message"]["content"][1]["text"],
            serde_json::json!("keep me")
        );
    }

    #[test]
    fn sanitize_claude_truncates_tool_use_result_sibling() {
        let large = "x".repeat(TRUNCATE_STRING_OVER + 64);
        let line = serde_json::json!({
            "type": "assistant",
            "tool_use_result": {"stdout": large, "code": 0},
            "message": {"content": []}
        })
        .to_string();
        let sanitized = sanitize_claude_outbound_line(&line).expect("rewritten");
        let val: serde_json::Value = serde_json::from_str(&sanitized).unwrap();
        assert!(val["tool_use_result"]["stdout"]
            .as_str()
            .unwrap()
            .starts_with("[truncated by pocketshell:"));
        assert_eq!(val["tool_use_result"]["code"], serde_json::json!(0));
    }

    #[test]
    fn sanitize_claude_ignores_wrong_type() {
        // Contains tool_result token but type is neither user nor assistant.
        let line = r#"{"type":"system","tool_use_result":{"x":1}}"#;
        assert!(sanitize_claude_outbound_line(line).is_none());
    }

    mod host_transfer_attestation_integration {
        //! Daemon-level glue tests for the mobile-as-introducer host transfer
        //! attestation (security audit finding B). The pure crypto path is
        //! covered in `signaling_crypto::tests`; these tests bind the helper
        //! `extract_and_verify_mobile_attestation` to a real `StateStore` so
        //! we also exercise the "mobile pubkey must be pinned locally"
        //! invariant — which is what closes the backend-MITM hole.
        use super::*;
        use crate::models::{
            AgentState, HostIdentity, HostTransferAttestation, TrustedDeviceRecord,
        };
        use base64::Engine;
        use chrono::Utc;
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        struct Fixture {
            store: StateStore,
            attestation: HostTransferAttestation,
            mobile_device_id: String,
            attestation_value: serde_json::Value,
            _tmp: tempfile::TempDir,
        }

        fn build_attestation(
            mobile_key: &SigningKey,
            mobile_device_id: &str,
            transfer_id: &str,
            src_host_id: &str,
            src_host_public_key: &str,
            dst_host_id: &str,
            dst_host_public_key: &str,
            expires_at: i64,
        ) -> HostTransferAttestation {
            let mut att = HostTransferAttestation {
                v: 1,
                mobile_device_id: mobile_device_id.into(),
                transfer_id: transfer_id.into(),
                src_host_id: src_host_id.into(),
                src_host_public_key: src_host_public_key.into(),
                dst_host_id: dst_host_id.into(),
                dst_host_public_key: dst_host_public_key.into(),
                expires_at,
                nonce: base64::engine::general_purpose::STANDARD.encode([0x42u8; 16]),
                sig: String::new(),
            };
            // Reproduce the canonical payload format from
            // signaling_crypto::canonical_host_transfer_attestation_payload.
            let canonical = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                signaling_crypto::HOST_TRANSFER_SIGNING_PREFIX,
                att.v,
                att.mobile_device_id,
                att.transfer_id,
                att.src_host_id,
                att.src_host_public_key,
                att.dst_host_id,
                att.dst_host_public_key,
                att.expires_at,
                att.nonce,
            );
            let sig = mobile_key.sign(canonical.as_bytes());
            att.sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
            att
        }

        fn make_fixture() -> Fixture {
            let mobile_key = SigningKey::generate(&mut OsRng);
            let mobile_pub_b64 = base64::engine::general_purpose::STANDARD
                .encode(mobile_key.verifying_key().to_bytes());
            let mobile_device_id = "mobile-A".to_string();

            // This host is the SOURCE in the transfer scenario.
            let src_host_id = "src-host-1".to_string();
            let src_host_public_key = "src-host-pub-key-b64".to_string();
            let dst_host_id = "dst-host-2".to_string();
            let dst_host_public_key = "dst-host-pub-key-b64".to_string();

            let state = AgentState {
                host: Some(HostIdentity {
                    host_id: src_host_id.clone(),
                    user_id: "u".into(),
                    hostname: "h".into(),
                    platform: "linux".into(),
                    app_version: "0.1.1".into(),
                    public_key: src_host_public_key.clone(),
                    private_key: String::new(),
                    registered_at: Utc::now(),
                }),
                trusted_devices: vec![TrustedDeviceRecord {
                    id: "td-1".into(),
                    host_id: src_host_id.clone(),
                    mobile_device_id: mobile_device_id.clone(),
                    approved_at: Some(Utc::now()),
                    revoked_at: None,
                    permissions_json: None,
                    device_public_key: Some(mobile_pub_b64.clone()),
                    created_at: Utc::now(),
                }],
                ..Default::default()
            };

            let tmp = tempfile::TempDir::new().unwrap();
            let store = StateStore::new_for_test(tmp.path().join("state.json"), state);

            let attestation = build_attestation(
                &mobile_key,
                &mobile_device_id,
                "transfer-xyz",
                &src_host_id,
                &src_host_public_key,
                &dst_host_id,
                &dst_host_public_key,
                Utc::now().timestamp() + 60,
            );
            let attestation_value = serde_json::to_value(&attestation).unwrap();

            Fixture {
                store,
                attestation,
                mobile_device_id,
                attestation_value,
                _tmp: tmp,
            }
        }

        #[test]
        fn extract_and_verify_accepts_valid_attestation() {
            let f = make_fixture();
            let out = extract_and_verify_mobile_attestation(
                &f.store,
                &f.mobile_device_id,
                Some(&f.attestation_value),
            )
            .expect("attestation should verify");
            assert_eq!(out.transfer_id, f.attestation.transfer_id);
            assert_eq!(out.src_host_public_key, f.attestation.src_host_public_key);
            assert_eq!(out.dst_host_public_key, f.attestation.dst_host_public_key);
        }

        #[test]
        fn extract_and_verify_rejects_when_mobile_not_pinned() {
            // The core defense: even if the attestation is well-formed and the
            // backend forwards a valid signature from SOME key, if that key
            // isn't the one pinned locally for the mobile device, reject.
            let mut f = make_fixture();
            f.store.state.trusted_devices.clear();
            let err = extract_and_verify_mobile_attestation(
                &f.store,
                &f.mobile_device_id,
                Some(&f.attestation_value),
            )
            .expect_err("must reject when mobile pubkey isn't locally pinned");
            let msg = format!("{err}");
            assert!(
                msg.contains("no mobile public key"),
                "unexpected error: {msg}"
            );
        }

        #[test]
        fn extract_and_verify_rejects_signed_by_attacker_key() {
            // Backend-forgery scenario: attacker signs an otherwise-valid
            // attestation with their OWN key. Local mobile pin must reject it.
            let f = make_fixture();
            let attacker = SigningKey::generate(&mut OsRng);
            let forged = build_attestation(
                &attacker,
                &f.mobile_device_id,
                &f.attestation.transfer_id,
                &f.attestation.src_host_id,
                &f.attestation.src_host_public_key,
                &f.attestation.dst_host_id,
                "EVIL-DST-PUBKEY", // attacker substitutes destination pubkey
                f.attestation.expires_at,
            );
            let forged_value = serde_json::to_value(&forged).unwrap();
            let err = extract_and_verify_mobile_attestation(
                &f.store,
                &f.mobile_device_id,
                Some(&forged_value),
            )
            .expect_err("attacker-signed attestation must not verify against pinned mobile key");
            assert!(format!("{err}").contains("invalid mobile transfer attestation"));
        }

        #[test]
        fn extract_and_verify_rejects_mobile_device_id_mismatch() {
            let f = make_fixture();
            let err = extract_and_verify_mobile_attestation(
                &f.store,
                "different-mobile-id",
                Some(&f.attestation_value),
            )
            .expect_err("device-id mismatch must be rejected");
            assert!(format!("{err}").contains("mobile device id mismatch"));
        }

        #[test]
        fn extract_and_verify_rejects_missing_attestation() {
            let f = make_fixture();
            let err = extract_and_verify_mobile_attestation(&f.store, &f.mobile_device_id, None)
                .expect_err("missing attestation must be rejected");
            assert!(format!("{err}").contains("missing mobile transfer attestation"));
        }

        #[test]
        fn local_host_matches_requires_host_id_and_pubkey() {
            let f = make_fixture();
            // Both match → ok.
            assert!(local_host_matches_attestation(
                &f.store,
                &f.attestation.src_host_id,
                &f.attestation.src_host_public_key,
            ));
            // Right host_id, wrong pubkey (backend swap attempt) → reject.
            assert!(!local_host_matches_attestation(
                &f.store,
                &f.attestation.src_host_id,
                "WRONG-PUBKEY",
            ));
            // Wrong host_id → reject.
            assert!(!local_host_matches_attestation(
                &f.store,
                "some-other-host",
                &f.attestation.src_host_public_key,
            ));
        }
    }
}
