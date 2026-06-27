use crate::audit::{write_audit_event_with_store, AuditEvent};
use crate::error::{HostError, Result};
use crate::models::{HostTransferAttestation, SignalEnvelope};
use crate::signaling_crypto;
use crate::store::StateStore;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tracing::warn;
use webrtc::data_channel::RTCDataChannel;

pub(super) const WS_SIGNING_PREFIX: &str = "pocketshell-ws-v1";
pub(super) const WS_AUTH_MAX_SKEW_SECS: i64 = 60;
pub(super) const WS_AUTH_NONCE_TTL: Duration = Duration::from_secs(120);

/// Classify a `verify_ws_message_auth` error string into a precise event type.
/// verify_ws_message_auth returns a fixed set of strings; matching by exact
/// prefix (not substring) avoids labelling structural errors like
/// "missing payload_hash" or "missing signature" as cryptographic failures.
pub(super) fn classify_ws_auth_failure(reason: &str) -> &'static str {
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
pub(super) fn audit_channel_auth(
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

pub(super) fn data_channel_auth_key(
    kind: &str,
    mobile_device_id: &str,
    channel: &Arc<RTCDataChannel>,
) -> String {
    format!("{kind}:{mobile_device_id}:{:p}", Arc::as_ptr(channel))
}

pub(super) fn clear_data_channel_auth(
    authenticated_channels: &mut HashSet<String>,
    pending_auth: &mut HashMap<String, (String, String)>,
    kind: &str,
    mobile_device_id: &str,
) {
    let legacy_key = format!("{kind}:{mobile_device_id}");
    let scoped_prefix = format!("{legacy_key}:");
    authenticated_channels.retain(|key| key != &legacy_key && !key.starts_with(&scoped_prefix));
    pending_auth.retain(|key, _| key != &legacy_key && !key.starts_with(&scoped_prefix));
}

/// Sentinel `mobile_device_id` for audit records where the requesting device
/// did not supply one (or supplied an empty string). Writing a literal value
/// instead of omitting the field lets SIEMs correlate anonymous probes —
/// `SELECT count(*) FROM audit GROUP BY mobile_device_id` will surface a
/// spike of `"(anonymous)"` entries when an attacker is enumerating without
/// presenting a device id.
pub(super) const AUDIT_ANONYMOUS_DEVICE: &str = "(anonymous)";

/// Emit an `authz.denied` audit event. Use at every rejection path where a
/// mobile device was refused — untrusted, no permission, bad signature, etc.
/// `operation` is what the device was trying to do (the message_type, action,
/// or channel kind); `reason` is a short machine-readable cause.
pub(super) fn audit_authz_denied(
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

/// If the host's private key is unavailable or signing fails, returns a plain
/// SDP payload (no signature) — preserves compatibility with legacy-paired
/// hosts where the private key may not be stored locally.
pub(super) fn build_signed_sdp_payload(
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

pub(super) fn verify_signed_sdp_payload(
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

pub(super) fn extract_and_verify_mobile_attestation(
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

pub(super) fn local_host_matches_attestation(
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

/// Sentinel prefix for challenge-response authentication messages on WebRTC channels.
pub(super) const AUTH_SENTINEL: &[u8] = b"\x00PSAU";
/// Sentinel prefix for terminal keepalive / latency messages.
pub(super) const TERMINAL_KEEPALIVE_SENTINEL: &[u8] = b"\x00PSKA";

/// Build a WebRTC auth protocol message with the \x00PSAU sentinel prefix.
pub(super) fn build_auth_message(json: &serde_json::Value) -> Vec<u8> {
    let json_bytes = serde_json::to_vec(json).unwrap_or_default();
    let mut msg = Vec::with_capacity(AUTH_SENTINEL.len() + json_bytes.len());
    msg.extend_from_slice(AUTH_SENTINEL);
    msg.extend_from_slice(&json_bytes);
    msg
}

pub(super) fn build_terminal_keepalive_pong(data: &[u8]) -> Option<Vec<u8>> {
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

pub(super) fn ws_message_permission_for(message_type: &str) -> Option<&'static str> {
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

pub(super) fn ws_auth_required(message_type: &str) -> bool {
    ws_message_permission_for(message_type).is_some()
}

pub(super) fn ws_message_permission(msg: &SignalEnvelope) -> Option<&'static str> {
    ws_message_permission_for(msg.message_type.as_str())
}

pub(super) fn device_permission_result(
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

pub(super) fn require_device_permission(
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

pub(super) fn canonical_json(value: &serde_json::Value) -> String {
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

pub(super) fn ws_payload_hash(payload: Option<&serde_json::Value>) -> String {
    let payload = payload.unwrap_or(&serde_json::Value::Null);
    let digest = Sha256::digest(canonical_json(payload).as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

pub(super) fn verify_ws_message_auth(
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
pub(super) fn verify_device_auth(
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
