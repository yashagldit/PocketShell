use crate::agent_session::{
    self, AgentExitWire, AgentRouter, AgentSession, Backend as AgentBackend,
};
use crate::models::SignalEnvelope;
use std::sync::Arc;
use tracing::{debug, info, warn};
use webrtc::data_channel::RTCDataChannel;

/// Rewrite a Claude stdout line so that embedded `tool_result` payloads keep a
/// bounded preview instead of the full body. Raw tool results can be hundreds
/// of KB (file contents, bash stdout, base64 images) and blow past the SCTP
/// max message size, killing the data channel mid-turn.
/// Conservative cap that leaves SCTP headroom while allowing larger streamed
/// agent frames through before truncation kicks in. webrtc-rs defaults to
/// `SCTP_MAX_MESSAGE_SIZE = 65535`; keeping a few KB in reserve covers framing
/// overhead and avoids flirting with the hard ceiling.
pub(super) const OUTBOUND_LINE_SAFE_MAX: usize = 60 * 1024;
/// Longest individual string value we'll keep verbatim before truncating.
/// 4 KB is more than enough for tool names, paths, short outputs, etc.
pub(super) const TRUNCATE_STRING_OVER: usize = 4 * 1024;

/// Walk the JSON value and replace any string longer than
/// `TRUNCATE_STRING_OVER` with a placeholder. Also collapses arrays that look
/// like content-part lists when they're the obvious culprit. Mutates in place
/// and reports whether anything changed.
pub(super) fn truncate_oversized_strings(val: &mut serde_json::Value) -> bool {
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
pub(super) fn truncate_outbound_line_if_too_large(line: &str) -> Option<String> {
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

pub(super) fn sanitize_claude_outbound_line(line: &str) -> Option<String> {
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
pub(super) async fn spawn_webrtc_agent_pump(
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
pub(super) async fn spawn_ws_agent_pump(
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
