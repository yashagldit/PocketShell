//! Uniform JSON-RPC style envelopes for the `control-{mobile_device_id}` data channel.
//!
//! Phase B establishes the substrate; future phases will add more methods.
//!
//! Envelope shape:
//! - Request:  `{"id": "<str>", "method": "<str>", "params": <any>}`
//! - Success:  `{"id": "<str>", "result": <any>}`
//! - Error:    `{"id": "<str>", "error": {"code": "<str>", "message": "<str>"}}`

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wire protocol version exposed through `version/info`.
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;

/// Incoming request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Outbound response envelope. Either `result` or `error` is populated.
#[derive(Debug, Clone, Serialize)]
pub struct RpcResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// Error codes (string enum) surfaced to the mobile client.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl RpcError {
    pub fn new<C: Into<String>, M: Into<String>>(code: C, message: M) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn not_found<M: Into<String>>(m: M) -> Self {
        Self::new("not_found", m)
    }
    pub fn permission_denied<M: Into<String>>(m: M) -> Self {
        Self::new("permission_denied", m)
    }
    pub fn invalid_params<M: Into<String>>(m: M) -> Self {
        Self::new("invalid_params", m)
    }
    pub fn unknown_method<M: Into<String>>(m: M) -> Self {
        Self::new("unknown_method", m)
    }
    pub fn internal<M: Into<String>>(m: M) -> Self {
        Self::new("internal", m)
    }
}

impl RpcResponse {
    pub fn ok(id: String, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: String, error: RpcError) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// Parse a raw data-channel payload into an `RpcRequest`. Returns `None` if the
/// payload is not a valid RPC request (e.g. unrelated JSON or malformed).
pub fn parse_request(data: &[u8]) -> Option<RpcRequest> {
    let s = std::str::from_utf8(data).ok()?;
    serde_json::from_str::<RpcRequest>(s).ok()
}

/// True for methods that require borrowing the daemon's [`StatsCollector`]
/// and therefore cannot be dispatched through the stateless [`dispatch`]
/// fast path. The control-message handler in `daemon.rs` checks this and
/// routes stateful methods inline so it can pass `&mut StatsCollector`.
pub fn is_stateful_method(method: &str) -> bool {
    matches!(
        method,
        "system/list_processes" | "audit/list" | "ports/expose" | "ports/unexpose"
    )
}

/// Dispatch an RPC request to the matching handler.
///
/// Stateful methods (see [`is_stateful_method`]) are intercepted by the
/// daemon's event loop before reaching here so they can borrow shared
/// resources like `StatsCollector`; if one slips through we surface it as
/// `internal` rather than `unknown_method` to make the routing mistake loud.
pub async fn dispatch(req: RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let result: std::result::Result<Value, RpcError> = match req.method.as_str() {
        "ping" => Ok(method_ping()),
        "version/info" => Ok(method_version_info()),
        "system/kill_process" => method_kill_process(&req.params),
        "system/reboot" => method_reboot(&req.params),
        "ports/list_dev" => method_list_dev_ports(&req.params).await,
        m if is_stateful_method(m) => Err(RpcError::internal(format!(
            "stateful method '{m}' must be routed via the daemon event loop"
        ))),
        other => Err(RpcError::unknown_method(format!(
            "unknown RPC method: {other}"
        ))),
    };
    match result {
        Ok(v) => RpcResponse::ok(id, v),
        Err(e) => RpcResponse::err(id, e),
    }
}

/// Stateful handler for `system/list_processes`. Pulled out of [`dispatch`]
/// because it needs a live `StatsCollector` to compute meaningful CPU% (the
/// daemon's collector is already warm from the 2s stats stream tick).
///
/// Params (all optional):
/// - `sort`: "cpu" | "mem" | "name" | "pid" | "user" | "status" (default: "cpu")
/// - `dir`:  "asc" | "desc" (default: column-specific — usage cols desc, identifier cols asc)
/// - `offset`: u32 (default: 0) — skip the first N entries of the sorted list
/// - `limit`: u32 (default: [`crate::stats::LIST_PROCESSES_DEFAULT_LIMIT`])
///
/// Response: `{ processes, total, more, captured_at_ms }`. The mobile client
/// paginates by bumping `offset` until `more` is false; `total` is stable
/// inside the snapshot TTL window so it can drive a progress indicator.
pub fn handle_list_processes(
    collector: &mut crate::stats::StatsCollector,
    req: RpcRequest,
) -> RpcResponse {
    use crate::stats::{ProcessSortKey, SortDirection};
    let id = req.id;
    let sort = req
        .params
        .get("sort")
        .and_then(|v| v.as_str())
        .map(ProcessSortKey::parse)
        .unwrap_or(ProcessSortKey::Cpu);
    let dir = req
        .params
        .get("dir")
        .and_then(|v| v.as_str())
        .and_then(SortDirection::parse)
        .unwrap_or_else(|| sort.default_direction());
    let offset = req
        .params
        .get("offset")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(0);
    let limit = req
        .params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);

    let (procs, total, more) = collector.list_processes(sort, dir, offset, limit);

    let result = serde_json::json!({
        "processes": procs,
        "total": total,
        "more": more,
        "captured_at_ms": now_ms(),
    });
    RpcResponse::ok(id, result)
}

/// Maximum number of audit events returnable in a single `audit/list` page.
/// Sized so the worst-case response (with long target paths, detailed JSON
/// payloads, large reason strings ≈ 1 KB/event) stays under WebRTC-data's
/// 64 KB unfragmented send budget with headroom for the envelope.
pub const AUDIT_LIST_MAX_LIMIT: usize = 100;
/// Default page size when the mobile omits `limit`.
pub const AUDIT_LIST_DEFAULT_LIMIT: usize = 50;
/// Hard cap on `event_type_prefix` length. Short event-type taxonomies
/// (`files.`, `process.`, etc.) are well under this; the cap exists purely to
/// block an authenticated mobile from CPU-DOS'ing the daemon with a multi-MB
/// prefix that forces a fresh memcmp against every line in the audit log.
pub const AUDIT_LIST_MAX_PREFIX_LEN: usize = 64;

/// Stateful handler for `audit/list`. Pulled out of [`dispatch`] because it
/// needs the `StateStore` (to auto-fill host_id/user_id when auditing the read)
/// and the mobile_device_id (captured from the channel auth context) — neither
/// of which travels through the stateless dispatch path.
///
/// Async because the underlying audit-file read is wrapped in
/// [`tokio::task::spawn_blocking`]: up to 5 MB of synchronous file I/O must
/// not stall the daemon's main event loop (the stream tick + other channels
/// share it).
///
/// Params (all optional):
/// - `limit`: integer, clamped to [1, [`AUDIT_LIST_MAX_LIMIT`]], default
///   [`AUDIT_LIST_DEFAULT_LIMIT`].
/// - `before_ts`: RFC3339 timestamp; only returns events strictly older than
///   this. The mobile sets it to the `at` of the oldest event in the previous
///   page to walk further back in history.
/// - `event_type_prefix`: returns only events whose `event_type` starts with
///   this string. Capped to [`AUDIT_LIST_MAX_PREFIX_LEN`] bytes to bound
///   the per-line memcmp work.
///
/// Response: `{ events: [...], more: bool }`. `events` are newest-first.
/// Writes an `audit.read` event for the *initial* page (before_ts is None) so
/// each "open the audit viewer" action is itself auditable (NIST SP 800-53
/// AU-9); subsequent pagination calls do not emit audit.read events, which
/// keeps a viewer that walks the whole history from flooding the log and
/// evicting genuine operational events under the 5 MB rotation cap.
pub async fn handle_audit_list(
    store: &crate::store::StateStore,
    mobile_device_id: &str,
    req: RpcRequest,
) -> RpcResponse {
    let id = req.id;
    // Saturating u64→usize cast keeps the clamp meaningful on smaller targets;
    // u64::MAX saturates to usize::MAX before clamp pulls it down to the cap.
    let limit = req
        .params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| {
            usize::try_from(n)
                .unwrap_or(usize::MAX)
                .clamp(1, AUDIT_LIST_MAX_LIMIT)
        })
        .unwrap_or(AUDIT_LIST_DEFAULT_LIMIT);
    let before_ts = req
        .params
        .get("before_ts")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(b) = &before_ts {
        if chrono::DateTime::parse_from_rfc3339(b).is_err() {
            return RpcResponse::err(
                id,
                RpcError::invalid_params("before_ts must be an RFC3339 timestamp with timezone"),
            );
        }
    }
    let event_type_prefix = req
        .params
        .get("event_type_prefix")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(p) = &event_type_prefix {
        if p.len() > AUDIT_LIST_MAX_PREFIX_LEN {
            return RpcResponse::err(
                id,
                RpcError::invalid_params(format!(
                    "event_type_prefix exceeds {} bytes",
                    AUDIT_LIST_MAX_PREFIX_LEN
                )),
            );
        }
    }

    let paths = match crate::config::AppConfig::paths() {
        Ok(p) => p,
        Err(e) => {
            return RpcResponse::err(id, RpcError::internal(format!("audit paths: {e}")));
        }
    };

    // Move the audit-file read off the daemon's main event loop. The audit
    // log is bounded at 5 MB by rotation, but a cold-cache read of that on
    // slow storage can stall other select! arms for tens of milliseconds.
    let audit_file = paths.audit_file.clone();
    let before_ts_for_read = before_ts.clone();
    let prefix_for_read = event_type_prefix.clone();
    let read_result = tokio::task::spawn_blocking(move || {
        crate::audit::read_audit_tail(
            &audit_file,
            limit,
            before_ts_for_read.as_deref(),
            prefix_for_read.as_deref(),
        )
    })
    .await;

    let (events, more) = match read_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return RpcResponse::err(id, RpcError::internal(format!("audit read: {e}")));
        }
        Err(e) => {
            return RpcResponse::err(id, RpcError::internal(format!("audit spawn: {e}")));
        }
    };

    // Audit only the first (initial) page request. Paginated continuations
    // would otherwise spam the log on rapid scrolling and crowd out real
    // events under the rotation cap.
    if before_ts.is_none() {
        let mut access_event = crate::audit::AuditEvent::new("audit.read");
        access_event.mobile_device_id = Some(mobile_device_id.to_string());
        access_event.details = Some(serde_json::json!({
            "limit": limit,
            "returned": events.len(),
            "more": more,
            "event_type_prefix": event_type_prefix,
        }));
        if let Err(e) = crate::audit::write_audit_event_with_store(access_event, store) {
            // Don't fail the RPC — the mobile already has the data. Surface
            // the failure to operators so a broken audit pipeline is visible.
            tracing::warn!("audit.read self-audit write failed: {}", e);
        }
    }

    let result = serde_json::json!({
        "events": events,
        "more": more,
    });
    RpcResponse::ok(id, result)
}

/// Stateful handler for `ports/expose`. Adds `port` to the dev-server
/// forwarding allowlist as an **ephemeral** entry — mobile-initiated
/// exposures always clear on the next daemon restart.
///
/// ## Why mobile may expose at all (threat-model note)
///
/// The original Phase-2 design made `pocketshell expose` TTY-only so a stolen
/// phone could not make local services tunnelable without the operator typing
/// a command on the host. That bar is real but thin: the same paired phone
/// has a sudo-capable terminal channel, so a motivated attacker can run the
/// CLI (modulo the `POCKETSHELL_REMOTE_TERMINAL` guard) or just read the
/// service directly through the shell. Discovery + one-tap expose is the
/// single biggest activation gap in the dev-server flow, so we accept the
/// trade deliberately and compensate:
///
///   - mobile exposures are **ephemeral-only** (gone on daemon restart);
///     persistent entries still require the CLI/TUI on the host,
///   - the device's `shell` permission is re-checked per call (mid-session
///     revoke takes effect immediately),
///   - every grant is audited as `ports.exposed` with `source: "mobile_rpc"`
///     and the mobile_device_id, same trail as the CLI path.
///
/// Params: `{ port: u16 }`. Response: `{ port, ephemeral: true }`.
pub fn handle_expose_port(
    store: &crate::store::StateStore,
    mobile_device_id: &str,
    req: RpcRequest,
) -> RpcResponse {
    let id = req.id;
    let Some(port) = parse_port_param(&req.params) else {
        return RpcResponse::err(
            id,
            RpcError::invalid_params("missing or out-of-range `port` (1-65535)"),
        );
    };

    let entry = match crate::exposed_ports::ExposedPortsStore::add(port, true) {
        Ok(e) => e,
        Err(e) => {
            return RpcResponse::err(id, RpcError::internal(format!("allowlist write: {e}")));
        }
    };

    let mut ev = crate::audit::AuditEvent::new("ports.exposed");
    ev.mobile_device_id = Some(mobile_device_id.to_string());
    ev.target = Some(port.to_string());
    ev.details = Some(serde_json::json!({
        "port": port,
        "ephemeral": true,
        "source": "mobile_rpc",
    }));
    if let Err(e) = crate::audit::write_audit_event_with_store(ev, store) {
        tracing::warn!("ports.exposed audit write failed: {}", e);
    }

    RpcResponse::ok(
        id,
        serde_json::json!({ "port": port, "ephemeral": entry.ephemeral }),
    )
}

/// Stateful handler for `ports/unexpose`. Removes `port` from the allowlist
/// (whether the entry was ephemeral or persistent — revoking access from the
/// phone is always safe). Audited as `ports.unexposed`.
///
/// Params: `{ port: u16 }`. Response: `{ port, removed: bool }`.
pub fn handle_unexpose_port(
    store: &crate::store::StateStore,
    mobile_device_id: &str,
    req: RpcRequest,
) -> RpcResponse {
    let id = req.id;
    let Some(port) = parse_port_param(&req.params) else {
        return RpcResponse::err(
            id,
            RpcError::invalid_params("missing or out-of-range `port` (1-65535)"),
        );
    };

    let removed = match crate::exposed_ports::ExposedPortsStore::remove(port) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::err(id, RpcError::internal(format!("allowlist write: {e}")));
        }
    };

    if removed {
        let mut ev = crate::audit::AuditEvent::new("ports.unexposed");
        ev.mobile_device_id = Some(mobile_device_id.to_string());
        ev.target = Some(port.to_string());
        ev.details = Some(serde_json::json!({ "port": port, "source": "mobile_rpc" }));
        if let Err(e) = crate::audit::write_audit_event_with_store(ev, store) {
            tracing::warn!("ports.unexposed audit write failed: {}", e);
        }
    }

    RpcResponse::ok(id, serde_json::json!({ "port": port, "removed": removed }))
}

/// Extract a valid TCP port from `params.port`. Returns `None` for missing,
/// non-integer, zero, or > 65535 values.
fn parse_port_param(params: &Value) -> Option<u16> {
    let n = params.get("port")?.as_u64()?;
    if n == 0 || n > u16::MAX as u64 {
        return None;
    }
    Some(n as u16)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn method_ping() -> Value {
    serde_json::json!({ "pong": true, "ts": now_ms() })
}

fn method_version_info() -> Value {
    serde_json::json!({
        "host_agent": env!("CARGO_PKG_VERSION"),
        "protocol": CONTROL_PROTOCOL_VERSION,
    })
}

/// Stateless handler for `ports/list_dev`. Enumerates locally-listening TCP
/// ports, probes them, and returns only ports that answer as HTTP plus whether
/// each is already exposed for forwarding.
///
/// Read-only: this never exposes a port — that still requires a TTY action
/// (`pocketshell expose <port>`). See [`crate::dev_ports`] for the threat
/// model rationale.
///
/// Params (all optional):
/// - `probe`: bool — accepted for backward compatibility, but ignored. This
///   endpoint always probes so it never returns raw non-HTTP system listeners.
///
/// Response: `{ ports: [{ port, pid?, process_name?, is_exposed, is_http,
/// server_kind?, server_header?, probe_status? }], probed, captured_at_ms }`.
async fn method_list_dev_ports(params: &Value) -> std::result::Result<Value, RpcError> {
    let _requested_probe = params
        .get("probe")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let ports = crate::dev_ports::list_dev_ports(true).await;
    serde_json::to_value(&ports)
        .map(|ports| {
            serde_json::json!({
                "ports": ports,
                "probed": true,
                "captured_at_ms": now_ms(),
            })
        })
        .map_err(|e| RpcError::internal(format!("serialize dev ports: {e}")))
}

fn method_kill_process(params: &Value) -> std::result::Result<Value, RpcError> {
    let pid = params
        .get("pid")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RpcError::invalid_params("missing or non-integer `pid`"))?;
    let signal = params
        .get("signal")
        .and_then(|v| v.as_str())
        .unwrap_or("TERM");

    if pid <= 0 {
        return Err(RpcError::invalid_params(
            "non-positive PIDs target process groups; refused",
        ));
    }
    if pid == 1 {
        return Err(RpcError::permission_denied(
            "refusing to signal pid 1 (init/systemd)",
        ));
    }

    let sig_num = match signal {
        "TERM" | "15" | "" => "15",
        "KILL" | "9" => "9",
        "HUP" | "1" => "1",
        "INT" | "2" => "2",
        "QUIT" | "3" => "3",
        other => {
            return Err(RpcError::invalid_params(format!(
                "unsupported signal '{other}'; allowed: TERM, KILL, HUP, INT, QUIT"
            )));
        }
    };

    tracing::info!("rpc system/kill_process pid={} signal={}", pid, sig_num);
    let mut command = std::process::Command::new("kill");
    crate::platform::hide_command_window(&mut command);
    let output = command
        .arg(format!("-{}", sig_num))
        .arg(pid.to_string())
        .output()
        .map_err(|e| RpcError::internal(format!("kill command failed to spawn: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let code = if stderr.to_lowercase().contains("not permitted") {
            "permission_denied"
        } else if stderr.to_lowercase().contains("no such process") {
            "not_found"
        } else {
            "internal"
        };
        return Err(RpcError::new(
            code,
            if stderr.is_empty() {
                format!("kill exited with status {}", output.status)
            } else {
                stderr
            },
        ));
    }
    Ok(serde_json::json!({ "killed": true }))
}

/// Try to reboot the host using the most permissive mechanism available.
///
/// On Linux we try `systemctl reboot` first — it goes through logind/polkit,
/// which on most distros allows active local users (and often any user with
/// an inhibitor-less session) to reboot without a sudoers entry. This lets
/// the non-root daemon trigger reboots out of the box on a typical desktop /
/// home server. If polkit denies it (headless boxes, hardened polkit rules)
/// we fall back to `sudo -n reboot` for users who have a NOPASSWD entry,
/// and finally to plain `reboot` which only works when the daemon itself
/// runs as root.
///
/// macOS has no equivalent, so we skip straight to the sudo/reboot path.
///
/// Returns Ok on success, or Err with a stable code ("permission_denied" |
/// "internal") and the last command's stderr.
pub fn try_reboot() -> std::result::Result<(), (&'static str, String)> {
    fn classify(stderr: &str) -> &'static str {
        let lower = stderr.to_lowercase();
        if lower.contains("not permitted")
            || lower.contains("permission")
            || lower.contains("denied")
            || lower.contains("authentication")
        {
            "permission_denied"
        } else {
            "internal"
        }
    }

    let mut last_err: Option<(&'static str, String)> = None;

    if cfg!(target_os = "linux") {
        let mut command = std::process::Command::new("systemctl");
        crate::platform::hide_command_window(&mut command);
        match command.arg("reboot").output() {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                tracing::warn!("systemctl reboot failed ({}): {}", out.status, stderr);
                last_err = Some((classify(&stderr), stderr));
            }
            Err(e) => {
                tracing::warn!("systemctl not available: {}", e);
            }
        }
    }

    let mut command = std::process::Command::new("sudo");
    crate::platform::hide_command_window(&mut command);
    match command.args(["-n", "reboot"]).output() {
        Ok(out) if out.status.success() => return Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            tracing::warn!("sudo -n reboot failed ({}): {}", out.status, stderr);
            last_err = Some((classify(&stderr), stderr));
        }
        Err(e) => {
            tracing::warn!("sudo not available: {}", e);
        }
    }

    let mut command = std::process::Command::new("reboot");
    crate::platform::hide_command_window(&mut command);
    match command.output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let msg = if stderr.is_empty() {
                format!("reboot exited with status {}", out.status)
            } else {
                stderr
            };
            Err((classify(&msg), msg))
        }
        Err(e) => Err(last_err.unwrap_or(("internal", format!("reboot failed to spawn: {e}")))),
    }
}

fn method_reboot(_params: &Value) -> std::result::Result<Value, RpcError> {
    tracing::info!("rpc system/reboot scheduled");
    match try_reboot() {
        Ok(()) => Ok(serde_json::json!({ "scheduled": true })),
        Err((code, msg)) => Err(RpcError::new(code, msg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let req = RpcRequest {
            id: "r1".into(),
            method: "nope".into(),
            params: Value::Null,
        };
        let resp = dispatch(req).await;
        assert_eq!(resp.id, "r1");
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, "unknown_method");
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let req = RpcRequest {
            id: "r1".into(),
            method: "ping".into(),
            params: Value::Null,
        };
        let resp = dispatch(req).await;
        assert_eq!(resp.id, "r1");
        let result = resp.result.unwrap();
        assert_eq!(result.get("pong").and_then(|v| v.as_bool()), Some(true));
        assert!(result.get("ts").and_then(|v| v.as_i64()).is_some());
    }

    #[tokio::test]
    async fn version_info_has_protocol_version() {
        let req = RpcRequest {
            id: "v".into(),
            method: "version/info".into(),
            params: Value::Null,
        };
        let resp = dispatch(req).await;
        let result = resp.result.unwrap();
        assert_eq!(
            result.get("protocol").and_then(|v| v.as_u64()),
            Some(CONTROL_PROTOCOL_VERSION as u64)
        );
        assert!(result.get("host_agent").and_then(|v| v.as_str()).is_some());
    }

    #[tokio::test]
    async fn kill_rejects_pid_1() {
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": 1, "signal": "TERM"}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "permission_denied");
    }

    #[tokio::test]
    async fn kill_rejects_missing_pid() {
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "invalid_params");
    }

    #[tokio::test]
    async fn kill_rejects_unknown_signal() {
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": 999999, "signal": "BOGUS"}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "invalid_params");
        assert!(err.message.contains("unsupported signal"));
    }

    #[test]
    fn parse_request_handles_valid_json() {
        let data = br#"{"id":"x","method":"ping","params":null}"#;
        let req = parse_request(data).unwrap();
        assert_eq!(req.method, "ping");
    }

    #[test]
    fn parse_request_rejects_junk() {
        assert!(parse_request(b"not json").is_none());
    }

    #[test]
    fn parse_request_rejects_non_utf8() {
        // 0xFF is not valid UTF-8.
        assert!(parse_request(&[0xFFu8, 0xFEu8, 0xFDu8]).is_none());
    }

    #[test]
    fn parse_request_rejects_missing_required_fields() {
        // Missing `method` (required by serde).
        assert!(parse_request(br#"{"id":"x"}"#).is_none());
        // Missing `id`.
        assert!(parse_request(br#"{"method":"ping"}"#).is_none());
    }

    #[test]
    fn parse_request_defaults_params_to_null() {
        let req = parse_request(br#"{"id":"x","method":"ping"}"#).unwrap();
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn rpc_error_constructors_set_code() {
        assert_eq!(RpcError::not_found("m").code, "not_found");
        assert_eq!(RpcError::permission_denied("m").code, "permission_denied");
        assert_eq!(RpcError::invalid_params("m").code, "invalid_params");
        assert_eq!(RpcError::unknown_method("m").code, "unknown_method");
        assert_eq!(RpcError::internal("m").code, "internal");
    }

    #[test]
    fn rpc_response_serialization_skips_none() {
        let ok = RpcResponse::ok("a".into(), serde_json::json!({"x": 1}));
        let v = serde_json::to_value(&ok).unwrap();
        assert!(v.get("result").is_some());
        assert!(v.get("error").is_none());

        let err = RpcResponse::err("b".into(), RpcError::not_found("nope"));
        let v = serde_json::to_value(&err).unwrap();
        assert!(v.get("result").is_none());
        assert_eq!(v["error"]["code"], "not_found");
        assert_eq!(v["error"]["message"], "nope");
    }

    #[tokio::test]
    async fn kill_rejects_negative_pid() {
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": -5, "signal": "TERM"}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "invalid_params");
        assert!(
            err.message.to_lowercase().contains("process group")
                || err.message.to_lowercase().contains("non-positive")
        );
    }

    #[tokio::test]
    async fn kill_rejects_zero_pid() {
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": 0, "signal": "TERM"}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "invalid_params");
    }

    #[tokio::test]
    async fn kill_rejects_non_integer_pid() {
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": "abc"}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "invalid_params");
    }

    #[tokio::test]
    async fn kill_nonexistent_pid_maps_to_not_found_or_permission() {
        // PID 9_999_999 almost certainly does not exist; the underlying
        // `kill(1)` writes "No such process" → mapped to `not_found`. If
        // the platform surfaces a different error string we fall through
        // to `internal`; we only care that it's an error, not a success.
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": 9_999_999i64, "signal": "TERM"}),
        };
        let resp = dispatch(req).await;
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn kill_accepts_numeric_signal_aliases() {
        // Signal "15" is accepted as TERM. Using a non-existent pid so the
        // kill command itself errors, but the signal validation must pass.
        let req = RpcRequest {
            id: "k".into(),
            method: "system/kill_process".into(),
            params: serde_json::json!({"pid": 9_999_998i64, "signal": "15"}),
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        // Should not be invalid_params — the signal "15" is valid.
        assert_ne!(err.code, "invalid_params");
    }

    #[test]
    fn is_stateful_method_flags_list_processes() {
        assert!(is_stateful_method("system/list_processes"));
        assert!(is_stateful_method("ports/expose"));
        assert!(is_stateful_method("ports/unexpose"));
        assert!(!is_stateful_method("ping"));
        assert!(!is_stateful_method("system/kill_process"));
        assert!(!is_stateful_method("system/reboot"));
        assert!(!is_stateful_method("ports/list_dev"));
        assert!(!is_stateful_method("nope"));
    }

    /// Run `f` with home env vars pointed at a fresh tmpdir so the allowlist
    /// and audit writes land there instead of the developer's real
    /// `~/.pocketshell`. Mirrors the helper in `exposed_ports::tests`.
    fn with_isolated_home<F: FnOnce()>(f: F) {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        let prev_test_home = std::env::var_os("POCKETSHELL_TEST_HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        unsafe { std::env::set_var("USERPROFILE", tmp.path()) };
        unsafe { std::env::set_var("POCKETSHELL_TEST_HOME", tmp.path()) };
        std::fs::create_dir_all(tmp.path().join(".pocketshell")).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
            match prev_test_home {
                Some(v) => std::env::set_var("POCKETSHELL_TEST_HOME", v),
                None => std::env::remove_var("POCKETSHELL_TEST_HOME"),
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    fn port_req(method: &str, params: Value) -> RpcRequest {
        RpcRequest {
            id: "p1".into(),
            method: method.into(),
            params,
        }
    }

    #[test]
    fn expose_port_rpc_adds_ephemeral_entry() {
        with_isolated_home(|| {
            let store = crate::store::StateStore::load().unwrap();
            let resp = handle_expose_port(
                &store,
                "device-1",
                port_req("ports/expose", serde_json::json!({"port": 5173})),
            );
            let result = resp.result.expect("expose must succeed");
            assert_eq!(result.get("port").and_then(|v| v.as_u64()), Some(5173));
            // Mobile-initiated exposures are ALWAYS ephemeral — persistent
            // entries require the host CLI/TUI. Load-bearing security
            // property, not a default.
            assert_eq!(
                result.get("ephemeral").and_then(|v| v.as_bool()),
                Some(true)
            );
            assert!(crate::exposed_ports::ExposedPortsStore::is_allowed(5173).unwrap());
            let entries = crate::exposed_ports::ExposedPortsStore::list().unwrap();
            assert!(entries.iter().any(|p| p.port == 5173 && p.ephemeral));
        });
    }

    #[test]
    fn expose_port_rpc_rejects_missing_or_bad_port() {
        with_isolated_home(|| {
            let store = crate::store::StateStore::load().unwrap();
            for params in [
                serde_json::json!({}),
                serde_json::json!({"port": 0}),
                serde_json::json!({"port": 70000}),
                serde_json::json!({"port": "5173"}),
            ] {
                let resp = handle_expose_port(&store, "device-1", port_req("ports/expose", params));
                assert_eq!(resp.error.unwrap().code, "invalid_params");
            }
            assert!(crate::exposed_ports::ExposedPortsStore::list()
                .unwrap()
                .is_empty());
        });
    }

    #[test]
    fn unexpose_port_rpc_removes_and_reports() {
        with_isolated_home(|| {
            let store = crate::store::StateStore::load().unwrap();
            crate::exposed_ports::ExposedPortsStore::add(3000, false).unwrap();

            let resp = handle_unexpose_port(
                &store,
                "device-1",
                port_req("ports/unexpose", serde_json::json!({"port": 3000})),
            );
            let result = resp.result.unwrap();
            assert_eq!(result.get("removed").and_then(|v| v.as_bool()), Some(true));
            assert!(!crate::exposed_ports::ExposedPortsStore::is_allowed(3000).unwrap());

            // Second remove is a no-op, not an error.
            let resp = handle_unexpose_port(
                &store,
                "device-1",
                port_req("ports/unexpose", serde_json::json!({"port": 3000})),
            );
            let result = resp.result.unwrap();
            assert_eq!(result.get("removed").and_then(|v| v.as_bool()), Some(false));
        });
    }

    #[tokio::test]
    async fn dispatch_rejects_stateful_method_with_internal() {
        let req = RpcRequest {
            id: "lp".into(),
            method: "system/list_processes".into(),
            params: Value::Null,
        };
        let resp = dispatch(req).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, "internal");
        assert!(err.message.contains("stateful"));
    }

    #[test]
    fn list_processes_returns_a_page_and_reports_total() {
        let mut c = crate::stats::StatsCollector::new();
        let req = RpcRequest {
            id: "lp1".into(),
            method: "system/list_processes".into(),
            params: serde_json::json!({ "sort": "pid", "limit": 10 }),
        };
        let resp = handle_list_processes(&mut c, req);
        assert_eq!(resp.id, "lp1");
        let result = resp.result.expect("ok response");
        let procs = result.get("processes").unwrap().as_array().unwrap();
        let total = result.get("total").unwrap().as_u64().unwrap() as usize;
        let more = result.get("more").unwrap().as_bool().unwrap();
        assert!(!procs.is_empty(), "expected at least one process");
        assert!(
            procs.len() <= 10,
            "page size not respected: {}",
            procs.len()
        );
        assert!(total >= procs.len(), "total must be >= returned count");
        assert_eq!(more, total > procs.len());
    }

    #[test]
    fn list_processes_pagination_walks_full_table() {
        // Two sequential page fetches should cover the table without
        // duplicates: page1 + page2 (where page1 has all-but-one) yields
        // exactly `total` distinct PIDs.
        let mut c = crate::stats::StatsCollector::new();
        let page1 = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "p1".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({ "sort": "pid", "offset": 0, "limit": 5 }),
            },
        )
        .result
        .unwrap();
        let page2 = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "p2".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({ "sort": "pid", "offset": 5, "limit": 5 }),
            },
        )
        .result
        .unwrap();

        let total: usize = page1.get("total").unwrap().as_u64().unwrap() as usize;
        let collect_pids = |v: &serde_json::Value| -> Vec<u64> {
            v.get("processes")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.get("pid").unwrap().as_u64().unwrap())
                .collect()
        };
        let mut pids = collect_pids(&page1);
        pids.extend(collect_pids(&page2));
        let unique: std::collections::HashSet<_> = pids.iter().copied().collect();
        assert_eq!(unique.len(), pids.len(), "pages must not overlap");
        assert!(pids.len() <= total, "pages cannot exceed total");
    }

    #[test]
    fn list_processes_offset_past_end_returns_empty_page() {
        let mut c = crate::stats::StatsCollector::new();
        let resp = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "off".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({ "offset": 10_000_000u64, "limit": 50 }),
            },
        );
        let result = resp.result.unwrap();
        assert_eq!(
            result.get("processes").unwrap().as_array().unwrap().len(),
            0
        );
        assert_eq!(result.get("more").unwrap().as_bool().unwrap(), false);
    }

    #[test]
    fn list_processes_sort_pid_ascending() {
        let mut c = crate::stats::StatsCollector::new();
        let resp = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "lp2".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({ "sort": "pid", "limit": 20 }),
            },
        );
        let procs = resp
            .result
            .unwrap()
            .get("processes")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        let pids: Vec<u64> = procs
            .iter()
            .map(|p| p.get("pid").unwrap().as_u64().unwrap())
            .collect();
        let mut sorted = pids.clone();
        sorted.sort();
        assert_eq!(pids, sorted, "pid sort must be ascending by default");
    }

    #[test]
    fn list_processes_dir_desc_overrides_default() {
        let mut c = crate::stats::StatsCollector::new();
        let resp = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "lp_dir".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({ "sort": "pid", "dir": "desc", "limit": 20 }),
            },
        );
        let procs = resp
            .result
            .unwrap()
            .get("processes")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        let pids: Vec<u64> = procs
            .iter()
            .map(|p| p.get("pid").unwrap().as_u64().unwrap())
            .collect();
        for w in pids.windows(2) {
            assert!(w[0] >= w[1], "pid+desc must be descending: {:?}", pids);
        }
    }

    #[test]
    fn list_processes_unknown_sort_falls_back_to_cpu() {
        let mut c = crate::stats::StatsCollector::new();
        let resp = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "lp3".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({ "sort": "garbage", "limit": 10 }),
            },
        );
        assert!(resp.error.is_none());
        let procs = resp
            .result
            .unwrap()
            .get("processes")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        let cpus: Vec<f64> = procs
            .iter()
            .map(|p| p.get("cpu_percent").unwrap().as_f64().unwrap())
            .collect();
        for w in cpus.windows(2) {
            assert!(w[0] >= w[1], "cpu sort must be descending: {:?}", cpus);
        }
    }

    #[test]
    fn list_processes_default_page_size_applied() {
        // No explicit limit → server applies the default page size.
        let mut c = crate::stats::StatsCollector::new();
        let resp = handle_list_processes(
            &mut c,
            RpcRequest {
                id: "lp4".into(),
                method: "system/list_processes".into(),
                params: serde_json::json!({}),
            },
        );
        let returned = resp
            .result
            .unwrap()
            .get("processes")
            .unwrap()
            .as_array()
            .unwrap()
            .len();
        assert!(returned <= crate::stats::LIST_PROCESSES_DEFAULT_LIMIT);
    }

    #[tokio::test]
    async fn list_dev_ports_returns_array_shape() {
        // probe:false is accepted for older clients but ignored: discovery
        // must still probe so raw system listeners are not returned. The
        // actual HTTP port list depends on the test host, so we don't assert
        // contents.
        let req = RpcRequest {
            id: "ports".into(),
            method: "ports/list_dev".into(),
            params: serde_json::json!({ "probe": false }),
        };
        let resp = dispatch(req).await;
        assert_eq!(resp.id, "ports");
        assert!(
            resp.error.is_none(),
            "list_dev must not error: {:?}",
            resp.error
        );
        let result = resp.result.unwrap();
        assert!(result.get("ports").unwrap().is_array());
        assert_eq!(result.get("probed").and_then(|v| v.as_bool()), Some(true));
        assert!(result
            .get("captured_at_ms")
            .and_then(|v| v.as_i64())
            .is_some());
    }

    #[tokio::test]
    async fn dispatch_echoes_request_id() {
        let req = RpcRequest {
            id: "custom-id-42".into(),
            method: "ping".into(),
            params: Value::Null,
        };
        let resp = dispatch(req).await;
        assert_eq!(resp.id, "custom-id-42");
    }
}
