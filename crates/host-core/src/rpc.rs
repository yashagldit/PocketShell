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
    matches!(method, "system/list_processes")
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
/// - `limit`: u32 — caller-supplied cap, clamped to [`crate::stats::LIST_PROCESSES_HARD_CAP`].
/// - `sort`: "cpu" | "mem" | "name" | "pid" — defaults to "cpu" (descending).
///
/// Response: `{ processes: [...], total: usize, truncated: bool, captured_at_ms: i64 }`.
pub fn handle_list_processes(
    collector: &mut crate::stats::StatsCollector,
    req: RpcRequest,
) -> RpcResponse {
    use crate::stats::ProcessSortKey;
    let id = req.id;
    let limit = req
        .params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);
    let sort = req
        .params
        .get("sort")
        .and_then(|v| v.as_str())
        .map(ProcessSortKey::parse)
        .unwrap_or(ProcessSortKey::Cpu);

    let (procs, total) = collector.list_processes(sort, limit);
    let truncated = total > procs.len();

    let result = serde_json::json!({
        "processes": procs,
        "total": total,
        "truncated": truncated,
        "captured_at_ms": now_ms(),
    });
    RpcResponse::ok(id, result)
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
    let output = std::process::Command::new("kill")
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

fn method_reboot(_params: &Value) -> std::result::Result<Value, RpcError> {
    tracing::info!("rpc system/reboot scheduled");
    // Try sudo -n reboot first (non-interactive); fall back to plain reboot.
    let sudo_try = std::process::Command::new("sudo")
        .args(["-n", "reboot"])
        .output();
    let sudo_ok = matches!(&sudo_try, Ok(out) if out.status.success());
    if sudo_ok {
        return Ok(serde_json::json!({ "scheduled": true }));
    }
    if let Ok(out) = &sudo_try {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        tracing::warn!("sudo reboot failed ({}): {}", out.status, stderr);
    }

    let plain = std::process::Command::new("reboot")
        .output()
        .map_err(|e| RpcError::internal(format!("reboot failed to spawn: {e}")))?;
    if !plain.status.success() {
        let stderr = String::from_utf8_lossy(&plain.stderr).trim().to_string();
        let code = if stderr.to_lowercase().contains("not permitted")
            || stderr.to_lowercase().contains("permission")
        {
            "permission_denied"
        } else {
            "internal"
        };
        return Err(RpcError::new(
            code,
            if stderr.is_empty() {
                format!("reboot exited with status {}", plain.status)
            } else {
                stderr
            },
        ));
    }
    Ok(serde_json::json!({ "scheduled": true }))
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
        assert!(!is_stateful_method("ping"));
        assert!(!is_stateful_method("system/kill_process"));
        assert!(!is_stateful_method("system/reboot"));
        assert!(!is_stateful_method("nope"));
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
    fn list_processes_returns_self_and_reports_total() {
        // Construct a real collector against the current process table — every
        // host running these tests has at least one process (us), so the result
        // must be non-empty and contain our own PID. We avoid a small `limit`
        // here because sort=pid + tiny limit would slice off the test process.
        let mut c = crate::stats::StatsCollector::new();
        let req = RpcRequest {
            id: "lp1".into(),
            method: "system/list_processes".into(),
            params: serde_json::json!({ "sort": "pid" }),
        };
        let resp = handle_list_processes(&mut c, req);
        assert_eq!(resp.id, "lp1");
        let result = resp.result.expect("ok response");
        let procs = result.get("processes").unwrap().as_array().unwrap();
        let total = result.get("total").unwrap().as_u64().unwrap() as usize;
        assert!(!procs.is_empty(), "expected at least one process");
        assert!(total >= procs.len(), "total must be >= returned count");

        // Truncated flag is set iff we trimmed (only happens above the hard cap).
        let truncated = result.get("truncated").unwrap().as_bool().unwrap();
        assert_eq!(truncated, total > procs.len());

        let own_pid = std::process::id();
        let saw_self = procs
            .iter()
            .any(|p| p.get("pid").and_then(|v| v.as_u64()) == Some(own_pid as u64));
        // On systems with more procs than the hard cap, sort=pid puts our
        // (higher) PID outside the window — only assert when not truncated.
        if !truncated {
            assert!(saw_self, "expected own pid {own_pid} in process list");
        }
    }

    #[test]
    fn list_processes_applies_caller_limit() {
        let mut c = crate::stats::StatsCollector::new();
        let req = RpcRequest {
            id: "lp1b".into(),
            method: "system/list_processes".into(),
            params: serde_json::json!({ "limit": 3 }),
        };
        let resp = handle_list_processes(&mut c, req);
        let result = resp.result.unwrap();
        let returned = result.get("processes").unwrap().as_array().unwrap().len();
        assert!(returned <= 3, "limit not applied: {returned}");
    }

    #[test]
    fn list_processes_sort_by_pid_is_ascending() {
        let mut c = crate::stats::StatsCollector::new();
        let req = RpcRequest {
            id: "lp2".into(),
            method: "system/list_processes".into(),
            params: serde_json::json!({ "sort": "pid", "limit": 20 }),
        };
        let resp = handle_list_processes(&mut c, req);
        let result = resp.result.unwrap();
        let procs = result.get("processes").unwrap().as_array().unwrap();
        let pids: Vec<u64> = procs
            .iter()
            .map(|p| p.get("pid").unwrap().as_u64().unwrap())
            .collect();
        let mut sorted = pids.clone();
        sorted.sort();
        assert_eq!(pids, sorted, "pid sort must be ascending");
    }

    #[test]
    fn list_processes_unknown_sort_falls_back_to_cpu() {
        // "cpu" is descending; unknown sort keys must not error and must
        // produce the same ordering as "cpu".
        let mut c = crate::stats::StatsCollector::new();
        let req = RpcRequest {
            id: "lp3".into(),
            method: "system/list_processes".into(),
            params: serde_json::json!({ "sort": "garbage", "limit": 10 }),
        };
        let resp = handle_list_processes(&mut c, req);
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
    fn list_processes_caps_at_hard_limit() {
        // Even if caller asks for a huge number, the server clamps to the cap.
        let mut c = crate::stats::StatsCollector::new();
        let req = RpcRequest {
            id: "lp4".into(),
            method: "system/list_processes".into(),
            params: serde_json::json!({ "limit": 999_999u64 }),
        };
        let resp = handle_list_processes(&mut c, req);
        let result = resp.result.unwrap();
        let returned = result.get("processes").unwrap().as_array().unwrap().len();
        assert!(returned <= crate::stats::LIST_PROCESSES_HARD_CAP);
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
