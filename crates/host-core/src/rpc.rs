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

/// Dispatch an RPC request to the matching handler.
///
/// The dispatcher is a plain `match` on `method` — simple and branch-predictable.
/// A hashmap-of-handlers was considered but is over-engineered for the current
/// handful of methods and requires `Box<dyn Fn>` acrobatics for async bodies;
/// we can refactor when method count climbs past ~10.
pub async fn dispatch(req: RpcRequest) -> RpcResponse {
    let id = req.id.clone();
    let result: std::result::Result<Value, RpcError> = match req.method.as_str() {
        "ping" => Ok(method_ping()),
        "version/info" => Ok(method_version_info()),
        "system/kill_process" => method_kill_process(&req.params),
        "system/reboot" => method_reboot(&req.params),
        other => Err(RpcError::unknown_method(format!(
            "unknown RPC method: {other}"
        ))),
    };
    match result {
        Ok(v) => RpcResponse::ok(id, v),
        Err(e) => RpcResponse::err(id, e),
    }
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
        assert!(err.message.to_lowercase().contains("process group")
            || err.message.to_lowercase().contains("non-positive"));
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
