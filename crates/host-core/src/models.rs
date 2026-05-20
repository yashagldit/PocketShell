use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub auth: Option<AuthState>,
    pub host: Option<HostIdentity>,
    pub pending_devices: Vec<TrustedDeviceRecord>,
    pub trusted_devices: Vec<TrustedDeviceRecord>,
    pub sessions: Vec<SessionRecord>,
    #[serde(default)]
    pub alert_thresholds: Vec<AlertThreshold>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub host_id: String,
    pub user_id: String,
    pub hostname: String,
    pub platform: String,
    pub app_version: String,
    pub public_key: String,
    #[serde(default)]
    pub private_key: String,
    pub registered_at: DateTime<Utc>,
}

/// Wire shape for the Strategy A pair-attestation. The canonical message
/// signed (and verified) is `pocketshell-pair-attest-v1|<code>|<host_pub>|
/// <nonce>|<ts>` — see `signaling_crypto::sign_pair_attestation` and the
/// matching mobile verifier at `mobile/src/services/pairAttestation.ts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairAttestation {
    pub sig: String,
    pub nonce: String,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingValidateRequest {
    pub code: String,
    pub hostname: String,
    pub platform: String,
    pub public_key: String,
    pub app_version: Option<String>,
    /// When set, indicates the host is already registered and wants to add a new
    /// mobile device's trust (device-add flow) rather than registering as a new host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// Skipped when None so old backends without this field keep accepting
    /// the request unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_attestation: Option<PairAttestation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostApiResponse {
    pub id: String,
    pub user_id: String,
    pub hostname: String,
    pub platform: String,
    pub public_key: String,
    pub app_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub status: String,
}

/// Combined response from pairing code validation: host info + auth tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingValidateResponse {
    #[serde(flatten)]
    pub host: HostApiResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: Option<String>,
    /// True when a device was added to an already-registered host (device-add flow).
    #[serde(default)]
    pub already_paired: bool,
    /// The mobile device's Ed25519 public key (base64), set during pairing.
    #[serde(default)]
    pub device_public_key: Option<String>,
    /// The mobile device ID that was paired.
    #[serde(default)]
    pub mobile_device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInitiatedCreateRequest {
    pub hostname: String,
    pub platform: String,
    pub public_key: String,
    pub app_version: String,
}

/// Body for the host-authenticated device-add endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInitiatedDeviceAddRequest {
    pub existing_host_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInitiatedCreateResponse {
    pub claim_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInitiatedStatusResponse {
    pub status: String,
    /// "new_host" | "device_add" — populated by backend on claimed responses.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub host: Option<HostApiResponse>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub mobile_device_id: Option<String>,
    #[serde(default)]
    pub device_public_key: Option<String>,
}

/// Result of polling the host-initiated pairing status endpoint.
pub enum HostInitiatedPollOutcome {
    Pending,
    Claimed(Box<HostInitiatedStatusResponse>),
    /// 410 Gone — claim was already delivered (or consumed).
    AlreadyDelivered,
    /// 404 — claim expired or invalid.
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDeviceRecord {
    pub id: String,
    pub host_id: String,
    pub mobile_device_id: String,
    pub approved_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub permissions_json: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_public_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub mobile_device_id: String,
    pub state: SessionState,
    pub updated_at: DateTime<Utc>,
    /// Whether this session should remain resumable after the viewer detaches.
    #[serde(default)]
    pub persistent: bool,
    /// Legacy tmux session name when persistence is delegated to tmux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_session_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Requested,
    Approved,
    Connecting,
    Connected,
    Detached,
    Ended,
    Failed,
}

impl SessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Detached => "detached",
            Self::Ended => "ended",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub host_id: String,
    pub active_sessions: usize,
    pub pending_devices: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub session_id: String,
    pub mobile_device_id: String,
    pub cols: u16,
    pub rows: u16,
    /// If set, attach to this tmux/screen session instead of spawning a new shell.
    pub attach_target: Option<AttachTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachTarget {
    pub session_type: String, // "tmux" or "screen"
    pub name: String,
}

/// Rich session info returned by the backend's active-sessions endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendSessionInfo {
    pub id: String,
    pub state: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub connection_mode: Option<String>,
    pub mobile_device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Seconds the process has been running
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_time_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIOStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    /// Per-second rates (None on first sample before a delta can be computed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent_per_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_recv_per_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIOStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
    /// Per-second rates (None on first sample before a delta can be computed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_bytes_per_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_bytes_per_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemperatureReading {
    pub label: String,
    pub temp_celsius: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_celsius: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub tcp_established: u32,
    pub tcp_time_wait: u32,
    pub tcp_close_wait: u32,
    pub tcp_listen: u32,
    pub tcp_total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedInUser {
    pub username: String,
    pub terminal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub hostname: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuCoreInfo {
    pub name: String,
    pub usage_percent: f32,
    pub frequency_mhz: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCounts {
    pub total: u32,
    pub running: u32,
    pub sleeping: u32,
    pub stopped: u32,
    pub zombie: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTimes {
    pub user_percent: f32,
    pub system_percent: f32,
    pub idle_percent: f32,
    pub iowait_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub cpu_usage_percent: f32,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_available_bytes: u64,
    pub memory_free_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub uptime_secs: u64,
    pub load_one: f64,
    pub load_five: f64,
    pub load_fifteen: f64,
    pub battery_percent: Option<f32>,
    pub collected_at: DateTime<Utc>,
    /// Per-process data for live stats mode. None for lightweight snapshots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcessInfo>>,
    /// Network I/O totals and rates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_io: Option<NetworkIOStats>,
    /// Disk I/O totals and rates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_io: Option<DiskIOStats>,
    /// Temperature sensor readings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperatures: Option<Vec<TemperatureReading>>,
    /// TCP connection counts by state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_connections: Option<NetworkConnection>,
    /// Currently logged-in users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_in_users: Option<Vec<LoggedInUser>>,
    /// Static OS information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_info: Option<OsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_per_core: Option<Vec<CpuCoreInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_counts: Option<TaskCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_times: Option<CpuTimes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    pub metric: String,
    pub threshold_value: f64,
    pub comparison: String,
    pub cooldown_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    pub metric: String,
    pub threshold_value: f64,
    pub actual_value: f64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    #[serde(rename = "type")]
    pub message_type: String,
    pub session_id: Option<String>,
    pub payload: Option<serde_json::Value>,
    pub state: Option<String>,
    pub accepted: Option<bool>,
    pub reason: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn sample_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap()
    }

    #[test]
    fn agent_state_default_is_empty() {
        let state = AgentState::default();
        assert!(state.auth.is_none());
        assert!(state.host.is_none());
        assert!(state.pending_devices.is_empty());
        assert!(state.trusted_devices.is_empty());
        assert!(state.sessions.is_empty());
        assert!(state.alert_thresholds.is_empty());
    }

    #[test]
    fn agent_state_missing_alert_thresholds_defaults_to_empty() {
        // alert_thresholds has #[serde(default)] — old state files lack it.
        let raw = r#"{
            "auth": null,
            "host": null,
            "pending_devices": [],
            "trusted_devices": [],
            "sessions": []
        }"#;
        let state: AgentState = serde_json::from_str(raw).unwrap();
        assert!(state.alert_thresholds.is_empty());
    }

    #[test]
    fn auth_state_roundtrip_preserves_fields() {
        let auth = AuthState {
            access_token: "acc".into(),
            refresh_token: "ref".into(),
            access_expires_at: Some(sample_time()),
        };
        let json = serde_json::to_string(&auth).unwrap();
        let back: AuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.access_token, "acc");
        assert_eq!(back.refresh_token, "ref");
        assert_eq!(back.access_expires_at, Some(sample_time()));
    }

    #[test]
    fn auth_state_null_expiry_is_accepted() {
        let raw = r#"{"access_token":"a","refresh_token":"b","access_expires_at":null}"#;
        let auth: AuthState = serde_json::from_str(raw).unwrap();
        assert!(auth.access_expires_at.is_none());
    }

    #[test]
    fn session_state_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&SessionState::Connected).unwrap(),
            "\"connected\""
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Requested).unwrap(),
            "\"requested\""
        );
        let parsed: SessionState = serde_json::from_str("\"detached\"").unwrap();
        assert_eq!(parsed, SessionState::Detached);
    }

    #[test]
    fn session_state_as_str_matches_serialization() {
        for state in [
            SessionState::Requested,
            SessionState::Approved,
            SessionState::Connecting,
            SessionState::Connected,
            SessionState::Detached,
            SessionState::Ended,
            SessionState::Failed,
        ] {
            let via_serde: String =
                serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
            assert_eq!(via_serde, state.as_str());
        }
    }

    #[test]
    fn session_state_unknown_variant_errors() {
        let err = serde_json::from_str::<SessionState>("\"nonsense\"");
        assert!(err.is_err());
    }

    #[test]
    fn pairing_validate_request_skips_none_host_id() {
        let req = PairingValidateRequest {
            code: "ABC".into(),
            hostname: "box".into(),
            platform: "linux".into(),
            public_key: "pk".into(),
            app_version: None,
            host_id: None,
            pair_attestation: None,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(
            v.get("host_id").is_none(),
            "host_id should be skipped when None"
        );
        // pair_attestation also has skip_serializing_if so old backends keep parsing.
        assert!(v.get("pair_attestation").is_none());
        // app_version doesn't have skip_serializing_if, so it should be present as null.
        assert!(v.get("app_version").is_some());
        assert!(v["app_version"].is_null());
    }

    #[test]
    fn pairing_validate_request_includes_host_id_when_some() {
        let req = PairingValidateRequest {
            code: "C".into(),
            hostname: "h".into(),
            platform: "p".into(),
            public_key: "k".into(),
            app_version: Some("1.0".into()),
            host_id: Some("host-123".into()),
            pair_attestation: Some(crate::models::PairAttestation {
                sig: "s".into(),
                nonce: "n".into(),
                ts: 1700000000,
            }),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["host_id"], "host-123");
        assert_eq!(v["pair_attestation"]["sig"], "s");
        assert_eq!(v["pair_attestation"]["nonce"], "n");
        assert_eq!(v["pair_attestation"]["ts"], 1700000000);
    }

    #[test]
    fn pairing_validate_response_flattens_host_fields() {
        // The flattened HostApiResponse means `id`, `user_id`, etc. live at the
        // top level alongside access_token.
        let raw = json!({
            "id": "host-1",
            "user_id": "user-1",
            "hostname": "box",
            "platform": "linux",
            "public_key": "pk",
            "app_version": "1.0",
            "created_at": "2024-01-01T00:00:00Z",
            "last_seen_at": null,
            "status": "online",
            "access_token": "at",
            "refresh_token": "rt",
            "token_type": "bearer"
        });
        let resp: PairingValidateResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(resp.host.id, "host-1");
        assert_eq!(resp.host.user_id, "user-1");
        assert_eq!(resp.access_token, "at");
        assert!(!resp.already_paired); // default
        assert!(resp.device_public_key.is_none());
        assert!(resp.mobile_device_id.is_none());
    }

    #[test]
    fn host_identity_private_key_defaults_to_empty() {
        let raw = json!({
            "host_id": "h",
            "user_id": "u",
            "hostname": "hn",
            "platform": "linux",
            "app_version": "1",
            "public_key": "pk",
            "registered_at": "2024-01-01T00:00:00Z"
        });
        let id: HostIdentity = serde_json::from_value(raw).unwrap();
        assert_eq!(id.private_key, "");
    }

    #[test]
    fn session_record_defaults_for_optional_fields() {
        let raw = json!({
            "session_id": "s1",
            "mobile_device_id": "m1",
            "state": "connected",
            "updated_at": "2024-01-01T00:00:00Z"
        });
        let rec: SessionRecord = serde_json::from_value(raw).unwrap();
        assert!(!rec.persistent);
        assert!(rec.tmux_session_name.is_none());
    }

    #[test]
    fn session_record_skips_none_tmux_name() {
        let rec = SessionRecord {
            session_id: "s".into(),
            mobile_device_id: "m".into(),
            state: SessionState::Connected,
            updated_at: sample_time(),
            persistent: true,
            tmux_session_name: None,
        };
        let v = serde_json::to_value(&rec).unwrap();
        assert!(v.get("tmux_session_name").is_none());
        assert_eq!(v["persistent"], true);
    }

    #[test]
    fn session_request_roundtrip() {
        let req = SessionRequest {
            session_id: "s".into(),
            mobile_device_id: "m".into(),
            cols: 80,
            rows: 24,
            attach_target: Some(AttachTarget {
                session_type: "tmux".into(),
                name: "main".into(),
            }),
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let back: SessionRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.cols, 80);
        assert_eq!(back.rows, 24);
        let target = back.attach_target.unwrap();
        assert_eq!(target.session_type, "tmux");
        assert_eq!(target.name, "main");
    }

    #[test]
    fn session_request_null_attach_target() {
        let raw =
            r#"{"session_id":"s","mobile_device_id":"m","cols":80,"rows":24,"attach_target":null}"#;
        let req: SessionRequest = serde_json::from_str(raw).unwrap();
        assert!(req.attach_target.is_none());
    }

    #[test]
    fn process_info_skips_none_options() {
        let p = ProcessInfo {
            pid: 1,
            name: "init".into(),
            cpu_percent: 0.5,
            memory_bytes: 1024,
            status: "running".into(),
            parent_pid: None,
            user: None,
            command: None,
            run_time_secs: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("parent_pid"));
        assert!(!obj.contains_key("user"));
        assert!(!obj.contains_key("command"));
        assert!(!obj.contains_key("run_time_secs"));
        assert_eq!(obj["pid"], 1);
    }

    #[test]
    fn signal_envelope_uses_type_rename_and_flattens_extras() {
        let raw = json!({
            "type": "offer",
            "session_id": "s1",
            "payload": {"sdp": "xxx"},
            "state": null,
            "accepted": null,
            "reason": null,
            "custom_field": "custom_value",
            "count": 7
        });
        let env: SignalEnvelope = serde_json::from_value(raw).unwrap();
        assert_eq!(env.message_type, "offer");
        assert_eq!(env.session_id.as_deref(), Some("s1"));
        assert_eq!(env.extra.get("custom_field").unwrap(), "custom_value");
        assert_eq!(env.extra.get("count").unwrap(), 7);

        // Serializing back should emit "type" (not "message_type").
        let back = serde_json::to_value(&env).unwrap();
        assert!(back.get("type").is_some());
        assert!(back.get("message_type").is_none());
        assert_eq!(back["custom_field"], "custom_value");
    }

    #[test]
    fn trusted_device_skips_none_public_key() {
        let rec = TrustedDeviceRecord {
            id: "id".into(),
            host_id: "h".into(),
            mobile_device_id: "m".into(),
            approved_at: None,
            revoked_at: None,
            permissions_json: None,
            device_public_key: None,
            created_at: sample_time(),
        };
        let v = serde_json::to_value(&rec).unwrap();
        assert!(v.get("device_public_key").is_none());
    }

    #[test]
    fn host_initiated_status_response_defaults() {
        let raw = json!({"status": "pending"});
        let resp: HostInitiatedStatusResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(resp.status, "pending");
        assert!(resp.mode.is_none());
        assert!(resp.host.is_none());
        assert!(resp.access_token.is_none());
    }

    #[test]
    fn stats_snapshot_skips_all_none_optionals() {
        let snap = StatsSnapshot {
            cpu_usage_percent: 1.0,
            memory_total_bytes: 1,
            memory_used_bytes: 1,
            memory_available_bytes: 1,
            memory_free_bytes: 1,
            disk_total_bytes: 1,
            disk_used_bytes: 1,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            uptime_secs: 0,
            load_one: 0.0,
            load_five: 0.0,
            load_fifteen: 0.0,
            battery_percent: None,
            collected_at: sample_time(),
            processes: None,
            network_io: None,
            disk_io: None,
            temperatures: None,
            network_connections: None,
            logged_in_users: None,
            os_info: None,
            cpu_per_core: None,
            task_counts: None,
            cpu_times: None,
        };
        let v = serde_json::to_value(&snap).unwrap();
        let obj = v.as_object().unwrap();
        for skipped in [
            "processes",
            "network_io",
            "disk_io",
            "temperatures",
            "network_connections",
            "logged_in_users",
            "os_info",
            "cpu_per_core",
            "task_counts",
            "cpu_times",
        ] {
            assert!(!obj.contains_key(skipped), "{} should be skipped", skipped);
        }
        // battery_percent has no skip_serializing_if, so it's present as null.
        assert!(obj.contains_key("battery_percent"));
    }
}
