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
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingValidateRequest {
    pub code: String,
    pub hostname: String,
    pub platform: String,
    pub public_key: String,
    pub app_version: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDeviceRecord {
    pub id: String,
    pub host_id: String,
    pub mobile_device_id: String,
    pub approved_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub permissions_json: Option<HashMap<String, serde_json::Value>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub mobile_device_id: String,
    pub state: SessionState,
    pub updated_at: DateTime<Utc>,
    /// Whether this session is backed by a persistent tmux session.
    #[serde(default)]
    pub persistent: bool,
    /// The tmux session name (e.g. "ps-{session_id}") if persistent.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub cpu_usage_percent: f32,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub uptime_secs: u64,
    pub load_one: f64,
    pub load_five: f64,
    pub load_fifteen: f64,
    pub battery_percent: Option<f32>,
    pub collected_at: DateTime<Utc>,
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
