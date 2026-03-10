use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub auth: Option<AuthState>,
    pub host: Option<HostIdentity>,
    pub pending_devices: Vec<DeviceRecord>,
    pub trusted_devices: Vec<DeviceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub host_id: String,
    pub hostname: String,
    pub platform: String,
    pub app_version: String,
    pub public_key: String,
    pub private_key: String,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub public_key: Option<String>,
    pub pending_since: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub pairing_code: String,
    pub hostname: String,
    pub platform: String,
    pub app_version: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub host_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: Option<DateTime<Utc>>,
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    PairingPending {
        device_id: String,
        device_name: String,
        platform: String,
        public_key: Option<String>,
    },
    SessionRequest {
        session_id: String,
        mobile_device_id: String,
        cols: u16,
        rows: u16,
    },
    SessionInput {
        session_id: String,
        data_b64: String,
    },
    SessionResize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    SessionClose {
        session_id: String,
    },
    SessionAck {
        session_id: String,
        accepted: bool,
        reason: Option<String>,
    },
    SessionOutput {
        session_id: String,
        data_b64: String,
    },
    Stats {
        payload: StatsSnapshot,
    },
    Presence {
        host_id: String,
        online: bool,
    },
}
