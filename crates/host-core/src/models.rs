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
