use crate::config::AppConfig;
use crate::error::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub at: String,
    pub host_id: Option<String>,
    pub mobile_device_id: Option<String>,
    pub session_id: Option<String>,
    pub details: Option<serde_json::Value>,
}

impl AuditEvent {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            at: Utc::now().to_rfc3339(),
            host_id: None,
            mobile_device_id: None,
            session_id: None,
            details: None,
        }
    }
}

pub fn write_audit_event(mut event: AuditEvent) -> Result<()> {
    let paths = AppConfig::paths()?;
    if !paths.state_dir.exists() {
        fs::create_dir_all(&paths.state_dir)?;
    }

    if event.at.is_empty() {
        event.at = Utc::now().to_rfc3339();
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.audit_file)?;

    let line = serde_json::to_string(&event)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
