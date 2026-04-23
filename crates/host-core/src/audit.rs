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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    #[test]
    fn audit_event_new_sets_event_type_and_rfc3339_timestamp() {
        let ev = AuditEvent::new("test.event");
        assert_eq!(ev.event_type, "test.event");
        assert!(ev.host_id.is_none());
        assert!(ev.mobile_device_id.is_none());
        assert!(ev.session_id.is_none());
        assert!(ev.details.is_none());
        // Must be a parsable rfc3339 timestamp.
        DateTime::parse_from_rfc3339(&ev.at)
            .unwrap_or_else(|e| panic!("at is not rfc3339 ({}): {e}", ev.at));
    }

    #[test]
    fn audit_event_is_json_serializable() {
        let ev = AuditEvent::new("x");
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"event_type\":\"x\""));
        assert!(s.contains("\"at\":\""));
    }

    #[test]
    fn write_audit_event_appends_json_line_to_audit_file() {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let mut ev = AuditEvent::new("unit.test.event");
        ev.host_id = Some("h-1".to_string());
        let result = write_audit_event(ev);

        // Restore HOME before any assertion so a failure doesn't leak env state.
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        result.expect("write_audit_event should succeed");
        let audit_path = tmp.path().join(".pocketshell").join("audit.log");
        let contents = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(contents.ends_with('\n'));
        let line = contents.trim_end();
        let parsed: serde_json::Value = serde_json::from_str(line).expect("valid json line");
        assert_eq!(parsed["event_type"], "unit.test.event");
        assert_eq!(parsed["host_id"], "h-1");
    }
}
