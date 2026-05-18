use crate::config::AppConfig;
use crate::error::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

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

/// Maximum size of `audit.log` before rotation kicks in.
const AUDIT_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// Number of rotated archives to keep (`audit.log.1` … `audit.log.N`).
const AUDIT_MAX_ARCHIVES: usize = 5;

pub fn write_audit_event(mut event: AuditEvent) -> Result<()> {
    let paths = AppConfig::paths()?;
    ensure_state_dir(&paths.state_dir)?;

    if event.at.is_empty() {
        event.at = Utc::now().to_rfc3339();
    }

    // Rotate before opening so the new write lands in a fresh file.
    if let Ok(meta) = fs::metadata(&paths.audit_file) {
        if meta.len() >= AUDIT_MAX_BYTES {
            if let Err(e) = rotate_audit_log(&paths.audit_file) {
                // Rotation failure should not lose the audit event; fall through
                // to append on the existing file.
                tracing::warn!("audit log rotation failed: {}", e);
            }
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.audit_file)?;

    harden_audit_file(&paths.audit_file)?;

    let line = serde_json::to_string(&event)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(unix)]
fn ensure_state_dir(state_dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !state_dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
    } else {
        // Tighten permissions if the directory was created by something else
        // (umask 022 default would leave it world-readable).
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(state_dir)?.permissions();
        if perms.mode() & 0o777 != 0o700 {
            perms.set_mode(0o700);
            // Best-effort; ignore failures (e.g. immutable bit).
            let _ = fs::set_permissions(state_dir, perms);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_state_dir(state_dir: &Path) -> Result<()> {
    if !state_dir.exists() {
        fs::create_dir_all(state_dir)?;
    }
    Ok(())
}

#[cfg(unix)]
fn harden_audit_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_audit_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// Rotate `audit.log` -> `audit.log.1`, shifting older archives up by one and
/// dropping the oldest beyond `AUDIT_MAX_ARCHIVES`. Each archived file is
/// re-chmod 0o600 in case rotation crossed a filesystem.
fn rotate_audit_log(audit_file: &Path) -> Result<()> {
    let archive_path = |n: usize| {
        let mut p = audit_file.to_path_buf();
        let name = audit_file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("audit.log");
        p.set_file_name(format!("{name}.{n}"));
        p
    };

    // Drop the oldest archive if it exists.
    let oldest = archive_path(AUDIT_MAX_ARCHIVES);
    if oldest.exists() {
        let _ = fs::remove_file(&oldest);
    }

    // Shift audit.log.(N-1) -> audit.log.N, ..., audit.log.1 -> audit.log.2
    for n in (1..AUDIT_MAX_ARCHIVES).rev() {
        let src = archive_path(n);
        let dst = archive_path(n + 1);
        if src.exists() {
            let _ = fs::rename(&src, &dst);
            let _ = harden_audit_file(&dst);
        }
    }

    // Move audit.log -> audit.log.1
    let first = archive_path(1);
    fs::rename(audit_file, &first)?;
    let _ = harden_audit_file(&first);
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

    #[cfg(unix)]
    #[test]
    fn audit_file_is_chmod_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let result = write_audit_event(AuditEvent::new("perm.test"));

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        result.expect("write_audit_event should succeed");

        let audit_path = tmp.path().join(".pocketshell").join("audit.log");
        let mode = std::fs::metadata(&audit_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit.log must be 0o600, got {:o}", mode);

        let dir_mode = std::fs::metadata(tmp.path().join(".pocketshell"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "state dir must be 0o700, got {:o}",
            dir_mode
        );
    }

    #[test]
    fn audit_log_rotates_at_size_threshold() {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        // Pre-seed an audit.log over the 5MB threshold to force rotation on
        // the next append.
        let state_dir = tmp.path().join(".pocketshell");
        std::fs::create_dir_all(&state_dir).unwrap();
        let audit_path = state_dir.join("audit.log");
        // Just over 5 MB.
        let blob = vec![b'a'; (AUDIT_MAX_BYTES as usize) + 16];
        std::fs::write(&audit_path, &blob).unwrap();

        let result = write_audit_event(AuditEvent::new("rot.test"));

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        result.expect("write_audit_event should succeed");

        // After rotation, audit.log should hold only the new event line, and
        // audit.log.1 should hold the seeded blob.
        let new_contents = std::fs::read_to_string(&audit_path).unwrap();
        assert!(
            new_contents.contains("rot.test"),
            "rotated audit.log should hold new event"
        );
        assert!(
            new_contents.len() < blob.len(),
            "rotated audit.log should be small"
        );
        let archive = state_dir.join("audit.log.1");
        assert!(archive.exists(), "audit.log.1 should exist after rotation");
        let archive_meta = std::fs::metadata(&archive).unwrap();
        assert!(archive_meta.len() as usize >= blob.len() - 1);
    }
}
