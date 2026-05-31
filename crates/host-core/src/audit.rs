use crate::config::AppConfig;
use crate::error::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Outcome of an audited operation. Aligns with NIST SP 800-53 AU-3 which
/// requires every record to carry success/failure status.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Denied,
    Failed,
}

impl Default for Outcome {
    fn default() -> Self {
        Outcome::Success
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub at: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Resource acted on (path, pid, agent_id, transfer_id, session_id, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl AuditEvent {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            at: Utc::now().to_rfc3339(),
            outcome: Outcome::Success,
            reason: None,
            user_id: None,
            host_id: None,
            mobile_device_id: None,
            session_id: None,
            target: None,
            details: None,
        }
    }

    /// Mark this event as a denial (permission/trust check failed).
    pub fn denied(mut self, reason: impl Into<String>) -> Self {
        self.outcome = Outcome::Denied;
        self.reason = Some(reason.into());
        self
    }

    /// Mark this event as a failure (operation attempted but errored).
    pub fn failed(mut self, reason: impl Into<String>) -> Self {
        self.outcome = Outcome::Failed;
        self.reason = Some(reason.into());
        self
    }
}

/// Helper that auto-fills `host_id` and `user_id` from the state store before
/// writing. Use this from any code path that has a `StateStore` handy — every
/// event then carries the "where" and "who" fields without each call site
/// remembering to set them.
pub fn write_audit_event_with_store(
    mut event: AuditEvent,
    store: &crate::store::StateStore,
) -> Result<()> {
    if event.host_id.is_none() {
        event.host_id = store.state.host.as_ref().map(|h| h.host_id.clone());
    }
    if event.user_id.is_none() {
        event.user_id = store.state.host.as_ref().map(|h| h.user_id.clone());
    }
    write_audit_event(event)
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

/// Read the tail of the current `audit.log`, newest-first, filtered and paginated.
///
/// - `limit`: maximum number of events to return (clamp by caller).
/// - `before_ts`: if set, only events with `at` strictly chronologically less
///   than this RFC3339 timestamp are returned. Used by the mobile client to
///   paginate older pages.
/// - `event_type_prefix`: if set, only events whose `event_type` starts with
///   this prefix are returned (e.g. `"file."` to filter to file actions).
///
/// Returns `(events, more)` where `more=true` indicates the caller can fetch
/// an older page by setting `before_ts` to the `at` of the last (oldest)
/// returned event. Malformed JSONL lines and events whose `at` doesn't parse
/// as RFC3339 are skipped silently — the audit writer is the only producer,
/// so this only happens after disk corruption or a writer-format change.
///
/// Rotated archives (`audit.log.1` …) are NOT consulted. 5 MB of current log
/// covers many thousands of events which is plenty for the mobile viewer.
pub fn read_audit_tail(
    path: &Path,
    limit: usize,
    before_ts: Option<&str>,
    event_type_prefix: Option<&str>,
) -> std::io::Result<(Vec<serde_json::Value>, bool)> {
    let contents = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(e),
    };

    // Parse the boundary once up front so we compare chronologically rather
    // than lexically — chrono::Utc::now().to_rfc3339() output is consistent
    // today, but a writer change that trims subseconds (or a future chrono
    // version) would silently break a lex compare at pagination boundaries.
    let before_dt: Option<chrono::DateTime<chrono::FixedOffset>> = match before_ts {
        Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(dt) => Some(dt),
            // Caller-validated input; if it reached here malformed, return an
            // empty page deterministically rather than crashing or returning
            // unfiltered data.
            Err(_) => return Ok((Vec::new(), false)),
        },
        None => None,
    };

    let mut matched: Vec<serde_json::Value> = Vec::new();
    for line in contents.lines() {
        if line.is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(prefix) = event_type_prefix {
            let et = ev.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
            if !et.starts_with(prefix) {
                continue;
            }
        }
        if let Some(before) = before_dt {
            let at_str = ev.get("at").and_then(|v| v.as_str()).unwrap_or("");
            let Ok(at_dt) = chrono::DateTime::parse_from_rfc3339(at_str) else {
                continue;
            };
            if at_dt >= before {
                continue;
            }
        }
        matched.push(ev);
    }

    // File is append-only oldest-first; reverse to newest-first.
    matched.reverse();
    let more = matched.len() > limit;
    matched.truncate(limit);
    Ok((matched, more))
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
    fn default_outcome_is_success() {
        let ev = AuditEvent::new("x");
        assert_eq!(ev.outcome, Outcome::Success);
    }

    #[test]
    fn denied_builder_sets_outcome_and_reason() {
        let ev = AuditEvent::new("authz.denied").denied("device_not_trusted");
        assert_eq!(ev.outcome, Outcome::Denied);
        assert_eq!(ev.reason.as_deref(), Some("device_not_trusted"));
    }

    #[test]
    fn failed_builder_sets_outcome_and_reason() {
        let ev = AuditEvent::new("file.write").failed("disk full");
        assert_eq!(ev.outcome, Outcome::Failed);
        assert_eq!(ev.reason.as_deref(), Some("disk full"));
    }

    #[test]
    fn empty_optional_fields_skip_serialization() {
        // skip_serializing_if means a barebones event should NOT include
        // host_id/mobile_device_id/session_id/target/details/reason —
        // keeps the JSON file readable when most events lack attribution.
        let ev = AuditEvent::new("ping");
        let s = serde_json::to_string(&ev).unwrap();
        assert!(!s.contains("host_id"));
        assert!(!s.contains("mobile_device_id"));
        assert!(!s.contains("session_id"));
        assert!(!s.contains("target"));
        assert!(!s.contains("details"));
        assert!(!s.contains("reason"));
        // outcome always present (success) — needed for compliance: every
        // record must indicate success/failure.
        assert!(s.contains("\"outcome\":\"success\""));
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

    #[test]
    fn read_audit_tail_returns_newest_first() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        // Three lines, oldest first (as on disk).
        let lines = [
            r#"{"event_type":"a","at":"2024-01-01T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"b","at":"2024-01-02T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"c","at":"2024-01-03T00:00:00+00:00","outcome":"success"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (events, more) = read_audit_tail(&path, 10, None, None).unwrap();
        assert_eq!(events.len(), 3);
        assert!(!more);
        // Newest first.
        assert_eq!(events[0]["event_type"], "c");
        assert_eq!(events[1]["event_type"], "b");
        assert_eq!(events[2]["event_type"], "a");
    }

    #[test]
    fn read_audit_tail_limit_and_more_flag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        let mut s = String::new();
        for i in 0..5 {
            s.push_str(&format!(
                r#"{{"event_type":"e{i}","at":"2024-01-0{}T00:00:00+00:00","outcome":"success"}}"#,
                i + 1
            ));
            s.push('\n');
        }
        std::fs::write(&path, &s).unwrap();

        let (events, more) = read_audit_tail(&path, 2, None, None).unwrap();
        assert_eq!(events.len(), 2);
        assert!(more, "more should be true when limit truncates the result");
        assert_eq!(events[0]["event_type"], "e4");
        assert_eq!(events[1]["event_type"], "e3");
    }

    #[test]
    fn read_audit_tail_before_ts_paginates_older() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        let lines = [
            r#"{"event_type":"a","at":"2024-01-01T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"b","at":"2024-01-02T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"c","at":"2024-01-03T00:00:00+00:00","outcome":"success"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // before_ts=c → returns b, a; before_ts=b → returns a only.
        let (events, _) =
            read_audit_tail(&path, 10, Some("2024-01-03T00:00:00+00:00"), None).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event_type"], "b");
        assert_eq!(events[1]["event_type"], "a");

        let (events, _) =
            read_audit_tail(&path, 10, Some("2024-01-02T00:00:00+00:00"), None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "a");
    }

    #[test]
    fn read_audit_tail_prefix_filter() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        let lines = [
            r#"{"event_type":"files.write","at":"2024-01-01T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"process.killed","at":"2024-01-02T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"files.delete","at":"2024-01-03T00:00:00+00:00","outcome":"success"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (events, _) = read_audit_tail(&path, 10, None, Some("files.")).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event_type"], "files.delete");
        assert_eq!(events[1]["event_type"], "files.write");
    }

    #[test]
    fn read_audit_tail_skips_malformed_lines() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        let lines = [
            r#"{"event_type":"a","at":"2024-01-01T00:00:00+00:00","outcome":"success"}"#,
            r#"not json at all"#,
            r#"{"event_type":"b","at":"2024-01-02T00:00:00+00:00","outcome":"success"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (events, _) = read_audit_tail(&path, 10, None, None).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn read_audit_tail_missing_file_returns_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("nope.log");
        let (events, more) = read_audit_tail(&path, 10, None, None).unwrap();
        assert!(events.is_empty());
        assert!(!more);
    }

    #[test]
    fn read_audit_tail_compares_timestamps_chronologically_not_lexically() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        // Boundary at 2024-01-01T10:00:00+05:30 == 2024-01-01T04:30:00 UTC.
        // "before": 2024-01-01T03:00:00+00:00 == 03:00 UTC, chronologically
        //   AND lexically older than the boundary — included by both compares.
        // "after":  2024-01-01T05:00:00+00:00 == 05:00 UTC, chronologically
        //   AFTER the boundary (so must be excluded) but the raw string
        //   `2024-01-01T05:00:00+00:00` sorts LEXICALLY before
        //   `2024-01-01T10:00:00+05:30` (position 11: '0' < '1'). A naïve
        //   lex compare would wrongly include it.
        let lines = [
            r#"{"event_type":"before","at":"2024-01-01T03:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"after","at":"2024-01-01T05:00:00+00:00","outcome":"success"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (events, _) =
            read_audit_tail(&path, 10, Some("2024-01-01T10:00:00+05:30"), None).unwrap();
        assert_eq!(events.len(), 1, "only 'before' should pass the boundary");
        assert_eq!(events[0]["event_type"], "before");
    }

    #[test]
    fn read_audit_tail_skips_events_with_unparseable_at_under_before_ts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        let lines = [
            r#"{"event_type":"a","at":"2024-01-01T00:00:00+00:00","outcome":"success"}"#,
            r#"{"event_type":"junk","at":"not a timestamp","outcome":"success"}"#,
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        // With a before_ts filter, the junk-at event is dropped (it can't be
        // compared). Without one, both come back.
        let (filtered, _) =
            read_audit_tail(&path, 10, Some("2024-12-31T00:00:00+00:00"), None).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["event_type"], "a");

        let (all, _) = read_audit_tail(&path, 10, None, None).unwrap();
        assert_eq!(all.len(), 2);
    }
}
