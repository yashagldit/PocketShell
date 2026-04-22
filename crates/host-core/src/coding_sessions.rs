// Discovers Claude Code and Codex chat sessions on disk and returns a
// compact summary list for the mobile app.

use crate::error::{HostError, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const TITLE_MAX_CHARS: usize = 80;
/// Hard cap on lines scanned per Claude JSONL when searching for metadata —
/// bounds worst-case I/O on a session with no qualifying user message.
const CLAUDE_SCAN_LINE_CAP: usize = 200;

#[derive(Serialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Claude,
    Codex,
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub source: Source,
    pub file_path: String,
    pub title: String,
    pub project_path: String,
    pub size_bytes: u64,
    #[serde(skip)]
    mtime_system: SystemTime,
    pub mtime: String,
}

pub async fn list_sessions(limit: Option<usize>) -> Result<serde_json::Value> {
    let home = dirs::home_dir()
        .ok_or_else(|| HostError::Backend("home dir not found".into()))?;

    let claude_dir = home.join(".claude");
    let codex_dir = home.join(".codex");

    let claude_task = tokio::task::spawn_blocking(move || scan_claude(&claude_dir));
    let codex_task = tokio::task::spawn_blocking(move || scan_codex(&codex_dir));

    let (claude_res, codex_res) = tokio::join!(claude_task, codex_task);
    let mut sessions = claude_res.map_err(task_err)?;
    sessions.extend(codex_res.map_err(task_err)?);

    sessions.sort_by(|a, b| b.mtime_system.cmp(&a.mtime_system));
    let total = sessions.len();
    if let Some(n) = limit {
        sessions.truncate(n);
    }

    Ok(serde_json::json!({
        "sessions": sessions,
        "total": total,
    }))
}

fn task_err(e: tokio::task::JoinError) -> HostError {
    HostError::Backend(format!("coding_sessions scan panicked: {e}"))
}

fn scan_claude(claude_dir: &Path) -> Vec<SessionInfo> {
    let projects_dir = claude_dir.join("projects");
    let mut out = Vec::new();

    let project_dirs = match fs::read_dir(&projects_dir) {
        Ok(r) => r,
        Err(_) => return out,
    };

    for project_entry in project_dirs.flatten() {
        let project_path = project_entry.path();
        if !project_path.is_dir() {
            continue;
        }

        let files = match fs::read_dir(&project_path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for file_entry in files.flatten() {
            let file_path = file_entry.path();
            let name = match file_path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if !name.ends_with(".jsonl") || name.starts_with("agent-") {
                continue;
            }

            if let Some(info) = parse_claude_session(&file_path) {
                out.push(info);
            }
        }
    }

    out
}

fn parse_claude_session(file_path: &Path) -> Option<SessionInfo> {
    let file = fs::File::open(file_path).ok()?;
    let metadata = file.metadata().ok()?;
    let size_bytes = metadata.len();
    let mtime_system = metadata.modified().ok()?;

    let reader = BufReader::new(file);

    let mut session_id = String::new();
    let mut cwd = String::new();
    let mut title: Option<String> = None;

    for (i, line) in reader.lines().enumerate() {
        if i >= CLAUDE_SCAN_LINE_CAP {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        let raw: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if session_id.is_empty() {
            if let Some(s) = raw.get("sessionId").and_then(|v| v.as_str()) {
                session_id = s.to_string();
            }
        }
        if cwd.is_empty() {
            if let Some(c) = raw.get("cwd").and_then(|v| v.as_str()) {
                cwd = c.to_string();
            }
        }

        if title.is_none() {
            let is_user = raw.get("type").and_then(|v| v.as_str()) == Some("user");
            let is_meta = raw
                .get("isMeta")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_user && !is_meta {
                if let Some(content) = raw.get("message").and_then(|m| m.get("content")) {
                    if let Some(t) = extract_title(content) {
                        title = Some(t);
                    }
                }
            }
        }

        if title.is_some() && !session_id.is_empty() && !cwd.is_empty() {
            break;
        }
    }

    if session_id.is_empty() {
        session_id = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
    }

    Some(SessionInfo {
        session_id,
        source: Source::Claude,
        file_path: file_path.to_string_lossy().into_owned(),
        title: title.unwrap_or_else(|| "Untitled Session".to_string()),
        project_path: cwd,
        size_bytes,
        mtime_system,
        mtime: format_mtime(mtime_system),
    })
}

fn scan_codex(codex_dir: &Path) -> Vec<SessionInfo> {
    let sessions_root = codex_dir.join("sessions");
    let mut out = Vec::new();

    let index = load_codex_index(&codex_dir.join("session_index.jsonl"));

    let mut stack: Vec<PathBuf> = vec![sessions_root];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if !name.starts_with("rollout-") || !name.ends_with(".jsonl") {
                continue;
            }

            if let Some(info) = parse_codex_session(&path, &index) {
                out.push(info);
            }
        }
    }

    out
}

fn load_codex_index(index_path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let file = match fs::File::open(index_path) {
        Ok(f) => f,
        Err(_) => return map,
    };
    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        if line.trim().is_empty() {
            continue;
        }
        let raw: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = raw.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let name = raw
            .get("thread_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !id.is_empty() && !name.is_empty() {
            map.insert(id.to_string(), name.to_string());
        }
    }
    map
}

fn parse_codex_session(
    file_path: &Path,
    index: &HashMap<String, String>,
) -> Option<SessionInfo> {
    let file = fs::File::open(file_path).ok()?;
    let metadata = file.metadata().ok()?;
    let size_bytes = metadata.len();
    let mtime_system = metadata.modified().ok()?;

    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).ok()? == 0 {
        return None;
    }

    let raw: serde_json::Value = serde_json::from_str(first_line.trim()).ok()?;
    if raw.get("type").and_then(|v| v.as_str()) != Some("session_meta") {
        return None;
    }

    let payload = raw.get("payload")?;
    let session_id = payload
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let cwd = payload
        .get("cwd")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if session_id.is_empty() {
        return None;
    }

    let title = index
        .get(&session_id)
        .cloned()
        .unwrap_or_else(|| session_id.clone());

    Some(SessionInfo {
        session_id,
        source: Source::Codex,
        file_path: file_path.to_string_lossy().into_owned(),
        title,
        project_path: cwd,
        size_bytes,
        mtime_system,
        mtime: format_mtime(mtime_system),
    })
}

fn format_mtime(t: SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    dt.to_rfc3339()
}

fn extract_title(content: &serde_json::Value) -> Option<String> {
    let raw = if let Some(s) = content.as_str() {
        s.to_string()
    } else if let Some(arr) = content.as_array() {
        let mut picked = String::new();
        for block in arr {
            if let Some(s) = block.as_str() {
                if !s.trim().is_empty() {
                    picked = s.to_string();
                    break;
                }
                continue;
            }
            let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if block_type == "text" || block_type == "input_text" {
                if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                    if !t.trim().is_empty() {
                        picked = t.to_string();
                        break;
                    }
                }
            }
        }
        picked
    } else {
        return None;
    };

    let cleaned = raw
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    if cleaned.len() < 3 || is_system_message(&cleaned) {
        return None;
    }

    if cleaned.chars().count() <= TITLE_MAX_CHARS {
        return Some(cleaned);
    }

    let mut truncated: String = cleaned.chars().take(TITLE_MAX_CHARS - 3).collect();
    if let Some(last_space) = truncated.rfind(' ') {
        if last_space > TITLE_MAX_CHARS / 2 {
            truncated.truncate(last_space);
        }
    }
    truncated.push_str("...");
    Some(truncated)
}

fn is_system_message(text: &str) -> bool {
    const PATTERNS: &[&str] = &[
        "<command-name>",
        "<local-command-stdout>",
        "<system-reminder>",
        "<tool_use_id>",
        "<ide_opened_file>",
        "<ide_selection>",
    ];
    PATTERNS.iter().any(|p| text.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_title_from_string_content() {
        let content = serde_json::json!("hello world, this is a message");
        assert_eq!(
            extract_title(&content).as_deref(),
            Some("hello world, this is a message"),
        );
    }

    #[test]
    fn extracts_title_from_array_text_blocks() {
        let content = serde_json::json!([
            { "type": "text", "text": "first real message" }
        ]);
        assert_eq!(extract_title(&content).as_deref(), Some("first real message"));
    }

    #[test]
    fn skips_system_reminder_content() {
        let content = serde_json::json!("<system-reminder>no</system-reminder>");
        assert!(extract_title(&content).is_none());
    }

    #[test]
    fn truncates_long_titles_on_word_boundary() {
        let long = "a".repeat(10) + " " + &"b".repeat(100);
        let content = serde_json::json!(long);
        let title = extract_title(&content).unwrap();
        assert!(title.ends_with("..."));
        assert!(title.chars().count() <= TITLE_MAX_CHARS);
    }

    #[test]
    fn source_serializes_lowercase() {
        let s = serde_json::to_string(&Source::Claude).unwrap();
        assert_eq!(s, "\"claude\"");
    }

    #[test]
    fn source_codex_serializes_lowercase() {
        let s = serde_json::to_string(&Source::Codex).unwrap();
        assert_eq!(s, "\"codex\"");
    }

    #[test]
    fn extract_title_rejects_too_short() {
        let content = serde_json::json!("hi");
        assert!(extract_title(&content).is_none());
    }

    #[test]
    fn extract_title_collapses_whitespace_and_newlines() {
        let content = serde_json::json!("line one\nline  two\t\tthree");
        assert_eq!(
            extract_title(&content).as_deref(),
            Some("line one line two three"),
        );
    }

    #[test]
    fn extract_title_skips_empty_array_blocks() {
        let content = serde_json::json!([
            { "type": "text", "text": "   " },
            { "type": "text", "text": "the real title" },
        ]);
        assert_eq!(extract_title(&content).as_deref(), Some("the real title"));
    }

    #[test]
    fn extract_title_handles_string_array_items() {
        let content = serde_json::json!(["  ", "picked this one"]);
        assert_eq!(extract_title(&content).as_deref(), Some("picked this one"));
    }

    #[test]
    fn extract_title_rejects_all_system_markers() {
        for marker in &[
            "<command-name>foo</command-name> yes indeed",
            "prefix <local-command-stdout> ignore",
            "<tool_use_id> whatever",
            "<ide_opened_file> path",
            "<ide_selection> selection",
        ] {
            let content = serde_json::json!(marker);
            assert!(
                extract_title(&content).is_none(),
                "expected system marker rejected: {marker}"
            );
        }
    }

    #[test]
    fn extract_title_input_text_block_variant() {
        let content = serde_json::json!([
            { "type": "input_text", "text": "input text block picked" }
        ]);
        assert_eq!(
            extract_title(&content).as_deref(),
            Some("input text block picked"),
        );
    }

    #[test]
    fn extract_title_returns_none_for_unsupported_variant() {
        let content = serde_json::json!(42);
        assert!(extract_title(&content).is_none());
    }

    #[test]
    fn extract_title_truncation_appends_ellipsis() {
        // Word without spaces longer than TITLE_MAX_CHARS — no word boundary in
        // the second half, so falls back to hard char truncation with "...".
        let content = serde_json::json!("a".repeat(200));
        let title = extract_title(&content).unwrap();
        assert!(title.ends_with("..."));
        assert!(title.chars().count() <= TITLE_MAX_CHARS);
    }

    #[test]
    fn is_system_message_negative() {
        assert!(!is_system_message("a normal user message"));
        assert!(!is_system_message(""));
    }

    #[test]
    fn session_info_serde_skips_mtime_system() {
        let info = SessionInfo {
            session_id: "abc".into(),
            source: Source::Claude,
            file_path: "/tmp/x.jsonl".into(),
            title: "t".into(),
            project_path: "/tmp".into(),
            size_bytes: 42,
            mtime_system: SystemTime::UNIX_EPOCH,
            mtime: "1970-01-01T00:00:00+00:00".into(),
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["session_id"], "abc");
        assert_eq!(v["source"], "claude");
        assert_eq!(v["size_bytes"], 42);
        // `mtime_system` has #[serde(skip)]
        assert!(v.get("mtime_system").is_none());
    }

    #[test]
    fn scan_claude_missing_dir_returns_empty() {
        let dir = std::path::PathBuf::from("/no/such/claude/xyz-missing-9999");
        assert!(scan_claude(&dir).is_empty());
    }

    #[test]
    fn scan_codex_missing_dir_returns_empty() {
        let dir = std::path::PathBuf::from("/no/such/codex/xyz-missing-9999");
        assert!(scan_codex(&dir).is_empty());
    }

    #[test]
    fn load_codex_index_missing_file_returns_empty() {
        let p = std::path::PathBuf::from("/no/such/index/xyz-9999.jsonl");
        assert!(load_codex_index(&p).is_empty());
    }

    #[test]
    fn load_codex_index_parses_valid_entries() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("session_index.jsonl");
        std::fs::write(
            &p,
            r#"{"id":"abc","thread_name":"My Chat"}
{"id":"","thread_name":"bad"}
not json
{"id":"def","thread_name":"Other"}
"#,
        )
        .unwrap();
        let map = load_codex_index(&p);
        assert_eq!(map.get("abc").map(String::as_str), Some("My Chat"));
        assert_eq!(map.get("def").map(String::as_str), Some("Other"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_codex_session_requires_session_meta() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-x.jsonl");
        // First line has wrong type — must return None.
        std::fs::write(&p, r#"{"type":"other","payload":{"id":"x"}}
"#).unwrap();
        let idx = HashMap::new();
        assert!(parse_codex_session(&p, &idx).is_none());
    }

    #[test]
    fn parse_codex_session_uses_index_title() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-y.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-1","cwd":"/work/dir"}}
"#,
        )
        .unwrap();
        let mut idx = HashMap::new();
        idx.insert("sess-1".into(), "My Session".into());
        let info = parse_codex_session(&p, &idx).unwrap();
        assert_eq!(info.session_id, "sess-1");
        assert_eq!(info.title, "My Session");
        assert_eq!(info.project_path, "/work/dir");
    }

    #[test]
    fn parse_codex_session_falls_back_to_id_title() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-z.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-2","cwd":""}}
"#,
        )
        .unwrap();
        let idx = HashMap::new();
        let info = parse_codex_session(&p, &idx).unwrap();
        assert_eq!(info.title, "sess-2");
    }

    #[test]
    fn parse_codex_session_empty_id_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-empty.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"","cwd":"/x"}}
"#,
        )
        .unwrap();
        let idx = HashMap::new();
        assert!(parse_codex_session(&p, &idx).is_none());
    }

    #[test]
    fn parse_claude_session_populates_fields_from_first_user_turn() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("claude.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"system","sessionId":"sess-a","cwd":"/work"}
{"type":"user","isMeta":true,"message":{"content":"skip meta"}}
{"type":"user","message":{"content":"first real user text"}}
"#,
        )
        .unwrap();
        let info = parse_claude_session(&p).unwrap();
        assert_eq!(info.session_id, "sess-a");
        assert_eq!(info.project_path, "/work");
        assert_eq!(info.title, "first real user text");
    }

    #[test]
    fn parse_claude_session_falls_back_to_file_stem_id() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fallback-id.jsonl");
        // No sessionId anywhere; should fall back to file stem.
        std::fs::write(&p, "\n").unwrap();
        let info = parse_claude_session(&p).unwrap();
        assert_eq!(info.session_id, "fallback-id");
        assert_eq!(info.title, "Untitled Session");
    }

    #[test]
    fn format_mtime_is_rfc3339_utc() {
        let s = format_mtime(SystemTime::UNIX_EPOCH);
        // RFC3339 form: "1970-01-01T00:00:00+00:00"
        assert!(s.starts_with("1970-01-01T00:00:00"));
    }
}
