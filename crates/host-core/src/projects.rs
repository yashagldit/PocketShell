//! Aggregates unique project directories from Claude Code and Codex session
//! files on disk. Lighter than `list_coding_sessions`: no titles, no pagination,
//! only cwd extraction and per-path chat counts for the mobile projects list.

use crate::coding_sessions::{collect_claude_candidates, collect_codex_candidates, Source};
use crate::error::{HostError, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

const CLAUDE_CWD_SCAN_LINE_CAP: usize = 80;

#[derive(Debug, Serialize)]
struct ProjectInfo {
    path: String,
    chat_count: u32,
    last_activity_at: String,
    last_activity_micros: i64,
}

pub async fn list_projects() -> Result<serde_json::Value> {
    let home = dirs::home_dir().ok_or_else(|| HostError::Backend("home dir not found".into()))?;
    let claude_dir = home.join(".claude");
    let codex_dir = home.join(".codex");

    let claude_task = tokio::task::spawn_blocking(move || collect_claude_candidates(&claude_dir));
    let codex_task = tokio::task::spawn_blocking(move || collect_codex_candidates(&codex_dir));

    let (claude_res, codex_res) = tokio::join!(claude_task, codex_task);
    let mut candidates = claude_res.map_err(task_err)?;
    candidates.extend(codex_res.map_err(task_err)?);

    let aggregated = tokio::task::spawn_blocking(move || aggregate_projects(candidates))
        .await
        .map_err(task_err)?;

    Ok(serde_json::json!({
        "projects": aggregated,
        "scanned_at": chrono::Utc::now().to_rfc3339(),
    }))
}

fn task_err(e: tokio::task::JoinError) -> HostError {
    HostError::Backend(format!("projects scan panicked: {e}"))
}

fn aggregate_projects(
    candidates: Vec<crate::coding_sessions::SessionCandidate>,
) -> Vec<ProjectInfo> {
    let mut by_path: HashMap<String, (u32, i64)> = HashMap::new();

    for candidate in candidates {
        let cwd = match candidate.source {
            Source::Claude => extract_claude_cwd(&candidate.file_path),
            Source::Codex => extract_codex_cwd(&candidate.file_path),
        };
        if cwd.is_empty() {
            continue;
        }
        let entry = by_path.entry(cwd).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.max(candidate.mtime_micros);
    }

    let mut projects: Vec<ProjectInfo> = by_path
        .into_iter()
        .map(|(path, (chat_count, last_activity_micros))| ProjectInfo {
            path,
            chat_count,
            last_activity_at: micros_to_rfc3339(last_activity_micros),
            last_activity_micros,
        })
        .collect();

    projects.sort_by(|a, b| {
        b.last_activity_micros
            .cmp(&a.last_activity_micros)
            .then_with(|| a.path.cmp(&b.path))
    });
    projects
}

fn extract_claude_cwd(file_path: &Path) -> String {
    let file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let reader = BufReader::new(file);
    for (i, line) in reader.lines().enumerate() {
        if i >= CLAUDE_CWD_SCAN_LINE_CAP {
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
        if let Some(cwd) = raw.get("cwd").and_then(|v| v.as_str()) {
            if !cwd.is_empty() {
                return cwd.to_string();
            }
        }
    }
    String::new()
}

fn extract_codex_cwd(file_path: &Path) -> String {
    let file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).ok().unwrap_or(0) == 0 {
        return String::new();
    }
    let raw: serde_json::Value = match serde_json::from_str(first_line.trim()) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if raw.get("type").and_then(|v| v.as_str()) != Some("session_meta") {
        return String::new();
    }
    raw.get("payload")
        .and_then(|p| p.get("cwd"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn micros_to_rfc3339(micros: i64) -> String {
    use chrono::{TimeZone, Utc};
    let secs = micros.div_euclid(1_000_000);
    let nsecs = ((micros.rem_euclid(1_000_000)) * 1_000) as u32;
    Utc.timestamp_opt(secs, nsecs)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extract_claude_cwd_reads_early_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sess.jsonl");
        let mut f = fs::File::create(&p).unwrap();
        writeln!(
            f,
            r#"{{"sessionId":"abc","cwd":"/work/my-app","type":"user"}}"#
        )
        .unwrap();
        assert_eq!(extract_claude_cwd(&p), "/work/my-app");
    }

    #[test]
    fn extract_codex_cwd_reads_session_meta() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-x.jsonl");
        fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"x","cwd":"/repo"}}
"#,
        )
        .unwrap();
        assert_eq!(extract_codex_cwd(&p), "/repo");
    }

    #[test]
    fn aggregate_projects_merges_same_path() {
        use crate::coding_sessions::SessionCandidate;
        use std::path::PathBuf;
        use std::time::{Duration, SystemTime};

        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("c.jsonl");
        let codex = dir.path().join("d.jsonl");
        fs::write(&claude, r#"{"sessionId":"a","cwd":"/proj","type":"user"}"#).unwrap();
        fs::write(
            &codex,
            r#"{"type":"session_meta","payload":{"id":"b","cwd":"/proj"}}
"#,
        )
        .unwrap();

        let candidates = vec![
            SessionCandidate {
                source: Source::Claude,
                file_path: PathBuf::from(&claude),
                mtime_micros: crate::coding_sessions::system_time_micros(t0),
                mtime_system: t0,
                size_bytes: fs::metadata(&claude).unwrap().len(),
            },
            SessionCandidate {
                source: Source::Codex,
                file_path: PathBuf::from(&codex),
                mtime_micros: crate::coding_sessions::system_time_micros(t1),
                mtime_system: t1,
                size_bytes: fs::metadata(&codex).unwrap().len(),
            },
        ];
        let out = aggregate_projects(candidates);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "/proj");
        assert_eq!(out[0].chat_count, 2);
    }
}
