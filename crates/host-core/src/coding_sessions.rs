// Discovers Claude Code and Codex chat sessions on disk and returns a
// compact summary list for the mobile app.

use crate::error::{HostError, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const TITLE_MAX_CHARS: usize = 80;
/// Hard cap on lines scanned per Claude JSONL when searching for metadata —
/// bounds worst-case I/O on a session with no qualifying user message.
const CLAUDE_SCAN_LINE_CAP: usize = 200;
/// Codex titles can come from early user turns or rename events in the rollout.
/// Keep the scan bounded so listing hundreds of sessions remains predictable.
const CODEX_SCAN_LINE_CAP: usize = 500;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const DEFAULT_PROJECT_SESSION_LIMIT: usize = 5;
const SESSION_PARSE_CACHE_MAX_ENTRIES: usize = 20_000;

#[derive(Default)]
struct CodexTitleStores {
    session_index: HashMap<String, String>,
    global_state: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Claude,
    Codex,
}

#[derive(Clone)]
pub(crate) struct SessionCandidate {
    pub(crate) source: Source,
    pub(crate) file_path: PathBuf,
    pub(crate) mtime_micros: i64,
    pub(crate) mtime_system: SystemTime,
    pub(crate) size_bytes: u64,
}

#[derive(Deserialize, Serialize)]
struct PageCursor {
    mtime_micros: i64,
    source: Source,
    file_path: String,
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub source: Source,
    pub file_path: String,
    pub title: String,
    pub project_path: String,
    pub size_bytes: u64,
    pub mtime: String,
    /// True if a host-side agent child for this session_id is currently
    /// running. Mobile uses this to badge rows as "live" so the user can tap
    /// them and reattach instead of spawning a new `--resume` child.
    pub alive: bool,
}

#[derive(Clone)]
enum CachedTitle {
    Fixed(String),
    Codex {
        thread_event: Option<String>,
        first_response_user: Option<String>,
        first_event_user: Option<String>,
    },
}

#[derive(Clone)]
struct CachedSessionInfo {
    session_id: String,
    source: Source,
    file_path: String,
    title: CachedTitle,
    project_path: String,
    size_bytes: u64,
    mtime: String,
}

struct SessionParseCacheEntry {
    mtime_micros: i64,
    size_bytes: u64,
    parsed: Option<CachedSessionInfo>,
}

static SESSION_PARSE_CACHE: OnceLock<Mutex<HashMap<PathBuf, SessionParseCacheEntry>>> =
    OnceLock::new();
static CODEX_TITLE_STORE_CACHE: OnceLock<Mutex<HashMap<PathBuf, CodexTitleStoreCacheEntry>>> =
    OnceLock::new();

struct CodexTitleStoreCacheEntry {
    mtime_micros: Option<i64>,
    size_bytes: u64,
    titles: HashMap<String, String>,
}

fn session_parse_cache() -> &'static Mutex<HashMap<PathBuf, SessionParseCacheEntry>> {
    SESSION_PARSE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn codex_title_store_cache() -> &'static Mutex<HashMap<PathBuf, CodexTitleStoreCacheEntry>> {
    CODEX_TITLE_STORE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
static SESSION_PARSE_MISS_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static SESSION_PARSE_MISS_PATH_COUNTS: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();

#[cfg(test)]
fn reset_session_parse_miss_count() {
    SESSION_PARSE_MISS_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    SESSION_PARSE_MISS_PATH_COUNTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(test)]
fn session_parse_miss_count_for(path: &Path) -> usize {
    SESSION_PARSE_MISS_PATH_COUNTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(path)
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
fn reset_coding_session_caches_for_test() {
    session_parse_cache().lock().unwrap().clear();
    codex_title_store_cache().lock().unwrap().clear();
    reset_session_parse_miss_count();
}

#[derive(Serialize)]
pub struct ProjectSessionsInfo {
    pub project_path: String,
    pub total: usize,
    pub loaded: usize,
    pub last_activity_at: String,
    pub last_activity_micros: i64,
    pub next_cursor: Option<String>,
}

struct ProjectSessionGroup {
    project_path: String,
    total: usize,
    last_activity_micros: i64,
    sessions: Vec<SessionInfo>,
    last_loaded_candidate: Option<SessionCandidate>,
}

pub async fn list_sessions(
    limit: Option<usize>,
    cursor: Option<String>,
    alive_ids: HashSet<String>,
    project_path: Option<String>,
    group_by_project: bool,
    project_session_limit: Option<usize>,
) -> Result<serde_json::Value> {
    let home = dirs::home_dir().ok_or_else(|| HostError::Backend("home dir not found".into()))?;
    list_sessions_in_home(
        home,
        limit,
        cursor,
        alive_ids,
        project_path,
        group_by_project,
        project_session_limit,
    )
    .await
}

async fn list_sessions_in_home(
    home: PathBuf,
    limit: Option<usize>,
    cursor: Option<String>,
    alive_ids: HashSet<String>,
    project_path: Option<String>,
    group_by_project: bool,
    project_session_limit: Option<usize>,
) -> Result<serde_json::Value> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = cursor
        .as_deref()
        .and_then(|s| serde_json::from_str::<PageCursor>(s).ok());
    let project_filter = project_path
        .as_deref()
        .map(normalize_project_path)
        .filter(|s| !s.is_empty());

    let claude_dir = home.join(".claude");
    let codex_dir = home.join(".codex");

    let claude_task = tokio::task::spawn_blocking(move || collect_claude_candidates(&claude_dir));
    let codex_task = tokio::task::spawn_blocking(move || collect_codex_candidates(&codex_dir));

    let (claude_res, codex_res) = tokio::join!(claude_task, codex_task);
    let mut candidates = claude_res.map_err(task_err)?;
    candidates.extend(codex_res.map_err(task_err)?);

    candidates.sort_by(compare_candidates);
    prune_session_parse_cache(&candidates);
    let total = candidates.len();

    if let Some(project_filter) = project_filter {
        return list_project_sessions(home, candidates, limit, cursor, alive_ids, project_filter)
            .await;
    }

    if group_by_project && cursor.is_none() {
        return list_grouped_project_sessions(
            home,
            candidates,
            project_session_limit
                .unwrap_or(DEFAULT_PROJECT_SESSION_LIMIT)
                .clamp(1, MAX_LIMIT),
            alive_ids,
        )
        .await;
    }

    let page_candidates: Vec<SessionCandidate> = candidates
        .into_iter()
        .filter(|c| is_after_cursor(c, cursor.as_ref()))
        .take(limit + 1)
        .collect();
    let has_more = page_candidates.len() > limit;
    let next_cursor = if has_more {
        page_candidates
            .get(limit.saturating_sub(1))
            .map(candidate_cursor)
            .transpose()?
    } else {
        None
    };

    let codex_titles = if page_candidates
        .iter()
        .take(limit)
        .any(|c| c.source == Source::Codex)
    {
        Some(load_codex_title_stores(&home.join(".codex")))
    } else {
        None
    };

    let mut sessions = Vec::new();
    for candidate in page_candidates.into_iter().take(limit) {
        let parsed = cached_parse_session(&candidate);
        if let Some(session) = parsed.and_then(|parsed| {
            session_from_cached(
                &parsed,
                codex_titles.as_ref(),
                alive_ids.contains(&parsed.session_id),
            )
        }) {
            sessions.push(session);
        }
    }

    Ok(serde_json::json!({
        "sessions": sessions,
        "total": total,
        "pagination_supported": true,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }))
}

async fn list_grouped_project_sessions(
    home: PathBuf,
    candidates: Vec<SessionCandidate>,
    per_project_limit: usize,
    alive_ids: HashSet<String>,
) -> Result<serde_json::Value> {
    let codex_titles = load_codex_title_stores(&home.join(".codex"));
    let mut groups: HashMap<String, ProjectSessionGroup> = HashMap::new();
    let mut total = 0usize;

    for candidate in candidates {
        let parsed = cached_parse_session(&candidate);
        let Some(session) = parsed.and_then(|parsed| {
            session_from_cached(
                &parsed,
                Some(&codex_titles),
                alive_ids.contains(&parsed.session_id),
            )
        }) else {
            continue;
        };

        total += 1;
        let key = normalize_project_path(&session.project_path);
        let group = groups.entry(key).or_insert_with(|| ProjectSessionGroup {
            project_path: normalize_project_path(&session.project_path),
            total: 0,
            last_activity_micros: 0,
            sessions: Vec::new(),
            last_loaded_candidate: None,
        });
        group.total += 1;
        group.last_activity_micros = group.last_activity_micros.max(candidate.mtime_micros);
        if group.sessions.len() < per_project_limit {
            group.last_loaded_candidate = Some(candidate.clone());
            group.sessions.push(session);
        }
    }

    let mut groups: Vec<ProjectSessionGroup> = groups.into_values().collect();
    groups.sort_by(|a, b| {
        if a.project_path.is_empty() {
            return std::cmp::Ordering::Greater;
        }
        if b.project_path.is_empty() {
            return std::cmp::Ordering::Less;
        }
        b.last_activity_micros
            .cmp(&a.last_activity_micros)
            .then_with(|| a.project_path.cmp(&b.project_path))
    });

    let mut sessions = Vec::new();
    let mut project_totals = Vec::new();
    for group in groups {
        project_totals.push(ProjectSessionsInfo {
            project_path: group.project_path,
            total: group.total,
            loaded: group.sessions.len(),
            last_activity_at: micros_to_rfc3339(group.last_activity_micros),
            last_activity_micros: group.last_activity_micros,
            next_cursor: if group.total > group.sessions.len() {
                group
                    .last_loaded_candidate
                    .as_ref()
                    .map(candidate_cursor)
                    .transpose()?
            } else {
                None
            },
        });
        sessions.extend(group.sessions);
    }

    Ok(serde_json::json!({
        "sessions": sessions,
        "total": total,
        "pagination_supported": false,
        "has_more": false,
        "next_cursor": null,
        "grouped_by_project": true,
        "project_totals": project_totals,
    }))
}

async fn list_project_sessions(
    home: PathBuf,
    candidates: Vec<SessionCandidate>,
    limit: usize,
    cursor: Option<PageCursor>,
    alive_ids: HashSet<String>,
    project_filter: String,
) -> Result<serde_json::Value> {
    let codex_titles = load_codex_title_stores(&home.join(".codex"));
    let mut total = 0usize;
    let mut sessions = Vec::new();
    let mut next_cursor = None;
    let mut last_returned_candidate = None;

    for candidate in candidates.into_iter() {
        let parsed = cached_parse_session(&candidate);
        let Some(mut session) =
            parsed.and_then(|parsed| session_from_cached(&parsed, Some(&codex_titles), false))
        else {
            continue;
        };
        if normalize_project_path(&session.project_path) != project_filter {
            continue;
        }

        total += 1;
        if !is_after_cursor(&candidate, cursor.as_ref()) {
            continue;
        }
        if sessions.len() < limit {
            session.alive = alive_ids.contains(&session.session_id);
            last_returned_candidate = Some(candidate.clone());
            sessions.push(session);
        } else if next_cursor.is_none() {
            next_cursor = last_returned_candidate
                .as_ref()
                .map(candidate_cursor)
                .transpose()?;
        }
    }

    Ok(serde_json::json!({
        "sessions": sessions,
        "total": total,
        "pagination_supported": true,
        "has_more": next_cursor.is_some(),
        "next_cursor": next_cursor,
    }))
}

fn normalize_project_path(path: &str) -> String {
    path.replace('\\', "/").trim_end_matches('/').to_string()
}

fn claude_project_path_from_record(raw: &serde_json::Value) -> Option<&str> {
    ["cwd", "project_path", "projectPath"]
        .into_iter()
        .find_map(|key| {
            raw.get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
}

fn decode_claude_project_path_from_file(file_path: &Path) -> Option<String> {
    let encoded = file_path.parent()?.file_name()?.to_str()?;
    decode_claude_project_dir(encoded)
}

fn decode_claude_project_dir(encoded: &str) -> Option<String> {
    if encoded.is_empty() {
        return None;
    }
    if encoded == "-" {
        return Some("/".to_string());
    }
    if let Some(path) = decode_windows_claude_project_dir(encoded) {
        return Some(path);
    }
    if let Some(path) = decode_existing_unix_claude_project_dir(encoded) {
        return Some(path);
    }
    if encoded.starts_with('-') {
        return Some(encoded.replace('-', "/"));
    }
    Some(encoded.to_string())
}

fn decode_windows_claude_project_dir(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    for (idx, window) in bytes.windows(3).enumerate() {
        if !encoded[..idx].bytes().all(|b| b == b'-') {
            return None;
        }
        let drive = window[0];
        let drive_sep_is_double_dash = window[1] == b'-' && window[2] == b'-';
        let drive_sep_is_colon_dash = window[1] == b':' && window[2] == b'-';
        if !drive.is_ascii_alphabetic() || (!drive_sep_is_double_dash && !drive_sep_is_colon_dash) {
            continue;
        }
        let rest = &encoded[idx + 3..];
        let drive = drive as char;
        let root = PathBuf::from(format!("{}:\\", drive.to_ascii_uppercase()));
        let parts: Vec<&str> = rest.split('-').filter(|part| !part.is_empty()).collect();
        if let Some(path) = resolve_existing_encoded_path(root, &parts) {
            return Some(path.to_string_lossy().into_owned());
        }
        if rest.is_empty() {
            return Some(format!("{}:\\", drive.to_ascii_uppercase()));
        }
        return Some(format!(
            "{}:\\{}",
            drive.to_ascii_uppercase(),
            rest.replace('-', "\\")
        ));
    }
    None
}

fn decode_existing_unix_claude_project_dir(encoded: &str) -> Option<String> {
    let rest = encoded.strip_prefix('-')?;
    if rest.is_empty() {
        return Some("/".to_string());
    }

    let parts: Vec<&str> = rest.split('-').filter(|part| !part.is_empty()).collect();
    let path = resolve_existing_encoded_path(PathBuf::from("/"), &parts)?;
    Some(path.to_string_lossy().into_owned())
}

fn resolve_existing_encoded_path(base: PathBuf, parts: &[&str]) -> Option<PathBuf> {
    if parts.is_empty() {
        return base.exists().then_some(base);
    }

    for end in 1..=parts.len() {
        let component = parts[..end].join("-");
        let candidate = base.join(component);
        if candidate.exists() {
            if let Some(resolved) = resolve_existing_encoded_path(candidate, &parts[end..]) {
                return Some(resolved);
            }
        }
    }

    None
}

fn cached_parse_session(candidate: &SessionCandidate) -> Option<CachedSessionInfo> {
    if let Some(hit) = {
        let cache = session_parse_cache().lock().unwrap();
        cache.get(&candidate.file_path).and_then(|entry| {
            if entry.mtime_micros == candidate.mtime_micros
                && entry.size_bytes == candidate.size_bytes
            {
                Some(entry.parsed.clone())
            } else {
                None
            }
        })
    } {
        return hit;
    }

    #[cfg(test)]
    {
        SESSION_PARSE_MISS_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *SESSION_PARSE_MISS_PATH_COUNTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(candidate.file_path.clone())
            .or_insert(0) += 1;
    }

    let parsed = match candidate.source {
        Source::Claude => parse_claude_session_cached(candidate),
        Source::Codex => parse_codex_session_cached(candidate),
    };

    let mut cache = session_parse_cache().lock().unwrap();
    cache.insert(
        candidate.file_path.clone(),
        SessionParseCacheEntry {
            mtime_micros: candidate.mtime_micros,
            size_bytes: candidate.size_bytes,
            parsed: parsed.clone(),
        },
    );
    parsed
}

fn prune_session_parse_cache(candidates: &[SessionCandidate]) {
    let seen: HashSet<&Path> = candidates.iter().map(|c| c.file_path.as_path()).collect();
    let mut cache = session_parse_cache().lock().unwrap();
    cache.retain(|path, _| seen.contains(path.as_path()));

    if cache.len() <= SESSION_PARSE_CACHE_MAX_ENTRIES {
        return;
    }

    let mut entries: Vec<(PathBuf, i64)> = cache
        .iter()
        .map(|(path, entry)| (path.clone(), entry.mtime_micros))
        .collect();
    entries.sort_by_key(|(_, mtime)| *mtime);
    let remove_count = cache.len() - SESSION_PARSE_CACHE_MAX_ENTRIES;
    for (path, _) in entries.into_iter().take(remove_count) {
        cache.remove(&path);
    }
}

fn session_from_cached(
    cached: &CachedSessionInfo,
    codex_titles: Option<&CodexTitleStores>,
    alive: bool,
) -> Option<SessionInfo> {
    let title = match &cached.title {
        CachedTitle::Fixed(title) => title.clone(),
        CachedTitle::Codex {
            thread_event,
            first_response_user,
            first_event_user,
        } => {
            let titles = codex_titles?;
            titles
                .session_index
                .get(&cached.session_id)
                .cloned()
                .or_else(|| thread_event.clone())
                .or_else(|| titles.global_state.get(&cached.session_id).cloned())
                .or_else(|| first_response_user.clone())
                .or_else(|| first_event_user.clone())
                .unwrap_or_else(|| "Codex Session".to_string())
        }
    };

    Some(SessionInfo {
        session_id: cached.session_id.clone(),
        source: cached.source,
        file_path: cached.file_path.clone(),
        title,
        project_path: cached.project_path.clone(),
        size_bytes: cached.size_bytes,
        mtime: cached.mtime.clone(),
        alive,
    })
}

fn task_err(e: tokio::task::JoinError) -> HostError {
    HostError::Backend(format!("coding_sessions scan panicked: {e}"))
}

pub(crate) fn collect_claude_candidates(claude_dir: &Path) -> Vec<SessionCandidate> {
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

            if let Some(candidate) = make_candidate(Source::Claude, file_path) {
                out.push(candidate);
            }
        }
    }

    out
}

fn parse_claude_session_cached(candidate: &SessionCandidate) -> Option<CachedSessionInfo> {
    let file_path = &candidate.file_path;
    let file = fs::File::open(file_path).ok()?;
    let reader = BufReader::new(file);

    let mut session_id = String::new();
    let mut cwd = String::new();
    // Claude emits a dedicated `{"type":"ai-title","aiTitle":...}` line — a
    // concise LLM-generated summary. Prefer it; fall back to the first
    // non-meta user message for sessions that have no ai-title yet (brand-new
    // or pre-feature sessions).
    let mut ai_title: Option<String> = None;
    let mut user_title: Option<String> = None;

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
            if let Some(c) = claude_project_path_from_record(&raw) {
                cwd = c.to_string();
            }
        }

        if ai_title.is_none() {
            if let Some(t) = raw.get("aiTitle").and_then(|v| v.as_str()) {
                ai_title = normalize_title(t);
            }
        }

        if user_title.is_none() {
            let is_user = raw.get("type").and_then(|v| v.as_str()) == Some("user");
            let is_meta = raw.get("isMeta").and_then(|v| v.as_bool()).unwrap_or(false);
            if is_user && !is_meta {
                if let Some(content) = raw.get("message").and_then(|m| m.get("content")) {
                    if let Some(t) = extract_title(content) {
                        user_title = Some(t);
                    }
                }
            }
        }

        // The ai-title is the best source — once we have it plus identity and
        // location, stop. Sessions without one fall through to the line cap.
        if ai_title.is_some() && !session_id.is_empty() && !cwd.is_empty() {
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

    let title = ai_title
        .or(user_title)
        .unwrap_or_else(|| "Untitled Session".to_string());

    if cwd.is_empty() {
        cwd = decode_claude_project_path_from_file(file_path).unwrap_or_default();
    }

    Some(CachedSessionInfo {
        session_id,
        source: Source::Claude,
        file_path: file_path.to_string_lossy().into_owned(),
        title: CachedTitle::Fixed(title),
        project_path: cwd,
        size_bytes: candidate.size_bytes,
        mtime: format_mtime(candidate.mtime_system),
    })
}

#[cfg(test)]
fn parse_claude_session(file_path: &Path) -> Option<SessionInfo> {
    let candidate = make_candidate(Source::Claude, file_path.to_path_buf())?;
    cached_parse_session(&candidate).and_then(|cached| session_from_cached(&cached, None, false))
}

pub(crate) fn collect_codex_candidates(codex_dir: &Path) -> Vec<SessionCandidate> {
    let sessions_root = codex_dir.join("sessions");
    let mut out = Vec::new();

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

            if let Some(candidate) = make_candidate(Source::Codex, path) {
                out.push(candidate);
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

fn load_codex_global_state_titles(global_state_path: &Path) -> HashMap<String, String> {
    let raw = fs::read_to_string(global_state_path).ok();
    let Some(raw) = raw else {
        return HashMap::new();
    };
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .ok()
        .unwrap_or(serde_json::Value::Null);
    let titles = parsed
        .get("thread-titles")
        .and_then(|v| v.get("titles"))
        .and_then(|v| v.as_object());
    let Some(titles) = titles else {
        return HashMap::new();
    };
    titles
        .iter()
        .filter_map(|(id, title)| {
            if id.ends_with("_old") {
                return None;
            }
            normalize_title(title.as_str().unwrap_or(""))
                .filter(|_| !id.is_empty())
                .map(|title| (id.to_string(), title))
        })
        .collect()
}

fn load_cached_title_store(
    path: &Path,
    loader: impl FnOnce(&Path) -> HashMap<String, String>,
) -> HashMap<String, String> {
    let metadata = fs::metadata(path).ok();
    let mtime_micros = metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(system_time_micros);
    let size_bytes = metadata.as_ref().map(fs::Metadata::len).unwrap_or(0);

    if let Some(hit) = {
        let cache = codex_title_store_cache().lock().unwrap();
        cache.get(path).and_then(|entry| {
            if entry.mtime_micros == mtime_micros && entry.size_bytes == size_bytes {
                Some(entry.titles.clone())
            } else {
                None
            }
        })
    } {
        return hit;
    }

    let titles = metadata
        .as_ref()
        .filter(|m| m.is_file())
        .map(|_| loader(path))
        .unwrap_or_default();
    let mut cache = codex_title_store_cache().lock().unwrap();
    cache.insert(
        path.to_path_buf(),
        CodexTitleStoreCacheEntry {
            mtime_micros,
            size_bytes,
            titles: titles.clone(),
        },
    );
    titles
}

fn load_codex_title_stores(codex_dir: &Path) -> CodexTitleStores {
    CodexTitleStores {
        session_index: load_cached_title_store(&codex_dir.join("session_index.jsonl"), |path| {
            load_codex_index(path)
        }),
        global_state: load_cached_title_store(
            &codex_dir.join(".codex-global-state.json"),
            |path| load_codex_global_state_titles(path),
        ),
    }
}

fn parse_codex_session_cached(candidate: &SessionCandidate) -> Option<CachedSessionInfo> {
    let file_path = &candidate.file_path;
    let file = fs::File::open(file_path).ok()?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let first_line = lines.next()?.ok()?;
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

    let mut thread_event_title: Option<String> = None;
    let mut first_response_user_title: Option<String> = None;
    let mut first_event_user_title: Option<String> = None;

    for line in lines.take(CODEX_SCAN_LINE_CAP.saturating_sub(1)).flatten() {
        if line.trim().is_empty() {
            continue;
        }
        let raw: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match raw.get("type").and_then(|v| v.as_str()) {
            Some("response_item") => {
                let payload = raw.get("payload").unwrap_or(&serde_json::Value::Null);
                if first_response_user_title.is_none()
                    && payload.get("type").and_then(|v| v.as_str()) == Some("message")
                    && payload.get("role").and_then(|v| v.as_str()) == Some("user")
                {
                    if let Some(content) = payload.get("content") {
                        first_response_user_title = extract_title(content);
                    }
                }
            }
            Some("event_msg") => {
                let payload = raw.get("payload").unwrap_or(&serde_json::Value::Null);
                match payload.get("type").and_then(|v| v.as_str()) {
                    Some("thread_name_updated") => {
                        if let Some(t) = payload
                            .get("thread_name")
                            .and_then(|v| v.as_str())
                            .and_then(normalize_title)
                        {
                            thread_event_title = Some(t);
                        }
                    }
                    Some("user_message") if first_event_user_title.is_none() => {
                        if let Some(t) = payload
                            .get("message")
                            .and_then(|v| v.as_str())
                            .and_then(normalize_title)
                        {
                            first_event_user_title = Some(t);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Some(CachedSessionInfo {
        session_id,
        source: Source::Codex,
        file_path: file_path.to_string_lossy().into_owned(),
        title: CachedTitle::Codex {
            thread_event: thread_event_title,
            first_response_user: first_response_user_title,
            first_event_user: first_event_user_title,
        },
        project_path: cwd,
        size_bytes: candidate.size_bytes,
        mtime: format_mtime(candidate.mtime_system),
    })
}

#[cfg(test)]
fn parse_codex_session(file_path: &Path, titles: &CodexTitleStores) -> Option<SessionInfo> {
    let candidate = make_candidate(Source::Codex, file_path.to_path_buf())?;
    cached_parse_session(&candidate)
        .and_then(|cached| session_from_cached(&cached, Some(titles), false))
}

fn make_candidate(source: Source, file_path: PathBuf) -> Option<SessionCandidate> {
    let metadata = file_path.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mtime_system = metadata.modified().ok()?;
    Some(SessionCandidate {
        source,
        file_path,
        mtime_micros: system_time_micros(mtime_system),
        mtime_system,
        size_bytes: metadata.len(),
    })
}

pub(crate) fn system_time_micros(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_micros().min(i64::MAX as u128) as i64,
        Err(e) => {
            let micros = e.duration().as_micros().min(i64::MAX as u128) as i64;
            -micros
        }
    }
}

fn compare_candidates(a: &SessionCandidate, b: &SessionCandidate) -> std::cmp::Ordering {
    b.mtime_micros
        .cmp(&a.mtime_micros)
        .then_with(|| a.source.cmp(&b.source))
        .then_with(|| a.file_path.cmp(&b.file_path))
}

fn is_after_cursor(candidate: &SessionCandidate, cursor: Option<&PageCursor>) -> bool {
    let Some(cursor) = cursor else {
        return true;
    };
    if candidate.mtime_micros != cursor.mtime_micros {
        return candidate.mtime_micros < cursor.mtime_micros;
    }
    if candidate.source != cursor.source {
        return candidate.source > cursor.source;
    }
    candidate.file_path.to_string_lossy().as_ref() > cursor.file_path.as_str()
}

fn candidate_cursor(candidate: &SessionCandidate) -> Result<String> {
    let cursor = PageCursor {
        mtime_micros: candidate.mtime_micros,
        source: candidate.source,
        file_path: candidate.file_path.to_string_lossy().into_owned(),
    };
    serde_json::to_string(&cursor)
        .map_err(|e| HostError::Backend(format!("coding_sessions cursor encode failed: {e}")))
}

fn format_mtime(t: SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    dt.to_rfc3339()
}

fn micros_to_rfc3339(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let nsecs = ((micros.rem_euclid(1_000_000)) * 1_000) as u32;
    Utc.timestamp_opt(secs, nsecs)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339())
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

    normalize_title(&raw)
}

/// Collapse whitespace, reject system/IDE noise, and truncate to
/// `TITLE_MAX_CHARS` on a word boundary. Shared by the user-message and
/// `ai-title` title sources.
fn normalize_title(raw: &str) -> Option<String> {
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

    fn codex_titles(session_index: HashMap<String, String>) -> CodexTitleStores {
        CodexTitleStores {
            session_index,
            global_state: HashMap::new(),
        }
    }

    fn codex_titles_with_global(global_state: HashMap<String, String>) -> CodexTitleStores {
        CodexTitleStores {
            session_index: HashMap::new(),
            global_state,
        }
    }

    fn encode_claude_project_dir_for_test(path: &Path) -> String {
        let encoded = path
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "-");
        if cfg!(windows) {
            encoded.replacen(":-", "--", 1)
        } else {
            encoded
        }
    }

    fn session_candidate_for_test(
        source: Source,
        file_path: PathBuf,
        mtime_micros: i64,
    ) -> SessionCandidate {
        let metadata = std::fs::metadata(&file_path).unwrap();
        SessionCandidate {
            source,
            file_path,
            mtime_micros,
            mtime_system: metadata.modified().unwrap(),
            size_bytes: metadata.len(),
        }
    }

    fn coding_session_cache_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn write_home_claude_session(home: &Path, name: &str, title: &str) -> PathBuf {
        let project_dir = home.join(".claude/projects/-work-project");
        std::fs::create_dir_all(&project_dir).unwrap();
        let path = project_dir.join(format!("{name}.jsonl"));
        std::fs::write(
            &path,
            format!(
                r#"{{"type":"system","sessionId":"{name}","cwd":"/work/project"}}
{{"type":"user","message":{{"content":"{title}"}}}}
"#
            ),
        )
        .unwrap();
        path
    }

    fn cache_contains(path: &Path) -> bool {
        session_parse_cache().lock().unwrap().contains_key(path)
    }

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
        assert_eq!(
            extract_title(&content).as_deref(),
            Some("first real message")
        );
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
    fn session_info_serde_includes_public_fields() {
        let info = SessionInfo {
            session_id: "abc".into(),
            source: Source::Claude,
            file_path: "/tmp/x.jsonl".into(),
            title: "t".into(),
            project_path: "/tmp".into(),
            size_bytes: 42,
            mtime: "1970-01-01T00:00:00+00:00".into(),
            alive: false,
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["session_id"], "abc");
        assert_eq!(v["source"], "claude");
        assert_eq!(v["size_bytes"], 42);
        assert_eq!(v["mtime"], "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn scan_claude_missing_dir_returns_empty() {
        let dir = std::path::PathBuf::from("/no/such/claude/xyz-missing-9999");
        assert!(collect_claude_candidates(&dir).is_empty());
    }

    #[test]
    fn scan_codex_missing_dir_returns_empty() {
        let dir = std::path::PathBuf::from("/no/such/codex/xyz-missing-9999");
        assert!(collect_codex_candidates(&dir).is_empty());
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
        std::fs::write(
            &p,
            r#"{"type":"other","payload":{"id":"x"}}
"#,
        )
        .unwrap();
        let titles = CodexTitleStores::default();
        assert!(parse_codex_session(&p, &titles).is_none());
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
        let info = parse_codex_session(&p, &codex_titles(idx)).unwrap();
        assert_eq!(info.session_id, "sess-1");
        assert_eq!(info.title, "My Session");
        assert_eq!(info.project_path, "/work/dir");
    }

    #[test]
    fn parse_codex_session_uses_thread_name_updated_event() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-z.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-2","cwd":""}}
{"type":"event_msg","payload":{"type":"thread_name_updated","thread_name":"Renamed from event"}}
"#,
        )
        .unwrap();
        let titles = CodexTitleStores::default();
        let info = parse_codex_session(&p, &titles).unwrap();
        assert_eq!(info.title, "Renamed from event");
    }

    #[test]
    fn parse_codex_session_uses_legacy_global_state_title() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-global.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-global","cwd":""}}
"#,
        )
        .unwrap();
        let mut global = HashMap::new();
        global.insert("sess-global".into(), "Legacy Global Title".into());
        let info = parse_codex_session(&p, &codex_titles_with_global(global)).unwrap();
        assert_eq!(info.title, "Legacy Global Title");
    }

    #[test]
    fn parse_codex_session_uses_first_response_user_prompt_title() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-user.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-user","cwd":""}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Implement better Codex titles in history"}]}}
"#,
        )
        .unwrap();
        let titles = CodexTitleStores::default();
        let info = parse_codex_session(&p, &titles).unwrap();
        assert_eq!(info.title, "Implement better Codex titles in history");
    }

    #[test]
    fn parse_codex_session_uses_first_event_user_prompt_title() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-event-user.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-event-user","cwd":""}}
{"type":"event_msg","payload":{"type":"user_message","message":"Look into the mobile agent drawer title"}}
"#,
        )
        .unwrap();
        let titles = CodexTitleStores::default();
        let info = parse_codex_session(&p, &titles).unwrap();
        assert_eq!(info.title, "Look into the mobile agent drawer title");
    }

    #[test]
    fn parse_codex_session_falls_back_to_codex_session_title() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rollout-no-title.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"session_meta","payload":{"id":"sess-empty-title","cwd":""}}
"#,
        )
        .unwrap();
        let titles = CodexTitleStores::default();
        let info = parse_codex_session(&p, &titles).unwrap();
        assert_eq!(info.title, "Codex Session");
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
        let titles = CodexTitleStores::default();
        assert!(parse_codex_session(&p, &titles).is_none());
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
    fn parse_claude_session_prefers_ai_title_over_user_turn() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("claude-ai-title.jsonl");
        // The first user turn appears before the ai-title line, but the
        // generated title must win.
        std::fs::write(
            &p,
            r#"{"type":"system","sessionId":"sess-b","cwd":"/work"}
{"type":"user","message":{"content":"the gatepass page is throwing errors"}}
{"type":"ai-title","aiTitle":"Debug employee gatepass page errors","sessionId":"sess-b"}
"#,
        )
        .unwrap();
        let info = parse_claude_session(&p).unwrap();
        assert_eq!(info.session_id, "sess-b");
        assert_eq!(info.title, "Debug employee gatepass page errors");
    }

    #[test]
    fn parse_claude_session_reads_project_path_when_cwd_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("claude-project-path.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"system","sessionId":"sess-c","project_path":"/work/from-project-path"}
{"type":"user","message":{"content":"first real user text"}}
"#,
        )
        .unwrap();
        let info = parse_claude_session(&p).unwrap();
        assert_eq!(info.session_id, "sess-c");
        assert_eq!(info.project_path, "/work/from-project-path");
    }

    #[test]
    fn parse_claude_session_decodes_project_dir_when_path_missing() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("repo-with-dash");
        std::fs::create_dir(&project).unwrap();
        let encoded_project = encode_claude_project_dir_for_test(&project);
        let claude_project_dir = dir.path().join(".claude/projects").join(encoded_project);
        std::fs::create_dir_all(&claude_project_dir).unwrap();
        let p = claude_project_dir.join("missing-cwd.jsonl");
        std::fs::write(
            &p,
            r#"{"type":"system","sessionId":"sess-d"}
{"type":"user","message":{"content":"first real user text"}}
"#,
        )
        .unwrap();

        let info = parse_claude_session(&p).unwrap();
        assert_eq!(info.project_path, project.to_string_lossy());
    }

    #[test]
    fn decode_claude_project_dir_resolves_nested_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("parent").join("child");
        std::fs::create_dir_all(&project).unwrap();
        let encoded = encode_claude_project_dir_for_test(&project);

        assert_eq!(
            decode_claude_project_dir(&encoded).as_deref(),
            Some(project.to_string_lossy().as_ref()),
        );
    }

    #[test]
    fn decode_claude_project_dir_decodes_windows_drive_prefix() {
        assert_eq!(
            decode_claude_project_dir("D--Codes-PocketShellApp").as_deref(),
            Some("D:\\Codes\\PocketShellApp")
        );
        assert_eq!(
            decode_claude_project_dir("d--xampp-htdocs-cold").as_deref(),
            Some("D:\\xampp\\htdocs\\cold")
        );
    }

    #[test]
    fn decode_claude_project_dir_decodes_prefixed_windows_drive_prefix() {
        assert_eq!(
            decode_claude_project_dir("----C--Users-Yash-Downloads").as_deref(),
            Some("C:\\Users\\Yash\\Downloads")
        );
    }

    #[test]
    fn decode_claude_project_dir_falls_back_to_slashes() {
        assert_eq!(
            decode_claude_project_dir("-Users-someone-missing").as_deref(),
            Some("/Users/someone/missing"),
        );
    }

    #[tokio::test]
    async fn list_project_sessions_cursor_resumes_after_last_returned_match() {
        let dir = tempfile::tempdir().unwrap();
        let project = "/work/project";
        let paths: Vec<PathBuf> = ["newest", "middle", "oldest"]
            .into_iter()
            .map(|name| {
                let path = dir.path().join(format!("{name}.jsonl"));
                std::fs::write(
                    &path,
                    format!(
                        r#"{{"type":"system","sessionId":"{name}","cwd":"{project}"}}
{{"type":"user","message":{{"content":"title for {name}"}}}}
"#
                    ),
                )
                .unwrap();
                path
            })
            .collect();
        let candidates = vec![
            session_candidate_for_test(Source::Claude, paths[0].clone(), 300),
            session_candidate_for_test(Source::Claude, paths[1].clone(), 200),
            session_candidate_for_test(Source::Claude, paths[2].clone(), 100),
        ];

        let first = list_project_sessions(
            dir.path().to_path_buf(),
            candidates.clone(),
            2,
            None,
            HashSet::new(),
            normalize_project_path(project),
        )
        .await
        .unwrap();
        let first_sessions = first["sessions"].as_array().unwrap();
        assert_eq!(first_sessions.len(), 2);
        assert_eq!(first_sessions[0]["session_id"], "newest");
        assert_eq!(first_sessions[1]["session_id"], "middle");
        assert_eq!(first["has_more"], true);

        let cursor = first["next_cursor"].as_str().unwrap().to_string();
        let cursor = serde_json::from_str::<PageCursor>(&cursor).unwrap();
        let second = list_project_sessions(
            dir.path().to_path_buf(),
            candidates,
            2,
            Some(cursor),
            HashSet::new(),
            normalize_project_path(project),
        )
        .await
        .unwrap();
        let second_sessions = second["sessions"].as_array().unwrap();
        assert_eq!(second_sessions.len(), 1);
        assert_eq!(second_sessions[0]["session_id"], "oldest");
        assert_eq!(second["total"], 3);
        assert_eq!(second["has_more"], false);
    }

    #[tokio::test]
    async fn list_grouped_project_sessions_returns_slice_and_totals() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidates = Vec::new();
        for (idx, (project, mtime)) in [
            ("/work/a", 500),
            ("/work/a", 400),
            ("/work/a", 300),
            ("/work/b", 600),
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("sess-{idx}");
            let path = dir.path().join(format!("{name}.jsonl"));
            std::fs::write(
                &path,
                format!(
                    r#"{{"type":"system","sessionId":"{name}","cwd":"{project}"}}
{{"type":"user","message":{{"content":"title for {name}"}}}}
"#
                ),
            )
            .unwrap();
            candidates.push(session_candidate_for_test(Source::Claude, path, mtime));
        }
        candidates.sort_by(compare_candidates);

        let out =
            list_grouped_project_sessions(dir.path().to_path_buf(), candidates, 2, HashSet::new())
                .await
                .unwrap();

        assert_eq!(out["grouped_by_project"], true);
        assert_eq!(out["pagination_supported"], false);
        assert_eq!(out["total"], 4);
        let sessions = out["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 3);
        assert_eq!(sessions[0]["project_path"], "/work/b");
        assert_eq!(sessions[1]["project_path"], "/work/a");
        assert_eq!(sessions[2]["project_path"], "/work/a");

        let totals = out["project_totals"].as_array().unwrap();
        assert_eq!(totals[0]["project_path"], "/work/b");
        assert_eq!(totals[0]["total"], 1);
        assert_eq!(totals[0]["loaded"], 1);
        assert_eq!(totals[1]["project_path"], "/work/a");
        assert_eq!(totals[1]["total"], 3);
        assert_eq!(totals[1]["loaded"], 2);
        assert!(totals[1]["next_cursor"].as_str().is_some());
    }

    #[tokio::test]
    async fn list_sessions_populates_cache_and_reparses_modified_file() {
        let _guard = coding_session_cache_test_lock().lock().await;
        reset_coding_session_caches_for_test();
        let dir = tempfile::tempdir().unwrap();
        let path = write_home_claude_session(dir.path(), "sess-cache", "first cache title");

        let first = list_sessions_in_home(
            dir.path().to_path_buf(),
            Some(10),
            None,
            HashSet::new(),
            None,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(first["sessions"][0]["title"], "first cache title");
        assert!(cache_contains(&path));
        assert_eq!(session_parse_miss_count_for(&path), 1);

        let second = list_sessions_in_home(
            dir.path().to_path_buf(),
            Some(10),
            None,
            HashSet::new(),
            None,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(second["sessions"][0]["title"], "first cache title");
        assert_eq!(session_parse_miss_count_for(&path), 1);

        let before = std::fs::metadata(&path).unwrap();
        for attempt in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::fs::write(
                &path,
                format!(
                    r#"{{"type":"system","sessionId":"sess-cache","cwd":"/work/project"}}
{{"type":"user","message":{{"content":"second cache title with more bytes {attempt}"}}}}
"#
                ),
            )
            .unwrap();
            let after = std::fs::metadata(&path).unwrap();
            if after.len() != before.len()
                || system_time_micros(after.modified().unwrap())
                    != system_time_micros(before.modified().unwrap())
            {
                break;
            }
        }

        let third = list_sessions_in_home(
            dir.path().to_path_buf(),
            Some(10),
            None,
            HashSet::new(),
            None,
            false,
            None,
        )
        .await
        .unwrap();
        assert!(third["sessions"][0]["title"]
            .as_str()
            .unwrap()
            .starts_with("second cache title with more bytes"));
        assert_eq!(session_parse_miss_count_for(&path), 2);
    }

    #[tokio::test]
    async fn list_sessions_evicts_deleted_file_from_cache_after_rescan() {
        let _guard = coding_session_cache_test_lock().lock().await;
        reset_coding_session_caches_for_test();
        let dir = tempfile::tempdir().unwrap();
        let kept = write_home_claude_session(dir.path(), "sess-kept", "kept cache title");
        let deleted = write_home_claude_session(dir.path(), "sess-deleted", "deleted cache title");

        let first = list_sessions_in_home(
            dir.path().to_path_buf(),
            Some(10),
            None,
            HashSet::new(),
            None,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(first["sessions"].as_array().unwrap().len(), 2);
        assert!(cache_contains(&kept));
        assert!(cache_contains(&deleted));
        assert_eq!(session_parse_miss_count_for(&kept), 1);
        assert_eq!(session_parse_miss_count_for(&deleted), 1);

        std::fs::remove_file(&deleted).unwrap();

        let second = list_sessions_in_home(
            dir.path().to_path_buf(),
            Some(10),
            None,
            HashSet::new(),
            None,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(second["sessions"].as_array().unwrap().len(), 1);
        assert!(cache_contains(&kept));
        assert!(!cache_contains(&deleted));
        assert_eq!(session_parse_miss_count_for(&kept), 1);
        assert_eq!(session_parse_miss_count_for(&deleted), 1);
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
