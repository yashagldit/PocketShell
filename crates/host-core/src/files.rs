use crate::error::{HostError, Result};
use base64::Engine;
use serde::Serialize;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_READ_SIZE: u64 = 512 * 1024; // 512 KB per read_file call
const MAX_LIST_DIR_PAGE_SIZE: usize = 250;

#[derive(Serialize)]
struct FileEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    permissions: String,
    modified_at: Option<String>,
    is_symlink: bool,
}

/// Top-level dispatcher for file channel actions.
pub async fn handle_files_action(payload: &serde_json::Value) -> Result<serde_json::Value> {
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let path_str = payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let payload = payload.clone();

    tokio::task::spawn_blocking(move || match action.as_str() {
        "list_dir" => {
            let offset = payload.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = payload
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(MAX_LIST_DIR_PAGE_SIZE as u64) as usize;
            list_dir(&path_str, offset, limit)
        }
        "read_file" => {
            let offset = payload.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit = payload
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(MAX_READ_SIZE);
            read_file(&path_str, offset, limit)
        }
        "stat" => stat_path(&path_str),
        "mkdir" => mkdir(&path_str),
        "delete" => delete_path(&path_str),
        "rename" => {
            let new_path = payload
                .get("new_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            rename_path(&path_str, new_path)
        }
        "copy" => {
            let destination = payload
                .get("destination")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let overwrite = payload
                .get("overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            copy_path(&path_str, destination, overwrite)
        }
        "move" => {
            let destination = payload
                .get("destination")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let overwrite = payload
                .get("overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            move_path(&path_str, destination, overwrite)
        }
        "write_file" => {
            let data_b64 = payload
                .get("data_b64")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let append = payload
                .get("append")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            write_file(&path_str, data_b64, append)
        }
        "download" => download_file(&path_str),
        "search" => {
            let query = payload.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let max_results = payload
                .get("max_results")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as usize;
            let max_depth = payload
                .get("max_depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as usize;
            search_files(&path_str, query, max_results, max_depth)
        }
        _ => Err(HostError::Backend(format!(
            "unknown files action: {action}"
        ))),
    })
    .await
    .map_err(|e| HostError::Backend(format!("file operation panicked: {e}")))?
}

fn resolve_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        return Ok(dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")));
    }

    let expanded = if raw.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            home.join(raw.strip_prefix("~/").unwrap_or(&raw[1..]))
        } else {
            PathBuf::from(raw)
        }
    } else {
        PathBuf::from(raw)
    };

    Ok(expanded)
}

fn safe_canonicalize(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path)
        .map_err(|e| HostError::Backend(format!("path not found: {}: {}", path.display(), e)))
}

/// Canonicalize a destination path that may not exist yet.
/// Resolves the closest existing ancestor to eliminate `..` traversal,
/// then appends the remaining unresolved components (which must not contain `..`).
fn safe_resolve_dest(raw: &str) -> Result<PathBuf> {
    let expanded = resolve_path(raw)?;

    // Walk up from the expanded path to find the deepest existing ancestor
    let mut existing = expanded.as_path();
    let mut tail_components: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if existing.exists() {
            break;
        }
        if let Some(name) = existing.file_name() {
            tail_components.push(name);
            existing = existing
                .parent()
                .unwrap_or_else(|| Path::new("/"));
        } else {
            // Reached root or something unexpected — just use expanded as-is
            break;
        }
    }

    let canonical_ancestor = safe_canonicalize(existing)?;
    tail_components.reverse();
    let mut result = canonical_ancestor;
    for component in &tail_components {
        let s = component.to_string_lossy();
        if s == ".." {
            return Err(HostError::Backend(
                "path traversal not allowed in destination".to_string(),
            ));
        }
        result = result.join(component);
    }

    Ok(result)
}

#[cfg(unix)]
fn format_permissions(mode: u32) -> String {
    let flags = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    flags
        .iter()
        .map(|(bit, ch)| if mode & bit != 0 { *ch } else { '-' })
        .collect()
}

#[cfg(not(unix))]
fn format_permissions(_mode: u32) -> String {
    "rwxr-xr-x".to_string()
}

fn get_permissions(metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        format_permissions(metadata.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        if metadata.permissions().readonly() {
            "r--r--r--".to_string()
        } else {
            "rw-rw-rw-".to_string()
        }
    }
}

fn modified_iso(metadata: &fs::Metadata) -> Option<String> {
    metadata.modified().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    })
}

fn list_dir(path_str: &str, offset: usize, limit: usize) -> Result<serde_json::Value> {
    let dir = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&dir)?;

    let mut entries = Vec::new();
    let reader = fs::read_dir(&canonical).map_err(|e| {
        HostError::Backend(format!(
            "cannot read directory {}: {}",
            canonical.display(),
            e
        ))
    })?;

    for entry_result in reader {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                warn!("read_dir entry error: {e}");
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let entry_path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                warn!("skipping {}: {}", entry_path.display(), e);
                continue;
            }
        };
        let is_symlink = entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false);

        entries.push(FileEntry {
            name,
            path: entry_path.to_string_lossy().to_string(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            permissions: get_permissions(&metadata),
            modified_at: modified_iso(&metadata),
            is_symlink,
        });
    }

    // Sort: dirs first, then by name (case-insensitive)
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    let total = entries.len();
    let capped_limit = limit.clamp(1, MAX_LIST_DIR_PAGE_SIZE);
    let page_entries: Vec<FileEntry> = entries
        .into_iter()
        .skip(offset)
        .take(capped_limit)
        .collect();
    let next_offset = offset.saturating_add(page_entries.len());
    let has_more = next_offset < total;

    Ok(serde_json::json!({
        "entries": page_entries,
        "cwd": canonical.to_string_lossy(),
        "offset": offset,
        "limit": capped_limit,
        "next_offset": next_offset,
        "has_more": has_more,
        "total": total,
    }))
}

fn read_file(path_str: &str, offset: u64, limit: u64) -> Result<serde_json::Value> {
    let file_path = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&file_path)?;

    let metadata = fs::metadata(&canonical)
        .map_err(|e| HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e)))?;

    if metadata.is_dir() {
        return Err(HostError::Backend("cannot read a directory".to_string()));
    }

    let size = metadata.len();
    let capped_limit = limit.min(MAX_READ_SIZE);

    let mut f = fs::File::open(&canonical)?;
    if offset > 0 {
        f.seek(std::io::SeekFrom::Start(offset))?;
    }
    let mut buf = vec![0u8; capped_limit as usize];
    let n = f.read(&mut buf)?;
    buf.truncate(n);

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&buf);

    Ok(serde_json::json!({
        "data_b64": data_b64,
        "size": size,
        "truncated": (offset + n as u64) < size,
    }))
}

fn stat_path(path_str: &str) -> Result<serde_json::Value> {
    let file_path = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&file_path)?;

    let metadata = fs::metadata(&canonical)
        .map_err(|e| HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e)))?;

    let symlink_meta = fs::symlink_metadata(&canonical).ok();
    let is_symlink = symlink_meta
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    let symlink_target = if is_symlink {
        fs::read_link(&canonical)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    } else {
        None
    };

    let name = canonical
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let created_at = metadata.created().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });

    Ok(serde_json::json!({
        "name": name,
        "path": canonical.to_string_lossy(),
        "is_dir": metadata.is_dir(),
        "size": metadata.len(),
        "permissions": get_permissions(&metadata),
        "modified_at": modified_iso(&metadata),
        "created_at": created_at,
        "is_symlink": is_symlink,
        "symlink_target": symlink_target,
    }))
}

fn mkdir(path_str: &str) -> Result<serde_json::Value> {
    let dir = safe_resolve_dest(path_str)?;
    fs::create_dir_all(&dir).map_err(|e| {
        HostError::Backend(format!("cannot create directory {}: {}", dir.display(), e))
    })?;
    Ok(serde_json::json!({}))
}

fn delete_path(path_str: &str) -> Result<serde_json::Value> {
    let target = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&target)?;
    let metadata = fs::metadata(&canonical)
        .map_err(|e| HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e)))?;

    if metadata.is_dir() {
        fs::remove_dir_all(&canonical).map_err(|e| {
            HostError::Backend(format!(
                "cannot delete directory {}: {}",
                canonical.display(),
                e
            ))
        })?;
    } else {
        fs::remove_file(&canonical).map_err(|e| {
            HostError::Backend(format!("cannot delete file {}: {}", canonical.display(), e))
        })?;
    }

    Ok(serde_json::json!({}))
}

fn rename_path(path_str: &str, new_path: &str) -> Result<serde_json::Value> {
    if new_path.is_empty() {
        return Err(HostError::Backend("new_path is required".to_string()));
    }
    let src = resolve_path(path_str)?;
    let dst = safe_resolve_dest(new_path)?;
    let canonical_src = safe_canonicalize(&src)?;

    fs::rename(&canonical_src, &dst).map_err(|e| {
        HostError::Backend(format!(
            "cannot rename {} -> {}: {}",
            canonical_src.display(),
            dst.display(),
            e
        ))
    })?;

    Ok(serde_json::json!({}))
}

fn copy_path(path_str: &str, destination: &str, overwrite: bool) -> Result<serde_json::Value> {
    if destination.is_empty() {
        return Err(HostError::Backend("destination is required".to_string()));
    }
    let src = resolve_path(path_str)?;
    let dst = safe_resolve_dest(destination)?;
    let canonical_src = safe_canonicalize(&src)?;

    if dst.exists() {
        if !overwrite {
            return Err(HostError::Backend(
                "FILE_EXISTS: destination already exists".to_string(),
            ));
        }
        // Clean replace: remove existing destination so we don't merge dirs
        if dst.is_dir() {
            fs::remove_dir_all(&dst).map_err(|e| {
                HostError::Backend(format!("cannot remove existing {}: {}", dst.display(), e))
            })?;
        } else {
            fs::remove_file(&dst).map_err(|e| {
                HostError::Backend(format!("cannot remove existing {}: {}", dst.display(), e))
            })?;
        }
    }

    let metadata = fs::metadata(&canonical_src).map_err(|e| {
        HostError::Backend(format!("cannot stat {}: {}", canonical_src.display(), e))
    })?;

    if metadata.is_dir() {
        copy_dir_recursive(&canonical_src, &dst)?;
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::copy(&canonical_src, &dst).map_err(|e| {
            HostError::Backend(format!(
                "cannot copy {} -> {}: {}",
                canonical_src.display(),
                dst.display(),
                e
            ))
        })?;
    }

    Ok(serde_json::json!({}))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| {
        HostError::Backend(format!("cannot create directory {}: {}", dst.display(), e))
    })?;

    for entry_result in fs::read_dir(src).map_err(|e| {
        HostError::Backend(format!("cannot read directory {}: {}", src.display(), e))
    })? {
        let entry =
            entry_result.map_err(|e| HostError::Backend(format!("read_dir entry error: {e}")))?;
        let file_type = entry
            .file_type()
            .map_err(|e| HostError::Backend(format!("cannot get file type: {e}")))?;
        let src_child = entry.path();
        let dst_child = dst.join(entry.file_name());

        if file_type.is_symlink() {
            // Preserve symlink rather than following it (avoids circular loops)
            let target = fs::read_link(&src_child).map_err(|e| {
                HostError::Backend(format!(
                    "cannot read symlink {}: {}",
                    src_child.display(),
                    e
                ))
            })?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_child).map_err(|e| {
                HostError::Backend(format!(
                    "cannot create symlink {} -> {}: {}",
                    dst_child.display(),
                    target.display(),
                    e
                ))
            })?;
            #[cfg(not(unix))]
            {
                // On non-unix, fall back to copying the target
                if file_type.is_dir() {
                    copy_dir_recursive(&src_child, &dst_child)?;
                } else {
                    fs::copy(&src_child, &dst_child).map_err(|e| {
                        HostError::Backend(format!(
                            "cannot copy {} -> {}: {}",
                            src_child.display(),
                            dst_child.display(),
                            e
                        ))
                    })?;
                }
            }
        } else if file_type.is_dir() {
            copy_dir_recursive(&src_child, &dst_child)?;
        } else {
            fs::copy(&src_child, &dst_child).map_err(|e| {
                HostError::Backend(format!(
                    "cannot copy {} -> {}: {}",
                    src_child.display(),
                    dst_child.display(),
                    e
                ))
            })?;
        }
    }

    Ok(())
}

fn move_path(path_str: &str, destination: &str, overwrite: bool) -> Result<serde_json::Value> {
    if destination.is_empty() {
        return Err(HostError::Backend("destination is required".to_string()));
    }
    let src = resolve_path(path_str)?;
    let dst = safe_resolve_dest(destination)?;
    let canonical_src = safe_canonicalize(&src)?;

    if dst.exists() {
        if !overwrite {
            return Err(HostError::Backend(
                "FILE_EXISTS: destination already exists".to_string(),
            ));
        }
        // Clean replace: remove existing destination so rename/copy doesn't merge
        if dst.is_dir() {
            fs::remove_dir_all(&dst).map_err(|e| {
                HostError::Backend(format!("cannot remove existing {}: {}", dst.display(), e))
            })?;
        } else {
            fs::remove_file(&dst).map_err(|e| {
                HostError::Backend(format!("cannot remove existing {}: {}", dst.display(), e))
            })?;
        }
    }

    // Ensure destination parent exists
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).ok();
    }

    // Try a simple rename first (fast, same-filesystem)
    match fs::rename(&canonical_src, &dst) {
        Ok(()) => return Ok(serde_json::json!({})),
        Err(e) => {
            // Only fall through to copy+delete for cross-device errors (EXDEV = 18)
            if e.raw_os_error() != Some(18) {
                return Err(HostError::Backend(format!(
                    "cannot move {} -> {}: {}",
                    canonical_src.display(),
                    dst.display(),
                    e
                )));
            }
        }
    }

    // Fallback: copy then delete (cross-filesystem)
    let metadata = fs::metadata(&canonical_src).map_err(|e| {
        HostError::Backend(format!("cannot stat {}: {}", canonical_src.display(), e))
    })?;

    if metadata.is_dir() {
        copy_dir_recursive(&canonical_src, &dst)?;
        fs::remove_dir_all(&canonical_src).map_err(|e| {
            HostError::Backend(format!(
                "copied but cannot remove source dir {}: {}",
                canonical_src.display(),
                e
            ))
        })?;
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::copy(&canonical_src, &dst).map_err(|e| {
            HostError::Backend(format!(
                "cannot copy {} -> {}: {}",
                canonical_src.display(),
                dst.display(),
                e
            ))
        })?;
        fs::remove_file(&canonical_src).map_err(|e| {
            HostError::Backend(format!(
                "copied but cannot remove source {}: {}",
                canonical_src.display(),
                e
            ))
        })?;
    }

    Ok(serde_json::json!({}))
}

fn write_file(path_str: &str, data_b64: &str, append: bool) -> Result<serde_json::Value> {
    let file_path = safe_resolve_dest(path_str)?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| HostError::Backend(format!("invalid base64 payload: {e}")))?;

    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(HostError::Backend(format!(
            "file too large: {} bytes (max {})",
            data.len(),
            MAX_FILE_SIZE
        )));
    }

    if append {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        f.write_all(&data)?;
    } else {
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(&file_path, &data)?;
    }

    Ok(serde_json::json!({ "bytes_written": data.len() }))
}

fn download_file(path_str: &str) -> Result<serde_json::Value> {
    let file_path = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&file_path)?;

    let metadata = fs::metadata(&canonical)
        .map_err(|e| HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e)))?;

    if metadata.is_dir() {
        return Err(HostError::Backend(
            "cannot download a directory".to_string(),
        ));
    }

    if metadata.len() > MAX_FILE_SIZE {
        return Err(HostError::Backend(format!(
            "file too large: {} bytes (max {})",
            metadata.len(),
            MAX_FILE_SIZE
        )));
    }

    let data = fs::read(&canonical)?;
    let name = canonical
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mime_type = mime_from_extension(&canonical);
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);

    Ok(serde_json::json!({
        "data_b64": data_b64,
        "name": name,
        "size": metadata.len(),
        "mime_type": mime_type,
    }))
}

/// Check if a query string contains glob characters (`*` or `?`).
fn is_glob(query: &str) -> bool {
    query.contains('*') || query.contains('?')
}

/// Convert a simple glob pattern to a regex pattern string.
/// Supports `*` (match any chars) and `?` (match single char).
fn glob_to_regex(glob: &str) -> String {
    let mut regex = String::with_capacity(glob.len() * 2 + 2);
    regex.push('^');
    for ch in glob.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }
    regex.push('$');
    regex
}

enum SearchMatcher {
    Substring(String),
    Glob(regex::Regex),
}

impl SearchMatcher {
    fn new(query: &str) -> Result<Self> {
        let query_lower = query.to_lowercase();
        if is_glob(&query_lower) {
            let pattern = glob_to_regex(&query_lower);
            let re = regex::Regex::new(&pattern)
                .map_err(|e| HostError::Backend(format!("invalid search pattern: {e}")))?;
            Ok(SearchMatcher::Glob(re))
        } else {
            Ok(SearchMatcher::Substring(query_lower))
        }
    }

    fn matches(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        match self {
            SearchMatcher::Substring(q) => lower.contains(q.as_str()),
            SearchMatcher::Glob(re) => re.is_match(&lower),
        }
    }
}

fn search_files(
    path_str: &str,
    query: &str,
    max_results: usize,
    max_depth: usize,
) -> Result<serde_json::Value> {
    if query.is_empty() {
        return Err(HostError::Backend("search query is required".to_string()));
    }

    let dir = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&dir)?;
    let matcher = SearchMatcher::new(query)?;

    let mut results: Vec<FileEntry> = Vec::new();

    fn walk(
        dir: &Path,
        matcher: &SearchMatcher,
        results: &mut Vec<FileEntry>,
        max_results: usize,
        depth: usize,
        max_depth: usize,
    ) {
        if depth > max_depth || results.len() >= max_results {
            return;
        }
        let reader = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        for entry_result in reader {
            if results.len() >= max_results {
                return;
            }
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip common heavy directories
            if depth == 0
                && (name == "node_modules"
                    || name == ".git"
                    || name == "target"
                    || name == "__pycache__"
                    || name == ".venv"
                    || name == "venv")
            {
                continue;
            }

            let entry_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let is_symlink = entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false);

            if matcher.matches(&name) {
                results.push(FileEntry {
                    name: name.clone(),
                    path: entry_path.to_string_lossy().to_string(),
                    is_dir: metadata.is_dir(),
                    size: metadata.len(),
                    permissions: get_permissions(&metadata),
                    modified_at: modified_iso(&metadata),
                    is_symlink,
                });
            }

            if metadata.is_dir() && !is_symlink {
                walk(
                    &entry_path,
                    matcher,
                    results,
                    max_results,
                    depth + 1,
                    max_depth,
                );
            }
        }
    }

    walk(
        &canonical,
        &matcher,
        &mut results,
        max_results,
        0,
        max_depth,
    );

    Ok(serde_json::json!({
        "entries": results,
        "total": results.len(),
        "cwd": canonical.to_string_lossy(),
    }))
}

fn mime_from_extension(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "txt" | "log" | "md" | "csv" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "ts" | "tsx" => "text/typescript",
        "py" => "text/x-python",
        "rs" => "text/x-rust",
        "sh" | "bash" | "zsh" => "text/x-shellscript",
        "yaml" | "yml" => "text/yaml",
        "toml" => "text/toml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    }
}

pub fn resolve_file_path_for_transfer(path_str: &str) -> Result<PathBuf> {
    resolve_path(path_str)
}

pub fn file_mime_type(path: &Path) -> &'static str {
    mime_from_extension(path)
}
