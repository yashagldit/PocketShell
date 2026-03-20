use crate::error::{HostError, Result};
use base64::Engine;
use serde::Serialize;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
const MAX_READ_SIZE: u64 = 512 * 1024; // 512 KB per read_file call

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

    tokio::task::spawn_blocking(move || {
        match action.as_str() {
            "list_dir" => list_dir(&path_str),
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
            _ => Err(HostError::Backend(format!("unknown files action: {action}"))),
        }
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
    fs::canonicalize(path).map_err(|e| {
        HostError::Backend(format!("path not found: {}: {}", path.display(), e))
    })
}

#[cfg(unix)]
fn format_permissions(mode: u32) -> String {
    let flags = [
        (0o400, 'r'), (0o200, 'w'), (0o100, 'x'),
        (0o040, 'r'), (0o020, 'w'), (0o010, 'x'),
        (0o004, 'r'), (0o002, 'w'), (0o001, 'x'),
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

fn list_dir(path_str: &str) -> Result<serde_json::Value> {
    let dir = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&dir)?;

    let mut entries = Vec::new();
    let reader = fs::read_dir(&canonical).map_err(|e| {
        HostError::Backend(format!("cannot read directory {}: {}", canonical.display(), e))
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
        let is_symlink = entry
            .file_type()
            .map(|ft| ft.is_symlink())
            .unwrap_or(false);

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

    Ok(serde_json::json!({
        "entries": entries,
        "cwd": canonical.to_string_lossy(),
    }))
}

fn read_file(path_str: &str, offset: u64, limit: u64) -> Result<serde_json::Value> {
    let file_path = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&file_path)?;

    let metadata = fs::metadata(&canonical).map_err(|e| {
        HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e))
    })?;

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

    let metadata = fs::metadata(&canonical).map_err(|e| {
        HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e))
    })?;

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
    let dir = resolve_path(path_str)?;
    fs::create_dir_all(&dir).map_err(|e| {
        HostError::Backend(format!("cannot create directory {}: {}", dir.display(), e))
    })?;
    Ok(serde_json::json!({}))
}

fn delete_path(path_str: &str) -> Result<serde_json::Value> {
    let target = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&target)?;
    let metadata = fs::metadata(&canonical).map_err(|e| {
        HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e))
    })?;

    if metadata.is_dir() {
        fs::remove_dir_all(&canonical).map_err(|e| {
            HostError::Backend(format!("cannot delete directory {}: {}", canonical.display(), e))
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
    let dst = resolve_path(new_path)?;
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

fn write_file(path_str: &str, data_b64: &str, append: bool) -> Result<serde_json::Value> {
    let file_path = resolve_path(path_str)?;
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

    let metadata = fs::metadata(&canonical).map_err(|e| {
        HostError::Backend(format!("cannot stat {}: {}", canonical.display(), e))
    })?;

    if metadata.is_dir() {
        return Err(HostError::Backend("cannot download a directory".to_string()));
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
