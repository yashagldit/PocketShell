use crate::error::{HostError, Result};
use base64::Engine;
use serde::Serialize;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::warn;

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_READ_SIZE: u64 = 512 * 1024; // 512 KB per read_file call
const MAX_LIST_DIR_PAGE_SIZE: usize = 250;

/// Directories that the file channel must NEVER expose. Even a "trusted"
/// mobile peer should not be able to read the host's own ED25519 private
/// key, the user's SSH/AWS/GnuPG/GitHub credentials, or shell histories.
/// All entries are home-relative (no leading slash); the check resolves
/// against the current `dirs::home_dir()` so a different host running as a
/// different user is still protected.
const DENIED_HOME_PREFIXES: &[&str] = &[
    ".pocketshell",
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gh",
    ".docker/config.json",
    ".kube",
    ".npmrc",
    ".pypirc",
];

/// Specific files (not just directories) that must be denied. Shell
/// histories often contain pasted secrets; the rest are credentials.
const DENIED_HOME_FILES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".node_repl_history",
    ".lesshst",
    ".netrc",
];

/// System-wide directories that the file channel must NEVER expose,
/// independently of where `$HOME` points. Protects against a daemon that
/// somehow ends up running with elevated privileges — `geteuid` should
/// block that before this list ever fires, but defense-in-depth.
///
/// We deliberately do NOT block `/var` wholesale because macOS canonicalises
/// the user-scoped `$TMPDIR` to `/private/var/folders/...`, which is just
/// scratch space. Instead we enumerate the specific sensitive subpaths under
/// `/var` (`/var/lib`, `/var/log`, `/var/db`, …) and let the rest through.
///
/// Same for `/etc` vs `/private/etc`: `fs::canonicalize` on macOS rewrites
/// `/etc/hosts` to `/private/etc/hosts`, so both forms must be listed.
///
/// `/tmp`, `/usr` (outside `/usr/local/etc`), `/opt`, and `/var/tmp` /
/// `/var/folders` are intentionally NOT denied — legitimate scratch /
/// build / install locations.
const DENIED_ABSOLUTE_PREFIXES: &[&str] = &[
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/usr/local/etc",
    "/var/lib",
    "/var/log",
    "/var/db",
    "/var/spool",
    "/var/root",
    "/var/audit",
    // macOS canonical forms — fs::canonicalize rewrites /etc → /private/etc
    // and /var/<x> → /private/var/<x>.
    "/private/etc",
    "/private/var/lib",
    "/private/var/log",
    "/private/var/db",
    "/private/var/spool",
    "/private/var/root",
    "/private/var/audit",
];

/// Resolved denylist entries against a specific home dir + the global
/// absolute denylist.
struct DeniedPaths {
    prefixes: Vec<PathBuf>,
    files: Vec<PathBuf>,
    absolute_prefixes: Vec<PathBuf>,
}

fn build_denied_paths(home: &Path) -> DeniedPaths {
    DeniedPaths {
        prefixes: DENIED_HOME_PREFIXES.iter().map(|p| home.join(p)).collect(),
        files: DENIED_HOME_FILES.iter().map(|f| home.join(f)).collect(),
        absolute_prefixes: DENIED_ABSOLUTE_PREFIXES.iter().map(PathBuf::from).collect(),
    }
}

fn is_path_denied_against(path: &Path, denied: &DeniedPaths) -> bool {
    denied.prefixes.iter().any(|p| path.starts_with(p))
        || denied.files.iter().any(|f| path == f)
        || denied.absolute_prefixes.iter().any(|p| path.starts_with(p))
}

/// Check whether `path` (already absolute, ideally canonicalized) lands
/// inside one of the denylisted regions of the user's home directory or
/// the system-wide absolute denylist. Production callers go through this;
/// the resolved denylist is cached in a `OnceLock` so per-file dispatches
/// don't re-stat $HOME. Tests that mutate $HOME use `is_path_denied_against`
/// directly to avoid the cache.
fn is_path_denied(path: &Path) -> bool {
    static CACHE: OnceLock<Option<DeniedPaths>> = OnceLock::new();
    let denied = CACHE.get_or_init(|| {
        let home = dirs::home_dir()?;
        // canonicalize follows /var → /private/var on macOS, etc.
        let base = fs::canonicalize(&home).unwrap_or(home);
        Some(build_denied_paths(&base))
    });
    match denied {
        Some(d) => is_path_denied_against(path, d),
        None => false,
    }
}

fn deny_if_protected(path: &Path) -> Result<()> {
    if is_path_denied(path) {
        warn!(
            "file channel denied: {} is in protected scope",
            path.display()
        );
        return Err(HostError::Backend(format!(
            "PROTECTED_PATH: access denied for {}",
            path.display()
        )));
    }
    Ok(())
}

fn default_file_home() -> PathBuf {
    if let Some(path) = std::env::var_os("POCKETSHELL_FILE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.exists())
    {
        return path;
    }

    #[cfg(unix)]
    {
        if nix::unistd::Uid::effective().is_root() {
            if let Some(path) = std::env::var_os("SUDO_USER")
                .and_then(|u| u.into_string().ok())
                .filter(|u| !u.is_empty() && u != "root")
                .and_then(|u| user_home(&u))
                .filter(|p| p.exists())
            {
                return path;
            }

            if let Some(path) = first_human_home().filter(|p| p.exists()) {
                return path;
            }
        }
    }

    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(unix)]
fn user_home(user: &str) -> Option<PathBuf> {
    nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.dir)
}

#[cfg(unix)]
fn first_human_home() -> Option<PathBuf> {
    let bases = if cfg!(target_os = "macos") {
        ["/Users", "/home"]
    } else {
        ["/home", "/Users"]
    };

    for base in bases {
        let Some(read_dir) = fs::read_dir(base).ok() else {
            continue;
        };
        let mut candidates = read_dir
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                if !path.is_dir() {
                    return None;
                }
                let name = path.file_name()?.to_string_lossy();
                if name == "root"
                    || name == "Shared"
                    || name.starts_with('.')
                    || name == "lost+found"
                {
                    return None;
                }
                Some(path)
            })
            .collect::<Vec<_>>();
        candidates.sort();
        if let Some(path) = candidates.into_iter().next() {
            return Some(path);
        }
    }
    None
}

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
pub async fn handle_files_action(
    payload: &serde_json::Value,
    agent_router: &crate::agent_session::AgentRouter,
) -> Result<serde_json::Value> {
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if action == "list_coding_sessions" {
        let limit = payload
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize);
        let alive = agent_router.alive_claude_resume_ids().await;
        return crate::coding_sessions::list_sessions(limit, alive).await;
    }

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
            let files_only = payload
                .get("files_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            search_files(&path_str, query, max_results, max_depth, files_only)
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
        return Ok(default_file_home());
    }

    let expanded = if raw.starts_with('~') {
        default_file_home().join(raw.strip_prefix("~/").unwrap_or(&raw[1..]))
    } else {
        PathBuf::from(raw)
    };

    Ok(expanded)
}

fn safe_canonicalize(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| HostError::Backend(format!("path not found: {}: {}", path.display(), e)))?;
    deny_if_protected(&canonical)?;
    Ok(canonical)
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
            existing = existing.parent().unwrap_or_else(|| Path::new("/"));
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

    // Re-check the assembled destination — the protected check on the
    // ancestor doesn't catch the case where the tail walks INTO a
    // protected dir that doesn't exist yet (e.g. writing to
    // `~/.ssh/authorized_keys` when `.ssh` is missing).
    deny_if_protected(&result)?;

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

    // Reject obviously oversize payloads BEFORE allocating the decoded buffer.
    // base64 expands raw bytes by 4/3; the +4 covers padding rounding. A 1 GB
    // base64 string from a malicious client would otherwise OOM the daemon
    // before the decoded-length check below could fire.
    let max_b64_len = (MAX_FILE_SIZE as usize).saturating_mul(4) / 3 + 4;
    if data_b64.len() > max_b64_len {
        let _ = crate::audit::write_audit_event(crate::audit::AuditEvent {
            event_type: "file_write_rejected_oversize".to_string(),
            details: Some(serde_json::json!({
                "path": path_str,
                "b64_len": data_b64.len(),
                "max_b64_len": max_b64_len,
                "max_file_size": MAX_FILE_SIZE,
            })),
            ..crate::audit::AuditEvent::new("file_write_rejected_oversize")
        });
        return Err(HostError::Backend(format!(
            "file payload too large: {} base64 bytes exceeds limit of {} (max file size {} bytes)",
            data_b64.len(),
            max_b64_len,
            MAX_FILE_SIZE
        )));
    }

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
    /// Match-everything sentinel — returned for an empty query so callers can
    /// still walk a path through `matches()` without special-casing the
    /// "browse this directory" case.
    Any,
    Substring(String),
    Glob(regex::Regex),
}

impl SearchMatcher {
    fn new(query: &str) -> Result<Self> {
        if query.is_empty() {
            return Ok(SearchMatcher::Any);
        }
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

    /// Match against both the bare filename and its path relative to the
    /// search root (e.g. `src/main.rs`). Path-shaped queries like
    /// `src/main` or `*.rs` then hit nested files instead of returning
    /// nothing because filenames never contain `/`. Inputs are expected to
    /// be lowercased once at the call site so we don't repeat the work
    /// per-variant for each entry.
    fn matches(&self, name_lower: &str, rel_path_lower: &str) -> bool {
        match self {
            SearchMatcher::Any => true,
            SearchMatcher::Substring(q) => {
                name_lower.contains(q.as_str()) || rel_path_lower.contains(q.as_str())
            }
            SearchMatcher::Glob(re) => re.is_match(name_lower) || re.is_match(rel_path_lower),
        }
    }

    /// `true` when the matcher reads its arguments — i.e. anything other
    /// than the empty-query browse case. Lets the walker skip the
    /// rel-path computation when it would be ignored.
    fn is_any(&self) -> bool {
        matches!(self, SearchMatcher::Any)
    }
}

fn search_files(
    path_str: &str,
    query: &str,
    max_results: usize,
    max_depth: usize,
    files_only: bool,
) -> Result<serde_json::Value> {
    let dir = resolve_path(path_str)?;
    let canonical = safe_canonicalize(&dir)?;
    let matcher = SearchMatcher::new(query)?;

    // Empty query → browse-style listing of the immediate children, sorted
    // by modified-time desc. This is what the agent-chat `@` trigger relies
    // on when no query has been typed yet — the user sees the most recent
    // files in cwd instead of an arbitrary substring hit on ".".
    let empty_query = query.is_empty();

    let mut results: Vec<FileEntry> = Vec::new();

    fn walk(
        root: &Path,
        dir: &Path,
        matcher: &SearchMatcher,
        results: &mut Vec<FileEntry>,
        max_results: usize,
        depth: usize,
        max_depth: usize,
        files_only: bool,
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

            // Don't surface denied paths in search hits, and don't
            // descend into denied directories. A user searching from $HOME
            // for "id_rsa" must not see SSH keys.
            if is_path_denied(&entry_path) {
                continue;
            }

            // The empty-query (`Any`) branch ignores both arguments to
            // `matches`, so we skip the rel-path build + lowercasing
            // entirely for it — that's the hot loop for the agent-chat
            // `@`-browse case.
            let pushed = if matcher.is_any() {
                true
            } else {
                let name_lower = name.to_lowercase();
                let rel_path = entry_path
                    .strip_prefix(root)
                    .unwrap_or(&entry_path)
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_lowercase();
                matcher.matches(&name_lower, &rel_path)
            };

            // `files_only` keeps directories out of the result set but
            // still recurses into them — the agent-chat `@` mention only
            // wants files, but the host shouldn't stop walking just
            // because the immediate hit was a directory.
            if pushed && !(files_only && metadata.is_dir()) {
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
                    root,
                    &entry_path,
                    matcher,
                    results,
                    max_results,
                    depth + 1,
                    max_depth,
                    files_only,
                );
            }
        }
    }

    if empty_query {
        // Don't recurse — just list the immediate children, sorted by
        // mtime desc. max_depth is ignored in this branch.
        walk(
            &canonical,
            &canonical,
            &matcher,
            &mut results,
            max_results,
            0,
            0,
            files_only,
        );
        results.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    } else {
        walk(
            &canonical,
            &canonical,
            &matcher,
            &mut results,
            max_results,
            0,
            max_depth,
            files_only,
        );
    }

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
    let expanded = resolve_path(path_str)?;
    if expanded.exists() {
        safe_canonicalize(&expanded)
    } else {
        safe_resolve_dest(path_str)
    }
}

pub fn file_mime_type(path: &Path) -> &'static str {
    mime_from_extension(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tempfile::tempdir;

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn is_glob_detects_glob_chars() {
        assert!(is_glob("foo*"));
        assert!(is_glob("f?o"));
        assert!(is_glob("*.rs"));
        assert!(!is_glob("plain"));
        assert!(!is_glob(""));
    }

    #[test]
    fn glob_to_regex_escapes_meta_and_handles_wildcards() {
        assert_eq!(glob_to_regex("*.rs"), "^.*\\.rs$");
        assert_eq!(glob_to_regex("a?b"), "^a.b$");
        assert_eq!(glob_to_regex("a+b"), "^a\\+b$");
        assert_eq!(glob_to_regex("(x)"), "^\\(x\\)$");
    }

    #[test]
    fn search_matcher_substring_and_glob() {
        // `matches` expects pre-lowercased inputs (the walker handles that
        // once per entry). Tests pass the lowercase form explicitly.
        let sub = SearchMatcher::new("Hello").unwrap();
        assert!(sub.matches("say hello world", "say hello world"));
        assert!(sub.matches("hello", "hello"));
        assert!(!sub.matches("goodbye", "goodbye"));

        let glob = SearchMatcher::new("*.RS").unwrap();
        assert!(glob.matches("main.rs", "main.rs"));
        assert!(glob.matches("lib.rs", "lib.rs"));
        assert!(!glob.matches("main.txt", "main.txt"));
    }

    #[test]
    fn search_matcher_matches_relative_path() {
        // Path-shaped queries (containing `/`) can never substring-match
        // the bare filename — they have to land on the relative path.
        let sub = SearchMatcher::new("src/main").unwrap();
        assert!(sub.matches("main.rs", "src/main.rs"));
        assert!(!sub.matches("main.rs", "lib/main.rs"));

        // Globs follow the same rule — `*.rs` against `src/main.rs`
        // succeeds because the regex (`^.*\.rs$`) matches the path.
        let glob = SearchMatcher::new("*.rs").unwrap();
        assert!(glob.matches("main.rs", "src/main.rs"));
        assert!(glob.matches("main.rs", "main.rs"));
        assert!(!glob.matches("main.txt", "src/main.txt"));
    }

    #[test]
    fn search_matcher_any_for_empty_query() {
        let any = SearchMatcher::new("").unwrap();
        assert!(any.is_any());
        assert!(any.matches("anything", "any/where.txt"));
        assert!(any.matches("", ""));
    }

    #[cfg(unix)]
    #[test]
    fn format_permissions_is_posix_style() {
        assert_eq!(format_permissions(0o755), "rwxr-xr-x");
        assert_eq!(format_permissions(0o644), "rw-r--r--");
        assert_eq!(format_permissions(0o000), "---------");
        assert_eq!(format_permissions(0o777), "rwxrwxrwx");
    }

    #[test]
    fn mime_from_extension_maps_known_types() {
        assert_eq!(mime_from_extension(Path::new("a.json")), "application/json");
        assert_eq!(mime_from_extension(Path::new("a.PNG")), "image/png");
        assert_eq!(mime_from_extension(Path::new("a.md")), "text/plain");
        assert_eq!(mime_from_extension(Path::new("a.rs")), "text/x-rust");
        assert_eq!(
            mime_from_extension(Path::new("a.unknown")),
            "application/octet-stream"
        );
        assert_eq!(
            mime_from_extension(Path::new("noext")),
            "application/octet-stream"
        );
    }

    #[test]
    fn safe_resolve_dest_errors_when_ancestor_unresolvable() {
        // Paths containing `..` in a non-existent segment cause the
        // resolver's file_name() to return None and the canonicalize step
        // to fail — exercising the "path not found" error branch.
        let dir = tempdir().unwrap();
        let raw = format!("{}/doesnotexist/../escape", dir.path().display());
        let err = safe_resolve_dest(&raw).unwrap_err();
        match err {
            HostError::Backend(m) => assert!(
                m.contains("path not found") || m.contains("traversal"),
                "got {m}"
            ),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn safe_resolve_dest_joins_nonexistent_tail_onto_canonical() {
        let dir = tempdir().unwrap();
        let raw = format!("{}/new_sub/file.txt", dir.path().display());
        let resolved = safe_resolve_dest(&raw).unwrap();
        assert!(resolved.ends_with("new_sub/file.txt"));
    }

    #[test]
    fn write_file_creates_and_reports_bytes() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("out.txt");
        let res = write_file(&p.to_string_lossy(), &b64(b"hello"), false).unwrap();
        assert_eq!(res["bytes_written"], 5);
        assert_eq!(fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn write_file_append_mode() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.txt");
        write_file(&p.to_string_lossy(), &b64(b"abc"), false).unwrap();
        write_file(&p.to_string_lossy(), &b64(b"DEF"), true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"abcDEF");
    }

    #[test]
    fn write_file_invalid_base64_errors() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("bad.txt");
        let err = write_file(&p.to_string_lossy(), "!!!not-base64!!!", false).unwrap_err();
        match err {
            HostError::Backend(m) => assert!(m.contains("base64")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn read_file_honors_offset_and_limit_and_truncation_flag() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("r.bin");
        fs::write(&p, b"0123456789").unwrap();

        let res = read_file(&p.to_string_lossy(), 0, 4).unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(res["data_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data, b"0123");
        assert_eq!(res["size"], 10);
        assert_eq!(res["truncated"], true);

        let res2 = read_file(&p.to_string_lossy(), 8, 100).unwrap();
        let data2 = base64::engine::general_purpose::STANDARD
            .decode(res2["data_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data2, b"89");
        assert_eq!(res2["truncated"], false);
    }

    #[test]
    fn read_file_rejects_directories() {
        let dir = tempdir().unwrap();
        let err = read_file(&dir.path().to_string_lossy(), 0, 10).unwrap_err();
        match err {
            HostError::Backend(m) => assert!(m.contains("directory")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn list_dir_sorts_dirs_first_and_paginates() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("zdir")).unwrap();
        fs::write(dir.path().join("afile"), b"").unwrap();
        fs::write(dir.path().join("bfile"), b"").unwrap();
        fs::write(dir.path().join("cfile"), b"").unwrap();

        let res = list_dir(&dir.path().to_string_lossy(), 0, 2).unwrap();
        assert_eq!(res["total"], 4);
        let entries = res["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        // First entry should be the directory (dirs-first)
        assert_eq!(entries[0]["name"], "zdir");
        assert_eq!(entries[0]["is_dir"], true);
        assert_eq!(entries[1]["name"], "afile");
        assert_eq!(res["has_more"], true);
        assert_eq!(res["next_offset"], 2);

        let res2 = list_dir(&dir.path().to_string_lossy(), 2, 100).unwrap();
        let entries2 = res2["entries"].as_array().unwrap();
        assert_eq!(entries2.len(), 2);
        assert_eq!(res2["has_more"], false);
    }

    #[test]
    fn list_dir_limit_is_clamped() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a"), b"").unwrap();
        let res = list_dir(&dir.path().to_string_lossy(), 0, 0).unwrap();
        assert_eq!(res["limit"], 1); // clamped min 1
        let res2 = list_dir(&dir.path().to_string_lossy(), 0, 10_000).unwrap();
        assert_eq!(res2["limit"], MAX_LIST_DIR_PAGE_SIZE as u64);
    }

    #[test]
    fn stat_path_returns_fields() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("s.txt");
        fs::write(&p, b"abc").unwrap();
        let res = stat_path(&p.to_string_lossy()).unwrap();
        assert_eq!(res["name"], "s.txt");
        assert_eq!(res["is_dir"], false);
        assert_eq!(res["size"], 3);
        assert_eq!(res["is_symlink"], false);
        assert!(res["permissions"].as_str().unwrap().len() == 9);
    }

    #[test]
    fn mkdir_and_delete_roundtrip() {
        let dir = tempdir().unwrap();
        let new = dir.path().join("nested/a/b");
        mkdir(&new.to_string_lossy()).unwrap();
        assert!(new.exists());
        delete_path(&new.to_string_lossy()).unwrap();
        assert!(!new.exists());
    }

    #[test]
    fn delete_handles_dir_recursively() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("rm");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("x"), b"x").unwrap();
        delete_path(&sub.to_string_lossy()).unwrap();
        assert!(!sub.exists());
    }

    #[test]
    fn rename_path_moves_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        fs::write(&src, b"x").unwrap();
        rename_path(&src.to_string_lossy(), &dst.to_string_lossy()).unwrap();
        assert!(!src.exists());
        assert!(dst.exists());
    }

    #[test]
    fn rename_path_requires_new_path() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("s");
        fs::write(&src, b"x").unwrap();
        let err = rename_path(&src.to_string_lossy(), "").unwrap_err();
        assert!(matches!(err, HostError::Backend(_)));
    }

    #[test]
    fn copy_path_copies_file_and_respects_overwrite_flag() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("s.txt");
        let dst = dir.path().join("d.txt");
        fs::write(&src, b"hello").unwrap();
        copy_path(&src.to_string_lossy(), &dst.to_string_lossy(), false).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"hello");

        // Exists, overwrite=false -> error
        let err = copy_path(&src.to_string_lossy(), &dst.to_string_lossy(), false).unwrap_err();
        match err {
            HostError::Backend(m) => assert!(m.contains("FILE_EXISTS")),
            other => panic!("expected Backend, got {other:?}"),
        }

        // overwrite=true -> ok
        fs::write(&src, b"world").unwrap();
        copy_path(&src.to_string_lossy(), &dst.to_string_lossy(), true).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"world");
    }

    #[test]
    fn copy_path_copies_directory_recursively() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("sdir");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"A").unwrap();
        fs::create_dir(src.join("sub")).unwrap();
        fs::write(src.join("sub/b.txt"), b"B").unwrap();
        let dst = dir.path().join("ddir");
        copy_path(&src.to_string_lossy(), &dst.to_string_lossy(), false).unwrap();
        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"A");
        assert_eq!(fs::read(dst.join("sub/b.txt")).unwrap(), b"B");
    }

    #[test]
    fn move_path_moves_file_and_removes_source() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("mv.txt");
        fs::write(&src, b"m").unwrap();
        let dst = dir.path().join("dst.txt");
        move_path(&src.to_string_lossy(), &dst.to_string_lossy(), false).unwrap();
        assert!(!src.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"m");
    }

    #[test]
    fn download_file_rejects_directory() {
        let dir = tempdir().unwrap();
        let err = download_file(&dir.path().to_string_lossy()).unwrap_err();
        match err {
            HostError::Backend(m) => assert!(m.contains("directory")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn download_file_returns_data_and_mime() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("info.json");
        fs::write(&p, b"{\"a\":1}").unwrap();
        let res = download_file(&p.to_string_lossy()).unwrap();
        assert_eq!(res["name"], "info.json");
        assert_eq!(res["mime_type"], "application/json");
        assert_eq!(res["size"], 7);
        let data = base64::engine::general_purpose::STANDARD
            .decode(res["data_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data, b"{\"a\":1}");
    }

    #[test]
    fn search_files_finds_matches_substring_and_respects_max_results() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("alpha.rs"), b"").unwrap();
        fs::write(dir.path().join("beta.rs"), b"").unwrap();
        fs::write(dir.path().join("gamma.txt"), b"").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/alphabet.rs"), b"").unwrap();

        let res = search_files(&dir.path().to_string_lossy(), "alpha", 10, 5, false).unwrap();
        assert_eq!(res["total"], 2);

        let res2 = search_files(&dir.path().to_string_lossy(), "*.rs", 10, 5, false).unwrap();
        assert_eq!(res2["total"], 3);

        let res3 = search_files(&dir.path().to_string_lossy(), "*.rs", 1, 5, false).unwrap();
        assert_eq!(res3["total"], 1);
    }

    #[test]
    fn search_files_skips_heavy_dirs_at_root() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("node_modules")).unwrap();
        fs::write(dir.path().join("node_modules/match.rs"), b"").unwrap();
        fs::write(dir.path().join("keep.rs"), b"").unwrap();
        let res = search_files(&dir.path().to_string_lossy(), "*.rs", 50, 5, false).unwrap();
        assert_eq!(res["total"], 1);
    }

    #[test]
    fn search_files_matches_path_shaped_queries() {
        // Used to return 0 hits because the substring matcher only saw
        // bare filenames — `src/main` could never match `main.rs`.
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), b"").unwrap();
        fs::create_dir(dir.path().join("lib")).unwrap();
        fs::write(dir.path().join("lib/main.rs"), b"").unwrap();

        let res = search_files(&dir.path().to_string_lossy(), "src/main", 10, 5, false).unwrap();
        assert_eq!(res["total"], 1);
        let entries = res["entries"].as_array().unwrap();
        assert_eq!(entries[0]["name"], "main.rs");
        assert!(entries[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("src/main.rs"));
    }

    #[test]
    fn search_files_empty_query_returns_immediate_children() {
        // Empty query is the agent-chat `@` browse case — return a flat
        // listing of cwd, no recursion, sorted by mtime desc.
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"").unwrap();
        fs::write(dir.path().join("b.txt"), b"").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        // Nested file must NOT be included — recursion is off.
        fs::write(dir.path().join("sub/inner.txt"), b"").unwrap();

        let res = search_files(&dir.path().to_string_lossy(), "", 10, 6, false).unwrap();
        let entries = res["entries"].as_array().unwrap();
        let names: Vec<&str> = entries
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));
        assert!(names.contains(&"sub"));
        assert!(!names.contains(&"inner.txt"));
    }

    #[test]
    fn search_files_files_only_excludes_dirs_but_recurses() {
        // `files_only` is the agent-chat `@`-mention path — directories
        // shouldn't take up slots in the result list, but the walker
        // still has to descend into them to find nested file hits.
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("foo_dir")).unwrap();
        fs::write(dir.path().join("foo_dir/foo_file.txt"), b"").unwrap();
        fs::write(dir.path().join("foo_top.txt"), b"").unwrap();

        let res = search_files(&dir.path().to_string_lossy(), "foo", 10, 5, true).unwrap();
        let entries = res["entries"].as_array().unwrap();
        let names: Vec<&str> = entries
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"foo_top.txt"));
        assert!(names.contains(&"foo_file.txt"));
        assert!(!names.contains(&"foo_dir"));
        // No FileEntry should report is_dir=true under files_only.
        assert!(entries.iter().all(|e| e["is_dir"] == false));
    }

    #[tokio::test]
    async fn handle_files_action_unknown_action_errors() {
        let v = serde_json::json!({"action": "does_not_exist", "path": "/tmp"});
        let router = crate::agent_session::AgentRouter::new();
        let err = handle_files_action(&v, &router).await.unwrap_err();
        match err {
            HostError::Backend(m) => assert!(m.contains("unknown files action")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_files_action_dispatches_stat() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("hi.txt");
        fs::write(&p, b"hi").unwrap();
        let v = serde_json::json!({
            "action": "stat",
            "path": p.to_string_lossy(),
        });
        let router = crate::agent_session::AgentRouter::new();
        let res = handle_files_action(&v, &router).await.unwrap();
        assert_eq!(res["size"], 2);
        assert_eq!(res["is_dir"], false);
    }

    #[test]
    fn denylist_blocks_protected_dirs() {
        // Test against an explicit fake home so the result doesn't
        // depend on the OnceLock-cached denylist (which other tests in
        // the workspace can pre-populate by mutating $HOME).
        let home = PathBuf::from("/Users/test-user");
        let d = build_denied_paths(&home);
        assert!(is_path_denied_against(&home.join(".ssh/id_ed25519"), &d));
        assert!(is_path_denied_against(
            &home.join(".pocketshell/state.json"),
            &d
        ));
        assert!(is_path_denied_against(&home.join(".aws/credentials"), &d));
        assert!(is_path_denied_against(
            &home.join(".gnupg/private-keys-v1.d/k"),
            &d
        ));
        assert!(is_path_denied_against(
            &home.join(".config/gh/hosts.yml"),
            &d
        ));
        assert!(is_path_denied_against(&home.join(".bash_history"), &d));
        assert!(is_path_denied_against(&home.join(".netrc"), &d));
        assert!(!is_path_denied_against(
            &home.join("Documents/file.txt"),
            &d
        ));
        assert!(!is_path_denied_against(&home.join(".bashrc"), &d));
    }

    #[test]
    fn denylist_blocks_writing_into_protected_dir() {
        // Writing a NEW file into a protected dir must be denied even
        // when the dir doesn't yet exist on disk. Exercises the
        // lexical-prefix path that safe_resolve_dest relies on.
        let home = PathBuf::from("/Users/test-user");
        let d = build_denied_paths(&home);
        assert!(is_path_denied_against(
            &home.join(".ssh").join("authorized_keys_attack"),
            &d,
        ));
    }

    #[test]
    fn denylist_blocks_system_paths() {
        // Defense-in-depth for the case where the daemon ends up running with
        // elevated privileges despite the EUID guard: every system credential
        // path the audit called out must be refused regardless of $HOME.
        let home = PathBuf::from("/Users/test-user");
        let d = build_denied_paths(&home);

        // Linux-shaped paths
        assert!(is_path_denied_against(Path::new("/etc/shadow"), &d));
        assert!(is_path_denied_against(Path::new("/etc/sudoers"), &d));
        assert!(is_path_denied_against(
            Path::new("/etc/ssh/ssh_host_ed25519_key"),
            &d
        ));
        assert!(is_path_denied_against(Path::new("/root/.ssh/id_rsa"), &d));
        assert!(is_path_denied_against(
            Path::new("/var/lib/postgresql/data/pg_hba.conf"),
            &d
        ));
        assert!(is_path_denied_against(Path::new("/var/log/auth.log"), &d));
        assert!(is_path_denied_against(Path::new("/boot/grub/grub.cfg"), &d));
        assert!(is_path_denied_against(Path::new("/proc/1/maps"), &d));
        assert!(is_path_denied_against(
            Path::new("/sys/class/net/eth0/address"),
            &d
        ));
        assert!(is_path_denied_against(Path::new("/dev/sda1"), &d));
        assert!(is_path_denied_against(
            Path::new("/usr/local/etc/openvpn/keys"),
            &d
        ));

        // macOS canonical paths (after fs::canonicalize rewrites /etc → /private/etc).
        assert!(is_path_denied_against(
            Path::new("/private/etc/master.passwd"),
            &d
        ));
        assert!(is_path_denied_against(
            Path::new("/private/var/db/sudo"),
            &d
        ));
        assert!(is_path_denied_against(
            Path::new("/private/var/log/system.log"),
            &d
        ));
    }

    #[test]
    fn denylist_allows_legitimate_paths() {
        // Sanity: the system-path denylist must NOT swallow common workspaces
        // — `/tmp` scratch, `/usr/local` source trees, `/opt` installs, the
        // macOS user `$TMPDIR` at `/private/var/folders/<hash>/T/`, POSIX
        // `/var/tmp`, and most of the user's home outside the home denylist.
        let home = PathBuf::from("/Users/test-user");
        let d = build_denied_paths(&home);

        assert!(!is_path_denied_against(Path::new("/tmp/build.log"), &d));
        assert!(!is_path_denied_against(
            Path::new("/var/tmp/scratch.txt"),
            &d
        ));
        assert!(!is_path_denied_against(
            Path::new("/var/folders/gz/abc/T/work.txt"),
            &d
        ));
        assert!(!is_path_denied_against(
            Path::new("/private/var/folders/gz/abc/T/work.txt"),
            &d,
        ));
        assert!(!is_path_denied_against(
            Path::new("/usr/local/src/myproj/README.md"),
            &d
        ));
        assert!(!is_path_denied_against(
            Path::new("/usr/local/bin/myapp"),
            &d
        ));
        assert!(!is_path_denied_against(
            Path::new("/opt/myapp/config.yml"),
            &d
        ));
        assert!(!is_path_denied_against(
            &home.join("projects/repo/src/main.rs"),
            &d
        ));
    }

    #[test]
    fn denylist_blocks_subpath_under_protected_root() {
        // `.starts_with` matches component-by-component, so an attacker can't
        // sneak past with a sibling name like `/etcetera/` — but they also
        // can't construct a deep path under a denied root.
        let home = PathBuf::from("/Users/test-user");
        let d = build_denied_paths(&home);

        // Deep paths under denied roots are denied.
        assert!(is_path_denied_against(
            Path::new("/etc/network/interfaces.d/01-eth0"),
            &d
        ));
        assert!(is_path_denied_against(
            Path::new("/var/log/nginx/access.log"),
            &d
        ));

        // Names that merely START with a denied component but are NOT under
        // it are not denied (`/etcetera` is a different directory than `/etc`).
        assert!(!is_path_denied_against(Path::new("/etcetera/file.txt"), &d));
        assert!(!is_path_denied_against(Path::new("/various/file.txt"), &d));
        // `/var/log` is denied but `/var/loghub` is a different dir.
        assert!(!is_path_denied_against(Path::new("/var/loghub/file"), &d));
    }
}
