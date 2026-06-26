//! Filename and in-file content search scoped to a project directory.
//! Uses the same skip rules as `list_project_tree` so searches stay fast and
//! avoid junk directories like `node_modules`.

use crate::error::{HostError, Result};
use crate::files::{is_path_denied, FileEntry};
use crate::project_index::{should_skip_dir, SEARCH_MAX_DEPTH};
use serde::Serialize;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const DEFAULT_FILENAME_RESULTS: usize = 200;
const DEFAULT_CONTENT_RESULTS: usize = 80;
const MAX_FILENAME_RESULTS: usize = 500;
const MAX_CONTENT_RESULTS: usize = 200;
const MAX_GREP_FILE_SIZE: u64 = 512 * 1024;
const PREVIEW_MAX_CHARS: usize = 160;

static BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "pdf", "zip", "gz", "tar", "7z", "rar",
    "wasm", "so", "dylib", "dll", "exe", "bin", "jar", "class", "o", "a", "lib", "mp3", "mp4",
    "mov", "avi", "mkv", "woff", "woff2", "ttf", "eot", "otf", "sqlite", "db", "pyc", "lock",
];

#[derive(Debug, Serialize)]
struct ContentMatch {
    path: String,
    line: u32,
    column: u32,
    preview: String,
}

pub async fn search_project(
    path_str: &str,
    query: &str,
    filename_limit: Option<usize>,
    content_limit: Option<usize>,
) -> Result<serde_json::Value> {
    let query = query.trim();
    if path_str.trim().is_empty() {
        return Err(HostError::Backend("project path is required".into()));
    }
    if query.is_empty() {
        return Err(HostError::Backend("search query is required".into()));
    }

    let filename_limit = filename_limit
        .unwrap_or(DEFAULT_FILENAME_RESULTS)
        .clamp(0, MAX_FILENAME_RESULTS);
    let content_limit = content_limit
        .unwrap_or(DEFAULT_CONTENT_RESULTS)
        .clamp(0, MAX_CONTENT_RESULTS);
    let path_str = path_str.to_string();
    let query_string = query.to_string();
    let query_echo = query_string.clone();

    let results = tokio::task::spawn_blocking(move || {
        search_project_blocking(&path_str, &query_string, filename_limit, content_limit)
    })
    .await
    .map_err(|e| HostError::Backend(format!("project_search panicked: {e}")))??;

    Ok(serde_json::json!({
        "project_path": results.project_path,
        "query": query_echo,
        "filename_matches": results.filename_matches,
        "content_matches": results.content_matches,
    }))
}

struct BlockingSearchResults {
    project_path: String,
    filename_matches: Vec<FileEntry>,
    content_matches: Vec<ContentMatch>,
}

fn search_project_blocking(
    path_str: &str,
    query: &str,
    filename_limit: usize,
    content_limit: usize,
) -> Result<BlockingSearchResults> {
    use crate::files::list_dir_all;

    let (root, _) = list_dir_all(path_str, false)?;
    let project_path = root.to_string_lossy().into_owned();
    let query_lower = query.to_lowercase();

    let mut filename_matches = Vec::new();
    let mut content_matches = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    if filename_limit == 0 && content_limit == 0 {
        return Ok(BlockingSearchResults {
            project_path,
            filename_matches,
            content_matches,
        });
    }
    queue.push_back((root.clone(), 0));

    while let Some((dir, depth)) = queue.pop_front() {
        if filename_matches.len() >= filename_limit && content_matches.len() >= content_limit {
            break;
        }

        let dir_key = dir.to_string_lossy().into_owned();
        let (_, children) = list_dir_all(&dir_key, false)?;

        for entry in children {
            if filename_matches.len() >= filename_limit && content_matches.len() >= content_limit {
                break;
            }

            let entry_path = PathBuf::from(&entry.path);
            let name_lower = entry.name.to_lowercase();
            let rel_lower = entry_path
                .strip_prefix(&root)
                .unwrap_or(&entry_path)
                .to_string_lossy()
                .replace('\\', "/")
                .to_lowercase();

            let filename_hit =
                name_lower.contains(&query_lower) || rel_lower.contains(&query_lower);
            if filename_hit && filename_matches.len() < filename_limit {
                filename_matches.push(entry.clone());
            }

            if entry.is_dir {
                if entry.is_symlink || should_skip_dir(&entry.name, depth + 1, SEARCH_MAX_DEPTH) {
                    continue;
                }
                queue.push_back((entry_path, depth + 1));
                continue;
            }

            if content_matches.len() < content_limit && is_grep_candidate(&entry.name) {
                if let Ok(metadata) = fs::metadata(&entry_path) {
                    if metadata.len() <= MAX_GREP_FILE_SIZE {
                        grep_file(
                            &entry_path,
                            &query_lower,
                            &mut content_matches,
                            content_limit,
                        );
                    }
                }
            }
        }
    }

    Ok(BlockingSearchResults {
        project_path,
        filename_matches,
        content_matches,
    })
}

fn is_grep_candidate(name: &str) -> bool {
    let lower = name.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        if ext != lower && BINARY_EXTENSIONS.iter().any(|b| *b == ext) {
            return false;
        }
    }
    true
}

fn grep_file(path: &Path, query_lower: &str, out: &mut Vec<ContentMatch>, limit: usize) {
    if out.len() >= limit || is_path_denied(path) {
        return;
    }
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);
    for (idx, line_result) in reader.lines().enumerate() {
        if out.len() >= limit {
            break;
        }
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line_lower = line.to_lowercase();
        let Some(column) = line_lower.find(query_lower) else {
            continue;
        };
        let preview = trim_preview(&line);
        out.push(ContentMatch {
            path: path.to_string_lossy().into_owned(),
            line: (idx + 1) as u32,
            column: column as u32,
            preview,
        });
    }
}

fn trim_preview(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.chars().count() <= PREVIEW_MAX_CHARS {
        return trimmed.to_string();
    }
    trimmed.chars().take(PREVIEW_MAX_CHARS).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_finds_filename_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("README.md"), "# PocketShell project").unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn pocketshell() {}\n").unwrap();

        let results = search_project_blocking(&root.to_string_lossy(), "main", 20, 20).unwrap();

        assert!(results.filename_matches.iter().any(|e| e.name == "main.rs"));

        let content =
            search_project_blocking(&root.to_string_lossy(), "pocketshell", 20, 20).unwrap();
        assert!(content
            .content_matches
            .iter()
            .any(|m| m.path.contains("main.rs") && m.line == 1));
    }

    #[test]
    fn zero_limits_disable_each_search_kind() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("target.txt"), "needle\n").unwrap();

        let filenames = search_project_blocking(&root.to_string_lossy(), "target", 20, 0).unwrap();
        assert!(!filenames.filename_matches.is_empty());
        assert!(filenames.content_matches.is_empty());

        let content = search_project_blocking(&root.to_string_lossy(), "needle", 0, 20).unwrap();
        assert!(content.filename_matches.is_empty());
        assert!(!content.content_matches.is_empty());
    }
}
