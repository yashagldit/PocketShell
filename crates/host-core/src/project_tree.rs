//! Walks a project directory on the host and returns a pre-indexed file tree
//! for the mobile project-space sidebar. Skips heavy directories (node_modules,
//! .git, …) and caps recursion depth so one RPC replaces hundreds of list_dir
//! round-trips.

use crate::error::{HostError, Result};
use crate::files::{list_dir_all, FileEntry};
use crate::project_index::{should_skip_dir, DEFAULT_MAX_DEPTH};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

const MAX_MAX_DEPTH: usize = 12;
/// Safety cap on indexed directories to keep payloads bounded.
const MAX_INDEXED_DIRS: usize = 4_000;

#[derive(Debug, Serialize)]
struct TreeNode {
    children: Vec<FileEntry>,
    complete: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    skipped: bool,
}

pub async fn list_project_tree(
    path_str: &str,
    max_depth: Option<usize>,
) -> Result<serde_json::Value> {
    if path_str.trim().is_empty() {
        return Err(HostError::Backend("project path is required".into()));
    }
    let max_depth = max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(1, MAX_MAX_DEPTH);
    let path_str = path_str.to_string();

    let indexed = tokio::task::spawn_blocking(move || index_project_tree(&path_str, max_depth))
        .await
        .map_err(|e| HostError::Backend(format!("project_tree scan panicked: {e}")))??;

    Ok(serde_json::json!({
        "project_path": indexed.project_path,
        "indexed_at": chrono::Utc::now().to_rfc3339(),
        "max_depth": max_depth,
        "nodes": indexed.nodes,
    }))
}

struct IndexedTree {
    project_path: String,
    nodes: HashMap<String, TreeNode>,
}

fn index_project_tree(path_str: &str, max_depth: usize) -> Result<IndexedTree> {
    let (root, _) = list_dir_all(path_str, false)?;
    let project_path = root.to_string_lossy().into_owned();
    let mut nodes: HashMap<String, TreeNode> = HashMap::new();
    let mut visited = HashSet::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((root.clone(), 0));

    while let Some((dir, depth)) = queue.pop_front() {
        let dir_key = dir.to_string_lossy().into_owned();
        if !visited.insert(dir_key.clone()) {
            continue;
        }
        if visited.len() > MAX_INDEXED_DIRS {
            break;
        }

        let (_, children) = list_dir_all(&dir_key, false)?;
        let mut child_dirs: Vec<FileEntry> = Vec::new();

        for entry in &children {
            if !entry.is_dir || entry.is_symlink {
                continue;
            }
            if should_skip_dir(&entry.name, depth + 1, max_depth) {
                nodes.insert(
                    entry.path.clone(),
                    TreeNode {
                        children: Vec::new(),
                        complete: true,
                        skipped: true,
                    },
                );
                continue;
            }
            child_dirs.push(entry.clone());
        }

        nodes.insert(
            dir_key,
            TreeNode {
                children,
                complete: true,
                skipped: false,
            },
        );

        for entry in child_dirs {
            queue.push_back((PathBuf::from(entry.path), depth + 1));
        }
    }

    Ok(IndexedTree {
        project_path,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn should_skip_node_modules() {
        assert!(should_skip_dir("node_modules", 1, DEFAULT_MAX_DEPTH));
        assert!(should_skip_dir("NODE_MODULES", 1, DEFAULT_MAX_DEPTH));
    }

    #[test]
    fn should_not_skip_src() {
        assert!(!should_skip_dir("src", 1, DEFAULT_MAX_DEPTH));
    }

    #[test]
    fn should_skip_beyond_max_depth() {
        assert!(should_skip_dir(
            "src",
            DEFAULT_MAX_DEPTH + 1,
            DEFAULT_MAX_DEPTH
        ));
    }

    #[test]
    fn index_project_tree_skips_node_modules_children() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        let nm = root.join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::create_dir(nm.join("left-pad")).unwrap();

        let indexed = index_project_tree(&root.to_string_lossy(), DEFAULT_MAX_DEPTH).unwrap();
        let root_node = indexed.nodes.get(&indexed.project_path).expect("root node");
        assert!(root_node.children.iter().any(|e| e.name == "src"));
        assert!(root_node.children.iter().any(|e| e.name == "node_modules"));

        let nm_node = indexed
            .nodes
            .values()
            .find(|node| node.skipped && node.children.is_empty())
            .expect("node_modules node");
        assert!(nm_node.skipped);
        assert!(nm_node.children.is_empty());
        assert_eq!(
            indexed
                .nodes
                .keys()
                .filter(|key| key.contains("left-pad"))
                .count(),
            0
        );
    }
}
