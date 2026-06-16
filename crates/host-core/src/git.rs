//! Thin wrappers around the `git` CLI for project-scoped VCS queries from mobile.

use std::path::Path;
use std::process::Command;

use crate::error::{HostError, Result};
use crate::files::resolve_path;

fn git_dir(cwd: &str) -> Result<std::path::PathBuf> {
    let resolved = resolve_path(cwd)?;
    if !resolved.is_dir() {
        return Err(HostError::Backend(format!("not a directory: {cwd}")));
    }
    Ok(resolved)
}

fn run_git(cwd: &str, args: &[&str]) -> Result<String> {
    let dir = git_dir(cwd)?;
    let output = Command::new("git")
        .args(args)
        .current_dir(&dir)
        .output()
        .map_err(|e| HostError::Backend(format!("git spawn failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        let msg = if stderr.trim().is_empty() {
            format!("git exited with {}", output.status)
        } else {
            stderr.trim().to_string()
        };
        return Err(HostError::Backend(msg));
    }
    Ok(stdout)
}

fn run_git_ok_stderr(cwd: &str, args: &[&str]) -> Result<String> {
    let dir = git_dir(cwd)?;
    let output = Command::new("git")
        .args(args)
        .current_dir(&dir)
        .output()
        .map_err(|e| HostError::Backend(format!("git spawn failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

/// `git status --porcelain=v1 -b` plus ahead/behind when available.
pub fn git_status(cwd: &str) -> Result<serde_json::Value> {
    let branch_out = run_git_ok_stderr(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_default();
    let branch = branch_out.trim().to_string();
    let porcelain = run_git_ok_stderr(cwd, &["status", "--porcelain=v1", "-b"]).unwrap_or_default();

    let mut ahead: u32 = 0;
    let mut behind: u32 = 0;
    let mut dirty = false;
    let mut staged = 0u32;
    let mut modified = 0u32;
    let mut untracked = 0u32;
    let mut deleted = 0u32;
    let mut files: Vec<serde_json::Value> = Vec::new();

    for line in porcelain.lines() {
        if line.starts_with("## ") {
            if let Some(rest) = line.strip_prefix("## ") {
                if let Some(bracket) = rest.find('[') {
                    let meta = &rest[bracket + 1..rest.len().saturating_sub(1)];
                    for part in meta.split(',') {
                        let part = part.trim();
                        if let Some(n) = part.strip_prefix("ahead ") {
                            ahead = n.trim().parse().unwrap_or(0);
                        } else if let Some(n) = part.strip_prefix("behind ") {
                            behind = n.trim().parse().unwrap_or(0);
                        }
                    }
                }
            }
            continue;
        }
        if line.len() < 3 {
            continue;
        }
        dirty = true;
        let x = line.as_bytes().get(0).copied().unwrap_or(b' ');
        let y = line.as_bytes().get(1).copied().unwrap_or(b' ');
        let path = line[3..].trim();
        let path = path.split(" -> ").next().unwrap_or(path).trim();

        let status = match (x, y) {
            (b'?', b'?') => {
                untracked += 1;
                "untracked"
            }
            (_, b'D') | (b'D', _) => {
                deleted += 1;
                "deleted"
            }
            (b'M', _) | (b'A', _) | (b'R', _) | (b'C', _) => {
                staged += 1;
                "staged"
            }
            (_, b'M') => {
                modified += 1;
                "modified"
            }
            _ => "changed",
        };
        files.push(serde_json::json!({
            "path": path,
            "status": status,
            "staged": x != b' ' && x != b'?',
            "unstaged": y != b' ' && y != b'?',
        }));
    }

    Ok(serde_json::json!({
        "branch": if branch.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(branch) },
        "dirty": dirty,
        "ahead": ahead,
        "behind": behind,
        "counts": {
            "staged": staged,
            "modified": modified,
            "untracked": untracked,
            "deleted": deleted,
        },
        "files": files,
    }))
}

/// Unified diff for one file or entire worktree when `file` is None.
pub fn git_diff(cwd: &str, file: Option<&str>) -> Result<serde_json::Value> {
    let mut args = vec!["diff", "--no-color"];
    if let Some(f) = file {
        if f.trim().is_empty() {
            return Err(HostError::Backend("empty file path".into()));
        }
        args.push(f);
    }
    let diff = run_git(cwd, &args)?;
    Ok(serde_json::json!({
        "diff": diff,
        "file": file,
    }))
}

/// Recent commits on current branch.
pub fn git_log(cwd: &str, limit: usize) -> Result<serde_json::Value> {
    let lim = limit.clamp(1, 50);
    let fmt = "--pretty=format:%H%x1f%s%x1f%ar";
    let out = run_git(
        cwd,
        &["log", "-n", &lim.to_string(), fmt],
    )?;
    let commits: Vec<serde_json::Value> = out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split('\x1f').collect();
            serde_json::json!({
                "hash": parts.first().copied().unwrap_or(""),
                "short_hash": parts.first().map(|h| &h[..h.len().min(7)]).unwrap_or(""),
                "subject": parts.get(1).copied().unwrap_or(""),
                "relative": parts.get(2).copied().unwrap_or(""),
            })
        })
        .collect();
    Ok(serde_json::json!({ "commits": commits }))
}

pub fn is_git_repo(cwd: &str) -> bool {
    git_dir(cwd)
        .ok()
        .map(|p| p.join(".git").exists() || is_git_worktree(&p))
        .unwrap_or(false)
}

fn is_git_worktree(dir: &Path) -> bool {
    let git = dir.join(".git");
    git.is_file() && std::fs::read_to_string(&git).map(|s| s.starts_with("gitdir:")).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn init_repo(dir: &Path) {
        Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(dir)
            .output()
            .expect("git init");
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .output()
            .expect("git config email");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .expect("git config name");
    }

    #[test]
    fn git_status_clean_repo() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi").unwrap();
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["dirty"].as_bool(), Some(false));
        assert_eq!(status["branch"].as_str(), Some("main"));
    }
}