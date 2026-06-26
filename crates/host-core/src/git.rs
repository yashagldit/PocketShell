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

fn git_command() -> Command {
    let mut command = Command::new("git");
    crate::platform::hide_command_window(&mut command);
    command
}

fn run_git(cwd: &str, args: &[&str]) -> Result<String> {
    let dir = git_dir(cwd)?;
    let output = git_command()
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

fn run_git_allow_exit(cwd: &str, args: &[&str], allowed_codes: &[i32]) -> Result<String> {
    let dir = git_dir(cwd)?;
    let output = git_command()
        .args(args)
        .current_dir(&dir)
        .output()
        .map_err(|e| HostError::Backend(format!("git spawn failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    if !output.status.success() && !allowed_codes.contains(&code) {
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
    let output = git_command()
        .args(args)
        .current_dir(&dir)
        .output()
        .map_err(|e| HostError::Backend(format!("git spawn failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

fn null_device_path() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

#[derive(Debug, Clone)]
struct GitStatusEntry {
    x: u8,
    y: u8,
    path: String,
    orig_path: Option<String>,
}

impl GitStatusEntry {
    fn is_untracked(&self) -> bool {
        self.x == b'?' && self.y == b'?'
    }

    fn is_staged(&self) -> bool {
        self.x != b' ' && self.x != b'?'
    }

    fn is_unstaged(&self) -> bool {
        self.is_untracked() || (self.y != b' ' && self.y != b'?')
    }

    fn is_rename_or_copy(&self) -> bool {
        matches!(self.x, b'R' | b'C') || matches!(self.y, b'R' | b'C')
    }

    fn status(&self) -> &'static str {
        match (self.x, self.y) {
            (b'?', b'?') => "new",
            (b'D', _) | (_, b'D') => "deleted",
            (b'A', _) | (_, b'A') => "new",
            (b'R', _) | (_, b'R') => "renamed",
            (b'C', _) | (_, b'C') => "copied",
            (b'M', _) | (_, b'M') => "modified",
            _ => "changed",
        }
    }
}

fn parse_status_z(out: &str) -> Vec<GitStatusEntry> {
    let mut entries = Vec::new();
    let mut parts = out.split('\0').filter(|part| !part.is_empty());
    while let Some(record) = parts.next() {
        if record.len() < 3 {
            continue;
        }
        let bytes = record.as_bytes();
        let x = bytes[0];
        let y = bytes[1];
        let path = record[3..].to_string();
        let orig_path = if matches!(x, b'R' | b'C') || matches!(y, b'R' | b'C') {
            parts.next().map(str::to_string)
        } else {
            None
        };
        entries.push(GitStatusEntry {
            x,
            y,
            path,
            orig_path,
        });
    }
    entries
}

fn status_entries(cwd: &str, file: Option<&str>) -> Result<Vec<GitStatusEntry>> {
    let out = match file {
        Some(f) => run_git(
            cwd,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--",
                f,
            ],
        )?,
        None => run_git(
            cwd,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?,
    };
    Ok(parse_status_z(&out))
}

fn status_entries_for_path(cwd: &str, file: &str) -> Result<Vec<GitStatusEntry>> {
    let entries: Vec<GitStatusEntry> = status_entries(cwd, None)?
        .into_iter()
        .filter(|entry| entry.path == file || entry.orig_path.as_deref() == Some(file))
        .collect();
    if entries.is_empty() {
        status_entries(cwd, Some(file))
    } else {
        Ok(entries)
    }
}

/// `git status --porcelain=v1 -b` plus ahead/behind when available.
pub fn git_status(cwd: &str) -> Result<serde_json::Value> {
    let branch_out =
        run_git_ok_stderr(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_default();
    let branch = branch_out.trim().to_string();
    let porcelain = run_git(cwd, &["status", "--porcelain=v1", "-b"])?;
    let entries = status_entries(cwd, None)?;

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
    }

    for entry in entries {
        dirty = true;
        if entry.is_staged() {
            staged += 1;
        }
        if entry.is_untracked() {
            untracked += 1;
        } else if entry.is_unstaged() {
            modified += 1;
        }
        if entry.x == b'D' || entry.y == b'D' {
            deleted += 1;
        }

        files.push(serde_json::json!({
            "path": entry.path,
            "status": entry.status(),
            "staged": entry.is_staged(),
            "unstaged": entry.is_unstaged(),
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
    if let Some(f) = file {
        if f.trim().is_empty() {
            return Err(HostError::Backend("empty file path".into()));
        }
        let entries = status_entries(cwd, Some(f))?;
        let diff = if entries.iter().any(GitStatusEntry::is_untracked) {
            run_git_allow_exit(
                cwd,
                &[
                    "diff",
                    "--no-color",
                    "--no-index",
                    "--",
                    null_device_path(),
                    f,
                ],
                &[0, 1],
            )?
        } else {
            run_git(cwd, &["diff", "--no-color", "HEAD", "--", f])
                .or_else(|_| run_git(cwd, &["diff", "--no-color", "--", f]))?
        };
        return Ok(serde_json::json!({
            "diff": diff,
            "file": file,
        }));
    }

    let diff = run_git(cwd, &["diff", "--no-color", "HEAD"])
        .or_else(|_| run_git(cwd, &["diff", "--no-color"]))?;
    Ok(serde_json::json!({
        "diff": diff,
        "file": file,
    }))
}

/// Recent commits on current branch.
pub fn git_log(cwd: &str, limit: usize) -> Result<serde_json::Value> {
    let lim = limit.clamp(1, 50);
    let fmt = "--pretty=format:%H%x1f%s%x1f%ar";
    let out = run_git(cwd, &["log", "-n", &lim.to_string(), fmt])?;
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

fn require_file_path(file: Option<&str>) -> Result<Option<&str>> {
    match file {
        Some(f) if f.trim().is_empty() => Err(HostError::Backend("empty file path".into())),
        Some(f) => Ok(Some(f)),
        None => Ok(None),
    }
}

pub fn git_stage(cwd: &str, file: Option<&str>) -> Result<serde_json::Value> {
    match require_file_path(file)? {
        Some(f) => {
            run_git(cwd, &["add", "--", f])?;
        }
        None => {
            run_git(cwd, &["add", "-A"])?;
        }
    }
    Ok(serde_json::json!({ "ok": true }))
}

pub fn git_unstage(cwd: &str, file: Option<&str>) -> Result<serde_json::Value> {
    match require_file_path(file)? {
        Some(f) => {
            run_git(cwd, &["restore", "--staged", "--", f])
                .or_else(|_| run_git(cwd, &["reset", "HEAD", "--", f]))
                .or_else(|_| run_git(cwd, &["rm", "--cached", "-r", "--", f]))?;
        }
        None => {
            run_git(cwd, &["restore", "--staged", ":/"])
                .or_else(|_| run_git(cwd, &["reset", "HEAD", "--", "."]))
                .or_else(|_| run_git(cwd, &["rm", "--cached", "-r", "."]))?;
        }
    }
    Ok(serde_json::json!({ "ok": true }))
}

pub fn git_discard(cwd: &str, file: Option<&str>) -> Result<serde_json::Value> {
    match require_file_path(file)? {
        Some(f) => {
            let entries = status_entries_for_path(cwd, f)?;
            for entry in entries {
                if entry.is_untracked() {
                    run_git(cwd, &["clean", "-fd", "--", &entry.path])?;
                    continue;
                }

                if entry.is_rename_or_copy() {
                    if let Some(orig) = entry.orig_path.as_deref() {
                        run_git(
                            cwd,
                            &[
                                "restore",
                                "--source=HEAD",
                                "--staged",
                                "--worktree",
                                "--",
                                orig,
                                &entry.path,
                            ],
                        )?;
                        continue;
                    }
                }

                run_git(
                    cwd,
                    &[
                        "restore",
                        "--source=HEAD",
                        "--staged",
                        "--worktree",
                        "--",
                        &entry.path,
                    ],
                )
                .or_else(|_| {
                    run_git(cwd, &["rm", "--cached", "-f", "--", &entry.path])
                        .and_then(|_| run_git(cwd, &["clean", "-fd", "--", &entry.path]))
                })?;
            }
        }
        None => {
            for entry in status_entries(cwd, None)? {
                git_discard(cwd, Some(&entry.path))?;
            }
        }
    }
    Ok(serde_json::json!({ "ok": true }))
}

pub fn git_commit(cwd: &str, message: &str) -> Result<serde_json::Value> {
    let message = message.trim();
    if message.is_empty() {
        return Err(HostError::Backend("empty commit message".into()));
    }
    let output = run_git(cwd, &["commit", "-m", message])?;
    let hash = run_git(cwd, &["rev-parse", "--short", "HEAD"]).unwrap_or_default();
    Ok(serde_json::json!({
        "ok": true,
        "hash": hash.trim(),
        "output": output.trim(),
    }))
}

pub fn git_branches(cwd: &str) -> Result<serde_json::Value> {
    let out = run_git(cwd, &["branch", "--format=%(refname:short)%00%(HEAD)"])?;
    let branches: Vec<serde_json::Value> = out
        .split('\n')
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split('\0');
            let name = parts.next().unwrap_or("").trim();
            let head = parts.next().unwrap_or("").trim();
            serde_json::json!({
                "name": name,
                "current": head == "*",
            })
        })
        .filter(|branch| branch["name"].as_str().is_some_and(|name| !name.is_empty()))
        .collect();
    Ok(serde_json::json!({ "branches": branches }))
}

pub fn git_checkout_branch(cwd: &str, branch: &str, create: bool) -> Result<serde_json::Value> {
    let branch = branch.trim();
    if branch.is_empty() {
        return Err(HostError::Backend("empty branch name".into()));
    }
    if branch.starts_with('-') || branch.contains("..") || branch.contains('\0') {
        return Err(HostError::Backend("invalid branch name".into()));
    }
    if create {
        run_git(cwd, &["checkout", "-b", branch])?;
    } else {
        run_git(cwd, &["checkout", branch])?;
    }
    Ok(serde_json::json!({ "ok": true, "branch": branch }))
}

pub fn is_git_repo(cwd: &str) -> bool {
    git_dir(cwd)
        .ok()
        .map(|p| p.join(".git").exists() || is_git_worktree(&p))
        .unwrap_or(false)
}

fn is_git_worktree(dir: &Path) -> bool {
    let git = dir.join(".git");
    git.is_file()
        && std::fs::read_to_string(&git)
            .map(|s| s.starts_with("gitdir:"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn init_repo(dir: &Path) {
        git_command()
            .args(["init", "-b", "main"])
            .current_dir(dir)
            .output()
            .expect("git init");
        git_command()
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .output()
            .expect("git config email");
        git_command()
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .expect("git config name");
    }

    fn commit_all(dir: &Path, message: &str) {
        git_command()
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .expect("git add");
        git_command()
            .args(["commit", "-m", message])
            .current_dir(dir)
            .output()
            .expect("git commit");
    }

    #[test]
    fn git_status_clean_repo() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi").unwrap();
        commit_all(dir.path(), "init");
        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["dirty"].as_bool(), Some(false));
        assert_eq!(status["branch"].as_str(), Some("main"));
    }

    #[test]
    fn git_diff_includes_staged_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("app.txt"), "old\n").unwrap();
        commit_all(dir.path(), "init");

        fs::write(dir.path().join("app.txt"), "new\n").unwrap();
        git_command()
            .args(["add", "app.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let diff = git_diff(&dir.path().to_string_lossy(), Some("app.txt")).unwrap();
        let text = diff["diff"].as_str().unwrap();
        assert!(text.contains("-old"));
        assert!(text.contains("+new"));
    }

    #[test]
    fn git_diff_renders_untracked_file_as_addition() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi\n").unwrap();
        commit_all(dir.path(), "init");

        fs::write(dir.path().join("new.txt"), "hello\n").unwrap();

        let diff = git_diff(&dir.path().to_string_lossy(), Some("new.txt")).unwrap();
        let text = diff["diff"].as_str().unwrap();
        assert!(text.contains("+++ b/new.txt") || text.contains("+++ new.txt"));
        assert!(text.contains("+hello"));
    }

    #[test]
    fn git_stage_unstage_and_commit_file() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("app.txt"), "hello\n").unwrap();

        git_stage(&dir.path().to_string_lossy(), Some("app.txt")).unwrap();
        let staged = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(staged["files"][0]["status"].as_str(), Some("new"));
        assert_eq!(staged["files"][0]["staged"].as_bool(), Some(true));

        git_unstage(&dir.path().to_string_lossy(), Some("app.txt")).unwrap();
        let unstaged = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(unstaged["files"][0]["unstaged"].as_bool(), Some(true));

        git_stage(&dir.path().to_string_lossy(), Some("app.txt")).unwrap();
        let committed = git_commit(&dir.path().to_string_lossy(), "add app").unwrap();
        assert_eq!(committed["ok"].as_bool(), Some(true));
        assert!(!committed["hash"].as_str().unwrap_or("").is_empty());
        let clean = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(clean["dirty"].as_bool(), Some(false));
    }

    #[test]
    fn git_discard_untracked_file_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi\n").unwrap();
        commit_all(dir.path(), "init");
        fs::write(dir.path().join("scratch.txt"), "temporary\n").unwrap();

        git_discard(&dir.path().to_string_lossy(), Some("scratch.txt")).unwrap();

        assert!(!dir.path().join("scratch.txt").exists());
        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["dirty"].as_bool(), Some(false));
    }

    #[test]
    fn git_status_expands_untracked_directory_contents() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi\n").unwrap();
        commit_all(dir.path(), "init");

        fs::create_dir_all(dir.path().join("new-dir/nested")).unwrap();
        fs::write(dir.path().join("new-dir/a.txt"), "a\n").unwrap();
        fs::write(dir.path().join("new-dir/nested/b.txt"), "b\n").unwrap();

        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        let paths: Vec<&str> = status["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|file| file["path"].as_str())
            .collect();

        assert!(paths.contains(&"new-dir/a.txt"));
        assert!(paths.contains(&"new-dir/nested/b.txt"));
        assert!(!paths.contains(&"new-dir/"));
        assert_eq!(status["counts"]["untracked"].as_u64(), Some(2));
    }

    #[test]
    fn parse_status_z_preserves_arrow_in_file_names() {
        let entries = parse_status_z("R  new -> name.txt\0old -> name.txt\0");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "new -> name.txt");
        assert_eq!(entries[0].orig_path.as_deref(), Some("old -> name.txt"));
    }

    #[test]
    fn git_discard_all_handles_initial_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("app.txt"), "hello\n").unwrap();
        git_stage(&dir.path().to_string_lossy(), Some("app.txt")).unwrap();

        git_discard(&dir.path().to_string_lossy(), None).unwrap();

        assert!(!dir.path().join("app.txt").exists());
        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["dirty"].as_bool(), Some(false));
    }

    #[test]
    fn git_discard_rename_restores_original_file() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("old.txt"), "hello\n").unwrap();
        commit_all(dir.path(), "init");
        git_command()
            .args(["mv", "old.txt", "new.txt"])
            .current_dir(dir.path())
            .output()
            .expect("git mv");

        git_discard(&dir.path().to_string_lossy(), Some("new.txt")).unwrap();

        assert!(dir.path().join("old.txt").exists());
        assert!(!dir.path().join("new.txt").exists());
        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["dirty"].as_bool(), Some(false));
    }

    #[cfg(not(windows))]
    #[test]
    fn git_status_preserves_arrow_in_file_names() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("old -> name.txt"), "hello\n").unwrap();
        commit_all(dir.path(), "init");
        git_command()
            .args(["mv", "old -> name.txt", "new -> name.txt"])
            .current_dir(dir.path())
            .output()
            .expect("git mv");

        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["files"][0]["path"].as_str(), Some("new -> name.txt"));

        git_discard(&dir.path().to_string_lossy(), Some("new -> name.txt")).unwrap();
        assert!(dir.path().join("old -> name.txt").exists());
        let clean = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(clean["dirty"].as_bool(), Some(false));
    }

    #[test]
    fn git_discard_all_fails_outside_repo() {
        let dir = tempfile::tempdir().unwrap();
        let result = git_discard(&dir.path().to_string_lossy(), None);
        assert!(result.is_err());
    }

    #[test]
    fn git_checkout_branch_can_create_and_switch() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi\n").unwrap();
        commit_all(dir.path(), "init");

        git_checkout_branch(&dir.path().to_string_lossy(), "feature/mobile", true).unwrap();
        let status = git_status(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(status["branch"].as_str(), Some("feature/mobile"));

        git_checkout_branch(&dir.path().to_string_lossy(), "main", false).unwrap();
        let branches = git_branches(&dir.path().to_string_lossy()).unwrap();
        let branch_names: Vec<&str> = branches["branches"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|branch| branch["name"].as_str())
            .collect();
        assert!(branch_names.contains(&"feature/mobile"));
    }

    #[test]
    fn git_checkout_branch_rejects_unsafe_name() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), "hi\n").unwrap();
        commit_all(dir.path(), "init");

        let result = git_checkout_branch(&dir.path().to_string_lossy(), "-bad", true);
        assert!(result.is_err());
    }
}
