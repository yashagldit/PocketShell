//! Thin wrappers around the `git` CLI for project-scoped VCS queries from mobile.

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{HostError, Result};
use crate::files::resolve_path;

const GIT_REMOTE_TIMEOUT: Duration = Duration::from_secs(60);

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

struct TimedGitOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn run_git_with_timeout(cwd: &str, args: &[&str], timeout: Duration) -> Result<TimedGitOutput> {
    let dir = git_dir(cwd)?;
    let mut child = git_command()
        .args(args)
        .current_dir(&dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HostError::Backend(format!("git spawn failed: {e}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HostError::Backend("git stdout pipe unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| HostError::Backend("git stderr pipe unavailable".into()))?;

    let stdout_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut stdout = stdout;
        std::io::Read::read_to_end(&mut stdout, &mut buf).map(|_| buf)
    });
    let stderr_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut stderr = stderr;
        std::io::Read::read_to_end(&mut stderr, &mut buf).map(|_| buf)
    });

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| HostError::Backend(format!("git wait failed: {e}")))?
        {
            break (status, false);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let status = child
                .wait()
                .map_err(|e| HostError::Backend(format!("git wait failed: {e}")))?;
            break (status, true);
        }
        thread::sleep(Duration::from_millis(50));
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| HostError::Backend("git stdout reader panicked".into()))?
        .map_err(|e| HostError::Backend(format!("git stdout read failed: {e}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| HostError::Backend("git stderr reader panicked".into()))?
        .map_err(|e| HostError::Backend(format!("git stderr read failed: {e}")))?;

    Ok(TimedGitOutput {
        status,
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        timed_out,
    })
}

fn combined_output(output: &TimedGitOutput) -> String {
    match (output.stderr.trim(), output.stdout.trim()) {
        ("", "") => String::new(),
        ("", stdout) => stdout.to_string(),
        (stderr, "") => stderr.to_string(),
        (stderr, stdout) => format!("{stderr}\n{stdout}"),
    }
}

fn timed_git_ok(output: TimedGitOutput) -> Result<String> {
    let combined = combined_output(&output);
    if output.timed_out {
        let seconds = GIT_REMOTE_TIMEOUT.as_secs();
        let msg = if combined.is_empty() {
            format!("git timed out after {seconds}s")
        } else {
            format!("git timed out after {seconds}s: {combined}")
        };
        return Err(HostError::Backend(msg));
    }
    if !output.status.success() {
        let msg = if combined.is_empty() {
            format!("git exited with {}", output.status)
        } else {
            combined
        };
        return Err(HostError::Backend(msg));
    }
    Ok(combined)
}

fn null_device_path() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

fn is_valid_git_hash(hash: &str) -> bool {
    (4..=64).contains(&hash.len()) && hash.chars().all(|c| c.is_ascii_hexdigit())
}

fn require_git_hash(hash: &str) -> Result<&str> {
    let hash = hash.trim();
    if is_valid_git_hash(hash) {
        Ok(hash)
    } else {
        Err(HostError::Backend("invalid commit hash".into()))
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

fn name_status_label(status: u8) -> &'static str {
    match status {
        b'A' => "new",
        b'D' => "deleted",
        b'R' => "renamed",
        b'C' => "copied",
        b'M' => "modified",
        _ => "changed",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitNameStatusEntry {
    path: String,
    old_path: Option<String>,
    status: &'static str,
}

fn parse_name_status_z(out: &str) -> Vec<GitNameStatusEntry> {
    let mut entries = Vec::new();
    let mut parts = out.split('\0').filter(|part| !part.is_empty());
    while let Some(record) = parts.next() {
        let status = record.as_bytes().first().copied().unwrap_or(b'?');
        if matches!(status, b'R' | b'C') {
            let Some(old_path) = parts.next() else {
                break;
            };
            let Some(path) = parts.next() else {
                break;
            };
            entries.push(GitNameStatusEntry {
                path: path.to_string(),
                old_path: Some(old_path.to_string()),
                status: name_status_label(status),
            });
        } else if let Some(path) = parts.next() {
            entries.push(GitNameStatusEntry {
                path: path.to_string(),
                old_path: None,
                status: name_status_label(status),
            });
        }
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
pub fn git_diff(cwd: &str, file: Option<&str>, commit: Option<&str>) -> Result<serde_json::Value> {
    let file = require_file_path(file)?;
    let commit = commit.map(require_git_hash).transpose()?;
    let diff = match (commit, file) {
        (Some(commit), Some(f)) => run_git(cwd, &["show", commit, "--format=", "--", f])?,
        (Some(commit), None) => run_git(cwd, &["show", commit, "--format="])?,
        (None, Some(f)) => {
            let entries = status_entries(cwd, Some(f))?;
            if entries.iter().any(GitStatusEntry::is_untracked) {
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
            }
        }
        (None, None) => run_git(cwd, &["diff", "--no-color", "HEAD"])
            .or_else(|_| run_git(cwd, &["diff", "--no-color"]))?,
    };
    Ok(serde_json::json!({
        "diff": diff,
        "file": file,
        "commit": commit,
    }))
}

/// Recent commits on current branch.
pub fn git_log(cwd: &str, limit: usize, skip: u32) -> Result<serde_json::Value> {
    let lim = limit.clamp(1, 50);
    let skip = skip.clamp(0, 10_000);
    let limit_arg = lim.to_string();
    let skip_arg = format!("--skip={skip}");
    let fmt = "--pretty=format:%H%x1f%s%x1f%ar%x1f%an";
    let out = run_git(cwd, &["log", "-n", &limit_arg, &skip_arg, fmt])?;
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
                "author": parts.get(3).copied().unwrap_or(""),
            })
        })
        .collect();
    Ok(serde_json::json!({ "commits": commits }))
}

pub fn git_pull(cwd: &str) -> Result<serde_json::Value> {
    let output = run_git_with_timeout(cwd, &["pull"], GIT_REMOTE_TIMEOUT)?;
    Ok(serde_json::json!({ "output": timed_git_ok(output)?.trim() }))
}

fn git_push_needs_upstream(output: &str) -> bool {
    output.contains("has no upstream branch") || output.contains("--set-upstream")
}

pub fn git_push(cwd: &str) -> Result<serde_json::Value> {
    let output = run_git_with_timeout(cwd, &["push"], GIT_REMOTE_TIMEOUT)?;
    if output.status.success() && !output.timed_out {
        return Ok(serde_json::json!({ "output": combined_output(&output).trim() }));
    }

    let combined = combined_output(&output);
    if !output.timed_out && git_push_needs_upstream(&combined) {
        let branch = run_git(cwd, &["rev-parse", "--abbrev-ref", "HEAD"])?;
        let branch = branch.trim();
        if branch == "HEAD" {
            return Err(HostError::Backend("cannot push from detached HEAD".into()));
        }
        let output = run_git_with_timeout(
            cwd,
            &["push", "--set-upstream", "origin", branch],
            GIT_REMOTE_TIMEOUT,
        )?;
        return Ok(serde_json::json!({ "output": timed_git_ok(output)?.trim() }));
    }

    Err(timed_git_ok(output)
        .err()
        .unwrap_or_else(|| HostError::Backend(combined)))
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

pub fn git_commit_files(cwd: &str, hash: &str) -> Result<serde_json::Value> {
    let hash = require_git_hash(hash)?;
    let parent = format!("{hash}^");
    let out =
        run_git(cwd, &["diff", "--name-status", "-M", "-z", &parent, hash]).or_else(|_| {
            run_git(
                cwd,
                &[
                    "diff-tree",
                    "-r",
                    "--root",
                    "--no-commit-id",
                    "--name-status",
                    "-M",
                    "-z",
                    hash,
                ],
            )
        })?;
    let files: Vec<serde_json::Value> = parse_name_status_z(&out)
        .into_iter()
        .map(|entry| {
            let mut file = serde_json::json!({
                "path": entry.path,
                "status": entry.status,
            });
            if let Some(old_path) = entry.old_path {
                file["old_path"] = serde_json::Value::String(old_path);
            }
            file
        })
        .collect();
    Ok(serde_json::json!({ "files": files }))
}

pub fn git_show_file(cwd: &str, hash: &str, file: &str) -> Result<serde_json::Value> {
    let hash = require_git_hash(hash)?;
    if file.trim().is_empty() {
        return Err(HostError::Backend("empty file path".into()));
    }
    if file.contains('\0') {
        return Err(HostError::Backend("invalid file path".into()));
    }

    let dir = git_dir(cwd)?;
    let spec = format!("{hash}:{file}");
    let output = git_command()
        .args(["show", &spec])
        .current_dir(&dir)
        .output()
        .map_err(|e| HostError::Backend(format!("git spawn failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = if stderr.trim().is_empty() {
            format!("git exited with {}", output.status)
        } else {
            stderr.trim().to_string()
        };
        return Err(HostError::Backend(msg));
    }
    if output.stdout.contains(&0) {
        return Err(HostError::Backend(
            "binary file output is not supported".into(),
        ));
    }
    if output.stdout.len() > 1_572_864 {
        return Err(HostError::Backend(
            "file content exceeds 1.5 MB limit".into(),
        ));
    }
    Ok(serde_json::json!({
        "content": String::from_utf8_lossy(&output.stdout),
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

        let diff = git_diff(&dir.path().to_string_lossy(), Some("app.txt"), None).unwrap();
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

        let diff = git_diff(&dir.path().to_string_lossy(), Some("new.txt"), None).unwrap();
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
    fn parse_name_status_z_handles_rename_records() {
        let entries =
            parse_name_status_z("M\0app.txt\0R100\0old.txt\0new.txt\0C75\0a.txt\0b.txt\0");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "app.txt");
        assert_eq!(entries[0].old_path, None);
        assert_eq!(entries[0].status, "modified");
        assert_eq!(entries[1].path, "new.txt");
        assert_eq!(entries[1].old_path.as_deref(), Some("old.txt"));
        assert_eq!(entries[1].status, "renamed");
        assert_eq!(entries[2].path, "b.txt");
        assert_eq!(entries[2].old_path.as_deref(), Some("a.txt"));
        assert_eq!(entries[2].status, "copied");
    }

    #[test]
    fn git_hash_validation_accepts_and_rejects_expected_values() {
        assert!(is_valid_git_hash("abcd"));
        assert!(is_valid_git_hash(
            "ABCDEF1234567890abcdef1234567890abcdef12"
        ));
        assert!(is_valid_git_hash(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_valid_git_hash("abc"));
        assert!(!is_valid_git_hash(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
        ));
        assert!(!is_valid_git_hash("abcd/ef"));
        assert!(!is_valid_git_hash("abcd..ef"));
        assert!(!is_valid_git_hash("abcd\0ef"));
        assert!(!is_valid_git_hash("-abcd"));
    }

    #[test]
    fn git_push_no_upstream_detection_matches_git_stderr() {
        assert!(git_push_needs_upstream(
            "fatal: The current branch feature has no upstream branch."
        ));
        assert!(git_push_needs_upstream(
            "To push the current branch and set the remote as upstream, use\n\n    git push --set-upstream origin feature"
        ));
        assert!(!git_push_needs_upstream("fatal: Authentication failed"));
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
