//! Self-update for the host agent.
//!
//! Downloads the matching pre-built `pocketshell` binary from GitHub
//! Releases, verifies its SHA-256, and atomically replaces the on-disk
//! binary. Mirrors `website/public/install.sh` so users get the same
//! release artifacts whether they install fresh or upgrade.
//!
//! Asset layout (standard GitHub Releases):
//!
//! ```text
//! <base_url>/releases/latest                                            # 302 → /releases/tag/vX.Y.Z
//! <base_url>/releases/download/<tag>/pocketshell-<tag>-<triple>.tar.gz
//! <base_url>/releases/download/<tag>/pocketshell-<tag>-<triple>.tar.gz.sha256
//! ```
//!
//! `<base_url>` is the GitHub repo URL — forks/mirrors can point
//! `POCKETSHELL_BASE_URL` at their own repo and the same logic works.

use crate::error::{HostError, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tracing::{info, warn};

/// Default release host. The public host-agent repo on GitHub — assets are
/// served as standard release downloads, no auth required.
pub const DEFAULT_BASE_URL: &str = "https://github.com/yashagldit/PocketShell";

/// Result of an update check — everything the caller needs to either show a
/// "you're up to date" message or proceed with [`download_and_install`].
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub current_version: String,
    /// Tag form (`vX.Y.Z`) — matches what the GitHub release is published under.
    pub target_version: String,
    /// Triple like `aarch64-apple-darwin` — must match the release artifact suffix.
    pub target_triple: String,
    /// `pocketshell-vX.Y.Z-<triple>.tar.gz`
    pub archive_name: String,
    /// Direct URL to the tarball on GitHub releases.
    pub download_url: String,
    /// Sibling `.sha256` URL on GitHub releases.
    pub checksum_url: String,
    /// True iff `current_version == target_version` (after stripping leading `v`).
    pub up_to_date: bool,
}

/// Detect the release-target triple matching this host. Mirrors the
/// `case "$os_kind/$arch_kind"` block in `install.sh`.
pub fn detect_target() -> Result<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let target = match (os, arch) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "x86_64") => {
            if is_musl() {
                "x86_64-unknown-linux-musl"
            } else {
                "x86_64-unknown-linux-gnu"
            }
        }
        _ => {
            return Err(HostError::Config(format!(
                "no prebuilt binary for {os}/{arch}"
            )))
        }
    };
    Ok(target.to_string())
}

/// Heuristic mirror of install.sh's musl detection. Only meaningful on Linux.
fn is_musl() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    Path::new("/lib/ld-musl-x86_64.so.1").exists()
        || Path::new("/lib/ld-musl-aarch64.so.1").exists()
        || Path::new("/etc/alpine-release").exists()
}

/// Resolve the latest release tag by following GitHub's `/releases/latest`
/// redirect. The final URL is `<base>/releases/tag/vX.Y.Z`; the tag is the
/// last path segment. No GitHub API call (anonymous quota would be a
/// problem for noisy update checks), no JSON parsing.
pub async fn resolve_latest_tag(base_url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| HostError::Config(format!("build http client: {e}")))?;

    let url = format!("{}/releases/latest", base_url.trim_end_matches('/'));
    let resp = client
        .head(&url)
        .send()
        .await
        .map_err(|e| HostError::Config(format!("fetch {url}: {e}")))?
        .error_for_status()
        .map_err(|e| HostError::Config(format!("fetch {url}: {e}")))?;

    let final_url = resp.url().clone();
    let tag = final_url
        .path()
        .rsplit('/')
        .find(|seg| !seg.is_empty())
        .unwrap_or("");
    if tag.is_empty() || tag == "latest" {
        return Err(HostError::Config(format!(
            "could not parse release tag from {final_url} — is {base_url} a GitHub repo with a published release?"
        )));
    }
    Ok(tag.to_string())
}

fn build_urls(base_url: &str, tag: &str, target: &str) -> (String, String, String) {
    let base = base_url.trim_end_matches('/');
    let archive = format!("pocketshell-{tag}-{target}.tar.gz");
    let dl = format!("{base}/releases/download/{tag}/{archive}");
    let sha = format!("{dl}.sha256");
    (archive, dl, sha)
}

fn normalize(v: &str) -> &str {
    v.trim_start_matches('v')
}

/// Resolve target version + URLs without downloading anything. Pass
/// `requested_version=None` to fall back on `<base_url>/releases/latest`.
pub async fn check(
    base_url: &str,
    current_version: &str,
    requested_version: Option<&str>,
) -> Result<UpdateInfo> {
    let target_version = match requested_version {
        Some(v) if !v.trim().is_empty() => {
            // Accept either `0.1.0` or `v0.1.0`; canonicalize to the tag form
            // because the artifact filenames embed the tag verbatim.
            let v = v.trim();
            if v.starts_with('v') {
                v.to_string()
            } else {
                format!("v{v}")
            }
        }
        _ => resolve_latest_tag(base_url).await?,
    };
    let target_triple = detect_target()?;
    let (archive_name, download_url, checksum_url) =
        build_urls(base_url, &target_version, &target_triple);
    let up_to_date = normalize(&target_version) == normalize(current_version);
    Ok(UpdateInfo {
        current_version: current_version.to_string(),
        target_version,
        target_triple,
        archive_name,
        download_url,
        checksum_url,
        up_to_date,
    })
}

/// Download the archive + checksum, verify SHA-256, extract the binary, and
/// atomically replace the currently-running binary on disk.
///
/// Returns the absolute path of the installed binary. The previous binary is
/// preserved at `<binary>.old` so an admin can roll back manually.
pub async fn download_and_install(info: &UpdateInfo) -> Result<PathBuf> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| HostError::Config(format!("build http client: {e}")))?;

    info!("downloading {}", info.download_url);
    let archive_bytes = client
        .get(&info.download_url)
        .send()
        .await
        .map_err(|e| HostError::Config(format!("download archive: {e}")))?
        .error_for_status()
        .map_err(|e| HostError::Config(format!("download archive: {e}")))?
        .bytes()
        .await
        .map_err(|e| HostError::Config(format!("read archive body: {e}")))?;

    let sha_text = client
        .get(&info.checksum_url)
        .send()
        .await
        .map_err(|e| HostError::Config(format!("download checksum: {e}")))?
        .error_for_status()
        .map_err(|e| HostError::Config(format!("download checksum: {e}")))?
        .text()
        .await
        .map_err(|e| HostError::Config(format!("read checksum body: {e}")))?;

    info!("verifying sha-256");
    let expected = parse_sha256_line(&sha_text, &info.archive_name)?;
    let actual = {
        let mut h = Sha256::new();
        h.update(&archive_bytes);
        format!("{:x}", h.finalize())
    };
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err(HostError::Config(format!(
            "checksum mismatch — refusing to install (expected {expected}, got {actual})"
        )));
    }

    // Stage inside the install dir so the final `rename` is on the same
    // filesystem (rename across filesystems would EXDEV).
    let current_exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| HostError::Config(format!("resolve current exe: {e}")))?;
    let install_dir = current_exe
        .parent()
        .ok_or_else(|| HostError::Config("current exe has no parent dir".into()))?
        .to_path_buf();
    let staging = install_dir.join(format!(".pocketshell-update-{}", std::process::id()));
    fs::create_dir_all(&staging).map_err(|e| {
        HostError::Config(format!(
            "create staging dir {} (need write access to install dir): {e}",
            staging.display()
        ))
    })?;
    let _cleanup = StagingGuard(staging.clone());

    let archive_path = staging.join(&info.archive_name);
    fs::write(&archive_path, &archive_bytes)
        .map_err(|e| HostError::Config(format!("write archive: {e}")))?;

    info!("extracting {}", info.archive_name);
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&staging)
        .status()
        .map_err(|e| HostError::Config(format!("spawn tar: {e}")))?;
    if !status.success() {
        return Err(HostError::Config("tar extraction failed".into()));
    }

    let new_binary = staging.join("pocketshell");
    if !new_binary.exists() {
        return Err(HostError::Config(
            "tarball did not contain a `pocketshell` binary".into(),
        ));
    }

    // Atomically replace the on-disk binary. On Linux/macOS, `rename` over
    // a running executable is safe: the kernel keeps the old inode alive
    // for the duration of any process that already mapped it.
    let backup_path = with_old_suffix(&current_exe);
    let _ = fs::remove_file(&backup_path);
    fs::rename(&current_exe, &backup_path).map_err(|e| {
        HostError::Config(format!(
            "back up current binary to {}: {e}",
            backup_path.display(),
        ))
    })?;

    if let Err(e) = fs::rename(&new_binary, &current_exe) {
        // Roll back so the user isn't left without a working `pocketshell`.
        let _ = fs::rename(&backup_path, &current_exe);
        return Err(HostError::Config(format!(
            "install new binary to {}: {e}",
            current_exe.display(),
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&current_exe)
            .map_err(|e| HostError::Config(format!("stat new binary: {e}")))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&current_exe, perms)
            .map_err(|e| HostError::Config(format!("chmod new binary: {e}")))?;
    }

    // tar-extracted binaries on macOS can inherit the quarantine xattr.
    // Strip it so the next exec doesn't get blocked by Gatekeeper, mirroring
    // the same step in install.sh. Best-effort.
    if cfg!(target_os = "macos") {
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&current_exe)
            .status();
    }

    info!(
        "installed pocketshell {} → {}",
        info.target_version,
        current_exe.display()
    );
    info!("previous binary saved at {}", backup_path.display());
    Ok(current_exe)
}

/// `current_exe.with_extension("old")` would mangle `pocketshell` into
/// `pocketshell.old` (correct), but on Windows-style paths with extensions
/// it would replace the extension. Keep both: `pocketshell` → `pocketshell.old`,
/// `pocketshell.exe` → `pocketshell.exe.old`.
fn with_old_suffix(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".old");
    PathBuf::from(s)
}

/// Cleans up the staging dir even on early-return / panic.
struct StagingGuard(PathBuf);
impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            warn!("failed to clean up staging dir {}: {e}", self.0.display());
        }
    }
}

/// `.sha256` files from our release pipeline look like:
///   `<hex>  <archive_name>\n`
/// Pull out the hex digest matching the expected archive name. Tolerates a
/// bare digest (no filename) for forward-compatibility with checksum tools
/// that emit only the hash.
fn parse_sha256_line(text: &str, archive_name: &str) -> Result<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex = parts.next().unwrap_or("").trim();
        // The leading `*` is the binary-mode marker emitted by some sha256
        // implementations (`sha256sum -b`).
        let file = parts.next().unwrap_or("").trim().trim_start_matches('*');
        if hex.is_empty() {
            continue;
        }
        if file.is_empty() || file == archive_name {
            return Ok(hex.to_string());
        }
    }
    Err(HostError::Config(format!(
        "no sha-256 entry found for {archive_name}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha256_accepts_standard_format() {
        let text = "abc123  pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz\n";
        let h = parse_sha256_line(text, "pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz").unwrap();
        assert_eq!(h, "abc123");
    }

    #[test]
    fn parse_sha256_accepts_binary_mode_marker() {
        let text = "abc123 *pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz\n";
        let h = parse_sha256_line(text, "pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz").unwrap();
        assert_eq!(h, "abc123");
    }

    #[test]
    fn parse_sha256_accepts_bare_digest() {
        let text = "deadbeef\n";
        let h = parse_sha256_line(text, "anything.tar.gz").unwrap();
        assert_eq!(h, "deadbeef");
    }

    #[test]
    fn parse_sha256_skips_comments_and_blanks() {
        let text = "\n# comment\nabc  archive.tar.gz\n";
        let h = parse_sha256_line(text, "archive.tar.gz").unwrap();
        assert_eq!(h, "abc");
    }

    #[test]
    fn parse_sha256_errors_when_filename_does_not_match() {
        let text = "abc  other.tar.gz\n";
        let err = parse_sha256_line(text, "wanted.tar.gz").err().unwrap();
        assert!(err.to_string().contains("no sha-256 entry"));
    }

    #[test]
    fn detect_target_returns_known_release_triple() {
        // Sanity-check we got one of the triples the release matrix actually ships.
        let t = detect_target().unwrap();
        assert!(
            matches!(
                t.as_str(),
                "aarch64-apple-darwin"
                    | "x86_64-apple-darwin"
                    | "aarch64-unknown-linux-gnu"
                    | "x86_64-unknown-linux-gnu"
                    | "x86_64-unknown-linux-musl"
            ),
            "unexpected target triple: {t}"
        );
    }

    #[test]
    fn build_urls_produces_expected_paths() {
        let (archive, dl, sha) = build_urls(
            "https://github.com/yashagldit/PocketShell",
            "v0.1.0",
            "aarch64-apple-darwin",
        );
        assert_eq!(archive, "pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            dl,
            "https://github.com/yashagldit/PocketShell/releases/download/v0.1.0/pocketshell-v0.1.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(sha, format!("{dl}.sha256"));
    }

    #[test]
    fn build_urls_tolerates_trailing_slash_on_base() {
        // Operator-friendly: don't double-slash if someone configures the
        // base with a trailing /.
        let (_, dl, _) = build_urls(
            "https://github.com/yashagldit/PocketShell/",
            "v0.1.0",
            "x86_64-unknown-linux-gnu",
        );
        assert_eq!(
            dl,
            "https://github.com/yashagldit/PocketShell/releases/download/v0.1.0/pocketshell-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn check_treats_v_prefix_and_bare_version_as_equivalent() {
        // Caller may pass a version with or without `v`; `target_version`
        // must canonicalize to the tag form, but `up_to_date` must compare
        // numerically (i.e. "v0.1.0" == "0.1.0").
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let info = rt
            .block_on(check("https://example.test/r", "0.1.0", Some("0.1.0")))
            .unwrap();
        assert_eq!(info.target_version, "v0.1.0");
        assert!(info.up_to_date);

        let info2 = rt
            .block_on(check("https://example.test/r", "0.1.0", Some("v0.1.0")))
            .unwrap();
        assert_eq!(info2.target_version, "v0.1.0");
        assert!(info2.up_to_date);

        let info3 = rt
            .block_on(check("https://example.test/r", "0.1.0", Some("0.2.0")))
            .unwrap();
        assert!(!info3.up_to_date);
    }

    #[test]
    fn with_old_suffix_appends_dot_old() {
        assert_eq!(
            with_old_suffix(Path::new("/usr/local/bin/pocketshell")),
            PathBuf::from("/usr/local/bin/pocketshell.old")
        );
        assert_eq!(
            with_old_suffix(Path::new("/opt/pocketshell.exe")),
            PathBuf::from("/opt/pocketshell.exe.old")
        );
    }
}
