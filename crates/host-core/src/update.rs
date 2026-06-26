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

/// Apple Team ID stamped on every released macOS binary by the codesign step
/// in `.github/workflows/release-host-agent.yml`. Not a secret — visible via
/// `codesign -dv` on any shipped binary — so it lives in source rather than
/// as a build-time env var. If the Apple Developer account ever rotates and
/// produces a new Team ID, bump this constant in the same commit as the new
/// signing cert and ship a release; older clients will reject the new binary
/// until they pull the constant update via some out-of-band path (re-pair,
/// manual install). That's a feature, not a bug: it forces a deliberate
/// rotation event instead of silently accepting a foreign signer.
const EXPECTED_APPLE_TEAM_ID: &str = "UKH6DFA3B9";

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
    /// Sibling `.cosign-bundle.json` URL on GitHub releases — Sigstore keyless
    /// signature produced by `.github/workflows/release-host-agent.yml`. Empty
    /// for releases predating the cosign rollout.
    pub cosign_bundle_url: String,
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
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
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

fn build_urls(base_url: &str, tag: &str, target: &str) -> (String, String, String, String) {
    let base = base_url.trim_end_matches('/');
    let archive = format!("pocketshell-{tag}-{target}.tar.gz");
    let dl = format!("{base}/releases/download/{tag}/{archive}");
    let sha = format!("{dl}.sha256");
    let bundle = format!("{dl}.cosign-bundle.json");
    (archive, dl, sha, bundle)
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
    let (archive_name, download_url, checksum_url, cosign_bundle_url) =
        build_urls(base_url, &target_version, &target_triple);
    let up_to_date = normalize(&target_version) == normalize(current_version);
    Ok(UpdateInfo {
        current_version: current_version.to_string(),
        target_version,
        target_triple,
        archive_name,
        download_url,
        checksum_url,
        cosign_bundle_url,
        up_to_date,
    })
}

/// Knobs the caller (CLI) can flip to relax authenticity checks. Every
/// non-default value here weakens the security posture; the corresponding CLI
/// flag must surface that to the user.
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Skip cosign keyless verification of the downloaded artifact. Only
    /// honored when the user explicitly passes `--insecure-skip-verify` (or
    /// equivalent). The SHA-256 + macOS codesign checks still run.
    pub skip_cosign: bool,
}

/// Download the archive + checksum + cosign bundle, verify SHA-256 and the
/// cosign keyless signature against our pinned workflow identity, then
/// atomically replace the currently-running binary on disk.
///
/// Returns the absolute path of the installed binary. The previous binary is
/// preserved at `<binary>.old` so an admin can roll back manually.
pub async fn download_and_install(info: &UpdateInfo) -> Result<PathBuf> {
    download_and_install_with(info, &InstallOptions::default()).await
}

/// Same as [`download_and_install`] but with explicit option control.
pub async fn download_and_install_with(
    info: &UpdateInfo,
    opts: &InstallOptions,
) -> Result<PathBuf> {
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

    // Cosign keyless verification. The SHA-256 above proves the bytes match
    // what the release origin served — same origin, same trust. The cosign
    // signature is pinned to a specific GitHub workflow identity (the
    // release-host-agent.yml in this repo), so it proves the bytes were
    // produced by *that* workflow run. An attacker who owns GitHub Releases
    // publishing alone can no longer push a malicious update — they'd also
    // need an OIDC token from a workflow at this exact path.
    if opts.skip_cosign {
        warn!(
            "--insecure-skip-verify in effect: cosign keyless verification SKIPPED for {}. \
             Only the SHA-256 (same-origin as the artifact) was checked. \
             Do not use this flag against an untrusted release.",
            info.archive_name
        );
    } else if !cosign_available() {
        // Cosign not installed on this host. Rather than block the update,
        // continue with SHA-256 + (on macOS) codesign as the trust anchors and
        // surface a loud warning. The user can install cosign to re-enable
        // keyless-signature verification on subsequent updates.
        warn!(
            "cosign not installed on PATH — skipping keyless signature verification for {}. \
             SHA-256 (same-origin as the artifact){} was still checked. \
             Install cosign (`brew install cosign`, `apt install cosign`, or \
             https://github.com/sigstore/cosign/releases) to re-enable signature \
             verification on future updates.",
            info.archive_name,
            if cfg!(target_os = "macos") {
                " and Apple codesign"
            } else {
                ""
            }
        );
    } else {
        let bundle_path = staging.join(format!("{}.cosign-bundle.json", info.archive_name));
        let bundle_text = client
            .get(&info.cosign_bundle_url)
            .send()
            .await
            .map_err(|e| HostError::Config(format!("download cosign bundle: {e}")))?
            .error_for_status()
            .map_err(|e| {
                HostError::Config(format!(
                    "download cosign bundle from {}: {e} — release may predate the cosign \
                     rollout. Pass --insecure-skip-verify only if you have manually verified \
                     the SHA-256 out of band.",
                    info.cosign_bundle_url
                ))
            })?
            .text()
            .await
            .map_err(|e| HostError::Config(format!("read cosign bundle body: {e}")))?;
        fs::write(&bundle_path, bundle_text.as_bytes())
            .map_err(|e| HostError::Config(format!("write cosign bundle: {e}")))?;
        verify_cosign_bundle(&archive_path, &bundle_path)?;
    }

    info!("extracting {}", info.archive_name);
    let mut command = Command::new("tar");
    crate::platform::hide_command_window(&mut command);
    let status = command
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&staging)
        .status()
        .map_err(|e| HostError::Config(format!("spawn tar: {e}")))?;
    if !status.success() {
        return Err(HostError::Config("tar extraction failed".into()));
    }

    // The release tarball carries `pocketshell.exe` on Windows, `pocketshell`
    // everywhere else — matching the binary name cargo produces per target.
    let bin_name = if cfg!(windows) {
        "pocketshell.exe"
    } else {
        "pocketshell"
    };
    let new_binary = staging.join(bin_name);
    if !new_binary.exists() {
        return Err(HostError::Config(format!(
            "tarball did not contain a `{bin_name}` binary"
        )));
    }

    // On macOS, verify the new binary carries our Developer ID code signature
    // before we swap it in. The SHA-256 above only proves the bytes match what
    // was served from the release origin — same origin can publish both the
    // tarball and its checksum, so it's integrity, not authenticity. A valid
    // codesign chain anchored to Apple + our Team ID is authenticity: an
    // attacker who pushes a malicious release would have to steal our Apple
    // Developer ID cert in addition to the release publishing flow.
    if let Err(e) = verify_macos_codesign(&new_binary) {
        return Err(HostError::Config(format!(
            "refusing to install: codesign verification failed for {}: {e}",
            new_binary.display()
        )));
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
        let mut command = Command::new("xattr");
        crate::platform::hide_command_window(&mut command);
        let _ = command
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

/// Sigstore keyless certificate identity that our release workflow produces.
/// Matches `https://github.com/<owner>/<repo>/.github/workflows/release-host-agent.yml@refs/tags/v...`
/// for any version tag. Anchored with `^` and `$` so a workflow at a similar
/// path (e.g. a fork's `release-host-agent-test.yml`) cannot satisfy this.
const COSIGN_IDENTITY_REGEXP: &str = concat!(
    "^https://github\\.com/yashagldit/PocketShell/",
    "\\.github/workflows/release-host-agent\\.yml@refs/tags/v[0-9][0-9A-Za-z.\\-]*$",
);

/// The OIDC issuer GitHub Actions uses to mint tokens for the workflow's
/// keyless signing flow. This is the same string the cosign-installer action
/// expects on the signing side; if either rotates the verify will fail loudly.
const COSIGN_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Probe whether `cosign` is invokable on PATH. Used to decide between
/// running a real signature verification and falling back to the SHA-256 +
/// codesign trust anchors with a loud warning. We deliberately don't try to
/// auto-install cosign — silently fetching another binary to verify this
/// binary expands the trust surface in a non-obvious way.
fn cosign_available() -> bool {
    let mut command = Command::new("cosign");
    crate::platform::hide_command_window(&mut command);
    command
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Shell out to `cosign verify-blob` to check the keyless signature bundle
/// produced by our release workflow. We require the cosign binary to be
/// installed on the host — there is no usable production-grade Rust verifier
/// in May 2026 (sigstore-rs is marked experimental; sigstore-verification was
/// archived 2026-05-18). When sigstore-rs stabilizes, replace this with an
/// in-process verifier and a baked-in TUF trust root.
fn verify_cosign_bundle(artifact: &Path, bundle: &Path) -> Result<()> {
    let mut command = Command::new("cosign");
    crate::platform::hide_command_window(&mut command);
    let output = command
        .args(["verify-blob", "--new-bundle-format", "--bundle"])
        .arg(bundle)
        .args(["--certificate-identity-regexp", COSIGN_IDENTITY_REGEXP])
        .args(["--certificate-oidc-issuer", COSIGN_OIDC_ISSUER])
        .arg(artifact)
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostError::Config(
                "cosign is not installed on PATH — required to verify the release signature. \
                 Install it (`brew install cosign`, `apt install cosign`, or download from \
                 https://github.com/sigstore/cosign/releases) and re-run, or pass \
                 --insecure-skip-verify if you have manually verified the artifact out of band."
                    .to_string(),
            ));
        }
        Err(e) => {
            return Err(HostError::Config(format!("spawn cosign: {e}")));
        }
    };
    if output.status.success() {
        info!("cosign verified (identity pinned to release workflow)");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(HostError::Config(format!(
        "cosign verify-blob rejected the release artifact — refusing to install. \
         Identity required: {COSIGN_IDENTITY_REGEXP}. cosign stderr: {stderr}"
    )))
}

/// Build the `codesign` designated-requirement clause that proves a binary
/// was signed by us:
///   * `anchor apple generic` — chain ultimately rooted in Apple
///   * intermediate `1.2.840.113635.100.6.2.6` — Developer ID CA
///   * leaf `1.2.840.113635.100.6.1.13` — Developer ID Application cert
///   * leaf subject OU equals our Team ID
fn developer_id_requirement(team_id: &str) -> String {
    format!(
        "anchor apple generic \
         and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{team_id}\""
    )
}

/// Verify a downloaded binary carries our Apple Developer ID signature before
/// we let it replace the on-disk binary. No-op on non-macOS targets — the
/// Sigstore cosign verify (TODO) will cover Linux + macOS uniformly later.
fn verify_macos_codesign(binary: &Path) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    // codesign's `-R requirement` (two args) is a sign-time option; the
    // verify form requires the equals-sign syntax `-R=<requirement>` as a
    // single argv entry. Easy to get wrong — see `man codesign`.
    let req_arg = format!("-R={}", developer_id_requirement(EXPECTED_APPLE_TEAM_ID));
    let mut command = Command::new("codesign");
    crate::platform::hide_command_window(&mut command);
    let output = command
        .args(["--verify", "--strict"])
        .arg(&req_arg)
        .arg(binary)
        .output()
        .map_err(|e| HostError::Config(format!("spawn codesign: {e}")))?;
    if output.status.success() {
        info!("codesign verified (Team ID {EXPECTED_APPLE_TEAM_ID})");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(HostError::Config(format!(
        "codesign --verify rejected binary (Team ID {EXPECTED_APPLE_TEAM_ID}): {stderr}"
    )))
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
                    | "x86_64-pc-windows-msvc"
            ),
            "unexpected target triple: {t}"
        );
    }

    #[test]
    fn build_urls_produces_expected_paths() {
        let (archive, dl, sha, bundle) = build_urls(
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
        assert_eq!(bundle, format!("{dl}.cosign-bundle.json"));
    }

    #[test]
    fn build_urls_tolerates_trailing_slash_on_base() {
        // Operator-friendly: don't double-slash if someone configures the
        // base with a trailing /.
        let (_, dl, _, _) = build_urls(
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

    #[test]
    fn developer_id_requirement_pins_team_id_and_apple_anchor() {
        let req = developer_id_requirement("ABCDE12345");
        // Pin the exact requirement clause: changing any of these tokens is a
        // semantic change to what "we signed this" means, and should require
        // an explicit test update — not a silent edit.
        assert!(req.contains("anchor apple generic"));
        assert!(req.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
        assert!(req.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert!(req.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
    }

    #[test]
    fn verify_macos_codesign_is_noop_on_non_macos() {
        // Off-platform the verify must short-circuit so Linux/Windows builds
        // of `pocketshell update` don't try to spawn a non-existent `codesign`.
        // We can't assert codesign behavior portably on macOS in unit tests
        // because it depends on a properly-signed binary at the given path.
        #[cfg(not(target_os = "macos"))]
        verify_macos_codesign(Path::new("/nonexistent")).unwrap();
    }

    #[test]
    fn cosign_identity_regexp_anchors_and_matches_expected_workflow_path() {
        // Pin the exact shape of the certificate-identity-regexp so a typo in
        // the workflow path (e.g. renaming release-host-agent.yml) is caught
        // here, not at update time on every user's machine.
        assert!(COSIGN_IDENTITY_REGEXP.starts_with("^https://github\\.com/"));
        assert!(COSIGN_IDENTITY_REGEXP.ends_with("$"));
        assert!(COSIGN_IDENTITY_REGEXP.contains("yashagldit/PocketShell"));
        assert!(COSIGN_IDENTITY_REGEXP.contains("release-host-agent\\.yml"));
        assert!(COSIGN_IDENTITY_REGEXP.contains("refs/tags/v"));

        let re = regex::Regex::new(COSIGN_IDENTITY_REGEXP).expect("regexp must compile");
        assert!(re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent.yml@refs/tags/v0.1.0"
        ));
        assert!(re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent.yml@refs/tags/v1.2.3-beta.4"
        ));
        // Negatives that must NOT satisfy the pin:
        assert!(!re.is_match(
            "https://github.com/somebodyelse/PocketShell/.github/workflows/release-host-agent.yml@refs/tags/v0.1.0"
        ));
        assert!(!re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent.yml@refs/heads/main"
        ));
        assert!(!re.is_match(
            "https://github.com/yashagldit/PocketShell/.github/workflows/release-host-agent-test.yml@refs/tags/v0.1.0"
        ));
    }

    #[test]
    fn cosign_oidc_issuer_is_github_actions_token_endpoint() {
        // Anchored to GitHub Actions' OIDC issuer URL. If GitHub ever rotates
        // this we'll hit a runtime verify failure; pin it here so the symptom
        // is a failing unit test instead of users getting broken updates.
        assert_eq!(
            COSIGN_OIDC_ISSUER,
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn expected_team_id_is_set_and_well_formed() {
        // 10-char alphanumeric Team ID, per Apple's account format. If this
        // changes the codesign requirement clause changes too — the test
        // catches accidental edits that would break authenticity on update.
        assert_eq!(EXPECTED_APPLE_TEAM_ID.len(), 10);
        assert!(EXPECTED_APPLE_TEAM_ID
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_macos_codesign_rejects_unsigned_file() {
        // Live invocation of `codesign --verify` against a known-bad file.
        // Catches regressions in the requirement-clause syntax that wouldn't
        // surface in the string-builder test (e.g. forgetting the `-R=` form
        // vs. `-R ` two-arg form, which means very different things).
        let dir = tempfile::tempdir().unwrap();
        let unsigned = dir.path().join("not-a-macho");
        std::fs::write(&unsigned, b"definitely not a signed Mach-O").unwrap();
        let err = verify_macos_codesign(&unsigned).unwrap_err();
        // We don't pin the exact codesign stderr — Apple has changed wording
        // across macOS releases. We just need confirmation we hit the verify
        // path, not the spawn-failed path.
        assert!(
            err.to_string().contains("codesign --verify rejected"),
            "expected verify-rejection error, got: {err}"
        );
    }
}
