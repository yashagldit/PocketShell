use crate::config::AppConfig;
use crate::error::{HostError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

/// Refuse to start the daemon if it's running with root privileges.
///
/// Rationale: the daemon's file channel grants any approved mobile peer
/// read/write access to the host's filesystem, scoped by a home-relative +
/// system-path denylist (see `files.rs`). Both layers assume the daemon
/// runs as the human user, so root effectively bypasses the user-scope
/// model — a single device approval becomes "approved to read /etc/shadow
/// and write /root/.ssh/authorized_keys".
///
/// Escape hatch: setting `POCKETSHELL_ALLOW_ROOT=1` skips the check for
/// the rare legitimate case (e.g. a kiosk box that has no non-root user).
/// We log a warning so it shows up in audit reviews.
#[cfg(unix)]
pub(super) fn refuse_if_root() -> Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        if std::env::var("POCKETSHELL_ALLOW_ROOT").as_deref() == Ok("1") {
            warn!(
                "daemon is running as root because POCKETSHELL_ALLOW_ROOT=1 is set; \
                 file-channel callers can reach the entire filesystem subject only to \
                 the static denylist — strongly prefer running as a non-root user"
            );
            return Ok(());
        }
        return Err(HostError::Backend(
            "refusing to run as root: the file channel relies on user-scope to bound \
             filesystem access. Re-run as your normal user (e.g. via `systemctl --user`), \
             or set POCKETSHELL_ALLOW_ROOT=1 if you have an explicit reason."
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn refuse_if_root() -> Result<()> {
    // Non-Unix targets don't have a euid concept the same way; the file
    // channel's risk profile is also different (Windows ACLs etc.). No-op.
    Ok(())
}

/// RAII flock on `paths.pid_file` so a second `daemon run` fails fast
/// instead of racing on the local-attach socket.
pub(super) struct DaemonPidLock {
    _file: File,
    path: PathBuf,
}

impl Drop for DaemonPidLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(super) fn acquire_daemon_pid_lock() -> Result<DaemonPidLock> {
    let paths = AppConfig::paths()?;
    if !paths.state_dir.exists() {
        std::fs::create_dir_all(&paths.state_dir)?;
    }
    let pid_path = paths.pid_file.clone();
    // Held mutably so the pid stamp below can write through this SAME handle
    // (avoids a try_clone() that would sit outside the per-handle lock on
    // Windows, where fs2 uses LockFileEx).
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&pid_path)?;

    // Non-blocking exclusive lock; if another daemon already holds it, fail
    // fast rather than racing on the local-attach socket. Released when the
    // handle inside the returned guard drops.
    if let Err(err) = crate::platform::try_lock_exclusive(&file) {
        return Err(HostError::Config(format!(
            "another pocketshell daemon is running (pid file {}): {}",
            pid_path.display(),
            err
        )));
    }

    // Stamp our pid so external tools (`daemon stop`, status checks) see the
    // live owner. Write through the SAME handle we locked: on Windows fs2 uses
    // LockFileEx, whose lock is per-handle, so a `try_clone()`d handle's writes
    // would sit outside the lock. Reusing `file` keeps lock + write on one
    // handle on every platform.
    let pid = std::process::id().to_string();
    {
        file.set_len(0)
            .map_err(|e| HostError::Config(format!("truncate pid_file: {e}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| HostError::Config(format!("seek pid_file: {e}")))?;
        file.write_all(pid.as_bytes())
            .map_err(|e| HostError::Config(format!("write pid_file: {e}")))?;
    }

    Ok(DaemonPidLock {
        _file: file,
        path: pid_path,
    })
}

/// Final step of `host_restart_agent`: terminate this process so the host
/// comes back up fresh.
///
/// `service::restart()` looks like a one-shot "restart everything for me"
/// call but has three exits with very different semantics, and getting any
/// of them wrong leaves the daemon in a hollow state — `close_all_active_sessions`
/// has already killed every PTY, dropped every WebRTC peer, aborted every
/// agent pump, and marked every backend session `Ended`. If we don't
/// actually die after that, the mobile UI shows "restart requested" but the
/// host is a zombie until somebody SSHes in.
///
/// - `Ok(RestartedService)` is effectively unreachable in practice:
///   `systemctl restart` / `launchctl kickstart -k` send SIGTERM to *us*
///   while we're awaiting the subprocess, so we'd be dead before observing
///   the return. We still `exit(0)` here as belt-and-suspenders against
///   any platform where the subprocess returns before signaling us.
/// - `Ok(StartedDaemon)` means a detached replacement has been forked;
///   exit so it can take over the daemon socket and the backend WS.
/// - `Err(_)` means none of the restart paths worked. Exiting non-zero
///   lets a `Restart=always` supervisor (the systemd units our installers
///   write all set this) respawn us. On unmanaged hosts the daemon dies
///   and needs a manual start, but that's strictly better than leaving a
///   hollowed-out process serving stale state.
pub(super) fn exit_for_restart(result: Result<crate::service::RestartStatus>) -> ! {
    match result {
        Ok(crate::service::RestartStatus::RestartedService) => std::process::exit(0),
        Ok(crate::service::RestartStatus::StartedDaemon) => std::process::exit(0),
        Err(err) => {
            warn!(
                "host_restart_agent failed: {} — exiting to let supervisor relaunch",
                err
            );
            std::process::exit(1);
        }
    }
}

/// Single-flight guard for self-update. The install (download → atomic binary
/// swap, see `update::download_and_install`) stages into a per-PID directory
/// and renames over the running executable; two concurrent installs in the same
/// process would race that swap and could leave a partial/absent binary. The
/// old code awaited the install inline on the daemon's main loop, which
/// serialized it for free; now that both the stats and control channels spawn it
/// as a detached task, this flag restores the one-at-a-time invariant.
pub(super) static UPDATE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Acquire [`UPDATE_IN_FLIGHT`] and spawn the install on success. Returns
/// `false` (without spawning) if an update is already running, so callers can
/// reject the duplicate. On a *successful* install the spawned task never
/// returns (it `exit_for_restart`s); on failure / already-up-to-date it releases
/// the guard so a later update can be attempted. Origin and version are pinned
/// to the latest signed build from our own repo — never taken from the message.
pub(super) fn try_spawn_self_update(current_version: String) -> bool {
    if UPDATE_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return false;
    }
    tokio::spawn(async move {
        if install_agent_update(
            current_version,
            crate::update::DEFAULT_BASE_URL.to_string(),
            None,
        )
        .await
        {
            exit_for_restart(crate::service::restart());
        }
        // Install failed or already up to date — release so a future request
        // can retry. (On success the line above never returns.)
        UPDATE_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
    true
}

pub(super) async fn install_agent_update(
    current_version: String,
    base_url: String,
    requested_version: Option<String>,
) -> bool {
    let info = match crate::update::check(&base_url, &current_version, requested_version.as_deref())
        .await
    {
        Ok(info) => info,
        Err(err) => {
            warn!("host_update_agent check failed: {}", err);
            return false;
        }
    };

    if info.up_to_date {
        info!(
            "host_update_agent: already up to date at {}",
            info.current_version
        );
        return false;
    }

    match crate::update::download_and_install(&info).await {
        Ok(installed) => {
            info!(
                "host_update_agent installed {} at {}; restarting",
                info.target_version,
                installed.display()
            );
            true
        }
        Err(err) => {
            warn!("host_update_agent install failed: {}", err);
            false
        }
    }
}

pub(super) fn version_gte(current: &str, required: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|v| v.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };

    let a = parse(current);
    let b = parse(required);
    let len = a.len().max(b.len());

    for i in 0..len {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        if av > bv {
            return true;
        }
        if av < bv {
            return false;
        }
    }

    true
}
