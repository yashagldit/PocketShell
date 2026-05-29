//! Cross-platform shims for the handful of OS primitives the agent needs but
//! `std` doesn't expose portably: advisory file locks and a "running as the
//! superuser" check.
//!
//! On Unix these map onto `flock(2)` / `geteuid(2)` (via the `fs2` and `nix`
//! crates). On Windows `fs2` uses `LockFileEx`; the elevation check has no
//! direct analogue that matters for our threat model, so it returns `false`
//! (see [`is_root`]).
//!
//! Everything that previously called `nix` directly for these jobs now goes
//! through here so the rest of the crate stays platform-agnostic and `nix`
//! can be a `cfg(unix)`-only dependency.

use std::fs::File;
use std::io;

/// Take an exclusive advisory lock on `file`, blocking until it's available.
///
/// The lock is released when the underlying `File` is dropped (or its handle
/// is otherwise closed) — callers rely on that RAII behaviour, so keep the
/// `File` alive for as long as the lock should be held.
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    fs2::FileExt::lock_exclusive(file)
}

/// Try to take an exclusive advisory lock without blocking. Returns an error
/// of kind [`io::ErrorKind::WouldBlock`] when another process already holds
/// it. Released on drop, same as [`lock_exclusive`].
pub fn try_lock_exclusive(file: &File) -> io::Result<()> {
    fs2::FileExt::try_lock_exclusive(file)
}

/// Whether the current process is running as the system superuser.
///
/// On Unix this is `euid == 0`. The file channel's access model leans on
/// per-user filesystem scoping, so the daemon refuses to run as root unless
/// explicitly overridden (see `daemon::refuse_if_root`).
///
/// On Windows there is no euid, and the equivalent "is this an elevated
/// (Administrator) token" question doesn't carry the same meaning for our
/// scoping model — a normal user account is already confined to its own
/// profile by NTFS ACLs. We therefore report `false`; the Windows hardening
/// story is ACL-based rather than uid-based.
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn exclusive_lock_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        // First lock succeeds.
        lock_exclusive(&f).unwrap();

        // A second handle to the same file can't take it without blocking.
        let f2 = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let contended = try_lock_exclusive(&f2);
        assert!(
            contended.is_err(),
            "expected the second handle to be locked out"
        );

        // Dropping the first handle releases the lock for the second.
        drop(f);
        try_lock_exclusive(&f2).expect("lock should be free after first handle drops");
    }

    #[test]
    fn is_root_is_callable() {
        // Just exercise the path; value depends on how tests are run.
        let _ = is_root();
    }
}
