//! Persistent allowlist of host ports that may be tunneled to the paired
//! mobile via the HTTP-forward data channel. Without an entry, the daemon
//! refuses to open the local TCP connection — a stolen-phone session can't
//! probe `127.0.0.1:5432` etc. without the user first running `pocketshell
//! expose <port>` on the host (which is sudo-equivalent via the existing
//! terminal channel, but is still a deliberate, audited action).
//!
//! Storage is `$STATE_DIR/exposed_ports.json` (0o600 via [`crate::store::atomic_write`]).
//! JSON, not TOML, to avoid pulling a new dependency just for one config file.
//!
//! Entries marked `ephemeral` are dropped on daemon startup via
//! [`ExposedPortsStore::purge_ephemeral`] — the sensible default for
//! `npm run dev`, where the user expects the exposure to vanish when they
//! quit and reboot.

use crate::config::AppConfig;
use crate::error::{HostError, Result};
use crate::store::atomic_write;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const FILE_NAME: &str = "exposed_ports.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExposedPort {
    pub port: u16,
    #[serde(default)]
    pub ephemeral: bool,
    pub added_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    ports: Vec<ExposedPort>,
}

pub struct ExposedPortsStore;

impl ExposedPortsStore {
    fn path() -> Result<PathBuf> {
        Ok(AppConfig::paths()?.state_dir.join(FILE_NAME))
    }

    /// Read all current entries (including ephemeral). On a missing file
    /// returns an empty list — the first-run case.
    pub fn list() -> Result<Vec<ExposedPort>> {
        let p = Self::path()?;
        if !p.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&p)?;
        if raw.trim().is_empty() {
            return Ok(Vec::new());
        }
        let doc: Document = serde_json::from_str(&raw)
            .map_err(|e| HostError::Config(format!("exposed_ports.json: {e}")))?;
        Ok(doc.ports)
    }

    /// True iff `port` has an entry. Called by the HTTP forwarder before it
    /// opens a local socket — reads from disk every time so CLI changes
    /// (`pocketshell expose 3000`) take effect without daemon restart.
    pub fn is_allowed(port: u16) -> Result<bool> {
        Ok(Self::list()?.iter().any(|p| p.port == port))
    }

    /// Add a port to the allowlist. If `port` is already present, its
    /// `ephemeral` flag and `added_at` are refreshed — re-running
    /// `pocketshell expose 3000` after a `--ephemeral` invocation upgrades it
    /// to persistent, and vice versa.
    pub fn add(port: u16, ephemeral: bool) -> Result<ExposedPort> {
        if port == 0 {
            return Err(HostError::Config("port 0 is not a real listener".into()));
        }
        let mut ports = Self::list()?;
        ports.retain(|p| p.port != port);
        let entry = ExposedPort {
            port,
            ephemeral,
            added_at: Utc::now().to_rfc3339(),
        };
        ports.push(entry.clone());
        ports.sort_by_key(|p| p.port);
        Self::write(&ports)?;
        Ok(entry)
    }

    /// Remove a port from the allowlist. Returns whether the entry existed.
    pub fn remove(port: u16) -> Result<bool> {
        let mut ports = Self::list()?;
        let before = ports.len();
        ports.retain(|p| p.port != port);
        let removed = ports.len() != before;
        if removed {
            Self::write(&ports)?;
        }
        Ok(removed)
    }

    /// Drop any `ephemeral = true` entries. The daemon calls this once on
    /// startup so `--ephemeral` exposures don't survive a reboot.
    pub fn purge_ephemeral() -> Result<()> {
        let ports = Self::list()?;
        if !ports.iter().any(|p| p.ephemeral) {
            return Ok(());
        }
        let kept: Vec<_> = ports.into_iter().filter(|p| !p.ephemeral).collect();
        Self::write(&kept)
    }

    fn write(ports: &[ExposedPort]) -> Result<()> {
        let p = Self::path()?;
        if let Some(parent) = p.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let doc = Document {
            ports: ports.to_vec(),
        };
        let raw = serde_json::to_string_pretty(&doc)?;
        atomic_write(&p, raw.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::HOME_LOCK as ENV_LOCK;

    /// Run `f` with home env vars pointed at a fresh tmpdir so the store reads
    /// and writes under it instead of the user's real `~/.pocketshell`. The
    /// `HOME_LOCK` mutex serializes tests in this binary that mutate home env.
    fn with_isolated_home<F: FnOnce()>(f: F) {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        let prev_test_home = std::env::var_os("POCKETSHELL_TEST_HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        unsafe { std::env::set_var("USERPROFILE", tmp.path()) };
        unsafe { std::env::set_var("POCKETSHELL_TEST_HOME", tmp.path()) };
        // Force the .pocketshell dir to exist for atomic_write's chmod path.
        std::fs::create_dir_all(tmp.path().join(".pocketshell")).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
            match prev_test_home {
                Some(v) => std::env::set_var("POCKETSHELL_TEST_HOME", v),
                None => std::env::remove_var("POCKETSHELL_TEST_HOME"),
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn list_empty_on_missing_file() {
        with_isolated_home(|| {
            let ports = ExposedPortsStore::list().unwrap();
            assert!(ports.is_empty());
        });
    }

    #[test]
    fn add_then_list_roundtrip() {
        with_isolated_home(|| {
            ExposedPortsStore::add(3000, false).unwrap();
            let ports = ExposedPortsStore::list().unwrap();
            assert_eq!(ports.len(), 1);
            assert_eq!(ports[0].port, 3000);
            assert!(!ports[0].ephemeral);
        });
    }

    #[test]
    fn add_twice_replaces_flag() {
        with_isolated_home(|| {
            ExposedPortsStore::add(5173, true).unwrap();
            let first = ExposedPortsStore::list().unwrap();
            assert_eq!(first.len(), 1);
            assert!(first[0].ephemeral);

            ExposedPortsStore::add(5173, false).unwrap();
            let second = ExposedPortsStore::list().unwrap();
            assert_eq!(second.len(), 1, "re-adding same port must not duplicate");
            assert!(!second[0].ephemeral, "ephemeral flag must be replaced");
        });
    }

    #[test]
    fn remove_returns_true_when_present() {
        with_isolated_home(|| {
            ExposedPortsStore::add(3000, false).unwrap();
            assert!(ExposedPortsStore::remove(3000).unwrap());
            assert!(ExposedPortsStore::list().unwrap().is_empty());
        });
    }

    #[test]
    fn remove_returns_false_when_absent() {
        with_isolated_home(|| {
            assert!(!ExposedPortsStore::remove(9999).unwrap());
        });
    }

    #[test]
    fn is_allowed_reflects_current_file() {
        with_isolated_home(|| {
            assert!(!ExposedPortsStore::is_allowed(3000).unwrap());
            ExposedPortsStore::add(3000, true).unwrap();
            assert!(ExposedPortsStore::is_allowed(3000).unwrap());
            assert!(!ExposedPortsStore::is_allowed(3001).unwrap());
        });
    }

    #[test]
    fn purge_ephemeral_drops_ephemeral_keeps_persistent() {
        with_isolated_home(|| {
            ExposedPortsStore::add(3000, false).unwrap();
            ExposedPortsStore::add(5173, true).unwrap();
            ExposedPortsStore::add(8080, true).unwrap();
            ExposedPortsStore::purge_ephemeral().unwrap();

            let kept = ExposedPortsStore::list().unwrap();
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].port, 3000);
        });
    }

    #[test]
    fn purge_ephemeral_noop_when_none_ephemeral() {
        // Important: a no-op purge must not rewrite the file with a fresh
        // mtime — otherwise daemon startup churns the file every restart and
        // tools that watch for changes get false positives.
        with_isolated_home(|| {
            ExposedPortsStore::add(3000, false).unwrap();
            let p = AppConfig::paths().unwrap().state_dir.join(FILE_NAME);
            let before = std::fs::metadata(&p).unwrap().modified().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            ExposedPortsStore::purge_ephemeral().unwrap();
            let after = std::fs::metadata(&p).unwrap().modified().unwrap();
            assert_eq!(
                before, after,
                "purge with no ephemeral entries must not rewrite"
            );
        });
    }

    #[test]
    fn add_rejects_port_zero() {
        with_isolated_home(|| {
            let err = ExposedPortsStore::add(0, false).unwrap_err();
            assert!(matches!(err, HostError::Config(_)));
        });
    }

    #[cfg(unix)]
    #[test]
    fn file_is_chmod_0600() {
        use std::os::unix::fs::PermissionsExt;
        with_isolated_home(|| {
            ExposedPortsStore::add(3000, false).unwrap();
            let p = AppConfig::paths().unwrap().state_dir.join(FILE_NAME);
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        });
    }

    #[test]
    fn list_returns_sorted_by_port() {
        with_isolated_home(|| {
            ExposedPortsStore::add(5173, false).unwrap();
            ExposedPortsStore::add(3000, false).unwrap();
            ExposedPortsStore::add(8080, true).unwrap();
            let ports = ExposedPortsStore::list().unwrap();
            assert_eq!(
                ports.iter().map(|p| p.port).collect::<Vec<_>>(),
                vec![3000, 5173, 8080]
            );
        });
    }

    #[test]
    fn list_empty_on_empty_file() {
        with_isolated_home(|| {
            let p = AppConfig::paths().unwrap().state_dir.join(FILE_NAME);
            std::fs::write(&p, "").unwrap();
            assert!(ExposedPortsStore::list().unwrap().is_empty());
        });
    }
}
