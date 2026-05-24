//! Integration tests for the `pocketshell` binary.
//!
//! These tests smoke-test the CLI surface: argument parsing, help output,
//! version output, and error handling for missing/unknown subcommands.
//! They deliberately avoid any subcommand that performs network I/O or
//! touches the real credential store — `HOME` is redirected to a tempdir
//! on every invocation.

use assert_cmd::Command;
use predicates::prelude::*;
use std::time::Duration;
use tempfile::TempDir;

/// Build a `Command` for the `pocketshell` binary with an isolated `HOME`
/// so tests never read or mutate real user state.
fn cmd(tmp: &TempDir) -> Command {
    let mut c = Command::cargo_bin("pocketshell").expect("binary built by cargo");
    c.env("HOME", tmp.path())
        .env_remove("RUST_LOG")
        .timeout(Duration::from_secs(30));
    c
}

#[test]
fn top_level_help_lists_all_subcommands() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("pair"))
        .stdout(predicate::str::contains("logout"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("devices"))
        .stdout(predicate::str::contains("daemon"))
        .stdout(predicate::str::contains("stats"))
        .stdout(predicate::str::contains("sessions"))
        .stdout(predicate::str::contains("remote"))
        .stdout(predicate::str::contains("restart"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("uninstall"));
}

#[test]
fn short_help_flag_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage").or(predicate::str::contains("usage")));
}

#[test]
fn version_flag_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("pocketshell"));
}

#[test]
fn no_args_starts_interactive_menu_and_requires_tty() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .assert()
        .failure()
        .stdout(predicate::str::contains("PocketShell"))
        .stderr(predicate::str::contains("not a terminal"));
}

#[test]
fn unknown_subcommand_exits_non_zero() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .arg("definitely-not-a-real-subcommand")
        .assert()
        .failure();
}

#[test]
fn unknown_flag_exits_non_zero() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .arg("--this-flag-does-not-exist")
        .assert()
        .failure();
}

#[test]
fn pair_help_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["pair", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pair"))
        .stdout(predicate::str::contains("--reset"));
}

#[test]
fn logout_help_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["logout", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--reset"));
}

#[test]
fn devices_help_succeeds_and_lists_subcommands() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["devices", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("revoke"));
}

#[test]
fn daemon_help_succeeds_and_lists_subcommands() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["daemon", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("start"))
        .stdout(predicate::str::contains("stop"))
        .stdout(predicate::str::contains("restart"))
        .stdout(predicate::str::contains("run"));
}

#[test]
fn restart_help_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["restart", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Restart").or(predicate::str::contains("restart")));
}

#[test]
fn update_help_succeeds_and_lists_flags() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["update", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--check"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--version"))
        .stdout(predicate::str::contains("--base-url"));
}

#[test]
fn uninstall_help_succeeds_and_lists_flags() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["uninstall", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--yes"))
        .stdout(predicate::str::contains("--keep-data"))
        .stdout(predicate::str::contains("--keep-binary"));
}

#[test]
fn stats_help_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["stats", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--watch"));
}

#[test]
fn sessions_help_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["sessions", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("attach"));
}

#[test]
fn remote_help_succeeds() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["remote", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--name").or(predicate::str::contains("-n")));
}

#[test]
fn devices_unknown_subcommand_fails() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp)
        .args(["devices", "not-a-real-op"])
        .assert()
        .failure();
}

#[test]
fn daemon_unknown_subcommand_fails() {
    let tmp = TempDir::new().unwrap();
    cmd(&tmp).args(["daemon", "explode"]).assert().failure();
}

#[test]
fn stats_snapshot_prints_json() {
    let tmp = TempDir::new().unwrap();
    // `stats` without --watch collects one snapshot and exits. It does not
    // touch auth or the network, so it's safe to exercise end-to-end.
    cmd(&tmp).arg("stats").assert().success().stdout(
        predicate::str::contains("cpu_usage_percent")
            .or(predicate::str::contains("memory_total_bytes")),
    );
}
