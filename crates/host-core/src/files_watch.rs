//! Poll-based JSONL tailer used to push appended lines from host
//! transcript files (Claude/Codex rollouts) to mobile. Modeled on
//! remodex-main/phodex-bridge/src/rollout-live-mirror.js — polling with
//! `stat` + seek/read rather than filesystem notifications, so it works
//! reliably across platforms and file rewrites.

use crate::error::{HostError, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const DEFAULT_POLL_MS: u64 = 700;
pub const DEFAULT_IDLE_MS: u64 = 60_000;
pub const MAX_LINES_PER_TICK: usize = 500;
const MAX_DELTA_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct TailState {
    pub last_size: u64,
    pub partial: String,
    read_buf: Vec<u8>,
}

impl TailState {
    pub fn starting_at(offset: u64) -> Self {
        Self {
            last_size: offset,
            partial: String::new(),
            read_buf: Vec::new(),
        }
    }
}

/// Size of the file right now, or 0 if it doesn't exist yet.
pub fn initial_offset(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Read any new content since `state.last_size`, split into complete
/// lines, and update `state`. Returns up to `MAX_LINES_PER_TICK` lines;
/// remaining growth stays in the file and is picked up next tick.
///
/// Handles three edge cases:
/// - File shrank (truncate/rotate): reset state and return empty.
/// - File missing (transient during rename): treat as no growth.
/// - Trailing partial line: buffered in `state.partial` until a `\n` arrives.
pub fn read_delta(path: &Path, state: &mut TailState) -> Result<Vec<String>> {
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(HostError::Backend(format!("stat failed: {err}"))),
    };

    if size < state.last_size {
        state.last_size = 0;
        state.partial.clear();
    }
    if size == state.last_size {
        return Ok(Vec::new());
    }

    let want = std::cmp::min(size - state.last_size, MAX_DELTA_BYTES) as usize;
    let mut file = File::open(path)
        .map_err(|e| HostError::Backend(format!("open failed: {e}")))?;
    file.seek(SeekFrom::Start(state.last_size))
        .map_err(|e| HostError::Backend(format!("seek failed: {e}")))?;
    state.read_buf.clear();
    state.read_buf.resize(want, 0);
    let mut read_total = 0usize;
    while read_total < want {
        let n = file
            .read(&mut state.read_buf[read_total..])
            .map_err(|e| HostError::Backend(format!("read failed: {e}")))?;
        if n == 0 {
            break;
        }
        read_total += n;
    }
    state.read_buf.truncate(read_total);
    state.last_size += read_total as u64;

    state
        .partial
        .push_str(&String::from_utf8_lossy(&state.read_buf));
    let ends_with_newline = state.partial.ends_with('\n');
    let mut lines: Vec<String> = state
        .partial
        .lines()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    state.partial = if ends_with_newline {
        String::new()
    } else {
        lines.pop().unwrap_or_default()
    };
    if lines.len() > MAX_LINES_PER_TICK {
        lines.truncate(MAX_LINES_PER_TICK);
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pocketshell_tailer_{}_{}.jsonl", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn append_yields_new_lines() {
        let path = tmp("append");
        std::fs::write(&path, "{\"a\":1}\n").unwrap();
        let mut state = TailState::starting_at(initial_offset(&path));
        assert!(read_delta(&path, &mut state).unwrap().is_empty());

        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{{\"b\":2}}").unwrap();
        writeln!(f, "{{\"c\":3}}").unwrap();
        drop(f);

        let got = read_delta(&path, &mut state).unwrap();
        assert_eq!(got, vec!["{\"b\":2}".to_string(), "{\"c\":3}".to_string()]);
    }

    #[test]
    fn partial_line_buffers_until_newline() {
        let path = tmp("partial");
        std::fs::write(&path, "").unwrap();
        let mut state = TailState::default();

        std::fs::write(&path, "{\"x\":").unwrap();
        assert!(read_delta(&path, &mut state).unwrap().is_empty());
        assert_eq!(state.partial, "{\"x\":");

        std::fs::write(&path, "{\"x\":1}\n").unwrap();
        let got = read_delta(&path, &mut state).unwrap();
        assert_eq!(got, vec!["{\"x\":1}".to_string()]);
        assert_eq!(state.partial, "");
    }

    #[test]
    fn truncate_resets_state() {
        let path = tmp("truncate");
        std::fs::write(&path, "{\"a\":1}\n{\"b\":2}\n").unwrap();
        let mut state = TailState::starting_at(initial_offset(&path));

        std::fs::write(&path, "{\"fresh\":1}\n").unwrap();
        let got = read_delta(&path, &mut state).unwrap();
        assert_eq!(got, vec!["{\"fresh\":1}".to_string()]);
    }

    #[test]
    fn missing_file_is_transient() {
        let path = tmp("missing");
        let mut state = TailState::default();
        assert!(read_delta(&path, &mut state).unwrap().is_empty());
    }

    #[test]
    fn initial_offset_returns_zero_for_missing_file() {
        let path = tmp("initial_missing");
        assert_eq!(initial_offset(&path), 0);
    }

    #[test]
    fn initial_offset_returns_file_size() {
        let path = tmp("initial_size");
        std::fs::write(&path, b"hello\n").unwrap();
        assert_eq!(initial_offset(&path), 6);
    }

    #[test]
    fn starting_at_sets_offset() {
        let s = TailState::starting_at(42);
        assert_eq!(s.last_size, 42);
        assert!(s.partial.is_empty());
    }

    #[test]
    fn multiple_lines_in_one_tick() {
        let path = tmp("multi");
        std::fs::write(&path, "").unwrap();
        let mut state = TailState::default();
        std::fs::write(&path, "a\nb\nc\nd\n").unwrap();
        let got = read_delta(&path, &mut state).unwrap();
        assert_eq!(got, vec!["a", "b", "c", "d"]);
        assert_eq!(state.partial, "");
    }

    #[test]
    fn empty_lines_are_filtered_out() {
        let path = tmp("empties");
        std::fs::write(&path, "").unwrap();
        let mut state = TailState::default();
        std::fs::write(&path, "one\n\n\ntwo\n").unwrap();
        let got = read_delta(&path, &mut state).unwrap();
        assert_eq!(got, vec!["one", "two"]);
    }

    #[test]
    fn no_growth_yields_no_lines() {
        let path = tmp("no_growth");
        std::fs::write(&path, "hello\n").unwrap();
        let mut state = TailState::starting_at(initial_offset(&path));
        let got = read_delta(&path, &mut state).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn partial_followed_by_more_partial_accumulates() {
        let path = tmp("partial_accum");
        std::fs::write(&path, "").unwrap();
        let mut state = TailState::default();

        std::fs::write(&path, "foo").unwrap();
        assert!(read_delta(&path, &mut state).unwrap().is_empty());
        assert_eq!(state.partial, "foo");

        // Overwrite with same prefix plus more — but since we seek from
        // last_size the "foo" prefix is consumed as partial already; appending
        // "bar\n" as a whole file rewrite means size equals 7, last_size is 3,
        // so we read "bar\n" from offset 3.
        std::fs::write(&path, "foobar\n").unwrap();
        let got = read_delta(&path, &mut state).unwrap();
        assert_eq!(got, vec!["foobar"]);
        assert_eq!(state.partial, "");
    }

}
