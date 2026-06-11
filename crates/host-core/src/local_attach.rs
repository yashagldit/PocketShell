use crate::config::AppConfig;
use crate::error::Result;
use std::path::PathBuf;

// Frame protocol: [type:u8][len:u32 big-endian][payload:len bytes]
/// Maximum payload size for a single frame (1 MiB). Prevents OOM from
/// malicious or corrupt frames.
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

pub const FRAME_TERMINAL_DATA: u8 = 0x01;
pub const FRAME_RESIZE: u8 = 0x02;
pub const FRAME_ATTACH: u8 = 0x03;
pub const FRAME_ERROR: u8 = 0x04;
pub const FRAME_ATTACHED_OK: u8 = 0x05;
pub const FRAME_DETACH: u8 = 0x06;

pub fn encode_frame(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(frame_type);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn socket_path() -> Result<PathBuf> {
    let paths = AppConfig::paths()?;
    Ok(paths.state_dir.join("daemon.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_frame_layout_for_non_empty_payload() {
        let payload = b"hello";
        let frame = encode_frame(FRAME_TERMINAL_DATA, payload);
        assert_eq!(frame.len(), 5 + payload.len());
        assert_eq!(frame[0], FRAME_TERMINAL_DATA);
        // Big-endian u32 length = 5
        assert_eq!(&frame[1..5], &[0, 0, 0, 5]);
        assert_eq!(&frame[5..], payload);
    }

    #[test]
    fn encode_frame_handles_empty_payload() {
        let frame = encode_frame(FRAME_DETACH, &[]);
        assert_eq!(frame, vec![FRAME_DETACH, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_frame_uses_big_endian_length() {
        let payload = vec![0u8; 300]; // 0x012C
        let frame = encode_frame(FRAME_RESIZE, &payload);
        assert_eq!(frame[0], FRAME_RESIZE);
        assert_eq!(&frame[1..5], &[0x00, 0x00, 0x01, 0x2C]);
        assert_eq!(frame.len(), 305);
    }

    #[test]
    fn frame_type_constants_are_distinct() {
        let codes = [
            FRAME_TERMINAL_DATA,
            FRAME_RESIZE,
            FRAME_ATTACH,
            FRAME_ERROR,
            FRAME_ATTACHED_OK,
            FRAME_DETACH,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes at {i} and {j} collide");
            }
        }
    }

    #[cfg(unix)] // POSIX-only behavior; not meaningful on Windows
    #[test]
    fn socket_path_ends_with_daemon_sock_under_pocketshell_dir() {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let result = socket_path();

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        let path = result.expect("socket_path should succeed");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("daemon.sock")
        );
        assert_eq!(
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str()),
            Some(".pocketshell")
        );
        assert!(path.starts_with(tmp.path()));
    }
}
