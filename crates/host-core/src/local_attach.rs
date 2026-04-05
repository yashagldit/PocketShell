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
