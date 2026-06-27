use crate::local_attach;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;
use tracing::warn;

/// Events from locally-attached CLI clients over the Unix socket.
pub(super) enum LocalClientEvent {
    /// Client wants to attach to a session.
    Attach { client_id: u64, session_id: String },
    /// Terminal input from a local client.
    Input { session_id: String, data: Vec<u8> },
    /// Resize from a local client.
    Resize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    /// Client disconnected.
    Disconnected { client_id: u64 },
}

// Local-attach IPC transport. On Unix this is a Unix-domain socket; on other
// platforms (Windows) the local CLI-attach feature is not wired up yet, so the
// listener is always `None` and never accepts. The half types below only need
// to satisfy the `AsyncRead`/`AsyncWrite` bounds used by the shared daemon
// loop — on non-Unix they alias throwaway in-memory pipe halves that are never
// constructed. Mobile sessions over WebRTC are unaffected on every platform.
#[cfg(unix)]
pub(super) type LocalReadHalf = tokio::net::unix::OwnedReadHalf;
#[cfg(unix)]
pub(super) type LocalWriteHalf = tokio::net::unix::OwnedWriteHalf;
#[cfg(unix)]
pub(super) type LocalAttachListener = tokio::net::UnixListener;

#[cfg(not(unix))]
pub(super) type LocalReadHalf = tokio::io::ReadHalf<tokio::io::DuplexStream>;
#[cfg(not(unix))]
pub(super) type LocalWriteHalf = tokio::io::WriteHalf<tokio::io::DuplexStream>;
#[cfg(not(unix))]
pub(super) type LocalAttachListener = DisabledLocalListener;

/// Stand-in listener for platforms where local attach is not available.
#[cfg(not(unix))]
pub(super) struct DisabledLocalListener;

/// Wait for the next local-attach client and return its split halves. On
/// platforms without a listener the returned future never resolves, so the
/// owning `select!` arm simply stays parked.
#[cfg(unix)]
pub(super) async fn local_accept(
    listener: Option<&LocalAttachListener>,
) -> Option<(LocalReadHalf, LocalWriteHalf)> {
    match listener {
        Some(l) => match l.accept().await {
            Ok((stream, _addr)) => Some(stream.into_split()),
            Err(e) => {
                warn!("local attach accept failed: {e}");
                None
            }
        },
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
pub(super) async fn local_accept(
    _listener: Option<&LocalAttachListener>,
) -> Option<(LocalReadHalf, LocalWriteHalf)> {
    std::future::pending().await
}

/// Tracks write halves of locally attached clients, keyed by session_id.
pub(super) struct LocalAttachClients {
    clients: HashMap<u64, (String, LocalWriteHalf)>,
}

impl LocalAttachClients {
    pub(super) fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    pub(super) fn add(&mut self, client_id: u64, session_id: String, writer: LocalWriteHalf) {
        self.clients.insert(client_id, (session_id, writer));
    }

    pub(super) fn remove(&mut self, client_id: u64) {
        self.clients.remove(&client_id);
    }

    /// Send terminal output to all local clients attached to this session.
    pub(super) async fn send_output(&mut self, session_id: &str, data: &[u8]) {
        let frame = local_attach::encode_frame(local_attach::FRAME_TERMINAL_DATA, data);
        let mut dead = Vec::new();
        for (id, (sid, writer)) in &mut self.clients {
            if sid == session_id {
                if writer.write_all(&frame).await.is_err() {
                    dead.push(*id);
                }
            }
        }
        for id in dead {
            self.clients.remove(&id);
        }
    }

    /// Notify all clients attached to a session that it ended, then remove them.
    pub(super) async fn end_session(&mut self, session_id: &str) {
        let frame = local_attach::encode_frame(local_attach::FRAME_ERROR, b"session ended");
        for (_, (sid, writer)) in &mut self.clients {
            if sid == session_id {
                let _ = writer.write_all(&frame).await;
            }
        }
        self.clients.retain(|_, (sid, _)| sid != session_id);
    }
}

/// Reads framed messages from a local attach client and sends events to the daemon loop.
pub(super) async fn local_attach_reader(
    client_id: u64,
    mut reader: LocalReadHalf,
    tx: tokio::sync::mpsc::UnboundedSender<LocalClientEvent>,
) {
    use tokio::io::AsyncReadExt;

    let mut session_id = String::new();
    let mut header = [0u8; 5]; // type(1) + len(4)

    loop {
        // Read frame header with idle timeout to detect crashed clients
        let read_result =
            tokio::time::timeout(Duration::from_secs(300), reader.read_exact(&mut header)).await;
        match read_result {
            Ok(Ok(_)) => {}
            _ => break, // timeout, EOF, or error
        }
        let frame_type = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

        // Reject oversized frames to prevent OOM
        if len > local_attach::MAX_FRAME_SIZE {
            warn!(
                "local attach: client {} sent oversized frame ({} bytes), disconnecting",
                client_id, len
            );
            break;
        }

        // Read payload
        let mut payload = vec![0u8; len];
        if len > 0 && reader.read_exact(&mut payload).await.is_err() {
            break;
        }

        match frame_type {
            local_attach::FRAME_ATTACH => {
                // Validate session_id: must be valid UTF-8 and reasonable length
                match String::from_utf8(payload) {
                    Ok(sid) if !sid.is_empty() && sid.len() <= 256 => {
                        session_id = sid;
                        let _ = tx.send(LocalClientEvent::Attach {
                            client_id,
                            session_id: session_id.clone(),
                        });
                    }
                    _ => {
                        warn!("local attach: client {} sent invalid session_id", client_id);
                        break;
                    }
                }
            }
            local_attach::FRAME_TERMINAL_DATA => {
                let _ = tx.send(LocalClientEvent::Input {
                    session_id: session_id.clone(),
                    data: payload,
                });
            }
            local_attach::FRAME_RESIZE => {
                if payload.len() == 4 {
                    let cols = u16::from_be_bytes([payload[0], payload[1]]);
                    let rows = u16::from_be_bytes([payload[2], payload[3]]);
                    if cols > 0 && rows > 0 {
                        let _ = tx.send(LocalClientEvent::Resize {
                            session_id: session_id.clone(),
                            cols,
                            rows,
                        });
                    }
                }
            }
            local_attach::FRAME_DETACH => {
                break;
            }
            _ => {}
        }
    }

    let _ = tx.send(LocalClientEvent::Disconnected { client_id });
}
