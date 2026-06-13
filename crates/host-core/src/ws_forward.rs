//! WebSocket tunneling from mobile to a local dev server on this host —
//! the live half of the dev-server preview (Phase 6). HMR (Vite / Next.js /
//! webpack-dev-server), framework error overlays, and app-level sockets all
//! ride a WebSocket; without this the in-app preview is request/response
//! only and the user reloads by hand after every edit.
//!
//! Frames ride the existing `http-{hostId}` data channel using the
//! `WsOpen` / `WsOpenOk` / `WsData` / `WsClose` opcodes from
//! [`crate::http_forward`], multiplexed by the same u32 request-id space as
//! HTTP forwards. Sharing the channel keeps backpressure unified — a chatty
//! socket competes with HTTP forwards the same way two HTTP forwards
//! compete with each other.
//!
//! ## Security gate
//!
//! Identical to HTTP forwarding: every `WsOpen` re-checks
//! [`ExposedPortsStore::is_allowed`] before any local socket is opened, and
//! the daemon audits the attempt (`ports.forward.requested` /
//! `ports.forward.denied` with `protocol: "ws"`).
//!
//! ## Message framing
//!
//! WebSocket messages can exceed the ~64 KB SCTP send ceiling, so a message
//! is carried as one or more `WsData` fragments; `WS_FLAG_FIN` marks the
//! last fragment. Both sides reassemble before delivering (tungstenite
//! upstream, the page's `WebSocket` shim on mobile). Reassembly is capped
//! at [`WS_MSG_MAX_BYTES`].

use crate::exposed_ports::ExposedPortsStore;
use crate::http_forward::{
    build_port_not_exposed, ErrorCode, ForwardOutcome, Frame, WsClientEvent, WsOpenRequest,
    RESP_BODY_CHUNK_BYTES, UPSTREAM_TIMEOUT, WS_MSG_MAX_BYTES,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::Message;

/// Close code we synthesize when the upstream connection drops without a
/// proper close handshake (RFC 6455 reserves 1006 for exactly this).
const CLOSE_ABNORMAL: u16 = 1006;
/// "Message too big" close code (RFC 6455 §7.4.1).
const CLOSE_TOO_BIG: u16 = 1009;
/// "Unexpected condition" close code.
const CLOSE_INTERNAL: u16 = 1011;

/// Request headers we do NOT forward into the upstream handshake: either
/// hop-by-hop, or owned by tungstenite's own client handshake (it generates
/// the key/version/upgrade set itself and duplicates would corrupt it).
fn header_is_ws_managed(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "upgrade"
            | "host"
            | "origin"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
            | "sec-websocket-accept"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "content-length"
    )
}

/// Open the upstream WebSocket and start the bidirectional relay.
/// Mirrors [`crate::http_forward::forward_request`]'s shape so the daemon
/// can reuse its pump: `head` is the first frame to write (`WsOpenOk` on
/// success, `RespError` on failure) and `body` streams every subsequent
/// frame (`WsData` fragments, then exactly one `WsClose`) until the relay
/// ends.
///
/// The relay terminates when:
///   - the upstream closes or errors (→ `WsClose` to mobile),
///   - the client sends `WsClose` (→ close handshake upstream),
///   - the client-event sender is dropped (channel close / session
///     shutdown) (→ upstream closed, no frame emitted — nobody is
///     listening).
pub async fn forward_ws(req: WsOpenRequest) -> ForwardOutcome {
    let (tx, rx) = tokio::sync::mpsc::channel::<Frame>(32);
    let id = req.id;
    let mut client_rx = req.client_rx;

    // Allowlist gate — fail closed, identical to the HTTP path.
    let allowed = match ExposedPortsStore::is_allowed(req.head.port) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("exposed_ports read failed: {} — denying ws open", e);
            false
        }
    };
    if !allowed {
        tracing::info!(
            port = req.head.port,
            path = %req.head.path,
            "ws-forward denied: port not in allowlist"
        );
        drop(tx);
        return ForwardOutcome {
            head: build_port_not_exposed(id, req.head.port),
            body: rx,
        };
    }

    let url = format!("ws://localhost:{}{}", req.head.port, req.head.path);
    let mut request = match url.clone().into_client_request() {
        Ok(r) => r,
        Err(e) => {
            drop(tx);
            return ForwardOutcome {
                head: Frame::RespError {
                    id,
                    code: ErrorCode::MalformedFrame,
                    message: format!("invalid ws url `{url}`: {e}"),
                },
                body: rx,
            };
        }
    };
    {
        let headers = request.headers_mut();
        for (name, value) in &req.head.headers {
            if header_is_ws_managed(name) {
                continue;
            }
            let (Ok(hn), Ok(hv)) = (
                name.parse::<tokio_tungstenite::tungstenite::http::header::HeaderName>(),
                value.parse::<tokio_tungstenite::tungstenite::http::HeaderValue>(),
            ) else {
                continue; // skip unrepresentable headers rather than fail the open
            };
            headers.insert(hn, hv);
        }
        // Synthesize a localhost Origin: Vite (`server.origin` checks),
        // webpack-dev-server, and Rails ActionCable all reject cross-origin
        // sockets by default; the page's real origin is our custom scheme
        // which every one of them would refuse.
        if let Ok(origin) = format!("http://localhost:{}", req.head.port).parse() {
            headers.insert("Origin", origin);
        }
    }

    // Race connect against the client cancelling (user navigated away
    // mid-connect) so a dead open doesn't hold the slot for 30 s.
    let connect = tokio::time::timeout(UPSTREAM_TIMEOUT, tokio_tungstenite::connect_async(request));
    tokio::pin!(connect);
    let connected = loop {
        tokio::select! {
            biased;
            ev = client_rx.recv() => match ev {
                Some(WsClientEvent::Close { .. }) | None => {
                    drop(tx);
                    return ForwardOutcome {
                        head: Frame::RespError {
                            id,
                            code: ErrorCode::InternalError,
                            message: "websocket open cancelled by client".into(),
                        },
                        body: rx,
                    };
                }
                // Data before the upstream is up: drop it. The shim opens
                // the socket and waits for `open` before sending, so this
                // only happens for misbehaving pages.
                Some(WsClientEvent::Data { .. }) => continue,
            },
            result = &mut connect => break result,
        }
    };

    let (ws, response) = match connected {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            drop(tx);
            return ForwardOutcome {
                head: Frame::RespError {
                    id,
                    code: ErrorCode::UpstreamFailed,
                    message: format!("websocket connect failed: {e}"),
                },
                body: rx,
            };
        }
        Err(_) => {
            drop(tx);
            return ForwardOutcome {
                head: Frame::RespError {
                    id,
                    code: ErrorCode::UpstreamTimeout,
                    message: format!(
                        "websocket connect timed out after {}s",
                        UPSTREAM_TIMEOUT.as_secs()
                    ),
                },
                body: rx,
            };
        }
    };

    tracing::info!(
        port = req.head.port,
        path = %req.head.path,
        "ws-forward established"
    );

    // Surface the handshake headers mobile cares about — primarily the
    // server-selected subprotocol, which the page's WebSocket shim must
    // report as `socket.protocol`.
    let mut ok_headers: Vec<(String, String)> = Vec::new();
    if let Some(proto) = response.headers().get("sec-websocket-protocol") {
        if let Ok(v) = proto.to_str() {
            ok_headers.push(("Sec-WebSocket-Protocol".to_string(), v.to_string()));
        }
    }

    tokio::spawn(relay_loop(id, ws, client_rx, tx));

    ForwardOutcome {
        head: Frame::WsOpenOk {
            id,
            headers: ok_headers,
        },
        body: rx,
    }
}

type Upstream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Pump messages both directions until either side ends. Emits `WsData`
/// fragments and a final `WsClose` into `tx`; the daemon writes them to the
/// data channel in order.
async fn relay_loop(
    id: u32,
    mut ws: Upstream,
    mut client_rx: tokio::sync::mpsc::Receiver<WsClientEvent>,
    tx: tokio::sync::mpsc::Sender<Frame>,
) {
    // Reassembly buffer for fragmented client→upstream messages.
    let mut partial: Vec<u8> = Vec::new();
    let mut partial_text = false;

    let close_frame = loop {
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(t))) => {
                    if send_chunked(&tx, id, true, t.as_bytes()).await.is_err() {
                        let _ = ws.close(None).await;
                        return;
                    }
                }
                Some(Ok(Message::Binary(b))) => {
                    if send_chunked(&tx, id, false, &b).await.is_err() {
                        let _ = ws.close(None).await;
                        return;
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    // tungstenite queues pongs internally on read, but only
                    // flushes them on the next send — answer explicitly so a
                    // quiet tunnel doesn't time out the upstream's keepalive.
                    let _ = ws.send(Message::Pong(data)).await;
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(cf))) => {
                    break match cf {
                        Some(cf) => Frame::WsClose {
                            id,
                            code: cf.code.into(),
                            reason: cf.reason.to_string(),
                        },
                        None => Frame::WsClose {
                            id,
                            code: CLOSE_ABNORMAL,
                            reason: "upstream closed".into(),
                        },
                    };
                }
                Some(Err(e)) => {
                    break Frame::WsClose {
                        id,
                        code: CLOSE_ABNORMAL,
                        reason: format!("upstream error: {e}"),
                    };
                }
                None => {
                    break Frame::WsClose {
                        id,
                        code: CLOSE_ABNORMAL,
                        reason: "upstream closed".into(),
                    };
                }
            },
            ev = client_rx.recv() => match ev {
                Some(WsClientEvent::Data { text, fin, data }) => {
                    if partial.len().saturating_add(data.len()) > WS_MSG_MAX_BYTES {
                        let _ = ws.close(Some(CloseFrame {
                            code: CloseCode::from(CLOSE_TOO_BIG),
                            reason: "client message exceeded reassembly cap".into(),
                        })).await;
                        break Frame::WsClose {
                            id,
                            code: CLOSE_TOO_BIG,
                            reason: format!("message exceeded {WS_MSG_MAX_BYTES} bytes"),
                        };
                    }
                    if partial.is_empty() {
                        partial_text = text;
                    }
                    partial.extend_from_slice(&data);
                    if !fin {
                        continue;
                    }
                    let bytes = std::mem::take(&mut partial);
                    let message = if partial_text {
                        match String::from_utf8(bytes) {
                            Ok(s) => Message::text(s),
                            Err(_) => {
                                let _ = ws.close(Some(CloseFrame {
                                    code: CloseCode::from(1007u16),
                                    reason: "invalid utf-8 in text message".into(),
                                })).await;
                                break Frame::WsClose {
                                    id,
                                    code: 1007,
                                    reason: "invalid utf-8 in text message".into(),
                                };
                            }
                        }
                    } else {
                        Message::binary(Bytes::from(bytes))
                    };
                    if let Err(e) = ws.send(message).await {
                        break Frame::WsClose {
                            id,
                            code: CLOSE_INTERNAL,
                            reason: format!("upstream send failed: {e}"),
                        };
                    }
                }
                Some(WsClientEvent::Close { code, reason }) => {
                    let _ = ws.close(Some(CloseFrame {
                        code: CloseCode::from(code),
                        reason: reason.clone().into(),
                    })).await;
                    // Client initiated — echo the close back so the shim's
                    // socket reaches CLOSED with the requested code even if
                    // the upstream never answers the handshake.
                    break Frame::WsClose { id, code, reason };
                }
                None => {
                    // Session shut down (data channel closed). Nobody is
                    // listening for frames — just close the upstream.
                    let _ = ws.close(None).await;
                    return;
                }
            },
        }
    };

    let _ = tx.send(close_frame).await;
}

/// Fragment one WebSocket message into `WsData` frames under the SCTP
/// ceiling, FIN on the last. Empty messages still emit a single empty
/// FIN frame (an empty text message is legal and some heartbeats use it).
async fn send_chunked(
    tx: &tokio::sync::mpsc::Sender<Frame>,
    id: u32,
    text: bool,
    data: &[u8],
) -> std::result::Result<(), ()> {
    if data.is_empty() {
        return tx
            .send(Frame::WsData {
                id,
                text,
                fin: true,
                data: Bytes::new(),
            })
            .await
            .map_err(|_| ());
    }
    let mut chunks = data.chunks(RESP_BODY_CHUNK_BYTES).peekable();
    while let Some(chunk) = chunks.next() {
        let fin = chunks.peek().is_none();
        tx.send(Frame::WsData {
            id,
            text,
            fin,
            data: Bytes::copy_from_slice(chunk),
        })
        .await
        .map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_forward::RequestHead;

    fn ws_head(port: u16, path: &str) -> RequestHead {
        RequestHead {
            port,
            method: "GET".into(),
            path: path.into(),
            headers: vec![],
        }
    }

    #[test]
    fn ws_managed_header_classification() {
        assert!(header_is_ws_managed("Sec-WebSocket-Key"));
        assert!(header_is_ws_managed("Upgrade"));
        assert!(header_is_ws_managed("Connection"));
        assert!(header_is_ws_managed("Host"));
        assert!(header_is_ws_managed("Origin"));
        assert!(!header_is_ws_managed("Sec-WebSocket-Protocol"));
        assert!(!header_is_ws_managed("Cookie"));
        assert!(!header_is_ws_managed("Authorization"));
    }

    /// Allowlist gate: a WsOpen for an unexposed port must be refused
    /// before any socket is opened — same contract as the HTTP forwarder.
    #[tokio::test]
    async fn forward_ws_denies_when_port_not_exposed() {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        std::fs::create_dir_all(tmp.path().join(".pocketshell")).unwrap();

        let (_tx, client_rx) = tokio::sync::mpsc::channel(4);
        let req = WsOpenRequest {
            id: 9,
            head: ws_head(65501, "/hmr"),
            client_rx,
        };
        let outcome = forward_ws(req).await;

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        match outcome.head {
            Frame::RespError { id, code, .. } => {
                assert_eq!(id, 9);
                assert_eq!(code, ErrorCode::PortNotExposed);
            }
            other => panic!("expected PortNotExposed, got {other:?}"),
        }
        let mut body = outcome.body;
        assert!(body.recv().await.is_none());
    }

    /// End-to-end relay against a real in-process tungstenite echo server:
    /// text and binary messages round-trip, fragmentation reassembles, and
    /// a client close propagates.
    #[tokio::test]
    async fn forward_ws_relays_echo_roundtrip() {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        std::fs::create_dir_all(tmp.path().join(".pocketshell")).unwrap();

        // Echo server on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    Message::Text(_) | Message::Binary(_) => {
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });

        ExposedPortsStore::add(port, true).unwrap();

        let (client_tx, client_rx) = tokio::sync::mpsc::channel(8);
        let req = WsOpenRequest {
            id: 1,
            head: ws_head(port, "/"),
            client_rx,
        };
        let outcome = forward_ws(req).await;

        // Restore HOME before any assertion can panic — the relay no longer
        // touches the store after the open.
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        assert!(
            matches!(outcome.head, Frame::WsOpenOk { id: 1, .. }),
            "expected WsOpenOk, got {:?}",
            outcome.head
        );
        let mut frames = outcome.body;

        // Text message, sent as two fragments — the relay must reassemble
        // before echoing upstream, and the echo comes back as one message.
        client_tx
            .send(WsClientEvent::Data {
                text: true,
                fin: false,
                data: Bytes::from_static(b"hello "),
            })
            .await
            .unwrap();
        client_tx
            .send(WsClientEvent::Data {
                text: true,
                fin: true,
                data: Bytes::from_static(b"world"),
            })
            .await
            .unwrap();
        match frames.recv().await.expect("echo frame") {
            Frame::WsData {
                id,
                text,
                fin,
                data,
            } => {
                assert_eq!(id, 1);
                assert!(text);
                assert!(fin);
                assert_eq!(&data[..], b"hello world");
            }
            other => panic!("expected WsData, got {other:?}"),
        }

        // Binary round-trip.
        client_tx
            .send(WsClientEvent::Data {
                text: false,
                fin: true,
                data: Bytes::from_static(&[1, 2, 3, 0xff]),
            })
            .await
            .unwrap();
        match frames.recv().await.expect("echo frame") {
            Frame::WsData { text, data, .. } => {
                assert!(!text);
                assert_eq!(&data[..], &[1, 2, 3, 0xff]);
            }
            other => panic!("expected WsData, got {other:?}"),
        }

        // Client close ends the relay with an echoed WsClose.
        client_tx
            .send(WsClientEvent::Close {
                code: 1000,
                reason: "done".into(),
            })
            .await
            .unwrap();
        match frames.recv().await.expect("close frame") {
            Frame::WsClose { code, reason, .. } => {
                assert_eq!(code, 1000);
                assert_eq!(reason, "done");
            }
            other => panic!("expected WsClose, got {other:?}"),
        }
        assert!(frames.recv().await.is_none(), "relay must end after close");
    }

    /// Oversized outbound messages from the upstream must be fragmented
    /// under the SCTP ceiling and reassemble exactly.
    #[tokio::test]
    async fn send_chunked_fragments_and_marks_fin() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let payload = vec![0xabu8; RESP_BODY_CHUNK_BYTES * 2 + 17];
        send_chunked(&tx, 5, false, &payload).await.unwrap();
        drop(tx);

        let mut got: Vec<u8> = Vec::new();
        let mut frames = 0;
        let mut saw_fin = false;
        while let Some(f) = rx.recv().await {
            match f {
                Frame::WsData { fin, data, .. } => {
                    assert!(!saw_fin, "no frames after FIN");
                    frames += 1;
                    got.extend_from_slice(&data);
                    saw_fin = fin;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(frames, 3);
        assert!(saw_fin);
        assert_eq!(got, payload);
    }
}
