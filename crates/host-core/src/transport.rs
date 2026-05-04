use crate::error::{HostError, Result};
use crate::models::SignalEnvelope;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderValue, AUTHORIZATION};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// What `recv_signal` produced. Distinguishing Pong from other keep-alive
/// frames lets the daemon's watchdog clear its "ping outstanding" deadline
/// without conflating it with auto-replied server Pings or stray binary frames.
#[derive(Debug)]
pub enum WsRead {
    /// A parsed control-plane signal envelope ready for handling.
    Signal(SignalEnvelope),
    /// A Pong from the server in response to a Ping we sent.
    Pong,
    /// Any other non-signal frame (server Ping we already auto-replied to,
    /// binary frame, raw frame). Counts as evidence the connection is alive.
    KeepAlive,
}

pub async fn connect_host_ws(
    base_ws_url: &str,
    host_id: &str,
    access_token: &str,
) -> Result<WsStream> {
    let full_url = if base_ws_url.contains('?') {
        format!("{base_ws_url}&host_id={host_id}")
    } else {
        format!("{base_ws_url}?host_id={host_id}")
    };

    let mut request = full_url
        .into_client_request()
        .map_err(|e| HostError::Backend(format!("invalid ws request: {e}")))?;

    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {access_token}"))
            .map_err(|e| HostError::Backend(format!("invalid auth header: {e}")))?,
    );

    let (socket, _) = connect_async(request)
        .await
        .map_err(|e| HostError::Backend(format!("control connection failed: {e}")))?;
    Ok(socket)
}

pub async fn send_signal(ws: &mut WsStream, msg: &SignalEnvelope) -> Result<()> {
    let raw = serde_json::to_string(msg)?;
    tokio::time::timeout(Duration::from_secs(10), ws.send(Message::Text(raw.into())))
        .await
        .map_err(|_| HostError::Backend("ws send timed out".into()))?
        .map_err(|e| HostError::Backend(format!("ws send failed: {e}")))
}

/// Read one frame from the WebSocket.
///
/// This function is **cancel-safe**: it awaits exactly one `ws.next()` and does
/// nothing else. The caller (the daemon's `tokio::select!` loop) must enforce
/// the read deadline externally by tracking `last_ws_message_at` and a
/// separate watchdog tick. An earlier version wrapped this in
/// `tokio::time::timeout(90s, …)` — that was unsound, because every other
/// branch of the select loop (50ms output/webrtc ticks) cancels this future
/// and resets the timer, so the deadline was mathematically unreachable and
/// dead control-plane sockets sat in `CLOSE_WAIT` indefinitely.
pub async fn recv_signal(ws: &mut WsStream) -> Result<WsRead> {
    match ws.next().await {
        Some(Ok(Message::Text(text))) => {
            let parsed = serde_json::from_str::<SignalEnvelope>(&text)
                .map_err(|e| HostError::Backend(format!("invalid control payload: {e}")))?;
            Ok(WsRead::Signal(parsed))
        }
        Some(Ok(Message::Ping(data))) => {
            ws.send(Message::Pong(data)).await.ok();
            Ok(WsRead::KeepAlive)
        }
        Some(Ok(Message::Pong(_))) => Ok(WsRead::Pong),
        Some(Ok(Message::Binary(_))) => Ok(WsRead::KeepAlive),
        Some(Ok(Message::Frame(_))) => Ok(WsRead::KeepAlive),
        Some(Ok(Message::Close(_))) => Err(HostError::Backend("ws closed by server".into())),
        Some(Err(e)) => Err(HostError::Backend(format!("ws read failed: {e}"))),
        None => Err(HostError::Backend("ws stream ended".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::protocol::Message as ServerMessage;

    /// Spin up an in-process WS server, accept one connection, and let the
    /// caller drive it. Returns the client `WsStream` and a handle to the
    /// server-side socket so the test can push specific frames.
    async fn ws_pair() -> (
        WsStream,
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_async(stream).await.unwrap()
        });
        let url = format!("ws://{addr}/");
        let (client, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let server = server.await.unwrap();
        // SAFETY-of-types: client side is MaybeTlsStream, server side is plain TcpStream.
        (client, server)
    }

    /// Regression test for the cancel-safety bug fixed in this file: the old
    /// `recv_signal` wrapped `ws.next()` in `tokio::time::timeout(90s, …)`,
    /// which got reset on every `tokio::select!` loss. Here we drive
    /// `recv_signal` from a `select!` whose other branch fires every 1ms for
    /// 200ms — far more cancellations than ticks of any real timeout — and
    /// assert that an actual frame still arrives. With the old buggy code
    /// this still worked (the timeout was reset, not exceeded); with the
    /// fixed code it also works because the inner state lives in
    /// `ws.next()`, which is cancel-safe. The test guards against someone
    /// re-introducing a non-cancel-safe wrapper inside `recv_signal`.
    #[tokio::test]
    async fn recv_signal_survives_repeated_select_cancellations() {
        let (mut client, mut server) = ws_pair().await;

        // Server pushes one signal frame after a delay long enough that the
        // 1ms ticker on the client side will have cancelled `recv_signal`
        // many times.
        let server_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let envelope = serde_json::json!({
                "type": "ping",
                "session_id": null,
            });
            server
                .send(ServerMessage::Text(envelope.to_string().into()))
                .await
                .unwrap();
        });

        let mut spam_tick = tokio::time::interval(Duration::from_millis(1));
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);

        let result = loop {
            tokio::select! {
                _ = spam_tick.tick() => {
                    // Constantly cancel `recv_signal` — analogous to the
                    // 50ms output_tick / webrtc_poll_tick branches in the
                    // daemon select loop.
                }
                read = recv_signal(&mut client) => break read,
                _ = &mut deadline => panic!("recv_signal never produced a frame"),
            }
        };

        match result {
            Ok(WsRead::Signal(env)) => assert_eq!(env.message_type, "ping"),
            other => panic!("expected Signal(ping), got {:?}", other),
        }

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn recv_signal_classifies_pong_separately_from_keepalive() {
        let (mut client, mut server) = ws_pair().await;

        let server_task = tokio::spawn(async move {
            server
                .send(ServerMessage::Pong(vec![].into()))
                .await
                .unwrap();
        });

        match recv_signal(&mut client).await {
            Ok(WsRead::Pong) => {}
            other => panic!("expected Pong, got {:?}", other),
        }

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn recv_signal_surfaces_stream_end_as_error() {
        let (mut client, server) = ws_pair().await;
        drop(server); // half-close so the client sees EOF
        match recv_signal(&mut client).await {
            Err(HostError::Backend(msg)) => {
                assert!(
                    msg.contains("closed") || msg.contains("ended") || msg.contains("read failed"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected Backend error on EOF, got {:?}", other),
        }
    }
}
