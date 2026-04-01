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

/// Returns `Ok(Some(signal))` for a valid message, `Ok(None)` for keep-alive
/// frames (ping/pong/binary), and `Err` for real disconnects or errors.
pub async fn recv_signal(ws: &mut WsStream) -> Result<Option<SignalEnvelope>> {
    let msg = tokio::time::timeout(Duration::from_secs(90), ws.next())
        .await
        .map_err(|_| HostError::Backend("ws read timed out (no message for 90s)".into()))?;
    match msg {
        Some(Ok(Message::Text(text))) => {
            let parsed = serde_json::from_str::<SignalEnvelope>(&text)
                .map_err(|e| HostError::Backend(format!("invalid control payload: {e}")))?;
            Ok(Some(parsed))
        }
        Some(Ok(Message::Ping(data))) => {
            ws.send(Message::Pong(data)).await.ok();
            Ok(None)
        }
        Some(Ok(Message::Pong(_))) => Ok(None),
        Some(Ok(Message::Binary(_))) => Ok(None),
        Some(Ok(Message::Frame(_))) => Ok(None),
        Some(Ok(Message::Close(_))) => Err(HostError::Backend("ws closed by server".into())),
        Some(Err(e)) => Err(HostError::Backend(format!("ws read failed: {e}"))),
        None => Err(HostError::Backend("ws stream ended".into())),
    }
}
