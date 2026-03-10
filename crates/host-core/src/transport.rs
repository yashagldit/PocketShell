use crate::error::{HostError, Result};
use crate::models::ControlMessage;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn connect_control_plane(ws_url: &str, access_token: &str) -> Result<WsStream> {
    let full = if ws_url.contains('?') {
        format!("{ws_url}&access_token={access_token}")
    } else {
        format!("{ws_url}?access_token={access_token}")
    };

    let (socket, _) = connect_async(full)
        .await
        .map_err(|e| HostError::Backend(format!("control connection failed: {e}")))?;
    Ok(socket)
}

pub async fn send_msg(ws: &mut WsStream, msg: &ControlMessage) -> Result<()> {
    let raw = serde_json::to_string(msg)?;
    ws.send(Message::Text(raw.into()))
        .await
        .map_err(|e| HostError::Backend(format!("ws send failed: {e}")))
}

pub async fn recv_msg(ws: &mut WsStream) -> Result<Option<ControlMessage>> {
    match ws.next().await {
        Some(Ok(Message::Text(text))) => {
            let parsed = serde_json::from_str::<ControlMessage>(&text)
                .map_err(|e| HostError::Backend(format!("invalid control payload: {e}")))?;
            Ok(Some(parsed))
        }
        Some(Ok(Message::Binary(_))) => Ok(None),
        Some(Ok(Message::Close(_))) => Ok(None),
        Some(Ok(Message::Ping(_))) => Ok(None),
        Some(Ok(Message::Pong(_))) => Ok(None),
        Some(Ok(Message::Frame(_))) => Ok(None),
        Some(Err(e)) => Err(HostError::Backend(format!("ws read failed: {e}"))),
        None => Ok(None),
    }
}
