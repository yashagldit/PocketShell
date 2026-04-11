#![cfg(feature = "webrtc")]

use crate::error::{HostError, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// A data channel event received from the remote peer.
pub struct DataChannelEvent {
    pub label: String,
    pub channel: Arc<RTCDataChannel>,
}

/// A WebRTC peer that acts as an answerer (host side).
pub struct WebRtcPeer {
    pub peer: Arc<RTCPeerConnection>,
    /// Receives newly opened data channels from the remote peer.
    pub channel_rx: mpsc::Receiver<DataChannelEvent>,
    /// Receives ICE candidates to send back via signaling.
    pub ice_tx: mpsc::Receiver<RTCIceCandidate>,
}

impl WebRtcPeer {
    pub async fn new(turn_uris: Vec<String>, username: String, credential: String) -> Result<Self> {
        let mut media = MediaEngine::default();
        media
            .register_default_codecs()
            .map_err(|e| HostError::Backend(format!("webrtc codec registration failed: {e}")))?;

        let api = APIBuilder::new().with_media_engine(media).build();
        // webrtc-rs doesn't support turns: (TURN-over-TLS) or transport=tcp;
        // filter to URIs this library can handle.
        let supported_uris: Vec<String> = turn_uris
            .into_iter()
            .filter(|u| !u.starts_with("turns:") && !u.contains("transport=tcp"))
            .collect();
        let config = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: supported_uris,
                username,
                credential,
                ..Default::default()
            }],
            ..Default::default()
        };

        let peer = Arc::new(
            api.new_peer_connection(config)
                .await
                .map_err(|e| HostError::Backend(format!("peer connection create failed: {e}")))?,
        );

        // Channel for receiving data channels from mobile
        let (ch_tx, channel_rx) = mpsc::channel::<DataChannelEvent>(16);
        peer.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let tx = ch_tx.clone();
            let label = dc.label().to_string();
            Box::pin(async move {
                let _ = tx.send(DataChannelEvent { label, channel: dc }).await;
            })
        }));

        // Channel for sending ICE candidates back to mobile
        let (ice_out_tx, ice_tx) = mpsc::channel::<RTCIceCandidate>(32);
        peer.on_ice_candidate(Box::new(move |candidate| {
            let tx = ice_out_tx.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    let _ = tx.send(c).await;
                }
            })
        }));

        Ok(Self {
            peer,
            channel_rx,
            ice_tx,
        })
    }

    /// Apply an offer from mobile, create and return an answer SDP.
    pub async fn apply_offer(&self, sdp: &str) -> Result<String> {
        let offer = RTCSessionDescription::offer(sdp.to_string())
            .map_err(|e| HostError::Backend(format!("invalid offer SDP: {e}")))?;

        self.peer
            .set_remote_description(offer)
            .await
            .map_err(|e| HostError::Backend(format!("set remote offer failed: {e}")))?;

        let answer = self
            .peer
            .create_answer(None)
            .await
            .map_err(|e| HostError::Backend(format!("answer create failed: {e}")))?;

        self.peer
            .set_local_description(answer.clone())
            .await
            .map_err(|e| HostError::Backend(format!("set local answer failed: {e}")))?;

        Ok(answer.sdp)
    }

    /// Create a local data channel and generate an SDP offer.
    pub async fn create_offer_with_data_channel(
        &self,
        label: &str,
    ) -> Result<(Arc<RTCDataChannel>, String)> {
        let data_channel = self
            .peer
            .create_data_channel(
                label,
                Some(RTCDataChannelInit {
                    ordered: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| HostError::Backend(format!("create data channel failed: {e}")))?;

        let offer = self
            .peer
            .create_offer(None)
            .await
            .map_err(|e| HostError::Backend(format!("offer create failed: {e}")))?;

        self.peer
            .set_local_description(offer.clone())
            .await
            .map_err(|e| HostError::Backend(format!("set local offer failed: {e}")))?;

        Ok((data_channel, offer.sdp))
    }

    /// Apply an answer SDP to a previously created local offer.
    pub async fn apply_answer(&self, sdp: &str) -> Result<()> {
        let answer = RTCSessionDescription::answer(sdp.to_string())
            .map_err(|e| HostError::Backend(format!("invalid answer SDP: {e}")))?;

        self.peer
            .set_remote_description(answer)
            .await
            .map_err(|e| HostError::Backend(format!("set remote answer failed: {e}")))
    }

    pub async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<()> {
        self.peer
            .add_ice_candidate(candidate)
            .await
            .map_err(|e| HostError::Backend(format!("add ice candidate failed: {e}")))
    }

    pub async fn close(&self) {
        let _ = self.peer.close().await;
    }

    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.peer.connection_state()
    }
}
