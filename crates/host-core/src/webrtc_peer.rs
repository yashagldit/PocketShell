#![cfg(feature = "webrtc")]

use crate::error::{HostError, Result};
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use std::sync::Arc;

pub struct WebRtcChannels {
    pub terminal: Arc<RTCDataChannel>,
    pub control: Arc<RTCDataChannel>,
    pub stats: Arc<RTCDataChannel>,
}

pub struct WebRtcPeer {
    pub peer: Arc<RTCPeerConnection>,
    pub channels: Option<WebRtcChannels>,
}

impl WebRtcPeer {
    pub async fn new(turn_uris: Vec<String>, username: String, credential: String) -> Result<Self> {
        let mut media = MediaEngine::default();
        media
            .register_default_codecs()
            .map_err(|e| HostError::Backend(format!("webrtc codec registration failed: {e}")))?;

        let api = APIBuilder::new().with_media_engine(media).build();
        let config = RTCConfiguration {
            ice_servers: vec![webrtc::ice_transport::ice_server::RTCIceServer {
                urls: turn_uris,
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

        Ok(Self {
            peer,
            channels: None,
        })
    }

    pub async fn create_channels(&mut self) -> Result<()> {
        let terminal = self
            .peer
            .create_data_channel("terminal", Some(RTCDataChannelInit::default()))
            .await
            .map_err(|e| HostError::Backend(format!("terminal channel create failed: {e}")))?;

        let control = self
            .peer
            .create_data_channel("control", Some(RTCDataChannelInit::default()))
            .await
            .map_err(|e| HostError::Backend(format!("control channel create failed: {e}")))?;

        let stats = self
            .peer
            .create_data_channel("stats", Some(RTCDataChannelInit::default()))
            .await
            .map_err(|e| HostError::Backend(format!("stats channel create failed: {e}")))?;

        self.channels = Some(WebRtcChannels {
            terminal,
            control,
            stats,
        });
        Ok(())
    }

    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        let offer = self
            .peer
            .create_offer(None)
            .await
            .map_err(|e| HostError::Backend(format!("offer create failed: {e}")))?;

        self.peer
            .set_local_description(offer.clone())
            .await
            .map_err(|e| HostError::Backend(format!("set local offer failed: {e}")))?;

        Ok(offer)
    }

    pub async fn apply_offer(&self, offer: RTCSessionDescription) -> Result<RTCSessionDescription> {
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

        Ok(answer)
    }

    pub async fn apply_answer(&self, answer: RTCSessionDescription) -> Result<()> {
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
