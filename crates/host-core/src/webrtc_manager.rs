#![cfg(feature = "webrtc")]

use crate::error::{HostError, Result};
use crate::webrtc_peer::{DataChannelEvent, WebRtcPeer};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

#[derive(Debug)]
pub enum WebRtcEvent {
    Input { session_id: String, data: Vec<u8> },
    ChannelOpened { session_id: String },
    ChannelClosed { session_id: String },
    IceCandidate { mobile_device_id: String, candidate_json: String },
}

pub struct WebRtcManager {
    peers: HashMap<String, WebRtcPeer>,
    /// Multiple data channels per session — supports multi-device viewing.
    session_channels: HashMap<String, Vec<Arc<RTCDataChannel>>>,
    /// Maps (session_id, mobile_device_id) to the index range of channels owned by that mobile.
    /// Used for cleanup when a specific mobile peer disconnects.
    channel_owners: Vec<(String, String, Arc<RTCDataChannel>)>, // (session_id, mobile_device_id, channel)
    event_tx: mpsc::UnboundedSender<WebRtcEvent>,
}

impl WebRtcManager {
    pub fn new(event_tx: mpsc::UnboundedSender<WebRtcEvent>) -> Self {
        Self {
            peers: HashMap::new(),
            session_channels: HashMap::new(),
            channel_owners: Vec::new(),
            event_tx,
        }
    }

    pub async fn handle_offer(
        &mut self,
        mobile_device_id: &str,
        turn_uris: Vec<String>,
        username: String,
        credential: String,
        offer_sdp: &str,
    ) -> Result<String> {
        if !self.peers.contains_key(mobile_device_id) {
            let peer = WebRtcPeer::new(turn_uris, username, credential).await?;
            self.peers.insert(mobile_device_id.to_string(), peer);
            info!("created WebRTC peer for mobile_device_id={}", mobile_device_id);
        }

        let peer = self.peers.get(mobile_device_id)
            .ok_or_else(|| HostError::Backend("peer not found after creation".into()))?;

        let answer_sdp = peer.apply_offer(offer_sdp).await?;
        info!("applied offer, sending answer for mobile_device_id={}", mobile_device_id);

        Ok(answer_sdp)
    }

    pub async fn add_ice_candidate(
        &mut self,
        mobile_device_id: &str,
        candidate: RTCIceCandidateInit,
    ) -> Result<()> {
        let peer = self.peers.get(mobile_device_id)
            .ok_or_else(|| HostError::Backend(format!("no peer for mobile {mobile_device_id}")))?;
        peer.add_ice_candidate(candidate).await
    }

    pub async fn poll_events(&mut self) {
        let mobile_ids: Vec<String> = self.peers.keys().cloned().collect();

        for mobile_id in mobile_ids {
            // Collect all events from this peer before processing to satisfy borrow checker
            let mut dc_events: Vec<DataChannelEvent> = Vec::new();
            let mut ice_candidates: Vec<webrtc::ice_transport::ice_candidate::RTCIceCandidate> =
                Vec::new();

            if let Some(peer) = self.peers.get_mut(&mobile_id) {
                while let Ok(dc_event) = peer.channel_rx.try_recv() {
                    dc_events.push(dc_event);
                }
                while let Ok(candidate) = peer.ice_tx.try_recv() {
                    ice_candidates.push(candidate);
                }
            }

            for dc_event in dc_events {
                self.handle_new_channel(&mobile_id, dc_event).await;
            }

            for candidate in ice_candidates {
                if let Ok(json) = candidate.to_json() {
                    let json_str = serde_json::to_string(&json).unwrap_or_default();
                    let _ = self.event_tx.send(WebRtcEvent::IceCandidate {
                        mobile_device_id: mobile_id.clone(),
                        candidate_json: json_str,
                    });
                }
            }
        }
    }

    /// Send output to all connected data channels for a session (fan-out).
    pub async fn send_output(&self, session_id: &str, data: &[u8]) -> bool {
        if let Some(channels) = self.session_channels.get(session_id) {
            if channels.is_empty() {
                return false;
            }
            let bytes = bytes::Bytes::copy_from_slice(data);
            let mut any_sent = false;
            for channel in channels {
                match channel.send(&bytes).await {
                    Ok(_) => any_sent = true,
                    Err(e) => {
                        warn!("webrtc send failed for session {}: {}", session_id, e);
                    }
                }
            }
            any_sent
        } else {
            false
        }
    }

    pub fn has_channel(&self, session_id: &str) -> bool {
        self.session_channels.get(session_id).map_or(false, |v| !v.is_empty())
    }

    pub fn close_session(&mut self, session_id: &str) {
        if let Some(channels) = self.session_channels.remove(session_id) {
            for channel in channels {
                tokio::spawn(async move {
                    let _ = channel.close().await;
                });
            }
        }
        self.channel_owners.retain(|(sid, _, _)| sid != session_id);
    }

    pub async fn close_peer(&mut self, mobile_device_id: &str) {
        if let Some(peer) = self.peers.remove(mobile_device_id) {
            peer.close().await;
        }

        // Collect channels owned by this mobile device
        let (to_close, remaining): (Vec<_>, Vec<_>) = self.channel_owners.drain(..)
            .partition(|(_, mid, _)| mid == mobile_device_id);

        self.channel_owners = remaining;

        // Close the channels and remove them from session_channels
        for (session_id, _, channel) in to_close {
            // Remove this specific channel from the session's channel vec
            if let Some(channels) = self.session_channels.get_mut(&session_id) {
                channels.retain(|c| !Arc::ptr_eq(c, &channel));
                if channels.is_empty() {
                    self.session_channels.remove(&session_id);
                }
            }
            tokio::spawn(async move {
                let _ = channel.close().await;
            });
        }
    }

    pub async fn close_all(&mut self) {
        let ids: Vec<String> = self.peers.keys().cloned().collect();
        for id in ids {
            self.close_peer(&id).await;
        }
    }

    async fn handle_new_channel(&mut self, mobile_id: &str, dc_event: DataChannelEvent) {
        let label = dc_event.label.clone();
        let channel = dc_event.channel;

        let session_id = if let Some(sid) = label.strip_prefix("terminal-") {
            sid.to_string()
        } else {
            warn!("ignoring unknown data channel label: {}", label);
            return;
        };

        info!("data channel opened: {} for session {} from mobile {}", label, session_id, mobile_id);

        self.session_channels
            .entry(session_id.clone())
            .or_insert_with(Vec::new)
            .push(Arc::clone(&channel));
        self.channel_owners.push((session_id.clone(), mobile_id.to_string(), Arc::clone(&channel)));

        // on_message is async in webrtc 0.14 — returns Pin<Box<dyn Future>>
        let event_tx = self.event_tx.clone();
        let sid = session_id.clone();
        channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = event_tx.clone();
            let session = sid.clone();
            Box::pin(async move {
                let _ = tx.send(WebRtcEvent::Input {
                    session_id: session,
                    data: msg.data.to_vec(),
                });
            })
        }));

        // on_close is also async in webrtc 0.14
        let event_tx = self.event_tx.clone();
        let sid = session_id.clone();
        channel.on_close(Box::new(move || {
            let tx = event_tx.clone();
            let session = sid.clone();
            Box::pin(async move {
                let _ = tx.send(WebRtcEvent::ChannelClosed { session_id: session });
            })
        }));

        let _ = self.event_tx.send(WebRtcEvent::ChannelOpened {
            session_id,
        });
    }
}
