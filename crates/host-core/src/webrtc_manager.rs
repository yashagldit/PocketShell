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
    Input {
        session_id: String,
        mobile_device_id: String,
        data: Vec<u8>,
    },
    ChannelOpened {
        session_id: String,
    },
    ChannelClosed {
        session_id: String,
    },
    IceCandidate {
        mobile_device_id: String,
        candidate_json: String,
    },
    StatsChannelOpened {
        host_id: String,
    },
    StatsChannelClosed {
        host_id: String,
    },
}

pub struct WebRtcManager {
    peers: HashMap<String, WebRtcPeer>,
    /// Multiple data channels per session — supports multi-device viewing.
    session_channels: HashMap<String, Vec<Arc<RTCDataChannel>>>,
    /// Maps (session_id, mobile_device_id) to the index range of channels owned by that mobile.
    /// Used for cleanup when a specific mobile peer disconnects.
    channel_owners: Vec<(String, String, Arc<RTCDataChannel>)>, // (session_id, mobile_device_id, channel)
    /// Stats channels tracked per mobile peer for proper cleanup.
    stats_channel_owners: Vec<(String, Arc<RTCDataChannel>)>, // (mobile_device_id, channel)
    event_tx: mpsc::UnboundedSender<WebRtcEvent>,
}

impl WebRtcManager {
    pub fn new(event_tx: mpsc::UnboundedSender<WebRtcEvent>) -> Self {
        Self {
            peers: HashMap::new(),
            session_channels: HashMap::new(),
            channel_owners: Vec::new(),
            stats_channel_owners: Vec::new(),
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
            info!(
                "created WebRTC peer for mobile_device_id={}",
                mobile_device_id
            );
        }

        let peer = self
            .peers
            .get(mobile_device_id)
            .ok_or_else(|| HostError::Backend("peer not found after creation".into()))?;

        let answer_sdp = peer.apply_offer(offer_sdp).await?;
        info!(
            "applied offer, sending answer for mobile_device_id={}",
            mobile_device_id
        );

        Ok(answer_sdp)
    }

    pub async fn add_ice_candidate(
        &mut self,
        mobile_device_id: &str,
        candidate: RTCIceCandidateInit,
    ) -> Result<()> {
        let peer = self
            .peers
            .get(mobile_device_id)
            .ok_or_else(|| HostError::Backend(format!("no peer for mobile {mobile_device_id}")))?;
        peer.add_ice_candidate(candidate).await
    }

    pub async fn poll_events(&mut self) {
        let mobile_ids: Vec<String> = self.peers.keys().cloned().collect();

        for mobile_id in mobile_ids {
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

    /// Broadcast data to a set of channels, returning true if any send succeeded.
    /// Removes channels that fail to send (dead channel pruning).
    async fn broadcast(channels: &mut Vec<Arc<RTCDataChannel>>, data: &[u8], label: &str) -> bool {
        if channels.is_empty() {
            return false;
        }
        let bytes = bytes::Bytes::copy_from_slice(data);
        let mut any_sent = false;
        let mut failed_indices = Vec::new();
        for (i, channel) in channels.iter().enumerate() {
            match channel.send(&bytes).await {
                Ok(_) => any_sent = true,
                Err(e) => {
                    warn!("{} send failed: {}", label, e);
                    failed_indices.push(i);
                }
            }
        }
        // Prune dead channels on send failure
        for i in failed_indices.into_iter().rev() {
            channels.swap_remove(i);
        }
        any_sent
    }

    /// Send output to all connected data channels for a session (fan-out).
    pub async fn send_output(&mut self, session_id: &str, data: &[u8]) -> bool {
        if let Some(channels) = self.session_channels.get_mut(session_id) {
            Self::broadcast(channels, data, &format!("session {session_id}")).await
        } else {
            false
        }
    }

    pub fn has_channel(&self, session_id: &str) -> bool {
        self.session_channels
            .get(session_id)
            .map_or(false, |v| !v.is_empty())
    }

    /// Send stats data to all connected stats channels.
    pub async fn send_stats(&mut self, data: &[u8]) -> bool {
        let mut channels: Vec<Arc<RTCDataChannel>> = self
            .stats_channel_owners
            .iter()
            .map(|(_, ch)| Arc::clone(ch))
            .collect();
        let result = Self::broadcast(&mut channels, data, "stats").await;
        // If broadcast pruned any, sync back to owners
        if channels.len() != self.stats_channel_owners.len() {
            self.stats_channel_owners
                .retain(|(_, ch)| channels.iter().any(|c| Arc::ptr_eq(c, ch)));
        }
        result
    }

    pub fn has_stats_channel(&self) -> bool {
        !self.stats_channel_owners.is_empty()
    }

    /// Remove closed stats channels (called when StatsChannelClosed event fires).
    pub fn prune_stats_channels(&mut self) {
        self.stats_channel_owners.retain(|(_, ch)| {
            ch.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        });
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

        // Close terminal channels owned by this mobile device
        let (to_close, remaining): (Vec<_>, Vec<_>) = self
            .channel_owners
            .drain(..)
            .partition(|(_, mid, _)| mid == mobile_device_id);

        self.channel_owners = remaining;

        for (session_id, _, channel) in to_close {
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

        // Close stats channels owned by this specific peer
        let (stats_to_close, stats_remaining): (Vec<_>, Vec<_>) = self
            .stats_channel_owners
            .drain(..)
            .partition(|(mid, _)| mid == mobile_device_id);
        self.stats_channel_owners = stats_remaining;
        for (_, ch) in stats_to_close {
            tokio::spawn(async move {
                let _ = ch.close().await;
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

        if let Some(host_id) = label.strip_prefix("stats-") {
            info!(
                "stats data channel opened for host {} from mobile {}",
                host_id, mobile_id
            );
            self.stats_channel_owners
                .push((mobile_id.to_string(), Arc::clone(&channel)));

            let event_tx = self.event_tx.clone();
            let hid = host_id.to_string();
            channel.on_close(Box::new(move || {
                let tx = event_tx.clone();
                let host = hid.clone();
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::StatsChannelClosed { host_id: host });
                })
            }));

            let _ = self.event_tx.send(WebRtcEvent::StatsChannelOpened {
                host_id: host_id.to_string(),
            });
            return;
        }

        let session_id = if let Some(sid) = label.strip_prefix("terminal-") {
            sid.to_string()
        } else {
            warn!("ignoring unknown data channel label: {}", label);
            return;
        };

        info!(
            "data channel opened: {} for session {} from mobile {}",
            label, session_id, mobile_id
        );

        self.session_channels
            .entry(session_id.clone())
            .or_insert_with(Vec::new)
            .push(Arc::clone(&channel));
        self.channel_owners.push((
            session_id.clone(),
            mobile_id.to_string(),
            Arc::clone(&channel),
        ));

        let event_tx = self.event_tx.clone();
        let sid = session_id.clone();
        let mobile_device_id = mobile_id.to_string();
        channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = event_tx.clone();
            let session = sid.clone();
            let mobile = mobile_device_id.clone();
            Box::pin(async move {
                let _ = tx.send(WebRtcEvent::Input {
                    session_id: session,
                    mobile_device_id: mobile,
                    data: msg.data.to_vec(),
                });
            })
        }));

        let event_tx = self.event_tx.clone();
        let sid = session_id.clone();
        channel.on_close(Box::new(move || {
            let tx = event_tx.clone();
            let session = sid.clone();
            Box::pin(async move {
                let _ = tx.send(WebRtcEvent::ChannelClosed {
                    session_id: session,
                });
            })
        }));

        let _ = self
            .event_tx
            .send(WebRtcEvent::ChannelOpened { session_id });
    }
}
