#![cfg(feature = "webrtc")]

use crate::error::{HostError, Result};
use crate::webrtc_peer::{DataChannelEvent, WebRtcPeer};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

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
        peer_key: String,
        mobile_device_id: String,
        candidate_json: String,
    },
    StatsChannelOpened {
        host_id: String,
        mobile_device_id: String,
        channel: Arc<RTCDataChannel>,
    },
    StatsChannelClosed {
        host_id: String,
        mobile_device_id: String,
    },
    StatsMessage {
        mobile_device_id: String,
        data: Vec<u8>,
        channel: Arc<RTCDataChannel>,
    },
    FilesChannelOpened {
        mobile_device_id: String,
        channel: Arc<RTCDataChannel>,
    },
    FilesChannelClosed {
        mobile_device_id: String,
    },
    FilesMessage {
        mobile_device_id: String,
        data: Vec<u8>,
        channel: Arc<RTCDataChannel>,
    },
    ControlChannelOpened {
        mobile_device_id: String,
        channel: Arc<RTCDataChannel>,
    },
    ControlChannelClosed {
        mobile_device_id: String,
    },
    ControlMessage {
        mobile_device_id: String,
        data: Vec<u8>,
        channel: Arc<RTCDataChannel>,
    },
    AgentChannelOpened {
        agent_id: String,
        mobile_device_id: String,
        channel: Arc<RTCDataChannel>,
    },
    AgentChannelClosed {
        agent_id: String,
        mobile_device_id: String,
    },
    AgentMessage {
        agent_id: String,
        mobile_device_id: String,
        data: Vec<u8>,
        channel: Arc<RTCDataChannel>,
    },
}

impl std::fmt::Debug for WebRtcEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input {
                session_id,
                mobile_device_id,
                data,
            } => f
                .debug_struct("Input")
                .field("session_id", session_id)
                .field("mobile_device_id", mobile_device_id)
                .field("data_len", &data.len())
                .finish(),
            Self::ChannelOpened { session_id } => f
                .debug_struct("ChannelOpened")
                .field("session_id", session_id)
                .finish(),
            Self::ChannelClosed { session_id } => f
                .debug_struct("ChannelClosed")
                .field("session_id", session_id)
                .finish(),
            Self::IceCandidate {
                peer_key,
                mobile_device_id,
                ..
            } => f
                .debug_struct("IceCandidate")
                .field("peer_key", peer_key)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::StatsChannelOpened { host_id, mobile_device_id, .. } => f
                .debug_struct("StatsChannelOpened")
                .field("host_id", host_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::StatsChannelClosed { host_id, mobile_device_id } => f
                .debug_struct("StatsChannelClosed")
                .field("host_id", host_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::StatsMessage { mobile_device_id, data, .. } => f
                .debug_struct("StatsMessage")
                .field("mobile_device_id", mobile_device_id)
                .field("data_len", &data.len())
                .finish(),
            Self::FilesChannelOpened {
                mobile_device_id, ..
            } => f
                .debug_struct("FilesChannelOpened")
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::FilesChannelClosed { mobile_device_id } => f
                .debug_struct("FilesChannelClosed")
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::FilesMessage {
                mobile_device_id,
                data,
                ..
            } => f
                .debug_struct("FilesMessage")
                .field("mobile_device_id", mobile_device_id)
                .field("data_len", &data.len())
                .finish(),
            Self::ControlChannelOpened { mobile_device_id, .. } => f
                .debug_struct("ControlChannelOpened")
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::ControlChannelClosed { mobile_device_id } => f
                .debug_struct("ControlChannelClosed")
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::ControlMessage { mobile_device_id, data, .. } => f
                .debug_struct("ControlMessage")
                .field("mobile_device_id", mobile_device_id)
                .field("data_len", &data.len())
                .finish(),
            Self::AgentChannelOpened { agent_id, mobile_device_id, .. } => f
                .debug_struct("AgentChannelOpened")
                .field("agent_id", agent_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::AgentChannelClosed { agent_id, mobile_device_id } => f
                .debug_struct("AgentChannelClosed")
                .field("agent_id", agent_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::AgentMessage { agent_id, mobile_device_id, data, .. } => f
                .debug_struct("AgentMessage")
                .field("agent_id", agent_id)
                .field("mobile_device_id", mobile_device_id)
                .field("data_len", &data.len())
                .finish(),
        }
    }
}

pub struct WebRtcManager {
    peers: HashMap<String, WebRtcPeer>,
    /// Multiple data channels per session — supports multi-device viewing.
    session_channels: HashMap<String, Vec<Arc<RTCDataChannel>>>,
    /// Maps (session_id, mobile_device_id) to the index range of channels owned by that mobile.
    /// Used for cleanup when a specific mobile peer disconnects.
    channel_owners: Vec<(String, String, Arc<RTCDataChannel>)>, // (session_id, peer_key, channel)
    /// Stats channels tracked per mobile peer for proper cleanup.
    stats_channel_owners: Vec<(String, Arc<RTCDataChannel>)>, // (peer_key, channel)
    /// Files channels tracked per mobile peer for proper cleanup.
    files_channel_owners: Vec<(String, Arc<RTCDataChannel>)>, // (peer_key, channel)
    /// Control channels tracked per mobile peer for proper cleanup.
    control_channel_owners: Vec<(String, Arc<RTCDataChannel>)>, // (peer_key, channel)
    /// Agent chat channels: one channel per `agent-{id}` label.
    /// Tracked by `(peer_key, agent_id, channel)` so we can prune by either
    /// peer disconnect or session close.
    agent_channel_owners: Vec<(String, String, Arc<RTCDataChannel>)>,
    event_tx: mpsc::UnboundedSender<WebRtcEvent>,
}

fn base_mobile_id(peer_key: &str) -> &str {
    peer_key.strip_prefix("files:").unwrap_or(peer_key)
}

impl WebRtcManager {
    pub fn new(event_tx: mpsc::UnboundedSender<WebRtcEvent>) -> Self {
        Self {
            peers: HashMap::new(),
            session_channels: HashMap::new(),
            channel_owners: Vec::new(),
            stats_channel_owners: Vec::new(),
            files_channel_owners: Vec::new(),
            control_channel_owners: Vec::new(),
            agent_channel_owners: Vec::new(),
            event_tx,
        }
    }

    pub async fn handle_offer(
        &mut self,
        peer_key: &str,
        turn_uris: Vec<String>,
        username: String,
        credential: String,
        offer_sdp: &str,
        force_new_peer: bool,
    ) -> Result<String> {
        let should_create = match self.peers.get(peer_key) {
            None => true,
            Some(peer) => {
                let state = peer.connection_state();
                // Don't replace a peer that is still connecting — TURN allocation
                // can take several seconds and killing it mid-flight causes cascading
                // failures.  Return empty answer so the mobile knows to wait.
                if state == RTCPeerConnectionState::Connecting {
                    warn!(
                        "skipping offer for peer_key={} — peer still connecting",
                        peer_key
                    );
                    return Ok(String::new());
                }
                force_new_peer
                    || matches!(
                        state,
                        RTCPeerConnectionState::Failed
                            | RTCPeerConnectionState::Closed
                            | RTCPeerConnectionState::Disconnected
                    )
            }
        };
        if should_create {
            if let Some(old) = self.peers.remove(peer_key) {
                info!(
                    "replacing WebRTC peer for peer_key={} (state={:?}, forced={})",
                    peer_key,
                    old.connection_state(),
                    force_new_peer
                );
                old.close().await;
            }
            let peer = WebRtcPeer::new(turn_uris, username, credential).await?;
            self.peers.insert(peer_key.to_string(), peer);
            info!("created WebRTC peer for peer_key={}", peer_key);
        }

        let peer = self
            .peers
            .get(peer_key)
            .ok_or_else(|| HostError::Backend("peer not found after creation".into()))?;

        let answer_sdp = peer.apply_offer(offer_sdp).await?;
        info!("applied offer, sending answer for peer_key={}", peer_key);

        Ok(answer_sdp)
    }

    pub async fn add_ice_candidate(
        &mut self,
        peer_key: &str,
        candidate: RTCIceCandidateInit,
    ) -> Result<()> {
        let peer = self
            .peers
            .get(peer_key)
            .ok_or_else(|| HostError::Backend(format!("no peer for {peer_key}")))?;
        peer.add_ice_candidate(candidate).await
    }

    pub async fn poll_events(&mut self) {
        let peer_keys: Vec<String> = self.peers.keys().cloned().collect();
        let mut peers_to_close: Vec<String> = Vec::new();

        for peer_key in peer_keys {
            let mut dc_events: Vec<DataChannelEvent> = Vec::new();
            let mut ice_candidates: Vec<webrtc::ice_transport::ice_candidate::RTCIceCandidate> =
                Vec::new();

            if let Some(peer) = self.peers.get_mut(&peer_key) {
                let state = peer.connection_state();
                if matches!(
                    state,
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) {
                    warn!(
                        "closing WebRTC peer for peer_key={} due to peer state {:?}",
                        peer_key, state
                    );
                    peers_to_close.push(peer_key.clone());
                    continue;
                }
                while let Ok(dc_event) = peer.channel_rx.try_recv() {
                    dc_events.push(dc_event);
                }
                while let Ok(candidate) = peer.ice_tx.try_recv() {
                    ice_candidates.push(candidate);
                }
            }

            for dc_event in dc_events {
                self.handle_new_channel(&peer_key, dc_event).await;
            }

            for candidate in ice_candidates {
                if let Ok(json) = candidate.to_json() {
                    let json_str = serde_json::to_string(&json).unwrap_or_default();
                    let _ = self.event_tx.send(WebRtcEvent::IceCandidate {
                        peer_key: peer_key.clone(),
                        mobile_device_id: base_mobile_id(&peer_key).to_string(),
                        candidate_json: json_str,
                    });
                }
            }
        }

        for peer_key in peers_to_close {
            self.close_peer(&peer_key).await;
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
            match timeout(Duration::from_millis(500), channel.send(&bytes)).await {
                Ok(Ok(_)) => any_sent = true,
                Ok(Err(e)) => {
                    warn!("{} send failed: {}", label, e);
                    failed_indices.push(i);
                }
                Err(_) => {
                    warn!("{} send timed out; pruning channel", label);
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

    /// Remove closed terminal channels for a session (called when ChannelClosed event fires).
    pub fn prune_session_channels(&mut self, session_id: &str) {
        use webrtc::data_channel::data_channel_state::RTCDataChannelState;
        if let Some(channels) = self.session_channels.get_mut(session_id) {
            channels.retain(|ch| ch.ready_state() == RTCDataChannelState::Open);
            if channels.is_empty() {
                self.session_channels.remove(session_id);
            }
        }
        self.channel_owners.retain(|(sid, _, ch)| {
            sid != session_id || ch.ready_state() == RTCDataChannelState::Open
        });
    }

    /// Remove closed stats channels (called when StatsChannelClosed event fires).
    pub fn prune_stats_channels(&mut self) {
        self.stats_channel_owners.retain(|(_, ch)| {
            ch.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        });
    }

    /// Remove closed files channels (called when FilesChannelClosed event fires).
    pub fn prune_files_channels(&mut self) {
        self.files_channel_owners.retain(|(_, ch)| {
            ch.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        });
    }

    /// Remove closed control channels (called when ControlChannelClosed event fires).
    pub fn prune_control_channels(&mut self) {
        self.control_channel_owners.retain(|(_, ch)| {
            ch.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        });
    }

    /// Drop any agent channels whose underlying data channel has closed. The
    /// daemon's pump task writes via the `Arc<RTCDataChannel>` it captured at
    /// open-time, so we don't need fan-out here — only cleanup on close.
    pub fn prune_agent_channels(&mut self) {
        self.agent_channel_owners.retain(|(_, _, ch)| {
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

    pub async fn close_peer(&mut self, peer_key: &str) {
        if let Some(peer) = self.peers.remove(peer_key) {
            peer.close().await;
        }

        // Close terminal channels owned by this specific peer.
        let (to_close, remaining): (Vec<_>, Vec<_>) = self
            .channel_owners
            .drain(..)
            .partition(|(_, owner_peer_key, _)| owner_peer_key == peer_key);

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

        // Close stats channels owned by this specific peer.
        let (stats_to_close, stats_remaining): (Vec<_>, Vec<_>) = self
            .stats_channel_owners
            .drain(..)
            .partition(|(owner_peer_key, _)| owner_peer_key == peer_key);
        self.stats_channel_owners = stats_remaining;
        for (_, ch) in stats_to_close {
            tokio::spawn(async move {
                let _ = ch.close().await;
            });
        }

        // Close files channels owned by this specific peer.
        let (files_to_close, files_remaining): (Vec<_>, Vec<_>) = self
            .files_channel_owners
            .drain(..)
            .partition(|(owner_peer_key, _)| owner_peer_key == peer_key);
        self.files_channel_owners = files_remaining;
        for (_, ch) in files_to_close {
            tokio::spawn(async move {
                let _ = ch.close().await;
            });
        }

        // Close control channels owned by this specific peer.
        let (ctrl_to_close, ctrl_remaining): (Vec<_>, Vec<_>) = self
            .control_channel_owners
            .drain(..)
            .partition(|(owner_peer_key, _)| owner_peer_key == peer_key);
        self.control_channel_owners = ctrl_remaining;
        for (_, ch) in ctrl_to_close {
            tokio::spawn(async move {
                let _ = ch.close().await;
            });
        }

        // Close agent channels owned by this specific peer.
        let (agent_to_close, agent_remaining): (Vec<_>, Vec<_>) = self
            .agent_channel_owners
            .drain(..)
            .partition(|(owner_peer_key, _, _)| owner_peer_key == peer_key);
        self.agent_channel_owners = agent_remaining;
        for (_, _, ch) in agent_to_close {
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

    async fn handle_new_channel(&mut self, peer_key: &str, dc_event: DataChannelEvent) {
        let mobile_id = base_mobile_id(peer_key).to_string();
        let label = dc_event.label.clone();
        let channel = dc_event.channel;

        if let Some(host_id) = label.strip_prefix("stats-") {
            info!(
                "stats data channel opened for host {} from mobile {} peer_key={}",
                host_id, mobile_id, peer_key
            );
            self.stats_channel_owners
                .push((peer_key.to_string(), Arc::clone(&channel)));

            let event_tx_msg = self.event_tx.clone();
            let mid_msg = mobile_id.clone();
            let ch_msg = Arc::clone(&channel);
            channel.on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = event_tx_msg.clone();
                let mobile = mid_msg.clone();
                let ch = Arc::clone(&ch_msg);
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::StatsMessage {
                        mobile_device_id: mobile,
                        data: msg.data.to_vec(),
                        channel: ch,
                    });
                })
            }));

            let event_tx = self.event_tx.clone();
            let hid = host_id.to_string();
            let mid_close = mobile_id.clone();
            channel.on_close(Box::new(move || {
                let tx = event_tx.clone();
                let host = hid.clone();
                let mobile = mid_close.clone();
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::StatsChannelClosed {
                        host_id: host,
                        mobile_device_id: mobile,
                    });
                })
            }));

            let _ = self.event_tx.send(WebRtcEvent::StatsChannelOpened {
                host_id: host_id.to_string(),
                mobile_device_id: mobile_id.to_string(),
                channel: Arc::clone(&channel),
            });
            return;
        }

        if label.starts_with("control-") {
            info!(
                "control data channel opened from mobile {} peer_key={}",
                mobile_id, peer_key
            );
            self.control_channel_owners
                .push((peer_key.to_string(), Arc::clone(&channel)));

            let event_tx_msg = self.event_tx.clone();
            let mid = mobile_id.to_string();
            let ch = Arc::clone(&channel);
            channel.on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = event_tx_msg.clone();
                let mobile = mid.clone();
                let channel = Arc::clone(&ch);
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::ControlMessage {
                        mobile_device_id: mobile,
                        data: msg.data.to_vec(),
                        channel,
                    });
                })
            }));

            let event_tx = self.event_tx.clone();
            let mid = mobile_id.to_string();
            channel.on_close(Box::new(move || {
                let tx = event_tx.clone();
                let mobile = mid.clone();
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::ControlChannelClosed {
                        mobile_device_id: mobile,
                    });
                })
            }));

            let _ = self.event_tx.send(WebRtcEvent::ControlChannelOpened {
                mobile_device_id: mobile_id.to_string(),
                channel: Arc::clone(&channel),
            });
            return;
        }

        if let Some(agent_id) = label.strip_prefix("agent-") {
            info!(
                "agent data channel opened for agent {} from mobile {} peer_key={}",
                agent_id, mobile_id, peer_key
            );
            let agent_id = agent_id.to_string();
            self.agent_channel_owners.push((
                peer_key.to_string(),
                agent_id.clone(),
                Arc::clone(&channel),
            ));

            let event_tx_msg = self.event_tx.clone();
            let mid_msg = mobile_id.clone();
            let aid_msg = agent_id.clone();
            let ch_msg = Arc::clone(&channel);
            channel.on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = event_tx_msg.clone();
                let mobile = mid_msg.clone();
                let agent = aid_msg.clone();
                let channel = Arc::clone(&ch_msg);
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::AgentMessage {
                        agent_id: agent,
                        mobile_device_id: mobile,
                        data: msg.data.to_vec(),
                        channel,
                    });
                })
            }));

            let event_tx = self.event_tx.clone();
            let mid_close = mobile_id.clone();
            let aid_close = agent_id.clone();
            channel.on_close(Box::new(move || {
                let tx = event_tx.clone();
                let mobile = mid_close.clone();
                let agent = aid_close.clone();
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::AgentChannelClosed {
                        agent_id: agent,
                        mobile_device_id: mobile,
                    });
                })
            }));

            let _ = self.event_tx.send(WebRtcEvent::AgentChannelOpened {
                agent_id,
                mobile_device_id: mobile_id.clone(),
                channel: Arc::clone(&channel),
            });
            return;
        }

        if label.starts_with("files-") {
            info!(
                "files data channel opened from mobile {} peer_key={}",
                mobile_id, peer_key
            );
            self.files_channel_owners
                .push((peer_key.to_string(), Arc::clone(&channel)));

            let event_tx_msg = self.event_tx.clone();
            let mid = mobile_id.to_string();
            let ch = Arc::clone(&channel);
            channel.on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = event_tx_msg.clone();
                let mobile = mid.clone();
                let channel = Arc::clone(&ch);
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::FilesMessage {
                        mobile_device_id: mobile,
                        data: msg.data.to_vec(),
                        channel,
                    });
                })
            }));

            let event_tx = self.event_tx.clone();
            let mid = mobile_id.to_string();
            channel.on_close(Box::new(move || {
                let tx = event_tx.clone();
                let mobile = mid.clone();
                Box::pin(async move {
                    let _ = tx.send(WebRtcEvent::FilesChannelClosed {
                        mobile_device_id: mobile,
                    });
                })
            }));

            let _ = self.event_tx.send(WebRtcEvent::FilesChannelOpened {
                mobile_device_id: mobile_id.to_string(),
                channel: Arc::clone(&channel),
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
            peer_key.to_string(),
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
