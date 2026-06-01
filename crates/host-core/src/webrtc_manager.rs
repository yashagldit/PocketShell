#![cfg(feature = "webrtc")]

use crate::error::{HostError, Result};
use crate::webrtc_peer::{DataChannelEvent, WebRtcPeer};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

/// How long a peer may sit in `Disconnected` before we tear it down. Matches
/// the spec-recommended grace period: shorter than the ~30s the browser takes
/// to reach `Failed`, but long enough that a transient network blip or mobile
/// ICE-restart attempt can recover without losing the peer.
const DISCONNECTED_GRACE: Duration = Duration::from_secs(20);
const RELAY_STATS_TIMEOUT: Duration = Duration::from_secs(3);
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
            Self::StatsChannelOpened {
                host_id,
                mobile_device_id,
                ..
            } => f
                .debug_struct("StatsChannelOpened")
                .field("host_id", host_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::StatsChannelClosed {
                host_id,
                mobile_device_id,
            } => f
                .debug_struct("StatsChannelClosed")
                .field("host_id", host_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::StatsMessage {
                mobile_device_id,
                data,
                ..
            } => f
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
            Self::ControlChannelOpened {
                mobile_device_id, ..
            } => f
                .debug_struct("ControlChannelOpened")
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::ControlChannelClosed { mobile_device_id } => f
                .debug_struct("ControlChannelClosed")
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::ControlMessage {
                mobile_device_id,
                data,
                ..
            } => f
                .debug_struct("ControlMessage")
                .field("mobile_device_id", mobile_device_id)
                .field("data_len", &data.len())
                .finish(),
            Self::AgentChannelOpened {
                agent_id,
                mobile_device_id,
                ..
            } => f
                .debug_struct("AgentChannelOpened")
                .field("agent_id", agent_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::AgentChannelClosed {
                agent_id,
                mobile_device_id,
            } => f
                .debug_struct("AgentChannelClosed")
                .field("agent_id", agent_id)
                .field("mobile_device_id", mobile_device_id)
                .finish(),
            Self::AgentMessage {
                agent_id,
                mobile_device_id,
                data,
                ..
            } => f
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
    /// Relay-bytes carried over from peers that were closed since the last
    /// `collect_relay_delta` call. Prevents tail bytes from being lost when
    /// a peer closes mid-interval.
    pending_relay_bytes: u64,
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
    /// First time we observed each peer in `Disconnected` state. Cleared once
    /// the peer recovers; used to enforce `DISCONNECTED_GRACE` before teardown.
    disconnected_since: HashMap<String, Instant>,
    event_tx: mpsc::UnboundedSender<WebRtcEvent>,
}

fn base_mobile_id(peer_key: &str) -> &str {
    peer_key
        .strip_prefix("files:")
        .or_else(|| peer_key.strip_prefix("agent:"))
        .or_else(|| peer_key.strip_prefix("stats:"))
        .unwrap_or(peer_key)
}

impl WebRtcManager {
    pub fn new(event_tx: mpsc::UnboundedSender<WebRtcEvent>) -> Self {
        Self {
            peers: HashMap::new(),
            pending_relay_bytes: 0,
            session_channels: HashMap::new(),
            channel_owners: Vec::new(),
            stats_channel_owners: Vec::new(),
            files_channel_owners: Vec::new(),
            control_channel_owners: Vec::new(),
            agent_channel_owners: Vec::new(),
            disconnected_since: HashMap::new(),
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
                // failures. Exception: if the caller explicitly asked for a fresh
                // peer (`force_new_peer`), the mobile side has already torn down
                // its end and the existing peer is dead from its perspective; keeping
                // it just causes a 30s ICE timeout. Return empty otherwise so the
                // mobile knows to wait.
                if state == RTCPeerConnectionState::Connecting && !force_new_peer {
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
            self.disconnected_since.remove(peer_key);
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
                if matches!(state, RTCPeerConnectionState::Disconnected) {
                    let entered = self
                        .disconnected_since
                        .entry(peer_key.clone())
                        .or_insert_with(Instant::now);
                    if entered.elapsed() >= DISCONNECTED_GRACE {
                        warn!(
                            "closing WebRTC peer for peer_key={} after {:?} in Disconnected",
                            peer_key,
                            entered.elapsed()
                        );
                        peers_to_close.push(peer_key.clone());
                        continue;
                    }
                } else if self.disconnected_since.remove(&peer_key).is_some() {
                    info!(
                        "WebRTC peer for peer_key={} recovered from Disconnected (state={:?})",
                        peer_key, state
                    );
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

    pub fn channel_count(&self, session_id: &str) -> usize {
        self.session_channels.get(session_id).map_or(0, |v| v.len())
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
        if let Some(mut peer) = self.peers.remove(peer_key) {
            let tail = Self::collect_peer_relay_delta(peer_key, &mut peer).await;
            self.pending_relay_bytes = self.pending_relay_bytes.saturating_add(tail);
            // webrtc-rs's RTCPeerConnection::close() can hang indefinitely when
            // the ICE agent is already in a Failed state. Fire-and-forget with a
            // timeout so a stuck close never wedges our caller (the main select
            // loop calls this via poll_events → close_peer).
            tokio::spawn(async move {
                let _ = timeout(Duration::from_secs(5), peer.close()).await;
            });
        }
        self.disconnected_since.remove(peer_key);

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

    /// Collect total relay bytes (sent+received) across every active peer since
    /// the previous call, plus any tail bytes carried over from peers that were
    /// closed in the meantime.
    pub async fn collect_relay_delta(&mut self) -> u64 {
        let mut total: u64 = 0;
        for (peer_key, peer) in self.peers.iter_mut() {
            let d = Self::collect_peer_relay_delta(peer_key, peer).await;
            total = total.saturating_add(d);
        }
        total = total.saturating_add(self.pending_relay_bytes);
        self.pending_relay_bytes = 0;
        total
    }

    async fn collect_peer_relay_delta(peer_key: &str, peer: &mut WebRtcPeer) -> u64 {
        match timeout(RELAY_STATS_TIMEOUT, peer.collect_relay_delta()).await {
            Ok(delta) => delta,
            Err(_) => {
                warn!(
                    "collect_relay_delta timed out for peer_key={} after {:?}; skipping relay accounting",
                    peer_key, RELAY_STATS_TIMEOUT
                );
                0
            }
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

#[cfg(all(test, feature = "webrtc"))]
mod tests {
    use super::*;

    #[test]
    fn base_mobile_id_strips_files_prefix() {
        assert_eq!(base_mobile_id("files:abc-123"), "abc-123");
    }

    #[test]
    fn base_mobile_id_leaves_plain_key_unchanged() {
        assert_eq!(base_mobile_id("mobile-device-xyz"), "mobile-device-xyz");
    }

    #[test]
    fn base_mobile_id_only_strips_at_prefix() {
        // The "files:" prefix should only be stripped when it appears at the start.
        assert_eq!(base_mobile_id("foo-files:bar"), "foo-files:bar");
    }

    #[test]
    fn base_mobile_id_handles_empty_after_prefix() {
        assert_eq!(base_mobile_id("files:"), "");
    }

    #[test]
    fn base_mobile_id_handles_empty_input() {
        assert_eq!(base_mobile_id(""), "");
    }

    #[test]
    fn base_mobile_id_strips_agent_prefix() {
        assert_eq!(base_mobile_id("agent:abc-123"), "abc-123");
    }

    #[test]
    fn base_mobile_id_handles_empty_after_agent_prefix() {
        assert_eq!(base_mobile_id("agent:"), "");
    }

    #[test]
    fn base_mobile_id_strips_stats_prefix() {
        assert_eq!(base_mobile_id("stats:abc-123"), "abc-123");
    }

    #[test]
    fn base_mobile_id_handles_empty_after_stats_prefix() {
        assert_eq!(base_mobile_id("stats:"), "");
    }

    #[test]
    fn base_mobile_id_only_strips_stats_at_prefix() {
        assert_eq!(base_mobile_id("foo-stats:bar"), "foo-stats:bar");
    }

    #[test]
    fn base_mobile_id_only_strips_agent_at_prefix() {
        // The "agent:" prefix should only be stripped when it appears at the start.
        assert_eq!(base_mobile_id("foo-agent:bar"), "foo-agent:bar");
    }

    #[test]
    fn base_mobile_id_strips_only_one_prefix() {
        // Only the first matching prefix is stripped; nested prefixes remain.
        assert_eq!(base_mobile_id("files:agent:xyz"), "agent:xyz");
        assert_eq!(base_mobile_id("agent:files:xyz"), "files:xyz");
    }

    fn make_manager() -> (WebRtcManager, mpsc::UnboundedReceiver<WebRtcEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (WebRtcManager::new(tx), rx)
    }

    #[test]
    fn new_manager_is_empty() {
        let (mgr, _rx) = make_manager();
        assert!(mgr.peers.is_empty());
        assert!(mgr.session_channels.is_empty());
        assert!(mgr.channel_owners.is_empty());
        assert!(mgr.stats_channel_owners.is_empty());
        assert!(mgr.files_channel_owners.is_empty());
        assert!(mgr.control_channel_owners.is_empty());
        assert!(mgr.agent_channel_owners.is_empty());
        assert!(!mgr.has_channel("any-session"));
        assert!(!mgr.has_stats_channel());
    }

    #[test]
    fn has_channel_returns_false_for_missing_session() {
        let (mgr, _rx) = make_manager();
        assert!(!mgr.has_channel("nope"));
    }

    #[test]
    fn has_channel_returns_false_for_empty_vec() {
        // A session entry with an empty channel list should report no channel.
        let (mut mgr, _rx) = make_manager();
        mgr.session_channels
            .insert("sess-1".to_string(), Vec::new());
        assert!(!mgr.has_channel("sess-1"));
    }

    #[test]
    fn close_session_on_empty_manager_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.close_session("does-not-exist");
        assert!(mgr.session_channels.is_empty());
        assert!(mgr.channel_owners.is_empty());
    }

    #[test]
    fn prune_session_channels_removes_empty_session_map_entry() {
        let (mut mgr, _rx) = make_manager();
        // Seed an empty channel list — prune should drop the map entry.
        mgr.session_channels
            .insert("sess-empty".to_string(), Vec::new());
        // Note: prune iterates only if the entry exists. An empty Vec stays unless
        // retain removes nothing and then we check is_empty. The code removes the
        // map entry when channels becomes empty after retain.
        mgr.prune_session_channels("sess-empty");
        assert!(!mgr.session_channels.contains_key("sess-empty"));
    }

    #[test]
    fn prune_session_channels_noop_for_unknown_session() {
        let (mut mgr, _rx) = make_manager();
        mgr.prune_session_channels("nope");
        assert!(mgr.session_channels.is_empty());
        assert!(mgr.channel_owners.is_empty());
    }

    #[test]
    fn prune_stats_channels_on_empty_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.prune_stats_channels();
        assert!(mgr.stats_channel_owners.is_empty());
    }

    #[test]
    fn prune_files_channels_on_empty_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.prune_files_channels();
        assert!(mgr.files_channel_owners.is_empty());
    }

    #[test]
    fn prune_control_channels_on_empty_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.prune_control_channels();
        assert!(mgr.control_channel_owners.is_empty());
    }

    #[test]
    fn prune_agent_channels_on_empty_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.prune_agent_channels();
        assert!(mgr.agent_channel_owners.is_empty());
    }

    #[test]
    fn webrtc_event_debug_input_hides_data_contents() {
        let ev = WebRtcEvent::Input {
            session_id: "sess".to_string(),
            mobile_device_id: "mob".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("Input"));
        assert!(dbg.contains("sess"));
        assert!(dbg.contains("mob"));
        assert!(dbg.contains("data_len"));
        assert!(dbg.contains('5'));
        // The raw bytes should not appear verbatim as a Vec.
        assert!(!dbg.contains("[1, 2, 3, 4, 5]"));
    }

    #[test]
    fn webrtc_event_debug_channel_opened() {
        let ev = WebRtcEvent::ChannelOpened {
            session_id: "abc".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("ChannelOpened"));
        assert!(dbg.contains("abc"));
    }

    #[test]
    fn webrtc_event_debug_channel_closed() {
        let ev = WebRtcEvent::ChannelClosed {
            session_id: "xyz".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("ChannelClosed"));
        assert!(dbg.contains("xyz"));
    }

    #[test]
    fn webrtc_event_debug_ice_candidate_omits_sdp() {
        let ev = WebRtcEvent::IceCandidate {
            peer_key: "pk".to_string(),
            mobile_device_id: "mid".to_string(),
            candidate_json: "{\"candidate\":\"super-secret-sdp\"}".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("IceCandidate"));
        assert!(dbg.contains("pk"));
        assert!(dbg.contains("mid"));
        // Candidate JSON is intentionally excluded from Debug output.
        assert!(!dbg.contains("super-secret-sdp"));
    }

    #[test]
    fn webrtc_event_debug_stats_channel_closed() {
        let ev = WebRtcEvent::StatsChannelClosed {
            host_id: "h1".to_string(),
            mobile_device_id: "m1".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("StatsChannelClosed"));
        assert!(dbg.contains("h1"));
        assert!(dbg.contains("m1"));
    }

    #[test]
    fn webrtc_event_debug_files_channel_closed() {
        let ev = WebRtcEvent::FilesChannelClosed {
            mobile_device_id: "m2".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("FilesChannelClosed"));
        assert!(dbg.contains("m2"));
    }

    #[test]
    fn webrtc_event_debug_control_channel_closed() {
        let ev = WebRtcEvent::ControlChannelClosed {
            mobile_device_id: "m3".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("ControlChannelClosed"));
        assert!(dbg.contains("m3"));
    }

    #[test]
    fn webrtc_event_debug_agent_channel_closed() {
        let ev = WebRtcEvent::AgentChannelClosed {
            agent_id: "agent-42".to_string(),
            mobile_device_id: "m4".to_string(),
        };
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("AgentChannelClosed"));
        assert!(dbg.contains("agent-42"));
        assert!(dbg.contains("m4"));
    }

    #[tokio::test]
    async fn poll_events_on_empty_manager_is_noop() {
        let (mut mgr, mut rx) = make_manager();
        mgr.poll_events().await;
        // No events produced because there are no peers.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn send_output_returns_false_when_no_channels() {
        let (mut mgr, _rx) = make_manager();
        assert!(!mgr.send_output("missing", b"hello").await);
    }

    #[tokio::test]
    async fn send_stats_returns_false_when_no_channels() {
        let (mut mgr, _rx) = make_manager();
        assert!(!mgr.send_stats(b"stats-payload").await);
    }

    #[tokio::test]
    async fn close_all_on_empty_manager_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.close_all().await;
        assert!(mgr.peers.is_empty());
    }

    #[tokio::test]
    async fn close_peer_on_unknown_key_is_noop() {
        let (mut mgr, _rx) = make_manager();
        mgr.close_peer("unknown").await;
        assert!(mgr.peers.is_empty());
        assert!(mgr.channel_owners.is_empty());
    }
}
