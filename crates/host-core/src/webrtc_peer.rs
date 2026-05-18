#![cfg(feature = "webrtc")]

use crate::error::{HostError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice::candidate::CandidateType;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::stats::StatsReportType;

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
    /// Per-candidate-pair cumulative byte counts from the last stats snapshot,
    /// keyed by pair id. Used by `collect_relay_delta` to compute deltas
    /// across ICE path migrations without double-counting.
    relay_pair_state: HashMap<String, RelayPairSnapshot>,
}

#[derive(Clone, Copy)]
struct RelayPairSnapshot {
    bytes_sent: u64,
    bytes_received: u64,
    was_relay: bool,
}

/// webrtc-rs does not support `turns:` (TURN-over-TLS) or `transport=tcp`.
/// Strip those URIs so they don't end up in the ICE config and break TURN
/// fallback silently.
pub(crate) fn filter_supported_turn_uris<I, S>(uris: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    uris.into_iter()
        .map(|u| u.as_ref().to_string())
        .filter(|u| !u.starts_with("turns:") && !u.contains("transport=tcp"))
        .collect()
}

/// Resolve hostnames in `turn:`/`stun:` URIs to an IP literal, preferring IPv4.
///
/// webrtc-rs's ICE gatherer does not retry across address families: if libc
/// returns an AAAA record first and the host has no working IPv6 route (common
/// on cheap VPS providers), the gather call fails with `Network is unreachable`
/// and no relay/srflx candidate is produced. By pre-resolving and feeding
/// webrtc-rs an IP literal, we sidestep that entirely. Falls back to IPv6 only
/// if no A record exists. IP-literal URIs and unknown schemes are passed through.
pub(crate) async fn resolve_uris_prefer_ipv4(uris: Vec<String>) -> Vec<String> {
    let mut cache: HashMap<(String, u16), Option<std::net::IpAddr>> = HashMap::new();
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        match resolve_one_uri(&uri, &mut cache).await {
            Some(rewritten) => {
                if rewritten != uri {
                    tracing::debug!(original = %uri, resolved = %rewritten, "rewrote TURN/STUN URI");
                }
                out.push(rewritten);
            }
            None => {
                tracing::warn!(uri = %uri, "could not resolve TURN/STUN URI; dropping");
            }
        }
    }
    out
}

async fn resolve_one_uri(
    uri: &str,
    cache: &mut HashMap<(String, u16), Option<std::net::IpAddr>>,
) -> Option<String> {
    let (scheme, rest) = uri.split_once(':')?;
    if !matches!(scheme, "turn" | "turns" | "stun" | "stuns") {
        return Some(uri.to_string());
    }
    let (hostport, query) = match rest.split_once('?') {
        Some((h, q)) => (h, Some(q)),
        None => (rest, None),
    };
    let (host, port_s) = hostport.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;

    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(uri.to_string());
    }

    let key = (host.to_string(), port);
    let chosen = match cache.get(&key) {
        Some(cached) => *cached,
        None => {
            let resolved = lookup_prefer_ipv4(host.to_string(), port).await;
            cache.insert(key, resolved);
            resolved
        }
    }?;

    let new_host = match chosen {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    Some(match query {
        Some(q) => format!("{scheme}:{new_host}:{port}?{q}"),
        None => format!("{scheme}:{new_host}:{port}"),
    })
}

async fn lookup_prefer_ipv4(host: String, port: u16) -> Option<std::net::IpAddr> {
    let lookup = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
            .unwrap_or_default()
    });
    let addrs = tokio::time::timeout(std::time::Duration::from_secs(3), lookup)
        .await
        .ok()?
        .ok()?;
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.iter().find(|a| a.is_ipv6()))
        .map(|a| a.ip())
}

impl WebRtcPeer {
    pub async fn new(turn_uris: Vec<String>, username: String, credential: String) -> Result<Self> {
        let mut media = MediaEngine::default();
        media
            .register_default_codecs()
            .map_err(|e| HostError::Backend(format!("webrtc codec registration failed: {e}")))?;

        let api = APIBuilder::new().with_media_engine(media).build();
        let supported_uris = filter_supported_turn_uris(turn_uris);
        let resolved_uris = resolve_uris_prefer_ipv4(supported_uris).await;
        let config = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: resolved_uris,
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
            relay_pair_state: HashMap::new(),
        })
    }

    /// Poll `get_stats()` and return the count of bytes (sent+received) that
    /// flowed through candidate pairs whose *local* candidate is a TURN relay
    /// since the last call. Only local-relay pairs are counted — if only the
    /// remote peer is relaying, those bytes bill against the remote's TURN
    /// allocation, not ours.
    ///
    /// Handles ICE path migration by tracking cumulative counters per pair id
    /// and summing deltas. Pairs not seen in a snapshot are dropped; new pairs
    /// start with their cumulative count attributed (since they didn't exist
    /// before this interval).
    pub async fn collect_relay_delta(&mut self) -> u64 {
        let report = self.peer.get_stats().await;

        let mut local_candidate_types: HashMap<&String, CandidateType> = HashMap::new();
        for (id, entry) in report.reports.iter() {
            if let StatsReportType::LocalCandidate(cand) = entry {
                local_candidate_types.insert(id, cand.candidate_type);
            }
        }

        let mut delta: u64 = 0;
        let mut seen: HashMap<String, RelayPairSnapshot> = HashMap::new();

        for entry in report.reports.values() {
            let StatsReportType::CandidatePair(pair) = entry else {
                continue;
            };
            let is_relay = local_candidate_types
                .get(&pair.local_candidate_id)
                .copied()
                .map(|t| matches!(t, CandidateType::Relay))
                .unwrap_or(false);

            let snap = RelayPairSnapshot {
                bytes_sent: pair.bytes_sent,
                bytes_received: pair.bytes_received,
                was_relay: is_relay,
            };

            if let Some(prev) = self.relay_pair_state.get(&pair.id) {
                if is_relay && prev.was_relay {
                    let d_sent = pair.bytes_sent.saturating_sub(prev.bytes_sent);
                    let d_recv = pair.bytes_received.saturating_sub(prev.bytes_received);
                    delta = delta.saturating_add(d_sent).saturating_add(d_recv);
                }
            } else if is_relay {
                delta = delta
                    .saturating_add(pair.bytes_sent)
                    .saturating_add(pair.bytes_received);
            }

            seen.insert(pair.id.clone(), snap);
        }

        self.relay_pair_state = seen;
        delta
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_turn_uris_keeps_udp_turn() {
        let out = filter_supported_turn_uris(["turn:t.example.com:3478?transport=udp"]);
        assert_eq!(out, vec!["turn:t.example.com:3478?transport=udp"]);
    }

    #[test]
    fn filter_turn_uris_drops_turns_tls() {
        let out = filter_supported_turn_uris([
            "turns:t.example.com:5349?transport=tcp",
            "turns:t.example.com:5349",
        ]);
        assert!(out.is_empty(), "turns: URIs must be dropped, got {out:?}");
    }

    #[test]
    fn filter_turn_uris_drops_tcp_transport() {
        let out = filter_supported_turn_uris(["turn:t.example.com:3478?transport=tcp"]);
        assert!(out.is_empty(), "transport=tcp must be dropped, got {out:?}");
    }

    #[test]
    fn filter_turn_uris_mixed_keeps_only_supported() {
        let out = filter_supported_turn_uris([
            "turn:t.example.com:3478?transport=udp",
            "turn:t.example.com:3478?transport=tcp",
            "turns:t.example.com:5349?transport=udp",
            "stun:stun.example.com:3478",
        ]);
        assert_eq!(
            out,
            vec![
                "turn:t.example.com:3478?transport=udp",
                "stun:stun.example.com:3478",
            ]
        );
    }

    #[test]
    fn filter_turn_uris_empty_input_yields_empty() {
        let out: Vec<String> = filter_supported_turn_uris(Vec::<String>::new());
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn resolve_uris_passes_through_ip_literal() {
        let out = resolve_uris_prefer_ipv4(vec![
            "turn:1.2.3.4:3478?transport=udp".into(),
            "stun:5.6.7.8:3478".into(),
        ])
        .await;
        assert_eq!(
            out,
            vec!["turn:1.2.3.4:3478?transport=udp", "stun:5.6.7.8:3478",]
        );
    }

    #[tokio::test]
    async fn resolve_uris_passes_through_unknown_scheme() {
        let out = resolve_uris_prefer_ipv4(vec!["https://example.com/turn".into()]).await;
        assert_eq!(out, vec!["https://example.com/turn"]);
    }

    #[tokio::test]
    async fn resolve_uris_rewrites_hostname_to_ipv4() {
        let out = resolve_uris_prefer_ipv4(vec!["stun:localhost:3478".into()]).await;
        assert_eq!(out.len(), 1, "expected one URI back, got {out:?}");
        let rewritten = &out[0];
        assert!(
            rewritten.starts_with("stun:"),
            "scheme preserved: {rewritten}"
        );
        assert!(rewritten.ends_with(":3478"), "port preserved: {rewritten}");
        assert!(
            !rewritten.contains("localhost"),
            "hostname should be replaced with an IP literal: {rewritten}"
        );
    }

    #[tokio::test]
    async fn resolve_uris_preserves_query_string() {
        let out = resolve_uris_prefer_ipv4(vec!["turn:localhost:3478?transport=udp".into()]).await;
        assert_eq!(out.len(), 1);
        assert!(
            out[0].ends_with("?transport=udp"),
            "query string preserved: {}",
            out[0]
        );
    }

    #[tokio::test]
    async fn resolve_uris_shares_host_across_uris() {
        // Cloudflare returns several URIs (turn:host:3478?transport=udp,
        // turn:host:3478?transport=tcp, stun:host:3478) that all point at the
        // same host:port. The cache must collapse those into one DNS lookup,
        // and all resulting URIs must rewrite to the same IP literal.
        let out = resolve_uris_prefer_ipv4(vec![
            "turn:localhost:3478?transport=udp".into(),
            "turn:localhost:3478?transport=tcp".into(),
            "stun:localhost:3478".into(),
        ])
        .await;
        assert_eq!(out.len(), 3);
        let extract_host = |s: &str| s.split(':').nth(1).map(|h| h.to_string());
        let hosts: Vec<_> = out.iter().filter_map(|s| extract_host(s)).collect();
        let first = &hosts[0];
        assert!(
            hosts.iter().all(|h| h == first),
            "all rewritten hosts should match: {hosts:?}"
        );
        assert_ne!(first, "localhost", "should be replaced with IP literal");
    }

    async fn new_local_peer() -> WebRtcPeer {
        // No TURN servers — ICE will use host candidates only. That's enough
        // for everything below except the loopback test (which adds ICE
        // relaying manually).
        WebRtcPeer::new(Vec::new(), String::new(), String::new())
            .await
            .expect("local peer construction should succeed")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_constructs_with_empty_turn_config() {
        let peer = new_local_peer().await;
        assert_eq!(peer.connection_state(), RTCPeerConnectionState::New);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_offer_with_data_channel_returns_non_empty_sdp() {
        let peer = new_local_peer().await;
        let (dc, sdp) = peer
            .create_offer_with_data_channel("terminal")
            .await
            .expect("create offer should succeed");
        assert!(!sdp.is_empty());
        assert!(
            sdp.contains("m=application"),
            "SDP should include data channel m-line"
        );
        assert_eq!(dc.label(), "terminal");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn apply_offer_rejects_malformed_sdp() {
        let peer = new_local_peer().await;
        let result = peer.apply_offer("this is not sdp").await;
        assert!(result.is_err(), "garbage SDP should be rejected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn apply_answer_rejects_malformed_sdp() {
        let peer = new_local_peer().await;
        // Have to create a local offer first or set_remote_description(answer) has no matching state.
        let (_dc, _offer) = peer
            .create_offer_with_data_channel("ctl")
            .await
            .expect("offer setup");
        let result = peer.apply_answer("junk").await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_is_idempotent() {
        let peer = new_local_peer().await;
        peer.close().await;
        peer.close().await; // second close must not panic
        assert_eq!(peer.connection_state(), RTCPeerConnectionState::Closed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offer_answer_loopback_opens_data_channel_and_roundtrips() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Notify;
        use tokio::task::JoinHandle;
        use tokio::time::timeout;

        /// Aborts spawned relay tasks on drop so a panic between spawn and
        /// the end of the test doesn't leave them holding the peer Arcs.
        struct AbortOnDrop(Vec<JoinHandle<()>>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                for h in &self.0 {
                    h.abort();
                }
            }
        }

        let mut initiator = new_local_peer().await;
        let mut responder = new_local_peer().await;

        let (dc, offer_sdp) = initiator
            .create_offer_with_data_channel("terminal")
            .await
            .expect("create offer");

        let answer_sdp = responder
            .apply_offer(&offer_sdp)
            .await
            .expect("responder applies offer");
        initiator
            .apply_answer(&answer_sdp)
            .await
            .expect("initiator applies answer");

        let init_peer = initiator.peer.clone();
        let resp_peer = responder.peer.clone();
        let _relays = AbortOnDrop(vec![
            tokio::spawn(async move {
                while let Some(c) = initiator.ice_tx.recv().await {
                    if let Ok(init) = c.to_json() {
                        let _ = resp_peer.add_ice_candidate(init).await;
                    }
                }
            }),
            tokio::spawn(async move {
                while let Some(c) = responder.ice_tx.recv().await {
                    if let Ok(init) = c.to_json() {
                        let _ = init_peer.add_ice_candidate(init).await;
                    }
                }
            }),
        ]);

        let open_notify = Arc::new(Notify::new());
        let on_open_notify = open_notify.clone();
        dc.on_open(Box::new(move || {
            let n = on_open_notify.clone();
            Box::pin(async move { n.notify_one() })
        }));

        timeout(Duration::from_secs(10), open_notify.notified())
            .await
            .expect("data channel should open within 10s");

        dc.send_text("ping".to_string())
            .await
            .expect("send_text should succeed on an open channel");
    }
}
