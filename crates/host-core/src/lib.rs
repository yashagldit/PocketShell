pub mod agent_session;
pub mod alerts;
pub mod api;
pub mod audit;
pub mod auth;
pub mod coding_sessions;
pub mod config;
pub mod daemon;
pub mod dev_ports;
pub mod discovery;
pub mod error;
pub mod exposed_ports;
pub mod files;
pub mod files_watch;
pub mod git;
pub mod http_forward;
pub mod job_object;
pub mod local_attach;
pub mod models;
pub mod platform;
pub mod pty;
pub mod rpc;
pub mod secret_store;
pub mod secure;
pub mod service;
pub mod session;
pub mod signaling_crypto;
pub mod stats;
pub mod store;
pub mod terminal;
pub mod terminal_marks;
pub mod transport;
pub mod update;
pub mod ws_forward;
#[cfg(feature = "webrtc")]
pub mod webrtc_manager;
#[cfg(feature = "webrtc")]
pub mod webrtc_peer;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;
    pub static HOME_LOCK: Mutex<()> = Mutex::new(());
}
