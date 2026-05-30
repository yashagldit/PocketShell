pub mod agent_session;
pub mod alerts;
pub mod api;
pub mod audit;
pub mod auth;
pub mod coding_sessions;
pub mod config;
pub mod daemon;
pub mod discovery;
pub mod error;
pub mod files;
pub mod files_watch;
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
pub mod terminal_marks;
pub mod transport;
pub mod update;
#[cfg(feature = "webrtc")]
pub mod webrtc_manager;
#[cfg(feature = "webrtc")]
pub mod webrtc_peer;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;
    pub static HOME_LOCK: Mutex<()> = Mutex::new(());
}
