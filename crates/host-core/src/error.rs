use thiserror::Error;

#[derive(Debug, Error)]
pub enum HostError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("not paired: run `pocketshell pair <CODE>` first")]
    NotLoggedIn,
    #[error("backend request failed: {0}")]
    Backend(String),
    #[error("authentication revoked or invalid; please run `pocketshell pair <CODE>` again")]
    AuthRevoked,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("pty error: {0}")]
    Pty(String),
    #[error("unsupported host version: {0}")]
    Version(String),
}

pub type Result<T> = std::result::Result<T, HostError>;
