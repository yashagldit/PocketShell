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
    #[error("host no longer exists on the backend (removed from account)")]
    HostGone,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_match_expected_strings() {
        assert_eq!(
            HostError::Config("bad".into()).to_string(),
            "configuration error: bad"
        );
        assert_eq!(
            HostError::NotLoggedIn.to_string(),
            "not paired: run `pocketshell pair <CODE>` first"
        );
        assert_eq!(
            HostError::Backend("500".into()).to_string(),
            "backend request failed: 500"
        );
        assert_eq!(
            HostError::AuthRevoked.to_string(),
            "authentication revoked or invalid; please run `pocketshell pair <CODE>` again"
        );
        assert_eq!(
            HostError::HostGone.to_string(),
            "host no longer exists on the backend (removed from account)"
        );
        assert_eq!(HostError::Pty("x".into()).to_string(), "pty error: x");
        assert_eq!(
            HostError::Version("old".into()).to_string(),
            "unsupported host version: old"
        );
    }

    #[test]
    fn from_io_error_converts_to_host_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: HostError = io_err.into();
        match err {
            HostError::Io(inner) => {
                assert_eq!(inner.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected HostError::Io, got {other:?}"),
        }
    }

    #[test]
    fn from_serde_error_converts_to_host_error_serde() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: HostError = json_err.into();
        match err {
            HostError::Serde(_) => {}
            other => panic!("expected HostError::Serde, got {other:?}"),
        }
    }

    #[test]
    fn result_alias_works_with_question_mark() {
        fn inner() -> Result<i32> {
            let _: serde_json::Value = serde_json::from_str("{}")?;
            Ok(42)
        }
        assert_eq!(inner().unwrap(), 42);
    }
}
