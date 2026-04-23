use crate::error::{HostError, Result};
use crate::models::AuthState;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};

pub fn parse_jwt_exp(token: &str) -> Option<DateTime<Utc>> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let exp = value.get("exp")?.as_i64()?;
    Utc.timestamp_opt(exp, 0).single()
}

pub fn token_is_expiring(expires_at: Option<DateTime<Utc>>, leeway_seconds: i64) -> bool {
    let Some(exp) = expires_at else {
        return true;
    };

    (exp - chrono::Duration::seconds(leeway_seconds)) <= Utc::now()
}

pub fn require_refresh_token(auth: &AuthState) -> Result<String> {
    if auth.refresh_token.is_empty() {
        return Err(HostError::AuthRevoked);
    }
    Ok(auth.refresh_token.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_token(payload: &serde_json::Value) -> String {
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("{header}.{body}.signature")
    }

    #[test]
    fn parse_jwt_exp_returns_timestamp_for_valid_token() {
        let token = make_token(&serde_json::json!({ "exp": 1_700_000_000_i64, "sub": "x" }));
        let parsed = parse_jwt_exp(&token).expect("should parse exp");
        assert_eq!(parsed.timestamp(), 1_700_000_000);
    }

    #[test]
    fn parse_jwt_exp_returns_none_when_exp_missing() {
        let token = make_token(&serde_json::json!({ "sub": "x" }));
        assert!(parse_jwt_exp(&token).is_none());
    }

    #[test]
    fn parse_jwt_exp_returns_none_for_malformed_token() {
        assert!(parse_jwt_exp("not-a-jwt").is_none());
        assert!(parse_jwt_exp("only.two").is_none());
        assert!(parse_jwt_exp("aaa.!!!notbase64!!!.bbb").is_none());
        // Valid base64 but not JSON
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        assert!(parse_jwt_exp(&format!("h.{bad}.s")).is_none());
    }

    #[test]
    fn parse_jwt_exp_returns_none_when_exp_not_integer() {
        let token = make_token(&serde_json::json!({ "exp": "not-an-int" }));
        assert!(parse_jwt_exp(&token).is_none());
    }

    #[test]
    fn token_is_expiring_true_when_none() {
        assert!(token_is_expiring(None, 30));
    }

    #[test]
    fn token_is_expiring_true_when_past() {
        let past = Utc::now() - chrono::Duration::seconds(60);
        assert!(token_is_expiring(Some(past), 0));
    }

    #[test]
    fn token_is_expiring_true_when_within_leeway() {
        let soon = Utc::now() + chrono::Duration::seconds(10);
        assert!(token_is_expiring(Some(soon), 30));
    }

    #[test]
    fn token_is_expiring_false_when_far_future() {
        let far = Utc::now() + chrono::Duration::seconds(3600);
        assert!(!token_is_expiring(Some(far), 30));
    }

    #[test]
    fn require_refresh_token_returns_clone_when_present() {
        let auth = AuthState {
            access_token: "a".into(),
            refresh_token: "r".into(),
            access_expires_at: None,
        };
        assert_eq!(require_refresh_token(&auth).unwrap(), "r");
    }

    #[test]
    fn require_refresh_token_errors_when_empty() {
        let auth = AuthState {
            access_token: "a".into(),
            refresh_token: String::new(),
            access_expires_at: None,
        };
        let err = require_refresh_token(&auth).unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked));
    }
}
