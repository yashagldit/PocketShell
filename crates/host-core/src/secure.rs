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
