use crate::error::{HostError, Result};
use crate::models::AuthState;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use keyring::Entry;

const SERVICE_NAME: &str = "pocketshell-host-agent";
const ACCESS_KEY: &str = "access_token";
const REFRESH_KEY: &str = "refresh_token";
const PRIVATE_KEY: &str = "host_private_key";

pub fn parse_jwt_exp(token: &str) -> Option<DateTime<Utc>> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let exp = value.get("exp")?.as_i64()?;
    Utc.timestamp_opt(exp, 0).single()
}

pub fn persist_tokens(auth: &AuthState) -> bool {
    let access = Entry::new(SERVICE_NAME, ACCESS_KEY)
        .and_then(|e| e.set_password(&auth.access_token))
        .is_ok();
    let refresh = Entry::new(SERVICE_NAME, REFRESH_KEY)
        .and_then(|e| e.set_password(&auth.refresh_token))
        .is_ok();
    access && refresh
}

pub fn load_tokens() -> Option<(String, String)> {
    let access = Entry::new(SERVICE_NAME, ACCESS_KEY).ok()?.get_password().ok()?;
    let refresh = Entry::new(SERVICE_NAME, REFRESH_KEY).ok()?.get_password().ok()?;
    Some((access, refresh))
}

pub fn clear_tokens() {
    let _ = Entry::new(SERVICE_NAME, ACCESS_KEY).and_then(|e| e.delete_credential());
    let _ = Entry::new(SERVICE_NAME, REFRESH_KEY).and_then(|e| e.delete_credential());
}

pub fn persist_private_key(private_key_b64: &str) {
    let _ = Entry::new(SERVICE_NAME, PRIVATE_KEY).and_then(|e| e.set_password(private_key_b64));
}

pub fn load_private_key() -> Option<String> {
    Entry::new(SERVICE_NAME, PRIVATE_KEY).ok()?.get_password().ok()
}

pub fn clear_private_key() {
    let _ = Entry::new(SERVICE_NAME, PRIVATE_KEY).and_then(|e| e.delete_credential());
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
