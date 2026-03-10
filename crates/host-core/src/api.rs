use crate::error::{HostError, Result};
use crate::models::{
    HeartbeatRequest, HostApiResponse, PairingValidateRequest, SessionState, TokenPairResponse,
    TrustedDeviceRecord,
};
use crate::secure::parse_jwt_exp;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};

#[derive(Clone)]
pub struct BackendClient {
    base_url: String,
    client: Client,
}

impl BackendClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }

    pub async fn request_otp(&self, email: &str) -> Result<()> {
        let url = format!("{}/api/v1/auth/otp/request", self.base_url);
        let res = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({"email": email}))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if res.status() != StatusCode::ACCEPTED {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("otp request failed: {body}")));
        }
        Ok(())
    }

    pub async fn verify_otp(&self, email: &str, otp_code: &str) -> Result<TokenPairResponse> {
        let url = format!("{}/api/v1/auth/otp/verify", self.base_url);
        let res = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({"email": email, "otp_code": otp_code}))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("otp verify failed: {body}")));
        }

        res.json::<TokenPairResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid auth payload: {e}")))
    }

    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPairResponse> {
        let url = format!("{}/api/v1/auth/token/refresh", self.base_url);
        let res = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({"refresh_token": refresh_token}))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if res.status() == StatusCode::UNAUTHORIZED {
            return Err(HostError::AuthRevoked);
        }

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("token refresh failed: {body}")));
        }

        res.json::<TokenPairResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid refresh payload: {e}")))
    }

    pub async fn validate_pairing_code(
        &self,
        access_token: &str,
        payload: &PairingValidateRequest,
    ) -> Result<HostApiResponse> {
        let url = format!("{}/api/v1/pairing/codes/validate", self.base_url);
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .json(payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("pairing validate failed: {body}")));
        }

        res.json::<HostApiResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid host registration payload: {e}")))
    }

    pub async fn send_heartbeat(&self, token: &str, payload: &HeartbeatRequest) -> Result<()> {
        let url = format!("{}/api/v1/presence/hosts/{}", self.base_url, payload.host_id);
        let res = self
            .client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if res.status() == StatusCode::UNAUTHORIZED {
            return Err(HostError::AuthRevoked);
        }

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "presence heartbeat failed: {}",
                res.status()
            )));
        }

        Ok(())
    }

    pub async fn list_trusted_devices(
        &self,
        token: &str,
        host_id: &str,
    ) -> Result<Vec<TrustedDeviceRecord>> {
        let url = format!("{}/api/v1/hosts/{}/trusted-devices", self.base_url, host_id);
        let res = self
            .client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if res.status() == StatusCode::UNAUTHORIZED {
            return Err(HostError::AuthRevoked);
        }

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "trusted-device list failed: {}",
                res.status()
            )));
        }

        res.json::<Vec<TrustedDeviceRecord>>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid trusted-device payload: {e}")))
    }

    pub async fn approve_device(&self, token: &str, host_id: &str, mobile_device_id: &str) -> Result<TrustedDeviceRecord> {
        let url = format!("{}/api/v1/hosts/{}/trusted-devices/approve", self.base_url, host_id);
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&serde_json::json!({
                "mobile_device_id": mobile_device_id,
                "permissions_json": {"terminal": true, "stats": true}
            }))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("approve failed: {body}")));
        }

        res.json::<TrustedDeviceRecord>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid approve response: {e}")))
    }

    pub async fn revoke_device(&self, token: &str, host_id: &str, mobile_device_id: &str) -> Result<TrustedDeviceRecord> {
        let url = format!("{}/api/v1/hosts/{}/trusted-devices/revoke", self.base_url, host_id);
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&serde_json::json!({"mobile_device_id": mobile_device_id}))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("revoke failed: {body}")));
        }

        res.json::<TrustedDeviceRecord>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid revoke response: {e}")))
    }

    pub async fn transition_session(
        &self,
        token: &str,
        session_id: &str,
        state: SessionState,
        connection_mode: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/api/v1/sessions/{}", self.base_url, session_id);
        let mut payload = serde_json::json!({"state": state.as_str()});
        if let Some(mode) = connection_mode {
            payload["connection_mode"] = serde_json::Value::String(mode.to_string());
        }

        let res = self
            .client
            .patch(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!("session transition failed: {body}")));
        }

        Ok(())
    }

    pub async fn turn_credentials(
        &self,
        token: &str,
    ) -> Result<(String, String, i64, Vec<String>)> {
        let url = format!("{}/api/v1/webrtc/turn-credentials", self.base_url);
        let res = self
            .client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!(
                "turn credentials request failed: {body}"
            )));
        }

        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| HostError::Backend(format!("invalid turn payload: {e}")))?;

        let username = body
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let credential = body
            .get("credential")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let ttl_seconds = body
            .get("ttl_seconds")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let uris = body
            .get("uris")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok((username, credential, ttl_seconds, uris))
    }
}

pub fn derive_access_expiry(token: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    parse_jwt_exp(token)
}
