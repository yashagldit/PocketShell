use crate::error::{HostError, Result};
use crate::models::{DeviceRecord, HeartbeatRequest, LoginRequest, LoginResponse};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;

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

    pub async fn login_host(&self, payload: &LoginRequest) -> Result<LoginResponse> {
        let url = format!("{}/v1/host/login", self.base_url);
        let res = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res
                .text()
                .await
                .unwrap_or_else(|_| "<no response body>".to_string());
            return Err(HostError::Backend(format!("login failed: {body}")));
        }

        res.json::<LoginResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid login response: {e}")))
    }

    pub async fn send_heartbeat(&self, token: &str, payload: &HeartbeatRequest) -> Result<()> {
        let url = format!("{}/v1/host/heartbeat", self.base_url);
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .json(payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "heartbeat failed: {}",
                res.status()
            )));
        }

        Ok(())
    }

    pub async fn sync_device_approval(&self, token: &str, device_id: &str) -> Result<()> {
        let url = format!("{}/v1/host/devices/{}/approve", self.base_url, device_id);
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "approve failed: {}",
                res.status()
            )));
        }

        Ok(())
    }

    pub async fn sync_device_revocation(&self, token: &str, device_id: &str) -> Result<()> {
        let url = format!("{}/v1/host/devices/{}/revoke", self.base_url, device_id);
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "revoke failed: {}",
                res.status()
            )));
        }

        Ok(())
    }

    pub async fn fetch_pending_devices(&self, token: &str) -> Result<Vec<DeviceRecord>> {
        let url = format!("{}/v1/host/devices/pending", self.base_url);
        let res = self
            .client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "pending devices fetch failed: {}",
                res.status()
            )));
        }

        res.json::<Vec<DeviceRecord>>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid pending devices payload: {e}")))
    }
}
