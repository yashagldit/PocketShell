use crate::error::{HostError, Result};
use crate::models::{
    BackendSessionInfo, HeartbeatRequest, HostInitiatedCreateRequest,
    HostInitiatedCreateResponse, HostInitiatedDeviceAddRequest, HostInitiatedPollOutcome,
    HostInitiatedStatusResponse, PairingValidateRequest, PairingValidateResponse, SessionState,
    TokenPairResponse, TrustedDeviceRecord,
};
use crate::secure::parse_jwt_exp;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};

/// Optional action the backend can request via heartbeat response.
#[derive(Debug, Clone, PartialEq)]
pub enum HeartbeatAction {
    None,
    /// Backend requests the daemon to shut down (e.g. free-tier limit).
    Kill,
}

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
        payload: &PairingValidateRequest,
    ) -> Result<PairingValidateResponse> {
        let url = format!("{}/api/v1/pairing/codes/validate", self.base_url);
        let res = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!(
                "pairing validate failed: {body}"
            )));
        }

        res.json::<PairingValidateResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid host registration payload: {e}")))
    }

    /// Start a host-initiated pairing claim. No auth required.
    pub async fn start_host_initiated(
        &self,
        hostname: &str,
        platform: &str,
        public_key: &str,
        app_version: &str,
    ) -> Result<HostInitiatedCreateResponse> {
        let url = format!("{}/api/v1/pairing/host-initiated", self.base_url);
        let payload = HostInitiatedCreateRequest {
            hostname: hostname.to_string(),
            platform: platform.to_string(),
            public_key: public_key.to_string(),
            app_version: app_version.to_string(),
        };
        let res = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!(
                "host-initiated pairing start failed: {body}"
            )));
        }

        res.json::<HostInitiatedCreateResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid host-initiated create payload: {e}")))
    }

    /// Start a host-initiated device-add claim. Requires host auth (Bearer access token).
    /// Used when an already-paired host wants to add a new mobile device.
    pub async fn start_host_initiated_device_add(
        &self,
        token: &str,
        host_id: &str,
    ) -> Result<HostInitiatedCreateResponse> {
        let url = format!("{}/api/v1/pairing/host-initiated/device-add", self.base_url);
        let payload = HostInitiatedDeviceAddRequest {
            existing_host_id: host_id.to_string(),
        };
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if res.status() == StatusCode::UNAUTHORIZED {
            return Err(HostError::AuthRevoked);
        }

        // 403 on this endpoint means the backend doesn't recognize this host as
        // owned by the authenticated user — typically because the host was
        // deleted from the mobile app. Surface as HostGone so the caller can
        // auto-recover by re-registering as a new host.
        if res.status() == StatusCode::FORBIDDEN {
            return Err(HostError::HostGone);
        }

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!(
                "host-initiated device-add start failed: {body}"
            )));
        }

        res.json::<HostInitiatedCreateResponse>()
            .await
            .map_err(|e| HostError::Backend(format!("invalid host-initiated create payload: {e}")))
    }

    /// Poll the status of a host-initiated claim. No auth required.
    pub async fn poll_host_initiated_status(
        &self,
        claim_token: &str,
    ) -> Result<HostInitiatedPollOutcome> {
        let url = format!(
            "{}/api/v1/pairing/host-initiated/{}/status",
            self.base_url, claim_token
        );
        let res = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        match res.status() {
            StatusCode::GONE => Ok(HostInitiatedPollOutcome::AlreadyDelivered),
            StatusCode::NOT_FOUND => Ok(HostInitiatedPollOutcome::Expired),
            s if s.is_success() => {
                let body: HostInitiatedStatusResponse = res.json().await.map_err(|e| {
                    HostError::Backend(format!("invalid host-initiated status payload: {e}"))
                })?;
                if body.status == "claimed" {
                    Ok(HostInitiatedPollOutcome::Claimed(Box::new(body)))
                } else {
                    Ok(HostInitiatedPollOutcome::Pending)
                }
            }
            other => {
                let body = res.text().await.unwrap_or_default();
                Err(HostError::Backend(format!(
                    "host-initiated poll failed ({other}): {body}"
                )))
            }
        }
    }

    pub async fn send_heartbeat(
        &self,
        token: &str,
        payload: &HeartbeatRequest,
    ) -> Result<HeartbeatAction> {
        let url = format!(
            "{}/api/v1/presence/hosts/{}/heartbeat",
            self.base_url, payload.host_id
        );
        let res = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .json(payload)
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

        // Check if backend is requesting an action (e.g. kill for free-tier)
        let body: serde_json::Value = res
            .json()
            .await
            .map_err(|e| HostError::Backend(format!("invalid heartbeat response: {e}")))?;

        if let Some(action) = body.get("action").and_then(|v| v.as_str()) {
            if action == "kill" {
                return Ok(HeartbeatAction::Kill);
            }
        }

        Ok(HeartbeatAction::None)
    }

    pub async fn mark_offline(&self, token: &str, host_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/presence/hosts/{}/offline",
            self.base_url, host_id
        );
        let res = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| HostError::Backend(e.to_string()))?;

        if !res.status().is_success() {
            return Err(HostError::Backend(format!(
                "mark offline failed: {}",
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

    pub async fn approve_device(
        &self,
        token: &str,
        host_id: &str,
        mobile_device_id: &str,
    ) -> Result<TrustedDeviceRecord> {
        let url = format!(
            "{}/api/v1/hosts/{}/trusted-devices/approve",
            self.base_url, host_id
        );
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

    pub async fn revoke_device(
        &self,
        token: &str,
        host_id: &str,
        mobile_device_id: &str,
    ) -> Result<TrustedDeviceRecord> {
        let url = format!(
            "{}/api/v1/hosts/{}/trusted-devices/revoke",
            self.base_url, host_id
        );
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
            return Err(HostError::Backend(format!(
                "session transition failed: {body}"
            )));
        }

        Ok(())
    }

    /// Fetch active (CONNECTED + DETACHED) sessions for this host from the backend.
    /// Returns a list of `{"id": "...", "state": "..."}` objects.
    pub async fn list_active_sessions(
        &self,
        token: &str,
        host_id: &str,
    ) -> Result<Vec<(String, SessionState)>> {
        let url = format!("{}/api/v1/sessions/host/{}/active", self.base_url, host_id);
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
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!(
                "list active sessions failed: {body}"
            )));
        }

        let body: Vec<serde_json::Value> = res
            .json()
            .await
            .map_err(|e| HostError::Backend(format!("invalid sessions payload: {e}")))?;

        Ok(body
            .into_iter()
            .filter_map(|v| {
                let id = v.get("id")?.as_str()?.to_string();
                let state_str = v.get("state")?.as_str()?;
                let state = match state_str {
                    "CONNECTED" | "connected" => SessionState::Connected,
                    "DETACHED" | "detached" => SessionState::Detached,
                    _ => return None,
                };
                Some((id, state))
            })
            .collect())
    }

    /// Fetch active sessions with full detail from the backend.
    pub async fn list_active_sessions_full(
        &self,
        token: &str,
        host_id: &str,
    ) -> Result<Vec<BackendSessionInfo>> {
        let url = format!("{}/api/v1/sessions/host/{}/active", self.base_url, host_id);
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
            let body = res.text().await.unwrap_or_default();
            return Err(HostError::Backend(format!(
                "list active sessions failed: {body}"
            )));
        }

        let body: Vec<serde_json::Value> = res
            .json()
            .await
            .map_err(|e| HostError::Backend(format!("invalid sessions payload: {e}")))?;

        Ok(body
            .into_iter()
            .map(|v| BackendSessionInfo {
                id: v
                    .get("id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                state: v
                    .get("state")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                started_at: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                ended_at: v
                    .get("ended_at")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                connection_mode: v
                    .get("connection_mode")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                mobile_device_id: v
                    .get("mobile_device_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
            })
            .collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HeartbeatRequest, PairingValidateRequest};
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_host_json() -> serde_json::Value {
        json!({
            "id": "h1",
            "user_id": "u1",
            "hostname": "host.local",
            "platform": "linux",
            "public_key": "pk",
            "app_version": "1.0.0",
            "created_at": "2024-01-01T00:00:00Z",
            "last_seen_at": null,
            "status": "online",
        })
    }

    #[tokio::test]
    async fn refresh_tokens_sends_refresh_and_parses_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token/refresh"))
            .and(header("content-type", "application/json"))
            .and(body_json(json!({"refresh_token": "r-tok"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "new-a",
                "refresh_token": "new-r",
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = BackendClient::new(server.uri());
        let resp = c.refresh_tokens("r-tok").await.unwrap();
        assert_eq!(resp.access_token, "new-a");
        assert_eq!(resp.refresh_token, "new-r");
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
    }

    #[tokio::test]
    async fn refresh_tokens_maps_401_to_auth_revoked() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token/refresh"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let c = BackendClient::new(server.uri());
        let err = c.refresh_tokens("r").await.unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked), "got {err:?}");
    }

    #[tokio::test]
    async fn refresh_tokens_500_returns_backend_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token/refresh"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let c = BackendClient::new(server.uri());
        let err = c.refresh_tokens("r").await.unwrap_err();
        match err {
            HostError::Backend(msg) => assert!(msg.contains("boom")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn base_url_trailing_slash_is_trimmed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "a", "refresh_token": "r", "token_type": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = BackendClient::new(format!("{}/", server.uri()));
        c.refresh_tokens("x").await.unwrap();
    }

    #[tokio::test]
    async fn validate_pairing_code_posts_body_and_parses_response() {
        let server = MockServer::start().await;
        let req = PairingValidateRequest {
            code: "ABC123".into(),
            hostname: "hn".into(),
            platform: "linux".into(),
            public_key: "pk".into(),
            app_version: Some("1.0".into()),
            host_id: None,
        };

        let mut host = sample_host_json();
        host["access_token"] = json!("a");
        host["refresh_token"] = json!("r");
        host["token_type"] = json!("Bearer");
        host["already_paired"] = json!(false);

        Mock::given(method("POST"))
            .and(path("/api/v1/pairing/codes/validate"))
            .and(body_json(&req))
            .respond_with(ResponseTemplate::new(200).set_body_json(host))
            .expect(1)
            .mount(&server)
            .await;

        let c = BackendClient::new(server.uri());
        let resp = c.validate_pairing_code(&req).await.unwrap();
        assert_eq!(resp.access_token, "a");
        assert_eq!(resp.host.id, "h1");
        assert!(!resp.already_paired);
    }

    #[tokio::test]
    async fn validate_pairing_code_failure_returns_backend_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/pairing/codes/validate"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad code"))
            .mount(&server)
            .await;

        let c = BackendClient::new(server.uri());
        let req = PairingValidateRequest {
            code: "X".into(),
            hostname: "h".into(),
            platform: "l".into(),
            public_key: "p".into(),
            app_version: None,
            host_id: None,
        };
        let err = c.validate_pairing_code(&req).await.unwrap_err();
        match err {
            HostError::Backend(msg) => assert!(msg.contains("bad code")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn start_host_initiated_sends_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/pairing/host-initiated"))
            .and(body_json(json!({
                "hostname": "hn",
                "platform": "linux",
                "public_key": "pk",
                "app_version": "1.0",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "claim_token": "claim-xyz",
                "expires_at": "2030-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;

        let c = BackendClient::new(server.uri());
        let resp = c
            .start_host_initiated("hn", "linux", "pk", "1.0")
            .await
            .unwrap();
        assert_eq!(resp.claim_token, "claim-xyz");
    }

    #[tokio::test]
    async fn device_add_uses_bearer_and_maps_401_and_403() {
        // 401 -> AuthRevoked
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/pairing/host-initiated/device-add"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let err = c.start_host_initiated_device_add("tok", "h1").await.unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked));

        // 403 -> HostGone
        let server2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/pairing/host-initiated/device-add"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(json!({"existing_host_id": "h1"})))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        let err2 = c2
            .start_host_initiated_device_add("tok", "h1")
            .await
            .unwrap_err();
        assert!(matches!(err2, HostError::HostGone), "got {err2:?}");
    }

    #[tokio::test]
    async fn device_add_success_returns_claim() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/pairing/host-initiated/device-add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "claim_token": "ct",
                "expires_at": "2030-01-01T00:00:00Z"
            })))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let r = c.start_host_initiated_device_add("tok", "h1").await.unwrap();
        assert_eq!(r.claim_token, "ct");
    }

    #[tokio::test]
    async fn poll_host_initiated_status_variants() {
        // pending
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/pairing/host-initiated/t1/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "pending"
            })))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let out = c.poll_host_initiated_status("t1").await.unwrap();
        assert!(matches!(out, HostInitiatedPollOutcome::Pending));

        // claimed
        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/pairing/host-initiated/t2/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "claimed",
                "access_token": "at"
            })))
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        let out2 = c2.poll_host_initiated_status("t2").await.unwrap();
        match out2 {
            HostInitiatedPollOutcome::Claimed(b) => {
                assert_eq!(b.status, "claimed");
                assert_eq!(b.access_token.as_deref(), Some("at"));
            }
            other => panic!("expected Claimed, got {:?}", std::mem::discriminant(&other)),
        }

        // 410 -> AlreadyDelivered
        let server3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/pairing/host-initiated/t3/status"))
            .respond_with(ResponseTemplate::new(410))
            .mount(&server3)
            .await;
        let c3 = BackendClient::new(server3.uri());
        let out3 = c3.poll_host_initiated_status("t3").await.unwrap();
        assert!(matches!(out3, HostInitiatedPollOutcome::AlreadyDelivered));

        // 404 -> Expired
        let server4 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/pairing/host-initiated/t4/status"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server4)
            .await;
        let c4 = BackendClient::new(server4.uri());
        let out4 = c4.poll_host_initiated_status("t4").await.unwrap();
        assert!(matches!(out4, HostInitiatedPollOutcome::Expired));
    }

    #[tokio::test]
    async fn send_heartbeat_detects_kill_and_none() {
        let server = MockServer::start().await;
        let hb = HeartbeatRequest {
            host_id: "h1".into(),
            active_sessions: 2,
            pending_devices: 0,
        };
        Mock::given(method("POST"))
            .and(path("/api/v1/presence/hosts/h1/heartbeat"))
            .and(header("authorization", "Bearer tk"))
            .and(body_json(&hb))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"action": "kill"})))
            .expect(1)
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let action = c.send_heartbeat("tk", &hb).await.unwrap();
        assert_eq!(action, HeartbeatAction::Kill);

        // No action
        let server2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/presence/hosts/h1/heartbeat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        let a2 = c2.send_heartbeat("tk", &hb).await.unwrap();
        assert_eq!(a2, HeartbeatAction::None);

        // 401
        let server3 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/presence/hosts/h1/heartbeat"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server3)
            .await;
        let c3 = BackendClient::new(server3.uri());
        let err = c3.send_heartbeat("tk", &hb).await.unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked));
    }

    #[tokio::test]
    async fn mark_offline_posts_with_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/presence/hosts/h1/offline"))
            .and(header("authorization", "Bearer tk"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        c.mark_offline("tk", "h1").await.unwrap();

        let server2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/presence/hosts/h1/offline"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        assert!(c2.mark_offline("tk", "h1").await.is_err());
    }

    #[tokio::test]
    async fn list_trusted_devices_parses_array_and_handles_401() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hosts/h1/trusted-devices"))
            .and(header("authorization", "Bearer tk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "id": "td1",
                    "host_id": "h1",
                    "mobile_device_id": "m1",
                    "approved_at": null,
                    "revoked_at": null,
                    "permissions_json": null,
                    "created_at": "2024-01-01T00:00:00Z"
                }
            ])))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let list = c.list_trusted_devices("tk", "h1").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "td1");

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hosts/h1/trusted-devices"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        let err = c2.list_trusted_devices("tk", "h1").await.unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked));
    }

    #[tokio::test]
    async fn approve_device_sends_permissions_and_returns_record() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hosts/h1/trusted-devices/approve"))
            .and(header("authorization", "Bearer tk"))
            .and(body_json(json!({
                "mobile_device_id": "m1",
                "permissions_json": {"terminal": true, "stats": true}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "td1",
                "host_id": "h1",
                "mobile_device_id": "m1",
                "approved_at": "2024-01-01T00:00:00Z",
                "revoked_at": null,
                "permissions_json": null,
                "created_at": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let rec = c.approve_device("tk", "h1", "m1").await.unwrap();
        assert_eq!(rec.mobile_device_id, "m1");
        assert!(rec.approved_at.is_some());
    }

    #[tokio::test]
    async fn revoke_device_sends_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hosts/h1/trusted-devices/revoke"))
            .and(header("authorization", "Bearer tk"))
            .and(body_json(json!({"mobile_device_id": "m1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "td1",
                "host_id": "h1",
                "mobile_device_id": "m1",
                "approved_at": null,
                "revoked_at": "2024-01-01T00:00:00Z",
                "permissions_json": null,
                "created_at": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let r = c.revoke_device("tk", "h1", "m1").await.unwrap();
        assert!(r.revoked_at.is_some());
    }

    #[tokio::test]
    async fn transition_session_patches_with_state_and_mode() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/sessions/s1"))
            .and(header("authorization", "Bearer tk"))
            .and(body_json(json!({"state": "connected", "connection_mode": "p2p"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        c.transition_session("tk", "s1", SessionState::Connected, Some("p2p"))
            .await
            .unwrap();

        // Without connection_mode
        let server2 = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/sessions/s2"))
            .and(body_json(json!({"state": "ended"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        c2.transition_session("tk", "s2", SessionState::Ended, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_active_sessions_filters_and_maps_states() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/sessions/host/h1/active"))
            .and(header("authorization", "Bearer tk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "s1", "state": "CONNECTED"},
                {"id": "s2", "state": "detached"},
                {"id": "s3", "state": "GARBAGE"},
                {"state": "connected"}, // missing id - filtered
            ])))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let list = c.list_active_sessions("tk", "h1").await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], ("s1".to_string(), SessionState::Connected));
        assert_eq!(list[1], ("s2".to_string(), SessionState::Detached));
    }

    #[tokio::test]
    async fn list_active_sessions_401_to_auth_revoked() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/sessions/host/h1/active"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let err = c.list_active_sessions("tk", "h1").await.unwrap_err();
        assert!(matches!(err, HostError::AuthRevoked));
    }

    #[tokio::test]
    async fn list_active_sessions_full_parses_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/sessions/host/h1/active"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "id": "s1",
                    "state": "CONNECTED",
                    "started_at": "2024-01-01T00:00:00Z",
                    "ended_at": null,
                    "connection_mode": "p2p",
                    "mobile_device_id": "m1"
                }
            ])))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let list = c.list_active_sessions_full("tk", "h1").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "s1");
        assert_eq!(list[0].connection_mode.as_deref(), Some("p2p"));
        assert_eq!(list[0].mobile_device_id.as_deref(), Some("m1"));
        assert!(list[0].ended_at.is_none());
    }

    #[tokio::test]
    async fn turn_credentials_parses_all_fields_and_defaults() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/webrtc/turn-credentials"))
            .and(header("authorization", "Bearer tk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "username": "u",
                "credential": "c",
                "ttl_seconds": 3600,
                "uris": ["turn:a", "turn:b"]
            })))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let (u, cred, ttl, uris) = c.turn_credentials("tk").await.unwrap();
        assert_eq!(u, "u");
        assert_eq!(cred, "c");
        assert_eq!(ttl, 3600);
        assert_eq!(uris, vec!["turn:a".to_string(), "turn:b".to_string()]);

        // Missing fields default safely
        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/webrtc/turn-credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server2)
            .await;
        let c2 = BackendClient::new(server2.uri());
        let (u2, _c2, ttl2, uris2) = c2.turn_credentials("tk").await.unwrap();
        assert!(u2.is_empty());
        assert_eq!(ttl2, 0);
        assert!(uris2.is_empty());
    }

    #[tokio::test]
    async fn turn_credentials_failure_returns_backend_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/webrtc/turn-credentials"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&server)
            .await;
        let c = BackendClient::new(server.uri());
        let err = c.turn_credentials("tk").await.unwrap_err();
        match err {
            HostError::Backend(m) => assert!(m.contains("nope")),
            other => panic!("expected Backend got {other:?}"),
        }
    }
}
