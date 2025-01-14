use chrono::{Duration, Utc};
use serde_json::{json, Value};
use tracing::info;

use super::{
    flow::OidcFlow,
    session_store::{SessionData, SessionStore},
};

#[derive(Debug)]
pub struct TokenResponseData {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
}

pub struct SessionService {
    store: SessionStore,
    flow: OidcFlow,
}

impl SessionService {
    pub fn new(store: SessionStore, flow: OidcFlow) -> Self {
        Self { store, flow }
    }

    pub async fn create_new_session(
        &self,
        session_id: String,
        pkce_verifier: String,
        csrf_state: String,
    ) -> Result<String, String> {
        let session_data = SessionData::new(session_id, pkce_verifier, csrf_state);

        self.store
            .create_session(&session_data)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn exchange_code_and_store(
        &self,
        session_id: &str,
        pkce_verifier: &str,
        code: &str,
    ) -> Result<Value, String> {
        let (access_token, refresh_token, expires_in) = self
            .flow
            .exchange_code(code.to_string(), pkce_verifier.to_string())
            .await?;

        let refresh_expires_in = 86400_u64;

        let expires_at = Utc::now() + Duration::seconds(expires_in as i64);
        let expires_timestamp = expires_at.timestamp();

        self.store
            .update_tokens(session_id, &access_token, &refresh_token, expires_timestamp)
            .await
            .map_err(|e| e.to_string())?;

        let response = json!({
            "access_token": access_token,
            "access_token_expires_in": expires_in,
            "refresh_token": refresh_token,
            "refresh_token_expires_in": refresh_expires_in
        });
        Ok(response)
    }

    pub async fn load_session(&self, session_id: &str) -> Result<SessionData, String> {
        let session_data = self
            .store
            .load_session(session_id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(session_data)
    }

    pub async fn destroy_session(&self, session_id: &str) -> Result<(), String> {
        let success = self
            .store
            .destroy_session(session_id)
            .await
            .map_err(|e| e.to_string())?;
        if success {
            info!("Session {} destroyed", session_id);
            Ok(())
        } else {
            Err(format!("Session {} does not exist", session_id))
        }
    }

    pub async fn refresh_access_token(&self, session_id: &str) -> Result<String, String> {
        let session_data = self.load_session(session_id).await?;
        let refresh_token = session_data
            .refresh_token
            .ok_or("No refresh token stored".to_string())?;

        let (new_access_token, new_refresh_token, expires_in) =
            self.flow.refresh_token(&refresh_token).await?;

        let expires_at = (Utc::now() + Duration::seconds(expires_in as i64)).timestamp();
        self.store
            .update_tokens(
                session_id,
                &new_access_token,
                &new_refresh_token,
                expires_at,
            )
            .await
            .map_err(|e| e.to_string())?;

        Ok(new_access_token)
    }
}
