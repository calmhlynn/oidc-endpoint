use axum::{extract::FromRef, http::StatusCode};
use axum_extra::extract::cookie::Key;
use deadpool_redis::{
    redis::{pipe, AsyncCommands, ErrorKind, RedisError, RedisResult},
    Config, Pool, Runtime,
};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env};
use tracing::info;
use uuid::Uuid;

static KEYCLOAK_AUTH_SERVER_URL: Lazy<String> =
    Lazy::new(|| env::var("KEYCLOAK_AUTH_SERVER_URL").unwrap());
static KEYCLOAK_REALM: Lazy<String> = Lazy::new(|| env::var("KEYCLOAK_REALM").unwrap());
static KEYCLOAK_CLIENT_ID: Lazy<String> = Lazy::new(|| env::var("KEYCLOAK_CLIENT_ID").unwrap());
static KEYCLOAK_CLIENT_SECRET: Lazy<String> =
    Lazy::new(|| env::var("KEYCLOAK_CLIENT_SECRET").unwrap());
static CALLBACK_URL: Lazy<String> = Lazy::new(|| env::var("CALLBACK_URL").unwrap());

#[derive(Clone)]
pub struct OidcConfig {
    pub auth_server_url: String,
    pub realm: String,
    pub client_id: String,
    pub client_secret: String,
    pub callback_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub redis_pool: Pool,
    pub key: Key,
}
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let redis_cfg = Config::from_url(env::var("REDIS_URL").unwrap());
        let redis_pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();

        AppState {
            redis_pool,
            key: Key::generate(),
        }
    }
}

pub struct OidcFlow {
    pub config: OidcConfig,
}

impl Default for OidcFlow {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcFlow {
    pub fn new() -> Self {
        let config = OidcConfig {
            auth_server_url: KEYCLOAK_AUTH_SERVER_URL.to_string(),
            realm: KEYCLOAK_REALM.to_string(),
            client_id: KEYCLOAK_CLIENT_ID.to_string(),
            client_secret: KEYCLOAK_CLIENT_SECRET.to_string(),
            callback_url: CALLBACK_URL.to_string(),
        };

        OidcFlow { config }
    }

    pub fn logout_url() -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/logout",
            *KEYCLOAK_AUTH_SERVER_URL, *KEYCLOAK_REALM,
        )
    }

    pub fn create_client(&self) -> BasicClient {
        let auth_url = format!(
            "{}/realms/{}/protocol/openid-connect/auth",
            self.config.auth_server_url, self.config.realm
        );
        let token_url = format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.config.auth_server_url, self.config.realm
        );

        BasicClient::new(
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(self.config.callback_url.clone()).unwrap())
    }

    pub fn generate_pkce(&self) -> (PkceCodeChallenge, PkceCodeVerifier) {
        PkceCodeChallenge::new_random_sha256()
    }

    pub fn build_authorize_url(
        &self,
        client: &BasicClient,
        pkce_challenge: PkceCodeChallenge,
    ) -> (String, CsrfToken, String) {
        let csrf_token = CsrfToken::new_random();
        let session_id = Uuid::new_v4().to_string();

        let combined_state_value = format!("{}|{}", session_id, csrf_token.secret());
        let combined_state = CsrfToken::new(combined_state_value);

        let (authorize_url, _) = client
            .authorize_url(|| combined_state.clone())
            .set_pkce_challenge(pkce_challenge)
            .add_scope(Scope::new("openid".to_string()))
            .url();
        (authorize_url.to_string(), csrf_token, session_id)
    }

    pub fn validate_token(&self, state: &str) -> Result<(String, String), (StatusCode, String)> {
        let parts: Vec<&str> = state.split('|').collect();

        if parts.len() != 2 {
            return Err((StatusCode::BAD_REQUEST, "Invalid state format".into()));
        }

        let session_id = parts[0].to_string();
        let csrf_token = parts[1].to_string();

        Ok((session_id, csrf_token))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub access_token: Option<String>,
}

pub async fn create_session(redis_pool: &Pool, session_data: SessionData) -> RedisResult<String> {
    let mut conn = redis_pool.get().await.unwrap();

    let _: () = pipe()
        .hset(
            &session_data.session_id,
            "csrf_state",
            &session_data.csrf_state,
        )
        .hset(
            &session_data.session_id,
            "pkce_verifier",
            &session_data.pkce_verifier,
        )
        .expire(&session_data.session_id, 900) // 15 min
        .query_async(&mut conn)
        .await?;

    Ok(session_data.session_id)
}

pub async fn load_session_data(
    redis_pool: &Pool,
    session_id: &str,
) -> RedisResult<Option<SessionData>> {
    let mut conn = redis_pool.get().await.unwrap();

    let data: HashMap<String, String> = conn.hgetall(session_id).await?;

    if data.is_empty() {
        return Ok(None);
    }

    let csrf_state = data
        .get("csrf_state")
        .cloned()
        .ok_or_else(|| RedisError::from((ErrorKind::TypeError, "Missing csrf_state")))
        .unwrap();
    let pkce_verifier = data
        .get("pkce_verifier")
        .cloned()
        .ok_or_else(|| RedisError::from((ErrorKind::TypeError, "Missing pkce_verifier")))
        .unwrap();

    let access_token = data.get("access_token").cloned();

    Ok(Some(SessionData {
        session_id: session_id.to_string(),
        csrf_state,
        pkce_verifier,
        access_token,
    }))
}

pub async fn update_session(
    redis_pool: &Pool,
    session_id: &str,
    access_token: String,
) -> Result<String, String> {
    let mut conn = redis_pool.get().await.unwrap();

    let data: Option<String> = conn.get(session_id.to_string()).await.unwrap();

    if let Some(stored_data) = data {
        let mut session_data: SessionData = match serde_json::from_str(&stored_data) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to deserialize session data: {e}")),
        };

        session_data.access_token = Some(access_token);

        let serialized_session_data = match serde_json::to_string(&session_data) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to serialize updated session data: {e}")),
        };

        let result: Result<String, RedisError> = conn
            .set(session_id.to_string(), serialized_session_data)
            .await;

        match result {
            Ok(_) => {
                info!("Updated session id = {}", session_id);
                Ok(session_id.to_string())
            }
            Err(e) => Err(format!("Failed to update session: {e}")),
        }
    } else {
        Err("Session data doesn't exist".to_string())
    }
}

pub async fn destroy_session(redis_pool: &Pool, session_id: &str) -> Result<String, String> {
    let mut conn = redis_pool.get().await.unwrap();

    let result: Result<u64, RedisError> = conn.del(session_id.to_string()).await;

    match result {
        Ok(deleted) => {
            if deleted > 0 {
                info!("Destoryed session id: {}", session_id);
                Ok(format!("Session ID: {} successfully destoryed", session_id))
            } else {
                Err(format!("Sesssion ID: {} doesn't exist", session_id))
            }
        }
        Err(e) => Err(format!("Failed to destory session: {e}")),
    }
}
