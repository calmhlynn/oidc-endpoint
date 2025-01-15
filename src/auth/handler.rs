use axum::{extract::FromRef, http::StatusCode};
use axum_extra::extract::cookie::Key;
use chrono::{Duration, Utc};
use deadpool_redis::{
    redis::{pipe, AsyncCommands, ErrorKind, RedisError, RedisResult},
    Config, Pool, Runtime,
};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthUrl, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, ExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, StandardTokenResponse,
    TokenResponse, TokenType, TokenUrl,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, env};
use tracing::info;
use uuid::Uuid;

pub async fn process_token_response(
    redis_pool: &deadpool_redis::Pool,
    session_id: &str,
    access_token: String,
    access_token_expires_in: u64,
    refresh_token: String,
    refresh_token_expires_in: u64,
) -> Result<Value, (StatusCode, String)> {
    // Calculate expiration time
    let expires_at = Utc::now() + Duration::seconds(access_token_expires_in as i64);

    // Save tokens in Redis
    update_session_with_refresh_token(
        redis_pool,
        session_id,
        access_token.clone(),
        refresh_token.clone(),
        expires_at,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update session: {e}"),
        )
    })?;

    // Return JSON response
    Ok(json!({
        "access_token": access_token,
        "access_token_expires_in": access_token_expires_in,
        "refresh_token": refresh_token,
        "refresh_token_expires_in": refresh_token_expires_in
    }))
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

pub async fn refresh_access_token(
    redis_pool: &Pool,
    session_id: &str,
    oidc_flow: &OidcFlow,
) -> Result<String, String> {
    let mut conn = redis_pool.get().await.unwrap();

    let data: HashMap<String, String> = conn.hgetall(session_id).await.unwrap();

    let refresh_token = data
        .get("refresh_token")
        .cloned()
        .ok_or("Missing refresh_token")?;

    let client = oidc_flow.create_client();
    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.clone()))
        .request_async(async_http_client)
        .await;

    match token_response {
        Ok(resp) => {
            let access_token = resp.access_token().secret().to_owned();
            let new_refresh_token = resp.refresh_token().map(|r| r.secret().to_owned());
            let expires_at = resp
                .expires_in()
                .map(|e| chrono::Utc::now() + chrono::Duration::seconds(e.as_secs() as i64));
            update_session_with_refresh_token(
                redis_pool,
                session_id,
                access_token.clone(),
                new_refresh_token.unwrap_or(refresh_token),
                expires_at.unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(1)),
            )
            .await
            .unwrap();

            Ok(access_token)
        }
        Err(e) => Err(format!("Failed to refresh access token: {e}")),
    }
}

pub async fn update_session_with_refresh_token(
    redis_pool: &Pool,
    session_id: &str,
    access_token: String,
    refresh_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> RedisResult<()> {
    let mut conn = redis_pool.get().await.unwrap();

    let _: () = pipe()
        .hset(session_id, "access_token", &access_token)
        .hset(session_id, "refresh_token", &refresh_token)
        .hset(session_id, "expires_at", expires_at.timestamp())
        .query_async(&mut conn)
        .await?;

    Ok(())
}
