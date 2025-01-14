use std::collections::HashMap;

use deadpool_redis::{
    redis::{pipe, AsyncCommands, ErrorKind, RedisError, RedisResult},
    Pool,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

impl SessionData {
    pub fn new(session_id: String, pkce: String, csrf: String) -> Self {
        Self {
            session_id,
            pkce_verifier: pkce,
            csrf_state: csrf,
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }
}

#[derive(Clone)]
pub struct SessionStore {
    redis_pool: Pool,
}

impl SessionStore {
    pub fn new(redis_pool: Pool) -> Self {
        Self { redis_pool }
    }

    pub async fn create_session(&self, data: &SessionData) -> RedisResult<String> {
        let mut conn = self.redis_pool.get().await.map_err(|e| {
            RedisError::from((
                ErrorKind::IoError,
                "Failed to get connection",
                e.to_string(),
            ))
        })?;

        let _: () = pipe()
            .hset(&data.session_id, "csrf_state", &data.csrf_state)
            .hset(&data.session_id, "pkce_verifier", &data.pkce_verifier)
            .expire(&data.session_id, 900) // 15 min
            .query_async(&mut conn)
            .await?;

        Ok(data.session_id.clone())
    }

    pub async fn load_session(&self, session_id: &str) -> RedisResult<SessionData> {
        let mut conn = self.redis_pool.get().await.map_err(|e| {
            RedisError::from((
                ErrorKind::IoError,
                "Failed to get connection",
                e.to_string(),
            ))
        })?;

        let data: HashMap<String, String> = conn.hgetall(session_id).await?;

        if data.is_empty() {
            return Err(RedisError::from((
                ErrorKind::TypeError,
                "Session not found",
            )));
        }

        let csrf_state = data.get("csrf_state").cloned().unwrap_or_default();
        let pkce_verifier = data.get("pkce_verifier").cloned().unwrap_or_default();
        let access_token = data.get("access_token").cloned();
        let refresh_token = data.get("refresh_token").cloned();
        let expires_at = data.get("expires_at").and_then(|v| v.parse::<i64>().ok());

        Ok(SessionData {
            session_id: session_id.to_string(),
            pkce_verifier,
            csrf_state,
            access_token,
            refresh_token,
            expires_at,
        })
    }

    pub async fn update_tokens(
        &self,
        session_id: &str,
        access_token: &str,
        refresh_token: &str,
        expires_at: i64,
    ) -> RedisResult<()> {
        let mut conn = self.redis_pool.get().await.map_err(|e| {
            RedisError::from((
                ErrorKind::IoError,
                "Failed to get connection",
                e.to_string(),
            ))
        })?;

        let _: () = pipe()
            .hset(session_id, "access_token", access_token)
            .hset(session_id, "refresh_token", refresh_token)
            .hset(session_id, "expires_at", expires_at)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn destroy_session(&self, session_id: &str) -> RedisResult<bool> {
        let mut conn = self.redis_pool.get().await.map_err(|e| {
            RedisError::from((
                ErrorKind::IoError,
                "Failed to get connection",
                e.to_string(),
            ))
        })?;

        let deleted: u64 = conn.del(session_id).await?;
        Ok(deleted > 0)
    }
}
