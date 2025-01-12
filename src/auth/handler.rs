use std::env;

use axum::http::StatusCode;
use axum::response::Html;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::AppState;

static KEYCLOAK_AUTH_SERVER_URL: Lazy<String> =
    Lazy::new(|| env::var("KEYCLOAK_AUTH_SERVER_URL").unwrap());
static KEYCLOAK_REALM: Lazy<String> = Lazy::new(|| env::var("KEYCLOAK_REALM").unwrap());
static KEYCLOAK_CLIENT_ID: Lazy<String> = Lazy::new(|| env::var("KEYCLOAK_CLIENT_ID").unwrap());
static KEYCLOAK_CLIENT_SECRET: Lazy<String> =
    Lazy::new(|| env::var("KEYCLOAK_CLIENT_SECRET").unwrap());
static CALLBACK_URL: Lazy<String> = Lazy::new(|| env::var("CALLBACK_URL").unwrap());

pub(crate) async fn login(
    State(app_state): State<AppState>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    let auth_url = format!(
        "{}/realms/{}/protocol/openid-connect/auth",
        *KEYCLOAK_AUTH_SERVER_URL, *KEYCLOAK_REALM
    );
    let token_url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        *KEYCLOAK_AUTH_SERVER_URL, *KEYCLOAK_REALM
    );

    let client = BasicClient::new(
        ClientId::new(KEYCLOAK_CLIENT_ID.clone()),
        Some(ClientSecret::new(KEYCLOAK_CLIENT_SECRET.clone())),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(CALLBACK_URL.clone()).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".to_string()))
        .url();

    println!("Browse authorized URL: {}", authorize_url);

    let session_data = json!({
        "pkce_verifier": pkce_verifier.secret(),
        "csrf_state": csrf_state.secret()
    })
    .to_string();

    let session_id = Uuid::new_v4().to_string();

    {
        let mut sessions = app_state.sessions.lock().await;
        sessions.insert(session_id.clone(), session_data);
    }

    let jar = jar.add(Cookie::new("session_id", session_id));

    (jar, Redirect::to(authorize_url.as_str()))
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

pub(crate) async fn callback(
    Query(query): Query<AuthRequest>,
    State(app_state): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), (StatusCode, String)> {
    let session_id = match jar.get("session_id") {
        Some(c) => c.value().to_owned(),
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Missing session_id cookie. Please login first.".to_string(),
            ))
        }
    };

    let session_json = {
        let sessions = app_state.sessions.lock().await;
        sessions.get(&session_id).cloned()
    };

    let session_json = match session_json {
        Some(s) => s,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Session not found. Possibly expired or invalid session_id".to_string(),
            ))
        }
    };
    let session_data: Value = serde_json::from_str(&session_json).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse session JSON: {}", e),
        )
    })?;

    let stored_pkce = session_data["pkce_verifier"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let stored_state = session_data["csrf_state"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    if stored_state != query.state {
        return Err((StatusCode::UNAUTHORIZED, "CSRF state mismatch.".into()));
    }

    let auth_url = format!(
        "{}/realms/{}/protocol/openid-connect/auth",
        *KEYCLOAK_AUTH_SERVER_URL, *KEYCLOAK_REALM
    );
    let token_url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        *KEYCLOAK_AUTH_SERVER_URL, *KEYCLOAK_REALM
    );

    let client = BasicClient::new(
        ClientId::new(KEYCLOAK_CLIENT_ID.clone()),
        Some(ClientSecret::new(KEYCLOAK_CLIENT_SECRET.clone())),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(CALLBACK_URL.clone()).unwrap());

    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .set_pkce_verifier(PkceCodeVerifier::new(stored_pkce))
        .request_async(async_http_client)
        .await;

    let token_response = match token_result {
        Ok(t) => t,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to exchange code: {e}"),
            ))
        }
    };

    let access_token = token_response.access_token().secret().to_owned();

    println!("Access token: {:?}", access_token);

    let token_data = json!({
        "access_token": access_token,
    })
    .to_string();

    {
        let mut sessions = app_state.sessions.lock().await;
        sessions.insert(session_id.clone(), token_data);
    }

    Ok((jar, Redirect::to("/auth/protected")))
}

pub async fn protected(jar: PrivateCookieJar) -> impl IntoResponse {
    println!("TODO LIST");

    (StatusCode::OK, "protected").into_response()
}
