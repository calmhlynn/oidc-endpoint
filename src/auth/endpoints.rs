use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    Form, Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::info;

use crate::AppState;

use super::{flow::OidcFlow, session_service::SessionService, session_store::SessionStore};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

pub async fn login_handler(State(app_state): State<AppState>) -> impl IntoResponse {
    let flow = OidcFlow::default();
    let store = SessionStore::new(app_state.redis_pool.clone());
    let service = SessionService::new(store, flow.clone());

    let client = flow.create_client();
    let (pkce_challenge, pkce_verifier) = flow.generate_pkce();
    let (authorize_url, csrf_secret, session_id) =
        flow.build_authorization_url(&client, pkce_challenge);

    if let Err(e) = service
        .create_new_session(
            session_id.clone(),
            pkce_verifier.secret().to_string(),
            csrf_secret,
        )
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }

    Redirect::to(&authorize_url).into_response()
}

pub async fn callback_handler(
    State(app_state): State<AppState>,
    Query(query): Query<AuthRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let flow = OidcFlow::default();
    let store = SessionStore::new(app_state.redis_pool.clone());
    let service = SessionService::new(store, flow.clone());

    let (session_id, csrf_state) = flow
        .validate_state(&query.state)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let session_data = service
        .load_session(&session_id)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    if session_data.csrf_state != csrf_state {
        return Err((StatusCode::UNAUTHORIZED, "CSRF state mismatch".to_string()));
    }

    let response = service
        .exchange_code_and_store(&session_id, &session_data.pkce_verifier, &query.code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(response))
}

pub async fn protected_handler(
    State(app_state): State<AppState>,
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
) -> Result<Html<String>, Redirect> {
    let token = auth_header.token().to_string();
    let store = SessionStore::new(app_state.redis_pool.clone());
    let service = SessionService::new(store, OidcFlow::default());

    match service.load_session(&token).await {
        Ok(session) => {
            if session.access_token.is_none() {
                return Err(Redirect::to("/auth/login"));
            }

            Ok(Html(format!(
                "<h1>Protected Page</h1>
                 <p>Access token: {:?}</p>
                 <p><a href=\"/auth/logout\">Logout</a></p>",
                session.access_token
            )))
        }
        Err(_) => Err(Redirect::to("/auth/login")),
    }
}

pub async fn refresh_handler(
    State(app_state): State<AppState>,
    TypedHeader(refresh_token): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let token = refresh_token.token().to_string();
    let store = SessionStore::new(app_state.redis_pool.clone());
    let service = SessionService::new(store, OidcFlow::default());

    let new_access = service
        .refresh_access_token(&token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(json!({ "access_token": new_access })))
}

// TODO Redirect url parameters required for valid post redirect

pub async fn logout_handler(
    State(app_state): State<AppState>,
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    let token = auth_header.token().to_string();
    let store = SessionStore::new(app_state.redis_pool.clone());
    let service = SessionService::new(store, OidcFlow::default());
    if service.destroy_session(&token).await.is_ok() {
        info!("Session {} destroyed", token);
    }
    let flow = OidcFlow::default();
    let logout_url = flow.logout_url();
    Redirect::to(&logout_url)
}

pub async fn token_handler(
    State(app_state): State<AppState>,
    Form(payload): Form<TokenRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    match payload.grant_type.as_str() {
        "authorization_code" => {
            let code = payload
                .code
                .clone()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing code".to_string()))?;

            let store = SessionStore::new(app_state.redis_pool.clone());
            let service = SessionService::new(store, OidcFlow::default());

            // TODO
            let session_id = code.clone();
            let pkce_verifier = code.clone();

            let response = service
                .exchange_code_and_store(&session_id, &pkce_verifier, &code)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            Ok(Json(response))
        }
        "refresh_token" => {
            let refresh = payload
                .refresh_token
                .clone()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing refresh_token".to_string()))?;

            let flow = OidcFlow::default();
            let (new_access, new_refresh, expires_in) = flow
                .refresh_token(&refresh)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(json!({
                "access_token": new_access,
                "refresh_token": new_refresh,
                "expires_in": expires_in
            })))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            "Unsupported grant_type".to_string(),
        )),
    }
}

pub async fn userinfo_handler(
    State(app_state): State<AppState>,
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let token = auth_header.token().to_string();
    let store = SessionStore::new(app_state.redis_pool.clone());
    let service = SessionService::new(store, OidcFlow::default());

    let session = service
        .load_session(&token)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let access_token = session
        .access_token
        .clone()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "No access token".to_string()))?;

    Ok(Json(
        json!({ "access_token": access_token, "userinfo": "dummy user info" }),
    ))
}

pub async fn device_authorization_handler(
    State(_app_state): State<AppState>,
) -> Json<DeviceAuthResponse> {
    let resp = DeviceAuthResponse {
        device_code: "device_code_example".to_string(),
        user_code: "user_code_example".to_string(),
        verification_uri: "https://example.com/device".to_string(),
        verification_uri_complete: "https://example.com/device?user_code=user_code_example"
            .to_string(),
        expires_in: 1800,
        interval: 5,
    };
    Json(resp)
}
