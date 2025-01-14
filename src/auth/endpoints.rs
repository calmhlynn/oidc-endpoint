use axum::{
    extract::{Query, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect},
};
use axum_extra::TypedHeader;
use axum_extra::{
    extract::{cookie::Cookie, PrivateCookieJar},
    headers::{authorization::Bearer, Authorization},
};
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use serde::Deserialize;
use tracing::info;

use crate::auth::handler::{
    create_session, destroy_session, load_session_data, update_session, OidcConfig, SessionData,
};

use super::handler::{AppState, OidcFlow};

pub async fn login(State(app_state): State<AppState>) -> impl IntoResponse {
    let flow = OidcFlow::new();
    let client = flow.create_client();

    let (pkce_challenge, pkce_verifier) = flow.generate_pkce();

    let (authorize_url, csrf_state, session_id) = flow.build_authorize_url(&client, pkce_challenge);
    info!("Browse authorized URL: {}", authorize_url);

    let session_data = SessionData {
        session_id,
        pkce_verifier: pkce_verifier.secret().to_string(),
        csrf_state: csrf_state.secret().to_string(),
        access_token: None,
    };

    let session_id = create_session(&app_state.redis_pool, session_data)
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", session_id)).unwrap(),
    );

    (headers, Redirect::to(&authorize_url))
}
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

pub async fn callback(
    Query(query): Query<AuthRequest>,
    State(app_state): State<AppState>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let flow = OidcFlow::new();

    let (session_id, csrf_state) = flow.validate_token(&query.state).unwrap();

    info!(
        "CALLBACK session_id: {}, csrf_state: {}",
        session_id, csrf_state
    );

    if let Some(session_data) = load_session_data(&app_state.redis_pool, &session_id)
        .await
        .unwrap()
    {
        info!("Found data in session: {:?}", session_data);

        if session_data.csrf_state != csrf_state {
            return Err((StatusCode::UNAUTHORIZED, "CSRF state mismatch".into()));
        }

        let client = flow.create_client();
        let token_response = client
            .exchange_code(AuthorizationCode::new(query.code.clone()))
            .set_pkce_verifier(PkceCodeVerifier::new(session_data.pkce_verifier))
            .request_async(oauth2::reqwest::async_http_client)
            .await;

        if let Ok(t) = token_response {
            let access_token = t.access_token().secret().to_owned();
            info!("Access token: {access_token}");

            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", session_id)).unwrap(),
            );

            Ok((headers, Redirect::to("/auth/protected")))
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to exchange code".to_string(),
            ))
        }
    } else {
        Err((StatusCode::UNAUTHORIZED, "session expired".to_string()))
    }
}

pub async fn protected(
    State(app_state): State<AppState>,
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
) -> Result<Html<String>, Redirect> {
    let session_id = auth_header.token().to_string();

    if let Some(session_data) = load_session_data(&app_state.redis_pool, &session_id)
        .await
        .unwrap()
    {
        if session_data.access_token.is_none() {
            return Err(Redirect::to("/auth/login"));
        }

        Ok(Html(format!(
            "<h1>Protected Page</h1>
         <p>Access token: {:?}</p>
         <p><a href=\"/auth/logout\">Logout</a></p>",
            session_data.access_token
        )))
    } else {
        Err(Redirect::to("/auth/login"))
    }
}

pub async fn logout(
    State(app_state): State<AppState>,
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    let session_id = auth_header.token().to_string();

    if (destroy_session(&app_state.redis_pool, &session_id).await).is_ok() {
        info!("Session {} destroyed", session_id);
    }

    let mut logout_url = OidcFlow::logout_url();
    info!("Local logout, redirect to Keycloak logout: {}", logout_url);

    Redirect::to(&logout_url)
}
