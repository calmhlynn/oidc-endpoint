use oauth2::{
    basic::BasicClient, reqwest, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    Scope, TokenResponse, TokenUrl,
};
use uuid::Uuid;

use super::config::OidcConfig;

#[derive(Clone)]
pub struct OidcFlow {
    config: OidcConfig,
}

impl OidcFlow {
    pub fn new(config: OidcConfig) -> Self {
        OidcFlow { config }
    }

    pub fn logout_url(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/logout",
            self.config.auth_server_url, self.config.realm
        )
    }

    pub fn create_client(
        &self,
    ) -> BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet> {
        let auth_url = format!(
            "{}/realms/{}/protocol/openid-connect/auth",
            self.config.auth_server_url, self.config.realm
        );
        let token_url = format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.config.auth_server_url, self.config.realm
        );

        BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.config.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(auth_url).unwrap())
            .set_token_uri(TokenUrl::new(token_url).unwrap())
            .set_redirect_uri(RedirectUrl::new(self.config.callback_url.clone()).unwrap())
    }

    pub fn generate_pkce(&self) -> (PkceCodeChallenge, PkceCodeVerifier) {
        PkceCodeChallenge::new_random_sha256()
    }

    pub fn build_authorization_url(
        &self,
        client: &BasicClient<
            EndpointSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointSet,
        >,
        pkce_challenge: PkceCodeChallenge,
    ) -> (String, String, String) {
        let csrf_token = CsrfToken::new_random();
        let session_id = Uuid::new_v4().to_string();

        let combined_state_value = format!("{}|{}", session_id, csrf_token.secret());
        let combined_state = CsrfToken::new(combined_state_value);

        let (authorize_url, _) = client
            .authorize_url(|| combined_state.clone())
            .add_scope(Scope::new("openid".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        (
            authorize_url.to_string(),
            csrf_token.secret().to_string(),
            session_id,
        )
    }

    pub fn validate_state(&self, state: &str) -> Result<(String, String), String> {
        let parts: Vec<&str> = state.split('|').collect();
        if parts.len() != 2 {
            Err("State format is invalid (expected session_id|csrf_state)".to_string())
        } else {
            Ok((parts[0].to_string(), parts[1].to_string()))
        }
    }

    pub async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
    ) -> Result<(String, String, u64), String> {
        let client = self.create_client();

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let result = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&http_client)
            .await;

        match result {
            Ok(token_response) => {
                let access_token = token_response.access_token().secret().to_owned();
                let refresh_token = token_response
                    .refresh_token()
                    .map(|r| r.secret().to_owned())
                    .ok_or("Refresh token missing".to_string())?;
                let expires_in = token_response
                    .expires_in()
                    .map(|e| e.as_secs())
                    .unwrap_or(3600);

                Ok((access_token, refresh_token, expires_in))
            }
            Err(e) => Err(format!("Failed to exchange code: {e}")),
        }
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(String, String, u64), String> {
        let client = self.create_client();
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");
        let result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(&http_client)
            .await;

        match result {
            Ok(token_response) => {
                let new_access = token_response.access_token().secret().to_owned();
                let new_refresh = token_response
                    .refresh_token()
                    .map(|r| r.secret().to_owned())
                    .unwrap_or_else(|| refresh_token.to_string());
                let expires_in = token_response
                    .expires_in()
                    .map(|e| e.as_secs())
                    .unwrap_or(3600);

                Ok((new_access, new_refresh, expires_in))
            }
            Err(e) => Err(format!("Failed to refresh token: {e}")),
        }
    }
}

impl Default for OidcFlow {
    fn default() -> Self {
        Self::new(OidcConfig::new())
    }
}
