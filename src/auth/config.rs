use std::env;

use once_cell::sync::Lazy;

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

impl OidcConfig {
    pub fn new() -> Self {
        Self {
            auth_server_url: KEYCLOAK_AUTH_SERVER_URL.to_string(),
            realm: KEYCLOAK_REALM.to_string(),
            client_id: KEYCLOAK_CLIENT_ID.to_string(),
            client_secret: KEYCLOAK_CLIENT_SECRET.to_string(),
            callback_url: CALLBACK_URL.to_string(),
        }
    }
}
