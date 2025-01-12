pub mod auth;
pub mod logger;

use std::{
    collections::HashMap,
    future::ready,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use auth::handler::{callback, login, protected};
use axum::{extract::FromRef, middleware, routing::get, Router};
use axum_extra::extract::cookie::Key;
use dotenvy::dotenv;
use logger::metrics_builder::{recorder_builder, track_metrics};
use tokio::{io, net::TcpListener, sync::Mutex};

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    dotenv();
    let metrics_handler = recorder_builder();

    let app = Router::new()
        .route("/", get(root))
        .route("/metrics", get(move || ready(metrics_handler.render())))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/protected", get(protected))
        .with_state(AppState::new())
        .route_layer(middleware::from_fn(track_metrics));

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}

#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<Mutex<HashMap<String, String>>>,
    pub key: Key,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            key: Key::generate(),
        }
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}
