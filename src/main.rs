pub mod auth;
pub mod logger;

use std::{
    future::ready,
    net::{Ipv4Addr, SocketAddr},
};

use auth::{
    endpoints::{callback, login, logout, protected},
    handler::AppState,
};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use dotenvy::dotenv;
use logger::metrics_builder::{recorder_builder, track_metrics};
use tokio::{io, net::TcpListener};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let _ = dotenv();

    tracing_subscriber::fmt().init();

    info!("Starting the application...");
    let metrics_handler = recorder_builder();

    let app_store = AppState::new();

    let app = Router::new()
        .route("/", get(root))
        .route("/metrics", get(move || ready(metrics_handler.render())))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/protected", get(protected))
        .route("/auth/logout", get(logout))
        .with_state(app_store)
        .route_layer(middleware::from_fn(track_metrics));

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}
