pub mod auth;
pub mod logger;

use std::{
    env,
    future::ready,
    net::{Ipv4Addr, SocketAddr},
};

use auth::endpoints::{
    callback_handler, device_authorization_handler, login_handler, logout_handler,
    protected_handler, refresh_handler, token_handler, userinfo_handler,
};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use deadpool_redis::{Config, Pool, Runtime};
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
        .route("/auth/login", get(login_handler))
        .route("/auth/callback", get(callback_handler))
        .route("/auth/protected", get(protected_handler))
        .route("/auth/logout", get(logout_handler))
        .route("/auth/token", post(token_handler))
        .route("/auth/userinfo", get(userinfo_handler))
        .route(
            "/auth/device_authorization",
            get(device_authorization_handler),
        )
        .route("/auth/refresh", get(refresh_handler))
        .with_state(app_store)
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
    pub redis_pool: Pool,
}

impl AppState {
    pub fn new() -> Self {
        let redis_url = env::var("REDIS_URL").expect("REDIS_URL is not set");
        let redis_cfg = Config::from_url(redis_url);
        let redis_pool = redis_cfg
            .create_pool(Some(Runtime::Tokio1))
            .expect("Failed to create Redis pool");

        Self { redis_pool }
    }
}
