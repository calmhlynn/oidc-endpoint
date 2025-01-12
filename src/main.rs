pub mod logger;

use std::{
    future::ready,
    net::{Ipv4Addr, SocketAddr},
};

use axum::{middleware, routing::get, Router};
use logger::metrics_builder::{recorder_builder, track_metrics};
use tokio::{io, net::TcpListener};

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let metrics_handler = recorder_builder();
    let app = Router::new()
        .route("/", get(root))
        .route("/metrics", get(move || ready(metrics_handler.render())))
        .route_layer(middleware::from_fn(track_metrics));
    // .nest("/metrics", prometheus_router().await);

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}
