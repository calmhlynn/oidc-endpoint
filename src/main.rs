pub mod api;
pub mod logger;
pub mod util;

use std::{
    future::ready,
    net::{Ipv4Addr, SocketAddr},
};

use api::{
    one::{self, get_one},
    two::{self, get_two},
};
use axum::{middleware, routing::get, Router};
use logger::metrics_builder::{recorder_builder, track_metrics};
use tokio::{io, net::TcpListener};
use util::jwt::SecurityAddon;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "/one", api = one::OneApi),
        (path = "/two", api = two::TwoApi)
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let metrics_handler = recorder_builder();
    let app = Router::new()
        .route("/", get(root))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/ones", get(get_one))
        .route("/api/v1/twos", get(get_two))
        .route("/metrics", get(move || ready(metrics_handler.render())))
        .route_layer(middleware::from_fn(track_metrics));
    // .nest("/metrics", prometheus_router().await);

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8888));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}
