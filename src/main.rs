pub mod api;
pub mod util;

use std::net::{Ipv4Addr, SocketAddr};

use api::{
    one::{self, get_one},
    two::{self, get_two},
};
use axum::{routing::get, Router};
use prometheus::{register_counter, Counter, Encoder, TextEncoder};
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
    let app = Router::new()
        .route("/", get(root))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/ones", get(get_one))
        .route("/api/v1/twos", get(get_two))
        .route("/metrics", get(metrics_handler));

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}

lazy_static::lazy_static! {
    static ref HTTP_REQUESTS_TOTAL: Counter = register_counter!(
        "http_requests_total",
        "Total number of HTTP requests made"
    ).unwrap();
}

// Metrics handler function
async fn metrics_handler() -> String {
    // Increment the counter
    HTTP_REQUESTS_TOTAL.inc();

    // Gather metrics and encode them in the Prometheus text format
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    // Return metrics as a string
    String::from_utf8(buffer).unwrap()
}
