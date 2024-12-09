pub mod api;
pub mod logger;
pub mod util;

use std::net::{Ipv4Addr, SocketAddr};

use api::{
    one::{self, get_one},
    two::{self, get_two},
};
use axum::{routing::get, Router};
use logger::prometheus_router;
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
        .nest("/metrics", prometheus_router().await);

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}
