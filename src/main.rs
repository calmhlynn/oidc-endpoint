pub mod api;

use std::net::{Ipv4Addr, SocketAddr};

use api::one::{self, OneApi};
use axum::{routing::get, Router};
use tokio::{io, net::TcpListener};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let doc = OneApi::openapi();

    let app = Router::new()
        .route("/", get(root))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
        .nest("/api/v1/ones", one::router());

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}
