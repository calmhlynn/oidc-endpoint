pub mod api;
pub mod util;

use std::net::{Ipv4Addr, SocketAddr};

use api::{
    one::{self, get_one, OneApi},
    two::{self, get_two},
};
use axum::{routing::get, Router};
use tokio::{io, net::TcpListener};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "/one", api = one::OneApi),
        (path = "/two", api = two::TwoApi)
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let doc = OneApi::openapi();

    let app = Router::new()
        .route("/", get(root))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api/v1/ones", get(get_one))
        .route("/api/v1/twos", get(get_two));

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

async fn root() -> &'static str {
    "root"
}
