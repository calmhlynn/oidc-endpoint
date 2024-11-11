use axum::{routing, Router};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(get_one))]
pub(crate) struct OneApi;

pub(crate) fn router() -> Router {
    Router::new().route("/one", routing::get(get_one))
}

#[utoipa::path(
    get,
    path = "/one",
    responses(
        (
            status = OK,
            description = "One result ok",
            body = str
        )
    )
)]
pub(crate) async fn get_one() -> &'static str {
    "one"
}
