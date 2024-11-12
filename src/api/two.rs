use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(paths(get_two))]
pub(crate) struct TwoApi;

#[utoipa::path(
    get,
    path = "/two",
    responses(
        (
            status = OK,
            description = "One result ok",
            body = str
        )
    )
)]
pub(crate) async fn get_two() -> &'static str {
    "two"
}
