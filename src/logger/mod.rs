use axum::{routing::get, Router};
use prometheus::{
    register_counter, Counter, Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry,
    TextEncoder,
};
use std::sync::Arc;

// Define the Prometheus metrics structure
struct Metrics {
    http_requests_total: IntCounter,
    http_errors_total: IntCounter,
    active_users: IntGauge,
    queue_size: IntGauge,
    request_latency: Histogram,
}

// Initialize Prometheus metrics
fn setup_metrics() -> (Arc<Metrics>, Registry) {
    let registry = Registry::new();

    // Counter for total HTTP requests
    let http_requests_total =
        IntCounter::new("http_requests_total", "Total HTTP requests").unwrap();
    registry
        .register(Box::new(http_requests_total.clone()))
        .unwrap();

    // Counter for HTTP errors
    let http_errors_total = IntCounter::new("http_errors_total", "Total HTTP errors").unwrap();
    registry
        .register(Box::new(http_errors_total.clone()))
        .unwrap();

    // Gauge for active users
    let active_users = IntGauge::new("active_users", "Number of active users").unwrap();
    registry.register(Box::new(active_users.clone())).unwrap();

    // Gauge for queue size
    let queue_size = IntGauge::new("queue_size", "Size of the task queue").unwrap();
    registry.register(Box::new(queue_size.clone())).unwrap();

    // Histogram for request latency
    let request_latency = Histogram::with_opts(
        HistogramOpts::new("request_latency_seconds", "Request latency in seconds")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0]),
    )
    .unwrap();
    registry
        .register(Box::new(request_latency.clone()))
        .unwrap();

    let metrics = Metrics {
        http_requests_total,
        http_errors_total,
        active_users,
        queue_size,
        request_latency,
    };

    (Arc::new(metrics), registry)
}

// Metrics handler for Prometheus scraping
async fn metrics_handler(registry: Arc<Registry>) -> String {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

// Example route handler
async fn example_handler(metrics: Arc<Metrics>) -> &'static str {
    // Simulate processing
    let timer = metrics.request_latency.start_timer();
    metrics.http_requests_total.inc(); // Increment total requests
    metrics.active_users.inc(); // Simulate an active user joining
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    metrics.active_users.dec(); // User leaves
    timer.observe_duration(); // Record latency
    "Hello, World!"
}

// Error route handler
async fn error_handler(metrics: Arc<Metrics>) -> &'static str {
    metrics.http_errors_total.inc(); // Increment error counter
    "Error occurred!"
}

lazy_static::lazy_static! {
    static ref HTTP_REQUESTS_TOTAL: Counter = register_counter!(
        "http_requests_total",
        "Total number of HTTP requests made"
    ).unwrap();
}

pub(crate) async fn prometheus_router() -> Router {
    // Setup Prometheus metrics
    let (metrics, registry) = setup_metrics();

    // Build Axum router
    Router::new()
        .route(
            "/example",
            get({
                let metrics = Arc::clone(&metrics);
                move || example_handler(metrics)
            }),
        )
        .route(
            "/error",
            get({
                let metrics = Arc::clone(&metrics);
                move || error_handler(metrics)
            }),
        )
        .route(
            "/",
            get({
                let registry = Arc::new(registry);
                move || metrics_handler(registry)
            }),
        )
}
