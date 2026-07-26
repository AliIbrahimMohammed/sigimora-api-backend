//! # SIGIMORA Server
//!
//! REST API backend for BFT Accountable Threshold Signing.
//!
//! ## Quick Start
//! ```bash
//! # Run with default settings (SQLite in ./data/)
//! cargo run -p sigimora-server
//!
//! # Or with environment config
//! SIGIMORA_LISTEN=0.0.0.0:8080 SIGIMORA_DATA_DIR=/var/sigimora cargo run -p sigimora-server
//! ```
//!
//! ## Configuration
//! All settings are via environment variables or `.env` file:
//!
//! ```text
//! SIGIMORA_LISTEN               — TCP address (default: 0.0.0.0:8080)
//! SIGIMORA_DATA_DIR             — Data directory (default: ./data)
//! SIGIMORA_DATABASE_URL         — Full SQLite URL (overrides DATA_DIR)
//! SIGIMORA_LOG_LEVEL            — Log level (default: info)
//! SIGIMORA_BOOTSTRAP_KEYS       — Comma-separated bootstrap API keys
//! SIGIMORA_CORS_ENABLED         — Enable CORS (default: true)
//! SIGIMORA_CORS_ORIGINS         — Comma-separated allowed origins (default: *)
//! SIGIMORA_MAX_BODY             — Max request body bytes (default: 10MiB)
//! SIGIMORA_RATE_LIMIT           — Requests/min per IP (default: 60)
//! SIGIMORA_TLS_ENABLED          — Enable TLS (default: false)
//! SIGIMORA_TLS_CERT             — Path to TLS cert PEM
//! SIGIMORA_TLS_KEY              — Path to TLS key PEM
//! ```
//!
//! ## API Overview
//! All endpoints require `Authorization: Bearer <api-key>`.
//!
//! ```text
//! GET    /api/v1/health                  → Server health
//! POST   /api/v1/networks                → Create network
//! GET    /api/v1/networks                → List networks
//! GET    /api/v1/networks/:id            → Network details
//! POST   /api/v1/networks/:id/dkg        → Run DKG
//! GET    /api/v1/networks/:id/dkg        → DKG status
//! POST   /api/v1/networks/:id/sign       → Threshold sign
//! POST   /api/v1/networks/:id/verify     → Verify signature
//! POST   /api/v1/networks/:id/trace      → Trace signers
//! POST   /api/v1/networks/:id/refresh    → Proactive refresh
//! GET    /api/v1/networks/:id/ledger     → View ledger
//! GET    /api/v1/networks/:id/nodes      → List nodes
//! GET    /api/v1/networks/:id/nodes/:nid → Node details
//! POST   /api/v1/api-keys                → Create API key (admin)
//! GET    /api/v1/api-keys                → List API keys (admin)
//! DELETE /api/v1/api-keys/:id            → Revoke API key (admin)
//! ```

mod audit;
mod auth;
mod config;
mod db;
mod error;
mod models;
mod routes;
mod state;

use axum::extract::State;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use std::net::SocketAddr;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::ServerConfig;
use crate::state::AppState;

// ── OpenAPI documentation ──────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    info(
        title = "SIGIMORA API",
        description = "BFT Accountable Threshold Signing Backend",
        version = env!("CARGO_PKG_VERSION"),
    ),
    paths(
        // Auto-discovered from route handlers with #[utoipa::path] attrs
    ),
    tags(
        (name = "health", description = "Server health"),
        (name = "networks", description = "Network management"),
        (name = "dkg", description = "Distributed Key Generation"),
        (name = "signing", description = "Threshold signing"),
        (name = "verify", description = "Signature verification"),
        (name = "trace", description = "Signer tracing"),
        (name = "ledger", description = "Transaction ledger"),
        (name = "nodes", description = "Node identity"),
        (name = "api-keys", description = "API key management"),
    ),
)]
struct ApiDoc;

// ── Request ID middleware ─────────────────────────────────────────────────

/// Middleware that ensures every request has an `X-Request-ID`.
///
/// If the client sends one, it is preserved; otherwise a new UUID v4 is
/// generated.  The ID is:
///   - inserted into the request extensions so handlers can retrieve it
///   - set on the `X-Request-ID` response header
///   - stored in the `REQUEST_ID` task-local so error responses include it
async fn request_id_middleware(
    mut req: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    req.extensions_mut().insert(id.clone());

    let res = crate::error::REQUEST_ID
        .scope(id.clone(), async move {
            let mut res = next.run(req).await;
            res.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&id).unwrap(),
            );
            res
        })
        .await;

    res
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::from_env();
    config.ensure_dirs()?;

    // ── Setup logging + OpenTelemetry ──────────────────────────────────
    {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true);

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);

        // If OTEL_EXPORTER_OTLP_ENDPOINT is set, add an OTLP tracing layer.
        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            match init_otlp_tracer() {
                Ok(tracer) => {
                    let otel_layer = tracing_opentelemetry::layer()
                        .with_tracer(tracer);
                    subscriber.with(otel_layer).init();
                    tracing::info!("OpenTelemetry OTLP tracing enabled");
                }
                Err(e) => {
                    tracing::warn!("Failed to init OTLP tracer (falling back to stdout): {}", e);
                    subscriber.init();
                }
            }
        } else {
            subscriber.init();
        }
    }

    tracing::info!("SIGIMORA Server v{} starting...", env!("CARGO_PKG_VERSION"));

    // ── Open database ───────────────────────────────────────────────────
    let database_url = config.database_url();
    tracing::info!("Database: {}", database_url);
    let db = crate::db::Database::open(&database_url).await?;

    // Register DB for audit logging
    crate::audit::set_audit_db(db.clone());

    // Ensure a bootstrap admin key exists
    ensure_bootstrap_key(&db, &config).await?;

    // Build application state
    let state = AppState::new(config.clone(), db);

    // Build router
    let app = build_router(state, &config)?;

    // ── Start listening ─────────────────────────────────────────────────
    let addr: SocketAddr = config.listen_addr.parse()?;

    if config.tls_enabled {
        tracing::warn!(
            "TLS is configured but full TLS listener not yet implemented. \
             Falling back to HTTP. Set SIGIMORA_TLS_ENABLED=false to silence this warning."
        );
    }
    tracing::info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Initialise an OTLP tracer using the `OTEL_EXPORTER_OTLP_ENDPOINT` env
/// var (defaults to `http://localhost:4317`).
fn init_otlp_tracer() -> Result<opentelemetry_sdk::trace::Tracer, Box<dyn std::error::Error>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::SpanExporter;

    let exporter = SpanExporter::builder()
        .with_http()
        .build()?;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();

    let tracer = provider.tracer("sigimora-server");
    let _ = opentelemetry::global::set_tracer_provider(provider);
    Ok(tracer)
}

/// Wait for SIGINT or SIGTERM to trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Shutting down (SIGINT)...");
        }
        _ = terminate => {
            tracing::info!("Shutting down (SIGTERM)...");
        }
    }
    tracing::info!("Server stopped.");
}

/// Ensure at least one bootstrap admin API key exists.
async fn ensure_bootstrap_key(
    db: &crate::db::Database,
    config: &ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if any keys exist
    let keys = db.list_api_keys().await?;
    if keys.is_empty() {
        // Generate a bootstrap key
        let (raw_key, row) = crate::auth::generate_api_key("bootstrap-admin", "admin");
        db.insert_api_key(&row).await?;

        tracing::info!(
            "First run — bootstrap API key created: {}. Save this key! It will not be shown again.",
            &raw_key
        );
    }

    // Also register any bootstrap keys from env
    for bk in &config.bootstrap_keys {
        let hash = crate::auth::sha256_hex(bk);
        if db.get_api_key_by_hash(&hash).await?.is_none() {
            let row = crate::db::ApiKeyRow {
                id: uuid::Uuid::new_v4().to_string(),
                key_hash: hash,
                key_prefix: bk[..16.min(bk.len())].to_string(),
                label: "env-bootstrap".to_string(),
                role: "admin".to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                last_used_at: None,
            };
            db.insert_api_key(&row).await?;
        }
    }

    Ok(())
}

/// Rate limiting middleware — check against AppState per IP.
/// Sets X-RateLimit-* headers on every response (GitHub-style).
async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));

    let (allowed, remaining) = state.rate_limiter.check_with_remaining(ip).await;
    let max_reqs = state.rate_limiter.max_requests();

    if !allowed {
        tracing::warn!("Rate limit exceeded for IP: {}", ip);
        let request_id = crate::error::REQUEST_ID.try_with(|id| id.clone()).ok();
        let body = axum::Json(serde_json::json!({
            "error": "rate limit exceeded",
            "code": "RateLimited",
            "request_id": request_id,
        }));
        let mut res = (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            body,
        )
            .into_response();
        res.headers_mut().insert(
            HeaderName::from_static("x-ratelimit-limit"),
            HeaderValue::from_str(&max_reqs.to_string()).unwrap(),
        );
        res.headers_mut().insert(
            HeaderName::from_static("x-ratelimit-remaining"),
            HeaderValue::from_str("0").unwrap(),
        );
        return res;
    }

    let mut res = next.run(req).await;
    res.headers_mut().insert(
        HeaderName::from_static("x-ratelimit-limit"),
        HeaderValue::from_str(&max_reqs.to_string()).unwrap(),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-ratelimit-remaining"),
        HeaderValue::from_str(&remaining.to_string()).unwrap(),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-ratelimit-reset"),
        HeaderValue::from_static("60"),
    );
    res
}

/// Build the Axum router with all routes and middleware layers.
fn build_router(
    state: AppState,
    config: &ServerConfig,
) -> Result<Router, Box<dyn std::error::Error>> {
    // ── CORS layer ──────────────────────────────────────────────────────
    let cors = if config.cors_enabled {
        let cors_layer = CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any);

        if config.cors_allowed_origins.is_empty() {
            cors_layer.allow_origin(Any)
        } else {
            let origins: Vec<HeaderValue> = config
                .cors_allowed_origins
                .iter()
                .filter_map(|o| o.parse::<HeaderValue>().ok())
                .collect();
            cors_layer.allow_origin(origins)
        }
    } else {
        CorsLayer::new() // restrictive default
    };

    // ── Security headers ────────────────────────────────────────────────
    let security_headers = SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // ── Request body limit ──────────────────────────────────────────────
    let body_limit = RequestBodyLimitLayer::new(config.max_body_size);

    // ── Middleware stack ─────────────────────────────────────────────────
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(axum::middleware::from_fn(request_id_middleware))
        .layer(security_headers);

    let router = Router::new()
        // Swagger UI (no auth required)
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // Health (no auth required)
        .route("/api/v1/health", get(routes::health::health_check))
        // Networks
        .route(
            "/api/v1/networks",
            post(routes::network::create_network).get(routes::network::list_networks),
        )
        .route("/api/v1/networks/{id}", get(routes::network::get_network))
        // DKG
        .route(
            "/api/v1/networks/{id}/dkg",
            post(routes::dkg::run_dkg).get(routes::dkg::get_dkg_status),
        )
        // Signing
        .route("/api/v1/networks/{id}/sign", post(routes::signing::sign_message))
        // Batch signing
        .route("/api/v1/networks/{id}/batch-sign", post(routes::batch::batch_sign))
        // Verify
        .route("/api/v1/networks/{id}/verify", post(routes::verify::verify_signature))
        // Trace
        .route("/api/v1/networks/{id}/trace", post(routes::trace::trace_signers))
        // Refresh
        .route("/api/v1/networks/{id}/refresh", post(routes::refresh::refresh_network))
        // Ledger
        .route("/api/v1/networks/{id}/ledger", get(routes::ledger::get_ledger))
        // Nodes
        .route("/api/v1/networks/{id}/nodes", get(routes::identity::list_nodes))
        .route(
            "/api/v1/networks/{id}/nodes/{node_id}",
            get(routes::identity::get_node),
        )
        // API Keys (admin)
        .route(
            "/api/v1/api-keys",
            post(routes::api_keys::create_api_key).get(routes::api_keys::list_api_keys),
        )
        .route(
            "/api/v1/api-keys/{id}",
            delete(routes::api_keys::delete_api_key),
        )
        // Layer: rate limiting applied to all routes except health
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware)
        .layer(body_limit)
        .with_state(state);

    Ok(router)
}


