//! Health-check endpoint.

use axum::extract::State;
use axum::Json;

use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// GET /api/v1/health — health check v2.
pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, ApiError> {
    let uptime = state.start_time.elapsed().as_secs();

    // DB connectivity check
    let db_status = match sqlx::query("SELECT 1").execute(state.db.pool()).await {
        Ok(_) => "connected".to_string(),
        Err(e) => format!("error: {}", e),
    };

    // Lightweight counts
    let networks = state.db.count_networks().await?;
    let nodes = state.db.count_all_nodes().await?;
    let ledger = state.db.count_all_ledger_entries().await?;
    let api_keys = state.db.count_api_keys().await?;

    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        uptime_human: state.uptime_human(),
        networks,
        nodes,
        ledger_entries: ledger,
        api_keys,
        db_status,
        cache_age_secs: None, // in-memory cache not yet implemented
        crypto_backend: "BLS12-381 (blstrs/blst) + Pedersen DKG + ATS".to_string(),
    }))
}
