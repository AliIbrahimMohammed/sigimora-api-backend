//! Health-check endpoint.

use axum::extract::State;
use axum::Json;

use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// GET /api/v1/health
pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, ApiError> {
    let uptime = state.start_time.elapsed().as_secs();

    // Lightweight counts: use COUNT queries instead of loading all rows
    let networks = state.db.count_networks().await?;
    let nodes = state.db.count_all_nodes().await?;
    let ledger = state.db.count_all_ledger_entries().await?;

    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        networks,
        nodes,
        ledger_entries: ledger,
        crypto_backend: "BLS12-381 (blstrs/blst) + Pedersen DKG + ATS".to_string(),
    }))
}
