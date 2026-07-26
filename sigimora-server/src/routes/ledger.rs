//! Ledger (blockchain) endpoints.

use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::Utc;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// GET /api/v1/networks/:id/ledger — view the transaction ledger.
pub async fn get_ledger(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<LedgerResponse>, ApiError> {
    // Verify network exists
    let _net = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    let rows = state
        .db
        .get_ledger_by_network(&network_id, pagination.offset(), pagination.limit())
        .await?;
    let total = state.db.count_ledger_by_network(&network_id).await?;

    let entries: Vec<LedgerEntry> = rows
        .iter()
        .map(|r| {
            let ts = chrono::DateTime::parse_from_rfc3339(&r.created_at)
                .map(|dt| dt.to_utc())
                .unwrap_or_else(|_| Utc::now());
            let signers: Vec<u16> = serde_json::from_str(&r.signers).unwrap_or_default();
            LedgerEntry {
                block_index: r.block_index as u64,
                tx_id: r.tx_id.clone(),
                payload_hash_hex: hex::encode(&r.message_hash),
                signers,
                epoch: r.epoch as u64,
                timestamp: ts,
                signature_hex: r.signature.as_ref().map(|b| hex::encode(b)).unwrap_or_default(),
            }
        })
        .collect();

    Ok(Json(LedgerResponse { entries, total }))
}
