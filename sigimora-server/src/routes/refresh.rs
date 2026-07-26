//! Proactive key refresh endpoints.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// POST /api/v1/networks/:id/refresh — trigger proactive key refresh.
pub async fn refresh_network(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<RefreshResponse>, ApiError> {
    let net_row = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    if net_row.state != "dkg_complete" {
        return Err(ApiError::BadRequest(format!(
            "network is in state {:?}, need 'dkg_complete'",
            net_row.state
        )));
    }

    let n = net_row.n as usize;
    let t = net_row.t as usize;

    // Load nodes
    let node_rows = state.db.get_nodes_by_network(&network_id).await?;
    if node_rows.len() != n {
        return Err(ApiError::Internal(format!(
            "expected {} nodes, found {}",
            n,
            node_rows.len()
        )));
    }

    // Decode current secret keys (must be exactly 32 bytes)
    let mut current_keys: Vec<sigimora_math::Scalar> = Vec::new();
    for row in &node_rows {
        if row.secret_key.len() != 32 {
            return Err(ApiError::Internal(format!(
                "node {} secret key has invalid length {}",
                row.node_id,
                row.secret_key.len(),
            )));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&row.secret_key);
        let sk = sigimora_math::Scalar::from_bytes(&b)
            .map_err(|_| ApiError::Crypto("invalid secret key".to_string()))?;
        current_keys.push(sk);
    }

    let pks_before: Vec<sigimora_math::G2Point> = current_keys
        .iter()
        .map(|k| sigimora_math::G2Point::generator().mul(k))
        .collect();

    // Run refresh
    let manager = sigimora_refresh::RefreshManager::new(n, t);
    let contributions: Vec<sigimora_refresh::RefreshContribution> = (1..=n as u16)
        .map(|i| manager.generate_contribution(i))
        .collect();

    let keys_after: Vec<sigimora_math::Scalar> = current_keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            sigimora_refresh::RefreshManager::apply_contributions(k, (i + 1) as u16, &contributions)
                .map_err(|e| ApiError::Crypto(format!("refresh apply: {}", e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let pks_after: Vec<sigimora_math::G2Point> = keys_after
        .iter()
        .map(|k| sigimora_math::G2Point::generator().mul(k))
        .collect();

    // Verify invariant
    let quorum: Vec<u16> = (1..=n as u16).take(t + 1).collect();
    let invariant = sigimora_refresh::RefreshManager::verify_collective_key_invariant(
        &pks_before, &pks_after, &quorum,
    );

    // Update node secret keys and epoch in DB
    let epoch = (node_rows.first().map(|r| r.epoch).unwrap_or(0) + 1) as u64;
    for (i, row) in node_rows.iter().enumerate() {
        let new_sk_bytes = keys_after[i].to_bytes().to_vec();
        state
            .db
            .update_node_secret(&network_id, row.node_id as u16, &new_sk_bytes)
            .await?;
        // Also update epoch
        sqlx::query("UPDATE nodes SET epoch = ? WHERE id = ?")
            .bind(epoch as i64)
            .bind(row.id)
            .execute(state.db.pool())
            .await?;
    }

    Ok(Json(RefreshResponse {
        network_id,
        epoch,
        invariant_preserved: invariant,
        message: format!(
            "Proactive refresh complete. Collective key invariant preserved: {}",
            invariant
        ),
    }))
}
