//! Node identity / membership endpoints.

use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::Utc;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// GET /api/v1/networks/:id/nodes — list nodes in a network (with pagination).
pub async fn list_nodes(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<PaginatedNodesResponse>, ApiError> {
    // Verify network exists
    let _net = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    let offset = pagination.offset();
    let limit = pagination.limit();
    let total = state.db.count_nodes_by_network(&network_id).await?;
    let node_rows = state.db.get_nodes_by_network_paginated(&network_id, offset, limit).await?;
    let nodes: Vec<NodeInfo> = node_rows
        .iter()
        .map(|r| NodeInfo {
            node_id: r.node_id as u16,
            network_id: network_id.clone(),
            public_key_hex: hex::encode(&r.public_key),
            address_hex: hex::encode(
                &sigimora_math::hash_to_g1(&r.public_key, b"SIGIMORA-ADDR").to_bytes()[..20],
            ),
            company_name: r.company_name.clone(),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                .map(|dt| dt.to_utc())
                .unwrap_or_else(|_| Utc::now()),
            epoch: r.epoch as u64,
            is_signer: true,
        })
        .collect();

    Ok(Json(PaginatedNodesResponse { nodes, total, offset, limit }))
}

/// GET /api/v1/networks/:id/nodes/:node_id — get a specific node.
pub async fn get_node(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path((network_id, node_id)): Path<(String, u16)>,
) -> Result<Json<NodeInfo>, ApiError> {
    let row = state
        .db
        .get_node(&network_id, node_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("node {} not found in network", node_id)))?;

    Ok(Json(NodeInfo {
        node_id: row.node_id as u16,
        network_id,
        public_key_hex: hex::encode(&row.public_key),
        address_hex: hex::encode(
            &sigimora_math::hash_to_g1(&row.public_key, b"SIGIMORA-ADDR").to_bytes()[..20],
        ),
        company_name: row.company_name,
        created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.to_utc())
            .unwrap_or_else(|_| Utc::now()),
        epoch: row.epoch as u64,
        is_signer: true,
    }))
}
