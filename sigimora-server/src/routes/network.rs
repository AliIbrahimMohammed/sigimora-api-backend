//! Network management endpoints.

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::db::NetworkRow;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// POST /api/v1/networks — create a new signing network.
pub async fn create_network(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(req): Json<CreateNetworkRequest>,
) -> Result<Json<CreateNetworkResponse>, ApiError> {
    if req.n < 2 {
        return Err(ApiError::BadRequest("n must be >= 2".to_string()));
    }
    if req.t == 0 || req.t >= req.n {
        return Err(ApiError::BadRequest(
            "t must be between 1 and n-1".to_string(),
        ));
    }

    let f = (req.n - 1) / 3;
    let quorum = req.t + 1;
    let network_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Generate tracking key pair
    let mut rng = rand::rngs::OsRng;
    let tracking = sigimora_ats::TrackingKeyPair::generate(&mut rng);

    let tracking_pk_bytes = tracking.public.to_bytes().to_vec();
    let tracking_sk_bytes = tracking.secret.to_bytes().to_vec();

    // Store network row
    let row = NetworkRow {
        id: network_id.clone(),
        n: req.n as i64,
        t: req.t as i64,
        f: f as i64,
        quorum: quorum as i64,
        collective_pk: None,
        tracking_pk: Some(tracking_pk_bytes),
        tracking_sk: Some(tracking_sk_bytes),
        state: "created".to_string(),
        created_at: now,
    };
    state.db.insert_network(&row).await?;

    // Create nodes inside the network
    for node_id in 1..=req.n as u16 {
        let node_sk = sigimora_math::Scalar::random(&mut rng);
        let node_pk = sigimora_math::G2Point::generator().mul(&node_sk);
        let node = crate::db::NodeRow {
            id: 0,
            node_id: node_id as i64,
            network_id: network_id.clone(),
            public_key: node_pk.to_bytes().to_vec(),
            secret_key: node_sk.to_bytes().to_vec(),
            company_name: Some(format!("Node {}", node_id)),
            epoch: 0,
            created_at: Utc::now().to_rfc3339(),
        };
        state.db.insert_node(&node).await?;
    }

    // Generate a bootstrap API key for this network
    let (raw_key, key_row) = crate::auth::generate_api_key(
        &format!("network-{}", &network_id[..8]),
        "admin",
    );
    state.db.insert_api_key(&key_row).await?;

    let network_info = NetworkInfo {
        id: network_id,
        n: req.n,
        t: req.t,
        f,
        quorum,
        collective_pk_hex: None,
        tracking_pk_hex: Some(hex::encode(tracking.public.to_bytes())),
        state: "created".to_string(),
        created_at: Utc::now(),
        node_count: req.n,
    };

    Ok(Json(CreateNetworkResponse {
        network: network_info,
        tracking_secret_key_hex: hex::encode(tracking.secret.to_bytes()),
        bootstrap_api_key: raw_key,
    }))
}

/// GET /api/v1/networks — list all networks.
pub async fn list_networks(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<NetworkInfo>>, ApiError> {
    let rows = state.db.list_networks().await?;
    let mut networks = Vec::with_capacity(rows.len());

    for row in rows {
        let node_count = state.db.count_nodes_by_network(&row.id).await?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.to_utc())
            .unwrap_or_else(|_| Utc::now());

        networks.push(NetworkInfo {
            id: row.id,
            n: row.n as usize,
            t: row.t as usize,
            f: row.f as usize,
            quorum: row.quorum as usize,
            collective_pk_hex: row.collective_pk.as_ref().map(|b| hex::encode(b)),
            tracking_pk_hex: row.tracking_pk.as_ref().map(|b| hex::encode(b)),
            state: row.state,
            created_at,
            node_count,
        });
    }

    Ok(Json(networks))
}

/// GET /api/v1/networks/:id — get network details.
pub async fn get_network(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<NetworkInfo>, ApiError> {
    let row = state
        .db
        .get_network(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", id)))?;

    let node_count = state.db.count_nodes_by_network(&id).await?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .map(|dt| dt.to_utc())
        .unwrap_or_else(|_| Utc::now());

    Ok(Json(NetworkInfo {
        id: row.id,
        n: row.n as usize,
        t: row.t as usize,
        f: row.f as usize,
        quorum: row.quorum as usize,
        collective_pk_hex: row.collective_pk.as_ref().map(|b| hex::encode(b)),
        tracking_pk_hex: row.tracking_pk.as_ref().map(|b| hex::encode(b)),
        state: row.state,
        created_at,
        node_count,
    }))
}
