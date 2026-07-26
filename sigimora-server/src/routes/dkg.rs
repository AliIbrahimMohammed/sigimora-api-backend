//! DKG (Distributed Key Generation) endpoints.
//!
//! Runs a full Pedersen DKG across all nodes in the network,
//! producing a collective public key and per-node secret shares.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// POST /api/v1/networks/:id/dkg — run DKG for all nodes.
pub async fn run_dkg(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<DkgStatusResponse>, ApiError> {
    let net_row = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    if net_row.state != "created" && net_row.state != "dkg_complete" {
        return Err(ApiError::BadRequest(format!(
            "network is in state {:?}, expected 'created' or 'dkg_complete'",
            net_row.state
        )));
    }

    let n = net_row.n as usize;
    let t = net_row.t as usize;

    // Load all nodes
    let node_rows = state.db.get_nodes_by_network(&network_id).await?;
    if node_rows.len() != n {
        return Err(ApiError::Internal(format!(
            "expected {} nodes, found {}",
            n,
            node_rows.len()
        )));
    }

    // Run Pedersen DKG across all nodes
    let mut rng = rand::rngs::OsRng;
    let pedersen = sigimora_crypto::pedersen::PedersenSetup::deterministic();

    // Create DKG states for each node
    let mut dkg_states: Vec<sigimora_crypto::dkg::DkgState> = (0..n)
        .map(|i| {
            let id = (i + 1) as u16;
            let mut s = sigimora_crypto::dkg::DkgState::new(n, t, id, pedersen.clone());
            s.start(&mut rng);
            s
        })
        .collect();

    // Exchange commitments
    let pks: Vec<_> = dkg_states
        .iter()
        .map(|s| s.my_public_key().unwrap())
        .collect();
    let vss_list: Vec<_> = dkg_states
        .iter()
        .map(|s| s.my_vss_public().unwrap())
        .collect();

    for i in 0..n {
        for j in 0..n {
            if i != j {
                let vss = sigimora_crypto::pedersen::VssPublic {
                    commitments: vss_list[i].commitments.clone(),
                };
                dkg_states[j]
                    .process_participant_commit(i as u16 + 1, pks[i].clone(), vss)
                    .map_err(|e| ApiError::Crypto(format!("DKG commit processing: {}", e)))?;
            }
        }
    }

    // Exchange shares
    for i in 0..n {
        for j in 0..n {
            if i != j {
                let share = dkg_states[i]
                    .shares_for((j + 1) as u16)
                    .ok_or_else(|| ApiError::Crypto(format!("DKG share generation for node {}", j + 1)))?;
                dkg_states[j]
                    .process_received_share(i as u16 + 1, share)
                    .map_err(|e| ApiError::Crypto(format!("DKG share processing: {}", e)))?;
            }
        }
    }

    // Finalize
    let outputs: Vec<sigimora_crypto::dkg::DkgOutput> = dkg_states
        .iter_mut()
        .map(|s| s.finalize().map_err(|e| ApiError::Crypto(format!("DKG finalize: {}", e))))
        .collect::<Result<Vec<_>, _>>()?;

    let collective_pk = outputs[0].collective_pk.clone();
    let collective_pk_bytes = collective_pk.to_bytes().to_vec();

    // Save DKG secret shares to node records in DB.
    // In a production multi-party setup each node would store its own secret,
    // but for this server-coordinated flow we persist them centrally.
    for (i, output) in outputs.iter().enumerate() {
        let node_id = (i + 1) as u16;
        let secret_bytes = output.my_secret.to_bytes().to_vec();
        state
            .db
            .update_node_secret(&network_id, node_id, &secret_bytes)
            .await?;
    }

    // Update network state
    state
        .db
        .update_network_state(&network_id, "dkg_complete", Some(&collective_pk_bytes))
        .await?;

    Ok(Json(DkgStatusResponse {
        network_id,
        state: "dkg_complete".to_string(),
        collective_pk_hex: Some(hex::encode(collective_pk_bytes)),
        member_count: n,
        threshold: t + 1,
    }))
}

/// GET /api/v1/networks/:id/dkg — get DKG status.
pub async fn get_dkg_status(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<DkgStatusResponse>, ApiError> {
    let net_row = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    Ok(Json(DkgStatusResponse {
        network_id,
        state: net_row.state,
        collective_pk_hex: net_row.collective_pk.as_ref().map(|b| hex::encode(b)),
        member_count: net_row.n as usize,
        threshold: (net_row.t + 1) as usize,
    }))
}
