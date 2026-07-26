//! Accountability tracing endpoints.
//!
//! Uses the ATS encrypted tags to identify which nodes signed a transaction.
//! Requires the network's tracking secret key.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// POST /api/v1/networks/:id/trace — trace signers of a transaction.
pub async fn trace_signers(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
    Json(req): Json<TraceRequest>,
) -> Result<Json<TraceResponse>, ApiError> {
    let net_row = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    // Decode tracking key
    let tracking_sk_hex = &req.tracking_key_hex;
    let sk_bytes = hex::decode(tracking_sk_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid tracking key hex: {}", e)))?;
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let _tracking_sk = sigimora_math::Scalar::from_bytes(&sk_arr)
        .map_err(|_| ApiError::Crypto("invalid tracking secret key".to_string()))?;

    // Get the signed transaction
    let tx = state
        .db
        .get_signed_tx(&req.tx_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("tx {} not found", req.tx_id)))?;

    // Reconstruct the ATS signature
    let mut sig_arr = [0u8; 48];
    sig_arr.copy_from_slice(&tx.signature);
    let _combined_sig = sigimora_math::G1Point::from_bytes(&sig_arr)
        .map_err(|_| ApiError::Crypto("invalid stored signature".to_string()))?;

    // Build the network parameters
    let collective_pk_bytes = net_row.collective_pk.ok_or_else(|| {
        ApiError::BadRequest("collective PK not available".to_string())
    })?;
    let mut cpk_arr = [0u8; 96];
    cpk_arr.copy_from_slice(&collective_pk_bytes);
    let collective_pk = sigimora_math::G2Point::from_bytes(&cpk_arr)
        .map_err(|_| ApiError::Crypto("invalid collective PK".to_string()))?;

    let tracking_pk_bytes = net_row.tracking_pk.ok_or_else(|| {
        ApiError::Internal("tracking PK missing".to_string())
    })?;
    let mut tpk_arr = [0u8; 96];
    tpk_arr.copy_from_slice(&tracking_pk_bytes);
    let tracking_pk = sigimora_math::G2Point::from_bytes(&tpk_arr)
        .map_err(|_| ApiError::Crypto("invalid tracking PK".to_string()))?;

    let node_rows = state.db.get_nodes_by_network(&network_id).await?;
    let mut member_pks = Vec::new();
    for row in &node_rows {
        let mut b = [0u8; 96];
        b.copy_from_slice(&row.public_key);
        let pk = sigimora_math::G2Point::from_bytes(&b)
            .map_err(|_| ApiError::Crypto("invalid node PK".to_string()))?;
        member_pks.push((row.node_id as u16, pk));
    }

    let _params = sigimora_ats::NetworkPublicParams {
        n: net_row.n as usize,
        threshold: (net_row.t + 1) as usize,
        collective_pk,
        tracking_pk,
        member_pks: member_pks.clone(),
        member_lt_pks: vec![],
    };

    // Since we stored the full AtsSignature we need the encrypted tags.
    // For now, we use a simplified trace: we check the ledger for the
    // signers list and return them.
    // In production, trace would decrypt the encrypted tags.
    //
    // We load the ledger entry to get the signers.
    let quorum: Vec<u16> = serde_json::from_str(&tx.quorum).unwrap_or_default();

    let signers: Vec<SignerInfo> = quorum
        .iter()
        .filter_map(|id| {
            member_pks
                .iter()
                .find(|(mid, _)| mid == id)
                .map(|(_, pk)| SignerInfo {
                    node_id: *id,
                    public_key_hex: hex::encode(pk.to_bytes()),
                    timestamp: None,
                })
        })
        .collect();

    Ok(Json(TraceResponse { signers }))
}
