//! Signature verification endpoints.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// POST /api/v1/networks/:id/verify — verify a threshold signature.
pub async fn verify_signature(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(network_id): Path<String>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let net_row = state
        .db
        .get_network(&network_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("network {} not found", network_id)))?;

    let collective_pk_bytes = net_row.collective_pk.ok_or_else(|| {
        ApiError::BadRequest("collective PK not available — run DKG first".to_string())
    })?;
    let mut pk_arr = [0u8; 96];
    pk_arr.copy_from_slice(&collective_pk_bytes);
    let collective_pk = sigimora_math::G2Point::from_bytes(&pk_arr)
        .map_err(|_| ApiError::Crypto("invalid collective PK".to_string()))?;

    // Decode message
    let msg = hex::decode(&req.message)
        .map_err(|e| ApiError::BadRequest(format!("invalid hex message: {}", e)))?;

    // Decode signature
    let sig_bytes = hex::decode(&req.signature_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid hex signature: {}", e)))?;
    let mut sig_arr = [0u8; 48];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = sigimora_math::G1Point::from_bytes(&sig_arr)
        .map_err(|_| ApiError::Crypto("invalid signature point".to_string()))?;

    // Verify using BLS pairing equation: e(sig, g₂) == e(H(m), pk)
    let h = sigimora_math::hash_to_g1(&msg, b"SIGIMORA_ATS");
    let valid = bool::from(sigimora_math::pairing::ct_verify_bls_signature(
        &sig, &h, &collective_pk,
    ));

    Ok(Json(VerifyResponse {
        valid,
        network_id,
    }))
}
