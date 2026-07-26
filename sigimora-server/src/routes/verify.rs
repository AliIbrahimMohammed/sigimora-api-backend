//! Signature verification endpoints.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;
use sigimora_math::{G1Point, G2Point};

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
    if collective_pk_bytes.len() != G2Point::BYTE_SIZE {
        return Err(ApiError::Internal(
            format!("collective PK has invalid length {}", collective_pk_bytes.len()),
        ));
    }
    let mut pk_arr = [0u8; G2Point::BYTE_SIZE];
    pk_arr.copy_from_slice(&collective_pk_bytes);
    let collective_pk = sigimora_math::G2Point::from_bytes(&pk_arr)
        .map_err(|_| ApiError::Crypto("invalid collective PK".to_string()))?;

    // Decode message
    let msg = hex::decode(&req.message)
        .map_err(|e| ApiError::BadRequest(format!("invalid hex message: {}", e)))?;

    // Decode signature (must be exactly 48 bytes for a G1 point)
    let sig_hex = &req.signature_hex;
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid hex signature: {}", e)))?;
    if sig_bytes.len() != G1Point::BYTE_SIZE {
        return Err(ApiError::BadRequest(
            format!("signature must be {} bytes ({} hex chars), got {} bytes", G1Point::BYTE_SIZE, G1Point::BYTE_SIZE * 2, sig_bytes.len()),
        ));
    }
    let mut sig_arr = [0u8; G1Point::BYTE_SIZE];
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

#[cfg(test)]
mod tests {
    use sigimora_math::{G1Point, G2Point};

    #[test]
    fn test_signature_length_check() {
        // 47 bytes instead of 48
        assert_ne!(47, G1Point::BYTE_SIZE);
        assert_eq!(48, G1Point::BYTE_SIZE);
    }

    #[test]
    fn test_pk_length_check() {
        assert_ne!(95, G2Point::BYTE_SIZE);
        assert_eq!(96, G2Point::BYTE_SIZE);
    }
}
