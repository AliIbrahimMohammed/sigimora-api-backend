//! Batch signing endpoint.
//!
//! Signs multiple messages in a single request using the same quorum.
//! More efficient than N sequential `/sign` calls because network
//! parameters are loaded and validated once.

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;
use sigimora_math::{G1Point, G2Point, Scalar};

/// POST /api/v1/networks/:id/batch-sign — threshold-sign multiple messages.
pub async fn batch_sign(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(network_id): Path<String>,
    Json(req): Json<BatchSignRequest>,
) -> Result<Json<BatchSignResponse>, ApiError> {
    if req.messages.is_empty() {
        return Err(ApiError::BadRequest(
            "messages list must not be empty".to_string(),
        ));
    }
    if req.messages.len() > 100 {
        return Err(ApiError::BadRequest(
            "maximum 100 messages per batch request".to_string(),
        ));
    }

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

    // Check quorum size
    if req.quorum.len() < t + 1 {
        return Err(ApiError::BadRequest(format!(
            "quorum size {} < threshold {}",
            req.quorum.len(),
            t + 1
        )));
    }

    // Load nodes
    let node_rows = state.db.get_nodes_by_network(&network_id).await?;
    if node_rows.len() != n {
        return Err(ApiError::Internal(format!(
            "expected {} nodes, found {}",
            n,
            node_rows.len()
        )));
    }

    // Build network parameters once
    let collective_pk_bytes = net_row.collective_pk.ok_or_else(|| {
        ApiError::BadRequest("collective PK not available — run DKG first".to_string())
    })?;
    if collective_pk_bytes.len() != G2Point::BYTE_SIZE {
        return Err(ApiError::Internal(format!(
            "collective PK has invalid length {}",
            collective_pk_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; G2Point::BYTE_SIZE];
    pk_arr.copy_from_slice(&collective_pk_bytes);
    let collective_pk = sigimora_math::G2Point::from_bytes(&pk_arr)
        .map_err(|_| ApiError::Crypto("invalid collective PK bytes".to_string()))?;

    let tracking_pk_bytes = net_row.tracking_pk.ok_or_else(|| {
        ApiError::Internal("tracking PK missing".to_string())
    })?;
    if tracking_pk_bytes.len() != G2Point::BYTE_SIZE {
        return Err(ApiError::Internal(format!(
            "tracking PK has invalid length {}",
            tracking_pk_bytes.len()
        )));
    }
    let mut tp_arr = [0u8; G2Point::BYTE_SIZE];
    tp_arr.copy_from_slice(&tracking_pk_bytes);
    let tracking_pk = sigimora_math::G2Point::from_bytes(&tp_arr)
        .map_err(|_| ApiError::Crypto("invalid tracking PK bytes".to_string()))?;

    // Build member PK list and signer configs
    let mut member_pks = Vec::new();
    let mut signer_configs = Vec::new();
    let mut rng = rand::rngs::OsRng;

    for node_row in &node_rows {
        let node_id = node_row.node_id as u16;
        if node_row.public_key.len() != G2Point::BYTE_SIZE {
            return Err(ApiError::Internal(format!(
                "node {} PK has invalid length {}",
                node_id,
                node_row.public_key.len()
            )));
        }
        let mut pk_b = [0u8; G2Point::BYTE_SIZE];
        pk_b.copy_from_slice(&node_row.public_key);
        let pk = sigimora_math::G2Point::from_bytes(&pk_b)
            .map_err(|_| ApiError::Crypto("invalid node PK".to_string()))?;
        member_pks.push((node_id, pk));

        let lt_sk = sigimora_math::Scalar::random(&mut rng);

        if node_row.secret_key.len() != Scalar::BYTE_SIZE {
            return Err(ApiError::Internal(format!(
                "node {} secret key has invalid length {} (expected 32)",
                node_row.node_id,
                node_row.secret_key.len(),
            )));
        }
        let mut sk_b = [0u8; Scalar::BYTE_SIZE];
        sk_b.copy_from_slice(&node_row.secret_key);
        let dkg_share = sigimora_math::Scalar::from_bytes(&sk_b)
            .map_err(|_| ApiError::Crypto("invalid node secret key".to_string()))?;

        let cfg = sigimora_ats::SignerConfig::new(node_id, dkg_share, lt_sk);
        signer_configs.push((node_id, cfg));
    }

    let params = sigimora_ats::NetworkPublicParams {
        n,
        threshold: t + 1,
        collective_pk,
        tracking_pk,
        member_pks,
        member_lt_pks: signer_configs
            .iter()
            .map(|(id, c)| (*id, c.lt_pk.clone()))
            .collect(),
    };

    // Select quorum once
    let quorum_cfgs: Vec<&sigimora_ats::SignerConfig> = req
        .quorum
        .iter()
        .filter_map(|qid| {
            signer_configs
                .iter()
                .find(|(id, _)| id == qid)
                .map(|(_, cfg)| cfg)
        })
        .collect();

    if quorum_cfgs.len() < t + 1 {
        return Err(ApiError::BadRequest(format!(
            "only {} of {} requested signers found in network",
            quorum_cfgs.len(),
            req.quorum.len()
        )));
    }

    // Sign each message
    let mut signatures = Vec::with_capacity(req.messages.len());
    for msg_hex in &req.messages {
        let msg = hex::decode(msg_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid hex message '{}': {}", msg_hex, e)))?;

        let partials: Vec<sigimora_ats::PartialSignature> = quorum_cfgs
            .iter()
            .map(|s| sigimora_ats::sign_partial(s, &msg, &params.tracking_pk, &mut rng))
            .collect();

        let sig = sigimora_ats::aggregate(&partials, &params, 0, req.quorum[0])?;

        let tx_id = Uuid::new_v4().to_string();
        let combined_sig_hex = hex::encode(sig.combined_sig.to_bytes());
        let h = sigimora_math::hash_to_g1(&msg, b"SIGIMORA_ATS");

        // Store in ledger
        let ledger_entry = crate::db::LedgerRow {
            block_index: 0,
            tx_id: tx_id.clone(),
            network_id: network_id.clone(),
            message_hash: h.to_bytes().to_vec(),
            signature: Some(sig.combined_sig.to_bytes().to_vec()),
            signers: serde_json::to_string(&req.quorum).unwrap_or_default(),
            epoch: 0,
            created_at: Utc::now().to_rfc3339(),
        };
        state.db.insert_ledger_entry(&ledger_entry).await?;

        // Store signed tx
        let signed_tx = crate::db::SignedTxRow {
            tx_id: tx_id.clone(),
            network_id: network_id.clone(),
            message: msg.clone(),
            signature: sig.combined_sig.to_bytes().to_vec(),
            quorum: serde_json::to_string(&req.quorum).unwrap_or_default(),
            created_at: Utc::now().to_rfc3339(),
        };
        state.db.insert_signed_tx(&signed_tx).await?;

        signatures.push(BatchSignEntry {
            message_hex: msg_hex.clone(),
            tx_id,
            combined_sig_hex,
            message_hash_hex: hex::encode(h.to_bytes()),
        });
    }

    // Audit
    crate::audit::audit(
        "batch_sign",
        &user.id,
        &network_id,
        &format!("signed {} messages with quorum {:?}", signatures.len(), req.quorum),
    );

    Ok(Json(BatchSignResponse {
        network_id,
        quorum: req.quorum,
        count: signatures.len(),
        signatures,
    }))
}
