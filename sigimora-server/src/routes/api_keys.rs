//! API key management endpoints (admin only).

use axum::extract::{Path, Query, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// POST /api/v1/api-keys — create a new API key.
pub async fn create_api_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    if user.role != "admin" {
        return Err(ApiError::Unauthorized("only admins can create API keys".to_string()));
    }

    let role = req.role.as_deref().unwrap_or("user");
    if role != "admin" && role != "user" {
        return Err(ApiError::BadRequest("role must be 'admin' or 'user'".to_string()));
    }

    let (raw_key, row) = crate::auth::generate_api_key(&req.label, role);
    state.db.insert_api_key(&row).await?;

    Ok(Json(CreateApiKeyResponse {
        api_key: ApiKeyInfo {
            id: row.id,
            key_prefix: row.key_prefix,
            label: row.label,
            role: row.role,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.to_utc())
                .unwrap_or_else(|_| chrono::Utc::now()),
            last_used_at: None,
        },
        raw_key,
    }))
}

/// GET /api/v1/api-keys — list all API keys (with pagination).
pub async fn list_api_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<PaginatedApiKeysResponse>, ApiError> {
    if user.role != "admin" {
        return Err(ApiError::Unauthorized("only admins can list API keys".to_string()));
    }

    let offset = pagination.offset();
    let limit = pagination.limit();
    let total = state.db.count_api_keys().await?;
    let rows = state.db.list_api_keys_paginated(offset, limit).await?;
    let keys: Vec<ApiKeyInfo> = rows
        .iter()
        .map(|r| ApiKeyInfo {
            id: r.id.clone(),
            key_prefix: r.key_prefix.clone(),
            label: r.label.clone(),
            role: r.role.clone(),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                .map(|dt| dt.to_utc())
                .unwrap_or_else(|_| chrono::Utc::now()),
            last_used_at: r.last_used_at.as_ref().and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.to_utc())
                    .ok()
            }),
        })
        .collect();

    Ok(Json(PaginatedApiKeysResponse { api_keys: keys, total, offset, limit }))
}

/// DELETE /api/v1/api-keys/:id — revoke (delete) an API key.
pub async fn delete_api_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if user.role != "admin" {
        return Err(ApiError::Unauthorized(
            "only admins can delete API keys".to_string(),
        ));
    }

    let deleted = state.db.delete_api_key(&id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("api key {} not found", id)));
    }

    // Audit
    crate::audit::audit("api_key.delete", &user.id, &id, "API key revoked");

    Ok(Json(serde_json::json!({ "deleted": true })))
}
