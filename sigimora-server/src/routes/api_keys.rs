//! API key management endpoints (admin only).

use axum::extract::State;
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

/// GET /api/v1/api-keys — list all API keys.
pub async fn list_api_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<ApiKeyInfo>>, ApiError> {
    if user.role != "admin" {
        return Err(ApiError::Unauthorized("only admins can list API keys".to_string()));
    }

    let rows = state.db.list_api_keys().await?;
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

    Ok(Json(keys))
}
