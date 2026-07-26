//! Audit log viewer (admin only).

use axum::extract::{Query, State};
use axum::Json;

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::models::*;
use crate::state::AppState;

/// GET /api/v1/audit-logs — list audit log entries (admin only, paginated).
pub async fn list_audit_logs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<PaginatedAuditLogsResponse>, ApiError> {
    if user.role != "admin" {
        return Err(ApiError::Unauthorized("only admins can view audit logs".to_string()));
    }

    let offset = pagination.offset();
    let limit = pagination.limit();
    let total = state.db.count_audit_logs().await?;
    let rows = state.db.list_audit_logs_paginated(offset, limit).await?;
    let entries: Vec<AuditLogEntry> = rows
        .iter()
        .map(|r| AuditLogEntry {
            id: r.id,
            timestamp: r.timestamp.clone(),
            action: r.action.clone(),
            actor: r.actor.clone(),
            target: r.target.clone(),
            details: r.details.clone(),
        })
        .collect();

    Ok(Json(PaginatedAuditLogsResponse { entries, total, offset, limit }))
}
