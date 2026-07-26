//! Axum extractors for common route parameters.

use axum::extract::{FromRef, FromRequestParts, Path};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use std::fmt;

use crate::db::NetworkRow;
use crate::error::ApiError;
use crate::state::AppState;

/// Extractor that loads a NetworkRow by its ID from the URL path.
/// Returns 404 if the network doesn't exist.
///
/// Usage:
/// ```ignore
/// async fn my_handler(State(state): State<AppState>, net: NetworkGuard) -> Result<..., ApiError> {
///     let network = net.0; // NetworkRow
/// }
/// ```
#[derive(Debug, Clone)]
pub struct NetworkGuard(pub NetworkRow);

impl<S> FromRequestParts<S> for NetworkGuard
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let network_id_path = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|e| {
                ApiError::BadRequest(format!("invalid network ID: {}", e)).into_response()
            })?;
        let network_id = network_id_path.0;

        let row = app_state
            .db
            .get_network(&network_id)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()).into_response())?
            .ok_or_else(|| {
                ApiError::NotFound(format!("network {} not found", network_id)).into_response()
            })?;

        Ok(NetworkGuard(row))
    }
}
