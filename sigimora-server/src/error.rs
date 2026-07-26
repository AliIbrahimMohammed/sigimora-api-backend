//! Unified error types for the REST API.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Machine-readable error codes for API responses.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ErrorCode {
    NotFound,
    BadRequest,
    Unauthorized,
    InternalError,
    DatabaseError,
    CryptoError,
    RateLimited,
    NetworkNotReady,
    InvalidSignature,
    InvalidKey,
    NetworkNotFound,
    KeyNotFound,
    NodeNotFound,
    TxNotFound,
}

/// Top-level API error.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl ApiError {
    /// Map this error to a machine-readable error code.
    pub fn code(&self) -> ErrorCode {
        match &self {
            ApiError::NotFound(_) => ErrorCode::NotFound,
            ApiError::BadRequest(_) => ErrorCode::BadRequest,
            ApiError::Unauthorized(_) => ErrorCode::Unauthorized,
            ApiError::Internal(_) => ErrorCode::InternalError,
            ApiError::Database(_) => ErrorCode::DatabaseError,
            ApiError::Crypto(_) => ErrorCode::CryptoError,
        }
    }
}

// Allow converting various error types into ApiError.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl From<sigimora_ats::AtsError> for ApiError {
    fn from(e: sigimora_ats::AtsError) -> Self {
        ApiError::Crypto(e.to_string())
    }
}

impl From<sigimora_mcp::McpError> for ApiError {
    fn from(e: sigimora_mcp::McpError) -> Self {
        ApiError::Crypto(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            ApiError::Database(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.to_string()),
            ApiError::Crypto(m) => (StatusCode::BAD_REQUEST, m.clone()),
        };

        let body = json!({
            "error": self.to_string(),
            "message": message,
            "code": self.code(),
        });

        (status, Json(body)).into_response()
    }
}
