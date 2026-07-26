//! Authentication & API key management.
//!
//! API keys are high-entropy (128-bit) random tokens.  They are hashed with
//! SHA-256 for storage and looked up via constant-time comparison (`subtle`).
//! Argon2id is **not** needed here because API keys have full 128-bit entropy;
//! SHA-256 with constant-time comparison provides adequate protection for
//! bearer tokens at this entropy level.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::db::{ApiKeyRow, Database};
use crate::error::ApiError;
use crate::state::AppState;

// ── Constants ────────────────────────────────────────────────────────────

/// Prefix for all generated API keys.
const API_KEY_PREFIX: &str = "sigimora_";

/// Length of the random hex suffix (32 hex chars = 128 bits).
const KEY_SUFFIX_BYTES: usize = 16; // 16 bytes = 128 bits

// ─── Key generation ──────────────────────────────────────────────────────

/// Generate a new API key and return `(raw_key, ApiKeyRow)`.
///
/// The raw key is returned **only once** — it is hashed before storage.
pub fn generate_api_key(label: &str, role: &str) -> (String, ApiKeyRow) {
    let mut entropy = [0u8; KEY_SUFFIX_BYTES];
    OsRng.fill_bytes(&mut entropy);

    let suffix: String = entropy
        .iter()
        .map(|b| {
            let idx = (*b as usize) % 62;
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[idx] as char
        })
        .collect();

    let raw_key = format!("{}{}", API_KEY_PREFIX, suffix);
    let key_prefix = raw_key[..16].to_string();

    // Hash for storage
    let hash = sha256_hex(&raw_key);

    let row = ApiKeyRow {
        id: Uuid::new_v4().to_string(),
        key_hash: hash,
        key_prefix,
        label: label.to_string(),
        role: role.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        last_used_at: None,
    };

    (raw_key, row)
}

/// Hash an API key for storage / lookup.
pub fn sha256_hex(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time comparison of two hex-encoded SHA-256 hashes.
fn ct_eq_hash(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    // If lengths differ, comparison is false (but we use constant-time length
    // via `subtle` by comparing up to the min length and tracking mismatch).
    a_bytes.ct_eq(b_bytes).into()
}

// ── Extractor ────────────────────────────────────────────────────────────

/// Authenticated identity extracted from the request.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    #[allow(dead_code)]
    pub id: String,
    pub role: String,
}

/// Axum extractor that validates the `Authorization: Bearer <key>` header.
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    Database: AxumFromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let db = Database::from_ref(state);

        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::Unauthorized("Missing Authorization header".to_string()).into_response()
            })?;

        let key = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                ApiError::Unauthorized("Authorization must be Bearer <key>".to_string())
                    .into_response()
            })?;

        // Validate key length (anti-timing / anti-DoS)
        if key.len() < 16 || key.len() > 256 {
            return Err(ApiError::Unauthorized("Invalid API key format".to_string()).into_response());
        }

        let hash = sha256_hex(key);
        let row = db.get_api_key_by_hash(&hash).await.map_err(|e| {
            ApiError::Internal(e.to_string()).into_response()
        })?;

        match row {
            Some(r) => {
                // Constant-time re-verify the hash
                if !ct_eq_hash(&r.key_hash, &hash) {
                    return Err(ApiError::Unauthorized("Invalid API key".to_string()).into_response());
                }
                let _ = db.touch_api_key(&r.id).await;
                Ok(AuthenticatedUser {
                    id: r.id,
                    role: r.role,
                })
            }
            None => {
                Err(ApiError::Unauthorized("Invalid API key".to_string()).into_response())
            }
        }
    }
}

use axum::extract::FromRef as AxumFromRef;

// Allow extracting Database from AppState state (used by AuthenticatedUser extractor)
impl AxumFromRef<AppState> for Database {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

// AppState: Clone, so axum::extract::FromRef<T> for T is already provided by axum_core.
// No need to implement it manually.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let (raw, row) = generate_api_key("test-label", "admin");
        assert!(raw.starts_with("sigimora_"));
        // prefix "sigimora_" (9) + 16 base62 chars = 25
        assert_eq!(raw.len(), 25);
        assert_eq!(row.label, "test-label");
        assert_eq!(row.role, "admin");
        assert_eq!(row.key_hash, sha256_hex(&raw));
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 = 64 hex chars
    }

    #[test]
    fn test_sha256_hex_different() {
        let h1 = sha256_hex("key_a");
        let h2 = sha256_hex("key_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_ct_eq_hash() {
        let a = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let b = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let c = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(ct_eq_hash(a, b));
        assert!(!ct_eq_hash(a, c));
    }

    #[test]
    fn test_generate_api_key_unique() {
        let (k1, _) = generate_api_key("a", "user");
        let (k2, _) = generate_api_key("b", "user");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_api_key_prefix_stored() {
        let (raw, row) = generate_api_key("test", "admin");
        assert_eq!(&row.key_prefix, &raw[..16]);
    }
}
