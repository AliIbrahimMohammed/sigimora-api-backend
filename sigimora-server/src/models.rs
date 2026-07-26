//! Request / response types for the REST API.
//!
//! These are serialised as JSON bodies both for requests and responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ══════════════════════════════════════════════════════════════════════════
//  Network
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub id: String,                          // UUID
    pub n: usize,
    pub t: usize,
    pub f: usize,
    pub quorum: usize,
    pub collective_pk_hex: Option<String>,
    pub tracking_pk_hex: Option<String>,
    pub state: String,                       // "created" | "dkg_complete" | "active"
    pub created_at: DateTime<Utc>,
    pub node_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct CreateNetworkRequest {
    pub n: usize,
    pub t: usize,
}

#[derive(Debug, Serialize)]
pub struct CreateNetworkResponse {
    pub network: NetworkInfo,
    pub tracking_secret_key_hex: String,     // only returned at creation
    pub bootstrap_api_key: String,
}

// ══════════════════════════════════════════════════════════════════════════
//  DKG
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct DkgStatusResponse {
    pub network_id: String,
    pub state: String,
    pub collective_pk_hex: Option<String>,
    pub member_count: usize,
    pub threshold: usize,
}

// ══════════════════════════════════════════════════════════════════════════
//  Signing
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub message: String,                     // hex-encoded message bytes
    pub quorum: Vec<u16>,                    // which nodes should sign
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub tx_id: String,                       // UUID
    pub combined_sig_hex: String,
    pub quorum: Vec<u16>,
    pub message_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub message: String,                     // hex-encoded original message
    pub signature_hex: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub quorum: Vec<u16>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub network_id: String,
}

// ══════════════════════════════════════════════════════════════════════════
//  Trace
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct TraceRequest {
    pub tx_id: String,
    pub tracking_key_hex: String,
}

#[derive(Debug, Serialize)]
pub struct TraceResponse {
    pub signers: Vec<SignerInfo>,
}

#[derive(Debug, Serialize)]
pub struct SignerInfo {
    pub node_id: u16,
    pub public_key_hex: String,
    pub timestamp: Option<DateTime<Utc>>,
}

// ══════════════════════════════════════════════════════════════════════════
//  Refresh
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub network_id: String,
    pub epoch: u64,
    pub invariant_preserved: bool,
    pub message: String,
}

// ══════════════════════════════════════════════════════════════════════════
//  Ledger
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct LedgerEntry {
    pub block_index: u64,
    pub tx_id: String,
    pub payload_hash_hex: String,
    pub signers: Vec<u16>,
    pub epoch: u64,
    pub timestamp: DateTime<Utc>,
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct LedgerResponse {
    pub entries: Vec<LedgerEntry>,
    pub total: usize,
}

// ══════════════════════════════════════════════════════════════════════════
//  Identity / Node
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub node_id: u16,
    pub network_id: String,
    pub public_key_hex: String,
    pub address_hex: String,
    pub company_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub epoch: u64,
    pub is_signer: bool,
}

// ══════════════════════════════════════════════════════════════════════════
//  Health
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,                      // "ok"
    pub version: String,
    pub uptime_seconds: u64,
    pub networks: usize,
    pub nodes: usize,
    pub ledger_entries: usize,
    pub crypto_backend: String,
}

// ══════════════════════════════════════════════════════════════════════════
//  API Key management
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub label: String,
    pub role: Option<String>,                // "admin" | "user" (default "user")
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub key_prefix: String,
    pub label: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: ApiKeyInfo,
    pub raw_key: String,                    // full key, only shown once
}

// ══════════════════════════════════════════════════════════════════════════
//  Generic pagination / listing
// ══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

impl PaginationParams {
    pub fn offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(100).min(1000)
    }
}
