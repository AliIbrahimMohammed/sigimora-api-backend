# SIGIMORA API

**BFT Accountable Threshold Signing — REST API Backend**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/AliIbrahimMohammed/sigimora-api-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/AliIbrahimMohammed/sigimora-api-backend/actions)
[![Tests](https://img.shields.io/badge/tests-113%20passed-brightgreen.svg)](#test-results)

---

## Overview

SIGIMORA API is a production-ready REST backend for **BFT Accountable Threshold Signing** using **BLS12-381** cryptography. It enables *n* parties to collectively sign messages such that any *t+1* can produce a valid signature, while a **tracking key holder** can cryptographically identify which parties signed.

### What It Offers

| Feature | Description |
|---|---|
| 🔐 **Threshold Signing** | Create secure signing networks with configurable *n* and *t* |
| 🗝️ **Distributed Key Generation** | 5-stage Pedersen DKG produces collective public key & per-node secret shares |
| ✅ **Public Verification** | Anyone verifies signatures via BLS pairing: *e(σ, g₂) == e(H(m), PK)* |
| 🕵️ **Accountability Tracing** | Encrypted ATS tags enable cryptographic signer identification |
| 🔄 **Proactive Refresh** | Zero-polynomial key rotation — new shares, same collective key |
| 📋 **Immutable Ledger** | Append-only record of all signed transactions |
| 🔑 **API Key Auth** | SHA-256 hashed bearer tokens with constant-time comparison |
| 🛡️ **Security Hardened** | Rate limiting, body size limit, CORS allow-list, input validation, audit logging |

### Architecture

```
sigimora-api/
├── sigimora-server         Axum REST API (routes, auth, database, middleware, metrics)
├── sigimora-math           BLS12-381 primitives (Scalar, G1, G2, GT, pairing)
├── sigimora-crypto         BLS, Shamir SSS, Pedersen VSS, 5-stage DKG
├── sigimora-ats            Accountable Threshold Signatures + ECIES tracing
├── sigimora-refresh        Proactive key refresh (zero-polynomial rotation)
└── sigimora-mcp            MPC protocol orchestration engine
```

---

## Quick Start

### Prerequisites

- **Rust** 1.85+ (stable)
- **C toolchain** (GCC/MinGW on Windows, GCC/Clang on Linux/macOS)

### Build & Run

```bash
# Clone
git clone https://github.com/AliIbrahimMohammed/sigimora-api-backend.git
cd sigimora-api-backend

# Build the server
cargo build --release -p sigimora-server

# Run
cargo run --release -p sigimora-server
```

On first run, a **bootstrap admin API key** is logged in the console output. **Save it** — it is your credential for all API calls.

### Docker

```bash
docker compose up --build
```

### Verify

```bash
curl http://localhost:8080/api/v1/health
```

```json
{"status":"ok","version":"1.1.0","uptime_seconds":5,"networks":0,"nodes":0,"ledger_entries":0,"crypto_backend":"BLS12-381 (blstrs/blst) + Pedersen DKG + ATS"}
```

> The `/health` and `/metrics` endpoints are the **only** unauthenticated endpoints.

---

## Configuration

All settings via environment variables, `.env` file, or `sigimora.toml`:

| Variable | Default | Description |
|---|---|---|
| `SIGIMORA_LISTEN` | `0.0.0.0:8080` | TCP bind address |
| `SIGIMORA_DATA_DIR` | `./data` | Data directory (SQLite DB + keys) |
| `SIGIMORA_DATABASE_URL` | *(auto)* | Full SQLite URL (overrides DATA_DIR) |
| `SIGIMORA_LOG_LEVEL` | `info` | Log level |
| `SIGIMORA_BOOTSTRAP_KEYS` | *(empty)* | Comma-separated pre-approved admin API keys |
| `SIGIMORA_CORS_ENABLED` | `true` | Enable CORS |
| `SIGIMORA_CORS_ORIGINS` | *(any)* | Comma-separated allowed origins (empty = allow all) |
| `SIGIMORA_MAX_BODY` | `10485760` | Max request body (bytes, 10 MiB) |
| `SIGIMORA_MAX_MSG_BYTES` | `1048576` | Max hex message length (bytes, 1 MiB) |
| `SIGIMORA_RATE_LIMIT` | `60` | Requests/min per IP (0 = disabled) |
| `SIGIMORA_TLS_ENABLED` | `false` | Enable TLS |
| `SIGIMORA_TLS_CERT` | *(none)* | Path to TLS certificate PEM |
| `SIGIMORA_TLS_KEY` | *(none)* | Path to TLS private key PEM |
| `SIGIMORA_CONFIG` | *(none)* | Path to TOML config file (default: `./sigimora.toml`) |

### TOML Config File Example

```toml
# sigimora.toml
listen = "0.0.0.0:8080"
log_level = "debug"
rate_limit = 120

[cors]
enabled = true
origins = ["https://app.example.com", "https://admin.example.com"]

[tls]
enabled = true
cert = "/etc/ssl/sigimora.crt"
key = "/etc/ssl/sigimora.key"
```

---

## API Reference

All endpoints (except `/health` and `/metrics`) require: `Authorization: Bearer <api-key>`

### Health & Metrics

```
GET /api/v1/health    → Server status, version, uptime, counters
GET /metrics          → Prometheus-compatible metrics
```

### Networks

```
POST /api/v1/networks          # Create network (n parties, threshold t)
GET  /api/v1/networks          # List all networks
GET  /api/v1/networks/:id      # Get network details
```

### Distributed Key Generation

```
POST /api/v1/networks/:id/dkg   # Run Pedersen DKG across all nodes
GET  /api/v1/networks/:id/dkg   # Check DKG status
```

### Threshold Signing

```
POST /api/v1/networks/:id/sign   # Sign a hex message with a quorum
```

### Verification

```
POST /api/v1/networks/:id/verify   # Verify a threshold signature
```

### Accountability Tracing

```
POST /api/v1/networks/:id/trace   # Identify signers using tracking key
```

### Proactive Refresh

```
POST /api/v1/networks/:id/refresh   # Rotate key shares, preserve collective key
```

### Ledger

```
GET /api/v1/networks/:id/ledger   # View transaction ledger (paginated)
```

### Nodes

```
GET  /api/v1/networks/:id/nodes         # List nodes
GET  /api/v1/networks/:id/nodes/:nid    # Get node details
```

### API Key Management (admin only)

```
POST /api/v1/api-keys       # Create API key (admin/user role)
GET  /api/v1/api-keys       # List API keys
DELETE /api/v1/api-keys/:id  # Revoke API key
```

### Error Responses

All errors return a JSON body with machine-readable error codes:

```json
{
  "error": "bad request: n must be >= 2",
  "message": "n must be >= 2",
  "code": "BadRequest"
}
```

| HTTP Status | Error Code | Meaning |
|---|---|---|
| 400 | `BadRequest` | Invalid input |
| 400 | `CryptoError` | Cryptographic operation failed |
| 401 | `Unauthorized` | Invalid or missing API key |
| 404 | `NotFound` | Resource does not exist |
| 429 | `RateLimited` | Too many requests from this IP |
| 500 | `InternalError` | Unexpected server error |
| 500 | `DatabaseError` | Database operation failed |

---

## Complete Example

```bash
# 1. Health check
curl http://localhost:8080/api/v1/health

# 2. Create a network (4 parties, threshold 2 → need 3 of 4 to sign)
curl -X POST http://localhost:8080/api/v1/networks \
  -H "Authorization: Bearer <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"n": 4, "t": 2}' | tee network.json

NET_ID=$(jq -r '.network.id' network.json)
TRACK_KEY=$(jq -r '.tracking_secret_key_hex' network.json)
NET_KEY=$(jq -r '.bootstrap_api_key' network.json)

# 3. Run DKG
curl -X POST "http://localhost:8080/api/v1/networks/$NET_ID/dkg" \
  -H "Authorization: Bearer $NET_KEY"

# 4. Sign a message (hex of "Hello SIGIMORA!")
curl -X POST "http://localhost:8080/api/v1/networks/$NET_ID/sign" \
  -H "Authorization: Bearer $NET_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "48656c6c6f20534947494d4f524121", "quorum": [1, 2, 3]}' | tee sig.json

TX_ID=$(jq -r '.tx_id' sig.json)
SIG_HEX=$(jq -r '.combined_sig_hex' sig.json)

# 5. Verify
curl -X POST "http://localhost:8080/api/v1/networks/$NET_ID/verify" \
  -H "Authorization: Bearer $NET_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"message\": \"48656c6c6f20534947494d4f524121\", \"signature_hex\": \"$SIG_HEX\"}"

# 6. Trace signers
curl -X POST "http://localhost:8080/api/v1/networks/$NET_ID/trace" \
  -H "Authorization: Bearer $NET_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"tx_id\": \"$TX_ID\", \"tracking_key_hex\": \"$TRACK_KEY\"}"

# 7. Proactive refresh
curl -X POST "http://localhost:8080/api/v1/networks/$NET_ID/refresh" \
  -H "Authorization: Bearer $NET_KEY"

# 8. Sign post-refresh (new shares, same collective key)
curl -X POST "http://localhost:8080/api/v1/networks/$NET_ID/sign" \
  -H "Authorization: Bearer $NET_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "72656672657368656421", "quorum": [2, 3, 4]}'

# 9. View ledger
curl "http://localhost:8080/api/v1/networks/$NET_ID/ledger" \
  -H "Authorization: Bearer $NET_KEY"

# 10. Create a user API key (admin only)
curl -X POST "http://localhost:8080/api/v1/api-keys" \
  -H "Authorization: Bearer $NET_KEY" \
  -H "Content-Type: application/json" \
  -d '{"label": "my-app", "role": "user"}'

# 11. Revoke an API key (admin only)
curl -X DELETE "http://localhost:8080/api/v1/api-keys/<key-id>" \
  -H "Authorization: Bearer $NET_KEY"
```

---

## Test Suite

### Rust Tests (113 total, 0 failures)

```bash
# All tests
cargo test --workspace

# Property-based tests only
cargo test -p sigimora-math --test proptest_tests
```

| Crate | Tests | Domain |
|---|---|---|
| sigimora-math | 47 + 12 proptest | Scalar, G1, G2, GT, pairing, hash-to-curve |
| sigimora-crypto | 26 | BLS, Shamir, Pedersen VSS/DKG, FROST |
| sigimora-ats | 8 | Sign/verify, tracing, quorum independence |
| sigimora-refresh | 5 | Zero-poly, collective key invariant |
| sigimora-mcp | 3 | Protocol lifecycle, state transitions |
| sigimora-server | 12 | Auth (7), Config (3), Negative (2) |

### Fuzz Targets

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzers
cargo fuzz run fuzz_scalar_deserialize
cargo fuzz run fuzz_g1_deserialize
cargo fuzz run fuzz_g2_deserialize
cargo fuzz run fuzz_hex_decode
```

### Python Integration Tests

```bash
pip install requests

# Start the server
cargo run -p sigimora-server

# Run integration test (37 checks)
python scripts/integration_test.py

# Run status code verification (64 checks)
python scripts/test_all_200.py
python scripts/test_error_codes.py

# Run rigorous crypto verification (54 checks)
python scripts/verify_crypto.py
```

---

## Protocol Flow

```
1. CREATE   → Network creator generates tracking key pair + config (n, t)
2. DKG      → All n nodes run 5-stage Pedersen DKG (parallelized)
               → Collective public key + per-node secret shares
3. SIGN     → t+1 nodes create partial BLS signatures + ECIES ATS tags
4. COMBINE  → Aggregate via Lagrange: σ = Σ λⱼ·σⱼ
5. VERIFY   → Anyone checks: e(σ, g₂) == e(H(m), PK)
6. TRACE    → Tracking key holder decrypts ATS tags → identifies signers
7. REFRESH  → Zero-polynomial rotation → new shares, same collective key
```

---

## Security

### Authentication
- **API Keys**: 128-bit random entropy, SHA-256 hashed for storage
- **Constant-Time Comparison**: `subtle::ConstantTimeEq` prevents timing attacks
- **RFC 7235 Bearer**: Accepts `Bearer`, `bearer`, and `BEARER` prefixes
- **Rate Limiting**: Sliding-window per-IP limiter (configurable via `SIGIMORA_RATE_LIMIT`)

### Input Validation
- **Request Body Limit**: Capped at `SIGIMORA_MAX_BODY` (default 10 MiB)
- **Length Guards**: All `copy_from_slice()` calls validated (G1: 48B, G2: 96B, Scalar: 32B)
- **Hex Format**: Strict hex decoding with descriptive error messages
- **CORS**: Configurable origin allow-list via `SIGIMORA_CORS_ORIGINS`

### Data Protection
- **Headers**: `X-Content-Type-Options: nosniff` on all responses
- **Secrets**: Secret keys zeroized on drop (`Zeroize` + `ZeroizeOnDrop`)
- **Audit Logging**: All security-relevant operations logged as structured JSON
- **TLS**: Optional HTTPS (configured, full listener support upcoming)

### Operations
- **Graceful Shutdown**: SIGINT/SIGTERM handler drains in-flight requests
- **Caching**: 30-second TTL on network lookups (reduces SQLite read pressure)
- **DKG Parallelization**: CPU-intensive crypto runs on `spawn_blocking` thread pool
- **Metrics**: Prometheus-compatible `/metrics` endpoint for monitoring

---

## Author

**Ali Ibrahim Mohamed Al Gamal**
- Email: wekaali4335@gmail.com
- GitHub: https://github.com/AliIbrahimMohammed

## License

MIT OR Apache-2.0
