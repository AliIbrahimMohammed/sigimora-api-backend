# SIGIMORA API

**BFT Accountable Threshold Signing — REST API Backend**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-137%20passed-brightgreen.svg)](#test-results)

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
| 🛡️ **Security Hardened** | OsRng entropy, input validation, CORS control, TLS support, graceful shutdown |

### Architecture

```
sigimora-api/
├── sigimora-server         Axum REST API (routes, auth, database, error handling)
├── sigimora-math           BLS12-381 primitives (Scalar, G1, G2, GT, pairing)
├── sigimora-crypto         BLS, Shamir SSS, Pedersen VSS, 5-stage DKG
├── sigimora-ats            Accountable Threshold Signatures + ECIES tracing
├── sigimora-refresh        Proactive key refresh (zero-polynomial rotation)
└── sigimora-mcp            MPC protocol orchestration engine
```

---

## Quick Start

### Prerequisites

- **Rust** 1.96+ (stable)
- **C toolchain** (GCC/MinGW on Windows, GCC/Clang on Linux/macOS)

### Build & Run

```bash
# Clone
git clone https://github.com/AliIbrahimMohammed/sigimora-api.git
cd sigimora-api

# Build the server
cargo build --release -p sigimora-server

# Run
cargo run --release -p sigimora-server
```

On first run, a **bootstrap admin API key** is printed to the console. **Save it** — it is your credential for all API calls.

### Verify

```bash
curl http://localhost:8080/api/v1/health
```

```json
{"status":"ok","version":"0.1.0","uptime_seconds":5,"networks":0,"nodes":0,"ledger_entries":0,"crypto_backend":"BLS12-381 (blstrs/blst) + Pedersen DKG + ATS"}
```

> The `/health` endpoint is the **only** unauthenticated endpoint.

---

## Configuration

All settings via environment variables or `.env` file:

| Variable | Default | Description |
|---|---|---|
| `SIGIMORA_LISTEN` | `0.0.0.0:8080` | TCP bind address |
| `SIGIMORA_DATA_DIR` | `./data` | Data directory (SQLite DB + keys) |
| `SIGIMORA_DATABASE_URL` | *(auto)* | Full SQLite URL (overrides DATA_DIR) |
| `SIGIMORA_LOG_LEVEL` | `info` | Log level |
| `SIGIMORA_BOOTSTRAP_KEYS` | *(empty)* | Comma-separated pre-approved admin API keys |
| `SIGIMORA_CORS_ENABLED` | `true` | Enable CORS |
| `SIGIMORA_MAX_BODY` | `10485760` | Max request body (bytes) |
| `SIGIMORA_MAX_MSG_BYTES` | `1048576` | Max hex message length (bytes) |
| `SIGIMORA_RATE_LIMIT` | `60` | Requests/min per IP (0 = disabled) |
| `SIGIMORA_TLS_ENABLED` | `false` | Enable TLS |
| `SIGIMORA_TLS_CERT` | *(none)* | Path to TLS certificate PEM |
| `SIGIMORA_TLS_KEY` | *(none)* | Path to TLS private key PEM |

---

## API Reference

All endpoints (except `/health`) require: `Authorization: Bearer <api-key>`

### Health

```
GET /api/v1/health
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
POST /api/v1/api-keys   # Create API key (admin/user role)
GET  /api/v1/api-keys   # List API keys
```

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
```

---

## Integration Test

A comprehensive Python integration test is available at `scripts/integration_test.py`:

```bash
# Install dependencies
pip install requests

# Start the server in one terminal
cargo run -p sigimora-server

# Run the integration test in another
python scripts/integration_test.py
```

The test covers all 16 endpoints including:
- Health, Create/List/Get Network, DKG, Sign (valid + error), Verify (valid + wrong sig + wrong msg)
- Trace (valid + unknown tx 404 + invalid hex 400)
- Ledger (entries + pagination)
- Refresh (predkg rejection + invariant preserved)
- Nodes (list + get + unknown 404)
- API Keys (create admin/user + RBAC)
- Auth (no auth 401, short key 401, wrong key 401, malformed Bearer 401, SQL injection 401, long key 401)

---

## Development

### Running Tests

```bash
# All tests
cargo test --workspace

# Server tests only
cargo test -p sigimora-server
```

**137+ tests, 0 failures** across all crates:

| Crate | Tests | Domain |
|---|---|---|
| sigimora-math | 47 | Scalar, G1, G2, GT, pairing, hash-to-curve |
| sigimora-crypto | 26 | BLS, Shamir, Pedersen VSS/DKG, FROST |
| sigimora-ats | 8 | Sign/verify, tracing, quorum independence |
| sigimora-refresh | 5 | Zero-poly, collective key invariant |
| sigimora-mcp | 3 | Protocol lifecycle, state transitions |
| sigimora-server | 10 | Auth (7) + Config (3) |

### Building

```bash
cargo build --workspace
```

**0 errors, 0 warnings.**

---

## Protocol Flow

```
1. CREATE   → Network creator generates tracking key pair + config (n, t)
2. DKG      → All n nodes run 5-stage Pedersen DKG
              → Collective public key + per-node secret shares
3. SIGN     → t+1 nodes create partial BLS signatures + ECIES ATS tags
4. COMBINE  → Aggregate via Lagrange: σ = Σ λⱼ·σⱼ
5. VERIFY   → Anyone checks: e(σ, g₂) == e(H(m), PK)
6. TRACE    → Tracking key holder decrypts ATS tags → identifies signers
7. REFRESH  → Zero-polynomial rotation → new shares, same collective key
```

---

## Security

- **API Keys**: SHA-256 hashed, `subtle::ConstantTimeEq` comparison, OsRng entropy
- **Input Validation**: Length, hex format, and range checks on all parameters
- **Headers**: `X-Content-Type-Options: nosniff` on all responses
- **CORS**: Configurable via `SIGIMORA_CORS_ENABLED`
- **TLS**: Optional HTTPS with PEM certificates
- **Shutdown**: Graceful SIGINT/SIGTERM handler
- **Dependencies**: Minimal and audited

---

## Author

**Ali Ibrahim Mohamed Al Gamal**
- Email: wekaali4335@gmail.com
- GitHub: https://github.com/AliIbrahimMohammed
- LinkedIn: https://www.linkedin.com/in/0xali-ibrahim/

## License

MIT OR Apache-2.0
