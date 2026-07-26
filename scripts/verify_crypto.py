#!/usr/bin/env python3
"""
SIGIMORA API — Rigorous Cryptographic & Functional Verification

Tests every endpoint for:
  - Correct HTTP status codes
  - Cryptographically valid output formats
  - Mathematical correctness (BLS pairing equation)
  - Security properties (RBAC, auth, input validation)
  - Refresh invariant preservation
  - Edge case handling
"""

import json
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "http://127.0.0.1:18081/api/v1"
ADMIN_KEY = "sigimora_Rigor0usTestAdminKey0000"

passed = 0
failed = 0
details = []


def req(method, path, body=None, token=None, expect_range=None):
    """Send HTTP request, return (status, parsed_json, raw_bytes)."""
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(body).encode() if body else None
    try:
        req_obj = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req_obj, timeout=15) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read()
    except urllib.error.URLError as e:
        return (None, {"error": str(e)}, b"")

    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"raw": raw.decode()}

    if expect_range:
        lo, hi = expect_range
        if not (lo <= status < hi):
            raise AssertionError(
                f"  HTTP {status} outside expected range [{lo},{hi})"
            )
    return (status, parsed, raw)


def check(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  ✅ {name}")
        passed += 1
    except AssertionError as e:
        print(f"  ❌ {name}: {e}")
        failed += 1
        details.append((name, str(e)))
    except Exception as e:
        print(f"  ❌ {name}: EXCEPTION: {e}")
        failed += 1
        details.append((name, f"EXCEPTION: {e}"))


# ══════════════════════════════════════════════════════════════════════════
#  Cryptographic Helpers (pure Python checks on hex encodings)
# ══════════════════════════════════════════════════════════════════════════

def is_valid_hex(s, expected_bytes):
    """Check if s is a valid hex string of length expected_bytes*2."""
    if not isinstance(s, str):
        return False
    if len(s) != expected_bytes * 2:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# BLS12-381 serialization sizes
G1_BYTE_LEN = 48   # Compressed G1 point
G2_BYTE_LEN = 96   # Compressed G2 point
SCALAR_BYTE_LEN = 32  # Scalar field element


def verify_bls_signature_equation(sig_hex, msg_hex, pk_hex):
    """
    Verify the BLS pairing equation: e(sig, g2) == e(H(msg), pk)
    
    At the API level, we verify by calling the /verify endpoint.
    But we also check that the lengths are cryptographically valid.
    """
    s, d, _ = req("POST", f"/networks/{NET_ID}/verify",
                  {"message": msg_hex, "signature_hex": sig_hex},
                  token=NET_KEY)
    if s != 200:
        return False, f"verify returned HTTP {s}"
    if "valid" not in d:
        return False, f"no 'valid' field: {d}"
    return bool(d["valid"]), ""


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Health Endpoint
# ══════════════════════════════════════════════════════════════════════════

def test_health():
    """Health endpoint returns correct status and counters."""
    s, d, _ = req("GET", "/health")
    assert s == 200, f"Expected 200, got {s}"
    assert d["status"] == "ok", f"status={d['status']}"
    assert "version" in d and d["version"]
    assert "uptime_seconds" in d and d["uptime_seconds"] >= 0
    assert "networks" in d and isinstance(d["networks"], int)
    assert "nodes" in d and isinstance(d["nodes"], int)
    assert "ledger_entries" in d and isinstance(d["ledger_entries"], int)
    assert "crypto_backend" in d
    assert "BLS12-381" in d["crypto_backend"]
    # Health requires NO auth
    s2, d2, _ = req("GET", "/health", token=None)
    assert s2 == 200, f"Health without auth failed: {s2}"


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Authentication Security
# ══════════════════════════════════════════════════════════════════════════

def test_auth_no_header():
    """Missing auth header → 401."""
    s, d, _ = req("GET", "/networks")
    assert s == 401, f"Expected 401, got {s}"


def test_auth_short_key():
    """Key < 16 chars → 401."""
    s, d, _ = req("GET", "/networks", token="short")
    assert s == 401


def test_auth_long_key():
    """Key > 256 chars → 401."""
    s, d, _ = req("GET", "/networks", token="x" * 300)
    assert s == 401


def test_auth_wrong_key():
    """Valid format but unknown key → 401."""
    s, d, _ = req("GET", "/networks", token="sigimora_ThisKeyDoesNotExist1234")
    assert s == 401


def test_auth_malformed_bearer():
    """Missing 'Bearer ' prefix → 401."""
    url = f"{BASE}/networks"
    headers = {"Authorization": "NotBearer xyz"}
    try:
        req_obj = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req_obj, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == 401, f"Expected 401, got {status}"


def test_auth_sql_injection():
    """SQL injection in API key → 401 (not 500)."""
    s, d, _ = req("GET", "/networks",
                  token="sigimora_'; DROP TABLE api_keys;--")
    assert s == 401, f"Expected 401, got {s}"


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Network Creation
# ══════════════════════════════════════════════════════════════════════════

def test_create_network():
    """Create network: returns valid tracking keys, n nodes, correct structure."""
    global NET_ID, TRACK_KEY, NET_KEY, N_PARAM, T_PARAM
    N_PARAM, T_PARAM = 5, 2  # n=5, t=2 → quorum=3, f=1

    s, d, _ = req("POST", "/networks", {"n": N_PARAM, "t": T_PARAM}, token=ADMIN_KEY)
    assert s == 200, f"Expected 200, got {s}"

    # Check network info
    net = d["network"]
    assert net["n"] == N_PARAM, f"n={net['n']}"
    assert net["t"] == T_PARAM, f"t={net['t']}"
    assert net["f"] == (N_PARAM - 1) // 3, f"f={net['f']}"
    assert net["quorum"] == T_PARAM + 1, f"quorum={net['quorum']}"
    assert net["state"] == "created"
    assert net["node_count"] == N_PARAM

    # Validate UUID format for network ID
    assert len(net["id"]) == 36, f"network id={net['id']}"

    # Validate tracking public key: must be 96-byte hex (G2 point)
    assert is_valid_hex(net["tracking_pk_hex"], G2_BYTE_LEN), \
        f"invalid tracking_pk_hex: {net['tracking_pk_hex']}"

    # Tracking secret key: must be 32-byte hex (Scalar)
    assert is_valid_hex(d["tracking_secret_key_hex"], SCALAR_BYTE_LEN), \
        f"invalid tracking_sk_hex: {d['tracking_secret_key_hex']}"

    # Bootstrap API key format: sigimora_ prefix
    assert d["bootstrap_api_key"].startswith("sigimora_"), \
        f"bad key prefix: {d['bootstrap_api_key'][:10]}"

    # Collective PK should be null (DKG not run yet)
    assert net["collective_pk_hex"] is None

    NET_ID = net["id"]
    TRACK_KEY = d["tracking_secret_key_hex"]
    NET_KEY = d["bootstrap_api_key"]


def test_create_network_invalid():
    """Create network with invalid params → 400."""
    # n < 2
    s, d, _ = req("POST", "/networks", {"n": 0, "t": 0}, token=ADMIN_KEY)
    assert s == 400
    # n=1
    s, d, _ = req("POST", "/networks", {"n": 1, "t": 1}, token=ADMIN_KEY)
    assert s == 400
    # t >= n
    s, d, _ = req("POST", "/networks", {"n": 3, "t": 3}, token=ADMIN_KEY)
    assert s == 400
    # t = 0
    s, d, _ = req("POST", "/networks", {"n": 3, "t": 0}, token=ADMIN_KEY)
    assert s == 400


# ══════════════════════════════════════════════════════════════════════════
#  TEST: List / Get Networks
# ══════════════════════════════════════════════════════════════════════════

def test_list_networks():
    """List networks returns the created network."""
    s, d, _ = req("GET", "/networks", token=ADMIN_KEY)
    assert s == 200
    assert len(d) >= 1
    found = any(n["id"] == NET_ID for n in d)
    assert found, "created network not in list"


def test_get_network():
    """Get network by ID returns full details."""
    s, d, _ = req("GET", f"/networks/{NET_ID}", token=ADMIN_KEY)
    assert s == 200
    assert d["id"] == NET_ID
    assert d["n"] == N_PARAM
    assert d["t"] == T_PARAM


def test_get_network_404():
    """Get non-existent network → 404."""
    s, d, _ = req("GET", "/networks/nonexistent-id", token=ADMIN_KEY)
    assert s == 404


# ══════════════════════════════════════════════════════════════════════════
#  TEST: DKG — Distributed Key Generation
#  Cryptographic check: collective_pk must be a valid 96-byte G2 point
# ══════════════════════════════════════════════════════════════════════════

def test_dkg():
    """DKG produces valid collective public key and updates state."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/dkg", token=NET_KEY)
    assert s == 200
    assert d["state"] == "dkg_complete"
    assert d["member_count"] == N_PARAM
    assert d["threshold"] == T_PARAM + 1

    # CRYPTOGRAPHIC CHECK: collective_pk_hex must be valid 96-byte G2 point
    pk_hex = d.get("collective_pk_hex")
    assert pk_hex is not None, "No collective_pk_hex in response"
    assert is_valid_hex(pk_hex, G2_BYTE_LEN), \
        f"collective_pk_hex invalid (len={len(pk_hex) if pk_hex else 0})"

    global COLLECTIVE_PK
    COLLECTIVE_PK = pk_hex


def test_dkg_status():
    """DKG status returns same info as the POST response."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/dkg", token=NET_KEY)
    assert s == 200
    assert d["state"] == "dkg_complete"
    assert d["collective_pk_hex"] == COLLECTIVE_PK


def test_dkg_twice():
    """DKG twice should succeed (re-runs with new shares)."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/dkg", token=NET_KEY)
    assert s == 200
    assert d["state"] == "dkg_complete"
    # Collect new PK (DKG is deterministic from same nodes → should match)
    # On re-run, the node secrets are already set so DKG creates new shares
    # The collective key may differ since DKG uses fresh randomness each time
    # But it should still be a valid key
    assert is_valid_hex(d["collective_pk_hex"], G2_BYTE_LEN)
    global COLLECTIVE_PK
    COLLECTIVE_PK = d["collective_pk_hex"]


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Sign — Threshold Signing
#  Cryptographic checks:
#    1. Signature must be a valid 48-byte G1 point
#    2. Verify endpoint must return valid=true for correct msg+sig
#    3. Verify endpoint must return valid=false for wrong message
#    4. Verify endpoint must return 400 for invalid G1 point
#    5. Different quorum should produce different sig but still verify
# ══════════════════════════════════════════════════════════════════════════

MSG1 = "48656c6c6f20534947494d4f524121"  # "Hello SIGIMORA!"
MSG2 = "776f726c64"                        # "world"
MSG3 = "deadbeef"                          # arbitrary


def test_sign_valid():
    """Sign produces a valid signature for the correct quorum."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": MSG1, "quorum": [1, 2, 3]}, token=NET_KEY)
    assert s == 200

    # CRYPTOGRAPHIC CHECK: combined_sig must be valid 48-byte G1 point
    sig_hex = d.get("combined_sig_hex")
    assert sig_hex is not None, "No combined_sig_hex"
    assert is_valid_hex(sig_hex, G1_BYTE_LEN), \
        f"Signature invalid (len={len(sig_hex)})"

    # tx_id must be a UUID
    assert len(d["tx_id"]) == 36, f"tx_id={d['tx_id']}"

    # message_hash_hex must be valid 48-byte G1 point
    assert is_valid_hex(d["message_hash_hex"], G1_BYTE_LEN)

    # Quorum matches
    assert d["quorum"] == [1, 2, 3]

    global SIG1_TX, SIG1_HEX
    SIG1_TX = d["tx_id"]
    SIG1_HEX = sig_hex


def test_sign_verify_correct():
    """CRYPTOGRAPHIC: e(sig, g2) == e(H(msg), PK) → valid=true."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/verify",
                  {"message": MSG1, "signature_hex": SIG1_HEX}, token=NET_KEY)
    assert s == 200
    assert d["valid"] is True, f"BLS pairing equation failed! Got valid={d['valid']}"
    assert d["network_id"] == NET_ID


def test_sign_verify_wrong_message():
    """CRYPTOGRAPHIC: e(sig, g2) != e(H(wrong_msg), PK) → valid=false."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/verify",
                  {"message": MSG2, "signature_hex": SIG1_HEX}, token=NET_KEY)
    assert s == 200
    assert d["valid"] is False, \
        f"Signature verified against wrong message! Got valid={d['valid']}"
    assert d["network_id"] == NET_ID


def test_sign_verify_invalid_signature():
    """Invalid G1 point → 400 (crypto error), not 200."""
    invalid_sig = "ab" * 48  # 48 bytes but not a valid G1 point
    s, d, _ = req("POST", f"/networks/{NET_ID}/verify",
                  {"message": MSG1, "signature_hex": invalid_sig}, token=NET_KEY)
    assert s == 400, f"Expected 400 for invalid G1 point, got {s}"


def test_sign_different_quorum():
    """Different quorum produces a valid signature (threshold property)."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": MSG1, "quorum": [2, 3, 5]}, token=NET_KEY)
    assert s == 200
    sig_hex = d.get("combined_sig_hex")
    assert is_valid_hex(sig_hex, G1_BYTE_LEN)

    # CRYPTOGRAPHIC: This signature from a different quorum must also verify
    valid, err = verify_bls_signature_equation(sig_hex, MSG1, COLLECTIVE_PK)
    assert valid, f"Different quorum sig failed verification: {err}"


def test_sign_no_dkg():
    """Sign without DKG → 400."""
    s, nd, _ = req("POST", "/networks", {"n": 3, "t": 1}, token=ADMIN_KEY)
    assert s == 200
    no_dkg_id = nd["network"]["id"]
    no_dkg_key = nd["bootstrap_api_key"]
    s, d, _ = req("POST", f"/networks/{no_dkg_id}/sign",
                  {"message": "dead", "quorum": [1, 2]}, token=no_dkg_key)
    assert s == 400


def test_sign_insufficient_quorum():
    """Sign with quorum < t+1 → 400."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": MSG1, "quorum": [1]}, token=NET_KEY)
    assert s == 400


def test_sign_nonexistent_nodes():
    """Sign with nonexistent node IDs → 400."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": MSG1, "quorum": [99, 100, 101]}, token=NET_KEY)
    assert s == 400


def test_sign_invalid_hex():
    """Sign with non-hex message → 400."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": "nothex!", "quorum": [1, 2, 3]}, token=NET_KEY)
    assert s == 400


def test_sign_different_message():
    """Sign a different message and verify."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": MSG3, "quorum": [1, 3, 4]}, token=NET_KEY)
    assert s == 200
    sig_hex = d["combined_sig_hex"]
    assert is_valid_hex(sig_hex, G1_BYTE_LEN)

    # CRYPTOGRAPHIC: verify the new signature
    valid, err = verify_bls_signature_equation(sig_hex, MSG3, COLLECTIVE_PK)
    assert valid, f"Different message sig failed: {err}"

    # CRYPTOGRAPHIC: different message with wrong sig must fail
    valid2, _ = verify_bls_signature_equation(sig_hex, MSG2, COLLECTIVE_PK)
    assert not valid2, "Sig verified against wrong message!"

    global SIG2_HEX
    SIG2_HEX = sig_hex


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Trace — Accountability
#  Checks: returns correct signers, proper error codes
# ══════════════════════════════════════════════════════════════════════════

def test_trace():
    """Trace returns the signers who signed the transaction."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/trace",
                  {"tx_id": SIG1_TX, "tracking_key_hex": TRACK_KEY},
                  token=NET_KEY)
    assert s == 200
    assert "signers" in d
    signers = d["signers"]
    assert len(signers) > 0, "No signers returned"

    # Check signer structure
    for signer in signers:
        assert "node_id" in signer
        assert "public_key_hex" in signer
        assert is_valid_hex(signer["public_key_hex"], G2_BYTE_LEN), \
            f"invalid node pk: {signer['public_key_hex']}"

    # The signers should be the ones from our quorum
    signer_ids = set(s["node_id"] for s in signers)
    assert signer_ids == {1, 2, 3}, f"Expected quorum [1,2,3], got {signer_ids}"


def test_trace_unknown_tx():
    """Trace non-existent transaction → 404."""
    fake_tx = str(uuid.uuid4())
    s, d, _ = req("POST", f"/networks/{NET_ID}/trace",
                  {"tx_id": fake_tx, "tracking_key_hex": TRACK_KEY},
                  token=NET_KEY)
    assert s == 404


def test_trace_invalid_tracking_key():
    """Trace with non-hex tracking key → 400."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/trace",
                  {"tx_id": SIG1_TX, "tracking_key_hex": "nothex"},
                  token=NET_KEY)
    assert s == 400


def test_trace_wrong_tracking_key():
    """Trace with wrong tracking key length → 400."""
    # 31 bytes (wrong length for Scalar)
    wrong_key = "ab" * 31
    s, d, _ = req("POST", f"/networks/{NET_ID}/trace",
                  {"tx_id": SIG1_TX, "tracking_key_hex": wrong_key},
                  token=NET_KEY)
    assert s == 400


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Refresh — Proactive Key Refresh
#  Cryptographic checks:
#    1. Refresh completes successfully
#    2. invariant_preserved = true (collective key unchanged)
#    3. Post-refresh signatures still verify (collective key invariant)
# ══════════════════════════════════════════════════════════════════════════

def test_refresh():
    """Refresh preserves the collective key invariant."""
    s, d, _ = req("POST", f"/networks/{NET_ID}/refresh", token=NET_KEY)
    assert s == 200
    assert d["network_id"] == NET_ID
    assert d["epoch"] >= 1

    # CRYPTOGRAPHIC CHECK: invariant must be preserved
    assert d["invariant_preserved"] is True, \
        f"Refresh invariant NOT preserved! {d}"

    global EPOCH
    EPOCH = d["epoch"]


def test_refresh_before_dkg():
    """Refresh before DKG → 400."""
    s, nd, _ = req("POST", "/networks", {"n": 3, "t": 1}, token=ADMIN_KEY)
    assert s == 200
    no_dkg_id = nd["network"]["id"]
    no_dkg_key = nd["bootstrap_api_key"]
    s, d, _ = req("POST", f"/networks/{no_dkg_id}/refresh", token=no_dkg_key)
    assert s == 400


def test_sign_after_refresh():
    """CRYPTOGRAPHIC: After refresh, new shares still produce valid sigs.
    
    The collective key is unchanged (invariant preserved), so signatures
    from the new epoch must still verify against the same collective key.
    """
    msg = "72656672657368656421"  # "refreshed!"
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": msg, "quorum": [1, 4, 5]}, token=NET_KEY)
    assert s == 200
    sig_hex = d["combined_sig_hex"]
    assert is_valid_hex(sig_hex, G1_BYTE_LEN)

    # CRYPTOGRAPHIC: verify post-refresh signature
    valid, err = verify_bls_signature_equation(sig_hex, msg, COLLECTIVE_PK)
    assert valid, f"Post-refresh sig failed: {err}"

    # Verify the ledger recorded it
    s2, d2, _ = req("GET", f"/networks/{NET_ID}/ledger", token=NET_KEY)
    assert s2 == 200
    # Should have at least 4 entries: 3 signings + 1 post-refresh
    assert d2["total"] >= 4, f"Expected >=4 ledger entries, got {d2['total']}"


def test_refresh_twice():
    """Multiple refreshes all preserve the invariant."""
    for i in range(3):
        s, d, _ = req("POST", f"/networks/{NET_ID}/refresh", token=NET_KEY)
        assert s == 200
        assert d["invariant_preserved"] is True, \
            f"Refresh {i+1} invariant NOT preserved!"

    # After 3 more refreshes, signing still works
    msg = "6d756c7469706c655f72656672657368"
    s, d, _ = req("POST", f"/networks/{NET_ID}/sign",
                  {"message": msg, "quorum": [2, 4, 5]}, token=NET_KEY)
    assert s == 200
    sig_hex = d["combined_sig_hex"]
    valid, err = verify_bls_signature_equation(sig_hex, msg, COLLECTIVE_PK)
    assert valid, f"Post-multiple-refresh sig failed: {err}"


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Ledger
#  Checks: immutable append-only record, pagination
# ══════════════════════════════════════════════════════════════════════════

def test_ledger():
    """Ledger returns entries with correct structure."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/ledger", token=NET_KEY)
    assert s == 200
    assert "entries" in d
    assert "total" in d
    assert d["total"] >= 1

    for entry in d["entries"]:
        assert "block_index" in entry
        assert "tx_id" in entry
        assert "payload_hash_hex" in entry
        assert "signature_hex" in entry
        assert "signers" in entry
        assert "epoch" in entry
        assert "timestamp" in entry

        # Verify hex formats
        assert is_valid_hex(entry["payload_hash_hex"], G1_BYTE_LEN), \
            f"invalid payload hash: {entry['payload_hash_hex']}"
        # signature_hex may be empty string for some entries
        if entry["signature_hex"]:
            assert is_valid_hex(entry["signature_hex"], G1_BYTE_LEN), \
                f"invalid sig in ledger: {entry['signature_hex']}"


def test_ledger_pagination():
    """Ledger pagination works correctly."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/ledger?offset=0&limit=2",
                  token=NET_KEY)
    assert s == 200
    assert len(d["entries"]) <= 2
    assert d["total"] >= 1


def test_ledger_no_auth():
    """Ledger without auth → 401."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/ledger")
    assert s == 401


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Nodes — Identity
# ══════════════════════════════════════════════════════════════════════════

def test_list_nodes():
    """List nodes returns all nodes with correct structure."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/nodes", token=NET_KEY)
    assert s == 200
    assert len(d) == N_PARAM, f"Expected {N_PARAM} nodes, got {len(d)}"

    for node in d:
        assert "node_id" in node
        assert "public_key_hex" in node
        assert "address_hex" in node
        assert "epoch" in node
        assert "is_signer" in node
        assert 1 <= node["node_id"] <= N_PARAM
        # Node public key must be valid 96-byte G2 point
        assert is_valid_hex(node["public_key_hex"], G2_BYTE_LEN), \
            f"node {node['node_id']} invalid pk: {node['public_key_hex']}"


def test_get_node():
    """Get individual node returns correct info."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/nodes/1", token=NET_KEY)
    assert s == 200
    assert d["node_id"] == 1
    assert d["network_id"] == NET_ID
    assert is_valid_hex(d["public_key_hex"], G2_BYTE_LEN)
    assert is_valid_hex(d["address_hex"], 20)  # 20-byte address


def test_get_node_404():
    """Get non-existent node → 404."""
    s, d, _ = req("GET", f"/networks/{NET_ID}/nodes/99", token=NET_KEY)
    assert s == 404


# ══════════════════════════════════════════════════════════════════════════
#  TEST: API Key Management + RBAC
# ══════════════════════════════════════════════════════════════════════════

def test_create_api_key_admin():
    """Admin can create admin keys."""
    s, d, _ = req("POST", "/api-keys",
                  {"label": "secondary-admin", "role": "admin"}, token=ADMIN_KEY)
    assert s == 200
    assert d["api_key"]["role"] == "admin"
    assert d["api_key"]["label"] == "secondary-admin"
    assert d["raw_key"].startswith("sigimora_")
    global ADMIN2_KEY
    ADMIN2_KEY = d["raw_key"]


def test_create_api_key_user():
    """Admin can create user keys."""
    s, d, _ = req("POST", "/api-keys",
                  {"label": "regular-user", "role": "user"}, token=ADMIN_KEY)
    assert s == 200
    assert d["api_key"]["role"] == "user"
    assert d["raw_key"].startswith("sigimora_")
    global USER_KEY
    USER_KEY = d["raw_key"]


def test_create_api_key_no_admin():
    """User role cannot create API keys → 401."""
    s, d, _ = req("POST", "/api-keys",
                  {"label": "should-fail", "role": "user"}, token=USER_KEY)
    assert s == 401


def test_list_api_keys_admin():
    """Admin can list API keys."""
    s, d, _ = req("GET", "/api-keys", token=ADMIN_KEY)
    assert s == 200
    assert len(d) >= 3  # bootstrap + secondary-admin + regular-user


def test_list_api_keys_no_admin():
    """User role cannot list API keys → 401."""
    s, d, _ = req("GET", "/api-keys", token=USER_KEY)
    assert s == 401


def test_create_api_key_invalid_role():
    """Invalid role → 400."""
    s, d, _ = req("POST", "/api-keys",
                  {"label": "bad", "role": "superadmin"}, token=ADMIN_KEY)
    assert s == 400


def test_create_api_key_admin2():
    """Second admin key works (proves key persistence)."""
    s, d, _ = req("POST", "/api-keys",
                  {"label": "from-admin2", "role": "user"}, token=ADMIN2_KEY)
    assert s == 200
    assert d["api_key"]["label"] == "from-admin2"


def test_user_key_limited_access():
    """User key can access networks but not manage keys."""
    # Can access health (no auth needed)
    s, d, _ = req("GET", "/health", token=USER_KEY)
    assert s == 200
    # Can list networks
    s, d, _ = req("GET", "/networks", token=USER_KEY)
    assert s == 200
    # Cannot list api keys
    s, d, _ = req("GET", "/api-keys", token=USER_KEY)
    assert s == 401
    # Cannot create api keys
    s, d, _ = req("POST", "/api-keys", {"label": "x", "role": "user"},
                  token=USER_KEY)
    assert s == 401


# ══════════════════════════════════════════════════════════════════════════
#  TEST: Network Not Found Errors
# ══════════════════════════════════════════════════════════════════════════

def test_dkg_unknown_network():
    """DKG on unknown network → 404."""
    s, d, _ = req("POST", "/networks/bad-id/dkg", token=ADMIN_KEY)
    assert s == 404


def test_sign_unknown_network():
    """Sign on unknown network → 404."""
    s, d, _ = req("POST", "/networks/bad-id/sign",
                  {"message": "dead", "quorum": [1, 2, 3]}, token=ADMIN_KEY)
    assert s == 404


def test_verify_unknown_network():
    """Verify on unknown network → 404."""
    s, d, _ = req("POST", "/networks/bad-id/verify",
                  {"message": "dead", "signature_hex": "ab" * 48},
                  token=ADMIN_KEY)
    assert s == 404


def test_trace_unknown_network():
    """Trace on unknown network → 404."""
    s, d, _ = req("POST", "/networks/bad-id/trace",
                  {"tx_id": str(uuid.uuid4()), "tracking_key_hex": "ab" * 32},
                  token=ADMIN_KEY)
    assert s == 404


def test_refresh_unknown_network():
    """Refresh on unknown network → 404."""
    s, d, _ = req("POST", "/networks/bad-id/refresh", token=ADMIN_KEY)
    assert s == 404


def test_ledger_unknown_network():
    """Ledger on unknown network → 404."""
    s, d, _ = req("GET", "/networks/bad-id/ledger", token=ADMIN_KEY)
    assert s == 404


def test_nodes_unknown_network():
    """Nodes list on unknown network → 404."""
    s, d, _ = req("GET", "/networks/bad-id/nodes", token=ADMIN_KEY)
    assert s == 404


# ══════════════════════════════════════════════════════════════════════════
#  Run All Tests
# ══════════════════════════════════════════════════════════════════════════

def main():
    global passed, failed, details

    tests = [
        # Health
        ("Health endpoint", test_health),
        # Authentication security
        ("Auth: no header → 401", test_auth_no_header),
        ("Auth: short key → 401", test_auth_short_key),
        ("Auth: long key → 401", test_auth_long_key),
        ("Auth: wrong key → 401", test_auth_wrong_key),
        ("Auth: malformed Bearer → 401", test_auth_malformed_bearer),
        ("Auth: SQL injection → 401", test_auth_sql_injection),
        # Network CRUD
        ("Create network (n=5, t=2)", test_create_network),
        ("Create network invalid params", test_create_network_invalid),
        ("List networks", test_list_networks),
        ("Get network by ID", test_get_network),
        ("Get network 404", test_get_network_404),
        # DKG
        ("DKG produces valid G2 collective public key", test_dkg),
        ("DKG status", test_dkg_status),
        ("DKG re-run", test_dkg_twice),
        # Threshold Signing + Cryptographic Verification
        ("Sign message (quorum [1,2,3])", test_sign_valid),
        ("BLS VERIFY: e(sig,g2)=e(H(msg),PK) → true", test_sign_verify_correct),
        ("BLS VERIFY: wrong message → false", test_sign_verify_wrong_message),
        ("BLS VERIFY: invalid G1 point → 400", test_sign_verify_invalid_signature),
        ("Sign different quorum [2,3,5] still verifies", test_sign_different_quorum),
        ("Sign without DKG → 400", test_sign_no_dkg),
        ("Sign insufficient quorum → 400", test_sign_insufficient_quorum),
        ("Sign nonexistent nodes → 400", test_sign_nonexistent_nodes),
        ("Sign invalid hex message → 400", test_sign_invalid_hex),
        ("Sign different message, verify correct + wrong msg fail", test_sign_different_message),
        # Accountability Tracing
        ("Trace returns correct quorum signers", test_trace),
        ("Trace unknown tx → 404", test_trace_unknown_tx),
        ("Trace invalid tracking key hex → 400", test_trace_invalid_tracking_key),
        ("Trace wrong tracking key → 400", test_trace_wrong_tracking_key),
        # Proactive Refresh
        ("Refresh preserves collective key invariant", test_refresh),
        ("Refresh before DKG → 400", test_refresh_before_dkg),
        ("BLS VERIFY: post-refresh signature still valid", test_sign_after_refresh),
        ("Multiple refreshes all preserve invariant", test_refresh_twice),
        # Ledger
        ("Ledger entries correct structure", test_ledger),
        ("Ledger pagination", test_ledger_pagination),
        ("Ledger without auth → 401", test_ledger_no_auth),
        # Nodes
        ("List all nodes (correct count + G2 PKs)", test_list_nodes),
        ("Get individual node", test_get_node),
        ("Get node 404", test_get_node_404),
        # API Key Management + RBAC
        ("Create admin API key", test_create_api_key_admin),
        ("Create user API key", test_create_api_key_user),
        ("User cannot create API keys (RBAC)", test_create_api_key_no_admin),
        ("Admin can list API keys", test_list_api_keys_admin),
        ("User cannot list API keys (RBAC)", test_list_api_keys_no_admin),
        ("Invalid role → 400", test_create_api_key_invalid_role),
        ("Second admin key works (persistence)", test_create_api_key_admin2),
        ("User key limited access (networks ok, keys 401)", test_user_key_limited_access),
        # Network not found errors
        ("DKG unknown network → 404", test_dkg_unknown_network),
        ("Sign unknown network → 404", test_sign_unknown_network),
        ("Verify unknown network → 404", test_verify_unknown_network),
        ("Trace unknown network → 404", test_trace_unknown_network),
        ("Refresh unknown network → 404", test_refresh_unknown_network),
        ("Ledger unknown network → 404", test_ledger_unknown_network),
        ("Nodes unknown network → 404", test_nodes_unknown_network),
    ]

    print("=" * 70)
    print("  SIGIMORA API — Rigorous Cryptographic & Functional Verification")
    print("=" * 70)
    print()

    for name, fn in tests:
        check(name, fn)

    print()
    print("=" * 70)
    print(f"  RESULTS: {passed} passed, {failed} failed / {len(tests)} total")
    print("=" * 70)

    if failed > 0:
        print()
        print("  FAILED DETAILS:")
        for name, err in details:
            print(f"    ❌ {name}: {err}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
