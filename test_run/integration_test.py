#!/usr/bin/env python3
"""
SIGIMORA API — Full Integration Test Suite

Tests all 16 API endpoints with authentication, RBAC, error modes,
and edge cases. Run against a running server:

    cargo run -p sigimora-server &
    python scripts/integration_test.py
"""

import json
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "http://127.0.0.1:18080/api/v1"


# ── Helpers ──────────────────────────────────────────────────────────────

def req(method, path, body=None, token=None, expect=None):
    """Send an HTTP request and return (status, data)."""
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(body).encode() if body else None
    if method == "GET" and body:
        raise ValueError("GET with body")

    try:
        req_obj = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        with urllib.request.urlopen(req_obj, timeout=10) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read()

    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"raw": raw.decode()}

    outcome = "✅" if status < 400 else "❌"
    label = f"{method} {path}"
    if expect is not None and status != expect:
        print(f"  {outcome} {label} → {status} (expected {expect}) FAIL")
        return (status, parsed)
    if status < 400:
        print(f"  ✅ {label} → {status}")
    else:
        suffix = f" [{parsed.get('error', '')}]"
        print(f"  {outcome} {label} → {status}{suffix}")
    return (status, parsed)


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"assert_eq: {a} != {b}  {msg}")


def assert_ne(a, b, msg=""):
    if a == b:
        raise AssertionError(f"assert_ne: {a} == {b}  {msg}")


def assert_true(v, msg=""):
    if not v:
        raise AssertionError(f"assert_true failed: {msg}")


def assert_in(key, d, msg=""):
    if key not in d:
        raise AssertionError(f"key '{key}' not in response: {d}  {msg}")


# ── Test Plan ────────────────────────────────────────────────────────────

passed = 0
failed = 0
checks = []


def check(name, fn):
    global passed, failed
    print(f"\n── {name} ──")
    try:
        fn()
        print(f"  ✅ PASS")
        passed += 1
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        failed += 1
    checks.append((name, failed == 0))


# ── Tests ────────────────────────────────────────────────────────────────

def test_health():
    s, d = req("GET", "/health")
    assert_eq(s, 200)
    assert_eq(d["status"], "ok")
    assert_in("version", d)
    assert_in("uptime_seconds", d)


def test_create_network():
    global ADMIN_KEY
    s, d = req("POST", "/networks", {"n": 4, "t": 2}, token=ADMIN_KEY)
    assert_eq(s, 200)
    assert_in("network", d)
    assert_in("tracking_secret_key_hex", d)
    assert_in("bootstrap_api_key", d)
    n = d["network"]
    assert_eq(n["n"], 4)
    assert_eq(n["t"], 2)
    assert_eq(n["state"], "created")
    # Save for subsequent tests
    globals()["NET_ID"] = n["id"]
    globals()["TRACK_KEY"] = d["tracking_secret_key_hex"]
    globals()["NET_KEY"] = d["bootstrap_api_key"]


def test_list_networks():
    s, d = req("GET", "/networks", token=ADMIN_KEY)
    assert_eq(s, 200)
    assert_true(len(d) >= 1)
    found = any(n["id"] == NET_ID for n in d)
    assert_true(found, "created network not in list")


def test_get_network():
    s, d = req("GET", f"/networks/{NET_ID}", token=ADMIN_KEY)
    assert_eq(s, 200)
    assert_eq(d["id"], NET_ID)


def test_get_network_404():
    s, d = req("GET", "/networks/nonexistent-id", token=ADMIN_KEY)
    assert_eq(s, 404)


def test_dkg():
    s, d = req("POST", f"/networks/{NET_ID}/dkg", token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(d["state"], "dkg_complete")
    assert_in("collective_pk_hex", d)
    assert_true(len(d["collective_pk_hex"]) > 0)
    globals()["COLLECTIVE_PK"] = d["collective_pk_hex"]


def test_dkg_status():
    s, d = req("GET", f"/networks/{NET_ID}/dkg", token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(d["state"], "dkg_complete")


def test_sign():
    msg_hex = "48656c6c6f20534947494d4f524121"  # "Hello SIGIMORA!"
    s, d = req("POST", f"/networks/{NET_ID}/sign",
               {"message": msg_hex, "quorum": [1, 2, 3]}, token=NET_KEY)
    assert_eq(s, 200)
    assert_in("tx_id", d)
    assert_in("combined_sig_hex", d)
    assert_eq(len(d["combined_sig_hex"]), 96)  # 48 bytes = 96 hex chars
    globals()["TX_ID"] = d["tx_id"]
    globals()["SIG_HEX"] = d["combined_sig_hex"]
    globals()["MSG_HEX"] = msg_hex


def test_sign_wrong_quorum():
    # Request a quorum with unknown node IDs
    s, d = req("POST", f"/networks/{NET_ID}/sign",
               {"message": "deadbeef", "quorum": [99, 100]}, token=NET_KEY)
    assert_eq(s, 400)


def test_sign_no_dkg():
    # Create a network without DKG and try to sign
    s, nd = req("POST", "/networks", {"n": 3, "t": 1}, token=ADMIN_KEY)
    assert_eq(s, 200)
    no_dkg_id = nd["network"]["id"]
    no_dkg_key = nd["bootstrap_api_key"]
    s, d = req("POST", f"/networks/{no_dkg_id}/sign",
               {"message": "dead", "quorum": [1, 2]}, token=no_dkg_key)
    assert_eq(s, 400)


def test_verify_valid():
    s, d = req("POST", f"/networks/{NET_ID}/verify",
               {"message": MSG_HEX, "signature_hex": SIG_HEX}, token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(d["valid"], True)


def test_verify_wrong_message():
    wrong_msg = "deadbeef"
    s, d = req("POST", f"/networks/{NET_ID}/verify",
               {"message": wrong_msg, "signature_hex": SIG_HEX}, token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(d["valid"], False)


def test_verify_wrong_signature():
    fake_sig = "ab" * 48
    s, d = req("POST", f"/networks/{NET_ID}/verify",
               {"message": MSG_HEX, "signature_hex": fake_sig}, token=NET_KEY)
    # Invalid G1 point returns 400 (crypto error), not 200 with valid=false
    assert_eq(s, 400)


def test_trace():
    s, d = req("POST", f"/networks/{NET_ID}/trace",
               {"tx_id": TX_ID, "tracking_key_hex": TRACK_KEY}, token=NET_KEY)
    assert_eq(s, 200)
    assert_in("signers", d)
    assert_true(len(d["signers"]) > 0)


def test_trace_unknown_tx():
    fake_tx = str(uuid.uuid4())
    s, d = req("POST", f"/networks/{NET_ID}/trace",
               {"tx_id": fake_tx, "tracking_key_hex": TRACK_KEY}, token=NET_KEY)
    assert_eq(s, 404)


def test_trace_invalid_hex():
    s, d = req("POST", f"/networks/{NET_ID}/trace",
               {"tx_id": TX_ID, "tracking_key_hex": "nothex"}, token=NET_KEY)
    assert_eq(s, 400)


def test_refresh():
    s, d = req("POST", f"/networks/{NET_ID}/refresh", token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(d["invariant_preserved"], True)
    assert_in("epoch", d)


def test_refresh_before_dkg():
    # Create a network, try to refresh without DKG
    s, nd = req("POST", "/networks", {"n": 3, "t": 1}, token=ADMIN_KEY)
    assert_eq(s, 200)
    no_dkg_id = nd["network"]["id"]
    no_dkg_key = nd["bootstrap_api_key"]
    s, d = req("POST", f"/networks/{no_dkg_id}/refresh", token=no_dkg_key)
    assert_eq(s, 400)


def test_sign_after_refresh():
    """Sign after refresh — should still work with new shares."""
    msg = "72656672657368656421"  # "refreshed!"
    s, d = req("POST", f"/networks/{NET_ID}/sign",
               {"message": msg, "quorum": [2, 3, 4]}, token=NET_KEY)
    assert_eq(s, 200)
    assert_in("combined_sig_hex", d)
    # Verify it
    s2, d2 = req("POST", f"/networks/{NET_ID}/verify",
                 {"message": msg, "signature_hex": d["combined_sig_hex"]},
                 token=NET_KEY)
    assert_eq(s2, 200)
    assert_eq(d2["valid"], True)


def test_ledger():
    s, d = req("GET", f"/networks/{NET_ID}/ledger", token=NET_KEY)
    assert_eq(s, 200)
    assert_in("entries", d)
    assert_in("total", d)
    assert_true(d["total"] >= 2)  # at least 2 signings


def test_ledger_pagination():
    s, d = req("GET", f"/networks/{NET_ID}/ledger?offset=0&limit=1",
               token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(len(d["entries"]), 1)


def test_list_nodes():
    s, d = req("GET", f"/networks/{NET_ID}/nodes", token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(len(d), 4)  # n=4


def test_get_node():
    s, d = req("GET", f"/networks/{NET_ID}/nodes/1", token=NET_KEY)
    assert_eq(s, 200)
    assert_eq(d["node_id"], 1)


def test_get_node_404():
    s, d = req("GET", f"/networks/{NET_ID}/nodes/99", token=NET_KEY)
    assert_eq(s, 404)


def test_create_api_key_admin():
    s, d = req("POST", "/api-keys",
               {"label": "test-admin-key", "role": "admin"}, token=ADMIN_KEY)
    assert_eq(s, 200)
    assert_in("raw_key", d)
    assert_eq(d["api_key"]["role"], "admin")


def test_create_api_key_user():
    s, d = req("POST", "/api-keys",
               {"label": "test-user-key", "role": "user"}, token=ADMIN_KEY)
    assert_eq(s, 200)
    assert_eq(d["api_key"]["role"], "user")
    globals()["USER_KEY"] = d["raw_key"]


def test_create_api_key_invalid_role():
    s, d = req("POST", "/api-keys",
               {"label": "bad-role", "role": "superadmin"}, token=ADMIN_KEY)
    assert_eq(s, 400)


def test_create_api_key_no_admin():
    """Regular user cannot create API keys."""
    s, d = req("POST", "/api-keys",
               {"label": "should-fail", "role": "user"}, token=USER_KEY)
    assert_eq(s, 401)


def test_list_api_keys():
    s, d = req("GET", "/api-keys", token=ADMIN_KEY)
    assert_eq(s, 200)
    assert_true(len(d) >= 2)


def test_list_api_keys_no_admin():
    s, d = req("GET", "/api-keys", token=USER_KEY)
    assert_eq(s, 401)


def test_auth_no_header():
    s, d = req("GET", "/networks")
    assert_eq(s, 401)


def test_auth_short_key():
    s, d = req("GET", "/networks", token="short")
    assert_eq(s, 401)


def test_auth_long_key():
    s, d = req("GET", "/networks", token="x" * 300)
    assert_eq(s, 401)


def test_auth_wrong_key():
    s, d = req("GET", "/networks", token="sigimora_ThisKeyDoesNotExist1234")
    assert_eq(s, 401)


def test_auth_malformed_bearer():
    url = f"{BASE}/networks"
    headers = {"Authorization": "NotBearer xyz"}
    try:
        req_obj = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req_obj, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert_eq(status, 401)


def test_auth_sql_injection():
    # SQL injection attempt in the API key
    s, d = req("GET", "/networks",
               token="sigimora_'; DROP TABLE api_keys;--")
    assert_eq(s, 401)


def test_create_network_invalid_params():
    s, d = req("POST", "/networks", {"n": 0, "t": 0}, token=ADMIN_KEY)
    assert_eq(s, 400)
    s, d = req("POST", "/networks", {"n": 1, "t": 1}, token=ADMIN_KEY)
    assert_eq(s, 400)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    global ADMIN_KEY, USER_KEY

    print("=" * 60)
    print("  SIGIMORA API — Integration Test Suite")
    print("=" * 60)

    # Get a bootstrap admin key from server stdout or generate one
    # Try health first to see if server is running
    try:
        s, _ = req("GET", "/health")
        if s != 200:
            print("\n❌ Server not responding at", BASE)
            print("   Start with: cargo run -p sigimora-server")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Cannot connect to {BASE}: {e}")
        print("   Start with: cargo run -p sigimora-server")
        sys.exit(1)

    print("\n✅ Server is running\n")

    # To run fully automated, we need an admin key.
    # If SIGIMORA_BOOTSTRAP_KEYS env var is set, use it.
    # Otherwise, check for a .env file or read from first-run output.
    # For the test, we generate a key via the server's first-run behavior.
    # If no key is available, create one by hitting the API (but that requires
    # an existing admin key... circular dependency).
    #
    # Workaround: the test creates a temp admin key via direct DB or env.
    # For this test, we use a key from environment variable.
    import os
    env_key = os.environ.get("SIGIMORA_TEST_ADMIN_KEY")
    if env_key:
        ADMIN_KEY = env_key
        print(f"  Using admin key from SIGIMORA_TEST_ADMIN_KEY env var")
    else:
        # If no env key, we try to use the admin key printed on first run.
        # For automated testing, create a .env file with SIGIMORA_BOOTSTRAP_KEYS.
        print()
        print("  ⚠️  No SIGIMORA_TEST_ADMIN_KEY set.")
        print("  Set it to the bootstrap key printed on server startup.")
        print("  Or create a .env file with:")
        print('    SIGIMORA_BOOTSTRAP_KEYS="sigimora_MyAdminKey0123456789abcd"')
        print()
        # Try a default test key
        ADMIN_KEY = os.environ.get("ADMIN_KEY", "sigimora_TestAdminKey00000000000000")
        print(f"  Trying default key: {ADMIN_KEY[:20]}...")

    # Register all test functions (order matters for data dependencies)
    test_fns = [
        ("Health", test_health),
        ("Create Network", test_create_network),
        ("List Networks", test_list_networks),
        ("Get Network", test_get_network),
        ("Get Network 404", test_get_network_404),
        ("Invalid Create", test_create_network_invalid_params),
        ("DKG", test_dkg),
        ("DKG Status", test_dkg_status),
        ("Sign", test_sign),
        ("Sign Wrong Quorum", test_sign_wrong_quorum),
        ("Sign No DKG", test_sign_no_dkg),
        ("Verify Valid", test_verify_valid),
        ("Verify Wrong Message", test_verify_wrong_message),
        ("Verify Wrong Signature", test_verify_wrong_signature),
        ("Trace", test_trace),
        ("Trace Unknown TX", test_trace_unknown_tx),
        ("Trace Invalid Hex", test_trace_invalid_hex),
        ("Refresh", test_refresh),
        ("Refresh Before DKG", test_refresh_before_dkg),
        ("Sign After Refresh", test_sign_after_refresh),
        ("Ledger", test_ledger),
        ("Ledger Pagination", test_ledger_pagination),
        ("List Nodes", test_list_nodes),
        ("Get Node", test_get_node),
        ("Get Node 404", test_get_node_404),
        ("Create API Key Admin", test_create_api_key_admin),
        ("Create API Key User", test_create_api_key_user),
        ("Create API Key Invalid Role", test_create_api_key_invalid_role),
        ("Create API Key No Admin", test_create_api_key_no_admin),
        ("List API Keys", test_list_api_keys),
        ("List API Keys No Admin", test_list_api_keys_no_admin),
        ("Auth No Header", test_auth_no_header),
        ("Auth Short Key", test_auth_short_key),
        ("Auth Long Key", test_auth_long_key),
        ("Auth Wrong Key", test_auth_wrong_key),
        ("Auth Malformed Bearer", test_auth_malformed_bearer),
        ("Auth SQL Injection", test_auth_sql_injection),
    ]

    for name, fn in test_fns:
        check(name, fn)

    # Summary
    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed, {failed} failed / {len(test_fns)} total")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
