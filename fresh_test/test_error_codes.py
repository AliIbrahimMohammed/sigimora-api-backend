#!/usr/bin/env python3
"""VERIFY all error paths return correct status codes."""

import json, sys, urllib.error, urllib.request, uuid

BASE = "http://127.0.0.1:18082/api/v1"
KEY = "sigimora_Test200StatusKey0000000"

total = 0
passed = 0
failed = 0

def req(method, path, body=None, token=KEY):
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    try:
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw": body.decode()}
        return e.code, parsed
    except Exception as e:
        return None, {"error": str(e)}

def check(name, got, expected):
    global total, passed, failed
    total += 1
    mark = "✅" if got == expected else "❌"
    if got == expected:
        passed += 1
    else:
        failed += 1
    print(f"  {mark} {name} → got {got}, expected {expected}")

# Create a network + DKG for some tests
s, d = req("POST", "/networks", {"n": 4, "t": 2})
NET_ID = d["network"]["id"]
NET_KEY = d["bootstrap_api_key"]
NET_TRACK = d["tracking_secret_key_hex"]
req("POST", f"/networks/{NET_ID}/dkg", token=NET_KEY)
s, d = req("POST", f"/networks/{NET_ID}/sign",
           {"message": "deadbeef", "quorum": [1, 2, 3]}, token=NET_KEY)
TX_ID = d["tx_id"]
SIG_HEX = d["combined_sig_hex"]

# Create a network WITHOUT DKG for state-error tests
s, nd = req("POST", "/networks", {"n": 3, "t": 1})
NO_DKG_ID = nd["network"]["id"]
NO_DKG_KEY = nd["bootstrap_api_key"]

print("\n── 400 BAD REQUEST ──")
check("n < 2", req("POST", "/networks", {"n": 0, "t": 0})[0], 400)
check("n = 1", req("POST", "/networks", {"n": 1, "t": 1})[0], 400)
check("t >= n", req("POST", "/networks", {"n": 3, "t": 3})[0], 400)
check("Sign bad hex", req("POST", f"/networks/{NET_ID}/sign",
    {"message": "nothex!", "quorum": [1, 2, 3]}, token=NET_KEY)[0], 400)
check("Sign insufficient quorum", req("POST", f"/networks/{NET_ID}/sign",
    {"message": "dead", "quorum": [1]}, token=NET_KEY)[0], 400)
check("Sign nonexistent nodes", req("POST", f"/networks/{NET_ID}/sign",
    {"message": "dead", "quorum": [99, 100, 101]}, token=NET_KEY)[0], 400)
check("Verify wrong sig length", req("POST", f"/networks/{NET_ID}/verify",
    {"message": "dead", "signature_hex": "ab"*47}, token=NET_KEY)[0], 400)
check("Verify bad sig hex", req("POST", f"/networks/{NET_ID}/verify",
    {"message": "dead", "signature_hex": "xyz"}, token=NET_KEY)[0], 400)
check("Trace bad hex key", req("POST", f"/networks/{NET_ID}/trace",
    {"tx_id": TX_ID, "tracking_key_hex": "nothex"}, token=NET_KEY)[0], 400)
check("Trace wrong key length", req("POST", f"/networks/{NET_ID}/trace",
    {"tx_id": TX_ID, "tracking_key_hex": "ab"*31}, token=NET_KEY)[0], 400)
check("API key invalid role", req("POST", "/api-keys",
    {"label": "x", "role": "superadmin"})[0], 400)
check("Create network missing n", req("POST", "/networks", {})[0], 400)
check("Sign without DKG", req("POST", f"/networks/{NO_DKG_ID}/sign",
    {"message": "dead", "quorum": [1, 2]}, token=NO_DKG_KEY)[0], 400)
check("Refresh before DKG", req("POST", f"/networks/{NO_DKG_ID}/refresh",
    token=NO_DKG_KEY)[0], 400)

print("\n── 401 UNAUTHORIZED ──")
check("No auth header", req("GET", "/networks", token=None)[0], 401)
check("Short key (5 chars)", req("GET", "/networks", token="short")[0], 401)
check("Long key (300 chars)", req("GET", "/networks", token="x"*300)[0], 401)
check("Wrong key", req("GET", "/networks", token="sigimora_ThisKeyDoesNotExist1234")[0], 401)

# Malformed Bearer
url = f"{BASE}/networks"
headers = {"Authorization": "NotBearer xyz"}
try:
    r = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(r, timeout=10) as resp: s2 = resp.status
except urllib.error.HTTPError as e: s2 = e.code
check("Malformed Bearer", s2, 401)

check("SQL injection key", req("GET", "/networks",
    token="sigimora_'; DROP TABLE api_keys;--")[0], 401)
check("User creates API key", req("POST", "/api-keys",
    {"label": "x", "role": "user"}, token="")[0], 401)
check("User lists API keys", req("GET", "/api-keys",
    token="")[0], 401)

print("\n── 404 NOT FOUND ──")
check("Get unknown network", req("GET", "/networks/bad-id")[0], 404)
check("DKG unknown network", req("POST", "/networks/bad-id/dkg")[0], 404)
check("Sign unknown network", req("POST", "/networks/bad-id/sign",
    {"message": "dead", "quorum": [1, 2, 3]})[0], 404)
check("Verify unknown network", req("POST", "/networks/bad-id/verify",
    {"message": "dead", "signature_hex": "ab"*48})[0], 404)
check("Trace unknown network", req("POST", "/networks/bad-id/trace",
    {"tx_id": str(uuid.uuid4()), "tracking_key_hex": "ab"*32})[0], 404)
check("Refresh unknown network", req("POST", "/networks/bad-id/refresh")[0], 404)
check("Ledger unknown network", req("GET", "/networks/bad-id/ledger")[0], 404)
check("Nodes unknown network", req("GET", "/networks/bad-id/nodes")[0], 404)
check("Get node 99", req("GET", f"/networks/{NET_ID}/nodes/99")[0], 404)
check("Trace unknown tx", req("POST", f"/networks/{NET_ID}/trace",
    {"tx_id": str(uuid.uuid4()), "tracking_key_hex": NET_TRACK},
    token=NET_KEY)[0], 404)

print(f"\n{'='*50}")
if failed == 0:
    print(f"  ✅ ALL {total} ERROR CASES RETURN CORRECT STATUS CODES")
else:
    print(f"  ❌ {passed}/{total} passed, {failed} FAILED")
print(f"{'='*50}")
sys.exit(0 if failed == 0 else 1)
