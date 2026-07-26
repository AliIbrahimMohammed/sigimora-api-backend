#!/usr/bin/env python3
"""
TEST: Every API endpoint — verify ALL success paths return HTTP 200.
"""

import json, sys, time, urllib.error, urllib.request, uuid

BASE = "http://127.0.0.1:18082/api/v1"
KEY = "sigimora_Test200StatusKey0000000"

total = 0
passed = 0
failed = 0

def req(method, path, body=None, token=KEY):
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    try:
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()) if e.read() else {}
    except Exception as e:
        return None, {"error": str(e)}

def check(name, status, expected=200):
    global total, passed, failed
    total += 1
    if status == expected:
        print(f"  ✅ {status} {name}")
        passed += 1
    else:
        print(f"  ❌ {status} (expected {expected}) {name}")
        failed += 1

print("=" * 60)
print("  VERIFY: Every endpoint returns 200 on success")
print("=" * 60)

# ─── 1. HEALTH (no auth) ───
print("\n── Health ──")
s, d = req("GET", "/health", token=None)
check("GET /health (no auth)", s, 200)
assert d["status"] == "ok"

# ─── 2. CREATE NETWORK ───
print("\n── Networks ──")
s, d = req("POST", "/networks", {"n": 4, "t": 2})
check("POST /networks (n=4,t=2)", s, 200)
NET_ID = d["network"]["id"]
TRACK_KEY = d["tracking_secret_key_hex"]
NET_KEY = d["bootstrap_api_key"]

# ─── 3. LIST NETWORKS ───
s, d = req("GET", "/networks")
check("GET /networks", s, 200)
assert len(d) >= 1

# ─── 4. GET NETWORK ───
s, d = req("GET", f"/networks/{NET_ID}")
check(f"GET /networks/{NET_ID}", s, 200)
assert d["id"] == NET_ID

# ─── 5. DKG ───
print("\n── DKG ──")
s, d = req("POST", f"/networks/{NET_ID}/dkg", token=NET_KEY)
check(f"POST /networks/{NET_ID}/dkg", s, 200)
assert d["state"] == "dkg_complete"
assert len(d["collective_pk_hex"]) == 192  # 96 bytes = 192 hex chars
COLLECTIVE_PK = d["collective_pk_hex"]

# ─── 6. DKG STATUS ───
s, d = req("GET", f"/networks/{NET_ID}/dkg", token=NET_KEY)
check(f"GET /networks/{NET_ID}/dkg", s, 200)
assert d["collective_pk_hex"] == COLLECTIVE_PK

# ─── 7. SIGN ───
print("\n── Signing ──")
MSG = "48656c6c6f20534947494d4f524121"  # "Hello SIGIMORA!"
s, d = req("POST", f"/networks/{NET_ID}/sign",
           {"message": MSG, "quorum": [1, 2, 3]}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/sign [1,2,3]", s, 200)
assert "tx_id" in d
assert len(d["combined_sig_hex"]) == 96  # 48 bytes G1
TX_ID = d["tx_id"]
SIG_HEX = d["combined_sig_hex"]

# ─── 8. SIGN different quorum ───
s, d = req("POST", f"/networks/{NET_ID}/sign",
           {"message": MSG, "quorum": [2, 3, 4]}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/sign [2,3,4]", s, 200)

# ─── 9. SIGN different message ───
s, d = req("POST", f"/networks/{NET_ID}/sign",
           {"message": "deadbeef", "quorum": [1, 3, 4]}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/sign deadbeef", s, 200)

# ─── 10. VERIFY valid ───
print("\n── Verification ──")
s, d = req("POST", f"/networks/{NET_ID}/verify",
           {"message": MSG, "signature_hex": SIG_HEX}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/verify valid", s, 200)
assert d["valid"] == True

# ─── 11. VERIFY wrong message (still 200, valid=false) ───
s, d = req("POST", f"/networks/{NET_ID}/verify",
           {"message": "deadbeef", "signature_hex": SIG_HEX}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/verify wrong msg", s, 200)
assert d["valid"] == False

# ─── 12. TRACE ───
print("\n── Trace ──")
s, d = req("POST", f"/networks/{NET_ID}/trace",
           {"tx_id": TX_ID, "tracking_key_hex": TRACK_KEY}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/trace", s, 200)
assert len(d["signers"]) == 3
assert {s["node_id"] for s in d["signers"]} == {1, 2, 3}

# ─── 13. REFRESH ───
print("\n── Refresh ──")
s, d = req("POST", f"/networks/{NET_ID}/refresh", token=NET_KEY)
check(f"POST /networks/{NET_ID}/refresh", s, 200)
assert d["invariant_preserved"] == True
assert d["epoch"] >= 1

# ─── 14. SIGN AFTER REFRESH ───
s, d = req("POST", f"/networks/{NET_ID}/sign",
           {"message": "72656672657368656421", "quorum": [1, 2, 4]}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/sign after refresh", s, 200)

# Verify it too
s2, d2 = req("POST", f"/networks/{NET_ID}/verify",
             {"message": "72656672657368656421", "signature_hex": d["combined_sig_hex"]}, token=NET_KEY)
check(f"POST /networks/{NET_ID}/verify after refresh", s2, 200)
assert d2["valid"] == True

# ─── 15. LEDGER ───
print("\n── Ledger ──")
s, d = req("GET", f"/networks/{NET_ID}/ledger", token=NET_KEY)
check(f"GET /networks/{NET_ID}/ledger", s, 200)
assert "entries" in d
assert "total" in d
assert d["total"] >= 3

# ─── 16. LEDGER pagination ───
s, d = req("GET", f"/networks/{NET_ID}/ledger?offset=0&limit=2", token=NET_KEY)
check(f"GET /networks/{NET_ID}/ledger?offset=0&limit=2", s, 200)
assert len(d["entries"]) <= 2

# ─── 17. LIST NODES ───
print("\n── Nodes ──")
s, d = req("GET", f"/networks/{NET_ID}/nodes", token=NET_KEY)
check(f"GET /networks/{NET_ID}/nodes", s, 200)
assert len(d) == 4  # n=4

# ─── 18. GET NODE ───
s, d = req("GET", f"/networks/{NET_ID}/nodes/1", token=NET_KEY)
check(f"GET /networks/{NET_ID}/nodes/1", s, 200)
assert d["node_id"] == 1
assert len(d["public_key_hex"]) == 192  # 96 bytes hex

s, d = req("GET", f"/networks/{NET_ID}/nodes/2", token=NET_KEY)
check(f"GET /networks/{NET_ID}/nodes/2", s, 200)
s, d = req("GET", f"/networks/{NET_ID}/nodes/3", token=NET_KEY)
check(f"GET /networks/{NET_ID}/nodes/3", s, 200)
s, d = req("GET", f"/networks/{NET_ID}/nodes/4", token=NET_KEY)
check(f"GET /networks/{NET_ID}/nodes/4", s, 200)

# ─── 19. API KEYS ───
print("\n── API Keys ──")
s, d = req("POST", "/api-keys", {"label": "admin2", "role": "admin"})
check("POST /api-keys (admin)", s, 200)
assert d["api_key"]["role"] == "admin"
ADMIN2_KEY = d["raw_key"]

s, d = req("POST", "/api-keys", {"label": "user1", "role": "user"})
check("POST /api-keys (user)", s, 200)
assert d["api_key"]["role"] == "user"
USER_KEY = d["raw_key"]

s, d = req("GET", "/api-keys")
check("GET /api-keys (admin)", s, 200)
assert len(d) >= 3

# ─── 20. SECOND ADMIN KEY WORKS ───
s, d = req("POST", "/api-keys", {"label": "from-admin2", "role": "user"}, token=ADMIN2_KEY)
check("POST /api-keys (admin2 key)", s, 200)

# ─── 21. USER KEY CAN ACCESS NETWORKS ───
s, d = req("GET", "/networks", token=USER_KEY)
check("GET /networks (user key)", s, 200)

# ─── 22. SECOND NETWORK ───
print("\n── Second Network ──")
s, d = req("POST", "/networks", {"n": 3, "t": 1})
check("POST /networks (n=3,t=1)", s, 200)
NET2_ID = d["network"]["id"]
NET2_KEY = d["bootstrap_api_key"]

s, d = req("POST", f"/networks/{NET2_ID}/dkg", token=NET2_KEY)
check(f"DKG network2", s, 200)

s, d = req("POST", f"/networks/{NET2_ID}/sign",
           {"message": MSG, "quorum": [1, 2]}, token=NET2_KEY)
check(f"SIGN network2", s, 200)

s, d = req("POST", f"/networks/{NET2_ID}/verify",
           {"message": MSG, "signature_hex": d["combined_sig_hex"]}, token=NET2_KEY)
check(f"VERIFY network2", s, 200)
assert d["valid"] == True

# ─── 23. LIST ALL NETWORKS (should be 2) ───
s, d = req("GET", "/networks")
check("GET /networks (2 networks)", s, 200)
assert len(d) >= 2

# ─── SUMMARY ───
print("\n" + "=" * 60)
if failed == 0:
    print(f"  ✅ ALL {total} SUCCESS ENDPOINTS RETURN HTTP 200")
else:
    print(f"  ❌ {passed}/{total} passed, {failed} FAILED")
print("=" * 60)

sys.exit(0 if failed == 0 else 1)
