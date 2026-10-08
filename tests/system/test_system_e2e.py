"""System / end-to-end test against the DEPLOYED application (container or Kubernetes).

Run:  BASE_URL=http://127.0.0.1:8080 pytest tests/system -v
It talks HTTP to the real service exactly like a browser client would.
"""
import hashlib
import hmac
import json
import os
import time
import uuid

import pytest
import requests

BASE = os.getenv("BASE_URL")
pytestmark = pytest.mark.skipif(not BASE, reason="BASE_URL not set (system test runs against a deployment)")
PW = "Str0ng-Passw0rd!"


def login(user):
    r = requests.post(f"{BASE}/api/auth/login", json={"username": user, "password": PW}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()


def signed(sess, path, body):
    raw = json.dumps(body).encode()
    ts, nonce = str(int(time.time())), uuid.uuid4().hex
    canon = "|".join(["POST", path, ts, nonce, hashlib.sha256(raw).hexdigest()])
    sig = hmac.new(sess["signing_key"].encode(), canon.encode(), hashlib.sha256).hexdigest()
    h = {"Authorization": "Bearer " + sess["access_token"], "Content-Type": "application/json",
         "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig}
    return h, raw


def post_signed(sess, path, body, extra=None):
    h, raw = signed(sess, path, body)
    h.update(extra or {})
    return requests.post(BASE + path, data=raw, headers=h, timeout=10)


def auth(sess):
    return {"Authorization": "Bearer " + sess["access_token"]}


def test_health_and_security_headers():
    r = requests.get(f"{BASE}/health", timeout=10)
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"):
        assert h in r.headers
    assert "server" not in {k.lower() for k in r.headers}           # --no-server-header
    assert requests.get(f"{BASE}/docs", timeout=10).status_code == 404   # API docs disabled in prod


def test_end_to_end_customer_merchant_refund():
    tag = uuid.uuid4().hex[:8]
    cust, merch = f"e2e_c_{tag}", f"e2e_m_{tag}"
    assert requests.post(f"{BASE}/api/auth/register", json={"username": cust, "password": PW}, timeout=10).status_code == 201
    assert requests.post(f"{BASE}/api/auth/register", json={"username": merch, "password": PW, "role": "merchant"}, timeout=10).status_code == 201
    c, m = login(cust), login(merch)
    assert requests.post(f"{BASE}/api/wallets", headers=auth(c), timeout=10).status_code == 201
    mid = requests.post(f"{BASE}/api/merchants", json={"business_name": "E2E Store", "category": "retail"},
                        headers=auth(m), timeout=10).json()["merchant_id"]
    assert post_signed(c, "/api/wallets/topup", {"amount": 50_000}).status_code == 200
    pay = post_signed(c, "/api/payments", {"merchant_id": mid, "amount": 20_000},
                      {"Idempotency-Key": uuid.uuid4().hex}).json()
    assert post_signed(c, f"/api/payments/{pay['payment_id']}/confirm", {}).json()["status"] == "CONFIRMED"
    # replaying the confirm with a fresh signature still cannot double-spend
    assert post_signed(c, f"/api/payments/{pay['payment_id']}/confirm", {}).status_code == 409
    assert requests.get(f"{BASE}/api/wallets/me", headers=auth(c), timeout=10).json()["balance"] == 30_000
    assert post_signed(m, f"/api/payments/{pay['payment_id']}/refund", {"reason": "e2e refund"}).json()["status"] == "REFUNDED"
    hist = requests.get(f"{BASE}/api/transactions", headers=auth(c), timeout=10).json()
    assert [t["txn_type"] for t in hist] == ["REFUND_CREDIT", "DEBIT", "TOPUP"]


def test_attacks_rejected_by_deployment():
    tag = uuid.uuid4().hex[:8]
    requests.post(f"{BASE}/api/auth/register", json={"username": f"atk_{tag}", "password": PW}, timeout=10)
    a = login(f"atk_{tag}")
    requests.post(f"{BASE}/api/wallets", headers=auth(a), timeout=10)
    h, raw = signed(a, "/api/wallets/topup", {"amount": 100})
    assert requests.post(f"{BASE}/api/wallets/topup", data=raw, headers=h, timeout=10).status_code == 200
    assert requests.post(f"{BASE}/api/wallets/topup", data=raw, headers=h, timeout=10).status_code == 409   # replay
    h2, _ = signed(a, "/api/wallets/topup", {"amount": 100})
    assert requests.post(f"{BASE}/api/wallets/topup", data=b'{"amount": 9999999}', headers=h2, timeout=10).status_code == 401  # tamper
    assert requests.get(f"{BASE}/api/admin/audit", headers=auth(a), timeout=10).status_code == 403          # authz
