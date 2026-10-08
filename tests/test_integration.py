"""Integration tests - API + services + database together (FastAPI TestClient)."""
import threading
import uuid

from app import services
from tests.conftest import unique


def idem():
    return {"Idempotency-Key": uuid.uuid4().hex}


def test_full_payment_lifecycle(api):
    alice = api.new_customer(unique("alice"), funds=100_000)
    shop = api.new_merchant(unique("shop"))
    r = alice.signed_post("/api/payments", {"merchant_id": shop.merchant_id, "amount": 25_000}, extra=idem())
    assert r.status_code == 201 and r.json()["status"] == "PENDING"
    pid = r.json()["payment_id"]
    r = alice.signed_post(f"/api/payments/{pid}/confirm")
    assert r.status_code == 200 and r.json()["status"] == "CONFIRMED"
    assert alice.get("/api/wallets/me").json()["balance"] == 75_000
    assert shop.get("/api/wallets/me").json()["balance"] == 25_000
    r = shop.signed_post(f"/api/payments/{pid}/refund", {"reason": "customer returned item"})
    assert r.status_code == 200 and r.json()["status"] == "REFUNDED"
    assert alice.get("/api/wallets/me").json()["balance"] == 100_000
    types = [t["txn_type"] for t in alice.get("/api/transactions").json()]
    assert types == ["REFUND_CREDIT", "DEBIT", "TOPUP"]


def test_idempotency_same_key_returns_same_payment(api):
    c = api.new_customer(unique("idem"), funds=50_000)
    m = api.new_merchant(unique("m"))
    key = idem()
    a = c.signed_post("/api/payments", {"merchant_id": m.merchant_id, "amount": 1000}, extra=key).json()
    b = c.signed_post("/api/payments", {"merchant_id": m.merchant_id, "amount": 1000}, extra=key).json()
    assert a["payment_id"] == b["payment_id"] and b["idempotent_replay"] is True
    r = c.signed_post("/api/payments", {"merchant_id": m.merchant_id, "amount": 9999}, extra=key)
    assert r.status_code == 409                               # same key, different amount


def test_replayed_request_is_rejected(api):
    c = api.new_customer(unique("rep"), funds=10_000)
    nonce = uuid.uuid4().hex
    assert c.signed_post("/api/wallets/topup", {"amount": 500}, nonce=nonce).status_code == 200
    r = c.signed_post("/api/wallets/topup", {"amount": 500}, nonce=nonce)      # captured & resent
    assert r.status_code == 409 and "replay" in r.json()["detail"]
    assert c.get("/api/wallets/me").json()["balance"] == 10_500


def test_tampered_body_is_rejected(api, client):
    c = api.new_customer(unique("tam"), funds=0)
    h = c.headers(c.signed_headers("/api/wallets/topup", b'{"amount": 100}'))
    r = client.post("/api/wallets/topup", content=b'{"amount": 9000000}', headers=h)
    assert r.status_code == 401 and c.get("/api/wallets/me").json()["balance"] == 0


def test_cannot_confirm_someone_elses_payment(api):
    victim = api.new_customer(unique("vic"), funds=10_000)
    thief = api.new_customer(unique("thf"), funds=0)
    m = api.new_merchant(unique("m"))
    pid = victim.signed_post("/api/payments", {"merchant_id": m.merchant_id, "amount": 5000},
                             extra=idem()).json()["payment_id"]
    assert thief.signed_post(f"/api/payments/{pid}/confirm").status_code == 404     # no IDOR


def test_role_based_authorization(api):
    c = api.new_customer(unique("rb"), funds=1000)
    assert c.get("/api/admin/audit").status_code == 403
    assert c.signed_post("/api/payments/1/refund", {"reason": "steal it"}).status_code == 403
    assert api.http.get("/api/wallets/me").status_code == 401                      # no token


def test_account_lockout_after_failed_logins(api, client):
    name = unique("lock")
    api.register(name)
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": name, "password": "wrong-pass"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": name, "password": "Str0ng-Passw0rd!"})
    assert r.status_code == 423                                 # locked even with the right password


def test_insufficient_funds_fails_cleanly(api):
    c = api.new_customer(unique("poor"), funds=100)
    m = api.new_merchant(unique("m"))
    pid = c.signed_post("/api/payments", {"merchant_id": m.merchant_id, "amount": 5000}, extra=idem()).json()["payment_id"]
    assert c.signed_post(f"/api/payments/{pid}/confirm").json()["status"] == "FAILED"
    assert c.get("/api/wallets/me").json()["balance"] == 100


def test_double_spend_race_only_one_confirm_succeeds(api):
    """20 threads confirm the SAME payment at once: exactly one may succeed."""
    c = api.new_customer(unique("race"), funds=10_000)
    m = api.new_merchant(unique("m"))
    pid = services.initiate_payment(c.user_id, m.merchant_id, 10_000, uuid.uuid4().hex)["payment_id"]
    results, barrier = [], threading.Barrier(20)

    def worker():
        barrier.wait()
        try:
            results.append(services.confirm_payment(c.user_id, pid)["status"])
        except services.DomainError as e:
            results.append(e.status)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("CONFIRMED") == 1 and results.count(409) == 19
    assert services.get_wallet(c.user_id)["balance"] == 0
    assert services.get_wallet(m.user_id)["balance"] == 10_000


def test_concurrent_payments_never_overdraw(api):
    """10 different payments of 3,000 against a 10,000 balance: max 3 can succeed."""
    c = api.new_customer(unique("over"), funds=10_000)
    m = api.new_merchant(unique("m"))
    pids = [services.initiate_payment(c.user_id, m.merchant_id, 3000, uuid.uuid4().hex)["payment_id"] for _ in range(10)]
    results, barrier = [], threading.Barrier(10)

    def worker(pid):
        barrier.wait()
        results.append(services.confirm_payment(c.user_id, pid)["status"])

    threads = [threading.Thread(target=worker, args=(p,)) for p in pids]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("CONFIRMED") == 3
    assert services.get_wallet(c.user_id)["balance"] == 1000


def test_audit_chain_valid_after_activity(api):
    admin = api.login("admin_test", "Admin-Test-Pass-1")
    body = admin.get("/api/admin/audit").json()
    assert body["verification"]["valid"] is True and body["verification"]["entries"] > 10


def test_huge_ids_rejected_not_500(api):
    """DEF-06 regression (found by fuzzing): IDs beyond SQLite INTEGER range must give 422, not 500."""
    c = api.new_customer(unique("big"), funds=1000)
    r = c.signed_post("/api/payments", {"merchant_id": 2**70, "amount": 100}, extra=idem())
    assert r.status_code == 422
    r = c.signed_post(f"/api/payments/{2**70}/confirm")
    assert r.status_code == 422
