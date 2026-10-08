"""Fuzz tests (property-based, Hypothesis) on input boundaries.

Property: whatever the input, the API never crashes (no HTTP 500), never
accepts an out-of-range amount, and never lets a balance go negative.
"""
import uuid

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.conftest import unique

FUZZ = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])

amounts = st.one_of(st.integers(min_value=-(2**70), max_value=2**70), st.floats(allow_nan=True),
                    st.text(max_size=30), st.none(), st.booleans(), st.lists(st.integers(), max_size=3))


@FUZZ
@given(amount=amounts)
def test_fuzz_topup_amount(api, amount):
    c = api._fz if hasattr(api, "_fz") else None
    if c is None:
        c = api.new_customer(unique("fz"))
        api._fz = c
    before = c.get("/api/wallets/me").json()["balance"]
    r = c.signed_post("/api/wallets/topup", {"amount": amount})
    assert r.status_code in (200, 422), (amount, r.status_code, r.text)
    if r.status_code == 200:
        assert isinstance(amount, int) and not isinstance(amount, bool) and 0 < amount <= 10_000_000
        assert r.json()["balance"] == before + amount


@FUZZ
@given(username=st.text(max_size=60), password=st.text(max_size=200), role=st.text(max_size=12))
def test_fuzz_register(client, username, password, role):
    r = client.post("/api/auth/register", json={"username": username, "password": password, "role": role})
    assert r.status_code in (201, 409, 422), r.text
    assert "Traceback" not in r.text


@FUZZ
@given(nonce=st.text(max_size=80), ts=st.text(max_size=25), sig=st.text(max_size=80))
def test_fuzz_replay_headers(api, client, nonce, ts, sig):
    if not hasattr(api, "_hz"):
        api._hz = api.new_customer(unique("hz"))
    c = api._hz
    try:
        h = c.headers({"X-Nonce": nonce, "X-Timestamp": ts, "X-Signature": sig})
    except Exception:
        return
    try:
        r = client.post("/api/wallets/topup", json={"amount": 100}, headers=h)
    except Exception as e:                                  # non-ASCII header values are refused by the client lib
        assert "header" in str(e).lower() or isinstance(e, (UnicodeEncodeError, ValueError))
        return
    assert r.status_code in (401, 409, 422), r.text


@FUZZ
@given(merchant_id=st.one_of(st.integers(min_value=-(2**65), max_value=2**65), st.text(max_size=10)),
       amount=amounts)
def test_fuzz_payment_initiation(api, merchant_id, amount):
    if not hasattr(api, "_pz"):
        api._pz = api.new_customer(unique("pz"), funds=1000)
    c = api._pz
    r = c.signed_post("/api/payments", {"merchant_id": merchant_id, "amount": amount},
                      extra={"Idempotency-Key": uuid.uuid4().hex})
    assert r.status_code in (201, 404, 422), (merchant_id, amount, r.status_code, r.text)
    assert c.get("/api/wallets/me").json()["balance"] == 1000      # initiation never moves money
