"""Unit tests - security primitives and validation in isolation."""
import time

import jwt
import pytest

from app import audit, services
from app.config import settings
from app.db import tx
from app.security import (ReplayError, canonical, check_fresh, consume_nonce, decode_token, hash_password,
                          issue_token, sign, signing_key_for, verify_password, verify_signature)


def test_password_hash_is_salted_and_verifies():
    h1, h2 = hash_password("Correct-Horse-1"), hash_password("Correct-Horse-1")
    assert h1 != h2                                  # unique salt
    assert h1.startswith("$2b$12$")                  # bcrypt, cost 12
    assert verify_password("Correct-Horse-1", h1)
    assert not verify_password("wrong-password", h1)


def test_token_roundtrip_and_alg_none_rejected():
    tok = issue_token(7, "customer")
    assert decode_token(tok)["sub"] == "7"
    forged = jwt.encode({"sub": "1", "role": "admin", "exp": int(time.time()) + 60}, key="", algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        decode_token(forged)


def test_token_signed_with_other_key_rejected():
    forged = jwt.encode({"sub": "1", "role": "admin", "exp": int(time.time()) + 60}, "attacker-key-0123456789abcdef0123", algorithm="HS256")
    with pytest.raises(jwt.PyJWTError):
        decode_token(forged)


def test_signature_detects_tampering():
    key = signing_key_for(42)
    msg = canonical("POST", "/api/payments", "1700000000", "n" * 32, b'{"amount":100}')
    sig = sign(key, msg)
    assert verify_signature(42, msg, sig)
    tampered = canonical("POST", "/api/payments", "1700000000", "n" * 32, b'{"amount":999999}')
    assert not verify_signature(42, tampered, sig)          # body changed
    assert not verify_signature(43, msg, sig)               # other user's key


@pytest.mark.parametrize("ts,ok", [(0, True), (-60, True), (-(settings.replay_window_seconds + 5), False),
                                   (settings.replay_window_seconds + 5, False)])
def test_timestamp_window(ts, ok):
    now = time.time()
    if ok:
        check_fresh(str(int(now + ts)), now)
    else:
        with pytest.raises(ReplayError):
            check_fresh(str(int(now + ts)), now)


def test_timestamp_garbage_rejected():
    with pytest.raises(ReplayError):
        check_fresh("not-a-number")


def test_nonce_single_use(client):
    nonce = "unit-nonce-" + "a" * 20
    with tx() as con:
        consume_nonce(con, nonce, 1)
    with pytest.raises(ReplayError), tx() as con:
        consume_nonce(con, nonce, 1)


def test_audit_chain_detects_modification():
    rows, prev = [], audit.GENESIS
    for i in range(3):
        ts, detail = f"2026-10-08T10:0{i}:00", '{"amount": 100}'
        h = audit._entry_hash(prev, ts, 1, "X", "e", detail)
        rows.append({"audit_id": i + 1, "ts": ts, "actor_id": 1, "action": "X", "entity": "e",
                     "detail": detail, "prev_hash": prev, "entry_hash": h})
        prev = h
    assert audit.verify_chain(rows)["valid"]
    rows[1]["detail"] = '{"amount": 1}'                      # attacker edits an old record
    assert audit.verify_chain(rows) == {"valid": False, "broken_at": 2}


@pytest.mark.parametrize("amount", [0, -1, services.MAX_TOPUP + 1])
def test_topup_amount_bounds(client, amount):
    with pytest.raises(services.DomainError) as e:
        services.add_funds(999999, amount)
    assert e.value.status == 422
