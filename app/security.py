"""Authentication, request signing and replay protection."""
import hashlib
import hmac
import sqlite3
import time

import bcrypt
import jwt

from app.config import settings

JWT_ALG = "HS256"


# ---------- passwords ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


# ---------- tokens ----------
def issue_token(user_id: int, role: str) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "role": role, "iat": now, "exp": now + settings.jwt_ttl_seconds}
    return jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    # algorithms is pinned: blocks "alg=none" and algorithm-confusion attacks
    return jwt.decode(token, settings.jwt_secret, algorithms=[JWT_ALG], options={"require": ["exp", "sub"]})


# ---------- request signing (anti-tampering) ----------
def signing_key_for(user_id: int) -> str:
    """Per-user request-signing key, derived server-side, never stored."""
    return hmac.new(settings.hmac_secret.encode(), f"user:{user_id}".encode(), hashlib.sha256).hexdigest()


def canonical(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    return "|".join([method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest()])


def sign(key: str, message: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_signature(user_id: int, message: str, signature: str) -> bool:
    expected = sign(signing_key_for(user_id), message)
    return hmac.compare_digest(expected, signature or "")


# ---------- replay protection ----------
class ReplayError(Exception):
    pass


def check_fresh(timestamp: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        raise ReplayError("invalid timestamp") from None
    if abs(now - ts) > settings.replay_window_seconds:
        raise ReplayError("request expired")


def consume_nonce(con: sqlite3.Connection, nonce: str, user_id: int) -> None:
    if not nonce or len(nonce) < 16 or len(nonce) > 64:
        raise ReplayError("invalid nonce")
    cutoff = int(time.time()) - settings.replay_window_seconds * 2
    con.execute("DELETE FROM used_nonces WHERE seen_at < ?", (cutoff,))
    try:
        con.execute("INSERT INTO used_nonces(nonce, user_id, seen_at) VALUES (?,?,?)",
                    (nonce, user_id, int(time.time())))
    except sqlite3.IntegrityError:
        raise ReplayError("nonce already used") from None
