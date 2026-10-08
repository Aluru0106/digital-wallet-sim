"""SQLite data layer.

Money is stored as integer minor units (paise) to avoid floating-point errors.
Write paths use `BEGIN IMMEDIATE`, which takes the database write lock before
reading balances, so two concurrent payments cannot both pass a balance check.
"""
import sqlite3
from contextlib import contextmanager

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('customer','merchant','admin')),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wallets(
    wallet_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER UNIQUE NOT NULL REFERENCES users(user_id),
    balance    INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
    currency   TEXT NOT NULL DEFAULT 'INR',
    status     TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS merchants(
    merchant_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER UNIQUE NOT NULL REFERENCES users(user_id),
    business_name TEXT NOT NULL,
    category      TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments(
    payment_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    payer_wallet_id INTEGER NOT NULL REFERENCES wallets(wallet_id),
    merchant_id     INTEGER NOT NULL REFERENCES merchants(merchant_id),
    amount          INTEGER NOT NULL CHECK(amount > 0),
    status          TEXT NOT NULL CHECK(status IN ('PENDING','CONFIRMED','REFUNDED','FAILED')),
    idempotency_key TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    confirmed_at    TEXT,
    UNIQUE(payer_wallet_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS transactions(
    txn_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_id  INTEGER NOT NULL REFERENCES wallets(wallet_id),
    payment_id INTEGER REFERENCES payments(payment_id),
    txn_type   TEXT NOT NULL CHECK(txn_type IN ('TOPUP','DEBIT','CREDIT','REFUND_DEBIT','REFUND_CREDIT')),
    amount     INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS refunds(
    refund_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id INTEGER UNIQUE NOT NULL REFERENCES payments(payment_id),
    amount     INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS used_nonces(
    nonce      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
    audit_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor_id   INTEGER,
    action     TEXT NOT NULL,
    entity     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(settings.db_path, timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 10000")
    return con


def init_db() -> None:
    con = connect()
    try:
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript(SCHEMA)
    finally:
        con.close()


@contextmanager
def tx():
    """Serialised write transaction (BEGIN IMMEDIATE ... COMMIT/ROLLBACK)."""
    con = connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        yield con
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


@contextmanager
def read():
    con = connect()
    try:
        yield con
    finally:
        con.close()
