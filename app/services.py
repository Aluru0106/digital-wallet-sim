"""Wallet / payment business logic.

Integrity rules enforced here:
  * idempotency  - one payment per (payer wallet, Idempotency-Key)
  * no double spend / races - all money movement happens inside one
    BEGIN IMMEDIATE transaction with conditional updates (balance >= amount,
    status = 'PENDING') whose row counts are checked
  * authorization - every function receives the caller's identity and checks
    ownership (no IDOR)
  * audit - each state change appends a hash-chained audit entry in the same tx
"""
import sqlite3

from app import audit
from app.db import read, tx
from app.security import hash_password, verify_password

MAX_TOPUP = 10_000_000      # 1,00,000.00 INR in paise
MAX_PAYMENT = 5_000_000     # 50,000.00 INR in paise


class DomainError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# ---------------- users ----------------
def register_user(username: str, password: str, role: str) -> int:
    if role not in ("customer", "merchant"):
        raise DomainError(403, "role not allowed")       # admins cannot self-register
    try:
        with tx() as con:
            cur = con.execute("INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
                              (username, hash_password(password), role))
            uid = cur.lastrowid
            audit.append(con, uid, "USER_REGISTERED", f"user:{uid}", {"role": role})
    except sqlite3.IntegrityError:
        raise DomainError(409, "username already exists") from None
    return uid


def seed_admin(username: str, password: str) -> None:
    with tx() as con:
        if con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return
        cur = con.execute("INSERT INTO users(username, password_hash, role) VALUES (?,?,'admin')",
                          (username, hash_password(password)))
        audit.append(con, None, "ADMIN_SEEDED", f"user:{cur.lastrowid}", {})


_DUMMY_HASH = hash_password("dummy-password-for-timing")


def authenticate(username: str, password: str, now: int, max_failed: int, lockout: int) -> dict:
    failure = None
    with tx() as con:
        u = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u is None:
            verify_password(password, _DUMMY_HASH)     # same bcrypt cost for unknown users (no user enumeration)
            failure = DomainError(401, "invalid credentials")
        elif u["locked_until"] > now:
            failure = DomainError(423, "account temporarily locked")
        elif not verify_password(password, u["password_hash"]):
            failed = u["failed_logins"] + 1
            locked = now + lockout if failed >= max_failed else 0
            con.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE user_id=?",
                        (0 if locked else failed, locked, u["user_id"]))
            audit.append(con, u["user_id"], "LOGIN_FAILED", f"user:{u['user_id']}", {"locked": bool(locked)})
            failure = DomainError(401, "invalid credentials")
        else:
            con.execute("UPDATE users SET failed_logins=0, locked_until=0 WHERE user_id=?", (u["user_id"],))
            audit.append(con, u["user_id"], "LOGIN_OK", f"user:{u['user_id']}", {})
    # raised after COMMIT so the failed-attempt counter is persisted
    if failure:
        raise failure
    return {"user_id": u["user_id"], "role": u["role"], "username": u["username"]}


# ---------------- wallets ----------------
def _wallet_of(con, user_id: int):
    return con.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,)).fetchone()


def create_wallet(user_id: int) -> dict:
    try:
        with tx() as con:
            cur = con.execute("INSERT INTO wallets(user_id) VALUES (?)", (user_id,))
            audit.append(con, user_id, "WALLET_CREATED", f"wallet:{cur.lastrowid}", {})
            return {"wallet_id": cur.lastrowid, "balance": 0, "currency": "INR"}
    except sqlite3.IntegrityError:
        raise DomainError(409, "wallet already exists") from None


def get_wallet(user_id: int) -> dict:
    with read() as con:
        w = _wallet_of(con, user_id)
    if not w:
        raise DomainError(404, "wallet not found")
    return {"wallet_id": w["wallet_id"], "balance": w["balance"], "currency": w["currency"], "status": w["status"]}


def add_funds(user_id: int, amount: int) -> dict:
    if not (0 < amount <= MAX_TOPUP):
        raise DomainError(422, "amount out of range")
    with tx() as con:
        w = _wallet_of(con, user_id)
        if not w:
            raise DomainError(404, "wallet not found")
        con.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_id=?", (amount, w["wallet_id"]))
        bal = con.execute("SELECT balance FROM wallets WHERE wallet_id=?", (w["wallet_id"],)).fetchone()[0]
        con.execute("INSERT INTO transactions(wallet_id, txn_type, amount, balance_after) VALUES (?,?,?,?)",
                    (w["wallet_id"], "TOPUP", amount, bal))
        audit.append(con, user_id, "FUNDS_ADDED", f"wallet:{w['wallet_id']}", {"amount": amount})
    return {"wallet_id": w["wallet_id"], "balance": bal}


# ---------------- merchants ----------------
def register_merchant(user_id: int, business_name: str, category: str) -> dict:
    try:
        with tx() as con:
            cur = con.execute("INSERT INTO merchants(user_id, business_name, category) VALUES (?,?,?)",
                              (user_id, business_name, category))
            mid = cur.lastrowid
            if not _wallet_of(con, user_id):
                con.execute("INSERT INTO wallets(user_id) VALUES (?)", (user_id,))   # settlement wallet
            audit.append(con, user_id, "MERCHANT_REGISTERED", f"merchant:{mid}", {"name": business_name})
    except sqlite3.IntegrityError:
        raise DomainError(409, "merchant already registered") from None
    return {"merchant_id": mid, "business_name": business_name}


def list_merchants() -> list:
    with read() as con:
        return [dict(r) for r in con.execute("SELECT merchant_id, business_name, category FROM merchants")]


# ---------------- payments ----------------
def initiate_payment(user_id: int, merchant_id: int, amount: int, idem_key: str) -> dict:
    if not (0 < amount <= MAX_PAYMENT):
        raise DomainError(422, "amount out of range")
    with tx() as con:
        w = _wallet_of(con, user_id)
        if not w:
            raise DomainError(404, "wallet not found")
        m = con.execute("SELECT * FROM merchants WHERE merchant_id=?", (merchant_id,)).fetchone()
        if not m:
            raise DomainError(404, "merchant not found")
        if m["user_id"] == user_id:
            raise DomainError(422, "cannot pay yourself")
        existing = con.execute("SELECT * FROM payments WHERE payer_wallet_id=? AND idempotency_key=?",
                               (w["wallet_id"], idem_key)).fetchone()
        if existing:
            if existing["merchant_id"] != merchant_id or existing["amount"] != amount:
                raise DomainError(409, "idempotency key reused with different parameters")
            audit.security_event("idempotent_replay_returned", payment_id=existing["payment_id"], user_id=user_id)
            return {"payment_id": existing["payment_id"], "status": existing["status"], "amount": amount,
                    "idempotent_replay": True}
        cur = con.execute("INSERT INTO payments(payer_wallet_id, merchant_id, amount, status, idempotency_key) "
                          "VALUES (?,?,?,'PENDING',?)", (w["wallet_id"], merchant_id, amount, idem_key))
        pid = cur.lastrowid
        audit.append(con, user_id, "PAYMENT_INITIATED", f"payment:{pid}", {"amount": amount, "merchant": merchant_id})
    return {"payment_id": pid, "status": "PENDING", "amount": amount, "idempotent_replay": False}


def confirm_payment(user_id: int, payment_id: int) -> dict:
    with tx() as con:
        p = con.execute("SELECT p.*, w.user_id AS payer FROM payments p JOIN wallets w "
                        "ON w.wallet_id = p.payer_wallet_id WHERE p.payment_id=?", (payment_id,)).fetchone()
        if not p or p["payer"] != user_id:
            raise DomainError(404, "payment not found")          # same answer for "not yours" -> no enumeration
        if p["status"] != "PENDING":
            audit.security_event("double_confirm_blocked", level="WARNING", payment_id=payment_id, user_id=user_id)
            raise DomainError(409, f"payment already {p['status'].lower()}")
        # conditional debit: never lets balance go negative, even under concurrency
        debit = con.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_id=? AND balance >= ?",
                            (p["amount"], p["payer_wallet_id"], p["amount"]))
        if debit.rowcount != 1:
            con.execute("UPDATE payments SET status='FAILED' WHERE payment_id=?", (payment_id,))
            audit.append(con, user_id, "PAYMENT_FAILED", f"payment:{payment_id}", {"reason": "insufficient funds"})
            return {"payment_id": payment_id, "status": "FAILED", "reason": "insufficient funds"}
        mw = con.execute("SELECT w.wallet_id FROM merchants m JOIN wallets w ON w.user_id=m.user_id "
                         "WHERE m.merchant_id=?", (p["merchant_id"],)).fetchone()
        con.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_id=?", (p["amount"], mw["wallet_id"]))
        upd = con.execute("UPDATE payments SET status='CONFIRMED', confirmed_at=CURRENT_TIMESTAMP "
                          "WHERE payment_id=? AND status='PENDING'", (payment_id,))
        if upd.rowcount != 1:                                     # defence in depth
            raise DomainError(409, "payment state changed")
        for wid, typ in ((p["payer_wallet_id"], "DEBIT"), (mw["wallet_id"], "CREDIT")):
            bal = con.execute("SELECT balance FROM wallets WHERE wallet_id=?", (wid,)).fetchone()[0]
            con.execute("INSERT INTO transactions(wallet_id, payment_id, txn_type, amount, balance_after) "
                        "VALUES (?,?,?,?,?)", (wid, payment_id, typ, p["amount"], bal))
        audit.append(con, user_id, "PAYMENT_CONFIRMED", f"payment:{payment_id}", {"amount": p["amount"]})
    return {"payment_id": payment_id, "status": "CONFIRMED", "amount": p["amount"]}


def refund_payment(user_id: int, role: str, payment_id: int, reason: str) -> dict:
    with tx() as con:
        p = con.execute("SELECT p.*, m.user_id AS merchant_user FROM payments p JOIN merchants m "
                        "ON m.merchant_id = p.merchant_id WHERE p.payment_id=?", (payment_id,)).fetchone()
        if not p or (role != "admin" and p["merchant_user"] != user_id):
            raise DomainError(404, "payment not found")
        if p["status"] != "CONFIRMED":
            raise DomainError(409, "only confirmed payments can be refunded")
        mw = _wallet_of(con, p["merchant_user"])
        debit = con.execute("UPDATE wallets SET balance = balance - ? WHERE wallet_id=? AND balance >= ?",
                            (p["amount"], mw["wallet_id"], p["amount"]))
        if debit.rowcount != 1:
            raise DomainError(409, "merchant balance insufficient for refund")
        con.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_id=?", (p["amount"], p["payer_wallet_id"]))
        con.execute("UPDATE payments SET status='REFUNDED' WHERE payment_id=? AND status='CONFIRMED'", (payment_id,))
        con.execute("INSERT INTO refunds(payment_id, amount, reason, created_by) VALUES (?,?,?,?)",
                    (payment_id, p["amount"], reason, user_id))
        for wid, typ in ((mw["wallet_id"], "REFUND_DEBIT"), (p["payer_wallet_id"], "REFUND_CREDIT")):
            bal = con.execute("SELECT balance FROM wallets WHERE wallet_id=?", (wid,)).fetchone()[0]
            con.execute("INSERT INTO transactions(wallet_id, payment_id, txn_type, amount, balance_after) "
                        "VALUES (?,?,?,?,?)", (wid, payment_id, typ, p["amount"], bal))
        audit.append(con, user_id, "PAYMENT_REFUNDED", f"payment:{payment_id}", {"amount": p["amount"], "by": role})
    return {"payment_id": payment_id, "status": "REFUNDED", "amount": p["amount"]}


def history(user_id: int) -> list:
    with read() as con:
        w = _wallet_of(con, user_id)
        if not w:
            raise DomainError(404, "wallet not found")
        rows = con.execute("SELECT txn_id, payment_id, txn_type, amount, balance_after, created_at "
                           "FROM transactions WHERE wallet_id=? ORDER BY txn_id DESC LIMIT 200", (w["wallet_id"],))
        return [dict(r) for r in rows]


def merchant_payments(user_id: int) -> list:
    with read() as con:
        rows = con.execute("SELECT p.payment_id, p.amount, p.status, p.created_at FROM payments p "
                           "JOIN merchants m ON m.merchant_id=p.merchant_id WHERE m.user_id=? "
                           "ORDER BY p.payment_id DESC LIMIT 200", (user_id,))
        return [dict(r) for r in rows]


def audit_entries() -> dict:
    with read() as con:
        rows = con.execute("SELECT * FROM audit_log ORDER BY audit_id").fetchall()
    return {"verification": audit.verify_chain(rows), "entries": [dict(r) for r in rows[-100:]]}
