"""PayLite v1 - INITIAL (INSECURE) VERSION, kept only as 'before' evidence for refactoring.

DO NOT DEPLOY. Known issues (fixed in app/ v2):
  W1 hard-coded secret key                      -> config.py reads env / K8s Secret
  W2 float money                                -> integer paise
  W3 check-then-act balance update (race / double spend)
                                                -> BEGIN IMMEDIATE + conditional UPDATE
  W4 no idempotency key (client retry = 2 charges) -> UNIQUE(wallet, idempotency_key)
  W5 no ownership check on confirm (IDOR)       -> payer must own the payment
  W6 SQL built with string formatting (SQLi)    -> parameterised queries
  W7 internal error text returned to client     -> generic error handler
  W8 MD5 password hashing                       -> bcrypt cost 12
"""
import hashlib
import sqlite3
import threading
import time

SECRET_KEY = "paylite-secret-123"   # W1 (deliberate, for the 'before' scan)
DB = "legacy_v1.db"
_lock = threading.local()


def connect():
    con = sqlite3.connect(DB, timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init():
    con = connect()
    con.executescript("""
    DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS wallets; DROP TABLE IF EXISTS payments;
    CREATE TABLE users(user_id INTEGER PRIMARY KEY, username TEXT, pw TEXT);
    CREATE TABLE wallets(wallet_id INTEGER PRIMARY KEY, user_id INTEGER, balance REAL);
    CREATE TABLE payments(payment_id INTEGER PRIMARY KEY, wallet_id INTEGER, merchant_wallet INTEGER,
                          amount REAL, status TEXT);
    """)
    con.commit()
    con.close()


def register(username, password):
    con = connect()
    pw = hashlib.md5(password.encode()).hexdigest()           # W8
    con.execute(f"INSERT INTO users(username, pw) VALUES ('{username}', '{pw}')")   # W6
    con.commit()
    uid = con.execute("SELECT max(user_id) FROM users").fetchone()[0]
    con.execute("INSERT INTO wallets(user_id, balance) VALUES (?, 0)", (uid,))
    con.commit()
    con.close()
    return uid


def add_funds(user_id, amount):
    con = connect()
    con.execute("UPDATE wallets SET balance = balance + ? WHERE user_id=?", (float(amount), user_id))   # W2
    con.commit()
    con.close()


def balance(user_id):
    con = connect()
    b = con.execute("SELECT balance FROM wallets WHERE user_id=?", (user_id,)).fetchone()[0]
    con.close()
    return b


def initiate(user_id, merchant_user_id, amount):          # W4: every call creates a new payment
    con = connect()
    w = con.execute("SELECT wallet_id FROM wallets WHERE user_id=?", (user_id,)).fetchone()[0]
    mw = con.execute("SELECT wallet_id FROM wallets WHERE user_id=?", (merchant_user_id,)).fetchone()[0]
    cur = con.execute("INSERT INTO payments(wallet_id, merchant_wallet, amount, status) VALUES (?,?,?,'PENDING')",
                      (w, mw, amount))
    con.commit()
    con.close()
    return cur.lastrowid


def confirm(caller_id, payment_id):                       # W5: caller_id never checked
    con = connect()
    try:
        p = con.execute("SELECT * FROM payments WHERE payment_id=?", (payment_id,)).fetchone()
        if p["status"] != "PENDING":
            return "ALREADY"
        bal = con.execute("SELECT balance FROM wallets WHERE wallet_id=?", (p["wallet_id"],)).fetchone()[0]
        if bal < p["amount"]:
            return "INSUFFICIENT"
        time.sleep(0.05)                                  # simulates processing latency -> W3 race window
        con.execute("UPDATE wallets SET balance=? WHERE wallet_id=?", (bal - p["amount"], p["wallet_id"]))
        con.execute("UPDATE wallets SET balance = balance + ? WHERE wallet_id=?", (p["amount"], p["merchant_wallet"]))
        con.execute("UPDATE payments SET status='CONFIRMED' WHERE payment_id=?", (payment_id,))
        con.commit()
        return "CONFIRMED"
    except Exception as ex:
        return f"error: {ex}"                             # W7
    finally:
        con.close()
