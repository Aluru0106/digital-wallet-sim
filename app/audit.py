"""Tamper-evident audit log (hash chain) + structured security logging + metrics."""
import hashlib
import json
import logging
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone

GENESIS = "0" * 64

# ---------- structured JSON logs to stdout (collected by Docker/Kubernetes) ----------
_log = logging.getLogger("wallet.security")
if not _log.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
    _log.setLevel(logging.INFO)

METRICS: Counter = Counter()


def security_event(event: str, level: str = "INFO", **fields) -> None:
    METRICS[event] += 1
    record = {"ts": datetime.now(timezone.utc).isoformat(), "level": level, "event": event, **fields}
    _log.info(json.dumps(record, default=str))


# ---------- hash-chained audit table ----------
def _entry_hash(prev_hash: str, ts: str, actor_id, action: str, entity: str, detail: str) -> str:
    material = json.dumps([prev_hash, ts, actor_id, action, entity, detail], separators=(",", ":"))
    return hashlib.sha256(material.encode()).hexdigest()


def append(con: sqlite3.Connection, actor_id, action: str, entity: str, detail: dict) -> None:
    """Must be called inside the same transaction as the business change."""
    row = con.execute("SELECT entry_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1").fetchone()
    prev_hash = row["entry_hash"] if row else GENESIS
    ts = datetime.now(timezone.utc).isoformat()
    detail_s = json.dumps(detail, sort_keys=True)
    h = _entry_hash(prev_hash, ts, actor_id, action, entity, detail_s)
    con.execute(
        "INSERT INTO audit_log(ts, actor_id, action, entity, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?)",
        (ts, actor_id, action, entity, detail_s, prev_hash, h),
    )


def verify_chain(rows) -> dict:
    prev = GENESIS
    for r in rows:
        expected = _entry_hash(prev, r["ts"], r["actor_id"], r["action"], r["entity"], r["detail"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"valid": False, "broken_at": r["audit_id"]}
        prev = r["entry_hash"]
    return {"valid": True, "entries": len(rows)}
