"""SQLite persistence for alerts, allowlist, feedback, and audit log."""
import hashlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from src.utils import DATA_DIR

# Sentinel for the first row in the audit chain. Any 64-hex string works as long as
# it's well-known; zeros are conventional for genesis blocks.
_AUDIT_GENESIS_HASH = "0" * 64

DB_PATH = os.path.join(DATA_DIR, "netwatchai.db")


def _utc_now() -> datetime:
    return datetime.now(UTC)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    packet_size INTEGER,
    flags TEXT,
    attack_type TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    marked_fp INTEGER DEFAULT 0,
    dedup_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
-- Covering index for the hot path: dashboard + exporter both filter by ts and marked_fp.
CREATE INDEX IF NOT EXISTS idx_alerts_ts_fp ON alerts(ts, marked_fp);

CREATE TABLE IF NOT EXISTS allowlist (
    ip TEXT PRIMARY KEY,
    note TEXT,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    prev_hash TEXT,
    row_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    ts TEXT NOT NULL,
    label TEXT NOT NULL,
    actor TEXT
);

CREATE TABLE IF NOT EXISTS alert_explanations (
    alert_id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    model TEXT,
    explanation TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);
"""


def get_explanation(alert_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT alert_id, ts, model, explanation FROM alert_explanations WHERE alert_id=?",
            (alert_id,),
        ).fetchone()
        return dict(row) if row else None


def save_explanation(alert_id: int, explanation: str, model: str) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO alert_explanations (alert_id, ts, model, explanation) "
            "VALUES (?, ?, ?, ?)",
            (alert_id, _utc_now().isoformat(), model, explanation),
        )


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _compute_row_hash(prev_hash: str, ts: str, actor: str | None, action: str, detail: str | None) -> str:
    # Order matters — must match verification. Use NUL bytes as separators so e.g.
    # actor="a|b" and detail="c" can't collide with actor="a" and detail="b|c".
    payload = "\x00".join([prev_hash, ts, actor or "", action, detail or ""])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ensure_audit_columns(c: sqlite3.Connection) -> None:
    cols = {row[1] for row in c.execute("PRAGMA table_info(audit_log)")}
    if "prev_hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
    if "row_hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT")


def _backfill_audit_chain(c: sqlite3.Connection) -> int:
    """Compute hashes for any rows missing them. Returns rows updated."""
    rows = list(c.execute(
        "SELECT id, ts, actor, action, detail, prev_hash, row_hash "
        "FROM audit_log ORDER BY id ASC"
    ))
    prev = _AUDIT_GENESIS_HASH
    updates = []
    for r in rows:
        rid, ts, actor, action, detail, stored_prev, stored_hash = r
        if stored_hash:
            prev = stored_hash
            continue
        new_hash = _compute_row_hash(prev, ts, actor, action, detail)
        updates.append((prev, new_hash, rid))
        prev = new_hash
    if updates:
        c.executemany(
            "UPDATE audit_log SET prev_hash=?, row_hash=? WHERE id=?",
            updates,
        )
    return len(updates)


def init_db() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA)
        _ensure_audit_columns(c)
        _backfill_audit_chain(c)


def verify_audit_chain() -> dict:
    """Walk the audit log and verify each row's hash matches its computed value.

    Returns {ok, total, first_broken_id} where first_broken_id is None if intact.
    """
    with _conn() as c:
        rows = list(c.execute(
            "SELECT id, ts, actor, action, detail, prev_hash, row_hash "
            "FROM audit_log ORDER BY id ASC"
        ))
    prev = _AUDIT_GENESIS_HASH
    for r in rows:
        rid, ts, actor, action, detail, stored_prev, stored_hash = r
        if stored_prev != prev:
            return {"ok": False, "total": len(rows), "first_broken_id": rid, "reason": "prev_hash mismatch"}
        expected = _compute_row_hash(prev, ts, actor, action, detail)
        if expected != stored_hash:
            return {"ok": False, "total": len(rows), "first_broken_id": rid, "reason": "row_hash mismatch"}
        prev = stored_hash
    return {"ok": True, "total": len(rows), "first_broken_id": None}


def record_alerts(rows: list[dict]) -> int:
    if not rows:
        return 0
    with _conn() as c:
        c.executemany(
            "INSERT INTO alerts "
            "(ts, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, flags, attack_type, dedup_key) "
            "VALUES (:ts, :src_ip, :dst_ip, :protocol, :src_port, :dst_port, :packet_size, :flags, :attack_type, :dedup_key)",
            rows,
        )
    return len(rows)


def dedup_key(src_ip: str, attack_type: str, window_seconds: int) -> str:
    bucket = int(_utc_now().timestamp() // window_seconds)
    return f"{src_ip}|{attack_type}|{bucket}"


def alert_exists(key: str) -> bool:
    with _conn() as c:
        row = c.execute("SELECT 1 FROM alerts WHERE dedup_key=? LIMIT 1", (key,)).fetchone()
        return row is not None


def list_alerts(days: int = 30, include_fp: bool = False) -> list[dict]:
    cutoff = (_utc_now() - timedelta(days=days)).isoformat()
    sql = "SELECT * FROM alerts WHERE ts >= ?"
    if not include_fp:
        sql += " AND marked_fp = 0"
    sql += " ORDER BY ts DESC"
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, (cutoff,))]


def mark_false_positive(alert_id: int, actor: str = "user") -> None:
    now = _utc_now().isoformat()
    with _conn() as c:
        c.execute("UPDATE alerts SET marked_fp=1, status='closed' WHERE id=?", (alert_id,))
        c.execute(
            "INSERT INTO feedback (alert_id, ts, label, actor) VALUES (?, ?, ?, ?)",
            (alert_id, now, "false_positive", actor),
        )


def add_allowlist(ip: str, note: str = "") -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO allowlist (ip, note, added_at) VALUES (?, ?, ?)",
            (ip, note, _utc_now().isoformat()),
        )


def remove_allowlist(ip: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM allowlist WHERE ip=?", (ip,))


def list_allowlist() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM allowlist ORDER BY added_at DESC")]


def is_allowlisted(ip: str) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM allowlist WHERE ip=?", (ip,)).fetchone() is not None


def log_audit(actor: str, action: str, detail: str = "") -> None:
    ts = _utc_now().isoformat()
    with _conn() as c:
        prev_row = c.execute(
            "SELECT row_hash FROM audit_log WHERE row_hash IS NOT NULL "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev_row["row_hash"] if prev_row else _AUDIT_GENESIS_HASH
        row_hash = _compute_row_hash(prev_hash, ts, actor, action, detail)
        c.execute(
            "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, actor, action, detail, prev_hash, row_hash),
        )


def list_audit(limit: int = 200) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
        )]


def purge_older_than(days: int) -> int:
    cutoff = (_utc_now() - timedelta(days=days)).isoformat()
    with _conn() as c:
        cur = c.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
        return cur.rowcount


def daily_alert_counts(days: int = 7) -> list[dict]:
    cutoff = (_utc_now() - timedelta(days=days)).isoformat()
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT substr(ts, 1, 10) AS day, COUNT(*) AS count "
            "FROM alerts WHERE ts >= ? AND marked_fp = 0 "
            "GROUP BY day ORDER BY day",
            (cutoff,),
        )]
