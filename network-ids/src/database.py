"""SQLite schema + parameterized access for alert storage."""
from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from pathlib import Path
import config


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at     TEXT    NOT NULL,
    flow_timestamp  TEXT,
    source_ip       TEXT,
    source_port     INTEGER,
    dest_ip         TEXT,
    dest_port       INTEGER,
    protocol        TEXT,
    predicted_class TEXT    NOT NULL,
    confidence      REAL    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    anomaly_score   REAL,
    risk_score      REAL    NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT    NOT NULL CHECK (risk_level IN ('Low','Medium','High','Critical')),
    status          TEXT    NOT NULL DEFAULT 'New'
                        CHECK (status IN ('New','Investigating','Resolved')),
    dedup_key       TEXT    NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    features_json   TEXT,
    analyst_notes   TEXT,
    source_file     TEXT,
    model_version   TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_risk    ON alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_alerts_class   ON alerts(predicted_class);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup   ON alerts(dedup_key, last_seen);

CREATE TABLE IF NOT EXISTS alert_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   INTEGER NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    changed_at TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    note       TEXT
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at        TEXT NOT NULL,
    source_file   TEXT,
    total_records INTEGER NOT NULL,
    benign_count  INTEGER NOT NULL,
    suspicious_count INTEGER NOT NULL,
    summary_json  TEXT
);
"""

# Allow-listed columns for ORDER BY to prevent SQL injection
SORTABLE = {
    "alert_id", "detected_at", "risk_score", "risk_level",
    "status", "predicted_class", "source_ip", "dest_ip", "first_seen", "last_seen"
}


@contextmanager
def get_conn():
    """Context manager for SQLite connection with WAL mode and FK enforcement."""
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create schema if not exists; idempotent."""
    with get_conn() as conn:
        conn.executescript(SCHEMA_SQL)
        # Ensure schema_version has a row
        cur = conn.execute("SELECT COUNT(*) FROM schema_version")
        if cur.fetchone()[0] == 0:
            conn.execute("INSERT INTO schema_version (version) VALUES (1)")


def reset_db() -> None:
    """Drop all tables and recreate (for clean demo)."""
    with get_conn() as conn:
        conn.executescript("""
            DROP TABLE IF EXISTS alert_history;
            DROP TABLE IF EXISTS alerts;
            DROP TABLE IF EXISTS analysis_runs;
            DROP TABLE IF EXISTS schema_version;
        """)
    init_db()


def search_alerts(
    text: str | None = None,
    status: str | None = None,
    level: str | None = None,
    order_by: str = "detected_at",
    desc: bool = True,
    limit: int = 500,
) -> list[dict]:
    """Search alerts with filters; ORDER BY column is allow-listed."""
    if order_by not in SORTABLE:
        raise ValueError(f"Invalid sort column: {order_by}")
    sql, params = "SELECT * FROM alerts WHERE 1=1", []
    if status:
        sql += " AND status = ?"; params.append(status)
    if level:
        sql += " AND risk_level = ?"; params.append(level)
    if text:
        like = f"%{text}%"
        sql += " AND (source_ip LIKE ? OR dest_ip LIKE ? OR predicted_class LIKE ?)"
        params += [like, like, like]
    sql += f" ORDER BY {order_by} {'DESC' if desc else 'ASC'} LIMIT ?"
    params.append(int(limit))
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_alert(alert_id: int) -> dict | None:
    """Fetch a single alert by ID."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None


def update_alert_status(alert_id: int, new_status: str, note: str = "") -> bool:
    """Update alert status with history logging. Returns True if successful."""
    if new_status not in ("New", "Investigating", "Resolved"):
        raise ValueError(f"Invalid status: {new_status}")
    with get_conn() as conn:
        row = conn.execute("SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not row:
            return False
        old_status = row["status"]
        if old_status == new_status:
            return True
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id)
        )
        conn.execute(
            "INSERT INTO alert_history (alert_id, changed_at, old_status, new_status, note) VALUES (?,?,?,?,?)",
            (alert_id, now, old_status, new_status, note),
        )
    return True


def bulk_update_status(alert_ids: list[int], new_status: str, note: str = "") -> int:
    """Update status for multiple alerts. Returns count updated."""
    count = 0
    for aid in alert_ids:
        if update_alert_status(aid, new_status, note):
            count += 1
    return count


def export_alerts_csv(alerts: list[dict]) -> str:
    """Convert alerts to CSV string with formula-injection neutralization."""
    if not alerts:
        return ""
    import csv
    import io
    output = io.StringIO()
    fieldnames = list(alerts[0].keys())
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in alerts:
        # Neutralize formula injection: prefix cells starting with =,+,-,@ with '
        safe_row = {}
        for k, v in row.items():
            if isinstance(v, str) and v and v[0] in "=+-@":
                safe_row[k] = "'" + v
            else:
                safe_row[k] = v
        writer.writerow(safe_row)
    return output.getvalue()


def log_analysis_run(
    source_file: str,
    total_records: int,
    benign_count: int,
    suspicious_count: int,
    summary: dict,
) -> int:
    """Record a batch analysis run."""
    import json
    from datetime import datetime, timezone
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO analysis_runs (run_at, source_file, total_records, benign_count, suspicious_count, summary_json)
               VALUES (?,?,?,?,?,?)""",
            (datetime.now(timezone.utc).isoformat(), source_file, total_records, benign_count, suspicious_count, json.dumps(summary)),
        )
        return cur.lastrowid


def get_recent_runs(limit: int = 20) -> list[dict]:
    """Get recent analysis runs."""
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM analysis_runs ORDER BY run_at DESC LIMIT ?", (limit,)
        ).fetchall()]


def get_alert_counts() -> dict:
    """Get alert counts by status and risk level."""
    with get_conn() as conn:
        status_counts = dict(conn.execute("SELECT status, COUNT(*) as c FROM alerts GROUP BY status").fetchall())
        risk_counts = dict(conn.execute("SELECT risk_level, COUNT(*) as c FROM alerts GROUP BY risk_level").fetchall())
        class_counts = dict(conn.execute("SELECT predicted_class, COUNT(*) as c FROM alerts GROUP BY predicted_class").fetchall())
    return {"by_status": status_counts, "by_risk": risk_counts, "by_class": class_counts}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    if args.reset:
        reset_db()
        print("Database reset and reinitialized")
    elif args.init:
        init_db()
        print("Database initialized")
    else:
        init_db()
        print("Database ready at", config.DB_PATH)