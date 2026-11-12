"""Tests for database module."""
import pytest
import sqlite3
from pathlib import Path

from src.database import (
    get_conn,
    init_db,
    reset_db,
    search_alerts,
    update_alert_status,
    bulk_update_status,
    export_alerts_csv,
    log_analysis_run,
    get_recent_runs,
    get_alert_counts,
)


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database for testing."""
    import config
    original_db = config.DB_PATH
    config.DB_PATH = tmp_path / "test_alerts.db"
    init_db()
    yield
    config.DB_PATH = original_db


def test_schema_creation_idempotent(temp_db):
    """Running init_db twice should not error."""
    init_db()  # Should not raise
    with get_conn() as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        assert "alerts" in table_names
        assert "alert_history" in table_names
        assert "analysis_runs" in table_names
        assert "schema_version" in table_names


def test_insert_and_search_alert(temp_db):
    """Test basic alert insertion and search."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts (
                detected_at, predicted_class, confidence, risk_score, risk_level,
                dedup_key, first_seen, last_seen
            ) VALUES (?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                "DoS",
                0.95,
                85.0,
                "Critical",
                "test_key_1",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    results = search_alerts()
    assert len(results) == 1
    assert results[0]["predicted_class"] == "DoS"
    assert results[0]["risk_level"] == "Critical"


def test_search_filters(temp_db):
    """Test search with status, level, and text filters."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        for i, (cls, level, status) in enumerate([
            ("DoS", "Critical", "New"),
            ("PortScan", "Medium", "Investigating"),
            ("BruteForce", "High", "Resolved"),
        ]):
            conn.execute(
                """INSERT INTO alerts (
                    detected_at, source_ip, predicted_class, confidence, risk_score, risk_level,
                    status, dedup_key, first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    f"192.168.1.{i}",
                    cls,
                    0.9,
                    50.0 + i * 10,
                    level,
                    status,
                    f"key_{i}",
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    # Filter by status
    results = search_alerts(status="New")
    assert len(results) == 1
    assert results[0]["predicted_class"] == "DoS"

    # Filter by risk level
    results = search_alerts(level="High")
    assert len(results) == 1
    assert results[0]["predicted_class"] == "BruteForce"

    # Text search on IP
    results = search_alerts(text="192.168.1.1")
    assert len(results) == 1


def test_sql_injection_safety(temp_db):
    """SQL injection payload in search should be treated as data."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts (
                detected_at, source_ip, predicted_class, confidence, risk_score, risk_level,
                status, dedup_key, first_seen, last_seen
            ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                "192.168.1.1",
                "DoS",
                0.9,
                80.0,
                "High",
                "New",
                "key_1",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    # Injection attempt in text search
    results = search_alerts(text="1' OR '1'='1")
    # Should not return the alert (no IP matches that literal string)
    assert len(results) == 0

    # Injection attempt in order_by (should raise ValueError)
    with pytest.raises(ValueError, match="Invalid sort column"):
        search_alerts(order_by="alert_id; DROP TABLE alerts; --")


def test_invalid_status_rejected(temp_db):
    """Invalid status values should be rejected by CHECK constraint."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO alerts (
                    detected_at, predicted_class, confidence, risk_score, risk_level,
                    status, dedup_key, first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    "DoS",
                    0.9,
                    80.0,
                    "High",
                    "InvalidStatus",  # Invalid!
                    "key_1",
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


def test_status_transition_history(temp_db):
    """Status transitions should be recorded in alert_history."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO alerts (
                detected_at, predicted_class, confidence, risk_score, risk_level,
                status, dedup_key, first_seen, last_seen
            ) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                "DoS",
                0.9,
                80.0,
                "High",
                "New",
                "key_1",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        alert_id = cur.lastrowid

    # Update status
    assert update_alert_status(alert_id, "Investigating", "Started investigation")
    assert update_alert_status(alert_id, "Resolved", "False positive")

    with get_conn() as conn:
        history = conn.execute(
            "SELECT * FROM alert_history WHERE alert_id = ? ORDER BY changed_at",
            (alert_id,),
        ).fetchall()

    assert len(history) == 2
    assert history[0]["old_status"] == "New"
    assert history[0]["new_status"] == "Investigating"
    assert history[1]["old_status"] == "Investigating"
    assert history[1]["new_status"] == "Resolved"


def test_bulk_update_status(temp_db):
    """Bulk status update should update multiple alerts."""
    from datetime import datetime, timezone

    alert_ids = []
    with get_conn() as conn:
        for i in range(3):
            cur = conn.execute(
                """INSERT INTO alerts (
                    detected_at, predicted_class, confidence, risk_score, risk_level,
                    status, dedup_key, first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    "DoS",
                    0.9,
                    80.0,
                    "High",
                    "New",
                    f"key_{i}",
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            alert_ids.append(cur.lastrowid)

    updated = bulk_update_status(alert_ids, "Investigating", "Bulk triage")
    assert updated == 3

    with get_conn() as conn:
        statuses = conn.execute(
            "SELECT status FROM alerts WHERE alert_id IN ({})".format(
                ",".join("?" * len(alert_ids))
            ),
            alert_ids,
        ).fetchall()

    assert all(s[0] == "Investigating" for s in statuses)


def test_csv_export_formula_injection(temp_db):
    """CSV export should neutralize formula injection."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts (
                detected_at, source_ip, predicted_class, confidence, risk_score, risk_level,
                status, dedup_key, first_seen, last_seen, analyst_notes
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                "=1+1",  # Formula injection attempt
                "DoS",
                0.9,
                80.0,
                "High",
                "New",
                "key_1",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
                "@SUM(A1:A10)",  # Another attempt
            ),
        )

    alerts = search_alerts()
    csv = export_alerts_csv(alerts)
    # Source IP should be prefixed with '
    assert "='=1+1" in csv or "'=1+1" in csv
    # Notes should be prefixed
    assert "'@SUM" in csv


def test_alert_counts(temp_db):
    """get_alert_counts should return correct aggregations."""
    from datetime import datetime, timezone

    with get_conn() as conn:
        for cls, level, status in [
            ("DoS", "Critical", "New"),
            ("DoS", "High", "Investigating"),
            ("PortScan", "Medium", "Resolved"),
        ]:
            conn.execute(
                """INSERT INTO alerts (
                    detected_at, predicted_class, confidence, risk_score, risk_level,
                    status, dedup_key, first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    cls,
                    0.9,
                    50.0,
                    level,
                    status,
                    f"key_{cls}_{level}",
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    counts = get_alert_counts()
    assert counts["by_class"]["DoS"] == 2
    assert counts["by_class"]["PortScan"] == 1
    assert counts["by_status"]["New"] == 1
    assert counts["by_status"]["Investigating"] == 1
    assert counts["by_status"]["Resolved"] == 1
    assert counts["by_risk"]["Critical"] == 1
    assert counts["by_risk"]["High"] == 1
    assert counts["by_risk"]["Medium"] == 1