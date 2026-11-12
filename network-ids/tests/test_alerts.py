"""Tests for alert manager module."""
import pytest
from datetime import datetime, timedelta, timezone
import pandas as pd

from src.alert_manager import make_dedup_key, upsert_alert, create_alerts_from_results
from src.database import get_conn, init_db
import config


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database for testing."""
    original_db = config.DB_PATH
    config.DB_PATH = tmp_path / "test_alerts.db"
    init_db()
    yield
    config.DB_PATH = original_db


def test_make_dedup_key():
    """Test deduplication key generation."""
    row = {
        "source_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "predicted_class": "DoS",
    }
    key = make_dedup_key(row)
    assert len(key) == 40  # SHA1 hex length
    # Same inputs should produce same key
    assert make_dedup_key(row) == key

    # Different IP should produce different key
    row2 = row.copy()
    row2["source_ip"] = "192.168.1.2"
    assert make_dedup_key(row2) != key


def test_upsert_alert_creates_new(temp_db):
    """Test upsert_alert creates new alert when no duplicate."""
    row = {
        "predicted_class": "DoS",
        "confidence": 0.95,
        "anomaly_score": 0.8,
        "risk_score": 85.0,
        "risk_level": "Critical",
        "source_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "protocol": "TCP",
    }

    with get_conn() as conn:
        alert_id = upsert_alert(conn, row)

    assert alert_id == 1

    with get_conn() as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        assert alert["predicted_class"] == "DoS"
        assert alert["occurrence_count"] == 1
        assert alert["status"] == "New"


def test_upsert_alert_deduplicates_within_window(temp_db):
    """Test upsert_alert increments count for duplicate within window."""
    row = {
        "predicted_class": "DoS",
        "confidence": 0.95,
        "anomaly_score": 0.8,
        "risk_score": 85.0,
        "risk_level": "Critical",
        "source_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "protocol": "TCP",
    }

    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        # First insert
        id1 = upsert_alert(conn, row, now=now)
        # Second insert within window
        id2 = upsert_alert(conn, row, now=now + timedelta(seconds=100))

    assert id1 == id2  # Same alert ID

    with get_conn() as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (id1,)).fetchone()
        assert alert["occurrence_count"] == 2
        assert alert["risk_score"] == 85.0  # Max of both


def test_upsert_alert_no_dedup_outside_window(temp_db):
    """Test upsert_alert creates new alert when outside dedup window."""
    row = {
        "predicted_class": "DoS",
        "confidence": 0.95,
        "risk_score": 85.0,
        "risk_level": "Critical",
        "source_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "protocol": "TCP",
    }

    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        # First insert
        id1 = upsert_alert(conn, row, now=now)
        # Second insert OUTSIDE window (dedup window is 300 seconds default)
        id2 = upsert_alert(conn, row, now=now + timedelta(seconds=400))

    assert id1 != id2  # Different alert IDs


def test_upsert_alert_resolved_not_deduped(temp_db):
    """Resolved alerts should not be deduplicated against."""
    row = {
        "predicted_class": "DoS",
        "confidence": 0.95,
        "risk_score": 85.0,
        "risk_level": "Critical",
        "source_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "protocol": "TCP",
    }

    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        # First insert and resolve
        id1 = upsert_alert(conn, row, now=now)
        conn.execute("UPDATE alerts SET status = 'Resolved' WHERE alert_id = ?", (id1,))
        # Second insert within window but first is resolved
        id2 = upsert_alert(conn, row, now=now + timedelta(seconds=100))

    assert id1 != id2  # Should create new alert


def test_create_alerts_from_results(temp_db):
    """Test creating alerts from results DataFrame."""
    results = pd.DataFrame({
        "source_ip": ["192.168.1.1", "10.0.0.1", "192.168.1.2"],
        "dest_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "dest_port": [80, 22, 443],
        "protocol": ["TCP", "TCP", "TCP"],
        "predicted_class": ["DoS", "BruteForce", "PortScan"],
        "confidence": [0.95, 0.87, 0.92],
        "is_suspicious": [True, True, True],
        "anomaly_score": [0.8, 0.6, 0.7],
        "risk_score": [85.0, 65.0, 78.0],
        "risk_level": ["Critical", "High", "High"],
    })

    created, skipped = create_alerts_from_results(results, source_file="test.csv", min_risk=30, max_alerts=500)

    assert created == 3
    assert skipped == 0

    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert count == 3


def test_create_alerts_respects_min_risk(temp_db):
    """Alerts below min_risk should not be created."""
    results = pd.DataFrame({
        "source_ip": ["192.168.1.1", "10.0.0.1"],
        "dest_ip": ["10.0.0.1", "10.0.0.2"],
        "dest_port": [80, 22],
        "protocol": ["TCP", "TCP"],
        "predicted_class": ["PortScan", "PortScan"],
        "confidence": [0.6, 0.7],
        "is_suspicious": [True, True],
        "risk_score": [25.0, 35.0],  # First below min_risk (30), second above
        "risk_level": ["Low", "Medium"],
    })

    created, skipped = create_alerts_from_results(results, min_risk=30)

    assert created == 1
    assert skipped == 0  # Not skipped due to cap, just filtered out

    with get_conn() as conn:
        alert = conn.execute("SELECT predicted_class FROM alerts").fetchone()
        assert alert["predicted_class"] == "PortScan"  # Only the second one


def test_create_alerts_respects_batch_cap(temp_db):
    """Alert creation should respect MAX_ALERTS_PER_BATCH."""
    # Create more results than the cap
    n = config.MAX_ALERTS_PER_BATCH + 10
    results = pd.DataFrame({
        "source_ip": [f"192.168.1.{i}" for i in range(n)],
        "dest_ip": ["10.0.0.1"] * n,
        "dest_port": [80] * n,
        "protocol": ["TCP"] * n,
        "predicted_class": ["DoS"] * n,
        "confidence": [0.9] * n,
        "is_suspicious": [True] * n,
        "risk_score": [80.0] * n,
        "risk_level": ["High"] * n,
    })

    created, skipped = create_alerts_from_results(results, max_alerts=config.MAX_ALERTS_PER_BATCH)

    assert created == config.MAX_ALERTS_PER_BATCH
    assert skipped == 10


def test_alert_priority_highest_risk_first(temp_db):
    """When capped, highest risk alerts should be created first."""
    results = pd.DataFrame({
        "source_ip": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        "dest_ip": ["10.0.0.1"] * 3,
        "dest_port": [80, 80, 80],
        "protocol": ["TCP"] * 3,
        "predicted_class": ["DoS", "PortScan", "BruteForce"],
        "confidence": [0.9, 0.8, 0.7],
        "is_suspicious": [True, True, True],
        "risk_score": [85.0, 40.0, 60.0],  # Critical, Low, Medium
        "risk_level": ["Critical", "Low", "Medium"],
    })

    created, _ = create_alerts_from_results(results, max_alerts=2)

    assert created == 2
    with get_conn() as conn:
        alerts = conn.execute("SELECT risk_score FROM alerts ORDER BY risk_score DESC").fetchall()
    assert alerts[0]["risk_score"] == 85.0  # Critical first
    assert alerts[1]["risk_score"] == 60.0  # Medium second (not Low)