"""Alert creation, deduplication, and management."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import config
from src.database import get_conn


def make_dedup_key(row: dict) -> str:
    """Create deduplication key from flow identifiers."""
    parts = [
        str(row.get("source_ip", "")),
        str(row.get("dest_ip", "")),
        str(row.get("dest_port", "")),
        str(row.get("predicted_class", "")),
    ]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()


def upsert_alert(conn, row: dict, now: datetime | None = None) -> int:
    """Insert alert or update existing within dedup window. Returns alert_id."""
    now = now or datetime.now(timezone.utc)
    key = make_dedup_key(row)
    window_start = (now - timedelta(seconds=config.DEDUP_WINDOW_SECONDS)).isoformat()

    existing = conn.execute(
        "SELECT alert_id, risk_score FROM alerts "
        "WHERE dedup_key = ? AND status != 'Resolved' AND last_seen >= ?",
        (key, window_start),
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE alerts SET occurrence_count = occurrence_count + 1, last_seen = ?, "
            "risk_score = MAX(risk_score, ?) WHERE alert_id = ?",
            (now.isoformat(), row["risk_score"], existing["alert_id"]),
        )
        return existing["alert_id"]

    # Insert new alert
    features_json = row.get("features_json")
    if isinstance(features_json, dict):
        features_json = json.dumps(features_json)

    cur = conn.execute(
        """INSERT INTO alerts (
            detected_at, source_ip, dest_ip, dest_port, protocol,
            predicted_class, confidence, anomaly_score, risk_score, risk_level,
            status, dedup_key, first_seen, last_seen, features_json, model_version
        ) VALUES (?,?,?,?,?,?,?,?,?,?, 'New', ?,?,?,?,?)""",
        (
            now.isoformat(),
            row.get("source_ip"),
            row.get("dest_ip"),
            row.get("dest_port"),
            row.get("protocol"),
            row["predicted_class"],
            row["confidence"],
            row.get("anomaly_score", 0.0),
            row["risk_score"],
            row["risk_level"],
            key,
            now.isoformat(),
            now.isoformat(),
            features_json,
            row.get("model_version"),
        ),
    )
    return cur.lastrowid


def create_alerts_from_results(
    results_df,
    source_file: str = "upload",
    model_version: str | None = None,
    min_risk: float = config.ALERT_MIN_RISK,
    max_alerts: int = config.MAX_ALERTS_PER_BATCH,
) -> tuple[int, int]:
    """Create alerts from analysis results DataFrame.
    Returns (alerts_created, alerts_skipped_due_to_cap)."""
    # Filter eligible rows
    suspicious = results_df[results_df["is_suspicious"]].copy()
    # Also include benign but highly anomalous
    if "anomaly_score" in results_df.columns:
        # We'd need anomaly threshold from anomaly_detection; for now use risk threshold
        pass

    eligible = suspicious[suspicious["risk_score"] >= min_risk].copy()
    # Sort by risk descending to prioritize high-risk alerts
    eligible = eligible.sort_values("risk_score", ascending=False)

    created = 0
    with get_conn() as conn:
        for _, row in eligible.iterrows():
            if created >= max_alerts:
                break
            alert_row = row.to_dict()
            alert_row["source_file"] = source_file
            alert_row["model_version"] = model_version
            # Add key features for context (limit size)
            feature_cols = [c for c in row.index if c not in
                ["predicted_class", "confidence", "is_suspicious", "anomaly_score",
                 "risk_score", "risk_level", "detected_at", "source_ip", "dest_ip",
                 "dest_port", "protocol", "source_port", "flow_timestamp"]]
            alert_row["features_json"] = {c: float(row[c]) for c in feature_cols[:10]}
            upsert_alert(conn, alert_row)
            created += 1

    skipped = len(eligible) - created
    return created, max(0, skipped)


def get_alert_summary() -> dict[str, Any]:
    """Get summary statistics for the alerts dashboard."""
    from src.database import get_alert_counts
    counts = get_alert_counts()
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status != 'Resolved'").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE risk_level = 'Critical'").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM alerts WHERE risk_level = 'High'").fetchone()[0]
    return {
        "total_alerts": total,
        "open_alerts": open_alerts,
        "critical_alerts": critical,
        "high_alerts": high,
        "by_status": counts["by_status"],
        "by_risk": counts["by_risk"],
        "by_class": counts["by_class"],
    }