"""Security report generation (CSV, HTML, Markdown)."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

import config
from src.database import get_alert_counts, get_recent_runs


DISCLAIMER = """
**Disclaimer:** This report contains *suspected* malicious activity detected by a machine learning model.
Predictions are not confirmations of attacks. All detections require human analyst verification before
any response action. The model was trained on the CIC-IDS2017 dataset and may not generalize to all
network environments or novel attack techniques.
"""


def generate_csv_report(results: pd.DataFrame, path: Path) -> None:
    """Export results to CSV with formula-injection neutralization."""
    path.parent.mkdir(parents=True, exist_ok=True)
    df = results.copy()
    # Neutralize formula injection
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].apply(
            lambda x: f"'{x}" if isinstance(x, str) and x and x[0] in "=+-@" else x
        )
    df.to_csv(path, index=False)


def generate_html_report(
    results: pd.DataFrame,
    summary: dict,
    model_meta: dict | None = None,
    path: Path | None = None,
) -> str:
    """Generate HTML security report."""
    is_susp_col = results["is_suspicious"] if "is_suspicious" in results.columns else pd.Series([False] * len(results))
    suspicious = results[is_susp_col].copy()
    top_attacks = suspicious["predicted_class"].value_counts().head(10) if len(suspicious) > 0 else pd.Series()
    highest_risk = suspicious.nlargest(10, "risk_score") if len(suspicious) > 0 else pd.DataFrame()

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Network IDS Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0E1117; color: #E6EDF3; }}
        h1, h2, h3 {{ color: #2F81F7; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #30363D; padding: 8px; text-align: left; }}
        th {{ background: #161B22; }}
        tr:nth-child(even) {{ background: #161B22; }}
        .kpi {{ display: inline-block; background: #161B22; border: 1px solid #30363D; padding: 15px 25px; margin: 10px; border-radius: 6px; }}
        .kpi-value {{ font-size: 2em; font-weight: bold; color: #2F81F7; }}
        .kpi-label {{ color: #8B949E; }}
        .critical {{ color: #F85149; }}
        .high {{ color: #F0883E; }}
        .medium {{ color: #D29922; }}
        .low {{ color: #2EA043; }}
        .disclaimer {{ background: #21262D; border-left: 4px solid #D29922; padding: 15px; margin: 20px 0; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Network IDS Security Report</h1>
    <p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
    <p>Source: {summary.get('source_file', 'Unknown')}</p>

    <h2>Summary</h2>
    <div class="kpi"><div class="kpi-value">{summary.get('total_records', 0):,}</div><div class="kpi-label">Total Records</div></div>
    <div class="kpi"><div class="kpi-value">{summary.get('benign_count', 0):,}</div><div class="kpi-label">Benign</div></div>
    <div class="kpi"><div class="kpi-value">{summary.get('suspicious_count', 0):,}</div><div class="kpi-label">Suspected Malicious</div></div>

    <h2>Attack Distribution</h2>
    <table>
        <tr><th>Attack Class</th><th>Count</th></tr>
"""
    for cls, count in summary.get("attack_distribution", {}).items():
        risk_class = "low"
        if cls in ["Critical"]: risk_class = "critical"
        elif cls in ["High"]: risk_class = "high"
        elif cls in ["Medium"]: risk_class = "medium"
        html += f'        <tr><td class="{risk_class}">{cls}</td><td>{count}</td></tr>\n'

    html += """    </table>

    <h2>Risk Level Distribution</h2>
    <table>
        <tr><th>Risk Level</th><th>Count</th></tr>
"""
    for level, count in summary.get("risk_distribution", {}).items():
        html += f'        <tr><td class="{level.lower()}">{level}</td><td>{count}</td></tr>\n'

    html += """    </table>

    <h2>Top Suspected Attack Classes</h2>
    <table>
        <tr><th>Class</th><th>Count</th></tr>
"""
    for cls, count in top_attacks.items():
        html += f'        <tr><td>{cls}</td><td>{count}</td></tr>\n'

    html += """    </table>

    <h2>Highest Risk Detections</h2>
    <table>
        <tr><th>Time</th><th>Source IP</th><th>Dest IP:Port</th><th>Class</th><th>Confidence</th><th>Risk</th></tr>
"""
    if len(highest_risk) > 0:
        for _, row in highest_risk.iterrows():
            ts = row.get("detected_at", "")[:19]
            sip = row.get("source_ip", "N/A")
            dip = row.get("dest_ip", "N/A")
            dport = row.get("dest_port", "N/A")
            cls = row.get("predicted_class", "N/A")
            conf = f"{row.get('confidence', 0):.2%}"
            risk = row.get("risk_level", "N/A")
            html += f'        <tr><td>{ts}</td><td>{sip}</td><td>{dip}:{dport}</td><td>{cls}</td><td>{conf}</td><td class="{risk.lower()}">{risk}</td></tr>\n'

    html += """    </table>

    <h2>Model Information</h2>
"""
    if model_meta:
        html += f"""    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Model</td><td>{model_meta.get('model', 'Unknown')}</td></tr>
        <tr><td>Training Date</td><td>{model_meta.get('trained_at', 'Unknown')}</td></tr>
        <tr><td>Features</td><td>{len(model_meta.get('features', []))}</td></tr>
        <tr><td>Classes</td><td>{', '.join(model_meta.get('classes', []))}</td></tr>
        <tr><td>sklearn Version</td><td>{model_meta.get('sklearn_version', 'Unknown')}</td></tr>
    </table>
"""

    html += f"""
    <div class="disclaimer">{DISCLAIMER}</div>
</body>
</html>
"""
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
    return html


def generate_markdown_report(
    results: pd.DataFrame,
    summary: dict,
    model_meta: dict | None = None,
    path: Path | None = None,
) -> str:
    """Generate Markdown security report."""
    is_susp_col = results["is_suspicious"] if "is_suspicious" in results.columns else pd.Series([False] * len(results))
    suspicious = results[is_susp_col].copy()
    top_attacks = suspicious["predicted_class"].value_counts().head(10) if len(suspicious) > 0 else pd.Series()
    highest_risk = suspicious.nlargest(10, "risk_score") if len(suspicious) > 0 else pd.DataFrame()

    md = f"""# Network IDS Security Report

**Generated:** {datetime.now(timezone.utc).isoformat()}
**Source:** {summary.get('source_file', 'Unknown')}

## Summary

| Metric | Value |
|--------|-------|
| Total Records | {summary.get('total_records', 0):,} |
| Benign | {summary.get('benign_count', 0):,} |
| Suspected Malicious | {summary.get('suspicious_count', 0):,} |

## Attack Distribution

| Attack Class | Count |
|--------------|-------|
"""
    for cls, count in summary.get("attack_distribution", {}).items():
        md += f"| {cls} | {count} |\n"

    md += "\n## Risk Level Distribution\n\n| Risk Level | Count |\n|------------|-------|\n"
    for level, count in summary.get("risk_distribution", {}).items():
        md += f"| {level} | {count} |\n"

    md += "\n## Top Suspected Attack Classes\n\n| Class | Count |\n|-------|-------|\n"
    for cls, count in top_attacks.items():
        md += f"| {cls} | {count} |\n"

    md += "\n## Highest Risk Detections\n\n"
    if len(highest_risk) > 0:
        md += "| Time | Source IP | Dest IP:Port | Class | Confidence | Risk |\n|------|-----------|--------------|-------|------------|------|\n"
        for _, row in highest_risk.iterrows():
            ts = row.get("detected_at", "")[:19]
            sip = row.get("source_ip", "N/A")
            dip = row.get("dest_ip", "N/A")
            dport = row.get("dest_port", "N/A")
            cls = row.get("predicted_class", "N/A")
            conf = f"{row.get('confidence', 0):.2%}"
            risk = row.get("risk_level", "N/A")
            md += f"| {ts} | {sip} | {dip}:{dport} | {cls} | {conf} | {risk} |\n"
    else:
        md += "No suspicious detections.\n"

    if model_meta:
        md += f"""
## Model Information

| Property | Value |
|----------|-------|
| Model | {model_meta.get('model', 'Unknown')} |
| Training Date | {model_meta.get('trained_at', 'Unknown')} |
| Features | {len(model_meta.get('features', []))} |
| Classes | {', '.join(model_meta.get('classes', []))} |
| sklearn Version | {model_meta.get('sklearn_version', 'Unknown')} |
"""

    md += f"""

---
*{DISCLAIMER.strip()}*
"""
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md, encoding="utf-8")
    return md