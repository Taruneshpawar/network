"""System Information page: Model details, dataset info, risk formula, limitations."""
import streamlit as st
import json
import pandas as pd
import sklearn
import numpy as np
import platform
import sys
from pathlib import Path

import config
from src.database import get_alert_counts, get_recent_runs

st.set_page_config(page_title="System Information", layout="wide")
st.title("ℹ️ System Information")

# Model Details
st.subheader("🤖 Model Details")

meta_path = config.MODEL_DIR / "metadata.json"
if meta_path.exists():
    meta = json.loads(meta_path.read_text())

    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Algorithm:** {meta.get('model', 'Unknown')}")
        st.write(f"**Training Date:** {meta.get('trained_at', 'Unknown')}")
        st.write(f"**Features:** {len(meta.get('features', []))}")
        st.write(f"**Classes:** {len(meta.get('classes', []))}")
        st.write(f"**Random Seed:** {meta.get('seed', 'Unknown')}")

    with col2:
        st.write(f"**Train Rows:** {meta.get('train_rows', 'N/A'):,}")
        st.write(f"**Test Rows:** {meta.get('test_rows', 'N/A'):,}")
        st.write(f"**Sample Fraction:** {meta.get('sample_frac', 1.0):.0%}")
        st.write(f"**Tuned:** {meta.get('tuned', False)}")
        st.write(f"**sklearn Version:** {meta.get('sklearn_version', 'Unknown')}")

    # Feature list
    with st.expander("📋 Feature List"):
        features = meta.get("features", [])
        numeric = meta.get("numeric_features", [])
        categorical = meta.get("categorical_features", [])
        st.write(f"**Numeric ({len(numeric)}):**")
        st.code(", ".join(numeric[:50]) + ("..." if len(numeric) > 50 else ""))
        st.write(f"**Categorical ({len(categorical)}):**")
        st.code(", ".join(categorical))

    # Class list
    with st.expander("🏷️ Class Labels"):
        classes = meta.get("classes", [])
        st.dataframe(pd.DataFrame({"Class": classes}), hide_index=True, use_container_width=True)

    # Dataset file hashes
    if meta.get("dataset_files"):
        with st.expander("🔐 Dataset File Hashes (SHA-256)"):
            for fname, fhash in meta["dataset_files"].items():
                st.code(f"{fname}: {fhash}")
else:
    st.warning("No trained model found. Run `python -m src.train_model --data-dir data/raw --tune --with-anomaly`")

st.divider()

# Dataset Information
st.subheader("📊 Dataset Information")

st.markdown("""
**Source:** CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB)
**URL:** https://www.unb.ca/cic/datasets/ids-2017.html
**Citation:** I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," *ICISSP*, 2018.

**Variant Used:** GeneratedLabelledFlows (with Flow ID, IPs, Ports, Protocol, Timestamp)
**Day Coverage:**
- Monday: Benign only
- Tuesday: FTP-Patator, SSH-Patator (BruteForce)
- Wednesday: DoS (Hulk, GoldenEye, slowloris, Slowhttptest), Heartbleed
- Thursday: Web Attacks (Brute Force, XSS, SQL Injection), Infiltration
- Friday: Bot, PortScan, DDoS

**Label Taxonomy (Raw → Family):**
""")

label_map_df = pd.DataFrame(list(config.LABEL_MAP.items()), columns=["Raw Label", "Attack Family"])
st.dataframe(label_map_df, hide_index=True, use_container_width=True)

st.markdown("""
**Binary Target:** Benign vs Malicious (derived from family)

**Known Data Quality Issues (handled automatically):**
- Leading/trailing spaces in column names → stripped
- `Infinity` / `-Infinity` in `Flow Bytes/s`, `Flow Packets/s` → replaced with NaN, median-imputed
- NaN values → median imputation (fit on train only)
- Duplicate rows → dropped
- Duplicate-named columns (e.g., `Fwd Header Length`) → second occurrence dropped
- Constant/zero-variance columns → removed by `VarianceThreshold`
- Negative values in non-negative fields (e.g., `Init_Win_bytes_forward` = -1) → kept as sentinel
- Identifier columns (Flow ID, IPs, ports, Timestamp) → excluded from model features
""")

st.divider()

# Risk Score Formula
st.subheader("⚠️ Risk Scoring Formula")

st.markdown("""
**Formula:**
```
severity_base   = SEVERITY_BASE[predicted_class]          # 0–100
conf_factor     = 0.5 + 0.5 * confidence                  # 0.5–1.0
anomaly_bonus   = ANOMALY_WEIGHT * anomaly_score          # 0–ANOMALY_WEIGHT

if predicted_class == "Benign":
    risk_score = min(anomaly_bonus * ANOMALY_ONLY_SCALE, ANOMALY_ONLY_CAP)
else:
    risk_score = min(100, severity_base * conf_factor + anomaly_bonus)
```

**Current Parameters:**
""")

risk_params = pd.DataFrame({
    "Parameter": ["ANOMALY_WEIGHT", "ANOMALY_ONLY_CAP", "ANOMALY_ONLY_SCALE"],
    "Value": [config.ANOMALY_WEIGHT, config.ANOMALY_ONLY_CAP, "1.0 (implicit)"],
})
st.dataframe(risk_params, hide_index=True, use_container_width=True)

st.write("**Severity Base per Class:**")
severity_df = pd.DataFrame(list(config.SEVERITY_BASE.items()), columns=["Attack Family", "Severity Base"])
st.dataframe(severity_df, hide_index=True, use_container_width=True)

st.write("**Risk Levels:**")
risk_levels_df = pd.DataFrame({
    "Level": ["Critical", "High", "Medium", "Low"],
    "Score Range": ["80–100", "55–79", "30–54", "0–29"],
    "Suggested Action": [
        "Immediate investigation",
        "Investigate promptly",
        "Review during triage",
        "Log only / monitor"
    ],
})
st.dataframe(risk_levels_df, hide_index=True, use_container_width=True)

st.markdown("> **Risk is a prioritization aid, not a measure of proven harm.**")

st.divider()

# Alert Settings
st.subheader("🔔 Alert Settings")

alert_params = pd.DataFrame({
    "Parameter": ["ALERT_MIN_RISK", "DEDUP_WINDOW_SECONDS", "MAX_ALERTS_PER_BATCH"],
    "Value": [config.ALERT_MIN_RISK, f"{config.DEDUP_WINDOW_SECONDS}s", config.MAX_ALERTS_PER_BATCH],
    "Description": [
        "Minimum risk score to create an alert",
        "Deduplication time window",
        "Max new alerts per batch analysis"
    ],
})
st.dataframe(alert_params, hide_index=True, use_container_width=True)

st.divider()

# Unsupported Attacks
st.subheader("🚫 Unsupported Attack Types")

st.markdown("""
The model **only recognizes attack families present in the CIC-IDS2017 training data**.
The following are **NOT** detected (non-exhaustive list):
- Modern ransomware variants
- Supply chain attacks
- Zero-day exploits not in CIC-IDS2017
- Encrypted payload-based attacks (only flow stats analyzed)
- DNS tunneling, domain generation algorithms
- Advanced persistent threat (APT) specific techniques
- IoT/OT protocol attacks
- Cloud-specific attacks

**Anomaly detector (Isolation Forest)** provides partial coverage for unseen attacks
by flagging statistically anomalous benign-classified flows as "Anomalous – Unclassified".
""")

st.divider()

# Limitations
st.subheader("⚠️ Limitations & Responsible Use")

st.markdown("""
**Technical Limitations:**
- Trained on one dataset from one lab environment; may not generalize
- Supervised model recognizes only attack families seen in training
- Encrypted traffic analyzed only through flow statistics
- Flow-feature compatibility depends on flow exporter (CICFlowMeter recommended)
- Batch/replay analysis only; **no automated prevention or blocking**
- Confidence scores from Random Forest are not calibrated probabilities
- SQLite suited for single-user/demo workloads, not multi-user production
- Rare classes have limited samples and unreliable metrics

**Ethical & Legal Requirements:**
- Use only on data you are authorized to analyze
- Analyze only networks you own or have **written permission** to monitor
- Unauthorized interception may violate computer-misuse/privacy laws
- Demonstrations must use CIC-IDS2017, synthetic data, or authorized lab traffic
- **No attack generation, exploitation, scanning, or evasion tooling** in this project
- Packet payloads are not stored; IP masking available for presentations
- Model outputs are **decision-support signals** — detections are *suspected*, not confirmed
- All alerts require human analyst verification before any response action
""")

st.divider()

# Environment Diagnostics
st.subheader("🔧 Environment Diagnostics")

diag_col1, diag_col2 = st.columns(2)

with diag_col1:
    st.write("**Python Environment**")
    env_df = pd.DataFrame({
        "Component": ["Python", "Platform", "NumPy", "Pandas", "scikit-learn", "Streamlit", "Plotly", "Joblib"],
        "Version": [
            sys.version.split()[0],
            platform.platform(),
            np.__version__,
            pd.__version__,
            sklearn.__version__,
            st.__version__,
            "5.19+",
            "1.3+",
        ],
    })
    st.dataframe(env_df, hide_index=True, use_container_width=True)

with diag_col2:
    st.write("**Paths & Status**")
    paths_df = pd.DataFrame({
        "Path": [
            "Data Dir", "Raw Data", "Sample Data", "Model Dir", "Report Dir", "DB Path"
        ],
        "Exists": [
            config.DATA_DIR.exists(),
            config.RAW_DIR.exists(),
            config.SAMPLE_PATH.exists(),
            config.MODEL_DIR.exists(),
            config.REPORT_DIR.exists(),
            config.DB_PATH.exists(),
        ],
        "Details": [
            str(config.DATA_DIR),
            str(config.RAW_DIR),
            str(config.SAMPLE_PATH),
            str(config.MODEL_DIR),
            str(config.REPORT_DIR),
            str(config.DB_PATH),
        ],
    })
    st.dataframe(paths_df, hide_index=True, use_container_width=True)

# Artifact status
st.write("**Model Artifacts**")
artifacts = {
    "ids_pipeline.joblib": config.MODEL_DIR / "ids_pipeline.joblib",
    "ids_binary_pipeline.joblib": config.MODEL_DIR / "ids_binary_pipeline.joblib",
    "anomaly_model.joblib": config.MODEL_DIR / "anomaly_model.joblib",
    "metadata.json": config.MODEL_DIR / "metadata.json",
}
for name, path in artifacts.items():
    exists = path.exists()
    size = f"{path.stat().st_size / 1024 / 1024:.1f} MB" if exists else "Missing"
    st.write(f"- **{name}**: {'✅' if exists else '❌'} ({size})")

# Recent runs
st.divider()
st.subheader("📜 Recent Analysis Runs")
runs = get_recent_runs(10)
if runs:
    runs_df = pd.DataFrame(runs)
    runs_df["run_at"] = pd.to_datetime(runs_df["run_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(runs_df[["run_id", "run_at", "source_file", "total_records", "benign_count", "suspicious_count"]],
                 hide_index=True, use_container_width=True)
else:
    st.caption("No analysis runs recorded yet.")