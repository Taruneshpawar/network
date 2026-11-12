"""Streamlit entry point: Overview Dashboard."""
import streamlit as st
import pandas as pd
import plotly.express as px
import json
from pathlib import Path

import config
from src.database import get_alert_counts, get_recent_runs, init_db
from src.predict import IDSEngine, ArtifactsMissingError

# Page config
st.set_page_config(
    page_title="Network IDS - Overview",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize DB
init_db()

# Sidebar
st.sidebar.title("🛡️ Network IDS")
st.sidebar.caption("AI-Powered Intrusion Detection System")

# Load model metadata if available
model_meta = None
meta_path = config.MODEL_DIR / "metadata.json"
if meta_path.exists():
    model_meta = json.loads(meta_path.read_text())

# KPI Row
st.title("Overview Dashboard")

# Get alert counts
counts = get_alert_counts()

col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1:
    total_alerts = sum(counts["by_status"].values())
    st.metric("Total Alerts", f"{total_alerts:,}")
with col2:
    open_alerts = counts["by_status"].get("New", 0) + counts["by_status"].get("Investigating", 0)
    st.metric("Open Alerts", f"{open_alerts:,}")
with col3:
    critical = counts["by_risk"].get("Critical", 0)
    st.metric("Critical", f"{critical:,}", delta_color="inverse")
with col4:
    high = counts["by_risk"].get("High", 0)
    st.metric("High", f"{high:,}", delta_color="inverse")
with col5:
    recent_runs = get_recent_runs(1)
    total_records = recent_runs[0]["total_records"] if recent_runs else 0
    st.metric("Last Run Records", f"{total_records:,}")
with col6:
    if model_meta:
        st.metric("Model", model_meta.get("model", "Unknown"))
    else:
        st.metric("Model", "Not Trained")

st.divider()

# Charts row
if total_alerts > 0:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Attack Distribution")
        if counts["by_class"]:
            fig = px.pie(
                values=list(counts["by_class"].values()),
                names=list(counts["by_class"].keys()),
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Set3,
            )
            fig.update_layout(height=350, margin=dict(t=30, b=0, l=0, r=0))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack class data available")

    with chart_col2:
        st.subheader("Risk Level Distribution")
        risk_order = ["Critical", "High", "Medium", "Low"]
        risk_colors = {"Critical": "#F85149", "High": "#F0883E", "Medium": "#D29922", "Low": "#2EA043"}
        risk_data = {k: counts["by_risk"].get(k, 0) for k in risk_order}
        fig = px.bar(
            x=list(risk_data.keys()),
            y=list(risk_data.values()),
            color=list(risk_data.keys()),
            color_discrete_map=risk_colors,
        )
        fig.update_layout(height=350, margin=dict(t=30, b=0, l=0, r=0), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    # Recent alerts table
    st.subheader("Recent Security Alerts")
    from src.database import search_alerts
    recent = search_alerts(limit=10)
    if recent:
        df = pd.DataFrame(recent)
        # Format for display
        display_df = df[["alert_id", "detected_at", "source_ip", "dest_ip", "dest_port",
                         "predicted_class", "risk_level", "status", "occurrence_count"]].copy()
        display_df["detected_at"] = pd.to_datetime(display_df["detected_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "risk_level": st.column_config.TextColumn("Risk", help="Risk level"),
                "occurrence_count": st.column_config.NumberColumn("Occurrences", help="Deduplicated count"),
            },
        )
    else:
        st.info("No alerts yet. Analyze traffic on the **Traffic Analysis** page.")
else:
    # Empty state
    st.info("👋 Welcome! No data analyzed yet.")
    st.markdown("""
    **Get started:**
    1. **Train a model**: Run `python -m src.train_model --data-dir data/raw --tune --with-anomaly`
    2. **Analyze traffic**: Go to the **Traffic Analysis** page and upload a CSV
    3. **View alerts**: Suspected threats appear here and on the **Security Alerts** page

    **Need sample data?** Run `python scripts/make_sample.py --rows 2000` to create a demo dataset.
    """)

# Model snapshot
if model_meta:
    st.divider()
    st.subheader("Model Snapshot")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.write(f"**Algorithm:** {model_meta.get('model', 'Unknown')}")
        st.write(f"**Training Date:** {model_meta.get('trained_at', 'Unknown')[:10]}")
    with col2:
        st.write(f"**Features:** {len(model_meta.get('features', []))}")
        st.write(f"**Classes:** {', '.join(model_meta.get('classes', []))}")
    with col3:
        st.write(f"**Train Rows:** {model_meta.get('train_rows', 'N/A'):,}")
        st.write(f"**Test Rows:** {model_meta.get('test_rows', 'N/A'):,}")

# Load metrics for performance summary
metrics_path = config.REPORT_DIR / "metrics.json"
if metrics_path.exists():
    metrics = json.loads(metrics_path.read_text())
    best_model = model_meta.get("model")
    if best_model and best_model in metrics.get("models", {}):
        m = metrics["models"][best_model]
        st.divider()
        st.subheader("Model Performance (Held-Out Test Set)")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Accuracy", f"{m.get('accuracy', 0):.2%}")
        c2.metric("Balanced Acc", f"{m.get('balanced_accuracy', 0):.2%}")
        c3.metric("Macro F1", f"{m.get('macro_f1', 0):.2%}")
        c4.metric("Weighted F1", f"{m.get('weighted_f1', 0):.2%}")

# Sidebar filters (for consistency across pages)
st.sidebar.divider()
st.sidebar.subheader("Global Filters")
# These would be used by other pages via session_state
if "global_filters" not in st.session_state:
    st.session_state["global_filters"] = {}

# Filter inputs (stored but not applied on this page)
date_range = st.sidebar.date_input("Date Range", value=[])
min_risk = st.sidebar.select_slider(
    "Minimum Risk",
    options=["Low", "Medium", "High", "Critical"],
    value="Low",
)
attack_classes = st.sidebar.multiselect(
    "Attack Classes",
    options=list(counts["by_class"].keys()) if counts["by_class"] else [],
    default=[],
)

st.session_state["global_filters"] = {
    "date_range": date_range,
    "min_risk": min_risk,
    "attack_classes": attack_classes,
}