"""Threat Detection page: Suspicious records, drill-down, risk breakdown."""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import json
from pathlib import Path

import config
from src.predict import IDSEngine, ArtifactsMissingError
from src.database import search_alerts

st.set_page_config(page_title="Threat Detection", layout="wide")
st.title("🔍 Threat Detection")

# Warning banner
st.warning("⚠️ **Predictions indicate suspected malicious activity; they are not confirmation of an attack.** All detections require human analyst verification.")

# Load engine
@st.cache_resource
def get_engine():
    return IDSEngine()

try:
    engine = get_engine()
except ArtifactsMissingError as e:
    st.warning(str(e))
    st.stop()

# Load results from session or database
if "results" in st.session_state:
    results = st.session_state["results"]
    source = "Current Analysis"
else:
    # Load from alerts database
    alerts = search_alerts(limit=5000)
    if alerts:
        results = pd.DataFrame(alerts)
        source = "Alert Database"
    else:
        results = pd.DataFrame()
        source = None

if results.empty:
    st.info("No analysis results available. Run an analysis on the **Traffic Analysis** page or check the **Security Alerts** page.")
    st.stop()

st.caption(f"Data source: {source}")

# Filter to suspicious only
suspicious = results[results.get("is_suspicious", False)].copy()
if suspicious.empty:
    st.success("✅ No suspicious activity detected in current results.")
    st.stop()

# Sort by risk
suspicious = suspicious.sort_values("risk_score", ascending=False)

# KPIs
c1, c2, c3, c4 = st.columns(4)
c1.metric("Suspicious Records", f"{len(suspicious):,}")
c2.metric("Critical", f"{(suspicious['risk_level']=='Critical').sum():,}")
c3.metric("High", f"{(suspicious['risk_level']=='High').sum():,}")
c4.metric("Max Risk Score", f"{suspicious['risk_score'].max():.1f}")

# Tabs for different views
tab1, tab2, tab3, tab4 = st.tabs(["📋 Suspicious Records", "📊 Attack Timeline", "🎯 Risk Heatmap", "📈 Anomaly Distribution"])

with tab1:
    # Filter controls
    fcol1, fcol2, fcol3 = st.columns(3)
    classes = ["All"] + sorted(suspicious["predicted_class"].unique().tolist())
    fcol1.selectbox("Attack Class", classes, key="td_class")
    risk_levels = ["All", "Critical", "High", "Medium", "Low"]
    fcol2.selectbox("Risk Level", risk_levels, key="td_risk")
    fcol3.slider("Min Confidence", 0.0, 1.0, 0.0, 0.05, key="td_conf")

    # Apply filters
    filtered = suspicious.copy()
    if st.session_state.get("td_class", "All") != "All":
        filtered = filtered[filtered["predicted_class"] == st.session_state["td_class"]]
    if st.session_state.get("td_risk", "All") != "All":
        filtered = filtered[filtered["risk_level"] == st.session_state["td_risk"]]
    filtered = filtered[filtered["confidence"] >= st.session_state.get("td_conf", 0.0)]

    st.caption(f"Showing {len(filtered):,} of {len(suspicious):,} suspicious records")

    # Table with drill-down
    display_cols = [
        "detected_at", "source_ip", "dest_ip", "dest_port", "protocol",
        "predicted_class", "confidence", "risk_score", "risk_level", "anomaly_score"
    ]
    display_cols = [c for c in display_cols if c in filtered.columns]

    # Use selectbox for drill-down
    if len(filtered) > 0:
        # Create a selectable index
        options = filtered.index.tolist()
        option_labels = [
            f"{row['detected_at'][:19]} | {row.get('source_ip','?')}→{row.get('dest_ip','?')}:{row.get('dest_port','?')} | {row['predicted_class']} | {row['risk_level']} ({row['risk_score']:.1f})"
            for _, row in filtered.iterrows()
        ]
        selected_idx = st.selectbox(
            "Select record for drill-down",
            options=range(len(option_labels)),
            format_func=lambda i: option_labels[i] if i < len(option_labels) else "",
            key="drilldown_select"
        )

        if selected_idx is not None:
            record = filtered.iloc[selected_idx]
            st.divider()
            st.subheader("🔬 Record Drill-Down")

            dcol1, dcol2 = st.columns([1, 1])

            with dcol1:
                st.write("**Basic Info**")
                info_df = pd.DataFrame({
                    "Field": ["Timestamp", "Source IP", "Dest IP", "Dest Port", "Protocol", "Predicted Class"],
                    "Value": [
                        record.get("detected_at", "N/A")[:19],
                        record.get("source_ip", "N/A"),
                        record.get("dest_ip", "N/A"),
                        record.get("dest_port", "N/A"),
                        record.get("protocol", "N/A"),
                        record.get("predicted_class", "N/A"),
                    ]
                })
                st.dataframe(info_df, hide_index=True, use_container_width=True)

                st.write("**Scores**")
                score_df = pd.DataFrame({
                    "Metric": ["Confidence", "Risk Score", "Risk Level", "Anomaly Score"],
                    "Value": [
                        f"{record.get('confidence', 0):.2%}",
                        f"{record.get('risk_score', 0):.1f}",
                        record.get("risk_level", "N/A"),
                        f"{record.get('anomaly_score', 0):.3f}",
                    ]
                })
                st.dataframe(score_df, hide_index=True, use_container_width=True)

            with dcol2:
                # Probability distribution (if available in session or need to recompute)
                # For now, show risk breakdown
                st.write("**Risk Score Breakdown**")
                from src.risk import compute_risk
                from config import SEVERITY_BASE, ANOMALY_WEIGHT, ANOMALY_ONLY_CAP, RISK_LEVELS

                pred_class = record.get("predicted_class", "Benign")
                conf = record.get("confidence", 0)
                anomaly = record.get("anomaly_score", 0)

                if pred_class == "Benign":
                    bonus = ANOMALY_WEIGHT * anomaly
                    base_score = min(bonus, ANOMALY_ONLY_CAP)
                    breakdown = pd.DataFrame({
                        "Component": ["Anomaly Bonus", "Total"],
                        "Value": [bonus, base_score],
                    })
                else:
                    base = SEVERITY_BASE.get(pred_class, 50)
                    conf_factor = 0.5 + 0.5 * conf
                    severity_contrib = base * conf_factor
                    anomaly_bonus = ANOMALY_WEIGHT * anomaly
                    total = min(100, severity_contrib + anomaly_bonus)
                    breakdown = pd.DataFrame({
                        "Component": [f"Severity Base ({pred_class})", "Confidence Factor", "Severity × Confidence", "Anomaly Bonus", "Total (capped at 100)"],
                        "Value": [base, f"{conf_factor:.2f}", severity_contrib, anomaly_bonus, total],
                    })
                st.dataframe(breakdown, hide_index=True, use_container_width=True)

                # Probability bar chart (mock - would need model probas)
                st.write("**Class Probabilities** (estimated)")
                # We don't have actual probas here, show confidence as proxy
                prob_data = pd.DataFrame({
                    "Class": [pred_class, "Benign"],
                    "Probability": [conf, 1 - conf] if pred_class != "Benign" else [1 - conf, conf]
                })
                fig = px.bar(prob_data, x="Class", y="Probability", color="Class",
                            color_discrete_map={pred_class: "#F85149", "Benign": "#2EA043"})
                fig.update_layout(height=250, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)

    # Full table
    st.dataframe(
        filtered[display_cols].head(200),
        use_container_width=True,
        hide_index=True,
        column_config={
            "confidence": st.column_config.ProgressColumn("Confidence", format="%.2f", min_value=0, max_value=1),
            "risk_score": st.column_config.NumberColumn("Risk Score", format="%.1f"),
            "risk_level": st.column_config.TextColumn("Risk Level"),
        },
    )

with tab2:
    # Attack timeline
    if "detected_at" in suspicious.columns:
        try:
            suspicious["detected_dt"] = pd.to_datetime(suspicious["detected_at"], errors="coerce")
            valid = suspicious.dropna(subset=["detected_dt"])
            if len(valid) > 0:
                timeline = valid.groupby([valid["detected_dt"].dt.floor("min"), "predicted_class"]).size().reset_index(name="count")
                fig = px.line(timeline, x="detected_dt", y="count", color="predicted_class",
                             title="Attack Detections Over Time", markers=True)
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No valid timestamps for timeline")
        except Exception as e:
            st.info(f"Timeline unavailable: {e}")
    else:
        st.info("Timestamp data not available for timeline")

with tab3:
    # Risk heatmap: class vs risk level
    if len(suspicious) > 0:
        heatmap_data = suspicious.groupby(["predicted_class", "risk_level"]).size().reset_index(name="count")
        if len(heatmap_data) > 0:
            pivot = heatmap_data.pivot(index="predicted_class", columns="risk_level", values="count").fillna(0)
            # Reorder columns
            risk_order = ["Critical", "High", "Medium", "Low"]
            pivot = pivot.reindex(columns=[c for c in risk_order if c in pivot.columns])

            fig = px.imshow(
                pivot.values,
                x=pivot.columns,
                y=pivot.index,
                color_continuous_scale="Reds",
                title="Risk Level by Attack Class",
                labels=dict(x="Risk Level", y="Attack Class", color="Count"),
                text_auto=True,
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Insufficient data for heatmap")

with tab4:
    # Anomaly score histogram
    if "anomaly_score" in suspicious.columns:
        fig = px.histogram(
            suspicious, x="anomaly_score", color="risk_level",
            nbins=30, title="Anomaly Score Distribution",
            color_discrete_map={"Critical": "#F85149", "High": "#F0883E", "Medium": "#D29922", "Low": "#2EA043"},
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

    # Anomaly vs confidence scatter
    if "anomaly_score" in suspicious.columns and "confidence" in suspicious.columns:
        fig = px.scatter(
            suspicious, x="confidence", y="anomaly_score", color="risk_level",
            hover_data=["predicted_class", "source_ip", "dest_ip", "dest_port"],
            title="Confidence vs Anomaly Score",
            color_discrete_map={"Critical": "#F85149", "High": "#F0883E", "Medium": "#D29922", "Low": "#2EA043"},
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)