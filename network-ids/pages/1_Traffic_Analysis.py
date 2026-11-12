"""Traffic Analysis page: Upload CSV, validate, analyze, download results."""
import streamlit as st
import pandas as pd
import plotly.express as px
import io
from pathlib import Path

import config
from src.predict import IDSEngine, ArtifactsMissingError, ValidationError
from src.traffic_analysis import validate_upload, normalize_columns, analyze, summarize, get_column_template

st.set_page_config(page_title="Traffic Analysis", layout="wide")
st.title("📊 Network Traffic Analysis")

# Load engine
@st.cache_resource
def get_engine():
    return IDSEngine()

try:
    engine = get_engine()
except ArtifactsMissingError as e:
    st.warning(str(e))
    st.info("Train a model first: `python -m src.train_model --data-dir data/raw --tune --with-anomaly`")
    st.stop()

# Sidebar: Sample data button
if st.sidebar.button("📥 Use Bundled Sample Data", type="secondary"):
    if config.SAMPLE_PATH.exists():
        st.session_state["uploaded_file"] = str(config.SAMPLE_PATH)
        st.session_state["sample_mode"] = True
        st.rerun()
    else:
        st.sidebar.error("Sample data not found. Run `python scripts/make_sample.py --rows 2000`")

# File uploader
uploaded = st.file_uploader(
    "Upload network-flow CSV",
    type=["csv"],
    help=f"Max size: {config.MAX_UPLOAD_MB} MB. Must contain CIC-IDS2017 flow features.",
)

if uploaded:
    st.session_state["uploaded_file"] = uploaded
    st.session_state["sample_mode"] = False

# Process upload
if "uploaded_file" in st.session_state:
    file_obj = st.session_state["uploaded_file"]
    sample_mode = st.session_state.get("sample_mode", False)

    try:
        if sample_mode:
            df = pd.read_csv(file_obj)
        else:
            df = validate_upload(file_obj)
    except (ValidationError, ValueError, pd.errors.ParserError) as e:
        st.error(f"Upload rejected: {e}")
        st.stop()

    # Validation panel
    st.subheader("📋 File Validation")
    vcol1, vcol2, vcol3, vcol4 = st.columns(4)
    vcol1.metric("Rows", f"{len(df):,}")
    vcol2.metric("Columns", f"{df.shape[1]}")
    vcol3.metric("Size", f"{df.memory_usage(deep=True).sum() / 1024 / 1024:.1f} MB")

    # Column validation
    missing = [c for c in engine.expected_features if c not in df.columns]
    extra = [c for c in df.columns if c not in engine.expected_features]
    vcol4.metric("Missing Required", len(missing))

    if missing:
        st.error(f"❌ Missing required columns: {missing[:20]}{'...' if len(missing) > 20 else ''}")
        with st.expander("📋 Download Column Template"):
            template = get_column_template(engine)
            st.download_button(
                "Download Template CSV",
                template.to_csv(index=False),
                "ids_column_template.csv",
                "text/csv",
            )
    else:
        st.success("✅ All required columns present")

    if extra:
        st.warning(f"⚠️ Extra columns (will be ignored): {extra[:20]}{'...' if len(extra) > 20 else ''}")

    # Data quality summary
    with st.expander("🔍 Data Quality Summary", expanded=False):
        qcol1, qcol2 = st.columns(2)
        numeric_cols = df.select_dtypes(include=["number"]).columns
        qcol1.metric("Numeric Columns", len(numeric_cols))
        qcol2.metric("Non-Numeric Columns", len(df.columns) - len(numeric_cols))

        nan_counts = df.isna().sum()
        if nan_counts.any():
            st.write("**NaN counts:**")
            st.dataframe(nan_counts[nan_counts > 0].to_frame("NaN Count"), use_container_width=True)

        inf_counts = df[numeric_cols].map(lambda x: x == float('inf') or x == float('-inf')).sum()
        if inf_counts.any():
            st.write("**Infinity counts:**")
            st.dataframe(inf_counts[inf_counts > 0].to_frame("Inf Count"), use_container_width=True)

    # Preview
    st.subheader("👀 Data Preview (first 100 rows)")
    st.dataframe(df.head(100), use_container_width=True, hide_index=True)

    # Run analysis
    if st.button("🚀 Run Analysis", type="primary", disabled=len(df) == 0):
        with st.spinner("Scoring flows..."):
            results, summary = analyze(df, engine)
        st.session_state["results"] = results
        st.session_state["summary"] = summary
        st.session_state["source_file"] = file_obj.name if not sample_mode else "sample_flows.csv"
        st.success(f"✅ Analyzed {len(results):,} records")

# Display results
if "results" in st.session_state:
    results = st.session_state["results"]
    summary = st.session_state["summary"]

    st.divider()
    st.subheader("📈 Analysis Results")

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records", f"{summary['total_records']:,}")
    c2.metric("Benign", f"{summary['benign_count']:,}")
    c3.metric("Suspected Malicious", f"{summary['suspicious_count']:,}")
    c4.metric("Attack Rate", f"{summary['suspicious_count']/summary['total_records']*100:.1f}%")

    # Charts
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        if summary.get("attack_distribution"):
            fig = px.bar(
                x=list(summary["attack_distribution"].keys()),
                y=list(summary["attack_distribution"].values()),
                color=list(summary["attack_distribution"].keys()),
                title="Predicted Attack Classes",
            )
            fig.update_layout(showlegend=False, height=350)
            st.plotly_chart(fig, use_container_width=True)

    with chart_col2:
        if summary.get("risk_distribution"):
            risk_order = ["Critical", "High", "Medium", "Low"]
            risk_colors = {"Critical": "#F85149", "High": "#F0883E", "Medium": "#D29922", "Low": "#2EA043"}
            risk_data = {k: summary["risk_distribution"].get(k, 0) for k in risk_order}
            fig = px.bar(
                x=list(risk_data.keys()),
                y=list(risk_data.values()),
                color=list(risk_data.keys()),
                color_discrete_map=risk_colors,
                title="Risk Level Distribution",
            )
            fig.update_layout(showlegend=False, height=350)
            st.plotly_chart(fig, use_container_width=True)

    # Filters
    st.subheader("🔍 Filter Results")
    fcol1, fcol2, fcol3, fcol4 = st.columns(4)

    classes = ["All"] + sorted(results["predicted_class"].unique().tolist())
    fcol1.selectbox("Attack Class", classes, key="filter_class")

    risk_levels = ["All", "Critical", "High", "Medium", "Low"]
    fcol2.selectbox("Risk Level", risk_levels, key="filter_risk")

    min_conf = fcol3.slider("Min Confidence", 0.0, 1.0, 0.0, 0.05, key="filter_conf")

    search_text = fcol4.text_input("Search (IP, Port)", key="filter_search")

    # Apply filters
    filtered = results.copy()
    if st.session_state.get("filter_class", "All") != "All":
        filtered = filtered[filtered["predicted_class"] == st.session_state["filter_class"]]
    if st.session_state.get("filter_risk", "All") != "All":
        filtered = filtered[filtered["risk_level"] == st.session_state["filter_risk"]]
    filtered = filtered[filtered["confidence"] >= st.session_state.get("filter_conf", 0.0)]
    if st.session_state.get("filter_search"):
        search = st.session_state["filter_search"].lower()
        src_mask = filtered["source_ip"].astype(str).str.lower().str.contains(search, na=False) if "source_ip" in filtered.columns else pd.Series(False, index=filtered.index)
        dst_mask = filtered["dest_ip"].astype(str).str.lower().str.contains(search, na=False) if "dest_ip" in filtered.columns else pd.Series(False, index=filtered.index)
        port_mask = filtered["dest_port"].astype(str).str.contains(search, na=False) if "dest_port" in filtered.columns else pd.Series(False, index=filtered.index)
        filtered = filtered[src_mask | dst_mask | port_mask]

    st.caption(f"Showing {len(filtered):,} of {len(results):,} records")

    # Results table
    display_cols = [
        "detected_at", "source_ip", "dest_ip", "dest_port", "protocol",
        "predicted_class", "confidence", "risk_score", "risk_level", "anomaly_score"
    ]
    display_cols = [c for c in display_cols if c in filtered.columns]

    st.dataframe(
        filtered[display_cols].head(500),
        use_container_width=True,
        hide_index=True,
        column_config={
            "confidence": st.column_config.ProgressColumn("Confidence", format="%.2f", min_value=0, max_value=1),
            "risk_score": st.column_config.NumberColumn("Risk Score", format="%.1f"),
            "risk_level": st.column_config.TextColumn("Risk Level"),
        },
    )

    # Download buttons
    dcol1, dcol2 = st.columns(2)
    with dcol1:
        csv = filtered.to_csv(index=False)
        st.download_button(
            "📥 Download Filtered Results (CSV)",
            csv,
            f"ids_results_{st.session_state.get('source_file', 'analysis')}.csv",
            "text/csv",
        )
    with dcol2:
        if st.button("💾 Save Alerts to Database", type="secondary"):
            from src.alert_manager import create_alerts_from_results
            from src.database import get_conn
            import json

            # Get model version
            model_version = None
            meta_path = config.MODEL_DIR / "metadata.json"
            if meta_path.exists():
                model_version = json.loads(meta_path.read_text()).get("model")

            created, skipped = create_alerts_from_results(
                filtered,
                source_file=st.session_state.get("source_file", "upload"),
                model_version=model_version,
            )
            if created > 0:
                st.success(f"✅ Created {created} new alerts" + (f" ({skipped} skipped due to batch cap)" if skipped else ""))
            else:
                st.info("No new alerts created (all below threshold or duplicates)")