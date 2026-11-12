"""Model Performance page: Comparison, confusion matrix, per-class metrics."""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import numpy as np
from pathlib import Path

import config
from src.evaluation import load_metrics_json, confusion_matrix_figure, per_class_table

st.set_page_config(page_title="Model Performance", layout="wide")
st.title("📊 Model Performance")

# Load metrics
metrics = load_metrics_json()

if not metrics:
    st.warning("No metrics found. Train a model first: `python -m src.train_model --data-dir data/raw --tune --with-anomaly`")
    st.stop()

models = metrics.get("models", {})
inspection = metrics.get("data_inspection", {})

# Model comparison table
st.subheader("🏆 Model Comparison")

comparison_rows = []
for name, m in models.items():
    comparison_rows.append({
        "Model": name,
        "Accuracy": f"{m.get('accuracy', 0):.4f}",
        "Balanced Acc": f"{m.get('balanced_accuracy', 0):.4f}",
        "Macro Precision": f"{m.get('macro_precision', 0):.4f}",
        "Macro Recall": f"{m.get('macro_recall', 0):.4f}",
        "Macro F1": f"{m.get('macro_f1', 0):.4f}",
        "Weighted F1": f"{m.get('weighted_f1', 0):.4f}",
        "PR-AUC (bin)": f"{m.get('pr_auc', 0):.4f}" if m.get('pr_auc') else "N/A",
        "FPR": f"{m.get('binary_fpr', 0):.4f}",
        "FNR": f"{m.get('binary_fnr', 0):.4f}",
        "Train Time (s)": f"{m.get('train_seconds', 0):.1f}",
        "Latency (ms/1k)": f"{m.get('inference_ms_per_1k', 0):.1f}",
    })

comp_df = pd.DataFrame(comparison_rows)
st.dataframe(comp_df, use_container_width=True, hide_index=True)

# Highlight best model
if models:
    best_name = max(models, key=lambda n: models[n].get("macro_f1", 0))
    best_metrics = models[best_name]
    st.success(f"🏆 Best model (by Macro F1): **{best_name}** — Macro F1: {best_metrics.get('macro_f1', 0):.4f}")

st.divider()

# Confusion Matrix
st.subheader("🔢 Confusion Matrix")

model_names = list(models.keys())
selected_model = st.selectbox("Select Model", model_names, key="cm_model")

if selected_model and selected_model in models:
    cm_data = models[selected_model].get("confusion_matrix")
    if cm_data:
        # Toggle for normalized
        normalize = st.checkbox("Show Normalized", value=False, key="cm_normalize")

        fig = confusion_matrix_figure(cm_data, title=f"Confusion Matrix: {selected_model}")
        if normalize:
            # Recreate with normalized values
            labels = cm_data["labels"]
            matrix = cm_data["normalized"]
            fig = go.Figure(data=go.Heatmap(
                z=matrix,
                x=labels,
                y=labels,
                colorscale="Blues",
                text=[[f"{matrix[i][j]:.2%}" for j in range(len(labels))] for i in range(len(labels))],
                texttemplate="%{text}",
                textfont={"size": 10},
            ))
            fig.update_layout(
                title=f"Confusion Matrix (Normalized): {selected_model}",
                xaxis_title="Predicted",
                yaxis_title="Actual",
                width=700,
                height=600,
            )
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# Per-Class Metrics
st.subheader("📋 Per-Class Metrics")

if selected_model and selected_model in models:
    class_df = per_class_table(models[selected_model])
    if not class_df.empty:
        st.dataframe(
            class_df.style.format({
                "Precision": "{:.4f}",
                "Recall": "{:.4f}",
                "F1": "{:.4f}",
            }),
            use_container_width=True,
            hide_index=True,
        )

        # Class distribution from inspection
        if inspection.get("raw_label_distribution"):
            st.write("**Training Class Distribution (Raw Labels)**")
            dist_df = pd.DataFrame(
                list(inspection["raw_label_distribution"].items()),
                columns=["Raw Label", "Count"]
            )
            st.dataframe(dist_df, use_container_width=True, hide_index=True)

st.divider()

# Evaluation A vs B (if available)
st.subheader("📈 Evaluation A vs B (Generalization)")

st.info("""
**Evaluation A (Standard):** Stratified 80/20 hold-out on full dataset.
**Evaluation B (Day-Held-Out):** Train on Mon–Thu, test on Fri (Bot, PortScan, DDoS).
Evaluation B measures generalization to unseen attack types and temporal drift.
""")

# Check if day-held-out metrics exist
if "day_heldout" in metrics:
    day_heldout = metrics["day_heldout"]
    st.write("**Day-Held-Out Results**")
    for model_name, m in day_heldout.items():
        with st.expander(f"{model_name}"):
            col1, col2, col3 = st.columns(3)
            col1.metric("Accuracy", f"{m.get('accuracy', 0):.4f}")
            col2.metric("Macro F1", f"{m.get('macro_f1', 0):.4f}")
            col3.metric("Weighted F1", f"{m.get('weighted_f1', 0):.4f}")

            # Unseen classes
            if "unseen_classes" in m:
                st.warning(f"⚠️ Unseen classes in test: {', '.join(m['unseen_classes'])}")
else:
    st.caption("Day-held-out evaluation not run. Add `--day-heldout` flag to training script to enable.")

st.divider()

# False Positive / False Negative Analysis
st.subheader("❌ Error Analysis")

if selected_model and selected_model in models:
    m = models[selected_model]

    # FN analysis
    if "false_negative_classes" in m:
        st.write("**Most Frequent False Negatives (Attack → Benign)**")
        fn_df = pd.DataFrame(
            list(m["false_negative_classes"].items()),
            columns=["Actual Class", "Count"]
        )
        st.dataframe(fn_df, use_container_width=True, hide_index=True)

    # FP analysis
    if "false_positive_predicted" in m:
        st.write("**Most Frequent False Positives (Benign → Attack)**")
        fp_df = pd.DataFrame(
            list(m["false_positive_predicted"].items()),
            columns=["Predicted Class", "Count"]
        )
        st.dataframe(fp_df, use_container_width=True, hide_index=True)

st.divider()

# Feature Importance
st.subheader("🎯 Feature Importance")

if selected_model and selected_model in models:
    m = models[selected_model]
    if "permutation_importance" in m and m["permutation_importance"]:
        imp = m["permutation_importance"]
        if isinstance(imp, dict) and "error" not in imp:
            # Top 20 features
            top_features = dict(list(imp.items())[:20])
            imp_df = pd.DataFrame(
                list(top_features.items()),
                columns=["Feature", "Importance"]
            )
            fig = px.bar(
                imp_df, x="Importance", y="Feature",
                orientation="h", title=f"Permutation Importance (Top 20) - {selected_model}",
            )
            fig.update_layout(height=600, yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption(f"Permutation importance unavailable: {imp.get('error', 'Unknown')}")
    else:
        st.caption("Permutation importance not computed. Re-run training with `--compute-importance`.")

st.divider()

# Class Imbalance Discussion
st.subheader("⚖️ Class Imbalance & Limitations")

st.markdown("""
**Class Imbalance in CIC-IDS2017:**
- Benign flows typically dominate (70-80% of dataset)
- Some attack classes have very few samples (Heartbleed, Infiltration, SQL Injection: < 50 samples)
- Accuracy is misleading; **macro-F1, per-class recall, and PR-AUC** are primary indicators

**Mitigations Applied:**
- Class weighting (`class_weight="balanced"` / `"balanced_subsample"`)
- Stratified train/test splits
- Per-class metric reporting
- No resampling of validation/test data

**Caveats:**
- Rare-class results have wide uncertainty; do not over-interpret
- CIC-IDS2017 was generated in a controlled lab; real-world traffic differs
- Flow correlations within attack sessions can inflate random-split performance (hence Evaluation B)
- Published high-accuracy claims on this dataset often involve leakage (see Engelen et al., 2021)
""")

# Why FN vs FP Matter
st.subheader("🎯 Why Errors Matter in Cybersecurity")

error_df = pd.DataFrame({
    "Error Type": ["False Negative (FN)", "False Positive (FP)"],
    "Meaning": [
        "Attack classified as benign",
        "Benign classified as attack"
    ],
    "Consequence": [
        "Missed intrusion; attacker retains access; typically costlier",
        "Alert fatigue, wasted analyst time, risk real alerts ignored, possible disruption if automated blocking"
    ],
})
st.table(error_df)