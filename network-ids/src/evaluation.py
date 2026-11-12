"""Model evaluation: metrics, plots, and analysis."""
from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)
from sklearn.inspection import permutation_importance
import config


def compute_metrics(pipeline, X_test, y_test) -> dict[str, Any]:
    """Compute comprehensive metrics for a fitted pipeline."""
    t0 = time.perf_counter()
    y_pred = pipeline.predict(X_test)
    inference_ms = (time.perf_counter() - t0) * 1000 / len(X_test) * 1000  # ms per 1k flows

    # Probabilities for AUC
    try:
        y_proba = pipeline.predict_proba(X_test)
        has_proba = True
    except Exception:
        y_proba = None
        has_proba = False

    classes = sorted(pipeline.classes_)
    n_classes = len(classes)

    # Binary: Benign vs Malicious
    y_test_bin = (y_test != "Benign").astype(int)
    y_pred_bin = (y_pred != "Benign").astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "macro_precision": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "binary_fpr": float(
            confusion_matrix(y_test_bin, y_pred_bin, labels=[0, 1])[0, 1] /
            max(1, confusion_matrix(y_test_bin, y_pred_bin, labels=[0, 1])[0].sum())
        ),
        "binary_fnr": float(
            confusion_matrix(y_test_bin, y_pred_bin, labels=[0, 1])[1, 0] /
            max(1, confusion_matrix(y_test_bin, y_pred_bin, labels=[0, 1])[1].sum())
        ),
        "inference_ms_per_1k": float(inference_ms),
    }

    # AUC metrics (binary)
    if has_proba and n_classes == 2:
        benign_idx = list(classes).index("Benign")
        metrics["roc_auc"] = float(roc_auc_score(y_test_bin, y_proba[:, 1 - benign_idx]))
        metrics["pr_auc"] = float(average_precision_score(y_test_bin, y_proba[:, 1 - benign_idx]))
    elif has_proba and n_classes > 2:
        # Multi-class AUC (one-vs-rest)
        try:
            metrics["roc_auc_ovr"] = float(roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro"))
        except Exception:
            pass

    # Per-class metrics
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    metrics["per_class"] = {}
    for cls in classes:
        if cls in report:
            metrics["per_class"][cls] = {
                "precision": float(report[cls]["precision"]),
                "recall": float(report[cls]["recall"]),
                "f1": float(report[cls]["f1-score"]),
                "support": int(report[cls]["support"]),
            }

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    metrics["confusion_matrix"] = {
        "labels": classes,
        "matrix": cm.tolist(),
        "normalized": (cm.astype(float) / cm.sum(axis=1, keepdims=True)).tolist(),
    }

    return metrics


def confusion_matrix_figure(cm_data: dict, title: str = "Confusion Matrix"):
    """Create Plotly confusion matrix figure."""
    import plotly.graph_objects as go

    labels = cm_data["labels"]
    matrix = cm_data["matrix"]
    normalized = cm_data["normalized"]

    fig = go.Figure(data=go.Heatmap(
        z=normalized,
        x=labels,
        y=labels,
        colorscale="Blues",
        text=[[f"{matrix[i][j]} ({normalized[i][j]:.2%})" for j in range(len(labels))] for i in range(len(labels))],
        texttemplate="%{text}",
        textfont={"size": 10},
        hoverongaps=False,
    ))
    fig.update_layout(
        title=title,
        xaxis_title="Predicted",
        yaxis_title="Actual",
        width=600,
        height=500,
    )
    return fig


def per_class_table(metrics: dict) -> pd.DataFrame:
    """Create DataFrame from per-class metrics."""
    rows = []
    for cls, m in metrics.get("per_class", {}).items():
        rows.append({
            "Class": cls,
            "Precision": m["precision"],
            "Recall": m["recall"],
            "F1": m["f1"],
            "Support": m["support"],
        })
    return pd.DataFrame(rows)


def binary_error_analysis(pipeline, X_test, y_test, top_n: int = 10) -> dict:
    """Analyze false positives and false negatives."""
    y_pred = pipeline.predict(X_test)
    y_test_bin = (y_test != "Benign").astype(int)
    y_pred_bin = (y_pred != "Benign").astype(int)

    # False negatives: actual malicious, predicted benign
    fn_mask = (y_test_bin == 1) & (y_pred_bin == 0)
    fn_classes = y_test[fn_mask].value_counts().head(top_n).to_dict()

    # False positives: actual benign, predicted malicious
    fp_mask = (y_test_bin == 0) & (y_pred_bin == 1)
    fp_predicted = pd.Series(y_pred[fp_mask]).value_counts().head(top_n).to_dict()

    return {
        "false_negative_classes": fn_classes,
        "false_positive_predicted": fp_predicted,
    }


def permutation_importance_report(pipeline, X_test, y_test, n_repeats: int = 5, n_samples: int = 1000) -> dict:
    """Compute permutation importance on a test subsample."""
    # Subsample for speed
    if len(X_test) > n_samples:
        idx = np.random.default_rng(42).choice(len(X_test), n_samples, replace=False)
        X_sub = X_test.iloc[idx]
        y_sub = y_test.iloc[idx]
    else:
        X_sub, y_sub = X_test, y_test

    try:
        result = permutation_importance(
            pipeline, X_sub, y_sub,
            n_repeats=n_repeats,
            random_state=42,
            n_jobs=-1,
            scoring="f1_macro",
        )
        importances = result.importances_mean
        feature_names = getattr(pipeline, "feature_names_in_", [f"f{i}" for i in range(len(importances))])
        return dict(sorted(zip(feature_names, importances), key=lambda x: -x[1]))
    except Exception as e:
        return {"error": str(e)}


def save_metrics_json(
    results: dict,
    inspection: dict,
    path: Path = config.REPORT_DIR / "metrics.json",
    day_heldout: dict | None = None,
) -> None:
    """Save all metrics to JSON for dashboard consumption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    output: dict = {
        "models": results,
        "data_inspection": inspection,
    }
    if day_heldout:
        output["day_heldout"] = day_heldout
    path.write_text(json.dumps(output, indent=2, default=str))
    print(f"Metrics saved to {path}")


def load_metrics_json(path: Path = config.REPORT_DIR / "metrics.json") -> dict | None:
    """Load metrics from JSON."""
    if not path.exists():
        return None
    return json.loads(path.read_text())