"""Isolation Forest anomaly detection trained on benign flows only."""
from __future__ import annotations
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import config
from src.preprocessing import build_preprocessor, get_feature_columns, clean_columns


class AnomalyDetector:
    """Isolation Forest wrapper with its own preprocessing pipeline."""

    def __init__(self, contamination: float = 0.01, n_estimators: int = 200, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.pipeline: Pipeline | None = None
        self.threshold_: float | None = None  # anomaly score threshold (benign 99th percentile)
        self.feature_names_: list[str] | None = None

    def fit(self, benign_df: pd.DataFrame) -> "AnomalyDetector":
        """Train on benign-only flows."""
        df = clean_columns(benign_df)
        numeric_cols, categorical_cols = get_feature_columns(df)
        self.feature_names_ = numeric_cols + categorical_cols

        X = df[self.feature_names_].apply(pd.to_numeric, errors="coerce")

        # Build pipeline: impute + scale + isolation forest
        preprocessor = build_preprocessor(numeric_cols, categorical_cols)
        iso_forest = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.pipeline = Pipeline([
            ("prep", preprocessor),
            ("iso", iso_forest),
        ])
        self.pipeline.fit(X)

        # Compute threshold from benign validation scores (99th percentile)
        # Use decision_function: higher = more normal, lower = more anomalous
        scores = self.pipeline.decision_function(X)
        # Convert to 0-1 anomaly score where 1 = most anomalous
        # IsolationForest decision_function: positive = normal, negative = anomaly
        # We normalize to 0-1 range based on training distribution
        self.threshold_ = float(np.percentile(-scores, 99))  # 99th percentile of anomaly scores
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Return normalized anomaly score 0-1 (higher = more anomalous)."""
        if self.pipeline is None:
            raise RuntimeError("AnomalyDetector not fitted")
        df = clean_columns(df)
        X = df[self.feature_names_].apply(pd.to_numeric, errors="coerce")
        # decision_function: higher = more normal
        raw_scores = self.pipeline.decision_function(X)
        # Normalize: map to 0-1 where 1 = most anomalous
        # Using sigmoid-like transformation centered at threshold
        anomaly_scores = 1 / (1 + np.exp(raw_scores / max(self.threshold_, 1e-6)))
        return np.clip(anomaly_scores, 0.0, 1.0)

    def flag(self, df: pd.DataFrame, threshold: float | None = None) -> np.ndarray:
        """Return boolean array: True if anomalous."""
        scores = self.score(df)
        thresh = threshold if threshold is not None else 0.5
        return scores >= thresh

    def save(self, path: Path) -> None:
        """Save model and metadata."""
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, path)
        # Save metadata separately
        meta_path = path.with_suffix(".json")
        meta = {
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "threshold": self.threshold_,
            "feature_names": self.feature_names_,
        }
        meta_path.write_text(json.dumps(meta, indent=2))

    @classmethod
    def load(cls, path: Path) -> "AnomalyDetector":
        """Load model from disk."""
        meta_path = path.with_suffix(".json")
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
        else:
            meta = {}
        detector = cls(
            contamination=meta.get("contamination", 0.01),
            n_estimators=meta.get("n_estimators", 200),
            random_state=meta.get("random_state", 42),
        )
        detector.pipeline = joblib.load(path)
        detector.threshold_ = meta.get("threshold")
        detector.feature_names_ = meta.get("feature_names")
        return detector


def train_anomaly_detector(
    train_df: pd.DataFrame,
    contamination: float = 0.01,
    n_estimators: int = 200,
    random_state: int = 42,
) -> AnomalyDetector:
    """Train Isolation Forest on benign training flows."""
    benign_df = train_df[train_df["family"] == "Benign"].copy()
    print(f"Training Isolation Forest on {len(benign_df):,} benign flows...")
    detector = AnomalyDetector(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_state,
    )
    detector.fit(benign_df)
    return detector