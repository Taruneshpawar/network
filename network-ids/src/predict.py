"""Inference engine: loads saved artifacts, never fits."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import config
import sklearn
from src import preprocessing, risk


class ArtifactsMissingError(RuntimeError):
    """Raised when model artifacts are not found."""
    pass


class ValidationError(ValueError):
    """Raised when input validation fails."""
    pass


@dataclass
class ValidationResult:
    ok: bool
    missing: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)


class IDSEngine:
    """Main inference engine for the IDS."""

    def __init__(self, model_dir: Path = config.MODEL_DIR):
        model_path = model_dir / "ids_pipeline.joblib"
        meta_path = model_dir / "metadata.json"
        binary_path = model_dir / "ids_binary_pipeline.joblib"

        if not model_path.exists() or not meta_path.exists():
            raise ArtifactsMissingError(
                "Model artifacts not found. Train first: python -m src.train_model"
            )

        self.pipeline = joblib.load(model_path)  # only ever load our own artifacts
        self.meta = json.loads(meta_path.read_text())

        # Check sklearn version compatibility
        saved_version = self.meta.get("sklearn_version", "0.0")
        current_version = sklearn.__version__
        if saved_version.split(".")[0] != current_version.split(".")[0] or \
           saved_version.split(".")[1] != current_version.split(".")[1]:
            import warnings
            warnings.warn(
                f"scikit-learn version mismatch: trained with {saved_version}, "
                f"running with {current_version}. Consider retraining.",
                UserWarning,
            )

        # Load binary model if available
        self.binary_pipeline = None
        if binary_path.exists():
            self.binary_pipeline = joblib.load(binary_path)

        # Load anomaly detector
        self.anomaly = None
        anomaly_path = model_dir / "anomaly_model.joblib"
        if anomaly_path.exists():
            from src.anomaly_detection import AnomalyDetector
            self.anomaly = AnomalyDetector.load(anomaly_path)

    @property
    def expected_features(self) -> list[str]:
        return list(self.meta.get("features", []))

    @property
    def classes(self) -> list[str]:
        return list(self.meta.get("classes", []))

    def validate_columns(self, df: pd.DataFrame) -> ValidationResult:
        """Check if DataFrame has required columns."""
        cols = set(df.columns)
        missing = [c for c in self.expected_features if c not in cols]
        extra = [c for c in df.columns if c not in set(self.expected_features)]
        return ValidationResult(ok=not missing, missing=missing, extra=extra)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Run full prediction pipeline on a DataFrame."""
        df = preprocessing.clean_columns(df)
        v = self.validate_columns(df)
        if not v.ok:
            raise ValidationError(
                f"Missing required columns: {v.missing[:15]}"
                f"{' ...' if len(v.missing) > 15 else ''}"
            )

        # Select and coerce features
        X = df[self.expected_features].apply(pd.to_numeric, errors="coerce")
        out = df.copy()

        if X.empty:
            return out.assign(
                predicted_class=pd.Series(dtype=object),
                confidence=pd.Series(dtype=float),
                is_suspicious=pd.Series(dtype=bool),
                anomaly_score=pd.Series(dtype=float),
                risk_score=pd.Series(dtype=float),
                risk_level=pd.Series(dtype=object),
                detected_at=pd.Series(dtype=object),
            )

        # Multi-class prediction
        proba = self.pipeline.predict_proba(X)
        classes = self.pipeline.classes_
        pred_idx = proba.argmax(axis=1)
        out["predicted_class"] = [classes[i] for i in pred_idx]
        out["confidence"] = proba.max(axis=1)
        out["is_suspicious"] = out["predicted_class"] != "Benign"

        # Anomaly score
        if self.anomaly:
            out["anomaly_score"] = self.anomaly.score(X)
        else:
            out["anomaly_score"] = 0.0

        # Risk scoring
        out["risk_score"] = [
            risk.compute_risk(c, p, a)
            for c, p, a in zip(out["predicted_class"], out["confidence"], out["anomaly_score"])
        ]
        out["risk_level"] = out["risk_score"].map(risk.risk_level)
        out["detected_at"] = datetime.now(timezone.utc).isoformat()

        return out

    def predict_binary(self, df: pd.DataFrame) -> pd.DataFrame:
        """Run binary prediction (Benign vs Malicious) if binary model available."""
        if self.binary_pipeline is None:
            # Derive from multi-class
            results = self.predict(df)
            results["binary_predicted"] = results["predicted_class"].apply(
                lambda x: "Malicious" if x != "Benign" else "Benign"
            )
            return results
        # Use dedicated binary model
        df = preprocessing.clean_columns(df)
        X = df[self.expected_features].apply(pd.to_numeric, errors="coerce")
        out = df.copy()
        proba = self.binary_pipeline.predict_proba(X)
        classes = self.binary_pipeline.classes_
        pred_idx = proba.argmax(axis=1)
        out["binary_predicted"] = [classes[i] for i in pred_idx]
        out["binary_confidence"] = proba.max(axis=1)
        return out

    def predict_chunked(self, df: pd.DataFrame, chunk_size: int = config.PREDICT_CHUNK_SIZE) -> pd.DataFrame:
        """Predict in chunks for large DataFrames."""
        if len(df) <= chunk_size:
            return self.predict(df)

        results = []
        for i in range(0, len(df), chunk_size):
            chunk = df.iloc[i:i + chunk_size]
            results.append(self.predict(chunk))
        return pd.concat(results, ignore_index=True)