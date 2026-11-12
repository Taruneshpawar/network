"""Pure, testable risk scoring functions."""
from __future__ import annotations
import numpy as np
import config


def risk_level(score: float) -> str:
    """Map risk score to level."""
    for threshold, name in config.RISK_LEVELS:
        if score >= threshold:
            return name
    return "Low"


def compute_risk(predicted_class: str, confidence: float, anomaly_score: float = 0.0) -> float:
    """Compute risk score per Section 10 formula."""
    confidence = float(np.clip(confidence, 0.0, 1.0))
    anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))
    bonus = config.ANOMALY_WEIGHT * anomaly_score

    if predicted_class == "Benign":
        return float(min(bonus, config.ANOMALY_ONLY_CAP))

    base = config.SEVERITY_BASE.get(predicted_class, 50)  # unknown class -> medium default
    return float(min(100.0, base * (0.5 + 0.5 * confidence) + bonus))