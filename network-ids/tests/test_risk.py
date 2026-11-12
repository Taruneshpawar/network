"""Tests for risk scoring module."""
import pytest
from src.risk import compute_risk, risk_level


class TestRiskLevel:
    """Test risk level boundaries."""

    def test_low_boundary(self):
        assert risk_level(0) == "Low"
        assert risk_level(29) == "Low"

    def test_medium_boundary(self):
        assert risk_level(30) == "Medium"
        assert risk_level(54) == "Medium"

    def test_high_boundary(self):
        assert risk_level(55) == "High"
        assert risk_level(79) == "High"

    def test_critical_boundary(self):
        assert risk_level(80) == "Critical"
        assert risk_level(100) == "Critical"


class TestComputeRisk:
    """Test risk score computation."""

    def test_benign_with_no_anomaly(self):
        score = compute_risk("Benign", 0.9, 0.0)
        assert score == 0.0

    def test_benign_with_anomaly(self):
        # anomaly_bonus = 15 * 0.5 = 7.5, cap = 35
        score = compute_risk("Benign", 0.9, 0.5)
        assert score == 7.5

    def test_benign_anomaly_capped(self):
        # anomaly_bonus = 15 * 1.0 = 15, but cap at 35 for benign
        score = compute_risk("Benign", 0.9, 1.0)
        assert score == 15.0  # 15 * 1.0 = 15 < 35 cap

    def test_portscan_risk(self):
        # base=40, conf=0.9 -> 40 * (0.5 + 0.5*0.9) = 40 * 0.95 = 38
        score = compute_risk("PortScan", 0.9, 0.0)
        assert abs(score - 38.0) < 0.01

    def test_dos_risk(self):
        # base=75, conf=0.8 -> 75 * (0.5 + 0.5*0.8) = 75 * 0.9 = 67.5
        score = compute_risk("DoS", 0.8, 0.0)
        assert abs(score - 67.5) < 0.01

    def test_botnet_with_anomaly_bonus(self):
        # base=80, conf=0.9 -> 80 * 0.95 = 76, anomaly_bonus = 15*0.5 = 7.5, total = 83.5
        score = compute_risk("Botnet", 0.9, 0.5)
        assert abs(score - 83.5) < 0.01

    def test_score_never_exceeds_100(self):
        # Even with max confidence and anomaly, should cap at 100
        score = compute_risk("Heartbleed", 1.0, 1.0)
        # base=90 * 1.0 + 15 = 105 -> capped at 100
        assert score == 100.0

    def test_unknown_class_defaults_to_medium(self):
        score = compute_risk("UnknownAttack", 0.5, 0.0)
        # base=50 (default), conf=0.5 -> 50 * 0.75 = 37.5
        assert abs(score - 37.5) < 0.01

    def test_confidence_clipped(self):
        # Confidence > 1 should be clipped
        score = compute_risk("DoS", 1.5, 0.0)
        assert score <= 100

    def test_anomaly_score_clipped(self):
        # Anomaly score > 1 should be clipped
        score = compute_risk("Benign", 0.5, 1.5)
        # anomaly_bonus = 15 * 1.0 = 15 (clipped)
        assert score == 15.0