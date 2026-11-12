"""Test fixtures for Network IDS tests."""
import numpy as np
import pandas as pd
import pytest

# Core feature names from CIC-IDS2017 (subset for testing)
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "PSH Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Protocol",
]

@pytest.fixture
def synthetic_flows():
    """Generate synthetic flow data with known issues for testing."""
    rng = np.random.default_rng(42)
    n = 600
    df = pd.DataFrame({c: rng.random(n) * 100 for c in FEATURES})
    # Protocol as categorical
    df["Protocol"] = rng.choice([6, 17, 1], size=n)  # TCP, UDP, ICMP
    # Labels with class imbalance
    df["Label"] = rng.choice(
        ["BENIGN", "DoS Hulk", "PortScan"],
        size=n,
        p=[0.7, 0.15, 0.15]
    )
    # Inject known data quality issues
    df.loc[0, "Flow Bytes/s"] = np.inf                      # positive infinity
    df.loc[1, "Flow Packets/s"] = -np.inf                   # negative infinity
    df.loc[2, "Flow Duration"] = np.nan                     # NaN
    # Cast to object dtype first to avoid pandas FutureWarning about incompatible dtypes
    df["SYN Flag Count"] = df["SYN Flag Count"].astype(object)
    df.loc[3, "SYN Flag Count"] = "not_a_number"            # string in numeric col
    # Add duplicate rows
    df = pd.concat([df, df.iloc[:5]], ignore_index=True)
    # Add duplicate column name
    df["Flow Duration.1"] = df["Flow Duration"]
    return df


@pytest.fixture
def minimal_flows():
    """Minimal valid flow DataFrame for testing."""
    return pd.DataFrame({
        "Flow Duration": [1000, 2000, 3000],
        "Total Fwd Packets": [10, 20, 30],
        "Total Backward Packets": [5, 10, 15],
        "Flow Bytes/s": [1000.0, 2000.0, 3000.0],
        "Flow Packets/s": [100.0, 200.0, 300.0],
        "SYN Flag Count": [1, 2, 1],
        "Protocol": [6, 6, 17],
        "Label": ["BENIGN", "DoS Hulk", "PortScan"],
    })


@pytest.fixture
def sample_results():
    """Sample prediction results for testing."""
    return pd.DataFrame({
        "source_ip": ["192.168.1.1", "10.0.0.1", "192.168.1.1"],
        "dest_ip": ["192.168.1.100", "10.0.0.50", "192.168.1.100"],
        "dest_port": [80, 22, 443],
        "protocol": ["TCP", "TCP", "TCP"],
        "predicted_class": ["DoS", "BruteForce", "DoS"],
        "confidence": [0.95, 0.87, 0.92],
        "is_suspicious": [True, True, True],
        "anomaly_score": [0.8, 0.6, 0.7],
        "risk_score": [85.0, 65.0, 78.0],
        "risk_level": ["Critical", "High", "High"],
        "detected_at": ["2024-01-01T12:00:00", "2024-01-01T12:01:00", "2024-01-01T12:02:00"],
    })