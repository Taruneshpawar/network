"""Central configuration for the Network IDS."""
from __future__ import annotations
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
SAMPLE_PATH = DATA_DIR / "sample" / "sample_flows.csv"
MODEL_DIR = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = Path(os.getenv("IDS_DB_PATH", DATA_DIR / "alerts.db"))
LOG_PATH = BASE_DIR / "reports" / "ids.log"

RANDOM_SEED = 42
TEST_SIZE = 0.20
CV_FOLDS = 5

# --- Upload limits ---
MAX_UPLOAD_MB = int(os.getenv("IDS_MAX_UPLOAD_MB", "200"))
MAX_ROWS = 2_000_000
ALLOWED_EXTENSIONS = {".csv"}
PREDICT_CHUNK_SIZE = 50_000

# --- Label taxonomy: raw label -> family ---
LABEL_MAP = {
    "BENIGN": "Benign",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Bot": "Botnet",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}

# Identifier / time columns never used as model features
FEATURE_EXCLUDE = {
    "Flow ID", "Source IP", "Src IP", "Destination IP", "Dst IP",
    "Source Port", "Src Port", "Timestamp", "Label", "family", "source_file",
}

# --- Risk scoring (see Section 10) ---
SEVERITY_BASE = {
    "Benign": 0, "PortScan": 40, "BruteForce": 60, "WebAttack": 65,
    "DoS": 75, "Botnet": 80, "DDoS": 85, "Infiltration": 90, "Heartbleed": 90,
}
ANOMALY_WEIGHT = 15.0
ANOMALY_ONLY_SCALE = 1.0   # multiplier on anomaly_bonus for benign-classified flows
ANOMALY_ONLY_CAP = 35.0
RISK_LEVELS = [(80, "Critical"), (55, "High"), (30, "Medium"), (0, "Low")]  # descending

# --- Alerting ---
ALERT_MIN_RISK = 30
DEDUP_WINDOW_SECONDS = 300
MAX_ALERTS_PER_BATCH = 500

# --- Optional live capture (disabled by default) ---
ENABLE_LIVE_CAPTURE = os.getenv("ENABLE_LIVE_CAPTURE", "false").lower() == "true"