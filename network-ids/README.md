# AI-Powered Network Intrusion Detection System (IDS)

A college Information Security project implementing a machine-learning-based Network Intrusion Detection System using the CIC-IDS2017 dataset. Built with Python, scikit-learn, and Streamlit.

## Features

- **Multi-class attack classification**: Benign, DoS, DDoS, PortScan, BruteForce, Botnet, WebAttack, Infiltration, Heartbleed
- **Anomaly detection**: Isolation Forest for detecting unseen attack types
- **Risk scoring**: Configurable severity-based risk levels (Low/Medium/High/Critical)
- **Alert management**: SQLite-backed alert workflow (New → Investigating → Resolved) with deduplication
- **Interactive dashboard**: Streamlit multi-page UI with charts, filters, and CSV export
- **Leakage-safe ML pipeline**: Proper train/test splits, no data leakage, honest evaluation

## Quick Start

### Prerequisites

- Python 3.11 (3.10–3.12 supported)
- Git
- ≥ 8 GB RAM recommended for full training

### Installation

```bash
cd network-ids
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Linux/macOS
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Dataset Setup

1. Download **CIC-IDS2017** (GeneratedLabelledFlows variant preferred) from [UNB CIC](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Extract CSV files into `data/raw/`
3. Verify and create sample:
   ```bash
   python -m src.data_loader --inspect
   python scripts/make_sample.py --rows 2000
   ```

### Training

```bash
# Quick smoke run (small subset)
python -m src.train_model --data-dir data/raw --sample-frac 0.05 --no-tune

# Full run with tuning and anomaly detector
python -m src.train_model --data-dir data/raw --tune --with-anomaly

# Full run + day-held-out Evaluation B + permutation importance
python -m src.train_model --data-dir data/raw --tune --with-anomaly --day-heldout --compute-importance
```

Outputs: `models/ids_pipeline.joblib`, `models/anomaly_model.joblib`, `models/metadata.json`, `reports/metrics.json`

### Launch Dashboard

```bash
streamlit run app.py
```

Open http://localhost:8501

### Run Tests

```bash
pytest -q --cov=src --cov-report=term-missing
```

## Project Structure

```
network-ids/
├── app.py                          # Streamlit entry point: Overview Dashboard
├── config.py                       # Central configuration
├── requirements.txt
├── README.md
├── .gitignore
├── data/
│   ├── README.md
│   ├── raw/                        # CIC-IDS2017 CSVs (NOT committed)
│   └── sample/
│       └── sample_flows.csv        # Small test sample
├── models/
│   └── README.md
├── src/
│   ├── __init__.py
│   ├── data_loader.py
│   ├── preprocessing.py
│   ├── train_model.py
│   ├── evaluation.py
│   ├── predict.py
│   ├── anomaly_detection.py
│   ├── traffic_analysis.py
│   ├── risk.py
│   ├── alert_manager.py
│   ├── database.py
│   ├── pcap_utils.py
│   └── report.py
├── pages/
│   ├── 1_Traffic_Analysis.py
│   ├── 2_Threat_Detection.py
│   ├── 3_Security_Alerts.py
│   ├── 4_Model_Performance.py
│   └── 5_System_Information.py
├── scripts/
│   ├── make_sample.py
│   └── download_instructions.md
├── tests/
│   ├── conftest.py
│   ├── test_preprocessing.py
│   ├── test_prediction.py
│   ├── test_risk.py
│   ├── test_database.py
│   ├── test_alerts.py
│   └── test_upload.py
├── docs/
│   ├── architecture.md
│   └── demo_guide.md
└── reports/
```

## Dashboard Pages

1. **Overview** — KPIs, attack/risk distribution, recent alerts, model snapshot
2. **Traffic Analysis** — Upload CSV, validate, preview, run analysis, download results
3. **Threat Detection** — Suspicious records, drill-down, risk breakdown, feature contributions
4. **Security Alerts** — Search/filter alerts, status workflow, bulk actions, CSV export
5. **Model Performance** — Comparison table, confusion matrix, per-class metrics, F1/PR-AUC
6. **System Information** — Model details, dataset info, risk formula, limitations

## Wireshark/PCAP Workflow (Offline, Authorized Only)

```
1. Capture authorized traffic in Wireshark → save as .pcap/.pcapng
2. Convert to flow CSV with CICFlowMeter (produces CIC-IDS2017-compatible columns)
3. Upload CSV on "Traffic Analysis" page
4. System scores flows and optionally saves alerts
```

## Security & Ethics

- **Authorized use only**: Analyze only data you own or have written permission to monitor
- **No attack tooling**: No packet crafting, scanning, exploitation, or evasion
- **No payload storage**: Only flow statistics stored; IP masking available
- **Decision support**: Detections are *suspected*, not confirmed; require analyst review

## Citation

If using the CIC-IDS2017 dataset, cite:
> I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," *ICISSP*, 2018.

## License

Educational/research use. Follow CIC-IDS2017 publisher's citation requirements.