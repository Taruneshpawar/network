# Data Directory

## Raw Data (`data/raw/`)

Place CIC-IDS2017 CSV files here. **Do not commit** these files to version control.

### Download

1. Visit: https://www.unb.ca/cic/datasets/ids-2017.html
2. Download the **GeneratedLabelledFlows** variant (preferred) or **MachineLearningCSV**
3. Extract all CSV files into this directory (`data/raw/`)

### Expected Files

| File | Day | Main Content |
|------|-----|--------------|
| Monday-WorkingHours.pcap_ISCX.csv | Mon | Benign only |
| Tuesday-WorkingHours.pcap_ISCX.csv | Tue | FTP-Patator, SSH-Patator |
| Wednesday-workingHours.pcap_ISCX.csv | Wed | DoS (Hulk, GoldenEye, slowloris, Slowhttptest), Heartbleed |
| Thursday-Morning-WebAttacks.pcap_ISCX.csv | Thu | Web Attack – Brute Force, XSS, SQL Injection |
| Thursday-Afternoon-Infilteration.pcap_ISCX.csv | Thu | Infiltration |
| Friday-Morning.pcap_ISCX.csv | Fri | Bot |
| Friday-Afternoon-PortScan.pcap_ISCX.csv | Fri | PortScan |
| Friday-Afternoon-DDoS.pcap_ISCX.csv | Fri | DDoS |

### Verification

```bash
python -m src.data_loader --inspect
```

This will:
- Load and inspect all CSVs in `data/raw/`
- Print shape, dtypes, NaN/inf counts, duplicates, class distribution
- Save a detailed inspection report to `reports/data_inspection.json`

## Sample Data (`data/sample/`)

Contains a small stratified sample (`sample_flows.csv`, ≤2000 rows) for demos and testing.

### Generate Sample

```bash
python scripts/make_sample.py --rows 2000
```

This creates `data/sample/sample_flows.csv` from the real dataset in `data/raw/`.