# CIC-IDS2017 Download Instructions

## Direct Download

1. Go to: https://www.unb.ca/cic/datasets/ids-2017.html
2. Click "Dataset" → "GeneratedLabelledFlows" (preferred) or "MachineLearningCSV"
3. Download the ZIP file (approx. 1-2 GB)
4. Extract all CSV files to `data/raw/`

## Alternative: Using wget/curl (if direct links available)

```bash
# Note: UNB may require accepting terms; check the website first
# These are example commands - verify URLs on the dataset page

# GeneratedLabelledFlows (with IPs, timestamps, ports - preferred)
wget -P data/raw/ "https://www.unb.ca/cic/datasets/ids-2017/GeneratedLabelledFlows.zip"
unzip data/raw/GeneratedLabelledFlows.zip -d data/raw/

# Or MachineLearningCSV (features only, no IPs/timestamps)
wget -P data/raw/ "https://www.unb.ca/cic/datasets/ids-2017/MachineLearningCSV.zip"
unzip data/raw/MachineLearningCSV.zip -d data/raw/
```

## Verify Download

```bash
python -m src.data_loader --inspect
```

This should print dataset statistics and save `reports/data_inspection.json`.

## Expected Files After Extraction

```
data/raw/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-Morning.pcap_ISCX.csv
├── Friday-Afternoon-PortScan.pcap_ISCX.csv
└── Friday-Afternoon-DDoS.pcap_ISCX.csv
```

## Citation

If you use this dataset, cite:

> I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," *4th International Conference on Information Systems Security and Privacy (ICISSP)*, 2018.