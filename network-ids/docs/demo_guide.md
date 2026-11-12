# Demonstration Guide for Presentation

**Duration:** ~12–15 minutes
**Setup before presenting:**
- Model trained: `python -m src.train_model --data-dir data/raw --tune --with-anomaly`
- Dashboard running: `streamlit run app.py`
- Sample data ready: `data/sample/sample_flows.csv` (run `python scripts/make_sample.py --rows 2000`)
- Alert DB reset for clean demo: `python -m src.database --reset`

## Presentation Flow

| Step | Time | Action | Talking Points |
|------|------|--------|----------------|
| 1 | 1 min | Introduce problem (Section 2) | Scale of network traffic, signature-based IDS limitations, alert fatigue, need for ML |
| 2 | 1 min | Show architecture diagram | Training vs inference separation, leakage prevention, analyst workflow |
| 3 | 2 min | **Overview** page (empty → populated) | KPIs, empty-state guidance, model snapshot |
| 4 | 3 min | **Traffic Analysis**: upload sample CSV; show validation, preview, run analysis; also upload bad CSV to show clear error | Preprocessing identical to training, robustness, column validation |
| 5 | 2 min | **Threat Detection**: filter by High/Critical, open drill-down | Explainability: probabilities, risk breakdown, key features; "suspected ≠ confirmed" |
| 6 | 2 min | **Security Alerts**: search, change status New → Investigating → Resolved, export CSV | Analyst workflow; deduplication avoids alert flooding |
| 7 | 2 min | **Model Performance**: comparison, confusion matrix, per-class table, FN/FP analysis | Real measured results; imbalance discussion; Evaluation B generalization gap |
| 8 | 1 min | **System Information**: limitations, risk formula, unsupported attacks | Honest scope, responsible use |
| 9 | 1 min | Wireshark workflow slide (PCAP → CICFlowMeter → upload) | Authorized, offline analysis only |
| 10 | 1 min | Conclusion + future work + Q&A | |

## Likely Examiner Questions (Prepare Answers)

1. **"Why not just report 99% accuracy?"**
   → Class imbalance (benign dominates), leakage prevention, balanced metrics (macro-F1, PR-AUC), Evaluation B shows generalization gap

2. **"How did you prevent data leakage?"**
   → Split before any fitting; all preprocessing in sklearn Pipeline fitted on train only; duplicate removal before split; identifier columns excluded; unit test validates no leakage

3. **"Why Random Forest over Logistic Regression?"**
   → Show measured comparison from Model Performance page, not assumptions. RF typically handles non-linear boundaries better for this feature space.

4. **"Can it detect zero-day attacks?"**
   → Partially via Isolation Forest anomaly detector; show unseen-class results from Evaluation B honestly. Supervised model cannot name unseen attacks.

5. **"Is this real-time prevention?"**
   → No. Batch/replay detection only. Live capture is optional, disabled by default, experimental.

6. **"What are the ethical considerations?"**
   → Authorized monitoring only; no payload storage; no attack generation; IP masking for presentations; detections require human verification.

## Demo Tips

- **Reset alerts between demos**: `python -m src.database --reset`
- **Have a "bad" CSV ready** to show validation errors (wrong columns, wrong format)
- **Know the sample data**: It contains Benign, DoS, PortScan — show how each appears
- **Use the drill-down** on Threat Detection to show risk breakdown
- **Show the confusion matrix toggle** (counts ↔ normalized)
- **Point out the disclaimer** on every page: "suspected, not confirmed"

## Backup Slides (if needed)

- Data inspection report (`reports/data_inspection.json`)
- Training command and exact parameters used
- Evaluation B results table
- Feature importance chart
- Risk formula with live parameter values