# Model Artifacts

This directory contains trained model artifacts. **Do not commit** these files to version control.

## Generated Files

| File | Description |
|------|-------------|
| `ids_pipeline.joblib` | Fitted preprocessing + best multi-class classifier (single Pipeline) |
| `ids_binary_pipeline.joblib` | Binary model (Benign vs Malicious) — optional |
| `anomaly_model.joblib` | Isolation Forest + its own scaler (trained on benign-only flows) |
| `metadata.json` | Feature list, class list, library versions, seed, training date, dataset file hashes, split sizes, hyperparameters |

## Regeneration

Train models with:

```bash
# Quick smoke run
python -m src.train_model --data-dir data/raw --sample-frac 0.05 --no-tune

# Full run with tuning and anomaly detector
python -m src.train_model --data-dir data/raw --tune --with-anomaly
```

## Loading

The `IDSEngine` in `src/predict.py` loads these artifacts and validates version compatibility. A scikit-learn version mismatch produces a warning instructing retraining.