# System Architecture

## Layered Architecture

```mermaid
flowchart TB
    subgraph Data["Data Layer"]
        A1[CIC-IDS2017 CSV files]
        A2[Uploaded flow CSV]
        A3[PCAP -> CICFlowMeter flow CSV]
    end

    subgraph Training["Training Layer (offline)"]
        B1[data_loader.py]
        B2[preprocessing.py]
        B3[train_model.py]
        B4[evaluation.py]
        B5[anomaly_detection.py]
    end

    subgraph Artifacts["Model Artifacts"]
        C1[(models/ids_pipeline.joblib)]
        C2[(models/anomaly_model.joblib)]
        C3[(models/metadata.json)]
        C4[(reports/metrics.json)]
    end

    subgraph Inference["Inference Layer"]
        D1[predict.py - IDS Engine]
        D2[traffic_analysis.py]
        D3[alert_manager.py]
    end

    subgraph Storage["Storage Layer"]
        E1[(SQLite: alerts.db)]
    end

    subgraph UI["Presentation Layer - Streamlit"]
        F0[app.py Overview]
        F1[Traffic Analysis]
        F2[Threat Detection]
        F3[Security Alerts]
        F4[Model Performance]
        F5[System Information]
    end

    A1 --> B1 --> B2 --> B3 --> B4
    B3 --> C1
    B5 --> C2
    B3 --> C3
    B4 --> C4
    A2 --> D2
    A3 --> D2
    C1 --> D1
    C2 --> D1
    D2 --> D1 --> D3 --> E1
    D1 --> F2
    D2 --> F1
    E1 --> F3
    E1 --> F0
    C4 --> F4
    C3 --> F5
```

## Detection Data Flow

```
Upload CSV
   │
   ▼
[Validation]  ── size, extension, parse, required columns ──► clear error on failure
   │
   ▼
[Cleaning]    ── strip column whitespace, replace ±inf, handle NaN, coerce numerics
   │
   ▼
[Pipeline.transform] ── same fitted imputer + scaler as training (no refit)
   │
   ▼
[Classifier]  ── predicted class + probability vector
   │
   ▼
[Anomaly detector] ── anomaly score (0–1) from Isolation Forest
   │
   ▼
[Risk scorer] ── severity(class) × confidence + anomaly bonus → Low/Med/High/Critical
   │
   ▼
[Alert manager] ── dedup window, threshold filter → SQLite (status = New)
   │
   ▼
Dashboard: tables, charts, filters, CSV/report export
```

## Separation of Concerns

| Concern | Modules | Rule |
|---------|---------|------|
| Training | `data_loader`, `preprocessing`, `train_model`, `evaluation` | Never imported by UI inference path except metric reading. |
| Inference | `predict`, `traffic_analysis`, `anomaly_detection` | Loads artifacts only; never calls `fit`. |
| Persistence | `database`, `alert_manager` | Only module that touches SQLite. |
| UI | `app.py`, `pages/*` | Contains no ML logic; calls service functions. |

## Key Design Principles

1. **Leakage Prevention**: Split before any fitting; all preprocessing in sklearn Pipeline
2. **Honest Detection**: Predictions are *suspicions*, not confirmed attacks
3. **Analyst-Centric**: Alert workflow supports human review (New → Investigating → Resolved)
4. **Reproducibility**: Fixed seeds, pinned versions, metadata snapshots
5. **Security**: Parameterized SQL, upload validation, no payload storage, formula-injection neutralization