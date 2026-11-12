"""Upload validation and batch traffic analysis."""
from __future__ import annotations
import io
from pathlib import Path
from typing import Any

import pandas as pd

import config
from src.predict import IDSEngine, ValidationError
from src.preprocessing import clean_columns


class UploadValidationError(ValidationError):
    """Raised when upload validation fails."""
    pass


def validate_upload(file_obj, max_mb: int = config.MAX_UPLOAD_MB, max_rows: int = config.MAX_ROWS) -> pd.DataFrame:
    """Validate and parse uploaded CSV file."""
    # Check file extension
    if hasattr(file_obj, "name"):
        name = file_obj.name
    elif isinstance(file_obj, (str, Path)):
        name = str(file_obj)
    else:
        name = "upload.csv"

    ext = Path(name).suffix.lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        raise UploadValidationError(f"Invalid file extension: {ext}. Allowed: {config.ALLOWED_EXTENSIONS}")

    # Check file size
    if hasattr(file_obj, "seek") and hasattr(file_obj, "tell"):
        file_obj.seek(0, 2)  # Seek to end
        size = file_obj.tell()
        file_obj.seek(0)
        if size > max_mb * 1024 * 1024:
            raise UploadValidationError(f"File too large: {size / (1024*1024):.1f} MB > {max_mb} MB")

    # Parse CSV with fallback encoding
    try:
        df = pd.read_csv(file_obj, nrows=max_rows, on_bad_lines="error", encoding="utf-8")
    except UnicodeDecodeError:
        if hasattr(file_obj, "seek"):
            file_obj.seek(0)
        df = pd.read_csv(file_obj, nrows=max_rows, on_bad_lines="error", encoding="latin-1")
    except pd.errors.EmptyDataError:
        raise UploadValidationError("CSV file is empty")
    except pd.errors.ParserError as e:
        raise UploadValidationError(f"CSV parse error: {e}")

    if len(df) == 0:
        raise UploadValidationError("No data rows found in CSV")

    if len(df) >= max_rows:
        raise UploadValidationError(f"Row limit exceeded: {len(df)} >= {max_rows}")

    return df


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names and map known aliases."""
    df = clean_columns(df)

    # Common alias mappings for CIC-IDS2017 variants
    alias_map = {
        "Dst Port": "Destination Port",
        "Src Port": "Source Port",
        "Src IP": "Source IP",
        "Dst IP": "Destination IP",
        "Flow ID": "Flow ID",
        "Timestamp": "Timestamp",
        "Label": "Label",
        "label": "Label",
    }

    # Apply aliases
    rename_map = {}
    for col in df.columns:
        if col in alias_map:
            rename_map[col] = alias_map[col]
    if rename_map:
        df = df.rename(columns=rename_map)

    return df


def analyze(df: pd.DataFrame, engine: IDSEngine) -> tuple[pd.DataFrame, dict]:
    """End-to-end analysis of a flow DataFrame."""
    df = normalize_columns(df)
    results = engine.predict_chunked(df)

    summary = summarize(results)
    return results, summary


def summarize(results: pd.DataFrame) -> dict[str, Any]:
    """Generate summary statistics from results."""
    total = len(results)
    suspicious = int(results.get("is_suspicious", pd.Series([False]*total)).sum())
    benign = total - suspicious

    summary = {
        "total_records": total,
        "benign_count": benign,
        "suspicious_count": suspicious,
        "attack_distribution": {},
        "risk_distribution": {},
        "mean_confidence": 0.0,
        "mean_anomaly_score": 0.0,
    }

    if "predicted_class" in results.columns:
        summary["attack_distribution"] = results["predicted_class"].value_counts().to_dict()

    if "risk_level" in results.columns:
        summary["risk_distribution"] = results["risk_level"].value_counts().to_dict()

    if "confidence" in results.columns:
        summary["mean_confidence"] = float(results["confidence"].mean())

    if "anomaly_score" in results.columns:
        summary["mean_anomaly_score"] = float(results["anomaly_score"].mean())

    # Time series if timestamp available
    if "flow_timestamp" in results.columns or "Timestamp" in results.columns:
        ts_col = "flow_timestamp" if "flow_timestamp" in results.columns else "Timestamp"
        try:
            results[ts_col] = pd.to_datetime(results[ts_col], errors="coerce")
            valid_ts = results.dropna(subset=[ts_col])
            if len(valid_ts) > 0:
                summary["time_range"] = {
                    "start": valid_ts[ts_col].min().isoformat(),
                    "end": valid_ts[ts_col].max().isoformat(),
                }
        except Exception:
            pass

    return summary


def get_column_template(engine: IDSEngine) -> pd.DataFrame:
    """Get a template DataFrame with expected columns for user reference."""
    template = pd.DataFrame(columns=engine.expected_features)
    return template