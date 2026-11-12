"""Load, merge, and inspect the CIC-IDS2017 dataset."""
from __future__ import annotations
import argparse
import json
import hashlib
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

import config


def find_dataset_files(data_dir: str | Path = config.RAW_DIR) -> list[Path]:
    """Locate CSV files in the data directory."""
    data_dir = Path(data_dir)
    if not data_dir.exists():
        raise FileNotFoundError(
            f"Data directory not found: {data_dir}. "
            "Download CIC-IDS2017 and place CSVs in data/raw/. "
            "See data/README.md for instructions."
        )
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}. "
            "Download CIC-IDS2017 and place CSVs in data/raw/. "
            "See data/README.md for instructions."
        )
    return files


def load_dataset(files: list[Path], nrows: int | None = None) -> pd.DataFrame:
    """Read and concatenate CSV files with chunked reading for large files."""
    frames = []
    for f in files:
        try:
            # Try UTF-8 first, fall back to Latin-1
            df = pd.read_csv(f, nrows=nrows, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            df = pd.read_csv(f, nrows=nrows, low_memory=False, encoding="latin-1")
        df["source_file"] = f.name
        frames.append(df)
    if not frames:
        raise ValueError("No data loaded from files")
    return pd.concat(frames, ignore_index=True)


def inspect_dataset(df: pd.DataFrame) -> dict[str, Any]:
    """Return a comprehensive inspection report dict."""
    report = {}
    report["shape"] = {"rows": int(df.shape[0]), "cols": int(df.shape[1])}
    report["dtypes"] = df.dtypes.astype(str).to_dict()
    report["missing_counts"] = df.isna().sum().to_dict()
    report["inf_counts"] = (
        df.select_dtypes(include=[np.number])
        .map(lambda x: np.isinf(x))
        .sum()
        .to_dict()
    )
    report["duplicate_rows"] = int(df.duplicated().sum())
    report["duplicate_columns"] = df.columns[df.columns.duplicated()].tolist()

    # Class distribution (raw Label column)
    if "Label" in df.columns:
        report["raw_label_distribution"] = df["Label"].value_counts().to_dict()
    elif "label" in df.columns:
        report["raw_label_distribution"] = df["label"].value_counts().to_dict()

    # Constant columns
    const_cols = [
        c for c in df.columns if df[c].nunique(dropna=False) <= 1
    ]
    report["constant_columns"] = const_cols

    return report


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Clean dataset: strip columns, handle inf, drop duplicates, map labels."""
    df = df.copy()

    # Strip column whitespace
    df.columns = df.columns.str.strip()

    # Drop duplicate-named columns (keep first)
    df = df.loc[:, ~df.columns.duplicated()]

    # Replace ±inf with NaN in numeric columns
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)

    # Drop exact duplicate rows
    before = len(df)
    df = df.drop_duplicates()
    after = len(df)
    if before != after:
        print(f"Dropped {before - after} duplicate rows")

    # Map raw labels to families
    if "Label" in df.columns:
        df["family"] = df["Label"].map(config.LABEL_MAP).fillna("Unknown")
    elif "label" in df.columns:
        df["family"] = df["label"].map(config.LABEL_MAP).fillna("Unknown")

    return df


def save_inspection_report(report: dict[str, Any], path: Path = config.REPORT_DIR / "data_inspection.json") -> None:
    """Save inspection report as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert non-serializable types
    def serialize(obj):
        if isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        if isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, pd.Timestamp):
            return obj.isoformat()
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        return obj

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return serialize(o)

    path.write_text(json.dumps(walk(report), indent=2))
    print(f"Inspection report saved to {path}")


def compute_file_hashes(files: list[Path]) -> dict[str, str]:
    """Compute SHA-256 hashes of dataset files for reproducibility."""
    hashes = {}
    for f in files:
        h = hashlib.sha256()
        with f.open("rb") as fp:
            for chunk in iter(lambda: fp.read(8192), b""):
                h.update(chunk)
        hashes[f.name] = h.hexdigest()
    return hashes


def main():
    """CLI entry point for data inspection."""
    ap = argparse.ArgumentParser(description="Inspect CIC-IDS2017 dataset")
    ap.add_argument("--data-dir", default=str(config.RAW_DIR))
    ap.add_argument("--inspect", action="store_true", help="Run full inspection and save report")
    args = ap.parse_args()

    files = find_dataset_files(args.data_dir)
    print(f"Found {len(files)} CSV files")
    df = load_dataset(files)
    print(f"Loaded {len(df):,} rows, {df.shape[1]} columns")

    if args.inspect:
        report = inspect_dataset(df)
        report["file_hashes"] = compute_file_hashes(files)
        save_inspection_report(report)
        print("\n=== Inspection Summary ===")
        print(f"Shape: {report['shape']}")
        print(f"Duplicates: {report['duplicate_rows']}")
        print(f"Constant columns: {len(report['constant_columns'])}")
        if "raw_label_distribution" in report:
            print("Raw label distribution:")
            for k, v in report["raw_label_distribution"].items():
                print(f"  {k}: {v:,}")


if __name__ == "__main__":
    main()