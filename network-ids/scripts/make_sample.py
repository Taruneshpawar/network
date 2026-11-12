"""Create a stratified sample CSV from the full dataset for demos/testing."""
from __future__ import annotations
import argparse
from pathlib import Path

import pandas as pd

import config
from src import data_loader


def main():
    ap = argparse.ArgumentParser(description="Create stratified sample from CIC-IDS2017")
    ap.add_argument("--data-dir", default=str(config.RAW_DIR))
    ap.add_argument("--rows", type=int, default=2000, help="Total rows in sample")
    ap.add_argument("--output", default=str(config.SAMPLE_PATH))
    args = ap.parse_args()

    files = data_loader.find_dataset_files(args.data_dir)
    df = data_loader.load_dataset(files)
    df = data_loader.clean_dataset(df)

    if "family" not in df.columns:
        raise ValueError("Dataset must have 'family' column after cleaning")

    # Stratified sample
    sample = df.groupby("family", group_keys=False).apply(
        lambda g: g.sample(n=min(len(g), max(1, int(args.rows * len(g) / len(df)))), random_state=42)
    )

    # If we got more than requested, trim
    if len(sample) > args.rows:
        sample = sample.sample(n=args.rows, random_state=42)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(output_path, index=False)

    print(f"Sample saved to {output_path} ({len(sample):,} rows)")
    print("Class distribution:")
    print(sample["family"].value_counts())


if __name__ == "__main__":
    main()