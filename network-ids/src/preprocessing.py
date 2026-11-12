"""Leakage-safe preprocessing: all fitted steps live inside the sklearn Pipeline."""
from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
import config


class InfToNaN(BaseEstimator, TransformerMixin):
    """Replace +/-inf with NaN (stateless, so safe at inference too)."""
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        X = pd.DataFrame(X).copy() if not isinstance(X, pd.DataFrame) else X.copy()
        return X.replace([np.inf, -np.inf], np.nan)
    def get_feature_names_out(self, input_features=None):
        return np.asarray(input_features)


def clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip column whitespace and drop duplicate-named columns."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    df = df.loc[:, ~df.columns.duplicated()]
    return df


def get_feature_columns(df: pd.DataFrame) -> tuple[list[str], list[str]]:
    """Return (numeric_cols, categorical_cols) for modeling, excluding identifiers."""
    numeric, categorical = [], []
    for col in df.columns:
        if col in config.FEATURE_EXCLUDE:
            continue
        if col == "Protocol":
            categorical.append(col)
        elif pd.api.types.is_numeric_dtype(df[col]):
            numeric.append(col)
    return numeric, categorical


def build_preprocessor(numeric_cols: list[str], categorical_cols: list[str]) -> ColumnTransformer:
    """Build an unfitted ColumnTransformer for numeric + optional categorical features."""
    num_pipe = Pipeline([
        ("inf", InfToNaN()),
        ("impute", SimpleImputer(strategy="median")),
        ("variance", VarianceThreshold(0.0)),
        ("scale", StandardScaler()),
    ])
    transformers = [("num", num_pipe, numeric_cols)]
    if categorical_cols:
        transformers.append(("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols))
    return ColumnTransformer(transformers, remainder="drop", verbose_feature_names_out=False)


class ColumnAligner(BaseEstimator, TransformerMixin):
    """Align columns to match training feature order; report missing/extra."""
    def __init__(self, expected_features: list[str]):
        self.expected_features = expected_features
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        X = pd.DataFrame(X).copy() if not isinstance(X, pd.DataFrame) else X.copy()
        missing = [c for c in self.expected_features if c not in X.columns]
        extra = [c for c in X.columns if c not in self.expected_features]
        if missing:
            raise ValueError(f"Missing required columns: {missing[:20]}{'...' if len(missing) > 20 else ''}")
        # Reorder to match training, drop extra
        return X[self.expected_features]
    def get_feature_names_out(self, input_features=None):
        return np.asarray(self.expected_features)


def time_or_day_split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Day-held-out split: train on Mon-Thu, test on Fri (Evaluation B).
    Requires 'source_file' column with day info in filename."""
    if "source_file" not in df.columns:
        raise ValueError("Day-held-out split requires 'source_file' column")

    fri_files = {"Friday-Morning.pcap_ISCX.csv", "Friday-Afternoon-PortScan.pcap_ISCX.csv", "Friday-Afternoon-DDoS.pcap_ISCX.csv"}
    is_fri = df["source_file"].isin(fri_files)
    train_df = df[~is_fri].copy()
    test_df = df[is_fri].copy()
    return train_df, test_df