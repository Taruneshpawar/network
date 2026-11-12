"""Tests for preprocessing module."""
import numpy as np
import pandas as pd
import pytest

from src.preprocessing import (
    clean_columns,
    get_feature_columns,
    build_preprocessor,
    InfToNaN,
    ColumnAligner,
    time_or_day_split,
)


def test_clean_columns_strips_whitespace():
    df = pd.DataFrame({ "  Col A  ": [1, 2], "Col B": [3, 4] })
    cleaned = clean_columns(df)
    assert list(cleaned.columns) == ["Col A", "Col B"]


def test_clean_columns_drops_duplicate_names():
    df = pd.DataFrame([[1, 2, 3]], columns=["A", "B", "A"])
    cleaned = clean_columns(df)
    assert list(cleaned.columns) == ["A", "B"]
    assert cleaned.shape[1] == 2


def test_get_feature_columns_excludes_identifiers():
    df = pd.DataFrame({
        "Flow Duration": [100],
        "Source IP": ["1.2.3.4"],
        "Destination IP": ["5.6.7.8"],
        "Label": ["BENIGN"],
        "Total Fwd Packets": [10],
        "Protocol": [6],
    })
    numeric, categorical = get_feature_columns(df)
    assert "Flow Duration" in numeric
    assert "Total Fwd Packets" in numeric
    assert "Protocol" in categorical
    assert "Source IP" not in numeric
    assert "Destination IP" not in numeric
    assert "Label" not in numeric


def test_inf_to_nan_transformer():
    transformer = InfToNaN()
    X = pd.DataFrame({"a": [1, np.inf, -np.inf], "b": [4, 5, 6]})
    result = transformer.fit_transform(X)
    assert np.isnan(result.loc[1, "a"])
    assert np.isnan(result.loc[2, "a"])
    assert result.loc[0, "a"] == 1


def test_build_preprocessor_creates_pipeline():
    numeric = ["a", "b"]
    categorical = ["c"]
    preprocessor = build_preprocessor(numeric, categorical)
    assert hasattr(preprocessor, "fit")
    assert hasattr(preprocessor, "transform")


def test_column_aligner_validates_columns():
    expected = ["a", "b", "c"]
    aligner = ColumnAligner(expected)

    # Missing column
    df = pd.DataFrame({"a": [1], "b": [2]})
    with pytest.raises(ValueError, match="Missing required columns"):
        aligner.transform(df)

    # Extra columns dropped
    df = pd.DataFrame({"a": [1], "b": [2], "c": [3], "extra": [4]})
    result = aligner.fit_transform(df)
    assert list(result.columns) == expected


def test_time_or_day_split_requires_source_file():
    df = pd.DataFrame({"a": [1, 2]})
    with pytest.raises(ValueError, match="requires 'source_file'"):
        time_or_day_split(df)


def test_no_leakage_scaler_fit_only_on_train(synthetic_flows):
    """Verify scaler/imputer fit only on training data (no leakage)."""
    from sklearn.model_selection import train_test_split
    from src.preprocessing import build_preprocessor, get_feature_columns

    df = synthetic_flows.copy()
    df = clean_columns(df)
    numeric, categorical = get_feature_columns(df)
    X = df[numeric + categorical]
    y = df["Label"].map({"BENIGN": "Benign", "DoS Hulk": "DoS", "PortScan": "PortScan"}).fillna("Unknown")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    preprocessor = build_preprocessor(numeric, categorical)
    preprocessor.fit(X_train, y_train)

    # Check that imputer statistics come from train only
    imputer = preprocessor.named_transformers_["num"].named_steps["impute"]
    train_mean = X_train[numeric].mean()
    # Imputer median should be close to train median, not full dataset median
    full_median = X[numeric].median()
    train_median = X_train[numeric].median()

    for col in numeric:
        imputed_val = imputer.statistics_[numeric.index(col)]
        # Should match train median, not full median (allowing for NaN handling)
        assert abs(imputed_val - train_median[col]) < abs(imputed_val - full_median[col]) + 1e-6