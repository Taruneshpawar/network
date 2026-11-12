"""Tests for upload validation (Section 15.1 test matrix: test_upload.py)."""
from __future__ import annotations
import io
import pytest
import pandas as pd

from src.traffic_analysis import validate_upload, UploadValidationError


class FakeFile:
    """Minimal file-like object for testing."""

    def __init__(self, name: str, content: bytes):
        self.name = name
        self._buf = io.BytesIO(content)

    # file-like interface
    def read(self, n=-1):
        return self._buf.read(n)

    def seek(self, pos, whence=0):
        return self._buf.seek(pos, whence)

    def tell(self):
        return self._buf.tell()


def _make_csv(rows: int = 5, columns: list[str] | None = None) -> bytes:
    """Build a minimal CSV in memory."""
    if columns is None:
        columns = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                   "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "Label"]
    import csv, io as _io
    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for i in range(rows):
        writer.writerow([i * 100] * len(columns))
    return buf.getvalue().encode("utf-8")


# ------------------------------------------------------------------
# Extension checks
# ------------------------------------------------------------------

def test_non_csv_extension_rejected():
    """Non-.csv extension must raise UploadValidationError."""
    f = FakeFile("traffic.txt", _make_csv())
    with pytest.raises(UploadValidationError, match="extension"):
        validate_upload(f)


def test_json_extension_rejected():
    """JSON file must be rejected even if content is valid CSV."""
    f = FakeFile("data.json", _make_csv())
    with pytest.raises(UploadValidationError, match="extension"):
        validate_upload(f)


def test_csv_extension_accepted():
    """Valid .csv file must not raise on extension check."""
    f = FakeFile("flows.csv", _make_csv())
    df = validate_upload(f)
    assert isinstance(df, pd.DataFrame)
    assert len(df) > 0


# ------------------------------------------------------------------
# Size checks
# ------------------------------------------------------------------

def test_oversized_file_rejected():
    """File exceeding max_mb must raise UploadValidationError."""
    # Build a fake file reported as >1 MB by seek/tell
    large_csv = _make_csv(rows=5)  # tiny content but we override size
    f = FakeFile("big.csv", large_csv)
    with pytest.raises(UploadValidationError, match="too large"):
        validate_upload(f, max_mb=0)  # 0 MB limit → anything is too large


def test_empty_file_rejected():
    """Completely empty CSV must raise UploadValidationError."""
    f = FakeFile("empty.csv", b"")
    with pytest.raises((UploadValidationError, Exception)):
        validate_upload(f)


def test_header_only_csv_rejected():
    """CSV with only header row (no data rows) must raise."""
    header_only = b"col1,col2,col3\n"
    f = FakeFile("header_only.csv", header_only)
    with pytest.raises(UploadValidationError, match="No data rows"):
        validate_upload(f)


# ------------------------------------------------------------------
# Corrupt / binary content
# ------------------------------------------------------------------

def test_corrupt_binary_file_handled():
    """Binary / corrupt file must raise, not crash."""
    binary_content = bytes(range(256)) * 100  # raw binary, not UTF-8
    f = FakeFile("binary.csv", binary_content)
    with pytest.raises(Exception):  # could be ParserError, UnicodeDecodeError, etc.
        validate_upload(f)


def test_malformed_csv_handled():
    """A malformed CSV (unbalanced quotes) must raise cleanly."""
    bad = b'col1,col2\n"unclosed_quote,1\n2,3\n'
    f = FakeFile("bad.csv", bad)
    with pytest.raises(Exception):
        validate_upload(f)


# ------------------------------------------------------------------
# Latin-1 fallback encoding
# ------------------------------------------------------------------

def test_latin1_encoding_accepted():
    """CSV encoded as Latin-1 (not UTF-8) should be accepted via fallback."""
    csv_latin = "Flow Duration,Label\n100,BENIGN\n200,PortScan\n"
    f = FakeFile("latin.csv", csv_latin.encode("latin-1"))
    df = validate_upload(f)
    assert "Flow Duration" in df.columns


# ------------------------------------------------------------------
# Valid content
# ------------------------------------------------------------------

def test_valid_csv_returns_dataframe():
    """A valid CSV must return a non-empty DataFrame."""
    f = FakeFile("valid.csv", _make_csv(rows=10))
    df = validate_upload(f)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 10


def test_column_whitespace_stripped_after_load():
    """Column names with whitespace should be stripped after validation."""
    from src.preprocessing import clean_columns
    content = b" Flow Duration , Total Fwd Packets \n100,10\n200,20\n"
    f = FakeFile("spaces.csv", content)
    df = validate_upload(f)
    df = clean_columns(df)
    assert "Flow Duration" in df.columns
    assert "Total Fwd Packets" in df.columns


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
