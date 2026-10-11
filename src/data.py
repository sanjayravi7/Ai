"""Data loading and lightweight profiling helpers for VULNOVA."""

from pathlib import Path
from typing import Union

import pandas as pd


DEFAULT_DATA_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "raw" / "vulnerabilities.csv"
)
_DATE_COLUMNS = ("mod_date", "pub_date")


def load_vulnerabilities(
    path: Union[str, Path] = DEFAULT_DATA_PATH,
) -> pd.DataFrame:
    """Load the raw CVE CSV and normalize its identifier and common data types.

    The source file has a blank header for its first column, which contains CVE
    identifiers. The raw CSV is left unchanged; this function names that column
    ``cve_id`` in memory and parses dates and CVSS scores for analysis.

    Args:
        path: CSV path. Defaults to ``data/raw/vulnerabilities.csv`` in this
            checkout.

    Returns:
        A DataFrame with normalized column names and parsed date/CVSS columns.
    """
    frame = pd.read_csv(path)
    frame.columns = [str(column).strip() for column in frame.columns]

    if frame.columns.size:
        first_column = frame.columns[0]
        if first_column == "" or first_column.lower().startswith("unnamed:"):
            frame = frame.rename(columns={first_column: "cve_id"})

    for column in _DATE_COLUMNS:
        if column in frame.columns:
            frame[column] = pd.to_datetime(frame[column], errors="coerce")

    if "cvss" in frame.columns:
        frame["cvss"] = pd.to_numeric(frame["cvss"], errors="coerce")

    return frame


def summarize_missingness(frame: pd.DataFrame) -> pd.DataFrame:
    """Return null counts and percentages for every column, most-missing first."""
    summary = pd.DataFrame(
        {
            "missing_count": frame.isna().sum(),
            "missing_percent": (frame.isna().mean() * 100).round(2),
        }
    )
    return summary.sort_values(
        by=["missing_count", "missing_percent"], ascending=False
    )
