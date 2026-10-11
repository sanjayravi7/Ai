#!/usr/bin/env python3
"""Print an untruncated schema and descriptive profile of the bundled CVE CSV."""

import argparse
from pathlib import Path

import pandas as pd

from src.data import DEFAULT_DATA_PATH, load_vulnerabilities, summarize_missingness


PERCENTILES = [0.25, 0.50, 0.75, 0.90, 0.95]


def inspect_data(path: Path) -> pd.DataFrame:
    """Load and print all columns, types, missingness, and descriptive stats.

    The loader normalizes the source's ``Unnamed: 0`` identifier heading to
    ``cve_id`` and parses date and CVSS fields in memory. It never writes to the
    source CSV.
    """
    frame = load_vulnerabilities(path)

    print(f"Input: {path}")
    print(f"Shape: {len(frame):,} rows x {len(frame.columns)} columns")
    print("Columns (all):")
    for position, column in enumerate(frame.columns, start=1):
        print(f"  {position:>2}. {column}")

    # Explicit to_string() calls avoid pandas' terminal-width and row/column
    # display limits hiding columns or statistics in redirected output too.
    with pd.option_context(
        "display.max_columns", None,
        "display.max_rows", None,
        "display.max_colwidth", None,
        "display.width", None,
    ):
        print("\nData types:")
        print(frame.dtypes.rename("dtype").to_frame().to_string())

        print("\nMissingness (every column):")
        print(summarize_missingness(frame).to_string())

        print("\nDescriptive statistics (every column; transposed):")
        statistics = frame.describe(include="all", percentiles=PERCENTILES).T
        print(statistics.to_string(max_rows=None, max_cols=None))

    return frame


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect every field and descriptive statistic in a CVE CSV."
    )
    parser.add_argument(
        "csv_path",
        nargs="?",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help=f"CSV to inspect (default: {DEFAULT_DATA_PATH})",
    )
    args = parser.parse_args(argv)
    inspect_data(args.csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
