"""Reproducible, non-destructive preprocessing for the bundled CVE CSV."""

import argparse
import json
from pathlib import Path
import re
from typing import Any, Dict, Tuple

import pandas as pd
from pandas.api.types import is_object_dtype, is_string_dtype

from .data import DEFAULT_DATA_PATH


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "vulnerabilities_clean.csv"
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
REQUIRED_COLUMNS = ("mod_date", "pub_date", "cvss")
DATE_COLUMNS = ("mod_date", "pub_date")


def _missing_mask(values: pd.Series) -> pd.Series:
    blank = values.astype("string").str.strip().eq("").fillna(False)
    return (values.isna() | blank).astype(bool)


def preprocess_dataframe(raw_frame: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Clean a raw-like DataFrame without dropping any rows.

    The first source column must contain syntactically valid CVE identifiers;
    it is renamed to ``cve_id``. Empty or whitespace-only cells are represented
    as missing values. Dates and CVSS are parsed, with malformed non-empty
    values converted to missing and counted in the returned report. All rows,
    including rows with missing attributes, are retained. The caller's DataFrame
    is not mutated.
    """
    if raw_frame.shape[1] == 0:
        raise ValueError("Input CSV has no columns; cannot verify a CVE identifier column.")
    if raw_frame.empty:
        raise ValueError("Input CSV has no records to preprocess.")

    cleaned = raw_frame.copy(deep=True)
    cleaned.columns = [str(column).strip() for column in cleaned.columns]
    first_column = cleaned.columns[0]
    if "cve_id" in cleaned.columns[1:]:
        raise ValueError(
            "The first source column must be the only cve_id column; found another cve_id column."
        )

    identifiers = cleaned.iloc[:, 0].astype("string").str.strip()
    missing_ids = _missing_mask(identifiers)
    valid_ids = identifiers.str.fullmatch(CVE_ID_PATTERN.pattern, na=False)
    invalid_ids = (~missing_ids) & (~valid_ids)
    invalid_id_mask = missing_ids | invalid_ids
    if bool(invalid_id_mask.any()):
        examples = [
            str(value)
            for value in cleaned.iloc[:, 0].loc[invalid_id_mask].head(10).tolist()
        ]
        raise ValueError(
            "First column failed CVE ID validation: "
            f"{int(invalid_id_mask.sum())} invalid or missing value(s); examples={examples}"
        )

    cleaned = cleaned.rename(columns={first_column: "cve_id"})
    cleaned["cve_id"] = identifiers

    missing_required = [column for column in REQUIRED_COLUMNS if column not in cleaned]
    if missing_required:
        raise ValueError(
            "Input is missing required fields from the observed VULNOVA schema: "
            + ", ".join(missing_required)
        )

    # Normalize empty CSV cells to an explicit missing marker in memory. Never
    # impute access, impact, text, date, or score fields with fabricated values.
    for column in cleaned.columns:
        values = cleaned[column]
        if is_object_dtype(values.dtype) or is_string_dtype(values.dtype):
            blank = values.astype("string").str.fullmatch(r"\s*", na=False)
            cleaned.loc[blank, column] = pd.NA

    date_parse_failures = {}
    for column in DATE_COLUMNS:
        original = cleaned[column]
        was_missing = _missing_mask(original)
        parsed = pd.to_datetime(original, errors="coerce")
        failures = (~was_missing) & parsed.isna()
        date_parse_failures[column] = {
            "count": int(failures.sum()),
            "examples": [str(value) for value in original.loc[failures].head(10).tolist()],
        }
        # Invalid non-empty dates become NaT, but their rows are retained and
        # the parse failure is made explicit in the report.
        cleaned[column] = parsed

    original_scores = cleaned["cvss"]
    score_was_missing = _missing_mask(original_scores)
    numeric_scores = pd.to_numeric(original_scores, errors="coerce")
    score_parse_failures = (~score_was_missing) & numeric_scores.isna()
    cleaned["cvss"] = numeric_scores

    report = {
        "rows_input": int(len(raw_frame)),
        "rows_output": int(len(cleaned)),
        "rows_dropped": 0,
        "source_first_column": str(first_column),
        "identifier_column": "cve_id",
        "identifier_pattern": CVE_ID_PATTERN.pattern,
        "invalid_identifier_count": 0,
        "date_parse_failures": date_parse_failures,
        "cvss_parse_failure_count": int(score_parse_failures.sum()),
        "cvss_parse_failure_examples": [
            str(value) for value in original_scores.loc[score_parse_failures].head(10).tolist()
        ],
        "missing_values_after_parsing": {
            str(column): int(count)
            for column, count in cleaned.isna().sum().items()
        },
        "missing_value_policy": (
            "Blank/whitespace-only fields remain missing (written as empty CSV cells); "
            "no values are imputed and no rows are dropped. Malformed non-empty dates "
            "and CVSS values become missing and are counted above."
        ),
    }
    return cleaned, report


def preprocess_file(input_path: Path, output_path: Path) -> Dict[str, Any]:
    """Read, preprocess, and write a CSV while protecting the input path."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must differ; raw data will not be overwritten.")

    raw_frame = pd.read_csv(
        input_path,
        dtype="string",
        keep_default_na=False,
        na_filter=False,
    )
    cleaned, report = preprocess_dataframe(raw_frame)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    cleaned.to_csv(
        output_path,
        index=False,
        na_rep="",
        date_format="%Y-%m-%d %H:%M:%S",
    )
    report["input_path"] = str(input_path)
    report["output_path"] = str(output_path)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify CVE IDs, parse dates/CVSS, preserve rows, and write a clean CSV."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help=f"Source CSV (default: {DEFAULT_DATA_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Processed CSV (default: {DEFAULT_OUTPUT_PATH})",
    )
    args = parser.parse_args(argv)

    report = preprocess_file(args.input, args.output)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
