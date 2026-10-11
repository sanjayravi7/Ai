"""Read-only quality checks for the VULNOVA CVE CSV.

The validator preserves raw field values while checking them. It does not clean,
rewrite, or otherwise mutate the input file.
"""

import argparse
from pathlib import Path
import re
from typing import Any, Dict, Mapping, Optional

import pandas as pd

from .data import DEFAULT_DATA_PATH


CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
DATE_COLUMNS = ("mod_date", "pub_date")


def _missing_mask(values: pd.Series) -> pd.Series:
    """Treat nulls and empty/whitespace-only CSV fields as missing."""
    blank = values.astype("string").str.strip().eq("").fillna(False)
    return (values.isna() | blank).astype(bool)


def _examples(values: pd.Series, mask: pd.Series, limit: int = 10):
    return [str(value) for value in values.loc[mask].head(limit).tolist()]


def _clean_headers(frame: pd.DataFrame) -> pd.DataFrame:
    """Make a shallow view with trimmed header strings; do not edit cell data."""
    view = frame.copy(deep=False)
    view.columns = [str(column).strip() for column in frame.columns]
    return view


def validate_dataframe(
    frame: pd.DataFrame,
    inferred_dtypes: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return validation findings for an in-memory raw-like DataFrame.

    Empty and whitespace-only cells count as missing. The first column is the
    identifier column unless a normalized ``cve_id`` column is already present.
    ``inferred_dtypes`` may supply pandas' normal CSV-inferred source dtypes;
    the CLI provides these alongside string-preserved values so the report can
    show both source and validation-time types.
    """
    source = _clean_headers(frame)
    columns = list(source.columns)
    row_count = len(source)

    missing_records = []
    for position, column in enumerate(columns):
        values = source.iloc[:, position]
        count = int(_missing_mask(values).sum())
        missing_records.append(
            {
                "column": column,
                "missing_count": count,
                "missing_percent": round((count / row_count * 100), 2)
                if row_count
                else 0.0,
            }
        )
    missing_values = pd.DataFrame(missing_records).set_index("column")

    identifier_column = "cve_id" if "cve_id" in columns else (
        columns[0] if columns else None
    )
    identifier_findings = {
        "pattern": CVE_ID_PATTERN.pattern,
        "missing_count": 0,
        "invalid_format_count": 0,
        "invalid_examples": [],
        "duplicate_id_count": 0,
        "duplicate_row_count": 0,
        "duplicate_examples": [],
    }
    identifier_values = None
    identifier_missing = None
    if identifier_column is not None:
        identifier_values = source[identifier_column].astype("string").str.strip()
        identifier_missing = _missing_mask(identifier_values)
        valid_format = identifier_values.str.fullmatch(
            CVE_ID_PATTERN.pattern, na=False
        )
        invalid_format = (~identifier_missing) & (~valid_format)
        duplicate_values = identifier_values.loc[~identifier_missing]
        duplicate_counts = duplicate_values.value_counts()
        duplicate_counts = duplicate_counts.loc[duplicate_counts > 1]

        identifier_findings.update(
            {
                "missing_count": int(identifier_missing.sum()),
                "invalid_format_count": int(invalid_format.sum()),
                "invalid_examples": _examples(
                    source[identifier_column], invalid_format
                ),
                "duplicate_id_count": int(len(duplicate_counts)),
                "duplicate_row_count": int(
                    duplicate_values.duplicated(keep="first").sum()
                ),
                "duplicate_examples": [
                    {"cve_id": str(value), "occurrences": int(count)}
                    for value, count in duplicate_counts.head(10).items()
                ],
            }
        )

    date_findings = {}
    parsed_dates = {}
    for column in DATE_COLUMNS:
        if column not in columns:
            date_findings[column] = {
                "present": False,
                "parse_failure_count": 0,
                "failure_examples": [],
                "parsed_dtype": None,
            }
            continue

        values = source[column]
        missing = _missing_mask(values)
        parsed = pd.to_datetime(values.where(~missing), errors="coerce")
        failed = (~missing) & parsed.isna()
        parsed_dates[column] = parsed
        date_findings[column] = {
            "present": True,
            "parse_failure_count": int(failed.sum()),
            "failure_examples": _examples(values, failed),
            "parsed_dtype": str(parsed.dtype),
        }

    cvss_findings = {
        "present": "cvss" in columns,
        "missing_count": 0,
        "non_numeric_count": 0,
        "non_numeric_examples": [],
        "out_of_range_count": 0,
        "out_of_range_examples": [],
        "parsed_dtype": None,
    }
    cvss_distribution = pd.DataFrame(columns=["cvss", "record_count"])
    parsed_cvss = None
    if "cvss" in columns:
        values = source["cvss"]
        missing = _missing_mask(values)
        parsed_cvss = pd.to_numeric(values.where(~missing), errors="coerce")
        non_numeric = (~missing) & parsed_cvss.isna()
        in_range = parsed_cvss.between(0, 10).fillna(False)
        out_of_range = parsed_cvss.notna() & (~in_range)

        cvss_findings.update(
            {
                "missing_count": int(missing.sum()),
                "non_numeric_count": int(non_numeric.sum()),
                "non_numeric_examples": _examples(values, non_numeric),
                "out_of_range_count": int(out_of_range.sum()),
                "out_of_range_examples": _examples(values, out_of_range),
                "parsed_dtype": str(parsed_cvss.dtype),
            }
        )

        counts = parsed_cvss.dropna().value_counts().sort_index()
        records = [
            {"cvss": float(score), "record_count": int(count)}
            for score, count in counts.items()
        ]
        if int(missing.sum()):
            records.append(
                {"cvss": "<MISSING>", "record_count": int(missing.sum())}
            )
        if int(non_numeric.sum()):
            records.append(
                {"cvss": "<NON_NUMERIC>", "record_count": int(non_numeric.sum())}
            )
        cvss_distribution = pd.DataFrame(records, columns=["cvss", "record_count"])

    cwe_columns = [column for column in ("cwe_code", "cwe_name") if column in columns]
    if cwe_columns:
        category_values = {}
        for column in cwe_columns:
            values = source[column].astype("string").str.strip()
            category_values[column] = values.mask(
                _missing_mask(source[column]), "<MISSING>"
            )
        cwe_distribution = (
            pd.DataFrame(category_values)
            .value_counts(dropna=False)
            .rename("record_count")
            .reset_index()
            .sort_values(
                by=["record_count"] + cwe_columns,
                ascending=[False] + [True] * len(cwe_columns),
                kind="mergesort",
            )
            .reset_index(drop=True)
        )
    else:
        cwe_distribution = pd.DataFrame(
            columns=cwe_columns + ["record_count"]
        )

    dtype_source = {} if inferred_dtypes is None else inferred_dtypes
    inferred = {
        str(column).strip(): str(dtype)
        for column, dtype in dtype_source.items()
    }
    dtype_records = []
    for position, column in enumerate(columns):
        original_dtype = inferred.get(column, str(source.iloc[:, position].dtype))
        if column == identifier_column:
            checked_dtype = "string (identifier check)"
        elif column in parsed_dates:
            checked_dtype = date_findings[column]["parsed_dtype"]
        elif column == "cvss" and parsed_cvss is not None:
            checked_dtype = str(parsed_cvss.dtype)
        else:
            checked_dtype = str(source.iloc[:, position].dtype)
        dtype_records.append(
            {
                "column": column,
                "source_dtype": original_dtype,
                "validation_dtype": checked_dtype,
            }
        )
    data_types = pd.DataFrame(dtype_records).set_index("column")

    return {
        "row_count": row_count,
        "column_count": len(columns),
        "columns": columns,
        "identifier_column": identifier_column,
        "identifier": identifier_findings,
        "missing_values": missing_values,
        "date_parse_failures": date_findings,
        "cvss": cvss_findings,
        "data_types": data_types,
        "cwe_distribution": cwe_distribution,
        "cvss_distribution": cvss_distribution,
    }


def validate_csv(path: Path) -> Dict[str, Any]:
    """Read a CSV without normalizing or writing it, then return its findings."""
    path = Path(path)
    raw_values = pd.read_csv(
        path,
        dtype="string",
        keep_default_na=False,
        na_filter=False,
    )
    inferred_values = pd.read_csv(path, low_memory=False)
    return validate_dataframe(raw_values, inferred_dtypes=inferred_values.dtypes)


def format_report(report: Dict[str, Any]) -> str:
    """Format all validation tables without pandas row/column truncation."""
    lines = [
        "VULNOVA read-only validation report",
        f"Rows: {report['row_count']:,} | Columns: {report['column_count']}",
        f"Columns: {', '.join(report['columns'])}",
        f"Identifier column checked: {report['identifier_column']!r}",
        "",
        "CVE identifier checks:",
        f"  Missing IDs: {report['identifier']['missing_count']}",
        f"  Invalid-format IDs: {report['identifier']['invalid_format_count']}",
        f"  Invalid examples: {report['identifier']['invalid_examples']}",
        f"  Duplicate identifier values: {report['identifier']['duplicate_id_count']}",
        f"  Duplicate rows after first occurrence: {report['identifier']['duplicate_row_count']}",
        f"  Duplicate examples: {report['identifier']['duplicate_examples']}",
        "",
        "Missingness by column:",
        report["missing_values"].to_string(),
        "",
        "Date parsing checks:",
    ]
    for column, finding in report["date_parse_failures"].items():
        lines.append(
            f"  {column}: present={finding['present']}, "
            f"parse_failures={finding['parse_failure_count']}, "
            f"parsed_dtype={finding['parsed_dtype']}, "
            f"examples={finding['failure_examples']}"
        )

    cvss = report["cvss"]
    lines.extend(
        [
            "",
            "CVSS checks:",
            f"  Present: {cvss['present']}",
            f"  Missing: {cvss['missing_count']}",
            f"  Non-numeric non-missing values: {cvss['non_numeric_count']} "
            f"(examples: {cvss['non_numeric_examples']})",
            f"  Outside [0, 10]: {cvss['out_of_range_count']} "
            f"(examples: {cvss['out_of_range_examples']})",
            "",
            "Data types (inferred from CSV and used for checks):",
            report["data_types"].to_string(),
            "",
            "CWE category distribution (all observed categories):",
            report["cwe_distribution"].to_string(index=False),
            "",
            "CVSS score distribution (all observed scores):",
            report["cvss_distribution"].to_string(index=False),
        ]
    )
    return "\n".join(lines)


def _has_strict_issues(report: Dict[str, Any]) -> bool:
    identifier = report["identifier"]
    if (
        report["identifier_column"] is None
        or identifier["missing_count"]
        or identifier["invalid_format_count"]
        or identifier["duplicate_id_count"]
    ):
        return True
    if any(
        finding["parse_failure_count"]
        for finding in report["date_parse_failures"].values()
    ):
        return True
    return bool(
        report["cvss"]["non_numeric_count"]
        or report["cvss"]["out_of_range_count"]
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate CVE identifiers, missingness, dates, CVSS, and categories."
    )
    parser.add_argument(
        "csv_path",
        nargs="?",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help=f"Raw CSV to inspect (default: {DEFAULT_DATA_PATH})",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 1 for malformed IDs, duplicates, parse failures, or invalid CVSS.",
    )
    args = parser.parse_args(argv)

    report = validate_csv(args.csv_path)
    print(format_report(report))
    return 1 if args.strict and _has_strict_issues(report) else 0


if __name__ == "__main__":
    raise SystemExit(main())
