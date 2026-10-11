"""A transparent CVSS-descending ranking baseline (not an exploitation model)."""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_PATH = PROJECT_ROOT / "data" / "processed" / "vulnerabilities_clean.csv"
DEFAULT_RANKED_PATH = PROJECT_ROOT / "data" / "processed" / "vulnerabilities_ranked.csv"
DEFAULT_SUMMARY_PATH = PROJECT_ROOT / "data" / "processed" / "baseline_summary.json"


def _missing_mask(values: pd.Series) -> pd.Series:
    blank = values.astype("string").str.strip().eq("").fillna(False)
    return (values.isna() | blank).astype(bool)


def rank_by_cvss(frame: pd.DataFrame) -> pd.DataFrame:
    """Return every row ranked by CVSS descending, with deterministic ties.

    Non-empty, non-numeric CVSS values and numeric values outside [0, 10] are
    rejected to avoid silently producing a misleading ranking. Missing scores
    are retained at the bottom. Equal scores are ordered by ``cve_id`` and then
    by their original input order. The only ranking signal is ``cvss``.
    """
    missing_columns = [
        column for column in ("cve_id", "cvss") if column not in frame.columns
    ]
    if missing_columns:
        raise ValueError(
            "Ranking requires the observed columns 'cve_id' and 'cvss'; missing: "
            + ", ".join(missing_columns)
        )
    if "baseline_rank" in frame.columns:
        raise ValueError("Input already contains 'baseline_rank'; refusing to overwrite it.")

    original_scores = frame["cvss"]
    score_missing = _missing_mask(original_scores)
    scores = pd.to_numeric(original_scores.where(~score_missing), errors="coerce")
    non_numeric = (~score_missing) & scores.isna()
    if bool(non_numeric.any()):
        examples = [str(value) for value in original_scores.loc[non_numeric].head(10).tolist()]
        raise ValueError(
            f"CVSS contains {int(non_numeric.sum())} non-numeric non-missing value(s); "
            f"examples={examples}"
        )

    in_range = scores.between(0, 10).fillna(False)
    out_of_range = scores.notna() & (~in_range)
    if bool(out_of_range.any()):
        examples = [str(value) for value in original_scores.loc[out_of_range].head(10).tolist()]
        raise ValueError(
            f"CVSS contains {int(out_of_range.sum())} value(s) outside [0, 10]; "
            f"examples={examples}"
        )

    ranked = frame.copy(deep=True)
    ranked["cvss"] = scores
    ranked["__vulnova_cve_sort"] = ranked["cve_id"].astype("string").fillna("")
    ranked["__vulnova_source_order"] = range(len(ranked))
    ranked = ranked.sort_values(
        by=["cvss", "__vulnova_cve_sort", "__vulnova_source_order"],
        ascending=[False, True, True],
        na_position="last",
        kind="mergesort",
    )
    ranked = ranked.drop(
        columns=["__vulnova_cve_sort", "__vulnova_source_order"]
    ).reset_index(drop=True)
    ranked.insert(0, "baseline_rank", range(1, len(ranked) + 1))
    return ranked


def _json_number(value: Any) -> Optional[float]:
    if pd.isna(value):
        return None
    # Shortest useful representation avoids exposing binary floating-point
    # artifacts such as 1.7000000000000002 in the JSON summary.
    return float("{:.12g}".format(float(value)))


def build_summary(
    source_frame: pd.DataFrame,
    ranked_frame: pd.DataFrame,
    input_path: Optional[str] = None,
    ranked_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Build deterministic, machine-readable metadata for the ranking output."""
    scores = pd.to_numeric(ranked_frame["cvss"], errors="coerce")
    numeric_scores = scores.dropna()
    score_counts = numeric_scores.value_counts().sort_index()
    score_distribution = [
        {"cvss": _json_number(score), "record_count": int(count)}
        for score, count in score_counts.items()
    ]
    missing_score_count = int(scores.isna().sum())

    first_record = ranked_frame.iloc[0] if len(ranked_frame) else None
    top_record = None
    if first_record is not None:
        top_record = {
            "cve_id": None if pd.isna(first_record["cve_id"]) else str(first_record["cve_id"]),
            "cvss": _json_number(first_record["cvss"]),
        }

    summary = {
        "baseline": "cvss_descending_ranking",
        "task_type": "ranking_only",
        "score_column": "cvss",
        "score_range_checked": [0, 10],
        "ranking_rule": "CVSS descending; missing scores last",
        "tie_break_rule": "cve_id ascending, then original input order",
        "rows_input": int(len(source_frame)),
        "rows_ranked": int(len(ranked_frame)),
        "rows_dropped": int(len(source_frame) - len(ranked_frame)),
        "missing_cvss_count": missing_score_count,
        "cvss_min": _json_number(numeric_scores.min()) if len(numeric_scores) else None,
        "cvss_max": _json_number(numeric_scores.max()) if len(numeric_scores) else None,
        "cvss_mean": _json_number(numeric_scores.mean()) if len(numeric_scores) else None,
        "cvss_median": _json_number(numeric_scores.median()) if len(numeric_scores) else None,
        "score_distribution": score_distribution,
        "top_ranked_record": top_record,
        "input_columns": [str(column) for column in source_frame.columns],
        "exploitation_label_column": None,
        "exploitation_prediction": False,
        "severity_column_present": "severity" in source_frame.columns,
        "epss_score_column_present": "epss_score" in source_frame.columns,
        "cvss_version": "not specified in the source dataset",
        "limitations": [
            "This is a CVSS-based prioritization ranking, not an exploitation prediction.",
            "The source has no exploitation label, severity column, or epss_score field.",
            "CVSS version and score provenance are not specified in the bundled CSV.",
            "No predictive model, target label, or model-performance estimate is used.",
        ],
    }
    if input_path is not None:
        summary["input_file"] = str(input_path)
    if ranked_path is not None:
        summary["ranked_file"] = str(ranked_path)
    return summary


def create_baseline(
    frame: pd.DataFrame,
    input_path: Optional[str] = None,
    ranked_path: Optional[str] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Rank a DataFrame and return it with a no-label baseline summary."""
    ranked = rank_by_cvss(frame)
    summary = build_summary(frame, ranked, input_path=input_path, ranked_path=ranked_path)
    return ranked, summary


def _portable_path(path: Path) -> str:
    """Use repository-relative paths in generated metadata when possible."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _safe_output_path(input_path: Path, output_path: Path, label: str) -> None:
    if input_path.resolve() == output_path.resolve():
        raise ValueError(f"The {label} output path must not overwrite the input CSV.")


def run_baseline(
    input_path: Path = DEFAULT_INPUT_PATH,
    ranked_path: Path = DEFAULT_RANKED_PATH,
    summary_path: Path = DEFAULT_SUMMARY_PATH,
) -> Dict[str, Any]:
    """Read the clean CSV and write ranked records plus a JSON summary."""
    input_path = Path(input_path)
    ranked_path = Path(ranked_path)
    summary_path = Path(summary_path)
    _safe_output_path(input_path, ranked_path, "ranked CSV")
    _safe_output_path(input_path, summary_path, "summary")
    if ranked_path.resolve() == summary_path.resolve():
        raise ValueError("Ranked CSV and summary paths must differ.")

    frame = pd.read_csv(input_path)
    ranked, summary = create_baseline(
        frame,
        input_path=_portable_path(input_path),
        ranked_path=_portable_path(ranked_path),
    )

    ranked_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    ranked.to_csv(ranked_path, index=False, na_rep="")
    summary["summary_file"] = _portable_path(summary_path)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Rank processed CVE records by CVSS; does not predict exploitation."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Preprocessed CSV (default: {DEFAULT_INPUT_PATH})",
    )
    parser.add_argument(
        "--ranked-output",
        type=Path,
        default=DEFAULT_RANKED_PATH,
        help=f"Ranked-record CSV (default: {DEFAULT_RANKED_PATH})",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=DEFAULT_SUMMARY_PATH,
        help=f"JSON baseline summary (default: {DEFAULT_SUMMARY_PATH})",
    )
    args = parser.parse_args(argv)

    summary = run_baseline(args.input, args.ranked_output, args.summary_output)
    print(
        "CVSS ranking complete: "
        f"{summary['rows_ranked']:,} records; "
        f"top={summary['top_ranked_record']}; "
        "ranking only, no exploitation prediction."
    )
    print(f"Ranked records: {args.ranked_output}")
    print(f"Machine-readable summary: {args.summary_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
