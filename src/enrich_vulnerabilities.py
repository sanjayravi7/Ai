"""Join verified KEV and EPSS snapshots to the cleaned historical CVE dataset.

Design rules:

* Every row of ``data/processed/vulnerabilities_clean.csv`` is preserved, in
  order. Unmatched CVEs are kept with blank ``ti_`` fields; they are *not*
  treated as negative labels.
* Original (historical) columns are copied verbatim as text. All current
  threat-intelligence fields carry a ``ti_`` prefix so they cannot be mistaken
  for 2019-era data.
* A blank ``ti_kev_listed`` / ``ti_epss_matched`` cell means the source was not
  ingested; ``False`` means the complete snapshot was checked and the CVE was
  absent from it.
* Join keys are normalized CVE identifiers. Source keys are unique (validated
  upstream), so the join cannot multiply rows; this is asserted.
* Output depends only on the dataset and the snapshot files named in the
  manifests, so identical inputs give byte-identical outputs.

Usage::

    python -m src.enrich_vulnerabilities
    python -m src.enrich_vulnerabilities --allow-missing-sources   # EPSS not yet ingested
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pandas as pd

from .fetch_threat_intelligence import (
    DEFAULT_SNAPSHOT_ROOT,
    list_manifests,
    verify_snapshot,
)
from .threat_intel_sources import (
    CVE_ID_PATTERN,
    EPSS_SOURCE,
    KEV_OUTPUT_COLUMNS,
    KEV_SOURCE,
    PARSERS,
    ParsedSnapshot,
    normalize_cve_id,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLEAN_PATH = PROJECT_ROOT / "data" / "processed" / "vulnerabilities_clean.csv"
DEFAULT_ENRICHED_PATH = PROJECT_ROOT / "data" / "processed" / "vulnerabilities_enriched_current.csv"
DEFAULT_COVERAGE_PATH = PROJECT_ROOT / "data" / "processed" / "threat_intel_coverage.json"
COVERAGE_SCHEMA_VERSION = 1
CVSS_BANDS = (
    ("0.0-3.9", 0.0, 4.0),
    ("4.0-6.9", 4.0, 7.0),
    ("7.0-8.9", 7.0, 9.0),
    ("9.0-10.0", 9.0, 10.0001),
)
KEV_TI_COLUMNS = (
    "ti_kev_listed",
    "ti_kev_date_added",
    "ti_kev_vendor_project",
    "ti_kev_product",
    "ti_kev_vulnerability_name",
    "ti_kev_short_description",
    "ti_kev_required_action",
    "ti_kev_due_date",
    "ti_kev_known_ransomware_campaign_use",
    "ti_kev_cwes",
    "ti_kev_snapshot_date",
)
EPSS_TI_COLUMNS = (
    "ti_epss_matched",
    "ti_epss_score",
    "ti_epss_percentile",
    "ti_epss_model_version",
    "ti_epss_snapshot_date",
)
TI_COLUMNS = KEV_TI_COLUMNS + EPSS_TI_COLUMNS


class MissingSnapshotError(RuntimeError):
    """A required threat-intelligence snapshot has not been fetched."""


def _blank(values: pd.Series) -> pd.Series:
    return values.isna() | values.astype(str).str.strip().eq("")


def read_clean_dataset(path: Path) -> pd.DataFrame:
    """Read the clean CSV as text so every original cell is preserved exactly."""
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "cve_id" not in frame.columns:
        raise ValueError(f"{path} lacks a 'cve_id' column; run python -m src.preprocess_data first.")
    overlap = [column for column in TI_COLUMNS if column in frame.columns]
    if overlap:
        raise ValueError(f"Clean dataset already contains threat-intel columns: {overlap}")
    return frame


def select_manifest(
    source: str,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    explicit: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Return the explicit manifest, or the newest verified manifest for ``source``."""
    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            raise MissingSnapshotError(f"{source.upper()} manifest not found: {path}")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["_manifest_path"] = str(path)
        return manifest
    manifests = list_manifests(source, root)
    return manifests[-1] if manifests else None


def load_verified_snapshot(manifest: Dict[str, Any]) -> Tuple[ParsedSnapshot, Dict[str, Any]]:
    """Checksum-verify and re-validate a snapshot before any join uses it."""
    path = verify_snapshot(manifest)
    parsed = PARSERS[manifest["source"]](path.read_bytes())
    if parsed.metadata["snapshot_date"] != manifest["snapshot_date"]:
        raise ValueError(
            f"Manifest snapshot_date {manifest['snapshot_date']} disagrees with file content "
            f"{parsed.metadata['snapshot_date']} for {path}"
        )
    return parsed, _source_summary(manifest, parsed)


def _source_summary(manifest: Dict[str, Any], parsed: ParsedSnapshot) -> Dict[str, Any]:
    return {
        "source": manifest["source"],
        "status": "ingested",
        "requested_url": manifest["requested_url"],
        "final_url": manifest["final_url"],
        "declared_origin": manifest.get("declared_origin"),
        "retrieval_method": manifest["retrieval_method"],
        "retrieved_utc": manifest["retrieved_utc"],
        "snapshot_date": manifest["snapshot_date"],
        "file": manifest["file"],
        "sha256": manifest["sha256"],
        "bytes": manifest["bytes"],
        "metadata": parsed.metadata,
        "validation_findings": parsed.findings,
    }


def _not_ingested(source: str, reason: str) -> Dict[str, Any]:
    return {"source": source, "status": "not_ingested", "reason": reason}


def _format_float(value: Any) -> str:
    if value is None or pd.isna(value):
        return ""
    return repr(float(value))


def _pct(numerator: int, denominator: int) -> Optional[float]:
    if not denominator:
        return None
    return round(100.0 * numerator / denominator, 4)


def _stats(series: pd.Series) -> Dict[str, Any]:
    values = pd.to_numeric(series, errors="coerce").dropna()
    if values.empty:
        return {"count": 0}
    return {
        "count": int(len(values)),
        "min": _round(values.min()),
        "p10": _round(values.quantile(0.10)),
        "p25": _round(values.quantile(0.25)),
        "median": _round(values.median()),
        "mean": _round(values.mean()),
        "p75": _round(values.quantile(0.75)),
        "p90": _round(values.quantile(0.90)),
        "p99": _round(values.quantile(0.99)),
        "max": _round(values.max()),
    }


def _round(value: Any) -> Optional[float]:
    if value is None or pd.isna(value):
        return None
    return float("{:.6g}".format(float(value)))


RANKING_TOP_K = (100, 1000, 10000)
# Documented in FIRST's EPSS data page: no scores exist before 2021-04-14, and later
# dates are model-version boundaries. Used as candidate as-of dates for label feasibility.
EPSS_FIRST_SCORE_DATE = "2021-04-14"
FEASIBILITY_AS_OF_DATES = ("2021-04-14", "2022-02-04", "2023-03-07", "2025-03-17")
FEASIBILITY_HORIZON_DAYS = (30, 365)


def _temporal_label_feasibility(pub: pd.Series, kev_added: pd.Series) -> Dict[str, Any]:
    """Count time-aligned KEV positives for candidate as-of dates and horizons.

    A dataset CVE is eligible at as-of date T if published on or before T. It is a
    positive for horizon H if its KEV dateAdded lies in (T, T + H]. This assumes the
    current catalog's dateAdded values are the historical listing dates (no removals)
    and counts only; no model is fitted.
    """
    rows = []
    for as_of in FEASIBILITY_AS_OF_DATES:
        threshold = pd.Timestamp(as_of)
        eligible = pub.dt.normalize() <= threshold
        for horizon in FEASIBILITY_HORIZON_DAYS:
            window_end = threshold + pd.Timedelta(days=horizon)
            positives = eligible & (kev_added > threshold) & (kev_added <= window_end)
            eligible_count = int(eligible.sum())
            positive_count = int(positives.sum())
            rows.append(
                {
                    "as_of_date": as_of,
                    "horizon_days": horizon,
                    "eligible_cves": eligible_count,
                    "positive_cves": positive_count,
                    "positive_rate_pct": _pct(positive_count, eligible_count),
                }
            )
    return {
        "method": (
            "Eligible = published on/before as_of_date. Positive = KEV dateAdded in (as_of_date, as_of_date + horizon]. "
            "Counts only; no model is trained or evaluated."
        ),
        "caveat": (
            "dateAdded is a catalog listing date. Entries on the initial 2021-11-03 publication were "
            "retrospective listings, so their dateAdded does not show when exploitation began."
        ),
        "epss_first_score_date": EPSS_FIRST_SCORE_DATE,
        "rows": rows,
    }


def _cvss_ranking_diagnostic(cvss: pd.Series, keys: pd.Series, positives: pd.Series) -> Dict[str, Any]:
    """Score the existing CVSS-descending baseline against KEV listing (no model fitted).

    KEV presence is positive-only evidence, so the negatives here are unlabelled
    rather than confirmed safe. These figures describe how the fixed CVSS ordering
    concentrates KEV-listed CVEs; they are not a predictive performance estimate.
    Ties follow the baseline rule (cve_id ascending).
    """
    frame = pd.DataFrame({"score": cvss, "cve": keys, "positive": positives}).dropna(subset=["score"])
    total = len(frame)
    n_positive = int(frame["positive"].sum())
    n_negative = total - n_positive
    result: Dict[str, Any] = {
        "scored_rows": int(total),
        "listed_positive_rows": n_positive,
        "unlabelled_rows": int(n_negative),
        "label_definition": "KEV-listed in the snapshot = positive; not listed = unlabelled (not a confirmed negative).",
        "ordering": "CVSS descending, ties by cve_id ascending (matches the baseline ranking).",
        "not_a_model_evaluation": True,
    }
    if n_positive == 0 or n_negative == 0:
        result["roc_auc_cvss_as_score"] = None
        result["recall_at_k"] = []
        return result
    ranks = frame["score"].rank(method="average")
    auc = (ranks[frame["positive"]].sum() - n_positive * (n_positive + 1) / 2) / (n_positive * n_negative)
    result["roc_auc_cvss_as_score"] = round(float(auc), 4)
    ordered = frame.sort_values(["score", "cve"], ascending=[False, True], kind="mergesort")
    recalls = []
    for k in RANKING_TOP_K:
        if k > total:
            continue
        hits = int(ordered["positive"].head(k).sum())
        recalls.append(
            {"k": k, "listed_in_top_k": hits, "recall": round(hits / n_positive, 4), "precision_lower_bound": round(hits / k, 6)}
        )
    result["recall_at_k"] = recalls
    return result


def enriched_kev_dates(dataset: pd.DataFrame, kev: ParsedSnapshot) -> pd.Series:
    """Per-row KEV dateAdded aligned to dataset order (blank where unmatched)."""
    indexed = kev.frame.set_index("cve_id")["kev_date_added"]
    keys = dataset["cve_id"].map(normalize_cve_id)
    return keys.map(indexed).fillna("")


def _dateadded_concentration(kev: ParsedSnapshot, kev_mask: pd.Series, keys: pd.Series) -> Dict[str, Any]:
    """Show how many entries share the earliest catalog dateAdded (initial load)."""
    dates = kev.frame["kev_date_added"]
    earliest = dates.min()
    listed_dates = keys[kev_mask].map(kev.frame.set_index("cve_id")["kev_date_added"])
    return {
        "earliest_date_added": earliest,
        "catalog_entries_on_earliest_date": int((dates == earliest).sum()),
        "dataset_rows_listed_on_earliest_date": int((listed_dates == earliest).sum()),
        "interpretation": (
            "The earliest date is the catalog's initial publication; those entries are retrospective "
            "listings, so their dateAdded is not an exploitation-onset date."
        ),
    }


def _cvss_band(score: Any) -> str:
    if score is None or pd.isna(score):
        return "<MISSING>"
    for label, low, high in CVSS_BANDS:
        if low <= score < high:
            return label
    return "<OUT_OF_RANGE>"


def enrich_dataset(
    dataset: pd.DataFrame,
    kev: Optional[ParsedSnapshot] = None,
    epss: Optional[ParsedSnapshot] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Return the enriched frame and a coverage report; ``dataset`` is not mutated."""
    if dataset.empty:
        raise ValueError("Clean dataset has no rows to enrich.")
    rows_input = len(dataset)
    enriched = dataset.copy(deep=True)

    normalized_ids = dataset["cve_id"].map(normalize_cve_id)
    invalid = normalized_ids.isna()
    if bool(invalid.any()):
        raise ValueError(
            f"{int(invalid.sum())} dataset rows have malformed cve_id values; "
            f"examples={dataset.loc[invalid, 'cve_id'].head(10).tolist()}"
        )
    enriched["__cve_key"] = normalized_ids
    dataset_key_counts = normalized_ids.value_counts()
    duplicate_keys = dataset_key_counts[dataset_key_counts > 1]

    report: Dict[str, Any] = {
        "coverage_schema_version": COVERAGE_SCHEMA_VERSION,
        "join_key": "normalized CVE identifier (trimmed, upper-case, CVE-YYYY-NNNN+)",
        "join_key_pattern": CVE_ID_PATTERN.pattern,
        "dataset": {
            "input_file_rows": int(rows_input),
            "unique_cve_ids": int(dataset_key_counts.size),
            "duplicate_cve_id_count": int(len(duplicate_keys)),
            "duplicate_cve_id_rows": int(duplicate_keys.sum()),
            "duplicate_cve_id_examples": sorted(duplicate_keys.index.tolist())[:10],
        },
        "rules": {
            "unmatched_policy": "Unmatched CVEs are retained with blank ti_ fields; absence is not a negative label.",
            "ti_prefix": "Current threat-intelligence fields are prefixed 'ti_'; historical fields are unchanged.",
            "blank_ti_kev_listed": "KEV not ingested for this run.",
            "blank_ti_epss_matched": "EPSS not ingested for this run.",
        },
        "sources": {},
    }

    # --- KEV ---------------------------------------------------------------
    if kev is None:
        for column in KEV_TI_COLUMNS:
            enriched[column] = ""
        report["sources"][KEV_SOURCE] = _not_ingested(KEV_SOURCE, "No KEV snapshot supplied.")
        kev_mask = pd.Series(False, index=enriched.index)
    else:
        kev_indexed = kev.frame.set_index("cve_id")
        if not kev_indexed.index.is_unique:
            raise ValueError("KEV frame has duplicate CVE identifiers; refusing ambiguous join.")
        kev_mask = enriched["__cve_key"].isin(kev_indexed.index)
        enriched["ti_kev_listed"] = kev_mask.map({True: "True", False: "False"})
        enriched["ti_kev_snapshot_date"] = kev.metadata["snapshot_date"]
        for source_column in KEV_OUTPUT_COLUMNS[1:]:
            target = "ti_" + source_column
            mapped = enriched["__cve_key"].map(kev_indexed[source_column])
            enriched[target] = mapped.where(kev_mask, "").fillna("").astype(str)
        report["sources"][KEV_SOURCE] = {"status": "ingested", **kev_source_info(kev)}

    # --- EPSS --------------------------------------------------------------
    if epss is None:
        for column in EPSS_TI_COLUMNS:
            enriched[column] = ""
        report["sources"][EPSS_SOURCE] = _not_ingested(EPSS_SOURCE, "No EPSS snapshot supplied.")
        epss_mask = pd.Series(False, index=enriched.index)
    else:
        epss_indexed = epss.frame.set_index("cve_id")
        if not epss_indexed.index.is_unique:
            raise ValueError("EPSS frame has duplicate CVE identifiers; refusing ambiguous join.")
        epss_mask = enriched["__cve_key"].isin(epss_indexed.index)
        enriched["ti_epss_matched"] = epss_mask.map({True: "True", False: "False"})
        scores = enriched["__cve_key"].map(epss_indexed["epss_score"])
        percentiles = enriched["__cve_key"].map(epss_indexed["epss_percentile"])
        enriched["ti_epss_score"] = [
            _format_float(value) if matched else "" for value, matched in zip(scores, epss_mask)
        ]
        enriched["ti_epss_percentile"] = [
            _format_float(value) if matched else "" for value, matched in zip(percentiles, epss_mask)
        ]
        enriched["ti_epss_model_version"] = epss.metadata["model_version"]
        enriched["ti_epss_snapshot_date"] = epss.metadata["snapshot_date"]
        report["sources"][EPSS_SOURCE] = {"status": "ingested", **epss_source_info(epss)}

    # --- Join integrity ----------------------------------------------------
    if len(enriched) != rows_input:
        raise AssertionError("Enrichment changed the row count; join is not one-to-one.")
    for column in dataset.columns:
        if not enriched[column].equals(dataset[column]):
            raise AssertionError(f"Original column {column!r} was modified during enrichment.")

    enriched = enriched.drop(columns=["__cve_key"])
    enriched = enriched.fillna("")
    report["join"] = {
        "rows_input": int(rows_input),
        "rows_output": int(len(enriched)),
        "rows_preserved": bool(len(enriched) == rows_input),
        "rows_dropped": 0,
        "source_duplicate_key_conflicts": 0,
        "note": "Source keys are unique (validated); each dataset row joins to at most one record per source.",
    }

    report["coverage"] = _coverage(dataset, enriched, kev, epss, kev_mask, epss_mask)
    report["examples"] = _examples(enriched, kev, epss)
    report["ti_column_missingness"] = _missingness(enriched)
    return enriched, report


def kev_source_info(kev: ParsedSnapshot) -> Dict[str, Any]:
    return {
        "catalog_version": kev.metadata["catalog_version"],
        "date_released_utc": kev.metadata["date_released_utc"],
        "snapshot_date": kev.metadata["snapshot_date"],
        "record_count": kev.metadata["record_count"],
        "unique_cve_ids": kev.findings["unique_cve_ids"],
        "validation_findings": kev.findings,
    }


def epss_source_info(epss: ParsedSnapshot) -> Dict[str, Any]:
    return {
        "model_version": epss.metadata["model_version"],
        "score_date_utc": epss.metadata["score_date_utc"],
        "snapshot_date": epss.metadata["snapshot_date"],
        "record_count": epss.metadata["record_count"],
        "unique_cve_ids": epss.findings["unique_cve_ids"],
        "validation_findings": epss.findings,
    }


def _coverage(
    dataset: pd.DataFrame,
    enriched: pd.DataFrame,
    kev: Optional[ParsedSnapshot],
    epss: Optional[ParsedSnapshot],
    kev_mask: pd.Series,
    epss_mask: pd.Series,
) -> Dict[str, Any]:
    total_rows = len(dataset)
    keys = dataset["cve_id"].map(normalize_cve_id)
    unique_keys = set(keys.tolist())
    pub = pd.to_datetime(dataset.get("pub_date", pd.Series(dtype=str)), errors="coerce")
    mod = pd.to_datetime(dataset.get("mod_date", pd.Series(dtype=str)), errors="coerce")
    cvss = pd.to_numeric(dataset.get("cvss", pd.Series(dtype=str)), errors="coerce")
    cutoff = pub.max()

    summary_text = dataset["summary"].astype(str) if "summary" in dataset.columns else pd.Series("", index=dataset.index)
    reject_placeholder = summary_text.str.startswith("** REJECT **")
    disputed = summary_text.str.contains("** DISPUTED **", regex=False)
    reject_cvss = cvss[reject_placeholder]

    coverage: Dict[str, Any] = {
        "data_quality": {
            "reject_placeholder_rows": int(reject_placeholder.sum()),
            "reject_placeholder_cvss_values": {
                str(k): int(v) for k, v in reject_cvss.value_counts(dropna=False).sort_index().items()
            },
            "disputed_marker_rows": int(disputed.sum()),
            "note": (
                "'** REJECT **' records are withdrawn candidate entries kept in the source; they are "
                "reported, not removed. Their CVSS values affect the CVSS baseline and should be reviewed."
            ),
        },
        "dataset_rows": int(total_rows),
        "dataset_unique_cves": len(unique_keys),
        "dataset_pub_date_range": [
            None if pd.isna(pub.min()) else pub.min().strftime("%Y-%m-%d"),
            None if pd.isna(pub.max()) else pub.max().strftime("%Y-%m-%d"),
        ],
        "dataset_latest_mod_date": None if pd.isna(mod.max()) else mod.max().strftime("%Y-%m-%d"),
        "cvss_band_definitions": [label for label, _, _ in CVSS_BANDS],
    }

    if kev is not None:
        listed_rows = int(kev_mask.sum())
        matched_keys = set(keys[kev_mask].tolist())
        catalog_ids = set(kev.frame["cve_id"])
        kev_frame = kev.frame.set_index("cve_id")
        matched_frame = kev_frame.loc[sorted(matched_keys)] if matched_keys else kev_frame.iloc[0:0]
        added = pd.to_datetime(matched_frame["kev_date_added"], errors="coerce")
        # Compare calendar dates so time-of-day in pub_date cannot shift the lag.
        pub_by_key = pd.Series(pub.dt.normalize().values, index=keys.values)
        pub_by_key = pub_by_key[~pub_by_key.index.duplicated(keep="first")]
        lag_days = (added - pub_by_key.reindex(matched_frame.index)).dt.days
        ransomware = matched_frame["kev_known_ransomware_campaign_use"].replace("", "<BLANK>")
        ransomware_counts = {str(k): int(v) for k, v in ransomware.value_counts().sort_index().items()}
        year_table = []
        years = pub.dt.year
        kev_years = pd.Series(kev_mask.values, index=years.index)
        for year in sorted(years.dropna().unique().astype(int).tolist()):
            in_year = years.eq(year)
            hits = int((kev_years & in_year).sum())
            total_year = int(in_year.sum())
            year_table.append(
                {"pub_year": year, "records": total_year, "kev_listed": hits, "kev_listed_pct": _pct(hits, total_year)}
            )
        band_table = []
        bands = cvss.map(_cvss_band)
        for label in [band for band, _, _ in CVSS_BANDS] + ["<MISSING>"]:
            in_band = bands.eq(label)
            hits = int((kev_mask & in_band).sum())
            total_band = int(in_band.sum())
            band_table.append(
                {"cvss_band": label, "records": total_band, "kev_listed": hits, "kev_listed_pct": _pct(hits, total_band)}
            )
        coverage["kev"] = {
            "catalog_records": int(len(kev.frame)),
            "catalog_unique_cves": len(catalog_ids),
            "dataset_rows_listed": listed_rows,
            "dataset_rows_listed_pct": _pct(listed_rows, total_rows),
            "dataset_unique_cves_listed": len(matched_keys),
            "dataset_unique_cves_listed_pct": _pct(len(matched_keys), len(unique_keys)),
            "dataset_rows_not_listed": int(total_rows - listed_rows),
            "dataset_rows_not_listed_pct": _pct(total_rows - listed_rows, total_rows),
            "dataset_rows_not_listed_reject_placeholders": int((reject_placeholder & ~kev_mask).sum()),
            "catalog_entries_not_in_dataset": len(catalog_ids - unique_keys),
            "catalog_entries_not_in_dataset_pct": _pct(len(catalog_ids - unique_keys), len(catalog_ids)),
            "catalog_earliest_date_added": (
                None if kev.frame.empty else str(kev.frame["kev_date_added"].min())
            ),
            "catalog_entries_dated_after_dataset_latest_pub_date": int(
                (pd.to_datetime(kev.frame["kev_date_added"], errors="coerce") > cutoff).sum()
            ) if not pd.isna(cutoff) else None,
            "listed_ransomware_campaign_use": ransomware_counts,
            "lag_days_kev_date_added_minus_pub_date": {
                **_stats(lag_days),
                "negative_lag_count": int((lag_days < 0).sum()),
            },
            "cvss_band_listing_rates": band_table,
            "cvss_ranking_diagnostic": _cvss_ranking_diagnostic(cvss, keys, kev_mask),
            "dateadded_concentration": _dateadded_concentration(kev, kev_mask, keys),
            "pub_year_listing_rates": year_table,
            "interpretation": (
                "KEV presence is positive evidence of known exploitation as of the snapshot. "
                "Absence means 'not listed in this catalog snapshot', not 'never exploited'. "
                "dateAdded is the catalog addition date, not the exploitation start date."
            ),
        }
    else:
        coverage["kev"] = {"status": "not_ingested"}

    if kev is not None:
        coverage["temporal_label_feasibility"] = _temporal_label_feasibility(
            pub, pd.to_datetime(enriched_kev_dates(dataset, kev), errors="coerce")
        )
    else:
        coverage["temporal_label_feasibility"] = {"status": "not_ingested"}

    if epss is not None:
        matched_keys = set(keys[epss_mask].tolist())
        epss_frame = epss.frame
        epss_ids = set(epss_frame["cve_id"])
        matched_scores = pd.to_numeric(enriched.loc[epss_mask, "ti_epss_score"], errors="coerce")
        matched_pct = pd.to_numeric(enriched.loc[epss_mask, "ti_epss_percentile"], errors="coerce")
        matched_kev = kev_mask[epss_mask]
        coverage["epss"] = {
            "snapshot_model_version": epss.metadata["model_version"],
            "snapshot_score_date_utc": epss.metadata["score_date_utc"],
            "catalog_records": int(len(epss_frame)),
            "dataset_rows_matched": int(epss_mask.sum()),
            "dataset_rows_matched_pct": _pct(int(epss_mask.sum()), total_rows),
            "dataset_rows_unmatched": int(total_rows - epss_mask.sum()),
            "dataset_rows_unmatched_pct": _pct(total_rows - int(epss_mask.sum()), total_rows),
            "dataset_rows_unmatched_reject_placeholders": int((reject_placeholder & ~epss_mask).sum()),
            "dataset_rows_unmatched_other": int((~reject_placeholder & ~epss_mask).sum()),
            "dataset_unique_cves_matched": len(matched_keys),
            "catalog_entries_not_in_dataset": len(epss_ids - unique_keys),
            "matched_score_distribution": _stats(matched_scores),
            "matched_percentile_distribution": _stats(matched_pct),
            "matched_score_by_kev_listing": {
                "kev_listed": _stats(matched_scores[matched_kev.values]),
                "not_kev_listed": _stats(matched_scores[~matched_kev.values]),
            },
            "temporal_caveat": (
                "EPSS scores are model estimates computed at score_date_utc, years after most "
                "dataset CVEs were published. They are not historical 2019-era scores and must not "
                "be used as features for predicting outcomes that precede score_date_utc."
            ),
        }
    else:
        coverage["epss"] = {"status": "not_ingested"}

    return coverage


def _examples(enriched: pd.DataFrame, kev: Optional[ParsedSnapshot], epss: Optional[ParsedSnapshot]) -> Dict[str, Any]:
    examples: Dict[str, Any] = {}
    if kev is not None:
        listed = enriched[enriched["ti_kev_listed"] == "True"].sort_values("cve_id", kind="mergesort")
        examples["kev_matches"] = listed.head(5)[
            ["cve_id", "cvss", "pub_date", "ti_kev_date_added", "ti_kev_vendor_project",
             "ti_kev_product", "ti_kev_due_date", "ti_kev_known_ransomware_campaign_use"]
        ].to_dict(orient="records")
    if epss is not None:
        matched = enriched[enriched["ti_epss_matched"] == "True"].copy()
        matched["__score"] = pd.to_numeric(matched["ti_epss_score"], errors="coerce")
        top = matched.sort_values(["__score", "cve_id"], ascending=[False, True], kind="mergesort").head(5)
        examples["epss_matches_highest_score"] = top[
            ["cve_id", "cvss", "ti_epss_score", "ti_epss_percentile", "ti_epss_model_version", "ti_kev_listed"]
        ].to_dict(orient="records")
    return examples


def _missingness(enriched: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
    total = len(enriched)
    table = {}
    for column in TI_COLUMNS:
        if column not in enriched.columns:
            continue
        blanks = int(_blank(enriched[column]).sum())
        table[column] = {"blank_count": blanks, "blank_pct": _pct(blanks, total)}
    return table


def run_enrichment(
    clean_path: Path = DEFAULT_CLEAN_PATH,
    output_path: Path = DEFAULT_ENRICHED_PATH,
    coverage_path: Path = DEFAULT_COVERAGE_PATH,
    *,
    snapshot_root: Path = DEFAULT_SNAPSHOT_ROOT,
    kev_manifest: Optional[Path] = None,
    epss_manifest: Optional[Path] = None,
    allow_missing_sources: bool = False,
) -> Dict[str, Any]:
    clean_path = Path(clean_path)
    output_path = Path(output_path)
    coverage_path = Path(coverage_path)
    for path in (output_path, coverage_path):
        if path.resolve() == clean_path.resolve():
            raise ValueError("Enrichment outputs must not overwrite the clean dataset.")
    if output_path.resolve() == coverage_path.resolve():
        raise ValueError("Enriched CSV and coverage JSON must be different files.")

    dataset = read_clean_dataset(clean_path)

    loaded: Dict[str, Tuple[Optional[ParsedSnapshot], Dict[str, Any]]] = {}
    for source, explicit in ((KEV_SOURCE, kev_manifest), (EPSS_SOURCE, epss_manifest)):
        manifest = select_manifest(source, snapshot_root, explicit)
        if manifest is None:
            if not allow_missing_sources:
                raise MissingSnapshotError(
                    f"No {source.upper()} snapshot found under {snapshot_root / source}. "
                    "Run: python -m src.fetch_threat_intelligence --source "
                    f"{source}  (or pass --allow-missing-sources to enrich without it)."
                )
            loaded[source] = (None, {})
            continue
        loaded[source] = load_verified_snapshot(manifest)

    kev_snapshot, _ = loaded[KEV_SOURCE]
    epss_snapshot, _ = loaded[EPSS_SOURCE]
    enriched, report = enrich_dataset(dataset, kev=kev_snapshot, epss=epss_snapshot)

    # Attach provenance from the checksum-verified manifests used for the join.
    for source in (KEV_SOURCE, EPSS_SOURCE):
        _, summary = loaded[source]
        if summary:
            report["sources"][source].update(summary)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    enriched.to_csv(output_path, index=False)
    report["input_file"] = _relative(clean_path)
    report["output_file"] = _relative(output_path)
    report["coverage_file"] = _relative(coverage_path)
    coverage_path.parent.mkdir(parents=True, exist_ok=True)
    coverage_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, default=_json_default) + "\n",
        encoding="utf-8",
    )
    return report


def _relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _json_default(value: Any) -> Any:
    if isinstance(value, (pd.Timestamp,)):
        return value.isoformat()
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Not JSON serializable: {type(value)!r}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Enrich the clean CVE dataset with KEV and EPSS snapshots without dropping rows."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_CLEAN_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_ENRICHED_PATH)
    parser.add_argument("--coverage-output", type=Path, default=DEFAULT_COVERAGE_PATH)
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--kev-manifest", type=Path, help="Use this KEV manifest instead of the newest snapshot.")
    parser.add_argument("--epss-manifest", type=Path, help="Use this EPSS manifest instead of the newest snapshot.")
    parser.add_argument(
        "--allow-missing-sources",
        action="store_true",
        help="Proceed when a source has no snapshot; its ti_ fields stay blank and it is reported as not_ingested.",
    )
    args = parser.parse_args(argv)

    try:
        report = run_enrichment(
            args.input,
            args.output,
            args.coverage_output,
            snapshot_root=args.snapshot_root,
            kev_manifest=args.kev_manifest,
            epss_manifest=args.epss_manifest,
            allow_missing_sources=args.allow_missing_sources,
        )
    except (MissingSnapshotError, ValueError, OSError) as error:
        print(f"ERROR: {error}")
        return 1

    join = report["join"]
    print(f"Enriched rows: {join['rows_output']:,} of {join['rows_input']:,} (preserved={join['rows_preserved']})")
    kev = report["coverage"]["kev"]
    if "dataset_rows_listed" in kev:
        print(f"KEV listed: {kev['dataset_rows_listed']:,} rows ({kev['dataset_rows_listed_pct']}%)")
    else:
        print("KEV: not ingested")
    epss = report["coverage"]["epss"]
    if "dataset_rows_matched" in epss:
        print(f"EPSS matched: {epss['dataset_rows_matched']:,} rows ({epss['dataset_rows_matched_pct']}%)")
    else:
        print("EPSS: not ingested")
    print(f"Enriched CSV: {args.output}")
    print(f"Coverage JSON: {args.coverage_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
