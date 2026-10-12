"""Audit withdrawn CVE records and apply an explicit status-aware ranking policy.

The bundled snapshot contains 17 records whose ``summary`` begins with
``** REJECT **``. Those are withdrawn candidate identifiers, and the CVSS value
they carry (5.0) is a placeholder rather than a vulnerability severity. This
module:

1. finds every such record without touching the raw dataset;
2. states each record's status from an authoritative, commit-pinned
   ``CVEProject/cvelistV5`` snapshot (rejected / reinstated / unverified);
3. ranks the dataset under an explicit policy that excludes confirmed-rejected
   records from the primary active-vulnerability ranking, keeps reinstated
   records eligible, treats unverified records conservatively, and leaves
   ``** DISPUTED **`` records and every other record exactly as ranked before;
4. keeps the untouched CVSS-descending baseline available for comparison
   (``src.baseline`` is not modified); and
5. writes regenerable, Git-ignored outputs plus a machine-readable summary.

Policy summary (also embedded in the JSON summary):

* ``** REJECT **`` + authoritative state ``REJECTED`` -> excluded from the
  primary ranking, preserved in ``rejected_cve_audit.csv``. Its CVSS value is
  never used as a ranking score.
* ``** REJECT **`` + authoritative state ``PUBLISHED`` -> eligible for ranking;
  the snapshot score is used only when it is not one of the placeholder values
  observed on confirmed-rejected records.
* ``** REJECT **`` with no confirmable authoritative state -> excluded from the
  primary ranking by default (``UNVERIFIED``), disclosed in the summary and the
  audit table. ``--include-unverified`` keeps them, ranked with a missing score.
* Every other record -> unchanged: CVSS descending, ties by ``cve_id`` then
  input order, missing scores last.
* ``** DISPUTED **`` records -> unchanged and reported separately.

Usage::

    python -m src.audit_rejected_cves
    python -m src.audit_rejected_cves --include-unverified --disputed-output PATH
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from .baseline import rank_by_cvss
from .cve_status_sources import (
    CveRecord,
    CveStatusValidationError,
    STATUS_REJECTED,
    STATUS_REINSTATED,
    STATUS_UNMARKED,
    STATUS_UNVERIFIED,
    classify_status,
    has_disputed_marker,
    is_reject_placeholder,
    marker_audit,
    parse_rejection_reason,
)
from .enrich_vulnerabilities import (
    MissingSnapshotError,
    load_verified_snapshot,
    select_manifest,
)
from .fetch_cve_status import (
    MissingStatusSnapshotError,
    load_status_snapshot,
    select_status_manifest,
)
from .fetch_threat_intelligence import DEFAULT_SNAPSHOT_ROOT, sha256_file
from .threat_intel_sources import EPSS_SOURCE, KEV_SOURCE, ParsedSnapshot, normalize_cve_id


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "processed"
DEFAULT_RAW_PATH = PROJECT_ROOT / "data" / "raw" / "vulnerabilities.csv"
DEFAULT_CLEAN_PATH = DATA_DIR / "vulnerabilities_clean.csv"
DEFAULT_BASELINE_RANKED_PATH = DATA_DIR / "vulnerabilities_ranked.csv"
DEFAULT_AUDIT_PATH = DATA_DIR / "rejected_cve_audit.csv"
DEFAULT_REVIEWED_PATH = DATA_DIR / "vulnerabilities_ranked_reviewed.csv"
DEFAULT_SUMMARY_PATH = DATA_DIR / "rejected_cve_summary.json"
DEFAULT_DISPUTED_PATH = DATA_DIR / "disputed_cve_report.csv"

SUMMARY_SCHEMA = "vulnova-rejected-cve-audit-1"
POLICY_VERSION = "vulnova-status-policy-1"
TOP_N_LEVELS = (10, 100, 1000, 10000)

DATASET_COLUMNS = (
    "cve_id",
    "mod_date",
    "pub_date",
    "cvss",
    "cwe_code",
    "cwe_name",
    "summary",
    "access_authentication",
    "access_complexity",
    "access_vector",
    "impact_availability",
    "impact_confidentiality",
    "impact_integrity",
)
POLICY_COPY_COLUMNS = (
    "record_status",
    "status_source",
    "ranking_eligible",
    "score_used_for_ranking",
    "score_note",
    "baseline_rank",
)
POLICY_COLUMNS = POLICY_COPY_COLUMNS + ("reviewed_rank", "rank_shift")
AUDIT_COLUMNS = (
    "cve_id",
    "record_status",
    "status_reason",
    "source_cvss",
    "cvss_genuine",
    "summary",
    "pub_date",
    "mod_date",
    "kev_listed",
    "kev_date_added",
    "epss_matched",
    "epss_score",
    "epss_percentile",
    "authoritative_record_present",
    "authoritative_state",
    "date_rejected",
    "date_published",
    "date_updated",
    "assigner_short_name",
    "rejection_reason_detail",
    "rejection_reason",
    "consult_ids",
    "authoritative_cvss",
    "verification_date_utc",
    "verification_source",
    "source_api_url",
    "source_url",
    "ranking_eligible",
    "ranking_decision",
    "exclusion_reason",
    "baseline_rank",
    "reviewed_rank",
)

EXCLUSION_CONFIRMED_REJECTED = "confirmed_rejected"
EXCLUSION_UNVERIFIED = "unverified_status"

LIMITATIONS = [
    "The audit verifies only records whose summary begins with '** REJECT **'. "
    "Other records are not status-checked and are labelled UNMARKED, not ACTIVE.",
    "Status verification is a point-in-time check of one commit of "
    "CVEProject/cvelistV5; CVE status can change after the recorded date.",
    "Exclusion changes prioritization only: no record is deleted, and the raw "
    "dataset and every original field are preserved unchanged.",
    "The dataset CVSS version is unspecified, so authoritative base scores from "
    "other CVSS versions are disclosed but never substituted into the ranking.",
    "The placeholder values are derived from the confirmed-rejected records of "
    "this snapshot and are not a general statement about CVSS 5.0.",
    "'** DISPUTED **' records are reported, not re-scored; their treatment is "
    "unchanged and their CVSS values still drive their rank.",
    "This is a ranking-policy correction, not an exploitation model, and it "
    "makes no prediction about which vulnerabilities are exploited.",
]


def _blank(values: pd.Series) -> pd.Series:
    return values.isna() | values.astype("string").str.strip().eq("").fillna(False)


def _json_number(value: Any) -> Optional[float]:
    """Return a JSON-safe number, or None for blank/non-numeric input."""
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        return None
    number = pd.to_numeric(value, errors="coerce")
    if number is None or pd.isna(number):
        return None
    return float("{:.12g}".format(float(number)))


def _text(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def read_clean_dataset(path: Path) -> pd.DataFrame:
    """Read the clean CSV as text so every original cell is preserved exactly."""
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "cve_id" not in frame.columns:
        raise ValueError(f"{path} lacks 'cve_id'; run python -m src.preprocess_data first.")
    if "summary" not in frame.columns:
        raise ValueError(f"{path} lacks 'summary', so rejected records cannot be identified.")
    if "cvss" not in frame.columns:
        raise ValueError(f"{path} lacks 'cvss', so the ranking cannot be recomputed.")
    return frame


def load_status_records(
    status_root: Path = DEFAULT_SNAPSHOT_ROOT,
    status_manifest: Optional[Path] = None,
) -> Tuple[Dict[str, Tuple[CveRecord, str]], Dict[str, Any]]:
    """Load and checksum-verify the authoritative CVE status snapshot."""
    manifest = select_status_manifest(root=status_root, explicit=status_manifest)
    if manifest is None:
        raise MissingStatusSnapshotError(
            f"No CVE status snapshot found under {Path(status_root) / 'cve_status'}. "
            "Run: python -m src.fetch_cve_status  (or pass --allow-missing-status-source)."
        )
    records = load_status_snapshot(manifest)
    return records, manifest


def load_threat_intel(
    source: str,
    *,
    snapshot_root: Path = DEFAULT_SNAPSHOT_ROOT,
    explicit_manifest: Optional[Path] = None,
    allow_missing: bool = False,
) -> Optional[ParsedSnapshot]:
    """Load and re-validate a KEV or EPSS snapshot, or None when not ingested."""
    manifest = select_manifest(source, snapshot_root, explicit_manifest)
    if manifest is None:
        if allow_missing:
            return None
        raise MissingSnapshotError(
            f"No {source.upper()} snapshot found under {Path(snapshot_root) / source}. "
            f"Run: python -m src.fetch_threat_intelligence --source {source} "
            "(or pass --allow-missing-sources to leave those audit columns blank)."
        )
    snapshot, _ = load_verified_snapshot(manifest)
    return snapshot


def _match_source(
    dataset: pd.DataFrame, snapshot: Optional[ParsedSnapshot], columns: Sequence[str]
) -> pd.DataFrame:
    """Left-join one threat-intelligence source by normalized CVE identifier."""
    keys = dataset["cve_id"].map(normalize_cve_id)
    if snapshot is None:
        return pd.DataFrame({column: pd.Series("", index=dataset.index) for column in columns})
    frame = snapshot.frame.set_index("cve_id")
    aligned = frame.reindex(keys.values)
    aligned.index = dataset.index
    return pd.DataFrame({column: aligned[column] for column in columns})


def build_status_columns(
    dataset: pd.DataFrame,
    status_records: Optional[Dict[str, Tuple[CveRecord, str]]],
    manifest: Optional[Dict[str, Any]],
) -> pd.DataFrame:
    """Return per-row status columns for the dataset (order preserved)."""
    summaries = dataset["summary"]
    placeholder = summaries.map(is_reject_placeholder)
    source = "not_checked"
    verification_date = ""
    if manifest is not None:
        commit = str(manifest.get("commit_sha", ""))[:12]
        source = f"{manifest.get('repository', '')}@{commit}" if commit else "unavailable"
        verification_date = str(manifest.get("retrieved_utc", ""))
    if status_records is None:
        source = "unavailable"

    status = pd.Series(STATUS_UNMARKED, index=dataset.index, dtype="object")
    reason = pd.Series("summary_does_not_start_with_reject_marker", index=dataset.index, dtype="object")
    # Only marker records are status-checked; every other row says so explicitly
    # instead of implying that a check was performed and passed.
    status_source = pd.Series("not_checked", index=dataset.index, dtype="object")
    verification_dates = pd.Series("", index=dataset.index, dtype="object")
    record_by_id = status_records or {}

    for position in dataset.index[placeholder]:
        status_source.at[position] = source
        verification_dates.at[position] = verification_date
        identifier = normalize_cve_id(dataset.at[position, "cve_id"])
        if identifier is None:
            status.at[position] = STATUS_UNVERIFIED
            reason.at[position] = "dataset_identifier_malformed_or_missing"
            continue
        entry = record_by_id.get(identifier)
        record = entry[0] if entry else None
        mapped, mapped_reason = classify_status(record, placeholder=True)
        status.at[position] = mapped
        reason.at[position] = mapped_reason

    return pd.DataFrame(
        {
            "reject_placeholder": placeholder.astype(bool),
            "record_status": status,
            "status_reason": reason,
            "status_source": status_source,
            "verification_date_utc": verification_dates,
        },
        index=dataset.index,
    )


def derive_placeholder_values(
    audit_rows: pd.DataFrame,
    score_column: str = "source_cvss",
) -> List[float]:
    """CVSS values observed on confirmed-rejected records (never assumed)."""
    confirmed = audit_rows[audit_rows["record_status"] == STATUS_REJECTED]
    values = pd.to_numeric(confirmed[score_column], errors="coerce").dropna().unique()
    return [float(value) for value in sorted(values)]


def _score_state(
    status: str,
    score: Optional[float],
    placeholder_values: Sequence[float],
    include_unverified: bool,
) -> Tuple[bool, str, str, str]:
    """Decide eligibility and score provenance for one placeholder record.

    Returns ``(eligible, score_used_for_ranking, score_note, exclusion_reason)``.
    """
    matches_placeholder = score is not None and any(
        float(score) == float(value) for value in placeholder_values
    )
    if status == STATUS_REJECTED:
        return (
            False,
            "none_excluded",
            "placeholder_score_not_genuine"
            if matches_placeholder
            else "record_withdrawn_no_genuine_score",
            EXCLUSION_CONFIRMED_REJECTED,
        )
    if status == STATUS_REINSTATED:
        if score is None:
            return True, "none_missing_score", "no_cvss_in_snapshot", ""
        if matches_placeholder:
            return (
                True,
                "none_missing_score",
                "placeholder_value_unconfirmed_for_reinstated_record",
                "",
            )
        return True, "snapshot_cvss", "", ""
    if status == STATUS_UNVERIFIED:
        if include_unverified:
            return (
                True,
                "none_missing_score",
                "unverified_status_score_not_used",
                "",
            )
        return False, "none_excluded", "unverified_status_score_not_used", EXCLUSION_UNVERIFIED
    # UNMARKED records keep the historical behaviour exactly.
    if score is None:
        return True, "none_missing_score", "no_cvss_in_snapshot", ""
    return True, "snapshot_cvss", "", ""


def build_audit_frames(
    dataset: pd.DataFrame,
    *,
    status_records: Optional[Dict[str, Tuple[CveRecord, str]]] = None,
    status_manifest: Optional[Dict[str, Any]] = None,
    kev: Optional[ParsedSnapshot] = None,
    epss: Optional[ParsedSnapshot] = None,
    include_unverified: bool = False,
) -> Dict[str, Any]:
    """Build every audit artifact in memory (no file writes, no network).

    Returns a mapping with ``reviewed`` (primary ranking), ``audit`` (all
    withdrawn-candidate records), ``disputed`` (separate reporting), and
    ``summary`` (machine-readable report).
    """
    dataset = dataset.reset_index(drop=True).copy(deep=True)
    for column in ("cve_id", "summary", "cvss"):
        if column not in dataset.columns:
            raise ValueError(f"Dataset must contain '{column}' to run the audit.")

    status = build_status_columns(dataset, status_records, status_manifest)
    scores = pd.to_numeric(dataset["cvss"], errors="coerce")

    # The untouched CVSS-descending baseline, recomputed from the same input so
    # the correction can be measured against the original policy.
    baseline_input = dataset[["cve_id", "summary", "cvss"]].copy()
    baseline_input["__row_id"] = range(len(dataset))
    baseline_ranked = rank_by_cvss(baseline_input)
    baseline_rank_by_row = pd.Series(
        baseline_ranked["baseline_rank"].to_numpy(), index=baseline_ranked["__row_id"].to_numpy()
    ).sort_index()

    keys = dataset["cve_id"].map(normalize_cve_id)
    kev_columns = _match_source(dataset, kev, ("kev_date_added",))
    epss_columns = _match_source(
        dataset, epss, ("epss_score", "epss_percentile")
    )
    if kev is None:
        kev_listed = pd.Series("", index=dataset.index, dtype="object")
    else:
        catalog_ids = set(kev.frame["cve_id"].tolist())
        kev_listed = keys.isin(catalog_ids).astype(str)
    if epss is None:
        epss_matched = pd.Series("", index=dataset.index, dtype="object")
    else:
        epss_matched = epss_columns["epss_score"].notna().astype(str)

    placeholder_rows = dataset.index[status["reject_placeholder"]]
    audit_seed = pd.DataFrame(
        {
            "source_cvss": scores,
            "record_status": status["record_status"],
        }
    )
    placeholder_values = derive_placeholder_values(audit_seed.loc[placeholder_rows])

    decisions: List[Tuple[bool, str, str, str]] = []
    for position in dataset.index:
        is_placeholder = bool(status.at[position, "reject_placeholder"])
        raw_score = scores.at[position]
        score = None if pd.isna(raw_score) else float(raw_score)
        if not is_placeholder:
            if score is None:
                decisions.append((True, "none_missing_score", "no_cvss_in_snapshot", ""))
            else:
                decisions.append((True, "snapshot_cvss", "", ""))
            continue
        decisions.append(
            _score_state(
                str(status.at[position, "record_status"]),
                score,
                placeholder_values,
                include_unverified,
            )
        )

    decision_frame = pd.DataFrame(
        decisions,
        columns=("ranking_eligible", "score_used_for_ranking", "score_note", "exclusion_reason"),
        index=dataset.index,
    )

    policy_columns = pd.DataFrame(
        {
            "record_status": status["record_status"],
            "status_source": status["status_source"],
            "ranking_eligible": decision_frame["ranking_eligible"].astype(str),
            "score_used_for_ranking": decision_frame["score_used_for_ranking"],
            "score_note": decision_frame["score_note"],
            "baseline_rank": baseline_rank_by_row.reindex(dataset.index).to_numpy(),
        },
        index=dataset.index,
    )

    eligible_mask = decision_frame["ranking_eligible"].astype(bool)
    ranking_input = dataset.loc[eligible_mask, ["cve_id", "summary", "cvss"]].copy()
    ranking_input["__row_id"] = dataset.index[eligible_mask]
    # A placeholder or unconfirmed score must not compete as if it were a
    # genuine severity: those rows rank with a missing score (sorted last).
    unusable = (~decision_frame.loc[eligible_mask, "score_used_for_ranking"].eq("snapshot_cvss"))
    unusable = unusable | _blank(ranking_input["cvss"])
    ranking_input.loc[unusable, "cvss"] = pd.NA

    if len(ranking_input):
        reviewed_ranked = rank_by_cvss(ranking_input)
        reviewed_rank_by_row = pd.Series(
            reviewed_ranked["baseline_rank"].to_numpy(),
            index=reviewed_ranked["__row_id"].to_numpy(),
        ).sort_index()
    else:
        reviewed_rank_by_row = pd.Series(dtype="int64")

    reviewed = dataset.loc[eligible_mask].copy()
    for column in POLICY_COPY_COLUMNS:
        reviewed[column] = policy_columns.loc[eligible_mask, column].to_numpy()
    reviewed["reviewed_rank"] = reviewed_rank_by_row.reindex(reviewed.index).to_numpy()
    reviewed["rank_shift"] = reviewed["baseline_rank"] - reviewed["reviewed_rank"]
    reviewed = reviewed.sort_values("reviewed_rank", kind="mergesort").reset_index(drop=True)
    reviewed = reviewed[
        [column for column in dataset.columns if column in reviewed.columns]
        + list(POLICY_COLUMNS)
    ]

    audit = dataset.loc[placeholder_rows].copy()
    audit["record_status"] = policy_columns.loc[audit.index, "record_status"].to_numpy()
    audit["score_used_for_ranking"] = policy_columns.loc[
        audit.index, "score_used_for_ranking"
    ].to_numpy()
    audit["score_note"] = policy_columns.loc[audit.index, "score_note"].to_numpy()
    audit_ranks = baseline_rank_by_row.reindex(audit.index)
    audit["baseline_rank"] = audit_ranks.to_numpy()
    audit["reviewed_rank"] = [
        reviewed_rank_by_row.get(position, pd.NA) for position in audit.index
    ]
    audit["kev_listed"] = kev_listed.loc[audit.index].to_numpy()
    audit["kev_date_added"] = kev_columns["kev_date_added"].loc[audit.index].to_numpy()
    audit["epss_matched"] = epss_matched.loc[audit.index].to_numpy()
    audit["epss_score"] = epss_columns["epss_score"].loc[audit.index].to_numpy()
    audit["epss_percentile"] = epss_columns["epss_percentile"].loc[audit.index].to_numpy()
    audit["cvss_genuine"] = [
        _score_genuine(
            str(status.at[position, "record_status"]),
            scores.at[position],
            placeholder_values,
        )
        for position in audit.index
    ]

    detail_records: List[Dict[str, Any]] = []
    for position in audit.index:
        identifier = normalize_cve_id(dataset.at[position, "cve_id"])
        entry = (status_records or {}).get(identifier) if identifier else None
        record = entry[0] if entry else None
        detail_records.append(_audit_detail(record, status, position, status_manifest))
    for column in (
        "authoritative_record_present",
        "authoritative_state",
        "date_rejected",
        "date_published",
        "date_updated",
        "assigner_short_name",
        "rejection_reason_detail",
        "rejection_reason",
        "consult_ids",
        "authoritative_cvss",
        "verification_date_utc",
        "verification_source",
        "source_api_url",
        "source_url",
        "status_reason",
    ):
        audit[column] = [detail[column] for detail in detail_records]
    audit["ranking_eligible"] = decision_frame.loc[audit.index, "ranking_eligible"].astype(str).to_numpy()
    audit["ranking_decision"] = [
        "included"
        if bool(decision_frame.at[position, "ranking_eligible"])
        else f"excluded_{decision_frame.at[position, 'exclusion_reason']}"
        for position in audit.index
    ]
    audit["exclusion_reason"] = decision_frame.loc[audit.index, "exclusion_reason"].to_numpy()
    audit["source_cvss"] = scores.loc[audit.index].to_numpy()
    audit = audit.sort_values("baseline_rank", kind="mergesort").reset_index(drop=True)
    order = [
        "cve_id",
        "record_status",
        "status_reason",
        "source_cvss",
        "cvss_genuine",
        "summary",
        "pub_date",
        "mod_date",
        "kev_listed",
        "kev_date_added",
        "epss_matched",
        "epss_score",
        "epss_percentile",
        "authoritative_record_present",
        "authoritative_state",
        "date_rejected",
        "date_published",
        "date_updated",
        "assigner_short_name",
        "rejection_reason_detail",
        "rejection_reason",
        "consult_ids",
        "authoritative_cvss",
        "verification_date_utc",
        "verification_source",
        "source_api_url",
        "source_url",
        "ranking_eligible",
        "ranking_decision",
        "score_used_for_ranking",
        "score_note",
        "exclusion_reason",
        "baseline_rank",
        "reviewed_rank",
    ]
    audit = audit[order]

    disputed_mask = dataset["summary"].map(has_disputed_marker)
    disputed = dataset.loc[disputed_mask].copy()
    disputed["record_status"] = status.loc[disputed_mask, "record_status"].to_numpy()
    disputed["ranking_eligible"] = (
        policy_columns.loc[disputed_mask, "ranking_eligible"].to_numpy()
    )
    disputed["baseline_rank"] = baseline_rank_by_row.reindex(disputed.index).to_numpy()
    disputed["reviewed_rank"] = [
        reviewed_rank_by_row.get(position, pd.NA) for position in disputed.index
    ]
    disputed["kev_listed"] = kev_listed.loc[disputed.index].to_numpy()
    disputed["epss_matched"] = epss_matched.loc[disputed.index].to_numpy()
    disputed["policy_note"] = (
        "Treatment unchanged: '** DISPUTED **' records are not withdrawn, remain "
        "eligible, and keep their snapshot CVSS score; reported here for review."
    )
    disputed = disputed.sort_values("baseline_rank", kind="mergesort").reset_index(drop=True)

    placeholder_total = int(status["reject_placeholder"].sum())
    if len(audit) != placeholder_total:
        raise ValueError(
            f"Audit table holds {len(audit)} rows but {placeholder_total} records carry the marker."
        )
    if len(reviewed) + int((~eligible_mask).sum()) != len(dataset):
        raise ValueError("Reviewed ranking plus exclusions must account for every input row.")

    summary = _build_summary(
        dataset,
        status,
        decision_frame,
        placeholder_values,
        baseline_ranked,
        reviewed,
        audit,
        disputed,
        status_manifest,
        kev,
        epss,
        include_unverified,
    )
    return {
        "reviewed": reviewed,
        "audit": audit,
        "disputed": disputed,
        "baseline_ranked": baseline_ranked,
        "summary": summary,
    }


def _score_genuine(
    status_value: str, score: Any, placeholder_values: Sequence[float]
) -> str:
    """Whether the snapshot CVSS value can be treated as a genuine severity.

    Blank means the snapshot has no score. ``False`` covers withdrawn records,
    unverifiable records (whose value cannot be confirmed), and values that match
    a placeholder observed on confirmed rejections.
    """
    if score is None or pd.isna(score):
        return ""
    if status_value in (STATUS_REJECTED, STATUS_UNVERIFIED):
        return "False"
    if any(float(score) == float(value) for value in placeholder_values):
        return "False"
    return "True"


def _audit_detail(
    record: Optional[CveRecord],
    status: pd.DataFrame,
    position: int,
    manifest: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "status_reason": str(status.at[position, "status_reason"]),
        "authoritative_record_present": str(record is not None),
        "authoritative_state": "" if record is None else record.state,
        "date_rejected": "" if record is None else record.date_rejected,
        "date_published": "" if record is None else record.date_published,
        "date_updated": "" if record is None else record.date_updated,
        "assigner_short_name": "" if record is None else record.assigner_short_name,
        "rejection_reason_detail": "" if record is None else parse_rejection_reason(record.rejected_reason),
        "rejection_reason": "" if record is None else record.rejected_reason,
        "consult_ids": "" if record is None else ";".join(record.consult_ids),
        "authoritative_cvss": ""
        if record is None or record.cvss_base_score is None
        else f"{record.cvss_version}={_json_number(record.cvss_base_score)}",
        "verification_date_utc": str(status.at[position, "verification_date_utc"]),
        "verification_source": str(status.at[position, "status_source"]),
        "source_api_url": "",
        "source_url": "",
    }
    if manifest is not None and record is not None:
        record_meta = manifest.get("records", {}).get(record.cve_id, {})
        entry["source_api_url"] = str(record_meta.get("url", ""))
        entry["source_url"] = str(record_meta.get("html_url", ""))
    return entry


def _top_rank_comparison(
    baseline: pd.DataFrame, reviewed: pd.DataFrame, levels: Sequence[int] = TOP_N_LEVELS
) -> Dict[str, Any]:
    baseline_ids = baseline["cve_id"].astype(str).tolist()
    reviewed_ids = reviewed["cve_id"].astype(str).tolist()
    comparison: Dict[str, Any] = {
        "baseline_rows": len(baseline_ids),
        "reviewed_rows": len(reviewed_ids),
        "levels": [],
    }
    for level in levels:
        head_baseline = baseline_ids[:level]
        head_reviewed = reviewed_ids[:level]
        first_difference = None
        for index, (left, right) in enumerate(zip(head_baseline, head_reviewed), start=1):
            if left != right:
                first_difference = index
                break
        comparison["levels"].append(
            {
                "top_n": int(level),
                "baseline_size": len(head_baseline),
                "reviewed_size": len(head_reviewed),
                "identical": head_baseline == head_reviewed,
                "first_differing_rank": first_difference,
                "baseline_top_record": head_baseline[0] if head_baseline else None,
                "reviewed_top_record": head_reviewed[0] if head_reviewed else None,
            }
        )
    comparison["baseline_top_records"] = [
        {"cve_id": str(row["cve_id"]), "cvss": _json_number(row["cvss"])}
        for _, row in baseline.head(10).iterrows()
    ]
    comparison["reviewed_top_records"] = [
        {"cve_id": str(row["cve_id"]), "cvss": _json_number(row["cvss"])}
        for _, row in reviewed.head(10).iterrows()
    ]
    if len(reviewed):
        shifts = pd.to_numeric(reviewed["rank_shift"], errors="coerce")
        comparison["rank_shift"] = {
            "rows_present_in_both": int(shifts.notna().sum()),
            "rows_shifted": int((shifts.fillna(0) != 0).sum()),
            "max_shift_positions": int(shifts.max()) if shifts.notna().any() else 0,
            "min_shift_positions": int(shifts.min()) if shifts.notna().any() else 0,
            "first_affected_baseline_rank": int(
                pd.to_numeric(reviewed.loc[shifts.fillna(0) != 0, "baseline_rank"]).min()
            )
            if bool((shifts.fillna(0) != 0).any())
            else None,
            "mean_shift_positions": _json_number(shifts.mean()) if shifts.notna().any() else None,
        }
    else:
        comparison["rank_shift"] = {}
    return comparison


def _record_list(frame: pd.DataFrame, status_value: str) -> List[Dict[str, Any]]:
    subset = frame[frame["record_status"] == status_value]
    return [
        {
            "cve_id": str(row["cve_id"]),
            "source_cvss": _json_number(row["source_cvss"]),
            "record_status": str(row["record_status"]),
            "ranking_decision": str(row["ranking_decision"]),
            "baseline_rank": int(row["baseline_rank"])
            if not pd.isna(row["baseline_rank"])
            else None,
            "authoritative_state": str(row["authoritative_state"]),
            "date_rejected": str(row["date_rejected"]),
            "consult_ids": str(row["consult_ids"]),
            "source_url": str(row["source_url"]),
        }
        for _, row in subset.iterrows()
    ]


def _build_summary(
    dataset: pd.DataFrame,
    status: pd.DataFrame,
    decision: pd.DataFrame,
    placeholder_values: Sequence[float],
    baseline_ranked: pd.DataFrame,
    reviewed: pd.DataFrame,
    audit: pd.DataFrame,
    disputed: pd.DataFrame,
    status_manifest: Optional[Dict[str, Any]],
    kev: Optional[ParsedSnapshot],
    epss: Optional[ParsedSnapshot],
    include_unverified: bool,
) -> Dict[str, Any]:
    rejected = int((status["record_status"] == STATUS_REJECTED).sum())
    reinstated = int((status["record_status"] == STATUS_REINSTATED).sum())
    unverified = int((status["record_status"] == STATUS_UNVERIFIED).sum())
    eligible = int(decision["ranking_eligible"].astype(bool).sum())
    excluded = int(len(dataset) - eligible)

    verification = {
        "status": "not_ingested" if status_manifest is None else "verified",
        "source": "CVE Project CVE Services 5.x records (cvelistV5)",
        "repository": None if status_manifest is None else status_manifest.get("repository"),
        "commit_sha": None if status_manifest is None else status_manifest.get("commit_sha"),
        "requested_ref": None if status_manifest is None else status_manifest.get("requested_ref"),
        "verification_date_utc": None
        if status_manifest is None
        else status_manifest.get("retrieved_utc"),
        "retrieval_method": None if status_manifest is None else status_manifest.get("retrieval_method"),
        "manifest_file": None
        if status_manifest is None
        else _relative(Path(status_manifest["_manifest_path"]))
        if status_manifest.get("_manifest_path")
        else None,
        "records_in_snapshot": None
        if status_manifest is None
        else status_manifest.get("record_count"),
        "per_record": [
            {
                "cve_id": str(row["cve_id"]),
                "state": str(row["authoritative_state"]),
                "date_rejected": str(row["date_rejected"]),
                "date_updated": str(row["date_updated"]),
                "assigner_short_name": str(row["assigner_short_name"]),
                "source_url": str(row["source_url"]),
                "verification_date_utc": str(row["verification_date_utc"]),
            }
            for _, row in audit.iterrows()
        ],
    }

    summary: Dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "policy_version": POLICY_VERSION,
        "task": "rejected_cve_status_audit_and_status_aware_ranking",
        "policy": {
            "marker_rule": "A record is a withdrawn candidate when its summary begins with '** REJECT **'.",
            "verified_rejected": (
                "Excluded from the primary active-vulnerability ranking; preserved in the audit "
                "table. Its snapshot CVSS value is a placeholder and is never used as a ranking score."
            ),
            "verified_reinstated": (
                "Eligible for ranking. The snapshot CVSS value is used only when it differs from the "
                "placeholder values observed on confirmed-rejected records; otherwise the record is "
                "ranked with a missing score. Authoritative base scores of other CVSS versions are "
                "disclosed but not substituted."
            ),
            "unverified": (
                "Excluded from the primary ranking by default and disclosed with identifiers and "
                "source URLs; their unconfirmed scores are never used. "
                "With --include-unverified they are ranked at the bottom with a missing score."
            ),
            "unmarked_records": (
                "No reject marker: unchanged CVSS-descending order, ties by cve_id then input order, "
                "missing scores last. They are labelled UNMARKED, not ACTIVE: no status check was run."
            ),
            "disputed_records": (
                "Reported separately in the disputed report; treatment is unchanged and they remain "
                "eligible with their snapshot CVSS score."
            ),
            "placeholder_values": [str(_json_number(value)) for value in placeholder_values],
            "baseline_unchanged": (
                "src.baseline still ranks every row by CVSS. The reviewed ranking is a separate file; "
                "the baseline output remains for comparison."
            ),
            "include_unverified": bool(include_unverified),
        },
        "counts": {
            "rows_input": int(len(dataset)),
            "reject_placeholder_rows": int(status["reject_placeholder"].sum()),
            "verified_rejected_rows": rejected,
            "reinstated_rows": reinstated,
            "unverified_rows": unverified,
            "eligible_ranking_rows": eligible,
            "excluded_rows": excluded,
            "excluded_confirmed_rejected": int(
                (decision["exclusion_reason"] == EXCLUSION_CONFIRMED_REJECTED).sum()
            ),
            "excluded_unverified": int(
                (decision["exclusion_reason"] == EXCLUSION_UNVERIFIED).sum()
            ),
            "reviewed_rows": int(len(reviewed)),
            "audited_rows": int(len(audit)),
            "disputed_rows": int(len(disputed)),
            "rows_accounted_for": int(len(reviewed) + excluded),
        },
        "marker_audit": marker_audit(dataset["summary"]),
        "placeholder_score_values": [_json_number(value) for value in placeholder_values],
        "rejected_records": _record_list(audit, STATUS_REJECTED),
        "reinstated_records": _record_list(audit, STATUS_REINSTATED),
        "unverified_records": _record_list(audit, STATUS_UNVERIFIED),
        "disputed": {
            "marker_rows": int(len(disputed)),
            "policy": "unchanged; reported separately and still eligible for ranking",
            "kev_listed": int((disputed["kev_listed"] == "True").sum()),
            "epss_matched": int((disputed["epss_matched"] == "True").sum()),
            "highest_baseline_rank": int(disputed["baseline_rank"].min()) if len(disputed) else None,
        },
        "verification": verification,
        "sources": {
            "kev": "not_ingested" if kev is None else kev.metadata.get("catalog_version"),
            "kev_snapshot_date": None if kev is None else kev.metadata.get("snapshot_date"),
            "epss": "not_ingested" if epss is None else epss.metadata.get("model_version"),
            "epss_snapshot_date": None if epss is None else epss.metadata.get("snapshot_date"),
        },
        "baseline_comparison": _top_rank_comparison(baseline_ranked, reviewed),
        "limitations": LIMITATIONS,
    }
    return summary


def _relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _guard_outputs(inputs: Sequence[Path], outputs: Sequence[Path]) -> None:
    resolved_inputs = {Path(path).resolve() for path in inputs}
    resolved_outputs = [Path(path).resolve() for path in outputs]
    if len(set(resolved_outputs)) != len(resolved_outputs):
        raise ValueError("Audit output paths must all be different files.")
    for output in resolved_outputs:
        if output in resolved_inputs:
            raise ValueError(f"Refusing to overwrite an input with an audit output: {output}")


def run_audit(
    clean_path: Path = DEFAULT_CLEAN_PATH,
    *,
    audit_path: Path = DEFAULT_AUDIT_PATH,
    reviewed_path: Path = DEFAULT_REVIEWED_PATH,
    summary_path: Path = DEFAULT_SUMMARY_PATH,
    disputed_path: Path = DEFAULT_DISPUTED_PATH,
    baseline_ranked_path: Optional[Path] = DEFAULT_BASELINE_RANKED_PATH,
    status_root: Path = DEFAULT_SNAPSHOT_ROOT,
    status_manifest: Optional[Path] = None,
    snapshot_root: Path = DEFAULT_SNAPSHOT_ROOT,
    kev_manifest: Optional[Path] = None,
    epss_manifest: Optional[Path] = None,
    allow_missing_status_source: bool = False,
    allow_missing_sources: bool = False,
    include_unverified: bool = False,
) -> Dict[str, Any]:
    """Run the audit and write every output file; return the JSON summary."""
    clean_path = Path(clean_path)
    outputs = [Path(audit_path), Path(reviewed_path), Path(summary_path), Path(disputed_path)]
    _guard_outputs([clean_path, DEFAULT_RAW_PATH], outputs)

    dataset = read_clean_dataset(clean_path)

    status_records: Optional[Dict[str, Tuple[CveRecord, str]]] = None
    manifest: Optional[Dict[str, Any]] = None
    try:
        status_records, manifest = load_status_records(status_root, status_manifest)
    except MissingStatusSnapshotError:
        if not allow_missing_status_source:
            raise
        status_records, manifest = None, None

    kev = load_threat_intel(
        KEV_SOURCE, snapshot_root=snapshot_root, explicit_manifest=kev_manifest, allow_missing=allow_missing_sources
    )
    epss = load_threat_intel(
        EPSS_SOURCE, snapshot_root=snapshot_root, explicit_manifest=epss_manifest, allow_missing=allow_missing_sources
    )

    frames = build_audit_frames(
        dataset,
        status_records=status_records,
        status_manifest=manifest,
        kev=kev,
        epss=epss,
        include_unverified=include_unverified,
    )

    summary = frames["summary"]
    summary["input_file"] = _relative(clean_path)
    summary["outputs"] = {}

    audit_path.parent.mkdir(parents=True, exist_ok=True)
    frames["audit"].to_csv(audit_path, index=False, na_rep="")
    frames["reviewed"].to_csv(reviewed_path, index=False, na_rep="")
    frames["disputed"].to_csv(disputed_path, index=False, na_rep="")

    if baseline_ranked_path is not None and Path(baseline_ranked_path).is_file():
        existing = pd.read_csv(baseline_ranked_path, dtype=str, keep_default_na=False)
        summary["baseline_comparison"]["baseline_file"] = _relative(Path(baseline_ranked_path))
        summary["baseline_comparison"]["baseline_file_matches_recomputed_baseline"] = bool(
            existing["cve_id"].astype(str).tolist()
            == frames["baseline_ranked"]["cve_id"].astype(str).tolist()
        )
        summary["baseline_comparison"]["baseline_file_sha256"] = sha256_file(Path(baseline_ranked_path))

    summary["outputs"] = {
        "audit_file": _relative(Path(audit_path)),
        "reviewed_file": _relative(Path(reviewed_path)),
        "disputed_file": _relative(Path(disputed_path)),
        "summary_file": _relative(Path(summary_path)),
        "row_counts": {
            "audit": int(len(frames["audit"])),
            "reviewed": int(len(frames["reviewed"])),
            "disputed": int(len(frames["disputed"])),
        },
        "sha256": {
            "audit": sha256_file(audit_path),
            "reviewed": sha256_file(reviewed_path),
            "disputed": sha256_file(disputed_path),
        },
    }

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit '** REJECT **' records against CVEProject/cvelistV5 and rank the "
            "dataset with an explicit status-aware policy."
        )
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_CLEAN_PATH, help="Clean dataset CSV.")
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_PATH)
    parser.add_argument("--reviewed-output", type=Path, default=DEFAULT_REVIEWED_PATH)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY_PATH)
    parser.add_argument("--disputed-output", type=Path, default=DEFAULT_DISPUTED_PATH)
    parser.add_argument(
        "--baseline-ranked",
        type=Path,
        default=DEFAULT_BASELINE_RANKED_PATH,
        help="Existing baseline ranking used for the comparison check (optional).",
    )
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--status-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--status-manifest", type=Path, help="Pin a specific CVE status snapshot.")
    parser.add_argument("--kev-manifest", type=Path)
    parser.add_argument("--epss-manifest", type=Path)
    parser.add_argument(
        "--allow-missing-status-source",
        action="store_true",
        help="Run without a CVE status snapshot; every marker record becomes UNVERIFIED and is disclosed.",
    )
    parser.add_argument(
        "--allow-missing-sources",
        action="store_true",
        help="Leave KEV/EPSS audit columns blank when those snapshots are absent.",
    )
    parser.add_argument(
        "--include-unverified",
        action="store_true",
        help="Keep unverified records in the primary ranking, at the bottom with a missing score.",
    )
    args = parser.parse_args(argv)

    try:
        summary = run_audit(
            args.input,
            audit_path=args.audit_output,
            reviewed_path=args.reviewed_output,
            summary_path=args.summary_output,
            disputed_path=args.disputed_output,
            baseline_ranked_path=args.baseline_ranked,
            status_root=args.status_root,
            status_manifest=args.status_manifest,
            snapshot_root=args.snapshot_root,
            kev_manifest=args.kev_manifest,
            epss_manifest=args.epss_manifest,
            allow_missing_status_source=args.allow_missing_status_source,
            allow_missing_sources=args.allow_missing_sources,
            include_unverified=args.include_unverified,
        )
    except (MissingStatusSnapshotError, MissingSnapshotError, CveStatusValidationError, ValueError, OSError) as error:
        print(f"ERROR: {error}")
        return 1

    counts = summary["counts"]
    print(
        f"Rejected-record audit: {counts['reject_placeholder_rows']} marker row(s); "
        f"verified rejected={counts['verified_rejected_rows']}, "
        f"reinstated={counts['reinstated_rows']}, unverified={counts['unverified_rows']}"
    )
    print(
        f"Ranking: {counts['eligible_ranking_rows']:,} eligible of {counts['rows_input']:,} "
        f"(excluded {counts['excluded_rows']}); top record "
        f"{summary['baseline_comparison']['reviewed_top_records'][0]['cve_id'] if counts['eligible_ranking_rows'] else 'n/a'}"
    )
    print(f"Audit table: {args.audit_output}")
    print(f"Reviewed ranking: {args.reviewed_output}")
    print(f"Summary: {args.summary_output}")
    print(f"Disputed report: {args.disputed_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
