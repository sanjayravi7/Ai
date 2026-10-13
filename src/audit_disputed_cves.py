"""Phase 2.2: evidence-based audit of the ``** DISPUTED **`` CVE records.

What this module does
---------------------

The bundled snapshot contains 455 records whose summary contains the
``** DISPUTED **`` marker. Phase 2.1 inventoried them in
``data/processed/disputed_cve_report.csv`` and deliberately changed nothing about
their treatment. This module performs the follow-up evidence audit:

1. it re-derives the disputed set with the existing parser (no new rule, no new
   threshold) and keeps every original dataset column verbatim;
2. it retrieves the official CVE Program record for each identifier from a
   commit-pinned ``CVEProject/cvelistV5`` snapshot and records the record's
   administrative state, dates, tags, and the verbatim text - exactly as
   published, never paraphrased;
3. it classifies what that evidence can and cannot resolve
   (:mod:`src.disputed_evidence`), keeping four things strictly separate:
   official administrative status, the marker text in the snapshot, technical
   evidence about the disputed claim, and exploitation evidence;
4. it measures the ranking effect of several *hypothetical* treatments against
   the unchanged baseline and the current reviewed ranking; and
5. it writes regenerable, Git-ignored artifacts plus a JSON summary and a source
   manifest that records pins, checksums, retrieval timestamps, and failures.

What this module deliberately does **not** do
---------------------------------------------

* It does not modify ``data/raw/vulnerabilities.csv``, ``cve.csv.zip``,
  ``src/baseline.py``, the Phase 2 KEV/EPSS enrichment, or the Phase 2.1
  rejected-CVE policy.
* It does not overwrite ``data/processed/disputed_cve_report.csv`` (the Phase 2.1
  marker inventory). That file is read, hashed, and re-hashed after the run to
  prove it was preserved.
* It does not change, raise, or lower any record's score in the production or
  reviewed ranking, and it does not recommend automatic exclusion on the basis
  of the ``** DISPUTED **`` marker alone.
* It does not treat "PUBLISHED", "DISPUTED", KEV absence, or an EPSS value as
  proof of vulnerability validity or of exploitation.

Usage::

    python -m src.audit_disputed_cves
    python -m src.audit_disputed_cves --no-kev --no-epss
    python -m src.audit_disputed_cves --generated-utc 2026-10-12T00:00:00Z
"""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

import pandas as pd

from .baseline import rank_by_cvss
from .cve_status_sources import CveStatusSchemaError, CveStatusValidationError, has_disputed_marker
from .disputed_evidence import (
    BUCKET_NOT_VERIFIABLE,
    BUCKET_RESOLVED,
    BUCKET_UNRESOLVED,
    EXCLUSION_NOT_EVALUABLE,
    EXCLUSION_SUPPORTED,
    RESOLUTION_OPEN,
    RETRIEVAL_FAILED,
    RETRIEVAL_MALFORMED,
    RETRIEVAL_NOT_ATTEMPTED,
    RETRIEVAL_NOT_FOUND,
    RETRIEVAL_RETRIEVED,
    classify_dispute_evidence,
    dataset_dispute_text,
    parse_dispute_record,
)
from .enrich_vulnerabilities import MissingSnapshotError, load_verified_snapshot, select_manifest
from .fetch_cve_status import list_status_manifests
from .fetch_disputed_status import DEFAULT_DISPUTED_ROOT
from .fetch_threat_intelligence import DEFAULT_SNAPSHOT_ROOT, sha256_file
from .threat_intel_sources import EPSS_SOURCE, KEV_SOURCE, ParsedSnapshot, normalize_cve_id


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "processed"
DEFAULT_CLEAN_PATH = DATA_DIR / "vulnerabilities_clean.csv"
DEFAULT_BASELINE_RANKED_PATH = DATA_DIR / "vulnerabilities_ranked.csv"
DEFAULT_REVIEWED_RANKED_PATH = DATA_DIR / "vulnerabilities_ranked_reviewed.csv"
DEFAULT_PHASE21_AUDIT_PATH = DATA_DIR / "rejected_cve_audit.csv"
DEFAULT_PHASE21_DISPUTED_REPORT_PATH = DATA_DIR / "disputed_cve_report.csv"
DEFAULT_RAW_PATH = PROJECT_ROOT / "data" / "raw" / "vulnerabilities.csv"
DEFAULT_ARCHIVE_PATH = PROJECT_ROOT / "cve.csv.zip"

DEFAULT_AUDIT_PATH = DATA_DIR / "disputed_cve_evidence_audit.csv"
DEFAULT_IMPACT_PATH = DATA_DIR / "disputed_cve_ranking_impact.csv"
DEFAULT_REVIEW_QUEUE_PATH = DATA_DIR / "disputed_cve_review_queue.csv"
DEFAULT_SENSITIVITY_PATH = DATA_DIR / "disputed_cve_ranking_sensitivity.csv"
DEFAULT_SUMMARY_PATH = DATA_DIR / "disputed_cve_audit_summary.json"
DEFAULT_MANIFEST_PATH = DATA_DIR / "disputed_cve_source_manifest.json"

SUMMARY_SCHEMA = "vulnova-disputed-cve-audit-1"
AUDIT_VERSION = "vulnova-disputed-audit-1"
POLICY_VERSION = "vulnova-status-policy-1"

TOP_N_LEVELS = (100, 1000, 10000)
REVIEW_RANK_THRESHOLD = 1000

SCENARIO_CURRENT = "S0_CURRENT_POLICY"
SCENARIO_EVIDENCE_EXCLUSION = "S1_EVIDENCE_SUPPORTED_EXCLUSION"
SCENARIO_FLAG_ONLY = "S2_FLAG_UNRESOLVED_FOR_REVIEW"
SCENARIO_MARKER_ONLY = "S3_MARKER_ONLY_EXCLUSION"
SCENARIOS = (
    SCENARIO_CURRENT,
    SCENARIO_EVIDENCE_EXCLUSION,
    SCENARIO_FLAG_ONLY,
    SCENARIO_MARKER_ONLY,
)
SCENARIO_ROLES = {
    SCENARIO_CURRENT: "current_policy",
    SCENARIO_EVIDENCE_EXCLUSION: "hypothetical",
    SCENARIO_FLAG_ONLY: "hypothetical",
    SCENARIO_MARKER_ONLY: "rejected_hypothetical",
}
SCENARIO_DESCRIPTIONS = {
    SCENARIO_CURRENT: (
        "Keep every '** DISPUTED **' record eligible with its original snapshot CVSS score. "
        "This is the policy in force; Phase 2.2 changes nothing."
    ),
    SCENARIO_EVIDENCE_EXCLUSION: (
        "Exclude only records whose retrieved authoritative evidence supports exclusion "
        "(the CVE Program record state is REJECTED, so the identifier is withdrawn). "
        "All other disputed records stay eligible."
    ),
    SCENARIO_FLAG_ONLY: (
        "Exclude nothing. Flag records whose evidence is insufficient or unverifiable for manual "
        "review, and leave the ranking byte-identical to the current policy."
    ),
    SCENARIO_MARKER_ONLY: (
        "Exclude every record carrying the '** DISPUTED **' marker. This scenario is NOT justified "
        "by the audit evidence; it is measured only to quantify the effect of a marker-only rule, "
        "which this audit does not recommend."
    ),
}
SCENARIO_JUSTIFICATION = {
    SCENARIO_CURRENT: "Policy in force; preserved so every other scenario can be compared with it.",
    SCENARIO_EVIDENCE_EXCLUSION: (
        "Supported by the audit for withdrawn identifiers only. A '** DISPUTED **' marker alone "
        "never satisfies this rule."
    ),
    SCENARIO_FLAG_ONLY: (
        "Supported as a workflow change with no ranking effect; it operates on evidence quality, "
        "not on the marker."
    ),
    SCENARIO_MARKER_ONLY: (
        "NOT evidence-justified. It would remove records that the official record still publishes "
        "and for which no source supports exclusion."
    ),
}
SCENARIO_EVIDENCE_JUSTIFIED = {
    SCENARIO_CURRENT: True,
    SCENARIO_EVIDENCE_EXCLUSION: True,
    SCENARIO_FLAG_ONLY: True,
    SCENARIO_MARKER_ONLY: False,
}

REFERENCE_BASELINE = "baseline_cvss_unchanged"
REFERENCE_REVIEWED = "reviewed_status_policy"

REVIEW_PRIORITY_HIGH = 1
REVIEW_PRIORITY_CONTESTED = 2
REVIEW_PRIORITY_EVIDENCE_GAP = 3
REVIEW_PRIORITY_LABELS = {
    REVIEW_PRIORITY_HIGH: "P1_high_ranked_evidence_gap",
    REVIEW_PRIORITY_CONTESTED: "P2_high_ranked_open_dispute",
    REVIEW_PRIORITY_EVIDENCE_GAP: "P3_evidence_gap",
}

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
ADVISORY_REFERENCE_TAGS = (
    "vendor-advisory",
    "third-party-advisory",
    "advisory",
)

AUDIT_COLUMNS = (
    "disputed_marker_at_start",
    "disputed_marker_offset",
    "disputed_claim_text",
    "dataset_text_before_marker",
    "dataset_cvss_snapshot",
    "cvss_placeholder_suspect",
    "cvss_genuine",
    "cvss_note",
    "baseline_rank",
    "baseline_band",
    "reviewed_rank_current_policy",
    "official_lookup_attempted",
    "official_record_retrieval_status",
    "official_record_failure_reason",
    "official_record_sha256",
    "official_record_git_blob_sha",
    "official_record_bytes",
    "official_record_api_url",
    "official_record_html_url",
    "official_record_path",
    "official_source_repository",
    "official_source_commit",
    "official_record_retrieved_utc",
    "official_record_state",
    "official_record_data_version",
    "official_record_assigner",
    "official_record_date_reserved",
    "official_record_date_published",
    "official_record_date_updated",
    "official_record_date_rejected",
    "official_record_changed_since_snapshot",
    "official_record_tags",
    "official_record_dispute_tag_present",
    "official_record_dispute_language_present",
    "official_record_dispute_language_rule",
    "official_record_dispute_language_field",
    "official_record_text_fields_scanned",
    "official_record_reference_count",
    "official_record_advisory_reference_count",
    "official_record_reference_hosts",
    "official_reference_bodies_retrieved",
    "official_record_position",
    "dispute_resolution",
    "resolution_bucket",
    "evidence_classification",
    "evidence_status",
    "evidence_confidence",
    "confidence_rationale",
    "exclusion_evidence",
    "authoritative_rationale_status",
    "authoritative_rationale_field",
    "authoritative_rationale",
    "dispute_actor",
    "dispute_actor_field",
    "dispute_actor_quote",
    "dispute_subject",
    "dispute_subject_field",
    "dispute_subject_quote",
    "contradiction_rule",
    "contradiction_field",
    "contradiction_quote",
    "replacement_related_cve_ids",
    "replacement_evidence_field",
    "kev_snapshot_status",
    "kev_snapshot_date",
    "kev_catalog_version",
    "kev_date_added",
    "kev_known_ransomware_campaign_use",
    "kev_source",
    "epss_snapshot_status",
    "epss_snapshot_date",
    "epss_model_version",
    "epss_score",
    "epss_percentile",
    "epss_source",
    "exploitation_evidence_note",
    "human_review_required",
    "human_review_priority",
    "review_reason",
)

#: Manifest reasons that mean "the record is not present at the pinned commit",
#: as opposed to a transport or parsing failure.
NOT_FOUND_REASONS = ("http_404_not_found", "not_found", "http_404")

KEV_STATUS_MATCHED = "MATCHED"
KEV_STATUS_NOT_LISTED = "NOT_LISTED_IN_SNAPSHOT"
KEV_STATUS_UNAVAILABLE = "SNAPSHOT_UNAVAILABLE"

LIMITATIONS = [
    "The audit reads one commit of CVEProject/cvelistV5. CVE records can be updated "
    "after that commit, and no later change is observed here.",
    "Evidence is limited to what the official record contains: its administrative state, "
    "its tags, and its own text. Advisory and vendor pages referenced by a record were not "
    "retrieved in this environment, so their content is not evidence used by this audit.",
    "A '** DISPUTED **' marker is a snapshot-era editorial statement. It is not proof that a "
    "vulnerability is invalid, and a PUBLISHED record is not proof that a disputed technical "
    "claim is true. The audit records both without equating them.",
    "Absence from the KEV snapshot is not evidence that a vulnerability was never exploited, "
    "and an EPSS score is a current model estimate for its score date, not historical "
    "evidence of past exploitation or of exploitability in 2019.",
    "Failure to retrieve an official record is recorded as NOT_VERIFIABLE and is never "
    "interpreted as a rejection, a withdrawal, or an absence of a vulnerability.",
    "The snapshot does not name its CVSS version, so authoritatively published base scores "
    "are disclosed but never substituted into any ranking.",
    "Ranking scenarios are analytical only. They do not modify the baseline, the reviewed "
    "ranking, or any production artifact.",
]


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(stamp: datetime) -> str:
    return stamp.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:
        return ""
    return str(value).strip()


def _relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def json_safe(value: Any) -> Any:
    """Convert pandas/NumPy scalars to plain JSON types, preserving blanks."""
    if value is None:
        return None
    if isinstance(value, (bool,)):
        return bool(value)
    if isinstance(value, (int,)):
        return int(value)
    if isinstance(value, float):
        if value != value:
            return None
        return float("{:.12g}".format(value))
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return str(value)


def _json_number(value: Any) -> Optional[float]:
    if value is None or _text(value) == "":
        return None
    number = pd.to_numeric(value, errors="coerce")
    if number is None or pd.isna(number):
        return None
    return float("{:.12g}".format(float(number)))


def _bool_text(value: Any) -> str:
    if value is None or _text(value) == "":
        return ""
    return "True" if bool(value) else "False"


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def read_dataset(path: Path) -> pd.DataFrame:
    """Read the clean CSV as text so every original cell is preserved exactly."""
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "cve_id" not in frame.columns or "summary" not in frame.columns or "cvss" not in frame.columns:
        raise ValueError(
            f"{Path(path)} must contain 'cve_id', 'summary' and 'cvss'; run python -m src.preprocess_data first."
        )
    return frame


def read_ranked_ids(path: Path, rank_column: str) -> pd.DataFrame:
    """Read an existing ranking output and attach a numeric ``__rank`` column."""
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    for column in ("cve_id", "cvss", rank_column):
        if column not in frame.columns:
            raise ValueError(f"{Path(path)} lacks the '{column}' column.")
    reference = frame[["cve_id", "cvss", rank_column]].copy()
    reference["cve_id"] = reference["cve_id"].astype(str)
    reference["__rank"] = pd.to_numeric(reference[rank_column], errors="coerce")
    return reference


def verify_ranking_reproduced(
    reference: pd.DataFrame,
    rank_column: str,
    *,
    label: str,
) -> Dict[str, Any]:
    """Recompute a reference ranking and compare it with the stored output.

    Returns a verification record. The reference ranking is never modified; this
    only proves that the audited ranking is the one the repository produced.
    """
    recomputed = rank_by_cvss(reference[["cve_id", "cvss"]].copy())
    stored = reference["__rank"].fillna(-1).astype("int64").tolist()
    identical_order = bool(
        recomputed["cve_id"].astype(str).tolist() == reference["cve_id"].astype(str).tolist()
    )
    identical_ranks = bool(
        identical_order and recomputed["baseline_rank"].astype("int64").tolist() == stored
    )
    return {
        "reference": label,
        "rows": int(len(reference)),
        "ranked_rows": int(reference["__rank"].notna().sum()),
        "order_reproduced": identical_order,
        "ranks_reproduced": identical_ranks,
        "note": (
            "Recomputed from the stored ranking input with the unmodified CVSS ranking rule."
            if identical_ranks
            else "The stored ranking differs from a fresh recomputation; investigate before trusting shifts."
        ),
    }


def ranking_index(reference: pd.DataFrame) -> Dict[str, int]:
    """Return ``{cve_id: rank}`` for a reference ranking."""
    result: Dict[str, int] = {}
    for cve_id, rank in zip(reference["cve_id"], reference["__rank"]):
        if pd.notna(rank):
            result[str(cve_id)] = int(rank)
    return result


def load_disputed_records(
    root: Path = DEFAULT_DISPUTED_ROOT,
    manifest_path: Optional[Path] = None,
) -> Tuple[Dict[str, Any], Dict[str, str], Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Read the commit-pinned disputed-record snapshot.

    Returns ``(views, retrieval_status, failures, manifest)`` where:

    * ``views`` maps a CVE id to a parsed :class:`DisputedRecordView`;
    * ``retrieval_status`` maps every identifier named in the manifest to a
      :data:`RETRIEVAL_*` value; and
    * ``failures`` maps identifiers to a reason string (missing, unusable, or
      malformed).

    Integrity rules: a recorded checksum mismatch raises
    :class:`CveStatusValidationError`, because a snapshot that does not match
    its own manifest is not evidence. A record that is present and
    checksum-correct but unparseable is reported as ``MALFORMED_RECORD`` for that
    identifier only, so one bad file cannot hide the other 454.
    """
    if manifest_path is not None:
        path = Path(manifest_path)
        if not path.is_file():
            raise FileNotFoundError(f"CVE status manifest not found: {path}")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["_manifest_path"] = str(path)
    else:
        manifests = list_status_manifests(Path(root))
        if not manifests:
            raise FileNotFoundError(
                f"No disputed-record status snapshot under {Path(root) / 'cve_status'}. "
                "Run: python -m src.fetch_disputed_status"
            )
        manifest = manifests[-1]

    directory = Path(manifest["_manifest_path"]).parent
    views: Dict[str, Any] = {}
    retrieval: Dict[str, str] = {}
    failures: Dict[str, Dict[str, Any]] = {}

    for cve_id, entry in sorted(manifest.get("records", {}).items()):
        if not entry.get("present"):
            reason = str(entry.get("reason", "not_present_in_snapshot"))
            retrieval[cve_id] = RETRIEVAL_NOT_FOUND if reason in NOT_FOUND_REASONS else RETRIEVAL_FAILED
            failures[cve_id] = {"reason": reason, "retrieval_status": retrieval[cve_id]}
            continue
        record_path = directory / str(entry.get("file"))
        if not record_path.is_file():
            raise CveStatusValidationError(f"Snapshot record is missing: {record_path}")
        actual = sha256_file(record_path)
        if actual != entry.get("sha256"):
            raise CveStatusValidationError(
                f"Snapshot checksum mismatch for {record_path}: manifest={entry.get('sha256')} actual={actual}"
            )
        payload = record_path.read_bytes()
        try:
            view = parse_dispute_record(payload, expected_cve_id=cve_id)
        except (CveStatusSchemaError, CveStatusValidationError) as error:
            retrieval[cve_id] = RETRIEVAL_MALFORMED
            failures[cve_id] = {"reason": f"malformed_record:{str(error)[:160]}", "retrieval_status": RETRIEVAL_MALFORMED}
            continue
        views[cve_id] = view
        retrieval[cve_id] = RETRIEVAL_RETRIEVED
    return views, retrieval, failures, manifest


def load_threat_intel(
    source: str,
    *,
    snapshot_root: Path = DEFAULT_SNAPSHOT_ROOT,
    explicit_manifest: Optional[Path] = None,
    allow_missing: bool = False,
) -> Optional[ParsedSnapshot]:
    """Load and re-validate a KEV or EPSS snapshot, or ``None`` when absent."""
    manifest = select_manifest(source, Path(snapshot_root), explicit_manifest)
    if manifest is None:
        if allow_missing:
            return None
        raise MissingSnapshotError(
            f"No {source.upper()} snapshot found under {Path(snapshot_root) / source}. "
            f"Run: python -m src.fetch_threat_intelligence --source {source} "
            "(or pass --allow-missing-sources to leave those columns explicitly unavailable)."
        )
    snapshot, provenance = load_verified_snapshot(manifest)
    # Disclose the manifest's provenance next to the parsed values, so a report
    # can name the origin and the checksum of the exact bytes that were read.
    for key in (
        "requested_url",
        "final_url",
        "declared_origin",
        "retrieval_method",
        "retrieved_utc",
        "file",
        "bytes",
        "sha256",
    ):
        snapshot.metadata.setdefault(key, provenance.get(key))
    return snapshot


# ---------------------------------------------------------------------------
# Evidence frame
# ---------------------------------------------------------------------------


def _reference_summary(view: Any) -> Tuple[int, int, str]:
    """Return ``(total, advisory, hosts)`` for a record's references."""
    total = len(view.references)
    advisory = 0
    hosts: List[str] = []
    for reference in view.references:
        lowered = {str(tag).lower() for tag in reference.tags}
        if lowered & set(ADVISORY_REFERENCE_TAGS):
            advisory += 1
        host = urlparse(reference.url).netloc.lower()
        if host and host not in hosts:
            hosts.append(host)
    return total, advisory, ";".join(sorted(hosts))


def _changed_since_snapshot(view: Any, mod_date: str) -> str:
    """Whether the official record was updated after the snapshot's mod_date."""
    if not view.date_updated or not mod_date:
        return ""
    updated = pd.to_datetime(view.date_updated, utc=True, errors="coerce")
    snapshot_stamp = pd.to_datetime(mod_date, errors="coerce")
    if pd.isna(updated) or pd.isna(snapshot_stamp):
        return ""
    return _bool_text(updated.tz_localize(None) > snapshot_stamp)


def _exploitation_note(
    kev_status: str,
    kev_date: str,
    epss_status: str,
    epss_snapshot_date: str,
) -> str:
    if kev_status == KEV_STATUS_MATCHED:
        kev_note = (
            "Listed in the CISA KEV snapshot"
            + (f" (added {kev_date})" if kev_date else "")
            + ", which is recorded evidence of known exploitation by that date."
        )
    elif kev_status == KEV_STATUS_NOT_LISTED:
        kev_note = (
            "Absent from the CISA KEV snapshot, which only means it was not listed at that date; "
            "absence from KEV is not evidence that it was never exploited."
        )
    else:
        kev_note = "No KEV snapshot was available, so exploitation evidence is unknown, not negative."
    if epss_status == KEV_STATUS_MATCHED:
        epss_note = (
            "An EPSS score is present for the snapshot score date; it is a current model estimate, "
            "not historical evidence of past exploitation."
        )
    elif epss_status == KEV_STATUS_NOT_LISTED:
        epss_note = "No EPSS row exists for this identifier in the snapshot."
    else:
        epss_note = "No EPSS snapshot was available; the score is unknown, not zero."
    return f"{kev_note} {epss_note}"


def _match_kev(dataset_keys: pd.Series, kev: Optional[ParsedSnapshot]) -> pd.DataFrame:
    if kev is None:
        return pd.DataFrame(
            {
                "kev_matched": pd.Series("", index=dataset_keys.index, dtype="object"),
                "kev_date_added": pd.Series("", index=dataset_keys.index, dtype="object"),
                "kev_known_ransomware_campaign_use": pd.Series("", index=dataset_keys.index, dtype="object"),
            },
            index=dataset_keys.index,
        )
    frame = kev.frame.set_index("cve_id")
    aligned = frame.reindex(dataset_keys.values)
    aligned.index = dataset_keys.index
    return pd.DataFrame(
        {
            "kev_matched": aligned["kev_date_added"].notna().astype(str),
            "kev_date_added": aligned["kev_date_added"].fillna(""),
            "kev_known_ransomware_campaign_use": aligned["kev_known_ransomware_campaign_use"].fillna(""),
        },
        index=dataset_keys.index,
    )


def _match_epss(dataset_keys: pd.Series, epss: Optional[ParsedSnapshot]) -> pd.DataFrame:
    if epss is None:
        return pd.DataFrame(
            {
                "epss_score": pd.Series("", index=dataset_keys.index, dtype="object"),
                "epss_percentile": pd.Series("", index=dataset_keys.index, dtype="object"),
            },
            index=dataset_keys.index,
        )
    frame = epss.frame.set_index("cve_id")
    aligned = frame.reindex(dataset_keys.values)
    aligned.index = dataset_keys.index
    return pd.DataFrame(
        {
            "epss_score": aligned["epss_score"].astype("object").fillna(""),
            "epss_percentile": aligned["epss_percentile"].astype("object").fillna(""),
        },
        index=dataset_keys.index,
    )


def derive_placeholder_values(phase21_audit_path: Optional[Path]) -> Tuple[List[float], str]:
    """CVSS values observed on confirmed-rejected records of this snapshot.

    Reuses the Phase 2.1 derivation (values seen on ``RECORDED_REJECTED`` rows of
    ``rejected_cve_audit.csv``). When that file is absent the value list is empty
    and the note says so, because assuming a placeholder value would be a guess.
    """
    if phase21_audit_path is None or not Path(phase21_audit_path).is_file():
        return [], "unavailable: phase 2.1 rejected-CVE audit not present"
    frame = pd.read_csv(phase21_audit_path, dtype=str, keep_default_na=False)
    if "record_status" not in frame.columns or "source_cvss" not in frame.columns:
        return [], "unavailable: phase 2.1 audit lacks record_status/source_cvss"
    confirmed = frame[frame["record_status"].str.upper() == "REJECTED"]
    values = pd.to_numeric(confirmed["source_cvss"], errors="coerce").dropna().unique()
    return [float(value) for value in sorted(values)], _relative(Path(phase21_audit_path))


def build_audit_frame(
    dataset: pd.DataFrame,
    *,
    baseline_ranks: Dict[str, int],
    reviewed_ranks: Dict[str, int],
    views: Dict[str, Any],
    retrieval_status: Dict[str, str],
    manifest: Optional[Dict[str, Any]],
    kev: Optional[ParsedSnapshot],
    epss: Optional[ParsedSnapshot],
    placeholder_values: Sequence[float],
    failures: Optional[Dict[str, Dict[str, Any]]] = None,
) -> pd.DataFrame:
    """Build the per-record evidence audit table for every disputed row.

    ``failures`` carries the snapshot loader's per-identifier reason string
    (including the parser message for malformed records), which is disclosed
    verbatim in ``official_record_failure_reason``.
    """
    mask = dataset["summary"].map(has_disputed_marker)
    disputed = dataset.loc[mask].copy()
    if disputed.empty:
        raise ValueError("No '** DISPUTED **' records were found in the input dataset.")

    disputed = disputed.reset_index(drop=True)
    keys = disputed["cve_id"].map(normalize_cve_id)
    scores = pd.to_numeric(disputed["cvss"], errors="coerce")
    kev_columns = _match_kev(keys, kev)
    epss_columns = _match_epss(keys, epss)

    manifest_commit = str((manifest or {}).get("commit_sha", ""))
    manifest_repository = str((manifest or {}).get("repository", ""))
    manifest_retrieved = str((manifest or {}).get("retrieved_utc", ""))
    kev_snapshot_date = str((kev.metadata.get("snapshot_date", "") if kev is not None else ""))
    kev_catalog_version = str((kev.metadata.get("date_released_utc", "") if kev is not None else ""))
    epss_snapshot_date = str((epss.metadata.get("snapshot_date", "") if epss is not None else ""))
    epss_score_date = str((epss.metadata.get("score_date_utc", "") if epss is not None else ""))
    epss_model_version = str((epss.metadata.get("model_version", "") if epss is not None else ""))

    rows: List[Dict[str, Any]] = []
    for position in range(len(disputed)):
        identifier = _text(disputed.at[position, "cve_id"]).upper()
        claim = dataset_dispute_text(disputed.at[position, "summary"])
        status = retrieval_status.get(identifier, RETRIEVAL_NOT_ATTEMPTED)
        view = views.get(identifier)
        classification = classify_dispute_evidence(
            view, retrieval_status=status, dataset_claim_text=claim["disputed_claim_text"]
        )

        score = None if pd.isna(scores.at[position]) else float(scores.at[position])
        placeholder_suspect = bool(
            score is not None and any(float(score) == float(value) for value in placeholder_values)
        )
        if score is None:
            cvss_genuine, cvss_note = "", "no_cvss_value_in_snapshot"
        elif view is not None and view.state == "REJECTED":
            cvss_genuine, cvss_note = "False", "withdrawn_identifier_score_not_a_severity"
        elif placeholder_suspect:
            cvss_genuine, cvss_note = (
                "False",
                "value_matches_a_placeholder_observed_on_confirmed_rejected_records",
            )
        else:
            cvss_genuine, cvss_note = "True", "snapshot_value_not_matched_to_a_known_placeholder"

        entry: Dict[str, Any] = {}
        for column in DATASET_COLUMNS:
            entry[column] = disputed.at[position, column] if column in disputed.columns else ""
        entry.update(claim)
        entry["disputed_marker_at_start"] = _bool_text(claim["disputed_marker_at_start"])
        entry["dataset_cvss_snapshot"] = _text(disputed.at[position, "cvss"])
        entry["cvss_placeholder_suspect"] = _bool_text(placeholder_suspect)
        entry["cvss_genuine"] = cvss_genuine
        entry["cvss_note"] = cvss_note
        entry["baseline_rank"] = baseline_ranks.get(identifier, "")
        entry["baseline_band"] = band_label(baseline_ranks.get(identifier))
        entry["reviewed_rank_current_policy"] = reviewed_ranks.get(identifier, "")
        entry["official_lookup_attempted"] = _bool_text(identifier in retrieval_status)

        entry["official_record_retrieval_status"] = status
        if status == RETRIEVAL_RETRIEVED:
            entry["official_record_failure_reason"] = ""
        else:
            recorded = (failures or {}).get(identifier, {})
            entry["official_record_failure_reason"] = str(
                recorded.get("reason") or classification.get("review_reason", "")
            )
        record_entry = ((manifest or {}).get("records", {}) or {}).get(identifier, {})
        entry["official_record_sha256"] = str(record_entry.get("sha256") or "")
        entry["official_record_git_blob_sha"] = str(record_entry.get("git_blob_sha") or "")
        entry["official_record_bytes"] = record_entry.get("bytes", "")
        entry["official_record_api_url"] = str(record_entry.get("url") or "")
        entry["official_record_html_url"] = str(record_entry.get("html_url") or "")
        entry["official_record_path"] = str(record_entry.get("repository_path") or "")
        entry["official_source_repository"] = manifest_repository
        entry["official_source_commit"] = manifest_commit
        entry["official_record_retrieved_utc"] = manifest_retrieved

        for target, source_key in (
            ("official_record_state", "state"),
            ("official_record_data_version", "data_version"),
            ("official_record_assigner", "assigner_short_name"),
            ("official_record_date_reserved", "date_reserved"),
            ("official_record_date_published", "date_published"),
            ("official_record_date_updated", "date_updated"),
            ("official_record_date_rejected", "date_rejected"),
        ):
            entry[target] = str(getattr(view, source_key)) if view is not None else ""
        entry["official_record_changed_since_snapshot"] = (
            _changed_since_snapshot(view, disputed.at[position, "mod_date"]) if view is not None else ""
        )
        entry["official_record_tags"] = ";".join(view.all_tags) if view is not None else ""
        entry["official_record_dispute_tag_present"] = _bool_text(view.dispute_tag_present) if view is not None else ""
        entry["official_record_dispute_language_present"] = (
            _bool_text(classification.get("dispute_language_present", False)) if view is not None else ""
        )
        entry["official_record_dispute_language_rule"] = str(classification.get("dispute_language_rule", ""))
        entry["official_record_dispute_language_field"] = str(classification.get("dispute_language_field", ""))
        entry["official_record_text_fields_scanned"] = (
            ";".join(field.path for field in view.text_fields) if view is not None else ""
        )
        if view is not None:
            total, advisory, hosts = _reference_summary(view)
            entry["official_record_reference_count"] = total
            entry["official_record_advisory_reference_count"] = advisory
            entry["official_record_reference_hosts"] = hosts
        else:
            entry["official_record_reference_count"] = ""
            entry["official_record_advisory_reference_count"] = ""
            entry["official_record_reference_hosts"] = ""
        entry["official_reference_bodies_retrieved"] = "False"

        for target, key in (
            ("official_record_position", "official_record_position"),
            ("dispute_resolution", "dispute_resolution"),
            ("resolution_bucket", "resolution_bucket"),
            ("evidence_classification", "evidence_classification"),
            ("evidence_status", "evidence_status"),
            ("evidence_confidence", "evidence_confidence"),
            ("confidence_rationale", "confidence_rationale"),
            ("exclusion_evidence", "exclusion_evidence"),
            ("authoritative_rationale_status", "authoritative_rationale_status"),
            ("authoritative_rationale_field", "authoritative_rationale_field"),
            ("authoritative_rationale", "authoritative_rationale"),
            ("dispute_actor", "dispute_actor"),
            ("dispute_actor_field", "dispute_actor_field"),
            ("dispute_actor_quote", "dispute_actor_quote"),
            ("dispute_subject", "dispute_subject"),
            ("dispute_subject_field", "dispute_subject_field"),
            ("dispute_subject_quote", "dispute_subject_quote"),
            ("contradiction_rule", "contradiction_rule"),
            ("contradiction_field", "contradiction_field"),
            ("contradiction_quote", "contradiction_quote"),
        ):
            entry[target] = str(classification.get(key, "") or "")
        replacements = classification.get("replacement_ids") or ()
        entry["replacement_related_cve_ids"] = ";".join(str(item) for item in replacements)
        entry["replacement_evidence_field"] = str(classification.get("replacement_evidence_field", "") or "")

        if kev is None:
            kev_status = KEV_STATUS_UNAVAILABLE
        elif kev_columns.at[position, "kev_matched"] == "True":
            kev_status = KEV_STATUS_MATCHED
        else:
            kev_status = KEV_STATUS_NOT_LISTED
        entry["kev_snapshot_status"] = kev_status
        entry["kev_snapshot_date"] = kev_snapshot_date
        entry["kev_catalog_version"] = kev_catalog_version
        entry["kev_date_added"] = _text(kev_columns.at[position, "kev_date_added"])
        entry["kev_known_ransomware_campaign_use"] = _text(
            kev_columns.at[position, "kev_known_ransomware_campaign_use"]
        )
        entry["kev_source"] = str((kev.metadata.get("declared_origin") or "") if kev is not None else "")

        if epss is None:
            epss_status = KEV_STATUS_UNAVAILABLE
        elif _text(epss_columns.at[position, "epss_score"]) != "":
            epss_status = KEV_STATUS_MATCHED
        else:
            epss_status = KEV_STATUS_NOT_LISTED
        entry["epss_snapshot_status"] = epss_status
        entry["epss_snapshot_date"] = epss_snapshot_date or epss_score_date
        entry["epss_model_version"] = epss_model_version
        entry["epss_score"] = _text(epss_columns.at[position, "epss_score"])
        entry["epss_percentile"] = _text(epss_columns.at[position, "epss_percentile"])
        entry["epss_source"] = str((epss.metadata.get("declared_origin") or "") if epss is not None else "")
        entry["exploitation_evidence_note"] = _exploitation_note(
            kev_status, entry["kev_date_added"], epss_status, entry["epss_snapshot_date"]
        )

        review = review_decision(
            baseline_rank=baseline_ranks.get(identifier),
            evidence_status=str(classification.get("evidence_status", "")),
            exclusion_evidence=str(classification.get("exclusion_evidence", "")),
            dispute_resolution=str(classification.get("dispute_resolution", "")),
            review_reason=str(classification.get("review_reason", "") or ""),
        )
        entry.update(review)
        rows.append(entry)

    frame = pd.DataFrame(rows)
    frame = frame[[column for column in DATASET_COLUMNS if column in frame.columns] + list(AUDIT_COLUMNS)]
    ranks = pd.to_numeric(frame["baseline_rank"], errors="coerce")
    frame = frame.assign(__sort=ranks.fillna(len(frame) + 1)).sort_values(
        ["__sort", "cve_id"], kind="mergesort"
    )
    frame = frame.drop(columns=["__sort"]).reset_index(drop=True)
    return frame


def band_label(rank: Optional[int]) -> str:
    """Return the baseline band of a rank, or blank when the record is unranked."""
    if rank is None:
        return ""
    for level in TOP_N_LEVELS:
        if int(rank) <= level:
            return f"TOP_{level}"
    return f"BELOW_TOP_{TOP_N_LEVELS[-1]}"


def review_decision(
    *,
    baseline_rank: Optional[int],
    evidence_status: str,
    exclusion_evidence: str,
    dispute_resolution: str,
    review_reason: str,
) -> Dict[str, Any]:
    """Decide whether a disputed record needs human review, and why.

    This is a review-workflow decision only. It never changes eligibility, a
    score, or a rank.
    """
    high_ranked = baseline_rank is not None and int(baseline_rank) <= REVIEW_RANK_THRESHOLD
    evidence_gap = evidence_status in ("INSUFFICIENT", "CONTRADICTORY", "NOT_VERIFIABLE")
    withdrawable = exclusion_evidence == EXCLUSION_SUPPORTED

    if high_ranked and (evidence_gap or withdrawable):
        priority = REVIEW_PRIORITY_HIGH
    elif high_ranked and dispute_resolution == RESOLUTION_OPEN:
        priority = REVIEW_PRIORITY_CONTESTED
    elif evidence_gap or withdrawable:
        priority = REVIEW_PRIORITY_EVIDENCE_GAP
    else:
        return {
            "human_review_required": "False",
            "human_review_priority": "",
            "review_reason": "",
        }
    reasons = []
    if withdrawable:
        reasons.append("authoritative_record_is_withdrawn_but_record_remains_ranked")
    if evidence_gap:
        reasons.append(review_reason or "evidence_gap")
    if priority == REVIEW_PRIORITY_CONTESTED:
        reasons.append("high_ranked_record_whose_dispute_remains_open_at_the_source")
    return {
        "human_review_required": "True",
        "human_review_priority": REVIEW_PRIORITY_LABELS[priority],
        "review_reason": ";".join(dict.fromkeys(reasons)),
    }


# ---------------------------------------------------------------------------
# Ranking scenarios
# ---------------------------------------------------------------------------


def scenario_exclusions(
    audit: pd.DataFrame,
    scenario: str,
) -> Tuple[Set[str], Set[str]]:
    """Return ``(excluded_ids, flagged_ids)`` for one scenario.

    No scenario consults the number of records it would remove, and no scenario
    infers validity from a marker.
    """
    identifiers = audit["cve_id"].astype(str)
    if scenario == SCENARIO_CURRENT:
        return set(), set()
    if scenario == SCENARIO_EVIDENCE_EXCLUSION:
        mask = audit["exclusion_evidence"].astype(str).eq(EXCLUSION_SUPPORTED)
        return set(identifiers[mask]), set()
    if scenario == SCENARIO_FLAG_ONLY:
        mask = audit["human_review_required"].astype(str).eq("True")
        return set(), set(identifiers[mask])
    if scenario == SCENARIO_MARKER_ONLY:
        return set(identifiers), set()
    raise ValueError(f"Unknown scenario: {scenario!r}")


def scenario_ranking(reference: pd.DataFrame, excluded: Set[str]) -> pd.DataFrame:
    """Re-rank a reference ranking after removing ``excluded`` identifiers.

    The ranking rule is the unmodified :func:`src.baseline.rank_by_cvss`, so
    scenario rankings differ from the reference only by the rows removed.
    """
    keep = ~reference["cve_id"].astype(str).isin(excluded)
    subset = reference.loc[keep, ["cve_id", "cvss"]].copy()
    if subset.empty:
        return pd.DataFrame({"cve_id": [], "cvss": [], "rank": []})
    ranked = rank_by_cvss(subset)
    return pd.DataFrame({"cve_id": ranked["cve_id"].astype(str), "cvss": ranked["cvss"], "rank": ranked["baseline_rank"]})


def compare_rankings(
    reference: pd.DataFrame,
    scenario: pd.DataFrame,
    *,
    level: Optional[int],
) -> Dict[str, Any]:
    """Compare a scenario ranking with a reference ranking at one depth."""
    reference_sorted = reference.sort_values(["__rank", "cve_id"], kind="mergesort").reset_index(drop=True)
    reference_ids = reference_sorted["cve_id"].astype(str).tolist()
    scenario_ids = scenario["cve_id"].astype(str).tolist()

    depth = len(reference_ids) if level is None else min(level, len(reference_ids))
    reference_head = reference_ids[:depth]
    scenario_head = scenario_ids[:depth]
    reference_head_set = set(reference_head)
    scenario_head_set = set(scenario_head)

    removed = [cve_id for cve_id in reference_head if cve_id not in scenario_head_set]
    added = [cve_id for cve_id in scenario_head if cve_id not in reference_head_set]
    first_difference = None
    positions_changed = 0
    for index in range(depth):
        left = reference_head[index] if index < len(reference_head) else None
        right = scenario_head[index] if index < len(scenario_head) else None
        if left != right:
            positions_changed += 1
            if first_difference is None:
                first_difference = index + 1

    scenario_rank = {cve_id: index + 1 for index, cve_id in enumerate(scenario_ids)}
    shifts = []
    for index, cve_id in enumerate(reference_head):
        new_rank = scenario_rank.get(cve_id)
        if new_rank is None:
            continue
        shift = (index + 1) - new_rank
        if shift:
            shifts.append((abs(shift), shift, cve_id))
    shifts.sort(key=lambda item: (-item[0], item[2]))
    return {
        "level": "full" if level is None else level,
        "depth": depth,
        "reference_rows": len(reference_ids),
        "scenario_rows": len(scenario_ids),
        "removed_ids_all": removed,
        "added_ids_all": added,
        "ids_removed_from_top": ";".join(removed[:40]),
        "ids_removed_from_top_count": len(removed),
        "ids_added_to_top": ";".join(added[:40]),
        "ids_added_to_top_count": len(added),
        "first_position_changed": first_difference if first_difference is not None else "",
        "positions_changed_count": positions_changed,
        "max_abs_rank_shift": shifts[0][0] if shifts else 0,
        "max_rank_shift_cve": shifts[0][2] if shifts else "",
        "net_rank_shift_cve": shifts[0][1] if shifts else 0,
    }


def build_sensitivity(
    references: Dict[str, pd.DataFrame],
    audit: pd.DataFrame,
    scenarios: Sequence[str] = SCENARIOS,
    levels: Sequence[int] = TOP_N_LEVELS,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Measure every scenario against every reference ranking.

    Returns ``(sensitivity_frame, details)`` where ``details`` holds the excluded
    and flagged identifier sets per scenario for the summary.
    """
    rows: List[Dict[str, Any]] = []
    details: Dict[str, Any] = {}
    for scenario in scenarios:
        excluded, flagged = scenario_exclusions(audit, scenario)
        details[scenario] = {
            "scenario_role": SCENARIO_ROLES[scenario],
            "evidence_justified": bool(SCENARIO_EVIDENCE_JUSTIFIED[scenario]),
            "excluded_count": len(excluded),
            "flagged_count": len(flagged),
            "description": SCENARIO_DESCRIPTIONS[scenario],
            "justification": SCENARIO_JUSTIFICATION[scenario],
        }
        for reference_label, reference in references.items():
            scenario_frame = scenario_ranking(reference, excluded)
            ordered_reference = reference.sort_values(["__rank", "cve_id"], kind="mergesort")
            disputed_ids = set(audit["cve_id"].astype(str))
            for level in list(levels) + [None]:
                comparison = compare_rankings(reference, scenario_frame, level=level)
                baseline_head = ordered_reference.head(comparison["depth"])["cve_id"].astype(str)
                rows.append(
                    {
                        "scenario": scenario,
                        "scenario_role": SCENARIO_ROLES[scenario],
                        "reference_ranking": reference_label,
                        "level": str(comparison["level"]),
                        "records_excluded_by_scenario": len(excluded),
                        "records_flagged_for_review": len(flagged),
                        "evidence_justified": _bool_text(SCENARIO_EVIDENCE_JUSTIFIED[scenario]),
                        "disputed_records_in_reference_head": int(baseline_head.isin(disputed_ids).sum()),
                        "disputed_records_removed_from_head": int(comparison["ids_removed_from_top_count"]),
                        "flagged_records_in_reference_head": int(baseline_head.isin(flagged).sum()),
                        "records_removed_from_head": int(comparison["ids_removed_from_top_count"]),
                        "records_added_to_head": int(comparison["ids_added_to_top_count"]),
                        "ids_removed_from_top": comparison["ids_removed_from_top"],
                        "ids_added_to_top": comparison["ids_added_to_top"],
                        "first_position_changed": comparison["first_position_changed"],
                        "positions_changed_count": comparison["positions_changed_count"],
                        "max_abs_rank_shift_within_head": comparison["max_abs_rank_shift"],
                        "max_rank_shift_cve": comparison["max_rank_shift_cve"],
                        "depth": comparison["depth"],
                        "scenario_justification": SCENARIO_JUSTIFICATION[scenario],
                    }
                )
    frame = pd.DataFrame(rows)
    return frame, details


def build_ranking_impact(
    references: Dict[str, pd.DataFrame],
    audit: pd.DataFrame,
) -> pd.DataFrame:
    """Per-record baseline/reviewed/scenario ranks for every disputed record.

    Scenario ranks are measured against the current-policy reference ranking: the
    Phase 2.1 reviewed ranking when it is present, otherwise the baseline.
    """
    baseline = references[REFERENCE_BASELINE]
    baseline_by_id = ranking_index(baseline)
    current_reference = references.get(REFERENCE_REVIEWED, baseline)
    rows: List[Dict[str, Any]] = []
    scenario_frames = {
        scenario: scenario_ranking(current_reference, scenario_exclusions(audit, scenario)[0])
        for scenario in SCENARIOS
    }
    scenario_ranks = {
        scenario: {cve_id: rank for cve_id, rank in zip(frame["cve_id"], frame["rank"])}
        for scenario, frame in scenario_frames.items()
    }
    excluded_sets = {scenario: scenario_exclusions(audit, scenario)[0] for scenario in SCENARIOS}

    for _, entry in audit.iterrows():
        identifier = str(entry["cve_id"])
        baseline_rank = baseline_by_id.get(identifier)
        reviewed_rank = entry.get("reviewed_rank_current_policy", "")
        reviewed_rank_value = _json_number(reviewed_rank) if _text(reviewed_rank) else None
        row: Dict[str, Any] = {
            "cve_id": identifier,
            "baseline_rank": int(baseline_rank) if baseline_rank is not None and not pd.isna(baseline_rank) else "",
            "baseline_band": entry.get("baseline_band", ""),
            "reviewed_rank_current_policy": int(reviewed_rank_value) if reviewed_rank_value else "",
            "official_record_state": entry.get("official_record_state", ""),
            "dispute_resolution": entry.get("dispute_resolution", ""),
            "evidence_classification": entry.get("evidence_classification", ""),
            "evidence_status": entry.get("evidence_status", ""),
            "evidence_confidence": entry.get("evidence_confidence", ""),
            "exclusion_evidence": entry.get("exclusion_evidence", ""),
            "human_review_required": entry.get("human_review_required", ""),
            "human_review_priority": entry.get("human_review_priority", ""),
        }
        for level in TOP_N_LEVELS:
            row[f"baseline_in_top_{level}"] = _bool_text(
                baseline_rank is not None and not pd.isna(baseline_rank) and int(baseline_rank) <= level
            )
            row[f"reviewed_in_top_{level}"] = _bool_text(
                reviewed_rank_value is not None and int(reviewed_rank_value) <= level
            )
        for scenario in SCENARIOS:
            key = f"{scenario.lower()}_rank"
            row[key] = ""
            if scenario == SCENARIO_FLAG_ONLY:
                row[key] = row["reviewed_rank_current_policy"]
                continue
            if identifier in excluded_sets[scenario]:
                row[key] = ""
                continue
            rank = scenario_ranks[scenario].get(identifier)
            row[key] = int(rank) if rank is not None and not pd.isna(rank) else ""
        s0 = _json_number(row[f"{SCENARIO_CURRENT.lower()}_rank"])
        s1 = _json_number(row[f"{SCENARIO_EVIDENCE_EXCLUSION.lower()}_rank"])
        row["current_policy_rank_shift_vs_reviewed"] = (
            (int(reviewed_rank_value) - int(s0)) if reviewed_rank_value and s0 else ""
        )
        row["evidence_exclusion_rank"] = int(s1) if s1 else ""
        row["evidence_exclusion_rank_shift_vs_reviewed"] = (
            (int(reviewed_rank_value) - int(s1)) if reviewed_rank_value and s1 else ""
        )
        row["evidence_exclusion_applies"] = _bool_text(identifier in excluded_sets[SCENARIO_EVIDENCE_EXCLUSION])
        row["marker_only_exclusion_applies"] = _bool_text(identifier in excluded_sets[SCENARIO_MARKER_ONLY])
        rows.append(row)
    frame = pd.DataFrame(rows)
    order = ["cve_id", "baseline_rank", "baseline_band", "reviewed_rank_current_policy"]
    order += [f"baseline_in_top_{level}" for level in TOP_N_LEVELS]
    order += [f"reviewed_in_top_{level}" for level in TOP_N_LEVELS]
    order += [
        "official_record_state",
        "dispute_resolution",
        "evidence_classification",
        "evidence_status",
        "evidence_confidence",
        "exclusion_evidence",
        "human_review_required",
        "human_review_priority",
    ]
    order += [f"{scenario.lower()}_rank" for scenario in SCENARIOS]
    order += [
        "current_policy_rank_shift_vs_reviewed",
        "evidence_exclusion_applies",
        "evidence_exclusion_rank_shift_vs_reviewed",
        "marker_only_exclusion_applies",
    ]
    return frame[[column for column in order if column in frame.columns]]


def build_review_queue(audit: pd.DataFrame) -> pd.DataFrame:
    """Rows that need human review, most urgent first."""
    columns = [
        "cve_id",
        "baseline_rank",
        "baseline_band",
        "reviewed_rank_current_policy",
        "cvss",
        "dataset_cvss_snapshot",
        "cvss_placeholder_suspect",
        "cvss_genuine",
        "official_record_state",
        "dispute_resolution",
        "resolution_bucket",
        "evidence_classification",
        "evidence_status",
        "evidence_confidence",
        "exclusion_evidence",
        "human_review_priority",
        "review_reason",
        "disputed_claim_text",
        "authoritative_rationale",
        "authoritative_rationale_field",
        "official_record_html_url",
    ]
    queue = audit[audit["human_review_required"].astype(str).eq("True")].copy()
    if queue.empty:
        return pd.DataFrame(columns=columns)
    queue["__priority"] = queue["human_review_priority"].astype(str)
    ranks = pd.to_numeric(queue["baseline_rank"], errors="coerce").fillna(len(audit) + 1)
    queue = queue.assign(__rank=ranks).sort_values(["__priority", "__rank", "cve_id"], kind="mergesort")
    queue = queue.drop(columns=["__priority", "__rank"]).reset_index(drop=True)
    return queue[[column for column in columns if column in queue.columns]]


# ---------------------------------------------------------------------------
# Summary and manifest
# ---------------------------------------------------------------------------


def _counts(values: Iterable[Any]) -> Dict[str, int]:
    frame = pd.Series([str(value) if _text(value) != "" else "<BLANK>" for value in values])
    return {str(key): int(value) for key, value in frame.value_counts().sort_index().items()}


def build_summary(
    *,
    dataset: pd.DataFrame,
    audit: pd.DataFrame,
    sensitivity: pd.DataFrame,
    scenario_details: Dict[str, Any],
    manifest: Optional[Dict[str, Any]],
    views: Dict[str, Any],
    failures: Dict[str, Dict[str, Any]],
    kev: Optional[ParsedSnapshot],
    epss: Optional[ParsedSnapshot],
    placeholder_values: Sequence[float],
    placeholder_note: str,
    verification: Dict[str, Any],
    generated_utc: str,
) -> Dict[str, Any]:
    """Assemble the machine-readable audit summary."""
    scores = pd.to_numeric(audit["dataset_cvss_snapshot"], errors="coerce")
    baseline_ranks = pd.to_numeric(audit["baseline_rank"], errors="coerce")
    summary: Dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "audit_version": AUDIT_VERSION,
        "policy_version_in_force": POLICY_VERSION,
        "generated_utc": generated_utc,
        "ranking_policy_changed": False,
        "policy_statement": (
            "The ranking policy is unchanged. Every '** DISPUTED **' record remains eligible with its "
            "original snapshot CVSS score in the baseline and in the Phase 2.1 reviewed ranking. The "
            "scenarios below are analytical only and were not applied to any production artifact."
        ),
        "not_a_model": (
            "This is a data-quality and evidence audit. No model was trained, no label was invented, no "
            "exploitation was predicted, and a dispute marker was never treated as proof that a CVE is invalid."
        ),
        "scope": {
            "dataset_rows": int(len(dataset)),
            "disputed_rows_examined": int(len(audit)),
            "marker_rule": "summary contains the exact '** DISPUTED **' marker (src.cve_status_sources.has_disputed_marker)",
            "original_marker_inventory": _relative(DEFAULT_PHASE21_DISPUTED_REPORT_PATH),
            "original_marker_inventory_untouched": True,
        },
        "evidence_sources": {
            "primary": {
                "role": "official CVE Program record (administrative status, tags, text)",
                "repository": str((manifest or {}).get("repository", "")),
                "requested_ref": str((manifest or {}).get("requested_ref", "")),
                "commit_sha": str((manifest or {}).get("commit_sha", "")),
                "retrieved_utc": str((manifest or {}).get("retrieved_utc", "")),
                "record_count": int((manifest or {}).get("record_count", 0)),
                "missing_count": int((manifest or {}).get("missing_count", 0)),
                "snapshot_manifest": _relative(Path(str((manifest or {}).get("_manifest_path", ""))))
                if manifest
                else "",
                "retrieval_method": str((manifest or {}).get("retrieval_method", "")),
            },
            "secondary": {
                "kev": source_summary(kev, "kev"),
                "epss": source_summary(epss, "epss"),
            },
            "reference_bodies_retrieved": False,
            "reference_bodies_note": (
                "Reference and advisory URLs recorded inside the official CVE records were not fetched in "
                "this environment, so their content is not used as evidence. Only the official record's own "
                "text is quoted."
            ),
        },
        "records": {
            "audited": int(len(audit)),
            "resolved": int(audit["resolution_bucket"].eq(BUCKET_RESOLVED).sum()),
            "unresolved": int(audit["resolution_bucket"].eq(BUCKET_UNRESOLVED).sum()),
            "not_verifiable": int(audit["resolution_bucket"].eq(BUCKET_NOT_VERIFIABLE).sum()),
            "official_records_retrieved": int(audit["official_record_retrieval_status"].eq(RETRIEVAL_RETRIEVED).sum()),
            "official_records_not_retrieved": int((~audit["official_record_retrieval_status"].eq(RETRIEVAL_RETRIEVED)).sum()),
            "exclusion_evidence_supported": int(audit["exclusion_evidence"].eq(EXCLUSION_SUPPORTED).sum()),
            "exclusion_evidence_not_supported": int(audit["exclusion_evidence"].eq("NOT_SUPPORTED").sum()),
            "exclusion_evidence_not_evaluable": int(audit["exclusion_evidence"].eq(EXCLUSION_NOT_EVALUABLE).sum()),
            "human_review_required": int(audit["human_review_required"].astype(str).eq("True").sum()),
            "records_with_cvss_genuine_false": int(audit["cvss_genuine"].eq("False").sum()),
            "records_matching_known_placeholder_value": int(audit["cvss_placeholder_suspect"].eq("True").sum()),
        },
        "resolution_buckets": _counts(audit["resolution_bucket"]),
        "retrieval_status": _counts(audit["official_record_retrieval_status"]),
        "official_record_states": _counts(audit["official_record_state"]),
        "evidence_classifications": _counts(audit["evidence_classification"]),
        "evidence_status": _counts(audit["evidence_status"]),
        "evidence_confidence": _counts(audit["evidence_confidence"]),
        "official_record_positions": _counts(audit["official_record_position"]),
        "dispute_actors": _counts(audit["dispute_actor"]),
        "dispute_subjects": _counts(audit["dispute_subject"]),
        "replacement_ids_documented": int(audit["replacement_related_cve_ids"].astype(str).str.len().gt(0).sum()),
        "cvss_distribution": [
            {"cvss": _json_number(score), "records": int(count)}
            for score, count in scores.value_counts().sort_index().items()
        ],
        "cvss_placeholder_values_reference": {
            "values": [float(value) for value in placeholder_values],
            "source": placeholder_note,
            "note": (
                "Derived exactly as Phase 2.1 derives them: CVSS values observed on records whose official "
                "state is REJECTED. Matching a placeholder value means the snapshot value cannot be treated "
                "as a confirmed severity; it does not mean the value is fabricated."
            ),
        },
        "baseline_bands": {
            f"top_{level}": int((baseline_ranks <= level).sum()) for level in TOP_N_LEVELS
        }
        | {"below_top_10000": int((baseline_ranks > TOP_N_LEVELS[-1]).sum())},
        "top_ranked_disputed_ids": {
            f"top_{level}": sorted(audit.loc[baseline_ranks <= level, "cve_id"].astype(str).tolist())
            for level in TOP_N_LEVELS
        },
        "kev_evidence": {
            "snapshot_available": kev is not None,
            "snapshot_date": str((kev.metadata.get("snapshot_date", "") if kev is not None else "")),
            "catalog_released_utc": str((kev.metadata.get("date_released_utc", "") if kev is not None else "")),
            "catalog_records": int(len(kev.frame)) if kev is not None else 0,
            "matched": int(audit["kev_snapshot_status"].eq(KEV_STATUS_MATCHED).sum()),
            "not_listed_in_snapshot": int(audit["kev_snapshot_status"].eq(KEV_STATUS_NOT_LISTED).sum()),
            "snapshot_unavailable": int(audit["kev_snapshot_status"].eq(KEV_STATUS_UNAVAILABLE).sum()),
            "matched_ids": sorted(audit.loc[audit["kev_snapshot_status"].eq(KEV_STATUS_MATCHED), "cve_id"].astype(str)),
            "missing_semantics": (
                "SNAPSHOT_UNAVAILABLE means unknown, not negative; NOT_LISTED_IN_SNAPSHOT means the identifier "
                "was absent from the KEV catalog on the snapshot date, which is not evidence that the "
                "vulnerability was never exploited."
            ),
        },
        "epss_evidence": {
            "snapshot_available": epss is not None,
            "snapshot_date": str((epss.metadata.get("snapshot_date", "") if epss is not None else "")),
            "score_date_utc": str((epss.metadata.get("score_date_utc", "") if epss is not None else "")),
            "model_version": str((epss.metadata.get("model_version", "") if epss is not None else "")),
            "matched": int(audit["epss_snapshot_status"].eq(KEV_STATUS_MATCHED).sum()),
            "not_listed_in_snapshot": int(audit["epss_snapshot_status"].eq(KEV_STATUS_NOT_LISTED).sum()),
            "snapshot_unavailable": int(audit["epss_snapshot_status"].eq(KEV_STATUS_UNAVAILABLE).sum()),
            "missing_semantics": (
                "An EPSS score is a current model estimate for its score date and is not historical evidence "
                "of past exploitation, and an absent row is unknown rather than zero."
            ),
        },
        "retrieval_failures": {
            "count": len(failures),
            "records": [
                {"cve_id": cve_id, "reason": entry.get("reason", ""), "retrieval_status": entry.get("retrieval_status", "")}
                for cve_id, entry in sorted(failures.items())
            ],
        },
        "ranking_verification": verification,
        "sensitivity": {
            "current_policy": scenario_details.get(SCENARIO_CURRENT, {}),
            "scenarios": scenario_details,
            "ranking_effect": _sensitivity_digest(sensitivity),
            "caveat": (
                "Only scenario S1 is justified by retrieved authoritative evidence, and it applies only to "
                "identifiers whose official record state is REJECTED. Scenario S3 is reported to quantify the "
                "effect of a marker-only rule and is explicitly not evidence-justified."
            ),
        },
        "review_priorities": _counts(audit.loc[audit["human_review_required"].astype(str).eq("True"), "human_review_priority"]),
        "limitations": LIMITATIONS,
        "reproduction": [
            "python -c \"from pathlib import Path; from zipfile import ZipFile; p=Path('data/raw/vulnerabilities.csv'); "
            "p.parent.mkdir(parents=True, exist_ok=True); p.exists() or p.write_bytes(ZipFile('cve.csv.zip').read('cve.csv'))\"",
            "python -m src.validate_data",
            "python -m src.preprocess_data",
            "python -m src.baseline",
            "python -m src.fetch_cve_status --input data/processed/vulnerabilities_clean.csv",
            "python -m src.audit_rejected_cves --allow-missing-sources",
            "python -m src.fetch_disputed_status --input data/processed/vulnerabilities_clean.csv",
            "python -m src.audit_disputed_cves",
            "python -m unittest discover -s tests -v",
        ],
    }
    return summary


def _sensitivity_digest(sensitivity: pd.DataFrame) -> List[Dict[str, Any]]:
    digest: List[Dict[str, Any]] = []
    for _, row in sensitivity.iterrows():
        if str(row.get("level")) == "full":
            continue
        digest.append(
            {
                "scenario": str(row["scenario"]),
                "reference_ranking": str(row["reference_ranking"]),
                "level": str(row["level"]),
                "evidence_justified": str(row["evidence_justified"]) == "True",
                "disputed_records_in_reference_head": int(row["disputed_records_in_reference_head"]),
                "disputed_records_removed_from_head": int(row["disputed_records_removed_from_head"]),
                "first_position_changed": json_safe(row["first_position_changed"]),
                "positions_changed_count": int(row["positions_changed_count"]),
            }
        )
    return digest


def source_summary(snapshot: Optional[ParsedSnapshot], label: str) -> Dict[str, Any]:
    if snapshot is None:
        return {
            "available": False,
            "label": label,
            "note": (
                "No snapshot was available in this environment, so the audit records the field as unknown "
                "rather than as a negative result."
            ),
        }
    metadata = snapshot.metadata
    return {
        "available": True,
        "label": label,
        "snapshot_date": metadata.get("snapshot_date", ""),
        "score_date_utc": metadata.get("score_date_utc", ""),
        "model_version": metadata.get("model_version", ""),
        "date_released_utc": metadata.get("date_released_utc", ""),
        "record_count": int(len(snapshot.frame)),
        "declared_origin": metadata.get("declared_origin", "") or "",
        "requested_url": metadata.get("requested_url", "") or "",
        "retrieval_method": metadata.get("retrieval_method", ""),
        "snapshot_file": metadata.get("file", ""),
        "sha256": metadata.get("sha256", ""),
        "bytes": metadata.get("bytes", ""),
        "retrieved_utc": metadata.get("retrieved_utc", ""),
    }


def build_source_manifest(
    *,
    dataset_path: Path,
    manifest: Optional[Dict[str, Any]],
    kev: Optional[ParsedSnapshot],
    epss: Optional[ParsedSnapshot],
    failures: Dict[str, Dict[str, Any]],
    phase21_report_path: Path,
    generated_utc: str,
    artifacts: Dict[str, Dict[str, Any]],
    placeholder_note: str,
) -> Dict[str, Any]:
    """Describe every input the audit read, with pins, checksums, and timestamps."""
    report_hash = sha256_file(phase21_report_path) if Path(phase21_report_path).is_file() else ""
    source: Dict[str, Any] = {
        "schema": "vulnova-disputed-cve-source-manifest-1",
        "generated_utc": generated_utc,
        "audit_version": AUDIT_VERSION,
        "dataset": {
            "path": _relative(Path(dataset_path)),
            "sha256": sha256_file(dataset_path),
            "bytes": Path(dataset_path).stat().st_size,
            "role": "audited input (clean CSV; derived from data/raw/vulnerabilities.csv)",
        },
        "immutable_inputs": raw_dataset_state(),
        "official_cve_records": {
            "repository": str((manifest or {}).get("repository", "")),
            "requested_ref": str((manifest or {}).get("requested_ref", "")),
            "commit_sha": str((manifest or {}).get("commit_sha", "")),
            "retrieved_utc": str((manifest or {}).get("retrieved_utc", "")),
            "retrieval_method": str((manifest or {}).get("retrieval_method", "")),
            "snapshot_manifest": _relative(Path(str((manifest or {}).get("_manifest_path", ""))))
            if manifest
            else "",
            "snapshot_manifest_sha256": _manifest_hash(manifest),
            "records_present": int((manifest or {}).get("record_count", 0)),
            "records_missing": int((manifest or {}).get("missing_count", 0)),
            "missing_semantics": (
                "A missing record is NOT_VERIFIABLE: the audit never treats a missing or unreachable record "
                "as a rejection."
            ),
            "failures": [
                {
                    "cve_id": cve_id,
                    "reason": entry.get("reason", ""),
                    "retrieval_status": entry.get("retrieval_status", ""),
                }
                for cve_id, entry in sorted(failures.items())
            ],
        },
        "kev": source_summary(kev, "kev"),
        "epss": source_summary(epss, "epss"),
        "placeholder_reference": placeholder_note,
        "phase21_disputed_report": {
            "path": _relative(Path(phase21_report_path)),
            "sha256": report_hash,
            "role": "original marker inventory; read only, never written by Phase 2.2",
        },
        "artifacts": artifacts,
    }
    return source


def _manifest_hash(manifest: Optional[Dict[str, Any]]) -> str:
    if not manifest:
        return ""
    path = Path(str(manifest.get("_manifest_path", "")))
    return sha256_file(path) if path.is_file() else ""


def _artifact_table(paths: Sequence[Path]) -> Dict[str, Dict[str, Any]]:
    table: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        path = Path(path)
        table[_relative(path)] = {
            "sha256": sha256_file(path) if path.is_file() else "",
            "bytes": path.stat().st_size if path.is_file() else 0,
        }
    return table


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_audit(
    *,
    clean_path: Path = DEFAULT_CLEAN_PATH,
    baseline_ranked_path: Path = DEFAULT_BASELINE_RANKED_PATH,
    reviewed_ranked_path: Optional[Path] = DEFAULT_REVIEWED_RANKED_PATH,
    disputed_root: Path = DEFAULT_DISPUTED_ROOT,
    disputed_manifest: Optional[Path] = None,
    snapshot_root: Path = DEFAULT_SNAPSHOT_ROOT,
    allow_missing_sources: bool = False,
    audit_path: Path = DEFAULT_AUDIT_PATH,
    impact_path: Path = DEFAULT_IMPACT_PATH,
    review_queue_path: Path = DEFAULT_REVIEW_QUEUE_PATH,
    sensitivity_path: Path = DEFAULT_SENSITIVITY_PATH,
    summary_path: Path = DEFAULT_SUMMARY_PATH,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    phase21_disputed_report: Path = DEFAULT_PHASE21_DISPUTED_REPORT_PATH,
    phase21_audit_path: Optional[Path] = DEFAULT_PHASE21_AUDIT_PATH,
    generated_utc: Optional[str] = None,
    write: bool = True,
) -> Dict[str, Any]:
    """Run the Phase 2.2 audit and (optionally) write its artifacts."""
    generated = generated_utc or _utc_now_text()
    dataset = read_dataset(Path(clean_path))

    # The Phase 2.1 marker inventory is an input, never an output.
    report_hash_before = (
        sha256_file(phase21_disputed_report) if Path(phase21_disputed_report).is_file() else ""
    )

    baseline_reference = read_ranked_ids(Path(baseline_ranked_path), "baseline_rank")
    baseline_verification = verify_ranking_reproduced(
        baseline_reference, "baseline_rank", label=REFERENCE_BASELINE
    )
    fresh_baseline = rank_by_cvss(dataset[["cve_id", "cvss"]].copy())
    baseline_matches_dataset = bool(
        fresh_baseline["cve_id"].astype(str).tolist() == baseline_reference["cve_id"].astype(str).tolist()
    )
    baseline_verification["matches_clean_dataset"] = baseline_matches_dataset
    baseline_verification["rows_in_dataset"] = int(len(dataset))

    references: Dict[str, pd.DataFrame] = {REFERENCE_BASELINE: baseline_reference}
    reviewed_verification: Dict[str, Any] = {
        "reference": REFERENCE_REVIEWED,
        "available": False,
        "note": "Phase 2.1 reviewed ranking not present; scenarios were measured against the baseline only.",
    }
    if reviewed_ranked_path is not None and Path(reviewed_ranked_path).is_file():
        reviewed_reference = read_ranked_ids(Path(reviewed_ranked_path), "reviewed_rank")
        references[REFERENCE_REVIEWED] = reviewed_reference
        reviewed_verification = verify_ranking_reproduced(
            reviewed_reference, "reviewed_rank", label=REFERENCE_REVIEWED
        )
        reviewed_verification["available"] = True

    views, retrieval, failures, manifest = load_disputed_records(Path(disputed_root), disputed_manifest)
    kev = load_threat_intel(KEV_SOURCE, snapshot_root=Path(snapshot_root), allow_missing=True)
    epss = load_threat_intel(EPSS_SOURCE, snapshot_root=Path(snapshot_root), allow_missing=True)
    if not allow_missing_sources and kev is None and epss is None:
        raise MissingSnapshotError(
            "Neither KEV nor EPSS snapshot was available. Pass --allow-missing-sources to record them as "
            "explicitly unavailable instead."
        )

    placeholder_values, placeholder_note = derive_placeholder_values(
        Path(phase21_audit_path) if phase21_audit_path else None
    )

    baseline_ranks = ranking_index(baseline_reference)
    reviewed_ranks = (
        ranking_index(references[REFERENCE_REVIEWED]) if REFERENCE_REVIEWED in references else {}
    )
    audit = build_audit_frame(
        dataset,
        baseline_ranks=baseline_ranks,
        reviewed_ranks=reviewed_ranks,
        views=views,
        retrieval_status=retrieval,
        manifest=manifest,
        kev=kev,
        epss=epss,
        placeholder_values=placeholder_values,
        failures=failures,
    )
    sensitivity, scenario_details = build_sensitivity(references, audit)
    impact = build_ranking_impact(references, audit)
    queue = build_review_queue(audit)

    verification = {
        "baseline": baseline_verification,
        "reviewed": reviewed_verification,
        "raw_dataset_untouched": raw_dataset_state(),
        "phase21_disputed_report_sha256_before": report_hash_before,
        "phase21_disputed_report_sha256_after": "",
        "phase21_disputed_report_preserved": "",
        "snapshot_records_verified": int(len(views)),
        "snapshot_record_failures": int(len(failures)),
    }

    outputs: Dict[str, Path] = {
        "audit": Path(audit_path),
        "impact": Path(impact_path),
        "review_queue": Path(review_queue_path),
        "sensitivity": Path(sensitivity_path),
    }
    if write:
        for frame, path in (
            (audit, outputs["audit"]),
            (impact, outputs["impact"]),
            (queue, outputs["review_queue"]),
            (sensitivity, outputs["sensitivity"]),
        ):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            frame.to_csv(path, index=False, na_rep="")

    report_hash_after = (
        sha256_file(phase21_disputed_report) if Path(phase21_disputed_report).is_file() else ""
    )
    verification["phase21_disputed_report_sha256_after"] = report_hash_after
    verification["phase21_disputed_report_preserved"] = bool(report_hash_before == report_hash_after)

    summary = build_summary(
        dataset=dataset,
        audit=audit,
        sensitivity=sensitivity,
        scenario_details=scenario_details,
        manifest=manifest,
        views=views,
        failures=failures,
        kev=kev,
        epss=epss,
        placeholder_values=placeholder_values,
        placeholder_note=placeholder_note,
        verification=verification,
        generated_utc=generated,
    )
    artifact_table = _artifact_table(list(outputs.values())) if write else {}
    source_manifest = build_source_manifest(
        dataset_path=Path(clean_path),
        manifest=manifest,
        kev=kev,
        epss=epss,
        failures=failures,
        phase21_report_path=Path(phase21_disputed_report),
        generated_utc=generated,
        artifacts=artifact_table,
        placeholder_note=placeholder_note,
    )
    if write:
        Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
        Path(summary_path).write_text(
            json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
        Path(manifest_path).write_text(
            json.dumps(source_manifest, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
    return {
        "audit": audit,
        "impact": impact,
        "review_queue": queue,
        "sensitivity": sensitivity,
        "summary": summary,
        "source_manifest": source_manifest,
        "details": scenario_details,
    }


def raw_dataset_state() -> Dict[str, Any]:
    """Checksums of the immutable inputs, so the audit can prove it did not touch them."""
    state: Dict[str, Any] = {}
    for label, path in (
        ("raw_csv", DEFAULT_RAW_PATH),
        ("archive", DEFAULT_ARCHIVE_PATH),
    ):
        path = Path(path)
        state[label] = {
            "path": _relative(path),
            "present": path.is_file(),
            "sha256": sha256_file(path) if path.is_file() else "",
        }
    return state


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit every '** DISPUTED **' record against commit-pinned official CVE records and report "
            "the ranking sensitivity of hypothetical treatments. The ranking policy is not changed."
        )
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_CLEAN_PATH)
    parser.add_argument("--baseline-ranked", type=Path, default=DEFAULT_BASELINE_RANKED_PATH)
    parser.add_argument("--reviewed-ranked", type=Path, default=DEFAULT_REVIEWED_RANKED_PATH)
    parser.add_argument("--disputed-root", type=Path, default=DEFAULT_DISPUTED_ROOT)
    parser.add_argument("--disputed-manifest", type=Path, default=None)
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--allow-missing-sources", action="store_true",
                        help="Record KEV/EPSS as explicitly unavailable instead of failing.")
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_PATH)
    parser.add_argument("--impact-output", type=Path, default=DEFAULT_IMPACT_PATH)
    parser.add_argument("--review-queue-output", type=Path, default=DEFAULT_REVIEW_QUEUE_PATH)
    parser.add_argument("--sensitivity-output", type=Path, default=DEFAULT_SENSITIVITY_PATH)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY_PATH)
    parser.add_argument("--manifest-output", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--phase21-disputed-report", type=Path, default=DEFAULT_PHASE21_DISPUTED_REPORT_PATH)
    parser.add_argument("--phase21-audit", type=Path, default=DEFAULT_PHASE21_AUDIT_PATH)
    parser.add_argument("--generated-utc", default=None,
                        help="Override the report timestamp (for reproducible re-runs).")
    parser.add_argument("--no-write", action="store_true", help="Compute everything without writing files.")
    args = parser.parse_args(argv)

    outputs = {
        "audit_output", "impact_output", "review_queue_output", "sensitivity_output",
        "summary_output", "manifest_output", "phase21_disputed_report",
    }
    for name in outputs:
        path = Path(getattr(args, name))
        if Path(args.phase21_disputed_report).resolve() == path.resolve() and name != "phase21_disputed_report":
            print("ERROR: refusing to overwrite the Phase 2.1 disputed report; choose another output path.")
            return 2

    try:
        result = run_audit(
            clean_path=args.input,
            baseline_ranked_path=args.baseline_ranked,
            reviewed_ranked_path=args.reviewed_ranked,
            disputed_root=args.disputed_root,
            disputed_manifest=args.disputed_manifest,
            snapshot_root=args.snapshot_root,
            allow_missing_sources=args.allow_missing_sources,
            audit_path=args.audit_output,
            impact_path=args.impact_output,
            review_queue_path=args.review_queue_output,
            sensitivity_path=args.sensitivity_output,
            summary_path=args.summary_output,
            manifest_path=args.manifest_output,
            phase21_disputed_report=args.phase21_disputed_report,
            phase21_audit_path=args.phase21_audit,
            generated_utc=args.generated_utc,
            write=not args.no_write,
        )
    except (
        MissingSnapshotError,
        CveStatusValidationError,
        CveStatusSchemaError,
        FileNotFoundError,
        ValueError,
    ) as error:
        print(f"ERROR: {error}")
        return 1

    summary = result["summary"]
    counts = summary["records"]
    print(
        f"Disputed-record audit: {counts['audited']} record(s); resolved={counts['resolved']} "
        f"unresolved={counts['unresolved']} not_verifiable={counts['not_verifiable']}; "
        f"exclusion supported for {counts['exclusion_evidence_supported']} record(s)"
    )
    print(
        f"Official records: retrieved={counts['official_records_retrieved']} "
        f"not_retrieved={counts['official_records_not_retrieved']}; "
        f"human review flagged={counts['human_review_required']}"
    )
    print(
        "Current policy unchanged: all 455 disputed records remain eligible with their snapshot CVSS scores."
    )
    if not args.no_write:
        print(f"Evidence audit: {args.audit_output}")
        print(f"Ranking impact: {args.impact_output}")
        print(f"Review queue: {args.review_queue_output}")
        print(f"Sensitivity: {args.sensitivity_output}")
        print(f"Summary: {args.summary_output}")
        print(f"Source manifest: {args.manifest_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
