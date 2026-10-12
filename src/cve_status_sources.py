"""Pure parsers for authoritative CVE status records (CVE Program / cvelistV5).

This module performs no network access and never writes files. It provides:

* the dataset-side marker rules used to find withdrawn candidate entries
  (``** REJECT **``) and disputed records (``** DISPUTED **``);
* a strict parser for CVE Services 5.x CVE JSON records as published in the
  official ``CVEProject/cvelistV5`` repository; and
* a deterministic mapping from an authoritative record's ``state`` to the
  dataset-level status vocabulary used by the ranking policy.

Status vocabulary (used by ``src.audit_rejected_cves``):

``REJECTED``
    The dataset record carries the ``** REJECT **`` marker *and* the official
    record state is ``REJECTED``.
``REINSTATED``
    The dataset record carries the marker but the official record state is
    ``PUBLISHED``, so the identifier is active again.
``UNVERIFIED``
    The dataset record carries the marker but no authoritative record could be
    read (missing, unreachable, malformed, or a non-final state such as
    ``RESERVED``). Never guess a status.
``UNMARKED``
    The dataset record does not carry the marker. No status verification was
    attempted for it, and none is implied.

Malformed input raises ``CveStatusSchemaError`` or ``CveStatusValidationError``
with a message naming the failing field; nothing is silently coerced.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import pandas as pd

from .threat_intel_sources import CVE_ID_PATTERN, normalize_cve_id


CVE_STATUS_SOURCE = "cve_status"
CVELISTV5_REPOSITORY = "CVEProject/cvelistV5"
DEFAULT_API_BASE = "https://api.github.com"
DEFAULT_BLOB_BASE = "https://github.com"
SNAPSHOT_SCHEMA = "vulnova-cve-status-snapshot-1"

REJECT_MARKER = "** REJECT **"
DISPUTED_MARKER = "** DISPUTED **"

STATUS_REJECTED = "REJECTED"
STATUS_REINSTATED = "REINSTATED"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_UNMARKED = "UNMARKED"
STATUSES = (STATUS_REJECTED, STATUS_REINSTATED, STATUS_UNVERIFIED, STATUS_UNMARKED)

AUTHORITATIVE_REJECTED_STATE = "REJECTED"
AUTHORITATIVE_PUBLISHED_STATE = "PUBLISHED"

_DATE_FIELDS = ("datePublished", "dateUpdated", "dateReserved", "dateRejected")
_CONSULT_IDS_PATTERN = re.compile(r"ConsultI[Dd]s?\s*:\s*([^.\n]*)", re.IGNORECASE)
_REASON_PATTERN = re.compile(r"Reason\s*:\s*([^\n]*)", re.IGNORECASE)
_CVE_TOKEN_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# CVE JSON metrics keys, in the order a single "best" score is selected for
# disclosure only. Versions are never mixed inside the ranking.
_METRIC_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


class CveStatusSchemaError(ValueError):
    """An authoritative CVE record has an unexpected structure."""


class CveStatusValidationError(ValueError):
    """An authoritative CVE record has the expected shape but invalid values."""


@dataclass
class CveRecord:
    """Normalized view of one CVE Services 5.x record."""

    cve_id: str
    state: str
    date_published: str = ""
    date_updated: str = ""
    date_reserved: str = ""
    date_rejected: str = ""
    assigner_short_name: str = ""
    data_version: str = ""
    rejected_reason: str = ""
    consult_ids: Tuple[str, ...] = ()
    cvss_version: str = ""
    cvss_base_score: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "state": self.state,
            "date_published": self.date_published,
            "date_updated": self.date_updated,
            "date_reserved": self.date_reserved,
            "date_rejected": self.date_rejected,
            "assigner_short_name": self.assigner_short_name,
            "data_version": self.data_version,
            "rejected_reason": self.rejected_reason,
            "consult_ids": list(self.consult_ids),
            "cvss_version": self.cvss_version,
            "cvss_base_score": self.cvss_base_score,
        }


def _text(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def marker_summary(summary: Any) -> Dict[str, Any]:
    """Describe the marker content of one summary string.

    The result distinguishes an exact leading ``** REJECT **`` marker from
    near-misses (leading whitespace, case variant, marker only inside the
    text). Only the exact and leading-whitespace forms are treated as
    placeholders; the others are disclosed so a looser rule cannot change the
    ranking silently.
    """
    text = "" if summary is None or (isinstance(summary, float) and pd.isna(summary)) else str(summary)
    stripped = text.lstrip()
    return {
        "reject_exact_prefix": text.startswith(REJECT_MARKER),
        "reject_prefix_after_leading_whitespace": (
            not text.startswith(REJECT_MARKER) and stripped.startswith(REJECT_MARKER)
        ),
        "reject_case_variant_prefix": (
            not stripped.startswith(REJECT_MARKER)
            and stripped.upper().startswith(REJECT_MARKER)
        ),
        "reject_marker_not_at_start": (
            not stripped.startswith(REJECT_MARKER)
            and REJECT_MARKER in text
        ),
        "disputed_marker_present": DISPUTED_MARKER in text,
        "disputed_marker_at_start": stripped.startswith(DISPUTED_MARKER),
    }


def is_reject_placeholder(summary: Any) -> bool:
    """True when a summary begins with the ``** REJECT **`` marker.

    Leading whitespace is tolerated and reported separately by
    :func:`marker_summary` because the bundled snapshot contains none.
    """
    text = "" if summary is None else str(summary)
    return text.lstrip().startswith(REJECT_MARKER)


def has_disputed_marker(summary: Any) -> bool:
    """True when a ``** DISPUTED **`` marker appears anywhere in the summary."""
    text = "" if summary is None else str(summary)
    return DISPUTED_MARKER in text


def marker_audit(summaries: Iterable[Any]) -> Dict[str, Any]:
    """Count marker forms across a summary column without changing any rule."""
    counts = {
        "reject_exact_prefix": 0,
        "reject_prefix_after_leading_whitespace": 0,
        "reject_case_variant_prefix": 0,
        "reject_marker_not_at_start": 0,
        "disputed_marker_present": 0,
        "disputed_marker_at_start": 0,
        "rows": 0,
    }
    for summary in summaries:
        findings = marker_summary(summary)
        counts["rows"] += 1
        for key, value in findings.items():
            if value:
                counts[key] += 1
    counts["reject_placeholder_rows"] = (
        counts["reject_exact_prefix"] + counts["reject_prefix_after_leading_whitespace"]
    )
    return counts


def cvelistv5_record_path(cve_id: str) -> str:
    """Return the cvelistV5 repository path for a CVE identifier.

    The official layout buckets identifiers by year and thousand
    (``cves/2007/3xxx/CVE-2007-3004.json``).
    """
    normalized = normalize_cve_id(cve_id)
    if normalized is None:
        raise CveStatusValidationError(f"Not a well-formed CVE identifier: {cve_id!r}")
    _, year, number = normalized.split("-")
    return f"cves/{year}/{int(number) // 1000}xxx/{normalized}.json"


def cvelistv5_api_url(
    cve_id: str,
    *,
    repository: str = CVELISTV5_REPOSITORY,
    ref: Optional[str] = None,
    api_base: str = DEFAULT_API_BASE,
) -> str:
    """Return the GitHub contents-API URL used to fetch one raw CVE record."""
    url = f"{api_base.rstrip('/')}/repos/{repository}/contents/{cvelistv5_record_path(cve_id)}"
    if ref:
        url += f"?ref={quote(str(ref), safe='')}"
    return url


def cvelistv5_blob_url(
    cve_id: str,
    *,
    repository: str = CVELISTV5_REPOSITORY,
    ref: str,
    blob_base: str = DEFAULT_BLOB_BASE,
) -> str:
    """Return the human-readable, commit-pinned URL for one CVE record."""
    return (
        f"{blob_base.rstrip('/')}/{repository}/blob/{quote(str(ref), safe='')}/"
        f"{cvelistv5_record_path(cve_id)}"
    )


def parse_consult_ids(reason_text: str) -> Tuple[str, ...]:
    """Extract the consulted (replacement) CVE IDs from a rejection reason."""
    if not reason_text:
        return ()
    found: List[str] = []
    for match in _CONSULT_IDS_PATTERN.finditer(str(reason_text)):
        for token in _CVE_TOKEN_PATTERN.findall(match.group(1)):
            normalized = normalize_cve_id(token)
            if normalized and normalized not in found:
                found.append(normalized)
    return tuple(found)


def parse_rejection_reason(reason_text: str) -> str:
    """Extract the ``Reason:`` sentence from a rejection notice, if present."""
    if not reason_text:
        return ""
    match = _REASON_PATTERN.search(str(reason_text))
    if not match:
        return ""
    value = match.group(1).strip()
    # The official notices continue with "Notes:"; keep only the reason itself.
    return re.split(r"\s*Notes\s*:", value, maxsplit=1)[0].strip()


def _parse_timestamp(value: Any, field_name: str, cve_id: str) -> str:
    text = _text(value)
    if not text:
        return ""
    parsed = pd.to_datetime(text, utc=True, errors="coerce")
    if parsed is None or pd.isna(parsed):
        raise CveStatusValidationError(
            f"{cve_id}: {field_name} is not a parseable timestamp: {value!r}"
        )
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_cvss_metric(containers: Dict[str, Any]) -> Tuple[str, Optional[float]]:
    """Return the first labelled base score found, for disclosure only."""
    sources: List[Dict[str, Any]] = []
    for container_name in ("cna", "adp"):
        container = containers.get(container_name)
        if isinstance(container, list):
            for entry in container:
                if isinstance(entry, dict):
                    sources.append(entry)
        elif isinstance(container, dict):
            sources.append(container)
    for source in sources:
        metrics = source.get("metrics")
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key in _METRIC_KEYS:
                value = metric.get(key)
                if isinstance(value, dict) and value.get("baseScore") is not None:
                    score = pd.to_numeric(value.get("baseScore"), errors="coerce")
                    if score is not None and not pd.isna(score):
                        return key, float(score)
    return "", None


def parse_cve_record(
    payload: Any,
    *,
    expected_cve_id: Optional[str] = None,
) -> CveRecord:
    """Parse and validate one CVE Services 5.x record.

    Args:
        payload: Raw JSON bytes, text, or an already-decoded mapping.
        expected_cve_id: When given, the record's ``cveMetadata.cveId`` must
            match it after normalization.

    Raises:
        CveStatusSchemaError: The document is not a CVE 5.x record object.
        CveStatusValidationError: Fields are present but malformed, or the
            identifier does not match ``expected_cve_id``.
    """
    if isinstance(payload, (bytes, bytearray)):
        try:
            document = json.loads(bytes(payload).decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CveStatusSchemaError(f"CVE record is not valid UTF-8 JSON: {error}") from error
    elif isinstance(payload, str):
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as error:
            raise CveStatusSchemaError(f"CVE record is not valid JSON: {error}") from error
    else:
        document = payload

    if not isinstance(document, dict):
        raise CveStatusSchemaError("CVE record top level must be a JSON object.")
    metadata = document.get("cveMetadata")
    if not isinstance(metadata, dict):
        raise CveStatusSchemaError("CVE record is missing the 'cveMetadata' object.")

    raw_id = metadata.get("cveId")
    cve_id = normalize_cve_id(raw_id)
    if cve_id is None:
        raise CveStatusSchemaError(f"CVE record 'cveMetadata.cveId' is malformed: {raw_id!r}")
    if expected_cve_id is not None and cve_id != normalize_cve_id(expected_cve_id):
        raise CveStatusValidationError(
            f"CVE record identifier mismatch: fetched {cve_id}, expected {expected_cve_id}."
        )

    state = _text(metadata.get("state")).upper()
    if not state:
        raise CveStatusSchemaError(f"{cve_id}: 'cveMetadata.state' is missing or blank.")

    dates = {
        name: _parse_timestamp(metadata.get(name), f"cveMetadata.{name}", cve_id)
        for name in _DATE_FIELDS
    }

    containers = document.get("containers")
    if containers is None:
        containers = {}
    if not isinstance(containers, dict):
        raise CveStatusSchemaError(f"{cve_id}: 'containers' must be a JSON object.")

    reasons: List[str] = []
    cna = containers.get("cna")
    for entry in cna if isinstance(cna, list) else [cna]:
        if not isinstance(entry, dict):
            continue
        for reason in entry.get("rejectedReasons") or []:
            if isinstance(reason, dict):
                value = _text(reason.get("value"))
            else:
                value = _text(reason)
            if value:
                reasons.append(value)
    reason_text = " ".join(reasons)

    cvss_version, cvss_base_score = _first_cvss_metric(containers)

    return CveRecord(
        cve_id=cve_id,
        state=state,
        date_published=dates["datePublished"],
        date_updated=dates["dateUpdated"],
        date_reserved=dates["dateReserved"],
        date_rejected=dates["dateRejected"],
        assigner_short_name=_text(metadata.get("assignerShortName")),
        data_version=_text(document.get("dataVersion")),
        rejected_reason=reason_text,
        consult_ids=parse_consult_ids(reason_text),
        cvss_version=cvss_version,
        cvss_base_score=cvss_base_score,
        extra={"dataType": _text(document.get("dataType"))},
    )


def classify_status(record: Optional[CveRecord], placeholder: bool) -> Tuple[str, str]:
    """Map an authoritative record to the dataset-level status vocabulary.

    Returns:
        ``(status, reason)`` where ``reason`` explains the mapping and is stored
        verbatim in the audit output.
    """
    if not placeholder:
        return STATUS_UNMARKED, "summary_does_not_start_with_reject_marker"
    if record is None:
        return STATUS_UNVERIFIED, "no_authoritative_record_available"
    if record.state == AUTHORITATIVE_REJECTED_STATE:
        return STATUS_REJECTED, "authoritative_state_rejected"
    if record.state == AUTHORITATIVE_PUBLISHED_STATE:
        return STATUS_REINSTATED, "authoritative_state_published"
    return STATUS_UNVERIFIED, f"authoritative_state_not_final:{record.state}"


def verify_supported_identifier(value: Any) -> str:
    """Return a normalized CVE identifier or raise a validation error."""
    normalized = normalize_cve_id(value)
    if normalized is None:
        raise CveStatusValidationError(
            f"Not a well-formed CVE identifier (expected {CVE_ID_PATTERN.pattern}): {value!r}"
        )
    return normalized
