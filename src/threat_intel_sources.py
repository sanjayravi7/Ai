"""Pure parsers and schema validators for external threat-intelligence snapshots.

This module performs no network access and never writes files. It converts the
raw bytes of two official sources into validated pandas frames:

* CISA Known Exploited Vulnerabilities (KEV) catalog, JSON.
* FIRST Exploit Prediction Scoring System (EPSS) daily bulk CSV, gzip-compressed,
  with a ``#model_version:...,score_date:...`` comment header.

Malformed input raises ``SourceSchemaError`` or ``SourceValidationError`` with
a message that names the failing field and shows a few examples. Nothing is
silently coerced beyond the documented empty-cell-means-missing rule.
"""

import gzip
import io
import json
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
KEV_SOURCE = "kev"
EPSS_SOURCE = "epss"

KEV_TOP_LEVEL_FIELDS = ("catalogVersion", "dateReleased", "count", "vulnerabilities")
KEV_ENTRY_FIELDS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
)
KEV_OPTIONAL_ENTRY_FIELDS = ("cwes",)
KEV_EXPECTED_RANSOMWARE_VALUES = ("Known", "Unknown")
EPSS_COLUMNS = ("cve", "epss", "percentile")

KEV_OUTPUT_COLUMNS = (
    "cve_id",
    "kev_date_added",
    "kev_vendor_project",
    "kev_product",
    "kev_vulnerability_name",
    "kev_short_description",
    "kev_required_action",
    "kev_due_date",
    "kev_known_ransomware_campaign_use",
    "kev_cwes",
)
EPSS_OUTPUT_COLUMNS = ("cve_id", "epss_score", "epss_percentile")


class SourceSchemaError(ValueError):
    """The source's structure differs from what this pipeline was built for."""


class SourceValidationError(ValueError):
    """The source has the expected shape but contains invalid values."""


@dataclass
class ParsedSnapshot:
    source: str
    frame: pd.DataFrame
    metadata: Dict[str, Any]
    findings: Dict[str, Any] = field(default_factory=dict)


def normalize_cve_id(value: Any) -> Optional[str]:
    """Return an upper-case, trimmed CVE identifier, or None if malformed."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip().upper()
    if not CVE_ID_PATTERN.match(text):
        return None
    return text


def _examples(values: List[Any], limit: int = 10) -> List[str]:
    return [str(value) for value in values[:limit]]


def _parse_iso_date(value: Any) -> Optional[date]:
    """Parse a plain YYYY-MM-DD date. Returns None for blank or malformed text."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = pd.to_datetime(text, format="%Y-%m-%d", errors="raise")
    except (ValueError, TypeError):
        return None
    return parsed.date()


def _parse_utc_timestamp(value: str) -> Optional[pd.Timestamp]:
    try:
        stamp = pd.to_datetime(value.strip(), utc=True, errors="raise")
    except (ValueError, TypeError):
        return None
    if pd.isna(stamp):
        return None
    return stamp


def _maybe_gunzip(payload: bytes) -> Tuple[bytes, bool]:
    """Transparently decompress gzip content, reporting whether it was wrapped."""
    if payload[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(payload), True
        except (OSError, EOFError) as error:
            raise SourceSchemaError(f"Gzip payload could not be decompressed: {error}") from error
    return payload, False


# --------------------------------------------------------------------------- KEV


def parse_kev_json(payload: bytes) -> ParsedSnapshot:
    """Validate and normalize the CISA KEV JSON catalog.

    Fails when top-level or per-entry fields are missing, the declared ``count``
    disagrees with the record list, CVE identifiers are malformed or duplicated,
    or dates are unparseable. Unexpected ransomware-use values are retained and
    reported rather than rejected.
    """
    body, gzip_wrapped = _maybe_gunzip(payload)
    try:
        document = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceSchemaError(f"KEV payload is not valid UTF-8 JSON: {error}") from error

    if not isinstance(document, dict):
        raise SourceSchemaError("KEV top-level value must be a JSON object.")
    missing_top = [key for key in KEV_TOP_LEVEL_FIELDS if key not in document]
    if missing_top:
        raise SourceSchemaError(f"KEV catalog is missing top-level field(s): {missing_top}")

    entries = document["vulnerabilities"]
    if not isinstance(entries, list):
        raise SourceSchemaError("KEV 'vulnerabilities' must be a JSON array.")
    declared = document["count"]
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise SourceSchemaError(f"KEV 'count' must be an integer; found {declared!r}.")
    if declared != len(entries):
        raise SourceValidationError(
            f"KEV declared count={declared} but the catalog contains {len(entries)} entries."
        )

    release = _parse_utc_timestamp(str(document["dateReleased"]))
    if release is None:
        raise SourceValidationError(
            f"KEV dateReleased is not a parseable timestamp: {document['dateReleased']!r}"
        )

    rows = []
    bad_ids: List[Any] = []
    bad_dates: List[str] = []
    missing_field_rows: List[str] = []
    missing_value_counts = {column: 0 for column in _KEV_SOURCE_NAME}
    unexpected_ransomware: Dict[str, int] = {}
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SourceSchemaError(f"KEV entry at index {position} is not a JSON object.")
        absent = [name for name in KEV_ENTRY_FIELDS if name not in entry]
        if absent:
            missing_field_rows.append(f"index {position}: {absent}")
            continue

        cve_id = normalize_cve_id(entry["cveID"])
        if cve_id is None:
            bad_ids.append(entry["cveID"])
            continue

        date_added = _parse_iso_date(entry["dateAdded"])
        if date_added is None:
            bad_dates.append(f"{cve_id} dateAdded={entry['dateAdded']!r}")
        due_text = "" if entry["dueDate"] is None else str(entry["dueDate"]).strip()
        due_date = _parse_iso_date(due_text) if due_text else None
        if due_text and due_date is None:
            bad_dates.append(f"{cve_id} dueDate={entry['dueDate']!r}")

        cwes = entry.get("cwes")
        cwe_text = ""
        if isinstance(cwes, list):
            cwe_text = ";".join(str(item).strip() for item in cwes if str(item).strip())

        ransomware = "" if entry["knownRansomwareCampaignUse"] is None else str(
            entry["knownRansomwareCampaignUse"]
        ).strip()
        if ransomware not in KEV_EXPECTED_RANSOMWARE_VALUES:
            key = ransomware or "<blank>"
            unexpected_ransomware[key] = unexpected_ransomware.get(key, 0) + 1

        row = {
            "cve_id": cve_id,
            "kev_date_added": date_added.isoformat() if date_added else "",
            "kev_vendor_project": _text(entry["vendorProject"]),
            "kev_product": _text(entry["product"]),
            "kev_vulnerability_name": _text(entry["vulnerabilityName"]),
            "kev_short_description": _text(entry["shortDescription"]),
            "kev_required_action": _text(entry["requiredAction"]),
            "kev_due_date": due_date.isoformat() if due_date else "",
            "kev_known_ransomware_campaign_use": ransomware,
            "kev_cwes": cwe_text,
        }
        for column, source_name in _KEV_SOURCE_NAME.items():
            if not _text(entry[source_name]):
                missing_value_counts[column] += 1
        rows.append(row)

    if missing_field_rows:
        raise SourceSchemaError(
            f"{len(missing_field_rows)} KEV entries lack required fields; "
            f"examples={missing_field_rows[:5]}"
        )
    if bad_ids:
        raise SourceValidationError(
            f"{len(bad_ids)} KEV entries have malformed cveID values; examples={_examples(bad_ids)}"
        )
    if bad_dates:
        raise SourceValidationError(
            f"{len(bad_dates)} KEV entries have unparseable dates; examples={_examples(bad_dates)}"
        )

    frame = pd.DataFrame(rows, columns=list(KEV_OUTPUT_COLUMNS))
    duplicated = frame["cve_id"].duplicated(keep=False)
    if bool(duplicated.any()):
        examples = sorted(frame.loc[duplicated, "cve_id"].unique().tolist())
        raise SourceValidationError(
            f"KEV contains {int(duplicated.sum())} rows sharing {len(examples)} CVE IDs; "
            f"examples={_examples(examples)}"
        )

    snapshot_date = release.tz_convert("UTC").date().isoformat()
    metadata = {
        "catalog_title": str(document.get("title", "")),
        "catalog_version": str(document["catalogVersion"]),
        "date_released_utc": release.isoformat(),
        "snapshot_date": snapshot_date,
        "declared_count": declared,
        "record_count": int(len(frame)),
        "gzip_wrapped": gzip_wrapped,
        "expected_fields": list(KEV_ENTRY_FIELDS),
    }
    findings = {
        "unique_cve_ids": int(frame["cve_id"].nunique()),
        "duplicate_cve_id_rows": 0,
        "malformed_cve_id_count": 0,
        "missing_value_counts": missing_value_counts,
        "unexpected_ransomware_values": unexpected_ransomware,
    }
    return ParsedSnapshot(KEV_SOURCE, frame, metadata, findings)


_KEV_SOURCE_NAME = {
    "kev_date_added": "dateAdded",
    "kev_vendor_project": "vendorProject",
    "kev_product": "product",
    "kev_vulnerability_name": "vulnerabilityName",
    "kev_short_description": "shortDescription",
    "kev_required_action": "requiredAction",
    "kev_due_date": "dueDate",
    "kev_known_ransomware_campaign_use": "knownRansomwareCampaignUse",
}


def _text(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


# -------------------------------------------------------------------------- EPSS


def _split_metadata_line(line: str) -> Dict[str, str]:
    metadata: Dict[str, str] = {}
    for part in line.lstrip("#").split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def parse_epss_csv(payload: bytes) -> ParsedSnapshot:
    """Validate the FIRST EPSS bulk CSV (gzip-compressed or plain text).

    Expects leading ``#`` comment lines carrying ``model_version`` and
    ``score_date``, then the exact header ``cve,epss,percentile``. Scores and
    percentiles must lie in [0, 1]. Empty numeric cells are retained as missing
    and counted; malformed numbers, malformed CVE IDs, and duplicate CVE IDs are
    rejected.
    """
    body, gzip_wrapped = _maybe_gunzip(payload)
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise SourceSchemaError(f"EPSS payload is not UTF-8 text: {error}") from error

    lines = text.splitlines()
    comment_metadata: Dict[str, str] = {}
    index = 0
    while index < len(lines) and lines[index].startswith("#"):
        comment_metadata.update(_split_metadata_line(lines[index]))
        index += 1
    for required in ("model_version", "score_date"):
        if required not in comment_metadata:
            raise SourceSchemaError(
                f"EPSS comment header lacks '{required}'; found keys={sorted(comment_metadata)}"
            )

    if index >= len(lines):
        raise SourceSchemaError("EPSS payload has no column header or records.")
    header = [column.strip() for column in lines[index].split(",")]
    if tuple(header) != EPSS_COLUMNS:
        raise SourceSchemaError(
            f"EPSS header must be {list(EPSS_COLUMNS)}; found {header}."
        )

    score_stamp = _parse_utc_timestamp(comment_metadata["score_date"])
    if score_stamp is None:
        raise SourceValidationError(
            f"EPSS score_date is not parseable: {comment_metadata['score_date']!r}"
        )

    body_text = "\n".join(line for line in lines[index + 1 :] if line.strip() and not line.startswith("#"))
    if not body_text:
        raise SourceValidationError("EPSS payload contains a header but no score records.")
    raw = pd.read_csv(
        io.StringIO("\n".join(lines[index:]) + "\n"),
        dtype=str,
        keep_default_na=False,
        comment="#",
        skip_blank_lines=True,
    )
    raw.columns = [str(column).strip() for column in raw.columns]
    if tuple(raw.columns) != EPSS_COLUMNS:
        raise SourceSchemaError(f"EPSS columns changed; found {list(raw.columns)}.")

    cve_clean = raw["cve"].str.strip().str.upper()
    valid_id = cve_clean.str.match(CVE_ID_PATTERN.pattern)
    if not bool(valid_id.all()):
        examples = raw.loc[~valid_id, "cve"].head(10).tolist()
        raise SourceValidationError(
            f"{int((~valid_id).sum())} EPSS rows have malformed CVE IDs; examples={examples}"
        )

    numeric: Dict[str, pd.Series] = {}
    missing_counts: Dict[str, int] = {}
    for column in ("epss", "percentile"):
        text_values = raw[column].str.strip()
        blank = text_values.eq("")
        parsed = pd.to_numeric(text_values.where(~blank), errors="coerce")
        non_numeric = (~blank) & parsed.isna()
        if bool(non_numeric.any()):
            raise SourceValidationError(
                f"EPSS {column} has {int(non_numeric.sum())} non-numeric value(s); "
                f"examples={raw.loc[non_numeric, column].head(10).tolist()}"
            )
        out_of_range = parsed.notna() & ((parsed < 0) | (parsed > 1))
        if bool(out_of_range.any()):
            raise SourceValidationError(
                f"EPSS {column} has {int(out_of_range.sum())} value(s) outside [0, 1]; "
                f"examples={raw.loc[out_of_range, column].head(10).tolist()}"
            )
        numeric[column] = parsed.astype("float64")
        missing_counts[column] = int(blank.sum())

    frame = pd.DataFrame(
        {
            "cve_id": cve_clean.values,
            "epss_score": numeric["epss"].values,
            "epss_percentile": numeric["percentile"].values,
        },
        columns=list(EPSS_OUTPUT_COLUMNS),
    )
    duplicated = frame["cve_id"].duplicated(keep=False)
    if bool(duplicated.any()):
        examples = sorted(frame.loc[duplicated, "cve_id"].unique().tolist())
        raise SourceValidationError(
            f"EPSS contains {int(duplicated.sum())} rows sharing {len(examples)} CVE IDs; "
            f"examples={_examples(examples)}"
        )

    metadata = {
        "model_version": comment_metadata["model_version"],
        "score_date_utc": score_stamp.isoformat(),
        "snapshot_date": score_stamp.tz_convert("UTC").date().isoformat(),
        "record_count": int(len(frame)),
        "gzip_wrapped": gzip_wrapped,
        "header": list(EPSS_COLUMNS),
    }
    findings = {
        "unique_cve_ids": int(frame["cve_id"].nunique()),
        "duplicate_cve_id_rows": 0,
        "malformed_cve_id_count": 0,
        "missing_value_counts": missing_counts,
        "score_min": _round(frame["epss_score"].min()),
        "score_max": _round(frame["epss_score"].max()),
        "percentile_min": _round(frame["epss_percentile"].min()),
        "percentile_max": _round(frame["epss_percentile"].max()),
    }
    return ParsedSnapshot(EPSS_SOURCE, frame, metadata, findings)


def _round(value: Any) -> Optional[float]:
    if value is None or pd.isna(value):
        return None
    return float("{:.12g}".format(float(value)))


PARSERS = {KEV_SOURCE: parse_kev_json, EPSS_SOURCE: parse_epss_csv}
