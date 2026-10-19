"""Frozen vocabulary for VULNOVA 1.7 evidence acquisition.

Three statuses are the whole vocabulary.  Nothing here can be softened into a
pass: a missing artifact is ``UNAVAILABLE``, and an unmet precondition is
``BLOCKED``.  Only ``VERIFIED`` means "directly supported by inspected
evidence".

Two separate axes are recorded for every artifact:

``content_status``
    Whether the bytes are authentic: a resolved authoritative revision, a
    matching size and SHA-256, and a parseable payload.

``access_provenance``
    Whether *we* obtained the artifact at the time it describes.  Downloading an
    old revision today does not make the historical access contemporaneous, so a
    late retrieval can never be reported as verified historical provenance.

The temporal rules are imported from :mod:`vulnova.evaluation.constants` rather
than redefined, so acquisition cannot drift away from the readiness gate.
"""

from __future__ import annotations

import datetime as dt
from typing import Iterable

from ..evaluation.constants import (
    EARLIEST_THREE_BLOCK_CUTOFFS,
    HORIZON_DAYS,
    MATURITY_LAG_DAYS,
    MATURITY_SPAN_DAYS,
    REQUIRED_DISTINCT_TEST_EVENTS,
    REQUIRED_SEQUENTIAL_BLOCKS,
)
from ..evaluation.temporal import label_maturity_date, parse_date

SCHEMA_VERSION = "vulnova.acquisition/1.7"
PHASE_TITLE = "Historical Data Acquisition and Provenance"

# ---------------------------------------------------------------- statuses
VERIFIED = "VERIFIED"
UNAVAILABLE = "UNAVAILABLE"
BLOCKED = "BLOCKED"
STATUSES = (VERIFIED, UNAVAILABLE, BLOCKED)
_STATUS_RANK = {VERIFIED: 0, UNAVAILABLE: 1, BLOCKED: 2}

# ------------------------------------------------------- access provenance
CONTEMPORANEOUS = "CONTEMPORANEOUS"
LATE_RETRIEVAL = "LATE_RETRIEVAL"
NOT_RETRIEVED = "NOT_RETRIEVED"
ACCESS_PROVENANCE_VALUES = (CONTEMPORANEOUS, LATE_RETRIEVAL, NOT_RETRIEVED)

# ----------------------------------------------------------------- channels
CHANNEL_OFFICIAL = "OFFICIAL"
CHANNEL_OFFICIAL_GITHUB = "OFFICIAL_GITHUB"
CHANNEL_THIRD_PARTY_MIRROR = "THIRD_PARTY_MIRROR"
CHANNEL_LOCAL_SNAPSHOT = "LOCAL_SNAPSHOT"

#: Channels that may satisfy a requirement.  A third-party mirror never can.
TRUSTED_CHANNELS = (CHANNEL_OFFICIAL, CHANNEL_OFFICIAL_GITHUB, CHANNEL_LOCAL_SNAPSHOT)

# ------------------------------------------------------------- reason codes
OK_VERIFIED = "OK_VERIFIED"
OFFICIAL_SOURCE_UNREACHABLE = "OFFICIAL_SOURCE_UNREACHABLE"
HTTP_ERROR = "HTTP_ERROR"
MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
RATE_LIMITED = "RATE_LIMITED"
REVISION_NOT_FOUND = "REVISION_NOT_FOUND"
REVISION_AFTER_CUTOFF = "REVISION_AFTER_CUTOFF"
SOURCE_TIMESTAMP_MISSING = "SOURCE_TIMESTAMP_MISSING"
RETRIEVAL_TIMESTAMP_MISSING = "RETRIEVAL_TIMESTAMP_MISSING"
RETRIEVAL_BEFORE_SOURCE_TIME = "RETRIEVAL_BEFORE_SOURCE_TIME"
RETRIEVAL_NOT_CONTEMPORANEOUS = "RETRIEVAL_NOT_CONTEMPORANEOUS"
SHA256_MISMATCH = "SHA256_MISMATCH"
SIZE_MISMATCH = "SIZE_MISMATCH"
ARTIFACT_NOT_STORED = "ARTIFACT_NOT_STORED"
ARTIFACT_MISSING = "ARTIFACT_MISSING"
ARTIFACT_UNREADABLE = "ARTIFACT_UNREADABLE"
EPSS_FILE_MISSING = "EPSS_FILE_MISSING"
SCORE_DATE_MISMATCH = "SCORE_DATE_MISMATCH"
THIRD_PARTY_MIRROR_ONLY = "THIRD_PARTY_MIRROR_ONLY"
PIN_CONFLICT = "PIN_CONFLICT"
PIN_CROSSCHECK_SKIPPED = "PIN_CROSSCHECK_SKIPPED"
LABELS_NOT_MATURE = "LABELS_NOT_MATURE"
CATALOG_PREDATES_MATURITY = "CATALOG_PREDATES_MATURITY"
CUTOFF_OUTSIDE_GRID = "CUTOFF_OUTSIDE_GRID"
TRUNCATED_CATALOG = "TRUNCATED_CATALOG"
NO_RECORDS = "NO_RECORDS"
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"

REASON_DESCRIPTIONS = {
    OK_VERIFIED: "Evidence was inspected and supports the claim.",
    OFFICIAL_SOURCE_UNREACHABLE: (
        "The official source could not be reached from the acquisition "
        "environment."
    ),
    HTTP_ERROR: "The source answered with a non-success status.",
    MALFORMED_RESPONSE: "The response could not be parsed as the expected format.",
    RATE_LIMITED: "The source refused the request because of rate limiting.",
    REVISION_NOT_FOUND: "No revision exists at or before the cutoff.",
    REVISION_AFTER_CUTOFF: "The resolved revision is newer than the cutoff.",
    SOURCE_TIMESTAMP_MISSING: "The artifact carries no source timestamp.",
    RETRIEVAL_TIMESTAMP_MISSING: (
        "No actual retrieval timestamp was recorded, so retrieval provenance is "
        "unknown."
    ),
    RETRIEVAL_BEFORE_SOURCE_TIME: (
        "The retrieval timestamp precedes the source timestamp, which is "
        "impossible and marks the record as corrupt."
    ),
    RETRIEVAL_NOT_CONTEMPORANEOUS: (
        "The artifact was retrieved after the cutoff. The content may be "
        "authentic, but historical access was not observed at the time."
    ),
    SHA256_MISMATCH: "A stored artifact does not hash to its recorded digest.",
    SIZE_MISMATCH: "A stored artifact does not have its recorded size.",
    ARTIFACT_NOT_STORED: "Only a digest was recorded; the bytes are not kept here.",
    ARTIFACT_MISSING: "A recorded artifact is absent from the store.",
    ARTIFACT_UNREADABLE: "A stored artifact could not be read or parsed.",
    EPSS_FILE_MISSING: "No daily EPSS file exists for the requested date.",
    SCORE_DATE_MISMATCH: (
        "The file's own score date differs from the requested date; substituting "
        "it would silently backfill history."
    ),
    THIRD_PARTY_MIRROR_ONLY: (
        "Only a third-party mirror is reachable; mirrors cannot satisfy an "
        "official-source requirement."
    ),
    PIN_CONFLICT: "The live source disagrees with the revision recorded earlier.",
    PIN_CROSSCHECK_SKIPPED: "No reference dataset was supplied for a pin cross-check.",
    LABELS_NOT_MATURE: "The block's labels have not matured at the as-of date.",
    CATALOG_PREDATES_MATURITY: (
        "The catalog was released before the maturity date, so it cannot observe "
        "labels that matured later."
    ),
    CUTOFF_OUTSIDE_GRID: "The cutoff is not part of the Phase 2.3K cutoff grid.",
    TRUNCATED_CATALOG: "The catalog declares more entries than it contains.",
    NO_RECORDS: "No records were produced for this requirement.",
    INTEGRITY_FAILURE: (
        "Stored bytes no longer match the recorded digest, or the manifest is "
        "internally inconsistent."
    ),
}


def worst(statuses: Iterable[str]) -> str:
    """Return the least favourable status in ``statuses``."""
    values = list(statuses)
    if not values:
        return BLOCKED
    return max(values, key=lambda value: _STATUS_RANK.get(value, 2))


# --------------------------------------------------------------- cutoff grid
#: The candidate evaluation blocks.  Imported from the evaluation package so the
#: acquisition tool cannot quietly disagree with the readiness gate.
CANDIDATE_CUTOFFS = tuple(EARLIEST_THREE_BLOCK_CUTOFFS)
FINAL_CANDIDATE_CUTOFF = max(CANDIDATE_CUTOFFS)


def final_candidate_maturity() -> dt.date:
    return label_maturity_date(FINAL_CANDIDATE_CUTOFF)


def cutoff_maturity(cutoff: dt.date) -> dt.date:
    return label_maturity_date(cutoff)


def parse_cutoffs(values: Iterable[str]) -> tuple[dt.date, ...]:
    return tuple(parse_date(value) for value in values)


__all__ = [
    "ACCESS_PROVENANCE_VALUES",
    "BLOCKED",
    "CANDIDATE_CUTOFFS",
    "CHANNEL_LOCAL_SNAPSHOT",
    "CHANNEL_OFFICIAL",
    "CHANNEL_OFFICIAL_GITHUB",
    "CHANNEL_THIRD_PARTY_MIRROR",
    "CONTEMPORANEOUS",
    "EARLIEST_THREE_BLOCK_CUTOFFS",
    "FINAL_CANDIDATE_CUTOFF",
    "HORIZON_DAYS",
    "INTEGRITY_FAILURE",
    "LATE_RETRIEVAL",
    "MATURITY_LAG_DAYS",
    "MATURITY_SPAN_DAYS",
    "NOT_RETRIEVED",
    "PHASE_TITLE",
    "REASON_DESCRIPTIONS",
    "REQUIRED_DISTINCT_TEST_EVENTS",
    "REQUIRED_SEQUENTIAL_BLOCKS",
    "SCHEMA_VERSION",
    "STATUSES",
    "TRUSTED_CHANNELS",
    "UNAVAILABLE",
    "VERIFIED",
    "cutoff_maturity",
    "final_candidate_maturity",
    "parse_cutoffs",
    "worst",
]
