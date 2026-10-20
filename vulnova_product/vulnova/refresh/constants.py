"""Frozen vocabulary for the VULNOVA 1.8 maturity gate and evidence refresh.

The 1.8 vocabulary is deliberately small, and every term answers one question
that a later reader will ask:

``gate status`` (per candidate block)
    Has the block's label maturity date arrived, and can the catalog we hold
    actually observe labels that matured on that date?

``refresh status`` (whole run)
    Given the gate and the refreshed evidence, what may be claimed?

The two are separate on purpose.  A block can be *calendar mature* and still be
unobservable, because a KEV catalog released before the maturity date cannot
contain entries that matured after it.  Collapsing those into one "mature"
boolean is exactly the mistake this release exists to prevent.

Nothing here can approve the protocol, adopt a design or train a model.  The
statuses are evidence statements, not permission.
"""

from __future__ import annotations

import datetime as dt

from ..acquisition import constants as A

SCHEMA_VERSION = "vulnova.refresh/1.8"
PHASE_TITLE = "Maturity Gate and Evidence Refresh"
RELEASE = "1.8"

# --------------------------------------------------------------- gate statuses
#: The maturity date has not arrived at the run's as-of date.
GATE_NOT_MATURED = "NOT_MATURED"
#: The date arrived, but no readable catalog was acquired.
GATE_MATURED_SOURCE_MISSING = "MATURED_SOURCE_MISSING"
#: The date arrived, but the catalog was released before it.
GATE_MATURED_SOURCE_PREDATES = "MATURED_SOURCE_PREDATES"
#: The date arrived and the catalog was released on or after it.
GATE_MATURED_OBSERVED = "MATURED_AND_OBSERVED"

GATE_STATUSES = (
    GATE_NOT_MATURED,
    GATE_MATURED_SOURCE_MISSING,
    GATE_MATURED_SOURCE_PREDATES,
    GATE_MATURED_OBSERVED,
)

#: Gate statuses that permit a dateAdded-filtered view of the catalog.  Only a
#: catalog published on or after the maturity date can observe the whole
#: window; anything else is right-censored.
OBSERVING_GATE_STATUSES = (GATE_MATURED_OBSERVED,)

# ------------------------------------------------------------ refresh statuses
#: The calendar date has not reached the final candidate block's maturity.
REFRESH_BLOCKED_MATURITY = "BLOCKED_MATURITY_NOT_REACHED"
#: The date arrived, but the freshest catalog predates maturity (or is missing).
REFRESH_BLOCKED_SOURCE = "BLOCKED_SOURCE_CANNOT_OBSERVE_MATURITY"
#: Maturity is observable, but refreshed evidence is still incomplete.
REFRESH_BLOCKED_EVIDENCE = "BLOCKED_EVIDENCE_INCOMPLETE"
#: Every refreshed requirement is supported.  This is *not* an approval: the
#: protocol is still NOT_APPROVED and no design is adopted.
REFRESH_EVIDENCE_COMPLETE = "EVIDENCE_COMPLETE_FOR_REASSESSMENT"

REFRESH_STATUSES = (
    REFRESH_BLOCKED_MATURITY,
    REFRESH_BLOCKED_SOURCE,
    REFRESH_BLOCKED_EVIDENCE,
    REFRESH_EVIDENCE_COMPLETE,
)

# ------------------------------------------------------- 1.8-specific reasons
#: Calendar maturity has not been reached.  Distinct from
#: ``CATALOG_PREDATES_MATURITY``, which is about the artifact, not the clock.
MATURITY_NOT_REACHED = "MATURITY_NOT_REACHED"
#: The catalog cannot observe the maturity window, so no subset of its entries
#: may be presented as the matured label set.
RIGHT_CENSORED_NOT_FILTERED = "RIGHT_CENSORED_NOT_FILTERED"
#: The catalog can observe the window and a derived dateAdded view was built.
FILTERED_BY_DATE_ADDED = "FILTERED_BY_DATE_ADDED"
#: At least one entry carries an unusable ``dateAdded``; the view is not trusted.
DATE_ADDED_INVALID = "DATE_ADDED_INVALID"
#: The refresh would have claimed maturity while the run's own as-of date is
#: before the maturity date.  A hard invariant, never a warning.
MATURITY_CLAIMED_EARLY = "MATURITY_CLAIMED_EARLY"
#: The refresh store and the sealed 1.7 archive overlap.
REFRESH_STORE_OVERLAPS_ARCHIVE = "REFRESH_STORE_OVERLAPS_ARCHIVE"
#: The refresh could not be compared because no baseline report was supplied.
BASELINE_MISSING = "BASELINE_MISSING"
#: The refresh produced no readiness evidence to compare against.
READINESS_NOT_RUN = "READINESS_NOT_RUN"
#: The sealed 1.7 manifest or one of its artifacts changed during the refresh.
ARCHIVE_CHANGED_DURING_REFRESH = "ARCHIVE_CHANGED_DURING_REFRESH"

# --------------------------------------------------------------- 1.8 policies
POLICIES = {
    "maturity_gate": (
        "A block is usable only when its label maturity date has arrived and the "
        "catalog was published on or after that date. Calendar maturity alone is "
        "never sufficient."
    ),
    "date_added_filter": (
        "KEV entries are filtered by dateAdded only when the catalog observes the "
        "entire maturity window. Otherwise the observation is right-censored and is "
        "reported RIGHT_CENSORED_NOT_FILTERED rather than presented as complete."
    ),
    "derived_view": (
        "A dateAdded-filtered view is a derived lower bound over one catalog, not "
        "an observed point-in-time membership set, and never a substitute for the "
        "1.6 event-membership rules."
    ),
    "late_retrieval": (
        "Historical EPSS files retrieved today are LATE_RETRIEVAL, not "
        "contemporaneous provenance, however authentic their bytes are."
    ),
    "no_substitution": (
        "A later score file, a backfilled value or a third-party mirror is never "
        "substituted for a missing official historical snapshot."
    ),
    "sealed_archive": (
        "The 1.7 archive and the sealed Phase 2.3K export are read-only inputs. A "
        "refresh writes to its own store and its own report directory."
    ),
    "integrity_is_not_viability": (
        "A VERIFIED integrity result proves the stored bytes are intact. It is not "
        "evidence that a historical evaluation is viable."
    ),
    "protocol_approval": (
        "Protocol approval remains an explicit human decision. No refresh status "
        "authorises protocol execution or model training."
    ),
}

#: Directories the refresh must never write into, expressed relative to the
#: VULNOVA product root.
PROTECTED_RELATIVE_PATHS = (
    "data/acquisition_store",
    "reports/acquisition_1_7",
    "reports/evaluation_readiness_1_6",
    "data/snapshots",
)

#: Default output directory for the 1.8 refresh artifacts.
DEFAULT_STORE_RELATIVE = "data/refresh_store_1_8"
DEFAULT_REPORT_RELATIVE = "reports/refresh_1_8/refresh_report.json"
DEFAULT_MARKDOWN_RELATIVE = "reports/refresh_1_8/REFRESH_1_8_REPORT.md"

#: Artifact paths inside the refresh store.  Both channels are kept separate:
#: the direct CISA feed and CISA's GitHub repository may legitimately serve
#: different bytes, and one must never overwrite the other.
REFRESH_KEV_DIRECT_PATH = "kev/refresh/cisa_feed/known_exploited_vulnerabilities.json"
REFRESH_KEV_GITHUB_PATH = "kev/refresh/github/known_exploited_vulnerabilities.json"


def final_maturity() -> dt.date:
    """Maturity date of the final candidate block (2026-10-28)."""
    return A.final_candidate_maturity()


def maturity_of(cutoff: dt.date) -> dt.date:
    return A.cutoff_maturity(cutoff)


__all__ = [
    "ARCHIVE_CHANGED_DURING_REFRESH",
    "BASELINE_MISSING",
    "DATE_ADDED_INVALID",
    "DEFAULT_MARKDOWN_RELATIVE",
    "DEFAULT_REPORT_RELATIVE",
    "DEFAULT_STORE_RELATIVE",
    "FILTERED_BY_DATE_ADDED",
    "GATE_MATURED_OBSERVED",
    "GATE_MATURED_SOURCE_MISSING",
    "GATE_MATURED_SOURCE_PREDATES",
    "GATE_NOT_MATURED",
    "GATE_STATUSES",
    "MATURITY_CLAIMED_EARLY",
    "MATURITY_NOT_REACHED",
    "OBSERVING_GATE_STATUSES",
    "PHASE_TITLE",
    "POLICIES",
    "PROTECTED_RELATIVE_PATHS",
    "READINESS_NOT_RUN",
    "REFRESH_BLOCKED_EVIDENCE",
    "REFRESH_BLOCKED_MATURITY",
    "REFRESH_BLOCKED_SOURCE",
    "REFRESH_EVIDENCE_COMPLETE",
    "REFRESH_KEV_DIRECT_PATH",
    "REFRESH_KEV_GITHUB_PATH",
    "REFRESH_STATUSES",
    "REFRESH_STORE_OVERLAPS_ARCHIVE",
    "RELEASE",
    "RIGHT_CENSORED_NOT_FILTERED",
    "SCHEMA_VERSION",
    "final_maturity",
    "maturity_of",
]
