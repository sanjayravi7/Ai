"""Frozen vocabulary for VULNOVA 1.9 prospective evidence capture.

1.6 asked whether a historical evaluation was possible; 1.7 acquired the
historical evidence that question needed; 1.8 showed that the final block's
labels cannot be observed from a catalog published before they matured.  1.9
starts building evidence *from now on*, so that a future assessment does not
inherit the historical evaluation's central weakness: every artifact was
downloaded long after the period it describes.

Two things this module deliberately does not do:

* it never treats a capture as an evaluation, and
* it never treats a hash as proof that the evidence is historically correct or
  that research is viable.

The status vocabulary is the 1.7 one — ``VERIFIED`` / ``UNAVAILABLE`` /
``BLOCKED`` — imported rather than redefined, so the three-state rule cannot
drift between the two subsystems.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..acquisition import constants as A

SCHEMA_VERSION = "vulnova.prospective/1.9"
PHASE_TITLE = "Prospective Evidence Capture"
RELEASE = "1.9"

# ------------------------------------------------------------------- kinds
KEV = "kev"
EPSS = "epss"
CVELISTV5 = "cvelistv5"
CAPTURE_KINDS = (KEV, EPSS, CVELISTV5)

#: Artifact file extensions, chosen so a stored file is self-describing without
#: a sidecar.
ARTIFACT_SUFFIX = {KEV: ".json", EPSS: ".csv.gz", CVELISTV5: ".json"}

#: Run-level outcomes.  ``ALREADY_CAPTURED`` is an outcome of *this invocation*,
#: not something stored in the run record: the first capture remains the record.
OUTCOME_CAPTURED = "CAPTURED"
OUTCOME_ALREADY_CAPTURED = "ALREADY_CAPTURED"

# ------------------------------------------------------------- reason codes
#: The capture store overlaps a sealed historical path.  Distinct from the
#: refresh message so an operator can see which subsystem refused.
STORE_OVERLAPS_PROTECTED = "STORE_OVERLAPS_PROTECTED"
#: A run identifier already exists with different bytes.  Never overwritten.
CAPTURE_ID_COLLISION = "CAPTURE_ID_COLLISION"
#: A stored artifact does not match the digest it is filed under.
ARTIFACT_TAMPERED = "ARTIFACT_TAMPERED"
#: The store contains no runs at all.
NO_CAPTURES = "NO_CAPTURES"
#: A prospective capture record carries a historical cutoff.  Prospective
#: capture records observation dates, never block boundaries.
HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE = "HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE"
#: Two captures for one observation date disagree about a source's bytes.
CONFLICTING_CAPTURES = "CONFLICTING_CAPTURES"
#: The stored run digest does not recompute.
RUN_DIGEST_MISMATCH = "RUN_DIGEST_MISMATCH"

# --------------------------------------------------------------- policies
POLICIES = {
    "prospective_not_retroactive": (
        "Capture begins when capture begins. Nothing here backfills historical "
        "access, and no historical artifact is re-dated."
    ),
    "absence_is_not_evidence": (
        "A failed request, a missing EPSS file or a CVE absent from KEV is a "
        "gap in observation. It is never evidence that a vulnerability was not "
        "exploited."
    ),
    "no_substitution": (
        "A third-party mirror, a newer score file or a backfilled value is never "
        "recorded as an official capture. An unavailable source is recorded as "
        "UNAVAILABLE."
    ),
    "immutable_artifacts": (
        "Raw bytes are content-addressed and created once. A second capture of "
        "identical bytes is a no-op; different bytes are stored beside the first, "
        "never over it."
    ),
    "hash_is_not_history": (
        "A matching SHA-256 proves the stored bytes are the bytes that were "
        "captured. It does not prove historical correctness, completeness or "
        "research viability."
    ),
    "capture_is_not_evaluation": (
        "Collecting daily evidence does not satisfy the three-block protocol. "
        "Maturity, observability, event counts, source coverage, independence, "
        "provenance and written approval remain separate requirements."
    ),
    "protocol_approval": (
        "Protocol approval remains an explicit human decision. No capture status "
        "authorises protocol execution or model training."
    ),
}

#: Directories under the product root that a prospective capture must never
#: write into.  The 1.6/1.7/snapshot/export paths come from the 1.8 guard; these
#: are the 1.8 artifacts that must be added on top.
PROTECTED_RELATIVE_PATHS = (
    "data/refresh_store_1_8",
    "reports/refresh_1_8",
    "protocol",
)

#: Environment variable that relocates the evidence store.  The default lives
#: outside the repository on purpose: daily EPSS files are unbounded and must
#: not become repository history.
STORE_ENV = "VULNOVA_PROSPECTIVE_STORE"
DEFAULT_STORE_DIRNAME = Path(".vulnova") / "prospective"

RUNS_DIR = "runs"
ARTIFACTS_DIR = "artifacts"

#: Fields excluded from the run digest: the digest itself, and the identifier
#: derived from it.
RUN_DIGEST_EXCLUDED = ("run_digest", "run_id")

#: A prospective record must never look like a historical cutoff record.
FORBIDDEN_RECORD_FIELDS = ("cutoff",)


def default_store_root() -> Path:
    """Where evidence is stored when no ``--store`` is given.

    Outside the repository by design: a year of daily EPSS files is roughly
    100 MB, and committing that stream would be both unbounded and a poor
    archive.
    """
    override = os.environ.get(STORE_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / DEFAULT_STORE_DIRNAME


def statuses() -> tuple[str, ...]:
    """The 1.7 three-state vocabulary, for assertions and help text."""
    return A.STATUSES


__all__ = [
    "ARTIFACTS_DIR",
    "ARTIFACT_SUFFIX",
    "ARTIFACT_TAMPERED",
    "CAPTURE_ID_COLLISION",
    "CAPTURE_KINDS",
    "CONFLICTING_CAPTURES",
    "CVELISTV5",
    "DEFAULT_STORE_DIRNAME",
    "EPSS",
    "FORBIDDEN_RECORD_FIELDS",
    "HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE",
    "KEV",
    "NO_CAPTURES",
    "OUTCOME_ALREADY_CAPTURED",
    "OUTCOME_CAPTURED",
    "PHASE_TITLE",
    "POLICIES",
    "PROTECTED_RELATIVE_PATHS",
    "RELEASE",
    "RUNS_DIR",
    "RUN_DIGEST_EXCLUDED",
    "RUN_DIGEST_MISMATCH",
    "SCHEMA_VERSION",
    "STORE_ENV",
    "STORE_OVERLAPS_PROTECTED",
    "default_store_root",
    "statuses",
]
