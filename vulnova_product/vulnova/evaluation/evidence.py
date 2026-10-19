"""Three-state KEV evidence classification.

The distinction below is mandatory and must not be collapsed:

``CONFIRMED_KEV_INCLUSION``
    The CVE was observed in a readable CISA KEV catalog revision at the relevant
    point in time.

``ABSENT_FROM_KEV``
    A readable catalog revision existed and did not list the CVE.  This is an
    observation about one catalog, *not* proof that the vulnerability was never
    exploited.

``MISSING_HISTORICAL_EVIDENCE``
    No readable catalog revision is available at the relevant point in time
    (no revision, an unavailable source, or an unparseable/truncated revision).
    Nothing can be concluded either way.

``ABSENT_FROM_KEV`` is never converted into a negative exploitation label and
``MISSING_HISTORICAL_EVIDENCE`` is never converted into absence.  The helper
functions here are deliberately explicit about both prohibitions.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional


class KevEvidence(str, Enum):
    CONFIRMED_KEV_INCLUSION = "CONFIRMED_KEV_INCLUSION"
    ABSENT_FROM_KEV = "ABSENT_FROM_KEV"
    MISSING_HISTORICAL_EVIDENCE = "MISSING_HISTORICAL_EVIDENCE"


ABSENCE_INTERPRETATION = (
    "ABSENT_FROM_KEV is not proof of non-exploitation. KEV is not an exhaustive "
    "record of exploitation; a CVE missing from a catalog revision means only that "
    "this catalog did not list it at that observation point."
)

MISSING_INTERPRETATION = (
    "MISSING_HISTORICAL_EVIDENCE means the question cannot be answered from the "
    "available revision: no readable catalog was observed at the relevant time. "
    "It is not equivalent to absence and must not be imputed as one."
)


@dataclass(frozen=True)
class KevEvidenceAssessment:
    """One CVE's KEV status at one observation point."""

    cve_id: str
    status: KevEvidence
    observed_at: dt.date
    catalogue_revision: Optional[str]
    reason: str
    detail: str

    @property
    def confirms_inclusion(self) -> bool:
        return self.status is KevEvidence.CONFIRMED_KEV_INCLUSION

    @property
    def supports_negative_label(self) -> bool:
        """Absence never supports a negative exploitation label."""
        return False

    @property
    def supports_positive_label(self) -> bool:
        return self.confirms_inclusion

    def as_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "status": self.status.value,
            "observed_at": self.observed_at.isoformat(),
            "catalogue_revision": self.catalogue_revision,
            "reason": self.reason,
            "detail": self.detail,
            "supports_positive_label": self.supports_positive_label,
            "supports_negative_label": self.supports_negative_label,
        }


def classify_kev_evidence(
    cve_id: str,
    *,
    observed_at: dt.date,
    catalogue_revision: Optional[str],
    revision_available: bool,
    revision_readable: bool,
    membership_ids: Optional[Iterable[str]],
) -> KevEvidenceAssessment:
    """Classify one CVE without ever treating absence as non-exploitation.

    ``membership_ids`` must be the *observed* membership of the catalog revision
    in force at ``observed_at``.  A set reconstructed from ``dateAdded`` is not
    acceptable and must not be passed here.
    """
    revision = catalogue_revision
    if not revision_available:
        return KevEvidenceAssessment(
            cve_id=cve_id,
            status=KevEvidence.MISSING_HISTORICAL_EVIDENCE,
            observed_at=observed_at,
            catalogue_revision=revision,
            reason="NO_CATALOG_REVISION_AVAILABLE",
            detail="No KEV catalog revision was available at or before the observation point.",
        )
    if not revision_readable or membership_ids is None:
        return KevEvidenceAssessment(
            cve_id=cve_id,
            status=KevEvidence.MISSING_HISTORICAL_EVIDENCE,
            observed_at=observed_at,
            catalogue_revision=revision,
            reason="CATALOG_REVISION_UNREADABLE",
            detail="The catalog revision in force could not be read; membership is unknown.",
        )

    ids = membership_ids if isinstance(membership_ids, (set, frozenset)) else set(membership_ids)
    if cve_id in ids:
        return KevEvidenceAssessment(
            cve_id=cve_id,
            status=KevEvidence.CONFIRMED_KEV_INCLUSION,
            observed_at=observed_at,
            catalogue_revision=revision,
            reason="LISTED_IN_OBSERVED_CATALOG_REVISION",
            detail="The CVE is present in the catalog revision observed at or before the cutoff.",
        )
    return KevEvidenceAssessment(
        cve_id=cve_id,
        status=KevEvidence.ABSENT_FROM_KEV,
        observed_at=observed_at,
        catalogue_revision=revision,
        reason="NOT_LISTED_IN_OBSERVED_CATALOG_REVISION",
        detail="The CVE is not listed in this catalog revision. This is not evidence "
        "that the vulnerability was not exploited.",
    )


def absence_is_proof_of_non_exploitation() -> bool:
    """Constant answer, exposed so that callers cannot answer it by accident."""
    return False


def classification_vocabulary() -> dict:
    """The vocabulary carried into every machine-readable report."""
    return {
        "CONFIRMED_KEV_INCLUSION": {
            "meaning": "Observed in a readable KEV catalog revision at the observation point.",
            "can_support_positive_label": True,
            "can_support_negative_label": False,
        },
        "ABSENT_FROM_KEV": {
            "meaning": "A readable catalog revision did not list the CVE.",
            "can_support_positive_label": False,
            "can_support_negative_label": False,
            "interpretation": ABSENCE_INTERPRETATION,
        },
        "MISSING_HISTORICAL_EVIDENCE": {
            "meaning": "No readable catalog revision at the observation point; unknown.",
            "can_support_positive_label": False,
            "can_support_negative_label": False,
            "interpretation": MISSING_INTERPRETATION,
        },
        "absence_is_proof_of_non_exploitation": False,
    }
