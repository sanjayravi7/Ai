"""VULNOVA evaluation readiness (release 1.6).

This package reads the Phase 2.3K research export and produces a deterministic
readiness report.  It does not train, score, rank, approve or modify anything.
"""

from .constants import (
    HORIZON_DAYS,
    MATURITY_LAG_DAYS,
    MATURITY_SPAN_DAYS,
    REQUIRED_DISTINCT_TEST_EVENTS,
    REQUIRED_SEQUENTIAL_BLOCKS,
    SCHEMA_VERSION,
)
from .evidence import (
    KevEvidence,
    classify_kev_evidence,
    classification_vocabulary,
)
from .readiness import ReadinessOptions, build_report
from .temporal import (
    DesignSpec,
    evaluate_design,
    horizon_end,
    label_maturity_date,
    maturity_summary,
)

__all__ = [
    "HORIZON_DAYS",
    "MATURITY_LAG_DAYS",
    "MATURITY_SPAN_DAYS",
    "REQUIRED_DISTINCT_TEST_EVENTS",
    "REQUIRED_SEQUENTIAL_BLOCKS",
    "SCHEMA_VERSION",
    "KevEvidence",
    "classify_kev_evidence",
    "classification_vocabulary",
    "ReadinessOptions",
    "build_report",
    "DesignSpec",
    "evaluate_design",
    "horizon_end",
    "label_maturity_date",
    "maturity_summary",
]
