"""VULNOVA 1.8 — maturity gate and evidence refresh.

The package answers one question honestly: given the real calendar date and the
catalog we can actually obtain, may any block's labels be observed?

It reuses the 1.6 readiness engine and the 1.7 acquisition subsystem unchanged.
In particular it introduces no second status vocabulary, no second KEV parser and
no second transport, and it never writes to the sealed 1.7 archive or the sealed
Phase 2.3K export.
"""

from __future__ import annotations

from . import constants
from .gate import (
    CatalogFacts,
    DateAddedFilter,
    MaturityGateResult,
    catalog_facts,
    evaluate_gate,
    filter_entries_by_date_added,
    gate_summary,
)
from .errors import PathSafetyError, RefreshError
from .paths import assert_safe_write_targets
from .workflow import RefreshOptions, run_refresh

__all__ = [
    "CatalogFacts",
    "DateAddedFilter",
    "MaturityGateResult",
    "PathSafetyError",
    "RefreshError",
    "RefreshOptions",
    "assert_safe_write_targets",
    "catalog_facts",
    "constants",
    "evaluate_gate",
    "filter_entries_by_date_added",
    "gate_summary",
    "run_refresh",
]
