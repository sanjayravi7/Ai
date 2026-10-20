"""VULNOVA 1.9 — prospective evidence capture.

Start capturing evidence from the moment capture begins, so a future assessment
does not inherit the historical evaluation's central weakness: every artifact was
downloaded long after the period it describes.

Nothing here evaluates, matures labels, adopts a design or approves the protocol.
"""

from __future__ import annotations

from . import constants
from .capture import CaptureError, CaptureOptions, run_capture
from .cycle import CycleOptions, run_cycle
from .paths import assert_capture_safety, capture_protected_paths, historical_protected_paths
from .report import build_report, render_markdown, verify_digest
from .store import ProspectiveStore, StoreConflict
from .verify import verify_store

__all__ = [
    "CaptureError",
    "CaptureOptions",
    "CycleOptions",
    "ProspectiveStore",
    "StoreConflict",
    "assert_capture_safety",
    "build_report",
    "capture_protected_paths",
    "constants",
    "historical_protected_paths",
    "render_markdown",
    "run_capture",
    "run_cycle",
    "verify_digest",
    "verify_store",
]
