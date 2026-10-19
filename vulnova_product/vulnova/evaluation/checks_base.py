"""Shared types for readiness checks."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Optional

from . import constants as C
from .datasets import Dataset, PartitionScan
from .protocol import Protocol
from .temporal import DesignEvaluation


@dataclass
class Check:
    id: str
    title: str
    status: str
    reasons: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    blocking: bool = True

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "blocking": self.blocking,
            "reasons": list(self.reasons),
            "evidence": self.evidence,
        }


@dataclass
class CheckContext:
    dataset: Dataset
    protocol: Protocol
    as_of: dt.date
    reference_date: dt.date
    archive_results: list[dict] = field(default_factory=list)
    core_manifest: Optional[dict] = None
    full_manifest: Optional[dict] = None
    export_manifest: Optional[dict] = None
    extract_records: list[dict] = field(default_factory=list)
    scans: dict[str, PartitionScan] = field(default_factory=dict)
    scan_problems: list[dict] = field(default_factory=list)
    deep_requested: bool = True
    deep_performed: bool = False
    events_by_cutoff: dict[dt.date, set[str]] = field(default_factory=dict)
    event_problems: list[dict] = field(default_factory=list)
    first_seen_day: dict[str, dt.date] = field(default_factory=dict)
    source_coverage_end: Optional[dt.date] = None
    designs: list[DesignEvaluation] = field(default_factory=list)
    input_fingerprints: list[dict] = field(default_factory=list)
    previous_report: Optional[dict] = None

    @property
    def cutoff_texts(self) -> list[str]:
        return [cutoff.isoformat() for cutoff in self.dataset.cutoffs]

    @property
    def design_by_id(self) -> dict[str, DesignEvaluation]:
        return {design.id: design for design in self.designs}


def make_check(
    check_id: str,
    title: str,
    status: str,
    *,
    reasons: Optional[list[str]] = None,
    evidence: Optional[dict] = None,
    blocking: bool = True,
) -> Check:
    if status not in C.CHECK_STATUSES:
        raise ValueError(f"unknown check status: {status}")
    return Check(
        id=check_id,
        title=title,
        status=status,
        reasons=list(reasons or []),
        evidence=evidence or {},
        blocking=blocking,
    )


def passed(check_id: str, title: str, **kwargs) -> Check:
    return make_check(check_id, title, C.STATUS_PASS, **kwargs)


def failed(check_id: str, title: str, **kwargs) -> Check:
    return make_check(check_id, title, C.STATUS_FAIL, **kwargs)


def blocked(check_id: str, title: str, **kwargs) -> Check:
    return make_check(check_id, title, C.STATUS_BLOCKED, **kwargs)


def not_applicable(check_id: str, title: str, **kwargs) -> Check:
    return make_check(check_id, title, C.STATUS_NOT_APPLICABLE, **kwargs)


_STATUS_ORDER = {
    C.STATUS_NOT_APPLICABLE: 0,
    C.STATUS_PASS: 1,
    C.STATUS_BLOCKED: 2,
    C.STATUS_FAIL: 3,
}


def combine_status(statuses: list[str]) -> str:
    if not statuses:
        return C.STATUS_NOT_APPLICABLE
    return max(statuses, key=lambda value: _STATUS_ORDER.get(value, 0))
