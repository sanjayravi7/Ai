"""The maturity gate: has a block matured, and can the catalog observe it?

Two questions, asked separately, because they fail separately:

1. **Calendar.**  Has the block's label maturity date (cutoff + 210 days)
   arrived at the run's as-of date?  Nothing about an artifact can answer this.
2. **Observation.**  Was the catalog we hold published on or after that maturity
   date?  A catalog released the day before maturity is perfectly authentic and
   still cannot contain the labels that matured the day after.

Only when both answers are yes may a ``dateAdded``-filtered view be produced.
Otherwise the observation is *right-censored*: we can see that the catalog
stopped, but not what came after.  A censored observation is reported as
``RIGHT_CENSORED_NOT_FILTERED`` and is never dressed up as a complete label set.

The filtered view is itself a derived lower bound over a single catalog, not an
observed point-in-time membership set.  The 1.6 event rules — events are
*observed* first inclusions within ``(T, T+180d]``, never reconstructed from
``dateAdded`` — remain the only basis for a real label.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..acquisition import constants as A
from ..acquisition.records import ArtifactRecord, to_instant
from ..evaluation.temporal import label_maturity_date, parse_date
from . import constants as C


# --------------------------------------------------------------------- catalog
@dataclass(frozen=True)
class CatalogFacts:
    """What the selected catalog artifact says about itself."""

    available: bool
    key: Optional[str] = None
    channel: Optional[str] = None
    revision: Optional[str] = None
    catalog_version: Optional[str] = None
    released: Optional[str] = None
    released_day: Optional[dt.date] = None
    declared_count: Optional[int] = None
    parsed_count: Optional[int] = None
    sha256: Optional[str] = None
    artifact_path: Optional[str] = None
    retrieved_at: Optional[str] = None
    request_url: Optional[str] = None
    final_url: Optional[str] = None
    content_status: str = A.UNAVAILABLE
    reason_code: str = A.NO_RECORDS

    @property
    def verified(self) -> bool:
        return self.available and self.content_status == A.VERIFIED

    def as_dict(self) -> dict:
        return {
            "available": self.available,
            "verified": self.verified,
            "key": self.key,
            "channel": self.channel,
            "revision": self.revision,
            "catalog_version": self.catalog_version,
            "released": self.released,
            "released_day": (
                self.released_day.isoformat() if self.released_day else None
            ),
            "declared_count": self.declared_count,
            "parsed_count": self.parsed_count,
            "sha256": self.sha256,
            "artifact_path": self.artifact_path,
            "retrieved_at": self.retrieved_at,
            "request_url": self.request_url,
            "final_url": self.final_url,
            "redirected": bool(self.final_url and self.final_url != self.request_url),
            "content_status": self.content_status,
            "reason_code": self.reason_code,
        }


def catalog_facts(record: Optional[ArtifactRecord]) -> CatalogFacts:
    """Summarise a catalog record without trusting anything it does not state."""
    if record is None:
        return CatalogFacts(available=False)
    details = record.details or {}
    released = record.source_timestamp or details.get("date_released")
    released_day: Optional[dt.date] = None
    if isinstance(released, str) and released:
        try:
            released_day = to_instant(released).date()
        except (TypeError, ValueError):
            released_day = None
    return CatalogFacts(
        available=True,
        key=record.key,
        channel=record.channel,
        revision=record.revision,
        catalog_version=details.get("catalog_version"),
        released=released if isinstance(released, str) else None,
        released_day=released_day,
        declared_count=details.get("declared_count"),
        parsed_count=details.get("parsed_count"),
        sha256=record.sha256,
        artifact_path=record.artifact_path,
        retrieved_at=record.retrieved_at,
        request_url=record.request_url or None,
        final_url=record.final_url or None,
        content_status=record.content_status,
        reason_code=record.reason_code,
    )


# ------------------------------------------------------------------------ gate
@dataclass
class MaturityGateResult:
    """One block's maturity verdict."""

    cutoff: dt.date
    maturity_date: dt.date
    as_of: dt.date
    calendar_matured: bool
    days_remaining: int
    catalog_available: bool
    catalog_observes_maturity: bool
    catalog_released: Optional[str]
    status: str
    reason_code: str
    secondary_reason: Optional[str] = None
    detail: str = ""
    filter_applied: bool = False
    filter_basis: str = C.RIGHT_CENSORED_NOT_FILTERED

    @property
    def matured(self) -> bool:
        """True only when the date arrived *and* the catalog observes it."""
        return self.status in C.OBSERVING_GATE_STATUSES

    def as_dict(self) -> dict:
        return {
            "cutoff": self.cutoff.isoformat(),
            "maturity_date": self.maturity_date.isoformat(),
            "horizon_days": A.HORIZON_DAYS,
            "maturity_lag_days": A.MATURITY_LAG_DAYS,
            "maturity_span_days": A.MATURITY_SPAN_DAYS,
            "as_of": self.as_of.isoformat(),
            "calendar_matured": self.calendar_matured,
            "days_remaining": self.days_remaining,
            "catalog_available": self.catalog_available,
            "catalog_released": self.catalog_released,
            "catalog_observes_maturity": self.catalog_observes_maturity,
            "status": self.status,
            "reason_code": self.reason_code,
            "secondary_reason": self.secondary_reason,
            "detail": self.detail,
            "maturity_claimed": self.matured,
            "filter_applied": self.filter_applied,
            "filter_basis": self.filter_basis,
        }


def evaluate_gate(
    cutoff: dt.date,
    *,
    as_of: dt.date,
    catalog: Optional[CatalogFacts],
    maturity: Optional[dt.date] = None,
) -> MaturityGateResult:
    """Decide one block's gate without ever upgrading a censored observation."""
    maturity = maturity or label_maturity_date(cutoff)
    calendar_matured = maturity <= as_of
    days_remaining = (maturity - as_of).days
    released_day = catalog.released_day if catalog and catalog.verified else None
    observes = bool(released_day is not None and released_day >= maturity)

    result = MaturityGateResult(
        cutoff=cutoff,
        maturity_date=maturity,
        as_of=as_of,
        calendar_matured=calendar_matured,
        days_remaining=days_remaining,
        catalog_available=bool(catalog and catalog.verified),
        catalog_observes_maturity=observes,
        catalog_released=catalog.released if catalog else None,
        status=C.GATE_NOT_MATURED,
        reason_code=C.MATURITY_NOT_REACHED,
    )

    if not calendar_matured:
        # The clock is the first gate.  Record the artifact's own limitation as a
        # secondary reason so a reader can see both obstacles at once.
        result.status = C.GATE_NOT_MATURED
        result.reason_code = C.MATURITY_NOT_REACHED
        result.secondary_reason = (
            None if observes else A.CATALOG_PREDATES_MATURITY if catalog and catalog.verified else None
        )
        result.detail = (
            f"labels mature {maturity.isoformat()}, {abs(days_remaining)} day(s) after "
            f"the run date {as_of.isoformat()}; maturity is not claimed and no filtered "
            "label view is produced"
        )
        return result

    if not catalog or not catalog.verified:
        result.status = C.GATE_MATURED_SOURCE_MISSING
        result.reason_code = A.NO_RECORDS
        result.detail = (
            f"labels matured {maturity.isoformat()}, but no readable KEV catalog was "
            "acquired; the block cannot be observed"
        )
        return result

    if not observes:
        result.status = C.GATE_MATURED_SOURCE_PREDATES
        result.reason_code = A.CATALOG_PREDATES_MATURITY
        result.secondary_reason = C.RIGHT_CENSORED_NOT_FILTERED
        result.detail = (
            f"labels matured {maturity.isoformat()}, but the catalog was released "
            f"{catalog.released or 'at an unknown time'}; the observation is right-censored"
        )
        return result

    result.status = C.GATE_MATURED_OBSERVED
    result.reason_code = A.OK_VERIFIED
    result.filter_applied = True
    result.filter_basis = C.FILTERED_BY_DATE_ADDED
    result.detail = (
        f"labels matured {maturity.isoformat()} and the catalog was released "
        f"{catalog.released}; a dateAdded view up to maturity is permitted"
    )
    return result


# ------------------------------------------------------------ dateAdded filter
@dataclass
class DateAddedFilter:
    """A derived, clearly-labelled view — never a reconstructed label set."""

    applied: bool
    trustworthy: bool
    basis: str
    maturity_date: str
    catalog_released: Optional[str]
    entries_total: Optional[int] = None
    entries_observable: Optional[int] = None
    entries_after_maturity: Optional[int] = None
    entries_invalid: int = 0
    reason_code: str = C.RIGHT_CENSORED_NOT_FILTERED
    note: str = ""
    sample_after_maturity: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "applied": self.applied,
            "trustworthy": self.trustworthy,
            "basis": self.basis,
            "maturity_date": self.maturity_date,
            "catalog_released": self.catalog_released,
            "entries_total": self.entries_total,
            "entries_observable": self.entries_observable,
            "entries_after_maturity": self.entries_after_maturity,
            "entries_invalid": self.entries_invalid,
            "reason_code": self.reason_code,
            "sample_after_maturity": list(self.sample_after_maturity),
            "note": self.note,
        }


def filter_entries_by_date_added(
    entries: Iterable[dict],
    *,
    maturity: dt.date,
    applied: bool,
    catalog_released: Optional[str] = None,
) -> DateAddedFilter:
    """Count entries at or before ``maturity`` — only when that is observable.

    When ``applied`` is false the filter does not run at all and the result says
    so explicitly.  When an entry carries an unusable ``dateAdded`` the view is
    marked untrustworthy rather than silently dropping the entry.
    """
    maturity_text = maturity.isoformat()
    if not applied:
        return DateAddedFilter(
            applied=False,
            trustworthy=True,
            basis=C.RIGHT_CENSORED_NOT_FILTERED,
            maturity_date=maturity_text,
            catalog_released=catalog_released,
            reason_code=C.RIGHT_CENSORED_NOT_FILTERED,
            note=(
                "Not filtered: the catalog cannot observe the entire maturity window, "
                "so no subset of its entries may be reported as the matured labels."
            ),
        )

    total = 0
    observable = 0
    after = 0
    invalid = 0
    sample: list[str] = []
    for entry in entries:
        total += 1
        if not isinstance(entry, dict):
            invalid += 1
            continue
        raw = entry.get("dateAdded")
        if not isinstance(raw, str):
            invalid += 1
            continue
        try:
            added = parse_date(raw)
        except ValueError:
            invalid += 1
            continue
        if added <= maturity:
            observable += 1
        else:
            after += 1
            if len(sample) < 5 and isinstance(entry.get("cveID"), str):
                sample.append(entry["cveID"])

    if invalid:
        return DateAddedFilter(
            applied=True,
            trustworthy=False,
            basis=C.DATE_ADDED_INVALID,
            maturity_date=maturity_text,
            catalog_released=catalog_released,
            entries_total=total,
            entries_observable=observable,
            entries_after_maturity=after,
            entries_invalid=invalid,
            reason_code=C.DATE_ADDED_INVALID,
            sample_after_maturity=sample,
            note=(
                f"{invalid} entr(ies) carry no usable dateAdded; the derived view is "
                "reported but not trusted and must not be used as a label set."
            ),
        )

    return DateAddedFilter(
        applied=True,
        trustworthy=True,
        basis=C.FILTERED_BY_DATE_ADDED,
        maturity_date=maturity_text,
        catalog_released=catalog_released,
        entries_total=total,
        entries_observable=observable,
        entries_after_maturity=after,
        entries_invalid=0,
        reason_code=C.FILTERED_BY_DATE_ADDED,
        sample_after_maturity=sample,
        note=(
            "Derived lower bound over one catalog, not an observed point-in-time "
            "membership set; the 1.6 event rules still govern any real label."
        ),
    )


def gate_summary(gates: Iterable[MaturityGateResult]) -> dict:
    """Aggregate gate results without softening the worst one."""
    results = list(gates)
    if not results:
        return {
            "blocks": 0,
            "all_calendar_matured": False,
            "all_maturity_observable": False,
            "final_block_maturity_observable": False,
            "worst_status": C.GATE_NOT_MATURED,
        }
    final = max(results, key=lambda gate: gate.cutoff)
    return {
        "blocks": len(results),
        "all_calendar_matured": all(gate.calendar_matured for gate in results),
        "all_maturity_observable": all(gate.matured for gate in results),
        "final_block_maturity_observable": final.matured,
        "worst_status": _worst_gate(results),
        "final_cutoff": final.cutoff.isoformat(),
        "final_maturity_date": final.maturity_date.isoformat(),
        "final_days_remaining": final.days_remaining,
    }


_GATE_RANK = {
    C.GATE_MATURED_OBSERVED: 0,
    C.GATE_NOT_MATURED: 1,
    C.GATE_MATURED_SOURCE_PREDATES: 2,
    C.GATE_MATURED_SOURCE_MISSING: 3,
}


def _worst_gate(results: list[MaturityGateResult]) -> str:
    return max(results, key=lambda gate: _GATE_RANK.get(gate.status, 9)).status


__all__ = [
    "CatalogFacts",
    "DateAddedFilter",
    "MaturityGateResult",
    "catalog_facts",
    "evaluate_gate",
    "filter_entries_by_date_added",
    "gate_summary",
]
