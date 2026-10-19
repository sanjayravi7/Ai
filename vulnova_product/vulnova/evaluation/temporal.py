"""Temporal arithmetic and design feasibility.

The rules are intentionally small and explicit:

* an event must occur strictly after the cutoff and within the 180-day horizon;
* labels mature 30 days after the horizon ends, i.e. 210 days after the cutoff;
* a sequential block may only follow once the previous block's labels matured;
* a block is gated only when its labels are matured *and* the source timeline
  actually covers the maturity date.

Nothing here reads a model score or changes a weight.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

from .constants import (
    HORIZON_DAYS,
    MATURITY_LAG_DAYS,
    MATURITY_SPAN_DAYS,
    REQUIRED_DISTINCT_TEST_EVENTS,
    REQUIRED_SEQUENTIAL_BLOCKS,
)

# Reason codes.  They travel into the machine-readable report unchanged.
CUTOFF_MISSING = "CUTOFF_MISSING"
EVENT_GATE_NOT_MET = "EVENT_GATE_NOT_MET"
BLOCK_LABELS_NOT_MATURED = "BLOCK_LABELS_NOT_MATURED"
LABEL_STABILITY_NOT_OBSERVABLE = "LABEL_STABILITY_NOT_OBSERVABLE"
LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK = "LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK"
SHARED_EVENTS_BETWEEN_BLOCKS = "SHARED_EVENTS_BETWEEN_BLOCKS"
INSUFFICIENT_BLOCKS = "INSUFFICIENT_BLOCKS"
ROLLING_ORIGIN_NOT_SEQUENTIAL_DESIGN = "ROLLING_ORIGIN_NOT_SEQUENTIAL_DESIGN"
DESIGN_CONSTANT_MISMATCH = "DESIGN_CONSTANT_MISMATCH"


def parse_date(value: str) -> dt.date:
    """Parse an ISO date, raising a message that names the offending value."""
    try:
        return dt.date.fromisoformat(value.strip())
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"not an ISO date: {value!r}") from exc


def parse_instant(value: str) -> dt.datetime:
    """Parse an ISO timestamp into an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"not an ISO timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def horizon_end(cutoff: dt.date) -> dt.date:
    """Last day of the forward outcome window (inclusive)."""
    return cutoff + dt.timedelta(days=HORIZON_DAYS)


def label_maturity_date(cutoff: dt.date) -> dt.date:
    """Date on which a block's labels are considered settled."""
    return cutoff + dt.timedelta(days=MATURITY_SPAN_DAYS)


def days_until_matured(cutoff: dt.date, as_of: dt.date) -> int:
    """Signed number of days until maturity at ``as_of`` (negative = matured)."""
    return (label_maturity_date(cutoff) - as_of).days


def in_event_window(cutoff: dt.date, observed_day: dt.date) -> bool:
    """True when an observation falls in ``(cutoff, cutoff + 180 days]``."""
    return cutoff < observed_day <= horizon_end(cutoff)


@dataclass(frozen=True)
class BlockSpec:
    role: str
    cutoffs: tuple[dt.date, ...]


@dataclass(frozen=True)
class DesignSpec:
    id: str
    title: str
    kind: str  # "sequential" | "rolling_origin" | "single_cutoff"
    blocks: tuple[BlockSpec, ...]
    phase2_3k_verdict: Optional[str] = None

    @classmethod
    def from_dict(cls, payload: Mapping) -> "DesignSpec":
        blocks = tuple(
            BlockSpec(
                role=str(block.get("role", f"BLOCK{index + 1}")),
                cutoffs=tuple(parse_date(value) for value in block.get("cutoffs", [])),
            )
            for index, block in enumerate(payload.get("blocks", []))
        )
        return cls(
            id=str(payload["id"]),
            title=str(payload.get("title", payload["id"])),
            kind=str(payload.get("kind", "sequential")),
            blocks=blocks,
            phase2_3k_verdict=payload.get("phase2_3k_verdict"),
        )


@dataclass
class BlockEvaluation:
    role: str
    cutoffs: list[str]
    event_rows: int = 0
    distinct_events: int = 0
    reused_event_rows: int = 0
    maturity_date: Optional[str] = None
    horizon_end: Optional[str] = None
    matured_at_as_of: bool = False
    label_stability_observable: bool = False
    gate_met: Optional[bool] = None
    gate_basis: str = "NOT_EVALUATED"
    reasons: list[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "role": self.role,
            "cutoffs": list(self.cutoffs),
            "event_rows": self.event_rows,
            "distinct_events": self.distinct_events,
            "reused_event_rows": self.reused_event_rows,
            "maturity_date": self.maturity_date,
            "horizon_end": self.horizon_end,
            "matured_at_as_of": self.matured_at_as_of,
            "label_stability_observable": self.label_stability_observable,
            "gate_required": REQUIRED_DISTINCT_TEST_EVENTS,
            "gate_met": self.gate_met,
            "gate_basis": self.gate_basis,
            "reasons": list(self.reasons),
            "detail": self.detail,
        }


@dataclass
class DesignEvaluation:
    id: str
    title: str
    kind: str
    blocks: list[BlockEvaluation] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    verdict: str = "NOT_EVALUATED"
    protocol_admissible: bool = False
    phase2_3k_verdict: Optional[str] = None
    matches_phase2_3k: Optional[bool] = None
    comparison_as_of: Optional[str] = None
    detail: str = ""

    @property
    def feasible(self) -> bool:
        return self.verdict in ("FEASIBLE", "FEASIBLE_BUT_INSUFFICIENT_BLOCKS")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "blocks": [block.as_dict() for block in self.blocks],
            "required_sequential_blocks": REQUIRED_SEQUENTIAL_BLOCKS,
            "distinct_events_by_block": {
                block.role: block.distinct_events for block in self.blocks
            },
            "reason_codes": list(self.reason_codes),
            "verdict": self.verdict,
            "feasible": self.feasible,
            "protocol_admissible": self.protocol_admissible,
            "phase2_3k_verdict": self.phase2_3k_verdict,
            "matches_phase2_3k": self.matches_phase2_3k,
            "comparison_as_of": self.comparison_as_of,
            "detail": self.detail,
        }


_PHASE2_3K_CODE_MAP = {
    "INFEASIBLE_LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK": {
        LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK
    },
    "INFEASIBLE_BLOCK_NOT_MATURED": {BLOCK_LABELS_NOT_MATURED},
    "INFEASIBLE_SHARED_EVENTS_AND_LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK": {
        SHARED_EVENTS_BETWEEN_BLOCKS,
        LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK,
    },
    "FEASIBLE": set(),
}


def _evaluate_block(
    spec: BlockSpec,
    *,
    events_by_cutoff: Mapping[dt.date, set[str]],
    as_of: dt.date,
    source_coverage_end: Optional[dt.date],
) -> BlockEvaluation:
    cutoffs = sorted(spec.cutoffs)
    block = BlockEvaluation(role=spec.role, cutoffs=[c.isoformat() for c in cutoffs])
    missing = [c for c in cutoffs if c not in events_by_cutoff]
    if not cutoffs or missing:
        block.reasons.append(CUTOFF_MISSING)
        block.detail = (
            "No event data for cutoff(s): " + ", ".join(c.isoformat() for c in missing)
            if missing
            else "Block declares no cutoff."
        )
        block.gate_basis = "NOT_EVALUATED"
        return block

    all_events: set[str] = set()
    event_rows = 0
    for cutoff in cutoffs:
        ids = events_by_cutoff[cutoff]
        event_rows += len(ids)
        all_events.update(ids)

    block.event_rows = event_rows
    block.distinct_events = len(all_events)
    block.reused_event_rows = event_rows - len(all_events)
    block.maturity_date = max(label_maturity_date(c) for c in cutoffs).isoformat()
    block.horizon_end = max(horizon_end(c) for c in cutoffs).isoformat()
    maturity = label_maturity_date(max(cutoffs))
    block.matured_at_as_of = maturity <= as_of
    block.label_stability_observable = (
        source_coverage_end is not None and maturity <= source_coverage_end
    )

    if not block.matured_at_as_of:
        block.reasons.append(BLOCK_LABELS_NOT_MATURED)
    if not block.label_stability_observable:
        block.reasons.append(LABEL_STABILITY_NOT_OBSERVABLE)

    if block.matured_at_as_of and block.label_stability_observable:
        block.gate_met = block.distinct_events >= REQUIRED_DISTINCT_TEST_EVENTS
        block.gate_basis = "DISTINCT_EVENTS"
        if not block.gate_met:
            block.reasons.append(EVENT_GATE_NOT_MET)
    else:
        block.gate_met = None
        block.gate_basis = "FLOOR_NOT_A_GATE_RESULT"
    return block


def _matches_phase2_3k(
    expected: Optional[str], evaluation: DesignEvaluation
) -> Optional[bool]:
    if expected is None:
        return None
    if expected == "FEASIBLE":
        if evaluation.kind == "rolling_origin":
            # Phase 2.3K called each rolling cutoffs feasible on its own; the
            # design is still not a sequential protocol design.
            return all(not block.reasons for block in evaluation.blocks)
        return evaluation.feasible
    required = _PHASE2_3K_CODE_MAP.get(expected)
    if required is None:
        return None
    return required.issubset(set(evaluation.reason_codes))


def evaluate_design(
    spec: DesignSpec,
    *,
    events_by_cutoff: Mapping[dt.date, set[str]],
    as_of: dt.date,
    source_coverage_end: Optional[dt.date],
) -> DesignEvaluation:
    """Evaluate one candidate design against the frozen rules.

    The result never asserts protocol approval.  ``protocol_admissible`` is a
    technical admission test only: three sequential blocks, all labels matured
    and observable, every block above the event gate, and no shared events.
    """
    result = DesignEvaluation(
        id=spec.id,
        title=spec.title,
        kind=spec.kind,
        phase2_3k_verdict=spec.phase2_3k_verdict,
    )
    if not spec.blocks:
        result.reason_codes.append(CUTOFF_MISSING)
        result.verdict = "INFEASIBLE"
        result.detail = "Design declares no block."
        result.matches_phase2_3k = _matches_phase2_3k(spec.phase2_3k_verdict, result)
        return result

    if spec.kind == "rolling_origin":
        block_evals = [
            _evaluate_block(
                block,
                events_by_cutoff=events_by_cutoff,
                as_of=as_of,
                source_coverage_end=source_coverage_end,
            )
            for block in spec.blocks
        ]
        result.blocks = block_evals
        codes: set[str] = set()
        for block in block_evals:
            codes.update(block.reasons)
        codes.add(ROLLING_ORIGIN_NOT_SEQUENTIAL_DESIGN)
        result.reason_codes = sorted(codes)
        result.verdict = "INFEASIBLE"
        result.protocol_admissible = False
        result.detail = (
            "Rolling-origin cutoffs are independent single-cutoff evaluations, not a "
            "sequential train/validation/test design."
        )
        result.matches_phase2_3k = _matches_phase2_3k(spec.phase2_3k_verdict, result)
        return result

    block_evals = [
        _evaluate_block(
            block,
            events_by_cutoff=events_by_cutoff,
            as_of=as_of,
            source_coverage_end=source_coverage_end,
        )
        for block in spec.blocks
    ]
    result.blocks = block_evals

    codes: set[str] = set()
    for block in block_evals:
        codes.update(block.reasons)

    # Sequential maturity: a block's labels must settle before the next block
    # decides.  The decision point is the next block's earliest cutoff.
    for index in range(1, len(block_evals)):
        previous = block_evals[index - 1]
        current = block_evals[index]
        if previous.maturity_date is None or not current.cutoffs:
            continue
        maturity = parse_date(previous.maturity_date)
        decision = parse_date(min(current.cutoffs))
        slack = (decision - maturity).days
        if slack < 0:
            codes.add(LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK)
            previous.reasons.append(LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK)
            previous.detail = (
                f"Labels mature {maturity.isoformat()}, but the next block decides "
                f"{decision.isoformat()} ({slack} days short)."
            )

    # Event reuse between blocks.  Duplicate rows are a different defect and are
    # kept separate from cross-block reuse.
    seen: set[str] = set()
    for block in block_evals:
        if not block.cutoffs:
            continue
        current: set[str] = set()
        for cutoff_text in block.cutoffs:
            cutoff = parse_date(cutoff_text)
            current.update(events_by_cutoff.get(cutoff, set()))
        shared = current & seen
        if shared:
            codes.add(SHARED_EVENTS_BETWEEN_BLOCKS)
            block.detail = (
                (block.detail + " " if block.detail else "")
                + f"Shares {len(shared)} event(s) with an earlier block."
            )
        seen.update(current)

    if len(block_evals) < REQUIRED_SEQUENTIAL_BLOCKS:
        codes.add(INSUFFICIENT_BLOCKS)

    result.reason_codes = sorted(codes)
    blocking_codes = codes - {INSUFFICIENT_BLOCKS}
    if not blocking_codes:
        if len(block_evals) >= REQUIRED_SEQUENTIAL_BLOCKS:
            result.verdict = "FEASIBLE"
            result.protocol_admissible = True
            result.detail = "All frozen temporal and event-gate conditions are satisfied."
        else:
            result.verdict = "FEASIBLE_BUT_INSUFFICIENT_BLOCKS"
            result.protocol_admissible = False
            result.detail = (
                f"{len(block_evals)} block(s) are technically constructible, but the "
                f"protocol requires {REQUIRED_SEQUENTIAL_BLOCKS} sequential blocks; a "
                "two-block design is not silently substituted."
            )
    else:
        result.verdict = "INFEASIBLE"
        result.protocol_admissible = False
        result.detail = "Blocked by: " + ", ".join(sorted(blocking_codes)) + "."
    result.matches_phase2_3k = _matches_phase2_3k(spec.phase2_3k_verdict, result)
    return result


def matches_phase2_3k(
    evaluation: DesignEvaluation, reference_evaluation: DesignEvaluation
) -> Optional[bool]:
    """Compare a design against Phase 2.3K's verdict using the reference-date run.

    Maturity status is time-dependent.  Phase 2.3K recorded its verdict at the
    protocol reference date, so that is the only valid basis for comparison even
    when readiness is run with a later ``--as-of``.
    """
    result = _matches_phase2_3k(
        evaluation.phase2_3k_verdict, reference_evaluation
    )
    evaluation.matches_phase2_3k = result
    evaluation.comparison_as_of = None
    return result


def sequential_slack_days(previous_maturity: dt.date, next_decision: dt.date) -> int:
    """Positive slack means the next block decides after labels matured."""
    return (next_decision - previous_maturity).days


def validate_event_windows(
    events_by_cutoff: Mapping[dt.date, Iterable[str]],
    first_seen: Mapping[str, dt.date],
) -> list[dict]:
    """Return events whose first observation falls outside ``(T, T+180d]``."""
    violations: list[dict] = []
    for cutoff, ids in sorted(events_by_cutoff.items()):
        for cve_id in sorted(ids):
            observed = first_seen.get(cve_id)
            if observed is None:
                violations.append(
                    {
                        "cutoff": cutoff.isoformat(),
                        "cve_id": cve_id,
                        "reason": "NO_FIRST_OBSERVATION_EVIDENCE",
                    }
                )
            elif observed <= cutoff:
                violations.append(
                    {
                        "cutoff": cutoff.isoformat(),
                        "cve_id": cve_id,
                        "first_observed": observed.isoformat(),
                        "reason": "EVENT_OBSERVED_AT_OR_BEFORE_CUTOFF",
                    }
                )
            elif observed > horizon_end(cutoff):
                violations.append(
                    {
                        "cutoff": cutoff.isoformat(),
                        "cve_id": cve_id,
                        "first_observed": observed.isoformat(),
                        "reason": "EVENT_AFTER_HORIZON",
                    }
                )
    return violations


def event_set_overlaps(
    block_event_sets: Sequence[tuple[str, set[str]]],
) -> dict:
    """Pairwise event reuse, reported separately from outcome-window overlap."""
    pairs = []
    for left in range(len(block_event_sets)):
        for right in range(left + 1, len(block_event_sets)):
            left_role, left_ids = block_event_sets[left]
            right_role, right_ids = block_event_sets[right]
            shared = sorted(left_ids & right_ids)
            pairs.append(
                {
                    "left": left_role,
                    "right": right_role,
                    "shared_events": len(shared),
                    "sample": shared[:10],
                }
            )
    return {"pairs": pairs, "max_shared": max((p["shared_events"] for p in pairs), default=0)}


def maturity_summary(
    cutoff: dt.date,
    *,
    as_of: dt.date,
    source_coverage_end: Optional[dt.date],
) -> dict:
    maturity = label_maturity_date(cutoff)
    return {
        "cutoff": cutoff.isoformat(),
        "horizon_days": HORIZON_DAYS,
        "maturity_lag_days": MATURITY_LAG_DAYS,
        "maturity_span_days": MATURITY_SPAN_DAYS,
        "horizon_end": horizon_end(cutoff).isoformat(),
        "label_maturity_date": maturity.isoformat(),
        "matured_at_as_of": maturity <= as_of,
        "days_until_matured_at_as_of": (maturity - as_of).days,
        "source_covers_maturity": (
            source_coverage_end is not None and maturity <= source_coverage_end
        ),
        "days_until_source_coverage": (
            (maturity - source_coverage_end).days if source_coverage_end else None
        ),
    }
