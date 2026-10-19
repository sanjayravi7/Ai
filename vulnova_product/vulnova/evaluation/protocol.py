"""Loading and validating the documented evaluation protocol.

The protocol is a versioned file under ``protocol/``.  It carries an explicit
approval state and an ``adopted_design`` field.  This module can *read* an
approval; it cannot create one.  Nothing here writes to the protocol file.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from . import constants as C
from .temporal import DesignSpec, parse_date

APPROVAL_STATES = (
    "NOT_APPROVED",
    "PENDING_OWNER_APPROVAL",
    "APPROVED",
    "REJECTED",
    "SUPERSEDED",
)

#: Actions that must remain prohibited in every version of this protocol.
REQUIRED_PROHIBITIONS = (
    "model_training",
    "model_tuning",
    "predictive_performance_claims",
    "ranking_weight_changes",
    "source_data_changes",
    "event_gate_relaxation",
    "automatic_protocol_approval",
    "absence_as_non_exploitation",
)

#: Requirement areas that a complete protocol must trace to report checks.
REQUIRED_TRACEABILITY = (
    "dataset_integrity",
    "source_provenance",
    "cutoff_and_maturity",
    "event_gate",
    "point_in_time_features",
    "future_information_leakage",
    "evidence_classification",
    "protocol_approval",
    "reproducibility",
)


class ProtocolError(ValueError):
    """Raised when the protocol file cannot be read as a protocol."""


@dataclass(frozen=True)
class Protocol:
    path: Path
    raw: dict

    @property
    def protocol_id(self) -> str:
        return str(self.raw.get("protocol_id", ""))

    @property
    def version(self) -> str:
        return str(self.raw.get("version", ""))

    @property
    def status(self) -> str:
        return str(self.raw.get("status", ""))

    @property
    def approval(self) -> dict:
        value = self.raw.get("approval", {})
        return value if isinstance(value, dict) else {}

    @property
    def approval_state(self) -> str:
        return str(self.approval.get("state", "MISSING"))

    @property
    def approved(self) -> bool:
        return self.approval_state == "APPROVED"

    @property
    def adopted_design(self) -> Optional[str]:
        value = self.raw.get("adopted_design")
        return str(value) if value else None

    @property
    def reference_date(self) -> dt.date:
        return parse_date(str(self.raw.get("reference_date")))

    @property
    def constants(self) -> dict:
        value = self.raw.get("constants", {})
        return value if isinstance(value, dict) else {}

    @property
    def required_sequential_blocks(self) -> int:
        return int(self.raw.get("required_sequential_blocks", 0))

    @property
    def required_distinct_test_events(self) -> int:
        return int(self.raw.get("required_distinct_test_events", 0))

    @property
    def candidate_designs(self) -> tuple[DesignSpec, ...]:
        return tuple(
            DesignSpec.from_dict(item)
            for item in self.raw.get("candidate_designs", [])
        )

    @property
    def prohibited_actions(self) -> tuple[str, ...]:
        return tuple(str(value) for value in self.raw.get("prohibited_actions", []))

    @property
    def traceability(self) -> dict:
        value = self.raw.get("requirement_traceability", {})
        return value if isinstance(value, dict) else {}


def load_protocol(path: Path | str) -> Protocol:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProtocolError(f"protocol file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"protocol file is not valid JSON: {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ProtocolError(f"protocol file must contain a JSON object: {path}")
    if "protocol_id" not in raw or "version" not in raw:
        raise ProtocolError(f"protocol file lacks protocol_id/version: {path}")
    return Protocol(path=path, raw=raw)


def validate_protocol(protocol: Protocol) -> list[dict]:
    """Return structured problems; an empty list means structurally valid."""
    problems: list[dict] = []

    def add(code: str, detail: str) -> None:
        problems.append({"code": code, "detail": detail})

    if protocol.protocol_id != C.PROTOCOL_ID:
        add(
            "PROTOCOL_ID_MISMATCH",
            f"expected {C.PROTOCOL_ID!r}, found {protocol.protocol_id!r}",
        )
    if protocol.version != "1.6":
        add("PROTOCOL_VERSION_MISMATCH", f"expected version '1.6', found {protocol.version!r}")
    if protocol.approval_state not in APPROVAL_STATES:
        add(
            "APPROVAL_STATE_INVALID",
            f"{protocol.approval_state!r} is not one of {', '.join(APPROVAL_STATES)}",
        )

    constants = protocol.constants
    expected = {
        "horizon_days": C.HORIZON_DAYS,
        "maturity_lag_days": C.MATURITY_LAG_DAYS,
        "maturity_span_days": C.MATURITY_SPAN_DAYS,
        "required_distinct_test_events": C.REQUIRED_DISTINCT_TEST_EVENTS,
        "required_sequential_blocks": C.REQUIRED_SEQUENTIAL_BLOCKS,
    }
    for key, value in expected.items():
        if key not in constants:
            add("PROTOCOL_CONSTANT_MISSING", f"constants.{key} is missing")
        elif int(constants[key]) != value:
            add(
                "PROTOCOL_CONSTANT_MISMATCH",
                f"constants.{key}={constants[key]!r}, frozen value is {value}",
            )

    if protocol.required_sequential_blocks != C.REQUIRED_SEQUENTIAL_BLOCKS:
        add(
            "PROTOCOL_BLOCK_COUNT_MISMATCH",
            f"required_sequential_blocks={protocol.required_sequential_blocks}, "
            f"frozen value is {C.REQUIRED_SEQUENTIAL_BLOCKS}",
        )
    if protocol.required_distinct_test_events < C.REQUIRED_DISTINCT_TEST_EVENTS:
        add(
            "EVENT_GATE_RELAXED",
            f"required_distinct_test_events={protocol.required_distinct_test_events} "
            f"is below the frozen {C.REQUIRED_DISTINCT_TEST_EVENTS}",
        )

    approval = protocol.approval
    if protocol.approved:
        for field in ("approved_by", "approved_on", "approval_reference"):
            if not approval.get(field):
                add(
                    "APPROVAL_EVIDENCE_MISSING",
                    f"state is APPROVED but approval.{field} is empty",
                )
        if not protocol.adopted_design:
            add(
                "APPROVED_WITHOUT_ADOPTED_DESIGN",
                "state is APPROVED but no adopted_design is recorded",
            )
    else:
        if protocol.adopted_design:
            add(
                "UNAPPROVED_DESIGN_ADOPTED",
                f"adopted_design={protocol.adopted_design!r} while approval state is "
                f"{protocol.approval_state!r}",
            )
        for field in ("approved_by", "approved_on", "approval_reference"):
            if approval.get(field):
                add(
                    "APPROVAL_EVIDENCE_INCONSISTENT",
                    f"approval.{field} is set while state is {protocol.approval_state!r}",
                )

    ids = [design.id for design in protocol.candidate_designs]
    if len(ids) != len(set(ids)):
        add("DUPLICATE_DESIGN_ID", "candidate_designs contains duplicate ids")
    for design in protocol.candidate_designs:
        if design.id == protocol.adopted_design:
            continue
        if design.kind not in ("sequential", "rolling_origin", "single_cutoff"):
            add("DESIGN_KIND_UNKNOWN", f"{design.id}: unknown kind {design.kind!r}")
        if not design.blocks:
            add("DESIGN_WITHOUT_BLOCKS", f"{design.id}: no blocks declared")

    required = set(C.EARLIEST_THREE_BLOCK_CUTOFFS)
    earliest = next(
        (design for design in protocol.candidate_designs
         if design.id == C.EARLIEST_THREE_BLOCK_DESIGN_ID),
        None,
    )
    if earliest is None:
        add(
            "EARLIEST_THREE_BLOCK_NOT_REGISTERED",
            f"{C.EARLIEST_THREE_BLOCK_DESIGN_ID} must be registered as a candidate",
        )
    else:
        flat = {cutoff for block in earliest.blocks for cutoff in block.cutoffs}
        if flat != required:
            add(
                "EARLIEST_THREE_BLOCK_CUTOFFS_CHANGED",
                f"expected {sorted(c.isoformat() for c in required)}, "
                f"found {sorted(c.isoformat() for c in flat)}",
            )

    missing_prohibitions = [
        action for action in REQUIRED_PROHIBITIONS
        if action not in protocol.prohibited_actions
    ]
    for action in missing_prohibitions:
        add("PROHIBITION_MISSING", f"prohibited_actions lacks {action!r}")

    trace = protocol.traceability
    for area in REQUIRED_TRACEABILITY:
        if area not in trace:
            add("TRACEABILITY_MISSING", f"requirement_traceability lacks {area!r}")
        elif not trace[area]:
            add("TRACEABILITY_EMPTY", f"requirement_traceability[{area!r}] is empty")

    return problems


def protocol_summary(protocol: Protocol) -> dict:
    """JSON-safe summary carried by the readiness report."""
    return {
        "path": str(protocol.path),
        "protocol_id": protocol.protocol_id,
        "version": protocol.version,
        "status": protocol.status,
        "approval_state": protocol.approval_state,
        "approved": protocol.approved,
        "approval": protocol.approval,
        "adopted_design": protocol.adopted_design,
        "reference_date": protocol.reference_date.isoformat(),
        "required_sequential_blocks": protocol.required_sequential_blocks,
        "required_distinct_test_events": protocol.required_distinct_test_events,
        "constants": protocol.constants,
        "candidate_design_ids": [design.id for design in protocol.candidate_designs],
        "prohibited_actions": list(protocol.prohibited_actions),
        "protocol_approval_granted_by_this_command": False,
    }


def require_reference_date(value: Optional[str], protocol: Protocol) -> dt.date:
    """Resolve the as-of date, defaulting to the protocol reference date."""
    if value is None:
        return protocol.reference_date
    return parse_date(value)


def json_dump(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
