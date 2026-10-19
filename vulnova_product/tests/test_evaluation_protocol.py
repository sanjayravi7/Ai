"""The documented protocol, its approval state and its admission rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.evaluation import constants as C
from vulnova.evaluation.protocol import (
    REQUIRED_PROHIBITIONS,
    REQUIRED_TRACEABILITY,
    ProtocolError,
    load_protocol,
    protocol_summary,
    validate_protocol,
)

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = PRODUCT_ROOT / "protocol" / "evaluation_protocol.json"
PROTOCOL_MARKDOWN = PRODUCT_ROOT / "protocol" / "EVALUATION_PROTOCOL_1.6.md"


def _write_variant(tmp_path: Path, mutate) -> Path:
    payload = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "evaluation_protocol.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _codes(problems: list[dict]) -> set[str]:
    return {problem["code"] for problem in problems}


def test_repository_protocol_is_structurally_valid():
    protocol = load_protocol(PROTOCOL_PATH)
    assert validate_protocol(protocol) == []


def test_protocol_is_a_draft_and_adopts_nothing():
    protocol = load_protocol(PROTOCOL_PATH)
    assert protocol.protocol_id == C.PROTOCOL_ID
    assert protocol.version == "1.6"
    assert protocol.status == "DRAFT_AWAITING_APPROVAL"
    assert protocol.approval_state == "NOT_APPROVED"
    assert protocol.approved is False
    assert protocol.adopted_design is None
    assert protocol.approval["approved_by"] is None
    assert protocol.approval["approved_on"] is None
    assert protocol.approval["approval_reference"] is None


def test_protocol_constants_bind_to_frozen_values():
    protocol = load_protocol(PROTOCOL_PATH)
    assert protocol.constants == {
        "horizon_days": 180,
        "maturity_lag_days": 30,
        "maturity_span_days": 210,
        "required_distinct_test_events": 30,
        "required_sequential_blocks": 3,
    }
    assert protocol.required_distinct_test_events == 30
    assert protocol.required_sequential_blocks == 3


def test_candidates_include_three_and_two_block_designs_but_adopt_neither():
    protocol = load_protocol(PROTOCOL_PATH)
    designs = {design.id: design for design in protocol.candidate_designs}
    assert C.EARLIEST_THREE_BLOCK_DESIGN_ID in designs
    assert C.LARGEST_TWO_BLOCK_DESIGN_ID in designs
    assert len(designs[C.EARLIEST_THREE_BLOCK_DESIGN_ID].blocks) == 3
    assert len(designs[C.LARGEST_TWO_BLOCK_DESIGN_ID].blocks) == 2
    assert all(design.id != protocol.adopted_design for design in protocol.candidate_designs)
    assert all(
        record.get("adoption_status") == "CANDIDATE_NOT_ADOPTED"
        for record in protocol.raw["candidate_designs"]
    )


def test_prohibitions_cover_every_standing_constraint():
    protocol = load_protocol(PROTOCOL_PATH)
    assert set(REQUIRED_PROHIBITIONS) <= set(protocol.prohibited_actions)
    assert "model_training" in protocol.prohibited_actions
    assert "predictive_performance_claims" in protocol.prohibited_actions
    assert "absence_as_non_exploitation" in protocol.prohibited_actions


def test_requirement_traceability_covers_every_readiness_area():
    protocol = load_protocol(PROTOCOL_PATH)
    assert set(REQUIRED_TRACEABILITY) <= set(protocol.traceability)
    for area, check_ids in protocol.traceability.items():
        assert check_ids, f"{area} has no checks"


def test_approval_cannot_be_granted_by_a_tool_or_by_silence():
    protocol = load_protocol(PROTOCOL_PATH)
    summary = protocol_summary(protocol)
    assert summary["approved"] is False
    assert summary["protocol_approval_granted_by_this_command"] is False
    assert protocol.raw["approval"]["required_from"] == "project_owner"
    assert "approval_record_template" in protocol.raw


def test_adopted_design_without_approval_is_rejected(tmp_path):
    path = _write_variant(
        tmp_path,
        lambda payload: payload.__setitem__("adopted_design", "A2_EARLIEST_3BLOCK"),
    )
    problems = validate_protocol(load_protocol(path))
    assert "UNAPPROVED_DESIGN_ADOPTED" in _codes(problems)


def test_approved_state_without_evidence_is_rejected(tmp_path):
    def mutate(payload):
        payload["approval"]["state"] = "APPROVED"

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert "APPROVAL_EVIDENCE_MISSING" in _codes(problems)
    assert "APPROVED_WITHOUT_ADOPTED_DESIGN" in _codes(problems)


def test_relaxing_the_event_gate_is_rejected(tmp_path):
    def mutate(payload):
        payload["required_distinct_test_events"] = 20
        payload["constants"]["required_distinct_test_events"] = 20

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert "EVENT_GATE_RELAXED" in _codes(problems)
    assert "PROTOCOL_CONSTANT_MISMATCH" in _codes(problems)


def test_changing_the_earliest_three_block_cutoffs_is_rejected(tmp_path):
    def mutate(payload):
        for design in payload["candidate_designs"]:
            if design["id"] == C.EARLIEST_THREE_BLOCK_DESIGN_ID:
                design["blocks"][1]["cutoffs"] = ["2025-08-01"]

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert "EARLIEST_THREE_BLOCK_CUTOFFS_CHANGED" in _codes(problems)


def test_unknown_approval_state_is_rejected(tmp_path):
    path = _write_variant(
        tmp_path, lambda payload: payload["approval"].__setitem__("state", "MAYBE")
    )
    problems = validate_protocol(load_protocol(path))
    assert "APPROVAL_STATE_INVALID" in _codes(problems)


def test_malformed_protocol_raises_protocol_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProtocolError, match="not valid JSON"):
        load_protocol(path)
    with pytest.raises(ProtocolError, match="not found"):
        load_protocol(tmp_path / "absent.json")


def test_protocol_markdown_states_the_approval_and_the_rules():
    text = PROTOCOL_MARKDOWN.read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "**Approval state:** `NOT_APPROVED`" in text
    assert "**Adopted design:** **none**" in text
    assert "not adopt a two-block or three-block design" in flat
    assert "**180 days**" in text
    assert "**30 days**" in text
    assert "**210 days**" in text
    assert "Absence is not proof of non-exploitation" in flat
    assert "Missing is not absence" in flat
    assert "Never relaxed" in flat


def _approve(payload, *, design="A2_EARLIEST_3BLOCK", approved_on="2026-10-14"):
    """Turn a payload into a valid approval of a registered design."""
    payload["approval"]["state"] = "APPROVED"
    payload["approval"]["approved_by"] = "Project Owner"
    payload["approval"]["approved_on"] = approved_on
    payload["approval"]["approval_reference"] = "DECISION-2026-01"
    payload["adopted_design"] = design


def _candidate(payload, design_id):
    return next(
        design for design in payload["candidate_designs"] if design["id"] == design_id
    )


def test_adopted_design_with_unknown_kind_is_rejected(tmp_path):
    def mutate(payload):
        _approve(payload)
        _candidate(payload, "A2_EARLIEST_3BLOCK")["kind"] = "sneaky_kind"

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert "DESIGN_KIND_UNKNOWN" in _codes(problems)
    detail = next(
        problem["detail"] for problem in problems if problem["code"] == "DESIGN_KIND_UNKNOWN"
    )
    assert "A2_EARLIEST_3BLOCK" in detail
    assert "sneaky_kind" in detail


def test_adopted_design_without_blocks_is_rejected(tmp_path):
    def mutate(payload):
        _approve(payload)
        _candidate(payload, "A2_EARLIEST_3BLOCK")["blocks"] = []

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert "DESIGN_WITHOUT_BLOCKS" in _codes(problems)


def test_approved_protocol_referencing_nonexistent_design_is_rejected(tmp_path):
    def mutate(payload):
        _approve(payload, design="Z_DOES_NOT_EXIST")

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert _codes(problems) == {"ADOPTED_DESIGN_NOT_REGISTERED"}
    assert "Z_DOES_NOT_EXIST" in problems[0]["detail"]


@pytest.mark.parametrize(
    "approved_on",
    [
        "15-10-2026",
        "2026-13-01",
        "2026-1-5",
        "20261015",
        "2026-W42-1",
        "2026-10-32",
        "not-a-date",
        " 2026-10-14",
        "2026-10-14T00:00:00+00:00",
    ],
)
def test_invalid_approval_date_is_rejected(tmp_path, approved_on):
    def mutate(payload):
        _approve(payload, approved_on=approved_on)

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    assert _codes(problems) == {"APPROVAL_DATE_INVALID"}
    assert repr(approved_on) in problems[0]["detail"]


@pytest.mark.parametrize("approved_on", ["2026-10-14", "2024-02-29"])
def test_valid_approved_protocol_with_registered_design_is_valid(tmp_path, approved_on):
    def mutate(payload):
        _approve(payload, approved_on=approved_on)

    protocol = load_protocol(_write_variant(tmp_path, mutate))
    assert protocol.approved is True
    assert protocol.adopted_design == "A2_EARLIEST_3BLOCK"
    assert validate_protocol(protocol) == []


def test_adopted_design_is_validated_even_when_another_design_is_broken(tmp_path):
    def mutate(payload):
        _approve(payload)
        _candidate(payload, "A2_EARLIEST_3BLOCK")["kind"] = "made_up"
        _candidate(payload, "E_LABEL_MATURED_2BLOCK")["kind"] = "also_made_up"

    problems = validate_protocol(load_protocol(_write_variant(tmp_path, mutate)))
    details = [
        problem["detail"]
        for problem in problems
        if problem["code"] == "DESIGN_KIND_UNKNOWN"
    ]
    assert any("A2_EARLIEST_3BLOCK" in detail for detail in details)
    assert any("E_LABEL_MATURED_2BLOCK" in detail for detail in details)
