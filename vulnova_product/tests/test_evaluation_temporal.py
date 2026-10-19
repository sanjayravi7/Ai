"""Maturity boundaries, sequential spacing and the event gate."""

from __future__ import annotations

import datetime as dt

from vulnova.evaluation.constants import (
    HORIZON_DAYS,
    MATURITY_LAG_DAYS,
    MATURITY_SPAN_DAYS,
    REQUIRED_DISTINCT_TEST_EVENTS,
    REQUIRED_SEQUENTIAL_BLOCKS,
)
from vulnova.evaluation.temporal import (
    BLOCK_LABELS_NOT_MATURED,
    EVENT_GATE_NOT_MET,
    INSUFFICIENT_BLOCKS,
    LABEL_STABILITY_NOT_OBSERVABLE,
    LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK,
    BlockSpec,
    DesignSpec,
    evaluate_design,
    horizon_end,
    in_event_window,
    label_maturity_date,
    matches_phase2_3k,
)

D = dt.date


def _events(counts, start=0):
    result = {}
    for index, count in enumerate(counts):
        cutoff = [D(2025, 2, 1), D(2025, 9, 1), D(2026, 4, 1)][index]
        result[cutoff] = {f"CVE-2020-{start + index * 1000 + item}" for item in range(count)}
    return result


def _three_block_design():
    return DesignSpec(
        id="A2_EARLIEST_3BLOCK",
        title="three blocks",
        kind="sequential",
        blocks=(
            BlockSpec("BLOCK1", (D(2025, 2, 1),)),
            BlockSpec("BLOCK2", (D(2025, 9, 1),)),
            BlockSpec("BLOCK3", (D(2026, 4, 1),)),
        ),
    )


def test_frozen_constants_are_the_documented_values():
    assert HORIZON_DAYS == 180
    assert MATURITY_LAG_DAYS == 30
    assert MATURITY_SPAN_DAYS == 210
    assert REQUIRED_DISTINCT_TEST_EVENTS == 30
    assert REQUIRED_SEQUENTIAL_BLOCKS == 3


def test_label_maturity_is_t_plus_210():
    assert label_maturity_date(D(2025, 2, 1)) == D(2025, 8, 30)
    assert label_maturity_date(D(2025, 9, 1)) == D(2026, 3, 30)
    assert label_maturity_date(D(2026, 4, 1)) == D(2026, 10, 28)
    assert horizon_end(D(2025, 2, 1)) == D(2025, 7, 31)


def test_event_window_is_strictly_after_cutoff_and_inclusive_at_horizon():
    cutoff = D(2025, 2, 1)
    assert not in_event_window(cutoff, cutoff)
    assert in_event_window(cutoff, cutoff + dt.timedelta(days=1))
    assert in_event_window(cutoff, cutoff + dt.timedelta(days=180))
    assert not in_event_window(cutoff, cutoff + dt.timedelta(days=181))


def test_maturity_boundary_is_inclusive():
    design = DesignSpec(
        id="ONE",
        title="one",
        kind="sequential",
        blocks=(BlockSpec("TEST", (D(2025, 2, 1),)),),
    )
    events = {D(2025, 2, 1): {f"CVE-2020-{i}" for i in range(30)}}
    on_maturity = evaluate_design(
        design,
        events_by_cutoff=events,
        as_of=D(2025, 8, 30),
        source_coverage_end=D(2025, 8, 30),
    )
    assert on_maturity.blocks[0].matured_at_as_of is True
    assert on_maturity.blocks[0].gate_met is True

    one_day_early = evaluate_design(
        design,
        events_by_cutoff=events,
        as_of=D(2025, 8, 29),
        source_coverage_end=D(2025, 8, 30),
    )
    assert one_day_early.blocks[0].matured_at_as_of is False
    assert one_day_early.blocks[0].gate_met is None
    assert BLOCK_LABELS_NOT_MATURED in one_day_early.blocks[0].reasons
    assert one_day_early.blocks[0].gate_basis == "FLOOR_NOT_A_GATE_RESULT"


def test_event_gate_boundary_is_30_distinct_events():
    design = DesignSpec(
        id="ONE",
        title="one",
        kind="sequential",
        blocks=(BlockSpec("TEST", (D(2025, 2, 1),)),),
    )
    below = {D(2025, 2, 1): {f"CVE-2020-{i}" for i in range(29)}}
    result = evaluate_design(
        design,
        events_by_cutoff=below,
        as_of=D(2026, 1, 1),
        source_coverage_end=D(2026, 1, 1),
    )
    assert result.blocks[0].gate_met is False
    assert EVENT_GATE_NOT_MET in result.reason_codes

    at_gate = {D(2025, 2, 1): {f"CVE-2020-{i}" for i in range(30)}}
    result = evaluate_design(
        design,
        events_by_cutoff=at_gate,
        as_of=D(2026, 1, 1),
        source_coverage_end=D(2026, 1, 1),
    )
    assert result.blocks[0].gate_met is True
    assert EVENT_GATE_NOT_MET not in result.reason_codes


def test_180_day_spacing_fails_sequential_maturity_by_29_days():
    design = DesignSpec(
        id="A_180D",
        title="180d",
        kind="sequential",
        blocks=(
            BlockSpec("SEG1", (D(2025, 2, 1),)),
            BlockSpec("SEG2", (D(2025, 8, 1),)),
            BlockSpec("SEG3", (D(2026, 2, 1),)),
        ),
    )
    events = {
        D(2025, 2, 1): {f"CVE-2020-{i}" for i in range(40)},
        D(2025, 8, 1): {f"CVE-2020-{1000 + i}" for i in range(40)},
        D(2026, 2, 1): {f"CVE-2020-{2000 + i}" for i in range(40)},
    }
    result = evaluate_design(
        design,
        events_by_cutoff=events,
        as_of=D(2026, 10, 15),
        source_coverage_end=D(2026, 10, 15),
    )
    assert result.verdict == "INFEASIBLE"
    assert LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK in result.reason_codes
    assert result.blocks[0].detail.startswith("Labels mature 2025-08-30")
    assert "-29 days short" in result.blocks[0].detail
    assert "-26 days short" in result.blocks[1].detail


def test_210_day_spacing_is_the_earliest_sequential_design():
    design = DesignSpec(
        id="E",
        title="two",
        kind="sequential",
        blocks=(
            BlockSpec("BLOCK1", (D(2025, 2, 1),)),
            BlockSpec("BLOCK2", (D(2025, 9, 1),)),
        ),
    )
    events = {
        D(2025, 2, 1): {f"CVE-2020-{i}" for i in range(40)},
        D(2025, 9, 1): {f"CVE-2020-{1000 + i}" for i in range(40)},
    }
    result = evaluate_design(
        design,
        events_by_cutoff=events,
        as_of=D(2026, 10, 15),
        source_coverage_end=D(2026, 10, 15),
    )
    assert LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK not in result.reason_codes
    assert INSUFFICIENT_BLOCKS in result.reason_codes
    assert result.verdict == "FEASIBLE_BUT_INSUFFICIENT_BLOCKS"
    assert result.protocol_admissible is False


def test_earliest_three_block_design_is_not_admissible_at_reference_date():
    events = _events([40, 40, 40])
    result = evaluate_design(
        _three_block_design(),
        events_by_cutoff=events,
        as_of=D(2026, 10, 15),
        source_coverage_end=D(2026, 10, 15),
    )
    assert result.verdict == "INFEASIBLE"
    assert result.protocol_admissible is False
    assert BLOCK_LABELS_NOT_MATURED in result.reason_codes
    assert LABEL_STABILITY_NOT_OBSERVABLE in result.reason_codes
    assert result.blocks[2].maturity_date == "2026-10-28"


def test_calendar_pass_without_source_coverage_still_blocks_the_final_block():
    events = _events([40, 40, 40])
    result = evaluate_design(
        _three_block_design(),
        events_by_cutoff=events,
        as_of=D(2026, 10, 28),
        source_coverage_end=D(2026, 10, 15),
    )
    assert BLOCK_LABELS_NOT_MATURED not in result.reason_codes
    assert LABEL_STABILITY_NOT_OBSERVABLE in result.reason_codes
    assert result.blocks[2].matured_at_as_of is True
    assert result.blocks[2].label_stability_observable is False
    assert result.blocks[2].gate_met is None


def test_three_block_design_is_admissible_only_when_matured_and_observable():
    events = _events([40, 40, 40])
    result = evaluate_design(
        _three_block_design(),
        events_by_cutoff=events,
        as_of=D(2026, 11, 1),
        source_coverage_end=D(2026, 11, 1),
    )
    assert result.verdict == "FEASIBLE"
    assert result.protocol_admissible is True


def test_phase2_3k_match_uses_reference_date_not_later_as_of():
    events = _events([40, 40, 40])
    reference = DesignSpec(
        id="A2_EARLIEST_3BLOCK",
        title="three",
        kind="sequential",
        blocks=_three_block_design().blocks,
        phase2_3k_verdict="INFEASIBLE_BLOCK_NOT_MATURED",
    )
    at_reference = evaluate_design(
        reference,
        events_by_cutoff=events,
        as_of=D(2026, 10, 15),
        source_coverage_end=D(2026, 10, 15),
    )
    later = evaluate_design(
        reference,
        events_by_cutoff=events,
        as_of=D(2026, 10, 28),
        source_coverage_end=D(2026, 10, 15),
    )
    assert BLOCK_LABELS_NOT_MATURED in at_reference.reason_codes
    assert BLOCK_LABELS_NOT_MATURED not in later.reason_codes
    assert at_reference.matches_phase2_3k is True
    assert matches_phase2_3k(later, at_reference) is True


def test_censored_block_never_reports_a_gate_result():
    design = DesignSpec(
        id="ONE",
        title="one",
        kind="sequential",
        blocks=(BlockSpec("TEST", (D(2026, 4, 1),)),),
    )
    events = {D(2026, 4, 1): {f"CVE-2020-{i}" for i in range(47)}}
    result = evaluate_design(
        design,
        events_by_cutoff=events,
        as_of=D(2026, 10, 15),
        source_coverage_end=D(2026, 10, 15),
    )
    block = result.blocks[0]
    assert block.gate_met is None
    assert block.gate_basis == "FLOOR_NOT_A_GATE_RESULT"
    assert block.distinct_events == 47
