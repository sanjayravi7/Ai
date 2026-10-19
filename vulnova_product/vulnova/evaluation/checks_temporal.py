"""Temporal and event checks (TMP-*, EVT-*)."""

from __future__ import annotations

import datetime as dt
import re

from . import constants as C
from .checks_base import Check, CheckContext, blocked, failed, not_applicable, passed
from .datasets import integers
from .temporal import (
    DesignEvaluation,
    event_set_overlaps,
    horizon_end,
    in_event_window,
    label_maturity_date,
    maturity_summary,
    parse_date,
    validate_event_windows,
)

_SHARE_PATTERN = re.compile(r"\('([^']+)', '([^']+)'\)=(\d+)")


def _matured_cutoffs(ctx: CheckContext) -> list[dt.date]:
    return [
        cutoff
        for cutoff in ctx.dataset.cutoffs
        if label_maturity_date(cutoff) <= ctx.reference_date
    ]


def _event_sets_for_design(
    design: DesignEvaluation, events_by_cutoff: dict[dt.date, set[str]]
) -> list[tuple[str, set[str]]]:
    result = []
    for block in design.blocks:
        ids: set[str] = set()
        for cutoff_text in block.cutoffs:
            ids.update(events_by_cutoff.get(parse_date(cutoff_text), set()))
        result.append((block.role, ids))
    return result


def check_frozen_constants(ctx: CheckContext) -> Check:
    check_id = "TMP-01_frozen_constants"
    title = "Horizon, maturation lag and event gate are the frozen values"
    quality = ctx.dataset.quality_summary
    constants = quality.get("constants_preserved", {})
    reasons = []
    if not constants:
        return blocked(check_id, title, reasons=["Quality summary lacks constants_preserved."])
    quality_expected = {
        "horizon_days": C.HORIZON_DAYS,
        "maturity_lag_days": C.MATURITY_LAG_DAYS,
        "maturity_offset_days": C.MATURITY_SPAN_DAYS,
        "test_event_gate": C.REQUIRED_DISTINCT_TEST_EVENTS,
        "cutoff_count": len(ctx.dataset.cutoffs),
    }
    for key, value in quality_expected.items():
        if integers(constants, key) != value:
            reasons.append(f"quality_summary.constants_preserved.{key} is not {value}")
    if constants.get("changed_from_prior_phases") is not False:
        reasons.append("quality summary does not assert unchanged constants")
    protocol_constants = ctx.protocol.constants
    protocol_expected = {
        "horizon_days": C.HORIZON_DAYS,
        "maturity_lag_days": C.MATURITY_LAG_DAYS,
        "maturity_span_days": C.MATURITY_SPAN_DAYS,
        "required_distinct_test_events": C.REQUIRED_DISTINCT_TEST_EVENTS,
        "required_sequential_blocks": C.REQUIRED_SEQUENTIAL_BLOCKS,
    }
    for key, value in protocol_expected.items():
        if integers(protocol_constants, key) != value:
            reasons.append(f"protocol.constants.{key} is not {value}")
    split_gates = {
        integers(row, "gate_required")
        for row in ctx.dataset.splits
        if integers(row, "gate_required") is not None
    }
    if split_gates and split_gates != {C.REQUIRED_DISTINCT_TEST_EVENTS}:
        reasons.append(f"temporal_split_feasibility gate_required values: {sorted(split_gates)}")
    evidence = {
        "code_constants": {
            "horizon_days": C.HORIZON_DAYS,
            "maturity_lag_days": C.MATURITY_LAG_DAYS,
            "maturity_span_days": C.MATURITY_SPAN_DAYS,
            "required_distinct_test_events": C.REQUIRED_DISTINCT_TEST_EVENTS,
            "required_sequential_blocks": C.REQUIRED_SEQUENTIAL_BLOCKS,
        },
        "quality_constants": constants,
        "protocol_constants": protocol_constants,
        "quality_expected": quality_expected,
        "protocol_expected": protocol_expected,
        "split_gate_values": sorted(split_gates),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=["180-day horizon, 30-day lag, 210-day span and 30-event gate agree "
                 "across code, protocol and Phase 2.3K artifacts."],
        evidence=evidence,
    )


def check_maturity_dates(ctx: CheckContext) -> Check:
    check_id = "TMP-02_maturity_dates_recomputed"
    title = "Every recorded maturation date is recomputed from T + 180 + 30"
    denominators = ctx.dataset.denominator_by_cutoff
    outcomes = ctx.dataset.outcome_by_cutoff
    if not denominators:
        return blocked(check_id, title, reasons=["Denominator summary is unavailable."])
    reasons = []
    rows = []
    matured_at_reference = 0
    matured_at_as_of = 0
    for cutoff in ctx.dataset.cutoffs:
        text = cutoff.isoformat()
        row = denominators.get(text, {})
        expected_maturity = label_maturity_date(cutoff)
        recorded = row.get("maturity_date")
        if recorded != expected_maturity.isoformat():
            reasons.append(
                f"{text}: recorded maturity {recorded!r} != {expected_maturity.isoformat()}"
            )
        recorded_matured = row.get("matured")
        recomputed_reference = expected_maturity <= ctx.reference_date
        if (recorded_matured == "YES") != recomputed_reference:
            reasons.append(f"{text}: recorded matured flag disagrees with the reference date")
        outcome = outcomes.get(text, {})
        if outcome and (outcome.get("matured") == "YES") != (recorded_matured == "YES"):
            reasons.append(f"{text}: outcome and denominator mature flags disagree")
        if recomputed_reference:
            matured_at_reference += 1
        is_matured_as_of = expected_maturity <= ctx.as_of
        if is_matured_as_of:
            matured_at_as_of += 1
        rows.append(
            {
                "cutoff": text,
                **maturity_summary(
                    cutoff, as_of=ctx.as_of, source_coverage_end=ctx.source_coverage_end
                ),
                "recorded_maturity_date": recorded,
                "recorded_matured": recorded_matured,
            }
        )
    facts = ctx.dataset.facts
    if integers(facts, "matured_cutoffs") != matured_at_reference:
        reasons.append("facts.matured_cutoffs differs from the recomputed count")
    evidence = {
        "reference_date": ctx.reference_date.isoformat(),
        "as_of": ctx.as_of.isoformat(),
        "matured_at_reference_date": matured_at_reference,
        "matured_at_as_of": matured_at_as_of,
        "per_cutoff": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)}/{len(rows)} maturity dates recompute exactly; "
            f"{matured_at_reference} are matured "
            f"at the {ctx.reference_date} reference date and {matured_at_as_of} at the "
            f"{ctx.as_of} as-of date."
        ],
        evidence=evidence,
    )


def check_candidate_design_sequence(ctx: CheckContext) -> Check:
    check_id = "TMP-03_candidate_design_sequence"
    title = "Each protocol candidate design recomputes to the Phase 2.3K verdict"
    if not ctx.designs:
        return blocked(check_id, title, reasons=["No candidate designs could be evaluated."])
    reasons = []
    mismatched = []
    for design in ctx.designs:
        if design.matches_phase2_3k is False:
            mismatched.append(design.id)
            reasons.append(
                f"{design.id}: recomputed {design.verdict} / {design.reason_codes}, "
                f"but Phase 2.3K recorded {design.phase2_3k_verdict}"
            )
    comparable = [design for design in ctx.designs if design.phase2_3k_verdict]
    evidence = {
        "designs_evaluated": len(ctx.designs),
        "designs_with_recorded_verdict": len(comparable),
        "designs_matching_phase2_3k": sum(
            1 for design in ctx.designs if design.matches_phase2_3k is True
        ),
        "designs_not_comparable": [
            design.id for design in ctx.designs if design.matches_phase2_3k is None
        ],
        "mismatched_design_ids": mismatched,
        "designs": [design.as_dict() for design in ctx.designs],
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    if not comparable:
        return not_applicable(
            check_id,
            title,
            reasons=[
                "No candidate design carries a recorded Phase 2.3K verdict, so there is "
                "nothing historical to reproduce; the recomputed verdicts are reported "
                "on their own."
            ],
            evidence=evidence,
        )
    summary = "; ".join(f"{design.id}: {design.verdict}" for design in ctx.designs)
    return passed(
        check_id,
        title,
        reasons=[
            f"All {len(ctx.designs)} registered candidate designs recompute consistently "
            f"({summary}); no design is adopted."
        ],
        evidence=evidence,
    )


def check_earliest_three_block_design(ctx: CheckContext) -> Check:
    check_id = "TMP-04_earliest_three_block_design"
    expected_final = label_maturity_date(max(C.EARLIEST_THREE_BLOCK_CUTOFFS))
    title = (
        f"The earliest three-block design matures {expected_final.isoformat()} and is "
        "not adopted"
    )
    design = ctx.design_by_id.get(C.EARLIEST_THREE_BLOCK_DESIGN_ID)
    if design is None:
        return failed(
            check_id,
            title,
            reasons=[
                f"{C.EARLIEST_THREE_BLOCK_DESIGN_ID} is not registered in the protocol."
            ],
        )
    cutoffs = [parse_date(cutoff) for block in design.blocks for cutoff in block.cutoffs]
    expected = list(C.EARLIEST_THREE_BLOCK_CUTOFFS)
    reasons = []
    if sorted(cutoffs) != sorted(expected):
        reasons.append(
            f"registered cutoffs {[c.isoformat() for c in cutoffs]} differ from the "
            f"Phase 2.3K design {[c.isoformat() for c in expected]}"
        )
    final_cutoff = max(cutoffs) if cutoffs else None
    final_maturity = label_maturity_date(final_cutoff) if final_cutoff else None
    days_beyond_reference = (
        (final_maturity - ctx.reference_date).days if final_maturity else None
    )
    if final_maturity != dt.date(2026, 10, 28):
        reasons.append(f"final maturity is {final_maturity}, Phase 2.3K recorded 2026-10-28")
    if ctx.reference_date == dt.date(2026, 10, 15) and days_beyond_reference != 13:
        reasons.append(
            f"final maturity is {days_beyond_reference} days beyond the 2026-10-15 "
            "reference date; Phase 2.3K recorded 13"
        )
    adopted = ctx.protocol.adopted_design
    if adopted == design.id and not ctx.protocol.approved:
        reasons.append(
            "the earliest three-block design is marked adopted while the protocol is "
            "not approved"
        )
    evidence = {
        "design_id": design.id,
        "cutoffs": [cutoff.isoformat() for cutoff in sorted(cutoffs)],
        "block_maturity_dates": [block.maturity_date for block in design.blocks],
        "final_block_label_maturity": final_maturity.isoformat() if final_maturity else None,
        "reference_date": ctx.reference_date.isoformat(),
        "days_beyond_reference_date": days_beyond_reference,
        "matured_at_as_of": bool(
            final_maturity is not None and final_maturity <= ctx.as_of
        ),
        "days_until_matured_at_as_of": (
            (final_maturity - ctx.as_of).days if final_maturity else None
        ),
        "source_timeline_end": (
            ctx.source_coverage_end.isoformat() if ctx.source_coverage_end else None
        ),
        "source_timeline_covers_final_maturity": bool(
            final_maturity is not None
            and ctx.source_coverage_end is not None
            and final_maturity <= ctx.source_coverage_end
        ),
        "adopted_design": adopted,
        "adoption_status": (
            "ADOPTED_UNDER_APPROVAL"
            if adopted == design.id and ctx.protocol.approved
            else "CANDIDATE_NOT_ADOPTED"
        ),
        "requires_explicit_protocol_approval": True,
        "recomputed_verdict": design.verdict,
        "recomputed_reason_codes": design.reason_codes,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The earliest three-block design is "
            + " / ".join(cutoff.isoformat() for cutoff in sorted(cutoffs))
            + f". Its final labels mature {final_maturity.isoformat()}, "
            f"{days_beyond_reference} days after the reference date "
            f"{ctx.reference_date.isoformat()}, and the served KEV timeline ends "
            f"{ctx.source_coverage_end}. It remains a candidate; adoption requires "
            "explicit protocol approval."
        ],
        evidence=evidence,
    )


def check_two_block_design(ctx: CheckContext) -> Check:
    check_id = "TMP-05_two_block_design_not_adopted"
    title = "The two-block design is reported as insufficient, never adopted silently"
    design = ctx.design_by_id.get(C.LARGEST_TWO_BLOCK_DESIGN_ID)
    if design is None:
        return failed(
            check_id,
            title,
            reasons=[f"{C.LARGEST_TWO_BLOCK_DESIGN_ID} is not registered."],
        )
    reasons = []
    if len(design.blocks) >= C.REQUIRED_SEQUENTIAL_BLOCKS:
        reasons.append("the two-block design unexpectedly has enough blocks")
    if design.protocol_admissible:
        reasons.append("the two-block design is marked protocol-admissible")
    adopted = ctx.protocol.adopted_design
    if adopted == design.id and not ctx.protocol.approved:
        reasons.append("the two-block design is marked adopted without approval")
    recorded = {
        row.get("block"): integers(row, "distinct_events")
        for row in ctx.dataset.splits
        if row.get("split_id") == C.LARGEST_TWO_BLOCK_DESIGN_ID
    }
    by_role = {block.role: block.distinct_events for block in design.blocks}
    for role, events in by_role.items():
        if recorded.get(role) is not None and recorded[role] != events:
            reasons.append(
                f"{role}: recomputed {events} events but Phase 2.3K recorded {recorded[role]}"
            )
    evidence = {
        "design_id": design.id,
        "block_count": len(design.blocks),
        "required_block_count": C.REQUIRED_SEQUENTIAL_BLOCKS,
        "distinct_events_by_block": by_role,
        "recorded_events_by_block": recorded,
        "gate_met_by_block": {block.role: block.gate_met for block in design.blocks},
        "protocol_admissible": design.protocol_admissible,
        "adopted_design": adopted,
        "verdict": design.verdict,
        "interpretation": (
            "Constructible today as a technical two-block train/test design, but it has "
            "no separate validation block and does not satisfy the three-block protocol."
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The two-block design ("
            + " / ".join(
                f"{', '.join(block.cutoffs)} [{block.distinct_events} events]"
                for block in design.blocks
            )
            + f") is {design.verdict}; two blocks are insufficient for the "
            "three-block protocol. No substitution is made."
        ],
        evidence=evidence,
    )


def check_gate_not_relaxed(ctx: CheckContext) -> Check:
    check_id = "TMP-06_event_gate_not_relaxed"
    title = "The 30-distinct-event gate is unchanged everywhere it appears"
    reasons = []
    observed = {}
    observed["code"] = C.REQUIRED_DISTINCT_TEST_EVENTS
    observed["protocol"] = ctx.protocol.required_distinct_test_events
    observed["protocol_constants"] = integers(ctx.protocol.constants, "required_distinct_test_events")
    observed["quality_summary"] = integers(
        ctx.dataset.quality_summary.get("constants_preserved", {}), "test_event_gate"
    )
    for name, value in observed.items():
        if value != C.REQUIRED_DISTINCT_TEST_EVENTS:
            reasons.append(f"{name}: {value!r} != {C.REQUIRED_DISTINCT_TEST_EVENTS}")
    split_values = sorted(
        {
            integers(row, "gate_required")
            for row in ctx.dataset.splits
            if integers(row, "gate_required") is not None
        }
    )
    if split_values and split_values != [C.REQUIRED_DISTINCT_TEST_EVENTS]:
        reasons.append(f"temporal split rows require {split_values}")
    block_gates = [
        {
            "design": design.id,
            "role": block.role,
            "required": C.REQUIRED_DISTINCT_TEST_EVENTS,
            "distinct_events": block.distinct_events,
            "gate_met": block.gate_met,
        }
        for design in ctx.designs
        for block in design.blocks
    ]
    if any(block["required"] != C.REQUIRED_DISTINCT_TEST_EVENTS for block in block_gates):
        reasons.append("a computed block gate differs from 30")
    evidence = {
        "observed_gate_values": observed,
        "split_gate_values": split_values,
        "block_gate_evaluations": block_gates,
        "gate_relaxation_applied": False,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=["No artifact, protocol field or computed block lowers the gate below 30."],
        evidence=evidence,
    )


def check_label_window_observability(ctx: CheckContext) -> Check:
    check_id = "TMP-07_label_window_observability"
    title = "Matured blocks are covered by the served KEV timeline"
    if ctx.source_coverage_end is None:
        return blocked(check_id, title, reasons=["KEV timeline end is unavailable."])
    reasons = []
    rows = []
    matured = 0
    matured_observable = 0
    for cutoff in ctx.dataset.cutoffs:
        maturity = label_maturity_date(cutoff)
        end = horizon_end(cutoff)
        is_matured = maturity <= ctx.reference_date
        observable = maturity <= ctx.source_coverage_end
        if is_matured:
            matured += 1
            if observable:
                matured_observable += 1
            else:
                reasons.append(
                    f"{cutoff}: matured but the source timeline ends "
                    f"{ctx.source_coverage_end} before {maturity}"
                )
        rows.append(
            {
                "cutoff": cutoff.isoformat(),
                "horizon_end": end.isoformat(),
                "maturity_date": maturity.isoformat(),
                "matured_at_reference": is_matured,
                "source_covers_horizon": end <= ctx.source_coverage_end,
                "source_covers_maturity": observable,
            }
        )
    evidence = {
        "source_timeline_end": ctx.source_coverage_end.isoformat(),
        "reference_date": ctx.reference_date.isoformat(),
        "matured_cutoffs": matured,
        "matured_cutoffs_observable": matured_observable,
        "per_cutoff": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{matured_observable}/{matured} matured cutoffs have their full 210-day "
            f"label window inside the served timeline (ends {ctx.source_coverage_end})."
        ],
        evidence=evidence,
    )


def check_distinct_event_gate(ctx: CheckContext) -> Check:
    check_id = "EVT-01_distinct_event_gate"
    title = "Every matured cutoff clears 30 distinct events; censored cutoffs are floors"
    denominators = ctx.dataset.denominator_by_cutoff
    reasons = []
    rows = []
    matured_checked = 0
    matured_passed = 0
    censored = 0
    minimum = None
    for row in sorted(ctx.dataset.outcomes, key=lambda item: item.get("cutoff_T", "")):
        cutoff_text = row.get("cutoff_T", "")
        denominator = denominators.get(cutoff_text, {})
        try:
            cutoff = parse_date(cutoff_text)
        except ValueError:
            reasons.append(f"{cutoff_text}: invalid cutoff")
            continue
        ids = {item for item in row.get("event_ids", "").split(";") if item}
        declared = integers(row, "eligible_events")
        recorded_gate = row.get("gate_met")
        is_matured = denominator.get("matured") == "YES"
        if declared is not None and declared != len(ids):
            reasons.append(f"{cutoff_text}: eligible_events does not equal distinct ids")
        if is_matured:
            matured_checked += 1
            minimum = len(ids) if minimum is None else min(minimum, len(ids))
            if len(ids) < C.REQUIRED_DISTINCT_TEST_EVENTS:
                reasons.append(
                    f"{cutoff_text}: {len(ids)} distinct events is below "
                    f"{C.REQUIRED_DISTINCT_TEST_EVENTS}"
                )
            elif recorded_gate != "YES":
                reasons.append(f"{cutoff_text}: gate should be met but is recorded {recorded_gate}")
            else:
                matured_passed += 1
        else:
            censored += 1
            if recorded_gate not in ("NO", ""):
                reasons.append(f"{cutoff_text}: censored cutoff is recorded as gate-passing")
        rows.append(
            {
                "cutoff": cutoff_text,
                "matured": is_matured,
                "distinct_events": len(ids),
                "declared_events": declared,
                "gate_met": recorded_gate,
                "gate_basis": "DISTINCT_EVENTS" if is_matured else "FLOOR_NOT_A_GATE_RESULT",
                "horizon_end": horizon_end(cutoff).isoformat(),
            }
        )
    blocks = [
        {
            "design": design.id,
            "role": block.role,
            "cutoffs": block.cutoffs,
            "distinct_events": block.distinct_events,
            "gate_met": block.gate_met,
            "gate_basis": block.gate_basis,
        }
        for design in ctx.designs
        for block in design.blocks
    ]
    evidence = {
        "matured_cutoffs_checked": matured_checked,
        "matured_cutoffs_passing": matured_passed,
        "censored_cutoffs": censored,
        "minimum_matured_distinct_events": minimum,
        "gate_required": C.REQUIRED_DISTINCT_TEST_EVENTS,
        "per_cutoff": rows,
        "block_gate_evaluations": blocks,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{matured_passed}/{matured_checked} matured cutoffs clear the gate "
            f"(minimum {minimum}); the {censored} censored cutoffs are reported as floors, "
            "never as gate results."
        ],
        evidence=evidence,
    )


def check_event_row_uniqueness(ctx: CheckContext) -> Check:
    check_id = "EVT-02_event_row_uniqueness"
    title = "Event rows are unique per cutoff; cross-cutoff reuse is measured separately"
    reasons = list(
        f"{problem.get('cutoff')}: {problem.get('problem')}" for problem in ctx.event_problems
    )
    rows = []
    seen_pairs: set[tuple[str, str]] = set()
    duplicate_pairs = 0
    total_rows = 0
    all_ids: set[str] = set()
    matured_ids: set[str] = set()
    matured_rows = 0
    for row in sorted(ctx.dataset.outcomes, key=lambda item: item.get("cutoff_T", "")):
        cutoff_text = row.get("cutoff_T", "")
        ids = [item for item in row.get("event_ids", "").split(";") if item]
        for cve_id in ids:
            total_rows += 1
            all_ids.add(cve_id)
            pair = (cutoff_text, cve_id)
            if pair in seen_pairs:
                duplicate_pairs += 1
            seen_pairs.add(pair)
            if row.get("matured") == "YES":
                matured_rows += 1
                matured_ids.add(cve_id)
        rows.append(
            {
                "cutoff": cutoff_text,
                "matured": row.get("matured"),
                "event_rows": len(ids),
                "distinct_events": len(set(ids)),
                "duplicate_rows_in_cutoff": len(ids) - len(set(ids)),
            }
        )
    if duplicate_pairs:
        reasons.append(f"{duplicate_pairs} duplicate (cutoff, CVE) event rows")
    first_seen = ctx.dataset.kev_first_seen_rows
    first_seen_ids = [row.get("cve_id") for row in first_seen]
    if len(first_seen_ids) != len(set(first_seen_ids)):
        reasons.append("kev_first_seen.jsonl.gz has duplicate CVE rows")
    facts = ctx.dataset.facts
    checks = {
        "distinct_events_all_cutoffs": len(all_ids),
        "distinct_events_all_matured": len(matured_ids),
        "all_matured_rows": matured_rows,
    }
    for key, observed in checks.items():
        if integers(facts, key) is not None and integers(facts, key) != observed:
            reasons.append(f"facts.{key}={facts.get(key)} != recomputed {observed}")
    reuse = (matured_rows / len(matured_ids)) if matured_ids else None
    recorded_reuse = (
        (ctx.dataset.quality_summary.get("outcome_reconciliation") or {}).get("reuse_factor")
    )
    if reuse is not None and recorded_reuse is not None:
        if abs(float(recorded_reuse) - reuse) > 0.01:
            reasons.append(
                f"recorded reuse factor {recorded_reuse} != recomputed {reuse:.2f}"
            )
    evidence = {
        "event_rows_all_cutoffs": total_rows,
        "distinct_events_all_cutoffs": len(all_ids),
        "cross_cutoff_repeat_rows": total_rows - len(all_ids),
        "matured_event_rows": matured_rows,
        "distinct_matured_events": len(matured_ids),
        "reuse_factor_rows_per_distinct_event": round(reuse, 2) if reuse else None,
        "duplicate_cutoff_cve_pairs": duplicate_pairs,
        "first_seen_rows": len(first_seen),
        "first_seen_distinct": len(set(first_seen_ids)),
        "per_cutoff": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{total_rows} event rows contain no duplicate (cutoff, CVE) pair. "
            f"Cross-cutoff reuse is real and reported separately: {matured_rows} matured "
            f"rows cover {len(matured_ids)} distinct events ({reuse:.2f} rows/event). "
            "Reuse is not counted as independent evidence."
        ],
        evidence=evidence,
    )


def check_event_window_boundaries(ctx: CheckContext) -> Check:
    check_id = "EVT-03_event_window_boundaries"
    title = "Every event is first observed strictly after T and within 180 days"
    first_seen = ctx.dataset.first_seen_day
    violations = validate_event_windows(ctx.events_by_cutoff, first_seen)
    reasons = [
        f"{item['cutoff']}: {item['cve_id']} {item['reason']}" for item in violations[:20]
    ]
    publication_mismatches = []
    for row in ctx.dataset.outcomes:
        if row.get("publication_rule_satisfied") != row.get("eligible_events"):
            publication_mismatches.append(row.get("cutoff_T"))
    if publication_mismatches:
        reasons.append(
            "publication_rule_satisfied differs from eligible_events at "
            + ", ".join(str(item) for item in publication_mismatches[:5])
        )
    within_horizon = 0
    for cutoff, ids in ctx.events_by_cutoff.items():
        for cve_id in ids:
            observed = first_seen.get(cve_id)
            if observed and in_event_window(cutoff, observed):
                within_horizon += 1
    evidence = {
        "event_rows_checked": sum(len(ids) for ids in ctx.events_by_cutoff.values()),
        "rows_inside_window": within_horizon,
        "violations": violations[:100],
        "violation_count": len(violations),
        "first_seen_evidence": "raw/kev_first_seen.jsonl.gz",
        "observation_semantics": (
            "first observed KEV catalog inclusion, not the CVE record's dateAdded"
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"All {within_horizon} event rows fall in (T, T+180d]; no event precedes its "
            "cutoff and none exceeds the horizon."
        ],
        evidence=evidence,
    )


def check_event_membership_at_cutoff(ctx: CheckContext) -> Check:
    check_id = "EVT-04_event_membership_at_cutoff"
    title = "Every event was eligible at risk at its cutoff, not already in KEV"
    if not ctx.deep_requested:
        return blocked(
            check_id,
            title,
            reasons=["Deep scan disabled; event membership at T was not verified."],
        )
    if not ctx.scans:
        return blocked(
            check_id,
            title,
            reasons=["Membership partitions unavailable; event membership at T is unverified."],
        )
    reasons = []
    missing = []
    wrong_reason = []
    checked = 0
    already_in_kev = []
    unreadable = []
    for cutoff, ids in sorted(ctx.events_by_cutoff.items()):
        text = cutoff.isoformat()
        scan = ctx.scans.get(text)
        if scan is None:
            reasons.append(f"{text}: no membership partition")
            continue
        if scan.error or scan.partition_bytes is None:
            unreadable.append(
                {"cutoff": text, "problem": scan.error or "partition missing"}
            )
            continue
        for cve_id in sorted(ids):
            checked += 1
            reason = scan.event_reasons.get(cve_id)
            if reason is None:
                missing.append({"cutoff": text, "cve_id": cve_id})
            elif reason == "EXCLUDED_ALREADY_IN_KEV_AT_T":
                already_in_kev.append({"cutoff": text, "cve_id": cve_id})
            elif reason != "ELIGIBLE_AT_RISK":
                wrong_reason.append({"cutoff": text, "cve_id": cve_id, "reason": reason})
    if missing:
        reasons.append(
            f"{len(missing)} event(s) are absent from the risk-set partition at their cutoff"
        )
    if already_in_kev:
        reasons.append(
            f"{len(already_in_kev)} event(s) were already in KEV at their cutoff "
            "(future-information leakage)"
        )
    if wrong_reason:
        reasons.append(f"{len(wrong_reason)} event(s) carry a non-eligible reason code")
    evidence = {
        "event_rows_checked": checked,
        "missing_events": missing[:20],
        "already_in_kev_at_cutoff": already_in_kev[:20],
        "wrong_reason": wrong_reason[:20],
        "unreadable_partitions": unreadable,
        "membership_counts": {
            text: len(scan.event_reasons) for text, scan in sorted(ctx.scans.items())
        },
    }
    if reasons or missing or already_in_kev or wrong_reason:
        if reasons:
            pass
        if missing:
            reasons.append(
                f"{len(missing)} event(s) are absent from the risk-set partition at their cutoff"
            )
        if already_in_kev:
            reasons.append(
                f"{len(already_in_kev)} event(s) were already in KEV at their cutoff "
                "(future-information leakage)"
            )
        if wrong_reason:
            reasons.append(f"{len(wrong_reason)} event(s) carry a non-eligible reason code")
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    if unreadable:
        return blocked(
            check_id,
            title,
            reasons=[
                f"{len(unreadable)} membership partition(s) could not be read, so event "
                "membership is unverified (not treated as absence): "
                + ", ".join(item["cutoff"] for item in unreadable[:8])
            ],
            evidence=evidence,
        )
    return passed(
        check_id,
        title,
        reasons=[
            f"All {checked} event rows are present in their cutoff's partition with "
            "reason ELIGIBLE_AT_RISK; none was already in KEV at T."
        ],
        evidence=evidence,
    )


def _computed_overlaps(ctx: CheckContext) -> dict[str, dict]:
    result = {}
    for design in ctx.designs:
        if not design.blocks:
            continue
        sets = _event_sets_for_design(design, ctx.events_by_cutoff)
        result[design.id] = event_set_overlaps(sets)
    return result


def check_event_reuse(ctx: CheckContext) -> Check:
    check_id = "EVT-05_event_reuse_and_independence"
    title = "Event reuse is measured, and claimed overlaps recompute exactly"
    overlaps = _computed_overlaps(ctx)
    reasons = []
    recorded_rows = ctx.dataset.splits
    recorded_overlaps: dict[str, dict[tuple[str, str], int]] = {}
    for row in recorded_rows:
        split_id = row.get("split_id", "")
        for left, right, count in _SHARE_PATTERN.findall(row.get("shares_events_with", "")):
            key = tuple(sorted((left, right)))
            recorded_overlaps.setdefault(split_id, {})[key] = int(count)
    mismatches = []
    for split_id, pairs in recorded_overlaps.items():
        if split_id not in overlaps:
            continue
        computed = {
            tuple(sorted((pair["left"], pair["right"]))): pair["shared_events"]
            for pair in overlaps[split_id]["pairs"]
        }
        for key, value in pairs.items():
            if computed.get(key) != value:
                mismatches.append(
                    {
                        "split_id": split_id,
                        "pair": list(key),
                        "recorded": value,
                        "computed": computed.get(key),
                    }
                )
    if mismatches:
        reasons.append(f"{len(mismatches)} recorded event-overlap value(s) do not recompute")
    design_e = ctx.design_by_id.get(C.LARGEST_TWO_BLOCK_DESIGN_ID)
    if design_e is not None:
        computed_e = {
            tuple(sorted((pair["left"], pair["right"]))): pair["shared_events"]
            for pair in overlaps.get(design_e.id, {}).get("pairs", [])
        }
        if computed_e and any(value != 0 for value in computed_e.values()):
            reasons.append("the two-block design's event sets are not disjoint")
    evidence = {
        "recorded_overlap_claims": {
            split_id: {"+".join(key): value for key, value in pairs.items()}
            for split_id, pairs in recorded_overlaps.items()
        },
        "computed_overlaps": overlaps,
        "mismatches": mismatches,
        "window_overlap_is_reported_separately_from_event_reuse": True,
        "shared_events_are_not_independent_observations": True,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The naive contiguous split shares 42/44/15 events between block pairs, "
            "exactly as recorded. The two-block and three-block disjoint candidates "
            "share none. Event reuse is never counted as independent evidence."
        ],
        evidence=evidence,
    )


def check_censored_cutoffs_not_gated(ctx: CheckContext) -> Check:
    check_id = "EVT-06_censored_cutoffs_not_gated"
    title = "Censored cutoffs are floors and never used as gate results"
    denominators = ctx.dataset.denominator_by_cutoff
    reasons = []
    censored = []
    for row in ctx.dataset.outcomes:
        cutoff_text = row.get("cutoff_T", "")
        denominator = denominators.get(cutoff_text, {})
        is_censored = denominator.get("matured") == "NO"
        if not is_censored:
            continue
        censored.append(
            {
                "cutoff": cutoff_text,
                "eligible_events_floor": integers(row, "eligible_events"),
                "gate_met": row.get("gate_met"),
                "maturity_date": denominator.get("maturity_date"),
            }
        )
        if row.get("gate_met") == "YES":
            reasons.append(f"{cutoff_text}: censored cutoff is marked gate_met=YES")
    for design in ctx.designs:
        for block in design.blocks:
            for cutoff_text in block.cutoffs:
                denominator = denominators.get(cutoff_text, {})
                if denominator.get("matured") == "NO" and block.gate_met is True:
                    reasons.append(
                        f"{design.id}/{block.role}: censored cutoff {cutoff_text} used as "
                        "a passing gate result"
                    )
    evidence = {
        "censored_cutoffs": censored,
        "censored_count": len(censored),
        "floors_are_gate_results": False,
        "note": (
            "Counts from censored cutoffs are lower bounds because the 180-day window "
            "extends beyond the served source timeline. They are shown but never used."
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"All {len(censored)} censored cutoffs are labelled floors; no design uses "
            "one as a gate pass."
        ],
        evidence=evidence,
    )


def check_kev_removal_awareness(ctx: CheckContext) -> Check:
    check_id = "EVT-07_kev_removal_awareness"
    title = "Outcomes preserve removal-aware KEV replay, including CVE-2025-6264"
    summary = ctx.dataset.kev_timeline_summary
    revisions = ctx.dataset.kev_revisions
    reasons = []
    removals = summary.get("removals", [])
    removal_ids = {item.get("cve_id") for item in removals if isinstance(item, dict)}
    expected_removals = {
        "CVE-2025-4664",
        "CVE-2025-6264",
        "CVE-2026-1281",
        "CVE-2026-69836",
    }
    if removal_ids != expected_removals:
        reasons.append(
            f"removal id set is {sorted(removal_ids)}, expected the "
            f"{len(expected_removals)} known ids"
        )
    recorded_removals = sum(integers(row, "removed_since_previous", 0) or 0 for row in revisions)
    recorded_additions = sum(integers(row, "added_since_previous", 0) or 0 for row in revisions)
    if len(removals) != recorded_removals:
        reasons.append("removal list length differs from replay counters")
    if integers(summary, "total_additions") not in (None, recorded_additions):
        reasons.append("total_additions differs from replay counters")
    first_seen = ctx.dataset.first_seen_day
    for cve_id in expected_removals:
        if cve_id not in first_seen:
            reasons.append(f"{cve_id}: removed CVE has no first-observation evidence")
    event_cutoffs = []
    for cutoff, ids in sorted(ctx.events_by_cutoff.items()):
        if "CVE-2025-6264" in ids:
            event_cutoffs.append(cutoff.isoformat())
    if not event_cutoffs:
        reasons.append("CVE-2025-6264 contributes no event row, contradicting Phase 2.3K")
    prior_refutation = (
        ctx.dataset.quality_summary.get("kev_timeline") or {}
    ).get("refutes_prior_phase")
    if not prior_refutation:
        reasons.append("the 2.3J 493-additions/0-removals refutation is not preserved")
    evidence = {
        "removals_recorded": removals,
        "removal_ids": sorted(removal_ids),
        "additions_recomputed": recorded_additions,
        "removals_recomputed": recorded_removals,
        "distinct_cves_ever_listed": integers(summary, "distinct_cves_ever_listed"),
        "unparseable_revisions": summary.get("unparseable_revisions"),
        "cve_2025_6264_first_observed": (
            first_seen.get("CVE-2025-6264").isoformat()
            if first_seen.get("CVE-2025-6264")
            else None
        ),
        "cve_2025_6264_event_cutoffs": event_cutoffs,
        "prior_phase_refutation": prior_refutation,
        "membership_reconstruction": "REPLAY_OF_CATALOG_REVISIONS_NOT_DATE_ADDED",
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"Replaying {len(revisions)} revisions yields {recorded_additions} additions "
            f"and {recorded_removals} removals, not 2.3J's 493/0. CVE-2025-6264 is an "
            f"eligible event at {len(event_cutoffs)} cutoffs despite its removal."
        ],
        evidence=evidence,
    )
