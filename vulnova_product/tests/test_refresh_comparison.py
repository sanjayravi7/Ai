"""The feasibility comparison: status changes, not digest churn."""

from __future__ import annotations

import copy
import json

from vulnova.refresh.comparison import (
    build_comparison,
    comparison_inputs_digest,
    parse_report_date,
)

CHECKS = [
    {"id": "INT-01_archive_digests", "status": "PASS", "reasons": [], "blocking": True},
    {
        "id": "PRV-06_retrieval_timestamp_provenance",
        "status": "BLOCKED",
        "reasons": ["CVELISTV5_RETRIEVAL_TIMESTAMP_NOT_RECORDED"],
        "blocking": False,
    },
    {"id": "REP-02_previous_report_digest", "status": "NOT_APPLICABLE", "reasons": [], "blocking": True},
]

DESIGNS = [
    {
        "id": "A2_EARLIEST_3BLOCK",
        "verdict": "INFEASIBLE",
        "protocol_admissible": False,
        "reason_codes": ["BLOCK_LABELS_NOT_MATURED"],
    }
]


def _report(digest="a" * 64, as_of="2026-10-15", checks=None, designs=None):
    return {
        "report_digest": digest,
        "as_of": as_of,
        "summary": {"total": 3, "PASS": 1, "FAIL": 0, "BLOCKED": 1, "NOT_APPLICABLE": 1},
        "readiness": {
            "status": "BLOCKED_PROTOCOL_NOT_APPROVED",
            "protocol_execution_authorized": False,
            "model_training_authorized": False,
        },
        "protocol": {"approval_state": "NOT_APPROVED"},
        "checks": copy.deepcopy(checks if checks is not None else CHECKS),
        "designs": copy.deepcopy(designs if designs is not None else DESIGNS),
    }


def _epss(cutoff, *, content="UNAVAILABLE", historical=False, score_date=None):
    return {
        "key": cutoff,
        "cutoff": cutoff,
        "content_status": content,
        "historical_retrieval_verified": historical,
        "details": {"file_score_date": score_date or cutoff},
    }


def test_identical_reports_have_no_status_changes():
    report = _report()
    comparison = build_comparison(
        baseline=report, current=copy.deepcopy(report), gates=[]
    )
    assert comparison["checks"]["changed"] == []
    assert comparison["checks"]["only_in_baseline"] == []
    assert comparison["checks"]["only_in_current"] == []
    assert comparison["questions"]["semantic_check_statuses_match_baseline"] is True
    assert comparison["questions"]["report_digest_matches_baseline"] is True


def test_a_changed_check_is_reported_with_the_reason_difference():
    current = _report(digest="b" * 64, as_of="2026-10-20")
    current["checks"][1] = {
        "id": "PRV-06_retrieval_timestamp_provenance",
        "status": "PASS",
        "reasons": [],
        "blocking": False,
    }
    comparison = build_comparison(baseline=_report(), current=current, gates=[])
    assert len(comparison["checks"]["changed"]) == 1
    row = comparison["checks"]["changed"][0]
    assert row["id"] == "PRV-06_retrieval_timestamp_provenance"
    assert (row["baseline_status"], row["current_status"]) == ("BLOCKED", "PASS")
    assert row["reasons"]["removed"] == ["CVELISTV5_RETRIEVAL_TIMESTAMP_NOT_RECORDED"]
    assert comparison["questions"]["semantic_check_statuses_match_baseline"] is False
    assert comparison["checks"]["unchanged_blocked_or_failed"] == []


def test_added_and_removed_checks_are_reported():
    current = _report(digest="b" * 64)
    current["checks"] = [CHECKS[0], {"id": "NEW-01_extra", "status": "PASS", "reasons": []}]
    comparison = build_comparison(baseline=_report(), current=current, gates=[])
    assert comparison["checks"]["only_in_baseline"] == [
        "PRV-06_retrieval_timestamp_provenance",
        "REP-02_previous_report_digest",
    ]
    assert comparison["checks"]["only_in_current"] == ["NEW-01_extra"]
    assert comparison["checks"]["changed"] == []


def test_a_digest_difference_alone_is_not_a_status_change():
    baseline = _report(as_of="2026-10-15")
    current = _report(digest="c" * 64, as_of="2026-10-20")
    comparison = build_comparison(baseline=baseline, current=current, gates=[])
    assert comparison["questions"]["report_digest_matches_baseline"] is False
    assert comparison["questions"]["semantic_check_statuses_match_baseline"] is True
    assert any(
        "digest difference is expected" in item for item in comparison["limitations"]
    )


def test_remaining_blocked_checks_are_listed():
    comparison = build_comparison(baseline=_report(), current=_report(), gates=[])
    assert comparison["checks"]["unchanged_blocked_or_failed"] == [
        {
            "id": "PRV-06_retrieval_timestamp_provenance",
            "status": "BLOCKED",
            "blocking": False,
        }
    ]


def test_baseline_that_is_absent_produces_an_explicit_gap():
    comparison = build_comparison(baseline=None, current=_report(), gates=[])
    assert comparison["baseline"]["available"] is False
    assert comparison["questions"]["report_digest_matches_baseline"] is False
    assert any("No baseline readiness report" in item for item in comparison["limitations"])


def test_a_matured_gate_answers_the_final_maturity_question():
    gates = [
        {"cutoff": "2026-04-01", "status": "MATURED_AND_OBSERVED", "maturity_date": "2026-10-28", "maturity_claimed": True}
    ]
    comparison = build_comparison(
        baseline=_report(),
        current=_report(),
        gates=gates,
        epss_records=[_epss("2026-04-01", content="VERIFIED", historical=False)],
    )
    assert comparison["questions"]["final_kev_maturity_requirement_satisfied"] is True
    assert comparison["questions"]["exact_historical_epss_available"] is True
    # Authentic bytes are still not contemporaneous provenance.
    assert comparison["questions"]["required_provenance_complete"] is False


def test_unmatured_gate_answers_no():
    gates = [
        {"cutoff": "2026-04-01", "status": "NOT_MATURED", "maturity_date": "2026-10-28", "maturity_claimed": False}
    ]
    comparison = build_comparison(baseline=_report(), current=_report(), gates=gates)
    assert comparison["questions"]["final_kev_maturity_requirement_satisfied"] is False


def test_an_admissible_design_is_detected():
    designs = [
        {
            "id": "A2_EARLIEST_3BLOCK",
            "verdict": "FEASIBLE",
            "protocol_admissible": True,
            "reason_codes": [],
        }
    ]
    comparison = build_comparison(
        baseline=_report(), current=_report(designs=designs), gates=[]
    )
    assert comparison["designs"]["any_protocol_admissible"] is True
    assert comparison["questions"]["any_candidate_design_admissible"] is True


def test_protocol_approval_state_is_never_manufactured():
    current = _report()
    current["protocol"] = {"approval_state": "APPROVED"}
    comparison = build_comparison(baseline=_report(), current=current, gates=[])
    assert comparison["questions"]["protocol_remains_not_approved"] is False
    # ... but execution still needs the readiness engine to authorise it.
    assert comparison["questions"]["protocol_execution_authorized"] is False


def test_the_comparison_is_deterministic():
    first = build_comparison(baseline=_report(), current=_report(digest="d" * 64), gates=[])
    second = build_comparison(baseline=_report(), current=_report(digest="d" * 64), gates=[])
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert comparison_inputs_digest([], "NOT_APPROVED") == comparison_inputs_digest(
        [], "NOT_APPROVED"
    )


def test_parse_report_date_tolerates_a_broken_value():
    assert parse_report_date({"as_of": "2026-10-15"}).isoformat() == "2026-10-15"
    assert parse_report_date({"as_of": "not-a-date"}) is None
    assert parse_report_date(None) is None
