"""End-to-end readiness reports over synthetic Phase 2.3K-shaped evidence."""

from __future__ import annotations

import datetime as dt
import json

from vulnova.evaluation import constants as C
from vulnova.evaluation.checks import CHECK_IDS
from vulnova.evaluation.readiness import (
    READINESS_BLOCKED_DESIGN,
    READINESS_BLOCKED_PROTOCOL,
    READINESS_NOT_READY_VALIDATION_FAILED,
    READINESS_READY,
    build_report,
)
from vulnova.evaluation.report import (
    canonical_digest,
    render_markdown,
    set_reproducibility,
    write_json,
    write_markdown,
)

from tests.evaluation_fixtures import CUTOFFS, build_fixture

D = dt.date


def _report(tmp_path, **kwargs):
    fixture = build_fixture(tmp_path / "fixture", **kwargs)
    return fixture, build_report(fixture.options)


def _checks(report):
    return {check["id"]: check for check in report["checks"]}


def _check_list(report):
    return "\n".join(render_markdown(report).splitlines())


def test_default_fixture_is_structurally_complete(tmp_path):
    _, report = _report(tmp_path)
    checks = _checks(report)
    assert len(checks) == len(report["checks"]) == report["summary"]["total"] == 44
    assert tuple(checks) == CHECK_IDS
    assert len(CHECK_IDS) == len(set(CHECK_IDS)) == 44
    assert all(check["status"] in C.CHECK_STATUSES for check in checks.values())
    assert all(isinstance(check["reasons"], list) for check in checks.values())
    assert all(check["reasons"] for check in checks.values())
    summary = report["summary"]
    assert summary["PASS"] + summary["FAIL"] + summary["BLOCKED"] + summary[
        "NOT_APPLICABLE"
    ] == summary["total"]
    assert report["parameters"] == {
        "horizon_days": 180,
        "maturity_lag_days": 30,
        "maturity_span_days": 210,
        "required_distinct_test_events": 30,
        "required_sequential_blocks": 3,
    }


def test_default_fixture_has_no_blocking_failure_and_no_approval(tmp_path):
    _, report = _report(tmp_path)
    checks = _checks(report)
    assert report["summary"]["FAIL"] == 0
    assert report["readiness"]["status"] == READINESS_BLOCKED_PROTOCOL
    assert report["readiness"]["primary_blocker"] == "PROTOCOL_NOT_APPROVED"
    assert report["readiness"]["protocol_approved"] is False
    assert report["readiness"]["protocol_execution_authorized"] is False
    assert report["readiness"]["approval_granted_by_this_command"] is False
    assert checks["PRO-02_approval_state_explicit"]["status"] == "PASS"
    assert any(
        blocker["code"] == "PROTOCOL_NOT_APPROVED" and blocker["primary"]
        for blocker in report["readiness"]["blockers"]
    )
    assert any(
        blocker["code"] == "NO_ADOPTED_DESIGN"
        for blocker in report["readiness"]["blockers"]
    )


def test_design_verdicts_match_phase2_3k_comparison(tmp_path):
    _, report = _report(tmp_path)
    designs = {design["id"]: design for design in report["designs"]}
    assert designs["A2_EARLIEST_3BLOCK"]["verdict"] == "FEASIBLE"
    assert designs["A2_EARLIEST_3BLOCK"]["protocol_admissible"] is True
    assert designs["E_LABEL_MATURED_2BLOCK"]["verdict"] == (
        "FEASIBLE_BUT_INSUFFICIENT_BLOCKS"
    )
    assert designs["E_LABEL_MATURED_2BLOCK"]["protocol_admissible"] is False
    assert all(design["matches_phase2_3k"] is None for design in report["designs"])
    assert all(
        design["comparison_as_of"] == report["reference_date"]
        for design in report["designs"]
    )
    assert _checks(report)["TMP-03_candidate_design_sequence"]["status"] == (
        "NOT_APPLICABLE"
    )


def test_maturity_boundary_blocks_the_earliest_design(tmp_path):
    _, report = _report(tmp_path, reference_date=D(2026, 10, 15))
    designs = {design["id"]: design for design in report["designs"]}
    earliest = designs["A2_EARLIEST_3BLOCK"]
    assert earliest["verdict"] == "INFEASIBLE"
    assert "BLOCK_LABELS_NOT_MATURED" in earliest["reason_codes"]
    assert earliest["blocks"][2]["maturity_date"] == "2026-10-28"
    assert earliest["blocks"][2]["matured_at_as_of"] is False
    assert earliest["blocks"][2]["gate_met"] is None
    assert earliest["blocks"][2]["gate_basis"] == "FLOOR_NOT_A_GATE_RESULT"
    maturity = {
        row["cutoff"]: row for row in report["maturity"]
    }
    assert maturity["2026-04-01"]["label_maturity_date"] == "2026-10-28"
    assert maturity["2026-04-01"]["days_until_matured_at_as_of"] == 13
    assert maturity["2026-04-01"]["matured_at_as_of"] is False
    blocker = next(
        item
        for item in report["readiness"]["blockers"]
        if item["code"] == "LABEL_MATURITY_NOT_REACHED"
    )
    assert "2026-10-28" in blocker["detail"]
    assert "13 days" in blocker["detail"]
    assert report["readiness"]["status"] == READINESS_BLOCKED_PROTOCOL


def test_calendar_maturity_without_source_coverage_stays_blocked(tmp_path):
    _, report = _report(
        tmp_path, reference_date=D(2026, 11, 1), source_end=D(2026, 10, 15)
    )
    checks = _checks(report)
    designs = {design["id"]: design for design in report["designs"]}
    assert checks["TMP-07_label_window_observability"]["status"] == "FAIL"
    assert designs["A2_EARLIEST_3BLOCK"]["verdict"] == "INFEASIBLE"
    assert "LABEL_STABILITY_NOT_OBSERVABLE" in designs["A2_EARLIEST_3BLOCK"][
        "reason_codes"
    ]
    assert any(
        blocker["code"] == "LABEL_STABILITY_NOT_OBSERVABLE_IN_PROVIDED_SOURCE"
        for blocker in report["readiness"]["blockers"]
    )
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED


def test_approved_three_block_design_is_ready_but_trains_nothing(tmp_path):
    _, report = _report(
        tmp_path, approved=True, adopted_design="A2_EARLIEST_3BLOCK"
    )
    readiness = report["readiness"]
    assert readiness["status"] == READINESS_READY
    assert readiness["primary_blocker"] is None
    assert readiness["protocol_execution_authorized"] is True
    assert readiness["model_training_authorized"] is False
    assert readiness["approval_granted_by_this_command"] is False
    assert readiness["confirmatory_no_go"] == "RETAINED"
    assert readiness["model_training_performed"] is False
    assert readiness["predictive_performance_claimed"] is False
    assert report["summary"]["FAIL"] == 0


def test_adopted_two_block_design_is_rejected(tmp_path):
    _, report = _report(
        tmp_path, approved=True, adopted_design="E_LABEL_MATURED_2BLOCK"
    )
    design = next(
        item
        for item in report["designs"]
        if item["id"] == "E_LABEL_MATURED_2BLOCK"
    )
    assert design["verdict"] == "FEASIBLE_BUT_INSUFFICIENT_BLOCKS"
    assert design["protocol_admissible"] is False
    assert report["readiness"]["status"] == READINESS_BLOCKED_DESIGN
    assert report["readiness"]["primary_blocker"] == "ADOPTED_DESIGN_INFEASIBLE"
    assert report["readiness"]["protocol_execution_authorized"] is False


def test_approved_protocol_without_a_design_is_invalid(tmp_path):
    _, report = _report(tmp_path, approved=True)
    checks = _checks(report)
    assert checks["PRO-01_protocol_document"]["status"] == "FAIL"
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED
    assert any(
        blocker["code"] == "NO_ADOPTED_DESIGN"
        for blocker in report["readiness"]["blockers"]
    )
    assert report["readiness"]["protocol_execution_authorized"] is False


def test_future_information_leakage_is_a_blocking_failure(tmp_path):
    _, report = _report(tmp_path, event_already_in_kev_at=CUTOFFS[0])
    checks = _checks(report)
    assert checks["EVT-04_event_membership_at_cutoff"]["status"] == "FAIL"
    assert checks["LKG-06_no_future_information"]["status"] == "FAIL"
    assert "future-information leakage" in " ".join(
        checks["EVT-04_event_membership_at_cutoff"]["reasons"]
    )
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED
    assert report["readiness"]["blockers"][0]["code"] == "VALIDATION_FAILURE"


def test_duplicate_event_rows_are_detected(tmp_path):
    _, report = _report(tmp_path, duplicate_event_at=CUTOFFS[0])
    checks = _checks(report)
    assert checks["EVT-02_event_row_uniqueness"]["status"] == "FAIL"
    assert "DUPLICATE_EVENT_ID_IN_CELL" in " ".join(
        checks["EVT-02_event_row_uniqueness"]["reasons"]
    )
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED


def test_corrupted_partition_fails_checksum_and_blocks_accounting(tmp_path):
    _, report = _report(tmp_path, corrupt_partition_at=CUTOFFS[1])
    checks = _checks(report)
    assert checks["INT-05_membership_partition_checksums"]["status"] == "FAIL"
    assert checks["INT-06_membership_row_accounting"]["status"] == "BLOCKED"
    assert checks["EVT-04_event_membership_at_cutoff"]["status"] == "BLOCKED"
    assert "not treated as absence" in " ".join(
        checks["EVT-04_event_membership_at_cutoff"]["reasons"]
    )
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED


def test_missing_partition_blocks_checks_without_accusing_the_data(tmp_path):
    _, report = _report(tmp_path, missing_partition_at=CUTOFFS[1])
    checks = _checks(report)
    assert checks["INT-05_membership_partition_checksums"]["status"] == "BLOCKED"
    assert checks["INT-06_membership_row_accounting"]["status"] == "BLOCKED"
    assert checks["EVT-04_event_membership_at_cutoff"]["status"] == "BLOCKED"
    assert report["summary"]["FAIL"] == 0
    assert any(
        blocker["code"] == "EVIDENCE_UNAVAILABLE"
        for blocker in report["readiness"]["blockers"]
    )
    assert report["readiness"]["status"] == READINESS_BLOCKED_PROTOCOL


def test_missing_membership_index_blocks_deep_verification(tmp_path):
    _, report = _report(tmp_path, missing_membership_index=True)
    checks = _checks(report)
    assert checks["INT-05_membership_partition_checksums"]["status"] == "BLOCKED"
    assert checks["INT-06_membership_row_accounting"]["status"] == "BLOCKED"
    assert checks["EVT-04_event_membership_at_cutoff"]["status"] == "BLOCKED"
    assert report["inputs"]["scan_performed"] is False


def test_report_digest_is_canonical_and_reproducible(tmp_path):
    fixture, first = _report(tmp_path)
    second = build_report(fixture.options)
    assert first["report_digest"] == second["report_digest"]
    assert first["report_digest"] == canonical_digest(first)
    assert canonical_digest({**first, "reproducibility": {"noise": True}}) == (
        first["report_digest"]
    )
    changed = build_report(
        build_fixture(tmp_path / "other", reference_date=D(2026, 10, 15)).options
    )
    assert changed["report_digest"] != first["report_digest"]


def test_reproducibility_block_and_rendered_outputs(tmp_path):
    fixture, report = _report(tmp_path)
    second = build_report(fixture.options)
    block = set_reproducibility(report, second_digest=second["report_digest"])
    assert block["double_run_match"] is True
    assert report["reproducibility"]["report_digest_sha256"] == report["report_digest"]

    json_path = write_json(report, tmp_path / "out" / "readiness.json")
    markdown_path = write_markdown(report, tmp_path / "out" / "readiness.md")
    reloaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert reloaded["report_digest"] == report["report_digest"]
    assert canonical_digest(reloaded) == report["report_digest"]

    text = markdown_path.read_text(encoding="utf-8")
    assert "BLOCKED_PROTOCOL_NOT_APPROVED" in text
    assert "PASS" in text and "NOT_APPLICABLE" in text
    assert "A2_EARLIEST_3BLOCK" in text
    assert "does **not** approve the protocol" in text


def test_evidence_classification_keeps_three_states(tmp_path):
    _, report = _report(tmp_path)
    classification = report["evidence_classification"]
    assert set(classification["states"]) >= {
        "CONFIRMED_KEV_INCLUSION",
        "ABSENT_FROM_KEV",
        "MISSING_HISTORICAL_EVIDENCE",
    }
    assert classification["absence_used_as_negative_label"] is False
    assert classification["missing_used_as_absence"] is False
    assert classification["classification_check_status"] == "PASS"
    assert classification["counts"]["confirmed_kev_inclusion_event_rows"] > 0
    assert classification["counts"]["absent_from_kev_risk_set_observations"] > 0
    assert classification["counts"]["missing_historical_evidence"][
        "cvelistv5_retrieval_time_unrecorded"
    ] is True
    assert "not proof of non-exploitation" in classification["absence_interpretation"]


def test_limitations_are_specific_and_bounded(tmp_path):
    _, report = _report(tmp_path)
    limitations = report["limitations"]
    assert len(limitations) >= 10
    text = " ".join(limitations)
    assert "NOT_APPROVED" in text
    assert "No model was trained" in text
    assert "Absence from the catalog is never proof" in text
    assert "2026-10-28" in text
    assert "2026-10-15" in text or report["as_of"] in text
    assert all(isinstance(item, str) and item.strip() for item in limitations)


def test_report_has_no_performance_or_ranking_claim(tmp_path):
    _, report = _report(tmp_path)
    encoded = json.dumps(report).lower()
    for forbidden in ("auc", "accuracy", "f1_score", "precision", "recall"):
        assert forbidden not in encoded
    assert report["readiness"]["ranking_weights_changed"] is False
    assert report["readiness"]["source_data_changed"] is False
    assert report["readiness"]["event_gate_relaxed"] is False


def test_markdown_lists_every_check(tmp_path):
    _, report = _report(tmp_path)
    text = _check_list(report)
    for check in report["checks"]:
        assert check["id"] in text


def test_cli_writes_machine_readable_and_markdown_reports(tmp_path, capsys):
    from vulnova.evaluation.cli import main

    fixture = build_fixture(tmp_path / "fixture")
    out = tmp_path / "out" / "readiness.json"
    markdown = tmp_path / "out" / "readiness.md"
    rc = main(
        [
            "readiness",
            "--artifacts",
            str(fixture.root),
            "--protocol",
            str(fixture.protocol),
            "--no-extract",
            "--check-reproducible",
            "--out",
            str(out),
            "--markdown",
            str(markdown),
        ]
    )
    assert rc == 0
    captured = capsys.readouterr().out
    assert "READINESS: BLOCKED_PROTOCOL_NOT_APPROVED" in captured
    assert "double-run digest match: yes" in captured
    assert out.is_file() and markdown.is_file()
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["reproducibility"]["double_run_match"] is True
    assert canonical_digest(report) == report["report_digest"]


def test_cli_require_ready_fails_while_the_protocol_is_unapproved(tmp_path, capsys):
    from vulnova.evaluation.cli import main

    fixture = build_fixture(tmp_path / "fixture")
    rc = main(
        [
            "readiness",
            "--artifacts",
            str(fixture.root),
            "--protocol",
            str(fixture.protocol),
            "--no-extract",
            "--quiet",
            "--require-ready",
            "--out",
            str(tmp_path / "readiness.json"),
        ]
    )
    assert rc == 1
    assert capsys.readouterr().out.strip() == "BLOCKED_PROTOCOL_NOT_APPROVED"


def _mutate_protocol(fixture, mutate):
    payload = json.loads(fixture.protocol.read_text(encoding="utf-8"))
    mutate(payload)
    fixture.protocol.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_silent_protocol_adoption_is_rejected(tmp_path):
    fixture = build_fixture(tmp_path / "fixture")
    _mutate_protocol(
        fixture,
        lambda payload: payload.__setitem__("adopted_design", "A2_EARLIEST_3BLOCK"),
    )
    report = build_report(fixture.options)
    checks = _checks(report)
    assert checks["PRO-03_no_silent_design_adoption"]["status"] == "FAIL"
    assert checks["TMP-04_earliest_three_block_design"]["status"] == "FAIL"
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED
    assert report["readiness"]["adopted_design"] == "A2_EARLIEST_3BLOCK"


def test_relaxing_the_event_gate_in_the_protocol_is_rejected(tmp_path):
    def relax(payload):
        payload["required_distinct_test_events"] = 20
        payload["constants"]["required_distinct_test_events"] = 20

    fixture = build_fixture(tmp_path / "fixture")
    _mutate_protocol(fixture, relax)
    report = build_report(fixture.options)
    checks = _checks(report)
    assert checks["TMP-06_event_gate_not_relaxed"]["status"] == "FAIL"
    assert checks["PRO-04_protocol_binding_constants"]["status"] == "FAIL"
    assert report["readiness"]["status"] == READINESS_NOT_READY_VALIDATION_FAILED
    assert report["readiness"]["event_gate_relaxed"] is False
