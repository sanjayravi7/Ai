"""Offline verification of a refresh report and its sealed archive."""

from __future__ import annotations

import copy
import json

from vulnova.acquisition import constants as A
from vulnova.refresh import constants as C
from vulnova.refresh.report import attach_digest
from vulnova.refresh.verify import verify_report
from vulnova.refresh.workflow import run_refresh

from tests.refresh_fixtures import build_scenario


def test_a_fresh_report_verifies_offline(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    report = run_refresh(scenario.options())
    result = verify_report(
        report,
        store_root=scenario.store.root,
        archive_manifest_path=scenario.baseline_manifest_path,
        archive_store_root=scenario.baseline_store_path,
    )
    assert result["status"] == A.VERIFIED
    # Integrity and evidence are separate axes and must stay separate.
    assert result["evidence_status"] == A.BLOCKED
    assert result["refresh_status"] == C.REFRESH_BLOCKED_MATURITY
    ids = [check["id"] for check in result["checks"]]
    assert ids == [
        "SCHEMA",
        "REPORT_DIGEST",
        "MATURITY_INVARIANT",
        "REFRESH_STATUS",
        "PROTOCOL_NOT_APPROVED",
        "REFRESH_ARTIFACTS",
        "SEALED_ARCHIVE",
    ]
    # The GitHub catalog plus two EPSS files? No: the default fixture's direct
    # feed is unreachable and EPSS is unavailable, so one catalog is stored.
    assert result["summary"]["artifacts_hashed"] == 1
    assert result["summary"]["network_used"] is False


def test_repeated_verification_of_the_same_report_is_stable(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    report = run_refresh(scenario.options())
    results = [
        verify_report(
            report,
            store_root=scenario.store.root,
            archive_manifest_path=scenario.baseline_manifest_path,
            archive_store_root=scenario.baseline_store_path,
        )
        for _ in range(3)
    ]
    assert results[0] == results[1] == results[2]
    assert json.dumps(results[0], sort_keys=True) == json.dumps(results[2], sort_keys=True)


def test_verify_detects_a_tampered_refresh_artifact(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    report = run_refresh(scenario.options())
    target = scenario.store.path(report["catalog"]["artifact_path"])
    target.write_bytes(b'{"count": 0, "vulnerabilities": []}')
    result = verify_report(
        report,
        store_root=scenario.store.root,
        archive_manifest_path=scenario.baseline_manifest_path,
        archive_store_root=scenario.baseline_store_path,
    )
    assert result["status"] == A.BLOCKED
    row = next(check for check in result["checks"] if check["id"] == "REFRESH_ARTIFACTS")
    assert row["status"] == A.BLOCKED


def test_verify_detects_an_edited_digest(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    report["refresh_digest"] = "0" * 64
    result = verify_report(report, store_root=scenario.store.root)
    assert result["status"] == A.BLOCKED
    row = next(check for check in result["checks"] if check["id"] == "REPORT_DIGEST")
    assert row["status"] == A.BLOCKED


def test_verify_detects_an_edited_claim_through_the_digest(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    edited = copy.deepcopy(report)
    edited["summary"]["maturity_claimed"] = True
    result = verify_report(edited, store_root=scenario.store.root)
    assert result["status"] == A.BLOCKED


def test_verify_detects_a_premature_maturity_claim(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    forged = copy.deepcopy(report)
    forged["maturity_gate"][-1]["maturity_claimed"] = True
    forged["maturity_gate"][-1]["status"] = C.GATE_MATURED_OBSERVED
    attach_digest(forged)  # a self-consistent forgery still fails the invariant
    result = verify_report(forged, store_root=scenario.store.root)
    assert result["status"] == A.BLOCKED
    row = next(check for check in result["checks"] if check["id"] == "MATURITY_INVARIANT")
    assert row["status"] == A.BLOCKED
    assert row["reason_code"] == C.MATURITY_CLAIMED_EARLY


def test_verify_detects_a_tampered_sealed_artifact(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    report = run_refresh(scenario.options())
    from tests.refresh_fixtures import tamper_archive

    tamper_archive(scenario)
    result = verify_report(
        report,
        store_root=scenario.store.root,
        archive_manifest_path=scenario.baseline_manifest_path,
        archive_store_root=scenario.baseline_store_path,
    )
    assert result["status"] == A.BLOCKED
    row = next(check for check in result["checks"] if check["id"] == "SEALED_ARCHIVE")
    assert row["status"] == A.BLOCKED


def test_verify_refuses_a_report_that_authorises_execution(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    forged = copy.deepcopy(report)
    forged["protocol"]["approval_state"] = "APPROVED"
    forged["protocol"]["protocol_execution_authorized"] = True
    attach_digest(forged)
    result = verify_report(forged, store_root=scenario.store.root)
    row = next(check for check in result["checks"] if check["id"] == "PROTOCOL_NOT_APPROVED")
    assert row["status"] == A.BLOCKED
    assert result["status"] == A.BLOCKED


def test_verify_without_stores_still_checks_the_report(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    result = verify_report(report)
    assert result["status"] == A.VERIFIED
    # Nothing was re-hashed, so the count says zero rather than implying it did.
    assert result["summary"]["artifacts_hashed"] == 0
