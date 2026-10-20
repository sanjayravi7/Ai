"""End-to-end refresh runs against canned bytes and a fixed clock.

The clock is injected through ``RefreshOptions``; nothing here reads the system
time, opens a socket, or writes outside ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.acquisition import constants as A
from vulnova.acquisition.store import ArtifactStore
from vulnova.refresh import constants as C
from vulnova.refresh.workflow import (
    RefreshError,
    archive_fingerprint,
    assert_separate_store,
    run_refresh,
)

from tests.refresh_fixtures import (
    CUTOFFS,
    ON_MATURITY_CATALOG,
    POST_MATURITY_CATALOG,
    PRE_MATURITY_CATALOG,
    build_scenario,
    tamper_archive,
)


def _requirements(report: dict) -> dict[str, dict]:
    return {row["id"]: row for row in report["requirements"]}


# ------------------------------------------------------------ clock behaviour
def test_refresh_before_maturity_claims_no_maturity(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    assert report["as_of"] == "2026-10-20"
    assert report["summary"]["refresh_status"] == C.REFRESH_BLOCKED_MATURITY
    assert report["summary"]["maturity_claimed"] is False
    assert report["final_candidate"] == {
        "cutoff": "2026-04-01",
        "maturity_date": "2026-10-28",
        "calendar_matured": False,
        "days_remaining": 8,
        "maturity_claimed": False,
    }
    final_gate = report["maturity_gate"][-1]
    assert final_gate["status"] == C.GATE_NOT_MATURED
    assert final_gate["filter_applied"] is False
    assert _requirements(report)["KEV-R3_MATURITY_OBSERVABLE"]["status"] == A.BLOCKED
    assert _requirements(report)["PROV-R1_NO_PREMATURE_MATURITY"]["status"] == A.VERIFIED


def test_refresh_records_the_real_clock_for_every_artifact(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    for record in report["kev_records"] + report["epss_records"]:
        if record.get("retrieved_at"):
            assert record["retrieved_at"] == "2026-10-20T09:00:10Z"
        assert record.get("retrieved_at") is not None or not record.get("sha256")
    assert report["generated_at"] == "2026-10-20T09:00:00Z"


def test_two_runs_with_the_same_clock_produce_the_same_digest(tmp_path):
    scenario = build_scenario(tmp_path)
    first = run_refresh(scenario.options())
    second = run_refresh(scenario.options())
    assert first["refresh_digest"] == second["refresh_digest"]
    assert first["maturity_gate"] == second["maturity_gate"]


def test_the_digest_excludes_the_clock_but_not_the_evidence(tmp_path):
    scenario = build_scenario(tmp_path)
    early = run_refresh(scenario.options())
    late = run_refresh(scenario.options(clock=lambda: "2026-10-20T23:59:00Z"))
    assert early["refresh_digest"] == late["refresh_digest"]
    assert late["generated_at"] == "2026-10-20T23:59:00Z"


# --------------------------------------------------------------- maturity day
def test_refresh_on_the_maturity_date_with_a_fresh_catalog_observes_labels(tmp_path):
    scenario = build_scenario(
        tmp_path,
        as_of="2026-10-28T08:00:00Z",
        retrieved_at="2026-10-28T08:00:10Z",
        catalog_released=ON_MATURITY_CATALOG,
        entries=[
            ("CVE-2024-1", "2024-01-01"),
            ("CVE-2025-9", "2025-01-01"),
            ("CVE-2026-7", "2026-11-02"),
        ],
    )
    report = run_refresh(scenario.options())
    assert report["final_candidate"]["calendar_matured"] is True
    assert report["final_candidate"]["days_remaining"] == 0
    assert report["final_candidate"]["maturity_claimed"] is True
    final_gate = report["maturity_gate"][-1]
    assert final_gate["status"] == C.GATE_MATURED_OBSERVED
    assert final_gate["filter_applied"] is True
    final_filter = report["date_added_filters"]["2026-04-01"]
    assert final_filter["applied"] is True
    assert final_filter["entries_total"] == 3
    assert final_filter["entries_observable"] == 2
    assert final_filter["entries_after_maturity"] == 1
    assert _requirements(report)["KEV-R3_MATURITY_OBSERVABLE"]["status"] == A.VERIFIED


def test_refresh_on_the_maturity_date_with_a_stale_catalog_is_still_censored(tmp_path):
    scenario = build_scenario(
        tmp_path, as_of="2026-10-28T08:00:00Z", catalog_released=PRE_MATURITY_CATALOG
    )
    report = run_refresh(scenario.options())
    assert report["final_candidate"]["calendar_matured"] is True
    assert report["final_candidate"]["maturity_claimed"] is False
    final_gate = report["maturity_gate"][-1]
    assert final_gate["status"] == C.GATE_MATURED_SOURCE_PREDATES
    assert final_gate["filter_applied"] is False
    assert report["date_added_filters"]["2026-04-01"]["basis"] == C.RIGHT_CENSORED_NOT_FILTERED
    assert report["summary"]["refresh_status"] == C.REFRESH_BLOCKED_SOURCE
    assert _requirements(report)["KEV-R3_MATURITY_OBSERVABLE"]["status"] == A.BLOCKED


def test_a_catalog_released_after_maturity_opens_the_gate_after_the_date(tmp_path):
    scenario = build_scenario(
        tmp_path,
        as_of="2026-11-05T09:00:00Z",
        retrieved_at="2026-11-05T09:00:10Z",
        catalog_released=POST_MATURITY_CATALOG,
    )
    report = run_refresh(scenario.options())
    assert report["maturity_gate"][-1]["status"] == C.GATE_MATURED_OBSERVED
    assert report["final_candidate"]["maturity_claimed"] is True


# ----------------------------------------------------------- evidence honesty
def test_every_byte_present_still_blocks_on_non_contemporaneous_provenance(tmp_path):
    scenario = build_scenario(
        tmp_path,
        as_of="2026-10-28T08:00:00Z",
        retrieved_at="2026-10-28T08:00:10Z",
        catalog_released=ON_MATURITY_CATALOG,
        epss="available",
    )
    report = run_refresh(scenario.options())
    requirements = _requirements(report)
    assert requirements["KEV-R3_MATURITY_OBSERVABLE"]["status"] == A.VERIFIED
    assert requirements["EPSS-R1_EXACT_DAILY_FILE"]["status"] == A.VERIFIED
    # Authentic bytes, downloaded today for a 2025 cutoff: late, not contemporaneous.
    assert requirements["EPSS-R2_HISTORICAL_PROVENANCE"]["status"] == A.BLOCKED
    assert requirements["EPSS-R2_HISTORICAL_PROVENANCE"]["reason_code"] == (
        A.RETRIEVAL_NOT_CONTEMPORANEOUS
    )
    assert report["summary"]["refresh_status"] == C.REFRESH_BLOCKED_EVIDENCE
    assert report["summary"]["evidence_status"] == A.BLOCKED


def test_refresh_never_marks_reassessment_eligible(tmp_path):
    scenario = build_scenario(
        tmp_path,
        as_of="2026-10-28T08:00:00Z",
        retrieved_at="2026-10-28T08:00:10Z",
        catalog_released=ON_MATURITY_CATALOG,
        epss="available",
    )
    report = run_refresh(scenario.options())
    reassessment = report["summary"]["reassessment"]
    assert reassessment["eligible_for_protocol_reassessment"] is False
    assert "PROTOCOL_NOT_APPROVED" in reassessment["blockers"]
    assert "NO_ADOPTED_DESIGN" in reassessment["blockers"]
    assert report["protocol"]["protocol_execution_authorized"] is False


def test_unavailable_epss_files_stay_visible_in_the_report(tmp_path):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    records = report["epss_records"]
    assert len(records) == len(CUTOFFS)
    for record in records:
        assert record["content_status"] == A.UNAVAILABLE
        assert record["reason_code"] == A.OFFICIAL_SOURCE_UNREACHABLE
        assert record["access_provenance"] == A.NOT_RETRIEVED
    assert _requirements(report)["EPSS-R1_EXACT_DAILY_FILE"]["status"] == A.UNAVAILABLE


def test_epss_score_date_mismatch_is_rejected_not_substituted(tmp_path):
    scenario = build_scenario(tmp_path, epss="mismatch")
    report = run_refresh(scenario.options())
    for record in report["epss_records"]:
        assert record["content_status"] == A.UNAVAILABLE
        assert record["reason_code"] == A.SCORE_DATE_MISMATCH
        assert record["details"]["requested_date"] == record["cutoff"]
    assert _requirements(report)["EPSS-R1_EXACT_DAILY_FILE"]["reason_code"] == (
        A.SCORE_DATE_MISMATCH
    )


# ------------------------------------------------------------- bad catalogs
def test_a_truncated_catalog_is_rejected(tmp_path):
    scenario = build_scenario(tmp_path, declared=99)
    report = run_refresh(scenario.options())
    assert report["catalog"]["verified"] is False
    assert report["catalog"]["content_status"] == A.BLOCKED
    assert report["catalog"]["reason_code"] == A.TRUNCATED_CATALOG
    assert _requirements(report)["KEV-R2_CURRENT_CATALOG"]["status"] == A.BLOCKED


def test_an_empty_catalog_response_is_rejected(tmp_path):
    scenario = build_scenario(tmp_path)
    # Replace the GitHub blob payload with an empty, still well-formed envelope.
    from tests.acquisition_fixtures import blob_payload, kev_blob_url, sha40

    blob_sha = sha40("refresh-blob")
    scenario.transport.add_json(
        kev_blob_url(blob_sha),
        blob_payload(b"", blob_sha),
        retrieved_at="2026-10-20T09:00:10Z",
    )
    report = run_refresh(scenario.options())
    assert report["catalog"]["verified"] is False
    assert all(gate["catalog_available"] is False for gate in report["maturity_gate"])


def test_a_catalog_released_after_its_own_retrieval_is_rejected(tmp_path):
    scenario = build_scenario(tmp_path, catalog_released="2026-11-01T00:00:00Z")
    report = run_refresh(scenario.options())
    assert report["catalog"]["verified"] is False
    assert report["catalog"]["reason_code"] == A.RETRIEVAL_BEFORE_SOURCE_TIME
    for gate in report["maturity_gate"]:
        assert gate["catalog_available"] is False


def test_a_missing_source_timestamp_is_rejected(tmp_path):
    body = json.dumps(
        {"catalogVersion": "2026.10.16", "count": 1, "vulnerabilities": [{"cveID": "CVE-2024-1"}]}
    ).encode("utf-8")
    scenario = build_scenario(tmp_path)
    from tests.acquisition_fixtures import (
        blob_payload,
        kev_blob_url,
        kev_tree_url,
        sha40,
        tree_payload,
    )

    tree_sha, blob_sha = sha40("refresh-tree"), sha40("refresh-blob")
    scenario.transport.add_json(
        kev_tree_url(tree_sha),
        tree_payload(blob_sha, len(body)),
        retrieved_at="2026-10-20T09:00:10Z",
    )
    scenario.transport.add_json(
        kev_blob_url(blob_sha),
        blob_payload(body, blob_sha),
        retrieved_at="2026-10-20T09:00:10Z",
    )
    report = run_refresh(scenario.options())
    assert report["catalog"]["verified"] is False
    assert report["catalog"]["reason_code"] == A.SOURCE_TIMESTAMP_MISSING


def test_a_catalog_with_invalid_date_added_is_not_trusted(tmp_path):
    scenario = build_scenario(
        tmp_path,
        as_of="2026-10-28T08:00:00Z",
        retrieved_at="2026-10-28T08:00:10Z",
        catalog_released=ON_MATURITY_CATALOG,
        raw_entries=[
            {"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"},
            {"cveID": "CVE-2024-2"},
        ],
    )
    report = run_refresh(scenario.options())
    final_filter = report["date_added_filters"]["2026-04-01"]
    assert final_filter["applied"] is True
    assert final_filter["trustworthy"] is False
    assert final_filter["reason_code"] == C.DATE_ADDED_INVALID
    assert final_filter["entries_invalid"] == 1


# -------------------------------------------------------------- URL provenance
def test_a_redirected_catalog_preserves_the_request_and_final_urls(tmp_path):
    scenario = build_scenario(
        tmp_path,
        direct_feed=True,
        direct_feed_redirect="https://www.cisa.gov/redirected/kev.json",
    )
    report = run_refresh(scenario.options())
    catalog = report["catalog"]
    assert catalog["channel"] == A.CHANNEL_OFFICIAL
    assert catalog["request_url"].startswith(
        "https://www.cisa.gov/sites/default/files/feeds/"
    )
    assert catalog["final_url"] == "https://www.cisa.gov/redirected/kev.json"
    assert catalog["redirected"] is True
    assert report["kev_records"][0]["final_url"] != report["kev_records"][0]["request_url"]


def test_an_unredirected_catalog_carries_no_redundant_final_url(tmp_path):
    scenario = build_scenario(tmp_path, direct_feed=True)
    report = run_refresh(scenario.options())
    for record in report["kev_records"]:
        if "final_url" in record:
            assert record["final_url"] != record["request_url"]


def test_the_direct_feed_wins_over_the_github_fallback(tmp_path):
    scenario = build_scenario(tmp_path, direct_feed=True)
    report = run_refresh(scenario.options())
    assert report["catalog"]["channel"] == A.CHANNEL_OFFICIAL
    assert _requirements(report)["KEV-R1_DIRECT_CISA_FEED"]["status"] == A.VERIFIED


# ----------------------------------------------------------------- seal guard
def test_refresh_refuses_a_store_inside_the_sealed_archive(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    scenario.store = ArtifactStore(
        Path(scenario.baseline_store_path) / "nested_refresh"
    )
    with pytest.raises(RefreshError) as excinfo:
        run_refresh(scenario.options())
    assert C.REFRESH_STORE_OVERLAPS_ARCHIVE in str(excinfo.value)


def test_refresh_refuses_a_store_that_contains_the_sealed_archive(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    # Siblings are fine: the refresh store and the sealed archive never overlap.
    assert_separate_store(scenario.root / "refresh_store", [scenario.baseline_store_path])
    # A store that contains the archive is refused in the other direction too.
    with pytest.raises(RefreshError) as excinfo:
        assert_separate_store(scenario.root, [scenario.baseline_store_path])
    assert C.REFRESH_STORE_OVERLAPS_ARCHIVE in str(excinfo.value)


def test_refresh_leaves_the_sealed_archive_byte_identical(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    before = archive_fingerprint(
        scenario.baseline_manifest_path, scenario.baseline_store_path
    )
    report = run_refresh(scenario.options())
    after = archive_fingerprint(
        scenario.baseline_manifest_path, scenario.baseline_store_path
    )
    assert before == after
    assert report["archive_guard"]["before"] == report["archive_guard"]["after"]
    assert _requirements(report)["PROV-R2_SEALED_ARCHIVE_UNCHANGED"]["status"] == A.VERIFIED


def test_refresh_detects_a_sealed_artifact_that_changed(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    tamper_archive(scenario)
    report = run_refresh(scenario.options())
    requirement = _requirements(report)["PROV-R2_SEALED_ARCHIVE_UNCHANGED"]
    assert requirement["status"] == A.BLOCKED
    assert requirement["reason_code"] == C.ARCHIVE_CHANGED_DURING_REFRESH
    assert report["archive_guard"]["after"]["all_artifacts_unchanged"] is False


def test_the_refresh_store_holds_only_refresh_paths(tmp_path):
    scenario = build_scenario(tmp_path)
    run_refresh(scenario.options())
    written = sorted(
        str(path.relative_to(scenario.store.root))
        for path in scenario.store.root.rglob("*")
        if path.is_file()
    )
    assert written
    for relative in written:
        assert not relative.startswith("kev/revisions/")
        assert relative.startswith(("kev/refresh/", "epss/"))


def test_the_sealed_archive_is_not_a_refresh_output_directory(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    with pytest.raises(RefreshError):
        run_refresh(
            scenario.options(
                store=ArtifactStore(Path(scenario.baseline_store_path) / "kev")
            )
        )


# ----------------------------------------------------------------- reporting
def test_requirements_use_the_shared_three_state_vocabulary(tmp_path):
    report = run_refresh(build_scenario(tmp_path).options())
    for row in report["requirements"]:
        assert row["status"] in A.STATUSES
    assert report["summary"]["evidence_status"] in A.STATUSES
    assert report["summary"]["refresh_status"] in C.REFRESH_STATUSES


def test_the_report_carries_the_honesty_policies(tmp_path):
    report = run_refresh(build_scenario(tmp_path).options())
    honesty = report["honesty"]
    assert "not evidence that a historical evaluation is viable" in (
        honesty["integrity_is_not_viability"]
    )
    assert "human decision" in honesty["protocol_approval"]
    assert report["parameters"] == {
        "horizon_days": 180,
        "maturity_lag_days": 30,
        "maturity_span_days": 210,
        "required_distinct_test_events": 30,
        "required_sequential_blocks": 3,
    }


def test_without_a_baseline_the_comparison_says_so(tmp_path):
    report = run_refresh(build_scenario(tmp_path).options())
    comparison = report["readiness_comparison"]
    assert comparison["baseline"]["available"] is False
    assert comparison["current"]["available"] is False
    assert comparison["questions"]["report_digest_matches_baseline"] is False
    assert any(
        "No baseline readiness report" in item for item in report["limitations"]
    )


def test_readiness_comparison_uses_the_injected_run(tmp_path):
    baseline = {
        "report_digest": "b" * 64,
        "as_of": "2026-10-15",
        "summary": {"total": 1, "PASS": 1, "FAIL": 0, "BLOCKED": 0, "NOT_APPLICABLE": 0},
        "readiness": {
            "status": "BLOCKED_PROTOCOL_NOT_APPROVED",
            "protocol_execution_authorized": False,
            "model_training_authorized": False,
        },
        "protocol": {"approval_state": "NOT_APPROVED"},
        "checks": [{"id": "INT-01_archive_digests", "status": "PASS", "reasons": []}],
        "designs": [{"id": "A2_EARLIEST_3BLOCK", "verdict": "INFEASIBLE", "protocol_admissible": False, "reason_codes": []}],
    }
    baseline_path = Path(tmp_path) / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    current = json.loads(json.dumps(baseline))
    current["report_digest"] = "c" * 64
    current["as_of"] = "2026-10-20"
    scenario = build_scenario(tmp_path / "run")
    scenario.baseline_report_path = baseline_path
    report = run_refresh(
        scenario.options(readiness_factory=lambda as_of: current)  # noqa: ARG005
    )
    comparison = report["readiness_comparison"]
    assert comparison["baseline"]["available"] is True
    assert comparison["current"]["available"] is True
    assert comparison["checks"]["changed"] == []
    assert comparison["questions"]["report_digest_matches_baseline"] is False
    assert comparison["questions"]["semantic_check_statuses_match_baseline"] is True
