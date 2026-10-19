"""Offline verification must catch tampering and overstated provenance."""

from __future__ import annotations

import copy
import json

from vulnova.acquisition import constants as C
from vulnova.acquisition.manifest import manifest_digest
from vulnova.acquisition.verify import check_coverage, verify_manifest
from vulnova.acquisition.workflow import AcquisitionOptions, run_acquisition

from tests.acquisition_fixtures import CUTOFFS, GRID, RUN_AT, build_scenario


def _manifest(tmp_path):
    scenario = build_scenario(tmp_path)
    options = AcquisitionOptions(
        store=scenario.store,
        transport=scenario.transport,
        api=scenario.api,
        cutoffs=CUTOFFS,
        grid=GRID,
        clock=lambda: RUN_AT,
    )
    return run_acquisition(options), scenario


def _check(result, check_id):
    return next(item for item in result["checks"] if item["id"] == check_id)


def _resign(manifest):
    manifest["manifest_digest"] = manifest_digest(manifest)
    return manifest


def test_clean_manifest_verifies(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    result = verify_manifest(manifest, scenario.store)
    assert result["status"] == C.VERIFIED
    assert result["evidence_status"] == C.BLOCKED  # honest, not an integrity failure


def test_tampered_artifact_is_caught_by_hash(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    record = next(item for item in manifest["records"] if item["artifact_path"])
    path = scenario.store.path(record["artifact_path"])
    path.write_bytes(path.read_bytes() + b"\n")
    result = verify_manifest(manifest, scenario.store)
    assert result["status"] == C.BLOCKED
    check = _check(result, "ARTIFACT_SHA256")
    assert check["status"] == C.BLOCKED
    assert check["reason_code"] == C.SHA256_MISMATCH


def test_missing_artifact_is_caught(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    record = next(item for item in manifest["records"] if item["artifact_path"])
    scenario.store.path(record["artifact_path"]).unlink()
    result = verify_manifest(manifest, scenario.store)
    check = _check(result, "ARTIFACT_PRESENT")
    assert check["status"] == C.BLOCKED
    assert check["reason_code"] == C.ARTIFACT_MISSING


def test_resigned_manifest_still_catches_a_missing_file(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    record = next(item for item in manifest["records"] if item["artifact_path"])
    scenario.store.path(record["artifact_path"]).unlink()
    assert verify_manifest(_resign(manifest), scenario.store)["status"] == C.BLOCKED


def test_edited_digest_is_caught(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["summary"]["records"] = 999
    result = verify_manifest(tampered, scenario.store)
    check = _check(result, "MANIFEST_DIGEST")
    assert check["status"] == C.BLOCKED


def test_backdated_retrieval_time_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    record = next(
        item
        for item in tampered["records"]
        if item["source"] == "cvelistv5" and item["cutoff"]
    )
    record["retrieved_at"] = "2024-01-01T00:00:00Z"
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "RETRIEVAL_AFTER_SOURCE")["status"] == C.BLOCKED


def test_fabricated_contemporaneous_claim_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    record = next(
        item for item in tampered["records"] if item["source"] == "kev" and item["cutoff"]
    )
    record["access_provenance"] = C.CONTEMPORANEOUS
    record["historical_retrieval_verified"] = True
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "ACCESS_PROVENANCE_RECONSISTENT")["status"] == C.BLOCKED
    assert _check(result, "HISTORICAL_RETRIEVAL_NOT_OVERSTATED")["status"] == C.BLOCKED


def test_retrieval_after_manifest_generation_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["generated_at"] = "2026-10-19T00:00:00Z"
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "RETRIEVAL_BEFORE_MANIFEST")["status"] == C.BLOCKED


def test_record_without_a_retrieval_time_but_claiming_access_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    record = next(item for item in tampered["records"] if item["source"] == "kev" and item["cutoff"])
    record["retrieved_at"] = None
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "RETRIEVAL_TIMESTAMP_PRESENT")["status"] == C.BLOCKED


def test_premature_maturity_claim_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["label_observations"]["2026-04-01"]["status"] = C.VERIFIED
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "FINAL_BLOCK_MATURITY_NOT_CLAIMED")["status"] == C.BLOCKED


def test_unknown_schema_version_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["schema_version"] = "vulnova.acquisition/1.6"
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "SCHEMA")["status"] == C.BLOCKED


def test_duplicate_records_are_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["records"].append(copy.deepcopy(tampered["records"][0]))
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "SCHEMA")["status"] == C.BLOCKED


def test_unknown_status_is_rejected(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["records"][0]["content_status"] = "PROBABLY_FINE"
    _resign(tampered)
    result = verify_manifest(tampered, scenario.store)
    assert _check(result, "SCHEMA")["status"] == C.BLOCKED


def test_coverage_flags_a_missing_source_row(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["records"] = [
        record
        for record in tampered["records"]
        if not (record["source"] == "epss" and record["cutoff"] == "2025-09-01")
    ]
    coverage = check_coverage(tampered)
    assert coverage["status"] == C.BLOCKED
    assert any(
        row["source"] == "epss" and row["cutoff"] == "2025-09-01"
        for row in coverage["missing"]
    )


def test_coverage_flags_a_cutoff_outside_the_grid(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    tampered = copy.deepcopy(manifest)
    tampered["cutoffs"].append("2025-03-15")
    coverage = check_coverage(tampered)
    assert coverage["cutoffs_outside_grid"] == ["2025-03-15"]
    assert coverage["status"] == C.BLOCKED


def test_verification_never_touches_the_network(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    calls_before = list(scenario.transport.calls)
    verify_manifest(manifest, scenario.store)
    assert scenario.transport.calls == calls_before


def test_verification_json_is_serialisable(tmp_path):
    manifest, scenario = _manifest(tmp_path)
    result = verify_manifest(manifest, scenario.store)
    assert json.loads(json.dumps(result))["status"] == result["status"]
