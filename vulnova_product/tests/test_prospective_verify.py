"""Offline verification: what it catches, and what it refuses to call success.

Each test tampers with a captured store through the public filesystem, then asks
``verify_store`` what happened.  Tampering that preserves internal consistency
(``_resign``) isolates one check at a time; tampering that does not is exactly
what a real corruption looks like.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.acquisition import constants as A
from vulnova.prospective import constants as C
from vulnova.prospective.capture import _digest, run_capture, run_id_for
from vulnova.prospective.store import ProspectiveStore
from vulnova.prospective.verify import verify_failure_reasons, verify_store

from tests.acquisition_fixtures import kev_catalog_bytes
from tests.prospective_fixtures import build_scenario


def _run_paths(store_root: Path) -> list[Path]:
    return sorted((store_root / "runs").glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _resign(payload: dict) -> None:
    """Recompute the digest and id so only the intended check can fail."""
    payload.pop("run_digest", None)
    payload.pop("run_id", None)
    digest = _digest(payload)
    payload["run_digest"] = digest
    payload["run_id"] = run_id_for(payload["capture_started_at"], digest)
    payload["_renamed_from"] = None
    payload.pop("_renamed_from")


def _verify_after(tmp_path: Path, mutate) -> dict:
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    run_file = _run_paths(scenario.store_root)[0]
    payload = _load(run_file)
    mutate(payload, scenario.store_root)
    _resign(payload)
    new_path = scenario.store_root / "runs" / f"{payload['run_id']}.json"
    _write(new_path, payload)
    if new_path != run_file:
        run_file.unlink()
    return verify_store(scenario.store_root)


# ------------------------------------------------------------- the good path
def test_a_fresh_store_verifies_every_check(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    result = verify_store(scenario.store_root)

    assert result["status"] == A.VERIFIED
    assert result["captures"] == 1
    assert result["artifacts_hashed"] == 3
    assert result["conflicts"] == []
    assert result["network_used"] is False
    assert result["observation_dates"] == ["2026-10-20"]
    for check in result["checks"]:
        assert check["status"] == A.VERIFIED, check
    assert verify_failure_reasons(result) == []


def test_verification_is_repeatable_and_read_only(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    before = {
        path: path.read_bytes()
        for path in scenario.store_root.rglob("*")
        if path.is_file()
    }
    first = verify_store(scenario.store_root)
    second = verify_store(scenario.store_root)
    after = {
        path: path.read_bytes()
        for path in scenario.store_root.rglob("*")
        if path.is_file()
    }
    assert first == second
    assert before == after


def test_an_empty_store_is_not_a_verified_store(tmp_path):
    result = verify_store(tmp_path / "nothing")
    assert result["status"] == A.BLOCKED
    assert result["captures"] == 0
    assert result["checks"][-1]["id"] == "CAPTURES_PRESENT"
    assert result["checks"][-1]["reason_code"] == C.NO_CAPTURES


# --------------------------------------------------------------- tampering
def test_a_tampered_artifact_is_caught(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    artifact = next((scenario.store_root / "artifacts" / "kev").glob("*.json"))
    artifact.write_bytes(artifact.read_bytes() + b" ")

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "ARTIFACTS" in verify_failure_reasons(result)
    check = next(item for item in result["checks"] if item["id"] == "ARTIFACTS")
    assert check["reason_code"] == C.ARTIFACT_TAMPERED


def test_a_deleted_artifact_is_reported_not_ignored(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    artifact = next((scenario.store_root / "artifacts" / "epss").glob("*.csv.gz"))
    artifact.unlink()

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "ARTIFACTS" in verify_failure_reasons(result)


def test_a_tampered_run_record_is_caught(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    run_file = _run_paths(scenario.store_root)[0]
    payload = _load(run_file)
    payload["summary"]["note"] = "edited after the fact"
    _write(run_file, payload)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RUN_DIGEST" in verify_failure_reasons(result)


def test_a_run_filed_under_the_wrong_id_is_caught(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    run_file = _run_paths(scenario.store_root)[0]
    payload = _load(run_file)
    payload["run_id"] = "20260101T000000Z-000000000000"
    payload["run_digest"] = _digest(payload)
    moved = scenario.store_root / "runs" / f"{payload['run_id']}.json"
    _write(moved, payload)
    run_file.unlink()

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RUN_IDENTITY" in verify_failure_reasons(result)


def test_a_historical_cutoff_in_a_prospective_record_is_refused(tmp_path):
    def mutate(payload, _store):
        payload["records"][0]["cutoff"] = "2026-04-01"

    result = _verify_after(tmp_path, mutate)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


def test_a_verified_record_without_an_artifact_is_refused(tmp_path):
    def mutate(payload, _store):
        for record in payload["records"]:
            if record["content_status"] == A.VERIFIED:
                record["artifact_path"] = None
                break

    result = _verify_after(tmp_path, mutate)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)
    check = next(item for item in result["checks"] if item["id"] == "RECORD_INVARIANTS")
    assert "artifact_path" in check["detail"]


def test_a_summary_that_disagrees_with_its_requirements_is_refused(tmp_path):
    def mutate(payload, _store):
        payload["summary"]["capture_status"] = A.VERIFIED
        payload["requirements"][1]["status"] = A.UNAVAILABLE

    result = _verify_after(tmp_path, mutate)
    assert result["status"] == A.BLOCKED
    assert "CAPTURE_STATUS" in verify_failure_reasons(result)


def test_a_checksum_mismatch_in_the_record_is_caught(tmp_path):
    def mutate(payload, _store):
        payload["records"][0]["sha256"] = "0" * 64

    result = _verify_after(tmp_path, mutate)
    assert result["status"] == A.BLOCKED
    assert "ARTIFACTS" in verify_failure_reasons(result)


# --------------------------------------------------------------- conflicts
def test_two_different_captures_of_one_date_are_preserved_as_a_conflict(tmp_path):
    scenario = build_scenario(tmp_path)
    first = run_capture(scenario.options())

    other = build_scenario(
        tmp_path / "other",
        kev_body=kev_catalog_bytes("2026.10.17", "2026-10-17T17:15:48Z"),
    )
    other.store_root = scenario.store_root
    second = run_capture(other.options())

    result = verify_store(scenario.store_root)
    # A disagreement is reported, never resolved and never a failure.
    assert result["status"] == A.VERIFIED
    assert len(result["conflicts"]) == 1
    conflict = result["conflicts"][0]
    assert conflict["kind"] == "kev"
    assert conflict["reason_code"] == C.CONFLICTING_CAPTURES
    assert set(conflict["run_ids"]) == {
        first["run"]["run_id"],
        second["run"]["run_id"],
    }


def test_the_same_capture_twice_is_not_a_conflict(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    run_capture(scenario.options())
    result = verify_store(scenario.store_root)
    assert result["conflicts"] == []
    assert result["status"] == A.VERIFIED


# -------------------------------------------------------------- store safety
def test_verification_refuses_a_traversing_run_name(tmp_path, monkeypatch):
    store = ProspectiveStore(tmp_path / "store")
    monkeypatch.setattr(store, "run_ids", lambda: ["../escape"])
    with pytest.raises(Exception):
        store.read_run("../escape")


def test_verification_of_an_unreadable_run_reports_it(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    run_file = _run_paths(scenario.store_root)[0]
    run_file.write_text("{not json")

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "SCHEMA" in verify_failure_reasons(result)


def test_a_record_that_is_not_an_object_is_reported_not_a_crash(tmp_path):
    def mutate(payload, _store):
        payload["records"].append("not a record")

    result = _verify_after(tmp_path, mutate)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


def test_an_unreadable_capture_instant_is_reported_not_a_crash(tmp_path):
    # The digest still recomputes; only the id derivation is impossible.
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    run_file = _run_paths(scenario.store_root)[0]
    payload = _load(run_file)
    payload["capture_started_at"] = "not-a-time"
    payload["run_digest"] = _digest(payload)
    _write(run_file, payload)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RUN_IDENTITY" in verify_failure_reasons(result)
    assert "RUN_DIGEST" not in verify_failure_reasons(result)


def test_a_requirements_block_that_is_not_a_list_is_reported(tmp_path):
    def mutate(payload, _store):
        payload["requirements"] = {"KEV-CAPTURE": "VERIFIED"}

    result = _verify_after(tmp_path, mutate)
    assert result["status"] == A.BLOCKED
    assert "CAPTURE_STATUS" in verify_failure_reasons(result)
