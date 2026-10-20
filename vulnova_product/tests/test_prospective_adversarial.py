"""Adversarial tests for the three 1.9 findings.

Each test starts from a real, captured store and then damages it the way a crash,
a partial write, a corrupted disk or a hand-edited JSON file would.  The rules
under test are deliberately blunt:

* a filesystem without hard links cannot store evidence at all;
* a malformed run is never summarized under the status it claims;
* an artifact is inventoried because it exists, not because a run mentions it.

The verification and report entry points are exercised through the API and the
CLI, because both are public surfaces.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

from vulnova.acquisition import constants as A
from vulnova.prospective import cli
from vulnova.prospective import constants as C
from vulnova.prospective.capture import CaptureError, _digest, run_capture, run_id_for
from vulnova.prospective.report import build_report, render_markdown, verify_digest
from vulnova.prospective.store import ProspectiveStore, atomic_create
from vulnova.prospective.verify import verify_failure_reasons, verify_store


# ------------------------------------------------------------------ helpers
def _captured(tmp_path: Path):
    from tests.prospective_fixtures import build_scenario

    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    return scenario


def _run_file(store_root: Path) -> Path:
    return sorted((store_root / "runs").glob("*.json"))[0]


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _rewrite(scenario, mutate, *, resign: bool = True) -> Path:
    """Apply ``mutate`` to the stored run, optionally re-signing it.

    Re-signing removes the digest mismatch so the test isolates the field it
    actually damaged; leaving it alone models a hand edit that was not re-signed.
    """
    run_file = _run_file(scenario.store_root)
    payload = _load(run_file)
    mutate(payload)
    if resign:
        payload.pop("run_digest", None)
        payload.pop("run_id", None)
        digest = _digest(payload)
        payload["run_digest"] = digest
        payload["run_id"] = run_id_for(payload["capture_started_at"], digest)
        new_path = scenario.store_root / "runs" / f"{payload['run_id']}.json"
        _write(new_path, payload)
        if new_path != run_file:
            run_file.unlink()
        return new_path
    _write(run_file, payload)
    return run_file


def _check(result: dict, check_id: str) -> dict:
    return next(item for item in result["checks"] if item["id"] == check_id)


def _orphan(store_root: Path, kind: str, body: bytes) -> Path:
    """Write a perfectly valid, content-addressed artifact nobody references."""
    digest = hashlib.sha256(body).hexdigest()
    path = store_root / "artifacts" / kind / f"{digest}{C.ARTIFACT_SUFFIX[kind]}"
    path.write_bytes(body)
    return path


# ----------------------------------------------- FINDING 1: atomic evidence
def test_a_capture_on_a_link_less_filesystem_writes_no_evidence(tmp_path, monkeypatch):
    """The integration path fails closed too, not just the primitive."""
    from tests.prospective_fixtures import build_scenario

    scenario = build_scenario(tmp_path)

    def no_links(*args, **kwargs):  # noqa: ARG001
        raise OSError(errno.EOPNOTSUPP, "Operation not supported")

    monkeypatch.setattr(os, "link", no_links)
    with pytest.raises(CaptureError) as excinfo:
        run_capture(scenario.options())

    assert C.ATOMIC_CREATE_UNAVAILABLE in str(excinfo.value)
    files = [path for path in scenario.store_root.rglob("*") if path.is_file()]
    assert files == [], "a refused capture must not leave partial evidence behind"
    assert not list(scenario.store_root.rglob(".tmp-*"))


def test_an_interrupted_write_is_reported_as_an_abandoned_temporary(tmp_path):
    """A kill -9 between mkstemp and link leaves a temp; verification says so."""
    scenario = _captured(tmp_path)
    leftover = scenario.store_root / "artifacts" / "kev" / ".tmp-deadbeef"
    leftover.write_bytes(b"half a catalog")

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    inventory = _check(result, "STORE_INVENTORY")
    assert inventory["reason_code"] == C.ABANDONED_TEMPORARY_FILE
    assert result["inventory"]["counts"]["temporary"] == 1
    assert f"artifacts/kev/{leftover.name}" in result["inventory"]["temporary"]


def test_a_store_that_cannot_link_leaves_its_existing_bytes_untouched(tmp_path, monkeypatch):
    store_root = tmp_path / "store"
    store = ProspectiveStore(store_root)
    stored = store.store_artifact(C.KEV, b"catalog")
    path = store_root / stored.relative_path
    before = path.read_bytes()

    def no_links(*args, **kwargs):  # noqa: ARG001
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    assert atomic_create(path, b"catalog") == "identical"
    with pytest.raises(Exception):
        atomic_create(path, b"a different catalog")
    assert path.read_bytes() == before


# ------------------------------------------- FINDING 3: artifact inventory
def test_a_valid_unreferenced_artifact_fails_the_inventory(tmp_path):
    scenario = _captured(tmp_path)
    orphan = _orphan(scenario.store_root, C.KEV, b'{"orphan": true}')

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    check = _check(result, "STORE_INVENTORY")
    assert check["status"] == A.BLOCKED
    assert check["reason_code"] == C.UNREFERENCED_ARTIFACT
    inventory = result["inventory"]
    assert inventory["counts"]["unreferenced"] == 1
    assert inventory["unreferenced"] == [f"artifacts/kev/{orphan.name}"]
    assert result["artifacts_unreferenced"] == 1
    # The bytes are intact, so the referenced artifacts still verify.
    assert _check(result, "ARTIFACTS")["status"] == A.VERIFIED


def test_a_filename_that_lies_about_its_bytes_is_corruption(tmp_path):
    scenario = _captured(tmp_path)
    declared = hashlib.sha256(b"declared").hexdigest()
    path = scenario.store_root / "artifacts" / "epss" / f"{declared}.csv.gz"
    path.write_bytes(b"completely different bytes")

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    check = _check(result, "STORE_INVENTORY")
    assert check["reason_code"] == C.ARTIFACT_TAMPERED
    assert result["inventory"]["counts"]["corrupt"] == 1


def test_two_orphans_are_counted_exactly(tmp_path):
    scenario = _captured(tmp_path)
    _orphan(scenario.store_root, C.KEV, b"first orphan")
    _orphan(scenario.store_root, C.EPSS, b"second orphan")

    result = verify_store(scenario.store_root)
    assert result["inventory"]["counts"]["unreferenced"] == 2
    assert result["artifacts_unreferenced"] == 2
    assert result["artifacts_hashed"] == 5
    assert result["artifacts_referenced"] == 3


def test_a_vanished_run_record_cannot_hide_its_artifacts(tmp_path):
    scenario = _captured(tmp_path)
    _run_file(scenario.store_root).unlink()

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "CAPTURES_PRESENT" in verify_failure_reasons(result)
    assert result["inventory"]["counts"]["unreferenced"] == 3
    assert result["artifacts_referenced"] == 0


def test_a_missing_referenced_artifact_is_reported_as_missing(tmp_path):
    scenario = _captured(tmp_path)
    artifact = next((scenario.store_root / "artifacts" / "kev").glob("*.json"))
    artifact.unlink()

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "ARTIFACTS" in verify_failure_reasons(result)
    inventory = _check(result, "STORE_INVENTORY")
    assert inventory["reason_code"] == A.ARTIFACT_MISSING
    assert result["inventory"]["counts"]["missing"] == 1


def test_an_unexpected_file_is_not_silently_ignored(tmp_path):
    scenario = _captured(tmp_path)
    (scenario.store_root / "artifacts" / "kev" / "notes.txt").write_text("hello")

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    check = _check(result, "STORE_INVENTORY")
    assert check["reason_code"] == C.UNEXPECTED_ARTIFACT
    assert result["inventory"]["counts"]["unexpected"] == 1


def test_a_symlink_cannot_pull_content_into_the_store(tmp_path):
    scenario = _captured(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"secret bytes outside the store")
    digest = hashlib.sha256(b"claimed").hexdigest()
    link = scenario.store_root / "artifacts" / "kev" / f"{digest}.json"
    link.symlink_to(outside)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    check = _check(result, "STORE_INVENTORY")
    assert check["reason_code"] == C.UNSAFE_ARTIFACT_PATH
    assert result["inventory"]["counts"]["unsafe"] == 1
    # The outside bytes were never hashed as if they were evidence.
    assert result["artifacts_hashed"] == 3
    assert str(outside) not in json.dumps(result)


def test_a_symlinked_artifact_directory_is_refused(tmp_path):
    scenario = _captured(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "planted.json").write_text('{"planted": true}')
    real = scenario.store_root / "artifacts" / "epss"
    for path in real.iterdir():
        path.unlink()
    real.rmdir()
    real.symlink_to(outside, target_is_directory=True)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert _check(result, "STORE_INVENTORY")["reason_code"] == C.UNSAFE_ARTIFACT_PATH
    assert result["inventory"]["counts"]["unsafe"] == 1


def test_a_directory_where_an_artifact_belongs_is_unexpected(tmp_path):
    scenario = _captured(tmp_path)
    digest = hashlib.sha256(b"nested").hexdigest()
    (scenario.store_root / "artifacts" / "kev" / f"{digest}.json").mkdir()

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert _check(result, "STORE_INVENTORY")["reason_code"] == C.UNEXPECTED_ARTIFACT


def test_a_symlinked_run_record_is_refused_not_followed(tmp_path):
    scenario = _captured(tmp_path)
    run_file = _run_file(scenario.store_root)
    outside = tmp_path / "outside-run.json"
    outside.write_bytes(run_file.read_bytes())
    run_file.unlink()
    run_file.symlink_to(outside)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "CAPTURES_PRESENT" in verify_failure_reasons(result)
    assert _check(result, "STORE_INVENTORY")["reason_code"] == C.UNSAFE_ARTIFACT_PATH
    assert str(outside) not in json.dumps(result)


def test_inventory_is_deterministic_and_read_only(tmp_path):
    scenario = _captured(tmp_path)
    _orphan(scenario.store_root, C.KEV, b"deterministic orphan")
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


def test_the_cli_reports_unreferenced_artifacts_and_exits_one(tmp_path, capsys):
    scenario = _captured(tmp_path)
    _orphan(scenario.store_root, C.KEV, b"cli orphan")

    assert cli.main(["verify", "--store", str(scenario.store_root), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == A.BLOCKED
    assert payload["inventory"]["counts"]["unreferenced"] == 1

    assert cli.main(["verify", "--store", str(scenario.store_root)]) == 1
    assert "1 unreferenced" in capsys.readouterr().out


# -------------------------------------------- FINDING 2: malformed run data
def test_a_status_that_is_a_list_does_not_crash_the_report(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["summary"].__setitem__("capture_status", []), resign=False)

    report = build_report(scenario.store_root)
    assert report["captures"] == 1
    assert report["malformed_captures"] == 1
    assert report["status_counts"][A.BLOCKED] == 1
    assert report["status_counts"][A.VERIFIED] == 0
    assert any("capture_status" in problem for problem in report["malformed_runs"][0]["problems"])
    assert verify_digest(report)[0] is True


def test_an_invented_status_is_never_counted_as_a_status(tmp_path):
    scenario = _captured(tmp_path)

    def mutate(run):
        run["summary"]["capture_status"] = "MADE_UP_STATUS"
        run["requirements"][0]["status"] = "MADE_UP_STATUS"

    _rewrite(scenario, mutate)
    report = build_report(scenario.store_root)
    assert "MADE_UP_STATUS" not in report["status_counts"]
    assert report["status_counts"] == {A.VERIFIED: 0, A.UNAVAILABLE: 0, A.BLOCKED: 1}
    assert report["malformed_captures"] == 1
    assert report["days"] == []


def test_duplicate_requirement_entries_are_refused(tmp_path):
    scenario = _captured(tmp_path)

    def mutate(run):
        duplicate = json.loads(json.dumps(run["requirements"][0]))
        run["requirements"].append(duplicate)

    _rewrite(scenario, mutate)
    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert any("duplicate" in problem for problem in report["malformed_runs"][0]["problems"])
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    # The extra entry makes the requirement count disagree with the summary.
    assert "CAPTURE_STATUS" in verify_failure_reasons(result)


def test_a_requirement_status_that_is_an_object_is_refused(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["requirements"][0].__setitem__("status", {}))
    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert report["sources"]["kev"] == {A.VERIFIED: 0, A.UNAVAILABLE: 0, A.BLOCKED: 0}
    assert report["days"] == []


def test_requirements_that_are_not_a_list_are_refused(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run.__setitem__("requirements", {"KEV-CAPTURE": "VERIFIED"}))
    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert any("requirements is not a list" in problem for problem in report["malformed_runs"][0]["problems"])


@pytest.mark.parametrize("records", [{}, None, "a string of records", [], 7])
def test_records_of_every_wrong_shape_are_refused(tmp_path, records):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run.__setitem__("records", records))
    report = build_report(scenario.store_root)
    assert report["captures"] == 1
    assert report["malformed_captures"] == 1
    assert report["days"] == []

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


def test_a_record_path_that_escapes_the_store_is_malformed(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["records"][0].__setitem__("artifact_path", "../../etc/passwd"))

    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert any(
        "artifact_path" in problem for problem in report["malformed_runs"][0]["problems"]
    )
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


def test_bad_hashes_sizes_and_timestamps_are_named(tmp_path):
    scenario = _captured(tmp_path)

    def mutate(run):
        run["records"][0]["sha256"] = "NOT-A-DIGEST"
        run["records"][1]["bytes"] = -1
        run["records"][2]["retrieved_at"] = "not-a-time"

    _rewrite(scenario, mutate)
    report = build_report(scenario.store_root)
    problems = " ".join(report["malformed_runs"][0]["problems"])
    assert "sha256" in problems
    assert "bytes" in problems
    assert "retrieved_at" in problems
    assert report["status_counts"][A.VERIFIED] == 0

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", 123),
        ("observation_date", 123),
        ("capture_completed_at", None),
    ],
)
def test_wrong_typed_top_level_fields_do_not_crash(tmp_path, field, value):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run.__setitem__(field, value), resign=False)
    report = build_report(scenario.store_root)
    assert report["captures"] == 1
    assert report["malformed_captures"] == 1
    assert report["status_counts"][A.BLOCKED] == 1
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "SCHEMA" in verify_failure_reasons(result)


def test_missing_fields_are_named_not_guessed(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run.pop("honesty"))
    report = build_report(scenario.store_root)
    assert any("missing field" in problem for problem in report["malformed_runs"][0]["problems"])
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert any("missing field" in check["detail"] for check in result["checks"])


def test_unexpected_fields_are_refused(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run.__setitem__("surprise", {"not": "in 1.9"}))
    report = build_report(scenario.store_root)
    assert any("unexpected field" in problem for problem in report["malformed_runs"][0]["problems"])
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "SCHEMA" in verify_failure_reasons(result)


def test_a_summary_counter_that_disagrees_with_the_requirements_is_refused(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["summary"].__setitem__("sources_verified", 0))
    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert any("sources_verified" in problem for problem in report["malformed_runs"][0]["problems"])
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "CAPTURE_STATUS" in verify_failure_reasons(result)


def test_many_malformed_records_in_one_store_are_all_reported(tmp_path):
    scenario = _captured(tmp_path)
    original = _load(_run_file(scenario.store_root))

    # A second, malformed run file beside the valid one.
    second = json.loads(json.dumps(original))
    second["summary"]["capture_status"] = []
    second["run_id"] = "20261021T140000Z-111111111111"
    second["run_digest"] = "0" * 64
    _write(scenario.store_root / "runs" / f"{second['run_id']}.json", second)

    # A third file that is not JSON at all.
    (scenario.store_root / "runs" / "20261022T140000Z-222222222222.json").write_text("{oops")

    report = build_report(scenario.store_root)
    assert report["captures"] == 2
    assert report["captures_well_formed"] == 1
    assert report["malformed_captures"] == 1
    assert len(report["malformed_runs"]) == 1
    assert len(report["unreadable_runs"]) == 1
    assert report["status_counts"] == {A.VERIFIED: 1, A.UNAVAILABLE: 0, A.BLOCKED: 1}
    # Every capture is accounted for exactly once: a well-formed run under its
    # validated status, a malformed one as BLOCKED.  The malformed count is a
    # subset of the BLOCKED count, never an additional category.
    assert sum(report["status_counts"].values()) == report["captures"]
    assert report["malformed_captures"] <= report["status_counts"][A.BLOCKED]
    assert verify_digest(report)[0] is True

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED

    assert cli.main(["report", "--store", str(scenario.store_root)]) == 0
    markdown = render_markdown(report)
    assert "Malformed runs" in markdown
    assert "Unreadable runs" in markdown


def test_a_malformed_store_report_is_deterministic_and_path_free(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["summary"].__setitem__("capture_status", []), resign=False)

    first = build_report(scenario.store_root)
    second = build_report(scenario.store_root)
    assert first == second
    body = json.dumps(first, sort_keys=True)
    assert str(tmp_path) not in body
    assert "/home/" not in body
    assert str(tmp_path) not in render_markdown(first)


def test_the_cli_reports_a_malformed_store_without_crashing(tmp_path, capsys):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["summary"].__setitem__("capture_status", {}), resign=False)

    assert cli.main(["verify", "--store", str(scenario.store_root)]) == 1
    assert "BLOCKED" in capsys.readouterr().out

    assert cli.main(["report", "--store", str(scenario.store_root)]) == 0
    assert "Malformed runs" in capsys.readouterr().out

    out = tmp_path / "report.json"
    assert (
        cli.main(
            ["report", "--store", str(scenario.store_root), "--json", "--out", str(out)]
        )
        == 0
    )
    payload = json.loads(out.read_text())
    assert payload["malformed_captures"] == 1
    assert verify_digest(payload)[0] is True


def test_an_untouched_valid_run_reports_exactly_as_before(tmp_path):
    """The hardening must not change what a sound store reports."""
    scenario = _captured(tmp_path)
    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 0
    assert report["malformed_runs"] == []
    assert report["status_counts"] == {A.VERIFIED: 1, A.UNAVAILABLE: 0, A.BLOCKED: 0}
    assert report["days"][0]["kev"] == A.VERIFIED
    assert verify_store(scenario.store_root)["status"] == A.VERIFIED


# ------------------------------------- unhashable JSON values, end to end
def test_an_unhashable_requirement_id_is_refused_not_a_crash(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["requirements"][0].__setitem__("id", []))

    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert report["status_counts"][A.BLOCKED] == 1
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "CAPTURE_STATUS" in verify_failure_reasons(result)


def test_an_unhashable_record_source_is_refused_not_a_crash(tmp_path):
    scenario = _captured(tmp_path)
    _rewrite(scenario, lambda run: run["records"][0].__setitem__("source", {}))

    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


def test_a_verified_record_without_its_evidence_fields_is_malformed(tmp_path):
    scenario = _captured(tmp_path)

    def mutate(run):
        record = next(
            item for item in run["records"] if item["content_status"] == A.VERIFIED
        )
        record["sha256"] = None
        record["artifact_path"] = None

    _rewrite(scenario, mutate)
    report = build_report(scenario.store_root)
    problems = " ".join(report["malformed_runs"][0]["problems"])
    assert "VERIFIED but missing artifact_path" in problems
    assert "VERIFIED but missing sha256" in problems
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)


def test_a_symlinked_run_directory_is_refused_not_followed(tmp_path):
    """The run directory itself can be a trap; verification never follows it."""
    scenario = _captured(tmp_path)
    real = scenario.store_root / "runs"
    outside = tmp_path / "runs-outside"
    real.rename(outside)
    real.symlink_to(outside, target_is_directory=True)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "CAPTURES_PRESENT" in verify_failure_reasons(result)
    assert _check(result, "STORE_INVENTORY")["reason_code"] == C.UNSAFE_ARTIFACT_PATH

    report = build_report(scenario.store_root)
    assert report["captures"] == 0
    assert report["unreadable_runs"]
    markdown = render_markdown(report)
    assert "No capture could be read" in markdown
    assert "evidence of absence" in markdown
    assert "empty store" not in markdown


def test_a_symlinked_artifacts_directory_is_refused(tmp_path):
    scenario = _captured(tmp_path)
    real = scenario.store_root / "artifacts"
    outside = tmp_path / "artifacts-outside"
    real.rename(outside)
    real.symlink_to(outside, target_is_directory=True)

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert _check(result, "STORE_INVENTORY")["reason_code"] == C.UNSAFE_ARTIFACT_PATH
    assert result["artifacts_hashed"] == 0


def test_an_artifact_path_for_the_wrong_kind_is_malformed(tmp_path):
    """A KEV record may not point at the EPSS file, even if the bytes match."""
    scenario = _captured(tmp_path)
    epss = next((scenario.store_root / "artifacts" / "epss").glob("*.csv.gz"))
    body = epss.read_bytes()

    def mutate(run):
        record = next(
            item
            for item in run["records"]
            if item["source"] == "kev" and item["artifact_path"]
        )
        record["artifact_path"] = f"artifacts/epss/{epss.name}"
        record["sha256"] = hashlib.sha256(body).hexdigest()
        record["bytes"] = len(body)

    _rewrite(scenario, mutate)
    report = build_report(scenario.store_root)
    assert report["malformed_captures"] == 1
    assert any(
        "is not under artifacts/kev/" in problem
        for problem in report["malformed_runs"][0]["problems"]
    )
    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "RECORD_INVARIANTS" in verify_failure_reasons(result)
