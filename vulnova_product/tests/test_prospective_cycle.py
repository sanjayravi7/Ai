"""The scheduled cycle: one capture, one verification, one exit status.

Every test drives the real ``run_cycle`` against canned responses and an injected
clock.  No test opens a socket — ``tests/conftest.py`` fails any connection to a
non-loopback address — and no test depends on a publisher being reachable.

The exit status is the contract a scheduler depends on, so it is asserted
explicitly in every case: ``0`` verified, ``2`` nothing recorded, ``3`` recorded
but incomplete, ``4`` the store did not verify.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from vulnova.acquisition import constants as A
from vulnova.prospective import cli as cli_module
from vulnova.prospective import constants as C
from vulnova.prospective.cycle import (
    EXIT_INCOMPLETE,
    EXIT_INTEGRITY,
    EXIT_NOT_RECORDED,
    EXIT_OK,
    REASON_INCOMPLETE,
    REASON_INTEGRITY,
    REASON_NOT_RECORDED,
    REASON_OK,
    REASON_REPORT,
    REASON_UNSAFE,
    CycleOptions,
    run_cycle,
)
from vulnova.prospective.report import build_report
from vulnova.prospective.verify import verify_store

from tests.acquisition_fixtures import epss_url
from tests.prospective_fixtures import DEFAULT_AS_OF, build_scenario

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
OBSERVATION = dt.date.fromisoformat(DEFAULT_AS_OF[:10])


def _cycle(scenario, *, report_path=None, report_format="markdown", clock=None):
    """Drive the real cycle with the scenario's fake transport and clock."""
    base = scenario.options()
    return run_cycle(
        CycleOptions(
            store_root=base.store_root,
            transport=base.transport,
            api=base.api,
            clock=base.clock if clock is None else clock,
            protected_paths=base.protected_paths,
            report_path=report_path,
            report_format=report_format,
        )
    )


def _source(result: dict, requirement_id: str) -> dict:
    return {item["id"]: item for item in result["sources"]}[requirement_id]


def _later_clock(start: str = "2026-10-20T15:00:00Z") -> callable:
    ticks = iter([start, "2026-10-20T15:00:07Z"])
    return lambda: next(ticks, "2026-10-20T15:00:07Z")


def _run_files(store_root: Path) -> list[Path]:
    return sorted((store_root / "runs").glob("*.json"))


# ------------------------------------------------------------------ healthy
def test_a_healthy_cycle_records_verifies_and_reports(tmp_path):
    scenario = build_scenario(tmp_path)
    result = _cycle(scenario)

    assert result["exit_code"] == EXIT_OK == 0
    assert result["reason"] == REASON_OK
    assert result["capture_attempted"] is True
    assert result["capture_recorded"] is True
    assert result["outcome"] == C.OUTCOME_CAPTURED
    assert result["observation_date"] == OBSERVATION.isoformat()
    assert result["capture_status"] == A.VERIFIED
    assert result["sources_verified"] == result["sources_total"] == 3
    assert [item["status"] for item in result["sources"]] == [A.VERIFIED] * 3
    assert result["integrity"]["status"] == A.VERIFIED
    assert result["integrity"]["captures"] == 1
    assert result["integrity"]["failed_checks"] == []
    assert result["report_digest"]
    assert result["error"] is None
    assert len(_run_files(scenario.store_root)) == 1


def test_the_cycle_report_digest_is_the_report_command_digest(tmp_path):
    scenario = build_scenario(tmp_path)
    result = _cycle(scenario)

    # One store, two ways of asking: the cycle must not invent a second format.
    assert result["report_digest"] == build_report(scenario.store_root)["report_digest"]
    assert verify_store(scenario.store_root)["status"] == A.VERIFIED


def test_the_result_carries_the_run_and_every_reason_code(tmp_path):
    scenario = build_scenario(tmp_path)
    result = _cycle(scenario)

    run_id = result["run_id"]
    assert run_id.startswith("20261020T140000Z-")
    assert result["capture_started_at"] == DEFAULT_AS_OF
    assert {item["id"] for item in result["sources"]} == {
        C.KEV_REQUIREMENT,
        C.EPSS_REQUIREMENT,
        C.CVELISTV5_REQUIREMENT,
    }
    for item in result["sources"]:
        assert item["reason_code"] == A.OK_VERIFIED, item
        assert item["detail"], item


# ------------------------------------------------------------------ partial
def test_a_partial_cycle_is_recorded_and_exits_incomplete(tmp_path):
    scenario = build_scenario(tmp_path, epss="unavailable")
    result = _cycle(scenario)

    assert result["exit_code"] == EXIT_INCOMPLETE == 3
    assert result["reason"] == REASON_INCOMPLETE
    # The run is evidence that an attempt happened; it is not rolled back.
    assert result["capture_recorded"] is True
    assert len(_run_files(scenario.store_root)) == 1
    assert result["capture_status"] == A.UNAVAILABLE
    assert result["sources_verified"] == 2

    epss = _source(result, C.EPSS_REQUIREMENT)
    assert epss["status"] == A.UNAVAILABLE
    assert epss["reason_code"] == A.OFFICIAL_SOURCE_UNREACHABLE
    # The store is intact; only the observation has a gap.
    assert result["integrity"]["status"] == A.VERIFIED


def test_a_blocked_epss_redirect_is_recorded_and_exits_incomplete(tmp_path):
    scenario = build_scenario(
        tmp_path,
        epss_redirect="https://www.first.org/epss/epss_scores-2026-10-20.csv.gz",
    )
    result = _cycle(scenario)

    assert result["exit_code"] == EXIT_INCOMPLETE
    assert result["capture_recorded"] is True
    assert result["capture_status"] == A.BLOCKED
    epss = _source(result, C.EPSS_REQUIREMENT)
    assert epss["status"] == A.BLOCKED
    assert epss["reason_code"] == A.REDIRECT_BLOCKED
    # A refused response is never stored, and nothing was substituted for it.
    epss_artifacts = list((scenario.store_root / "artifacts" / C.EPSS).glob("*"))
    assert epss_artifacts == []
    assert result["integrity"]["status"] == A.VERIFIED


def test_a_missing_epss_file_is_not_a_claim_that_nothing_was_exploited(tmp_path):
    scenario = build_scenario(tmp_path, epss="missing")
    result = _cycle(scenario)

    assert result["exit_code"] == EXIT_INCOMPLETE
    assert _source(result, C.EPSS_REQUIREMENT)["reason_code"] == A.EPSS_FILE_MISSING
    assert "not_exploited" not in json.dumps(result).lower()
    assert "gap in observation" in result["note"]


# ------------------------------------------------------- store not recorded
def test_a_capture_that_cannot_be_recorded_says_so_and_exits_two(tmp_path):
    scenario = build_scenario(tmp_path)
    backwards = iter(["2026-10-20T15:00:00Z", "2026-10-20T14:00:00Z"])
    result = _cycle(scenario, clock=lambda: next(backwards, "2026-10-20T14:00:00Z"))

    assert result["exit_code"] == EXIT_NOT_RECORDED == 2
    assert result["reason"] == REASON_NOT_RECORDED
    assert result["capture_attempted"] is True
    # Nothing was recorded, and the result says exactly that.
    assert result["capture_recorded"] is False
    assert result["run_id"] is None
    assert result["integrity"] is None
    assert result["report_digest"] is None
    assert "moved backwards" in result["error"]
    assert _run_files(scenario.store_root) == [] or not _run_files(scenario.store_root)


# ------------------------------------------------------------- integrity
def test_a_tampered_store_fails_integrity_but_keeps_the_new_capture(tmp_path):
    scenario = build_scenario(tmp_path)
    first = _cycle(scenario)
    assert first["exit_code"] == EXIT_OK

    # Rewrite one field of the stored run without re-signing it.  The bytes stay
    # valid JSON, so only the digest and identity checks can catch it.
    path = _run_files(scenario.store_root)[0]
    payload = json.loads(path.read_text())
    payload["summary"]["sources_verified"] = 1
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    second = _cycle(scenario, clock=_later_clock())

    assert second["exit_code"] == EXIT_INTEGRITY == 4
    assert second["reason"] == REASON_INTEGRITY
    # The second run was still written: a failed verification never deletes it.
    assert second["capture_recorded"] is True
    assert len(_run_files(scenario.store_root)) == 2
    assert second["integrity"]["status"] == A.BLOCKED
    assert "RUN_DIGEST" in second["integrity"]["failed_checks"]
    assert second["error"] is None


def test_a_malformed_run_file_fails_integrity(tmp_path):
    scenario = build_scenario(tmp_path)
    assert _cycle(scenario)["exit_code"] == EXIT_OK

    _run_files(scenario.store_root)[0].write_text("{ not valid json")

    result = _cycle(scenario, clock=_later_clock())

    assert result["exit_code"] == EXIT_INTEGRITY
    assert result["reason"] == REASON_INTEGRITY
    assert result["capture_recorded"] is True
    assert "SCHEMA" in result["integrity"]["failed_checks"]


def test_an_orphaned_artifact_fails_integrity_without_deleting_it(tmp_path):
    scenario = build_scenario(tmp_path)
    assert _cycle(scenario)["exit_code"] == EXIT_OK

    # Bytes whose name is their own digest but that no run record mentions: an
    # incomplete capture, not corruption.  Deleting it would erase the only
    # proof that the capture happened, so the cycle reports it instead.
    blob = b'{"synthetic": "orphan"}'
    digest = hashlib.sha256(blob).hexdigest()
    orphan = scenario.store_root / "artifacts" / C.KEV / f"{digest}.json"
    orphan.write_bytes(blob)

    result = _cycle(scenario, clock=_later_clock())

    assert result["exit_code"] == EXIT_INTEGRITY
    assert result["reason"] == REASON_INTEGRITY
    assert result["capture_recorded"] is True
    assert "STORE_INVENTORY" in result["integrity"]["failed_checks"]
    # Nothing was cleaned up to make the check pass.
    assert orphan.is_file()


def test_a_verifier_crash_is_reported_as_an_integrity_failure(monkeypatch, tmp_path):
    scenario = build_scenario(tmp_path)

    def boom(_store):
        raise RuntimeError("the verifier crashed")

    monkeypatch.setattr("vulnova.prospective.cycle.verify_store", boom)
    result = _cycle(scenario)

    assert result["exit_code"] == EXIT_INTEGRITY
    assert result["reason"] == REASON_INTEGRITY
    assert result["capture_recorded"] is True
    # No numbers are invented for a store that was never read.
    assert result["integrity"] is None
    assert "the verifier crashed" in result["error"]


def test_the_cli_survives_a_verifier_crash(monkeypatch, capsys, tmp_path):
    scenario = build_scenario(tmp_path)
    _wire_cli(monkeypatch, scenario)
    monkeypatch.setattr(
        "vulnova.prospective.cycle.verify_store",
        lambda _store: (_ for _ in ()).throw(RuntimeError("the verifier crashed")),
    )

    code = cli_module.main(["cycle", "--store", str(scenario.store_root)])

    out = capsys.readouterr().out
    assert code == EXIT_INTEGRITY
    assert "integrity: NOT ESTABLISHED" in out
    assert "result: INTEGRITY_FAILED" in out


# ------------------------------------------------------------- safety first
def test_an_unsafe_store_is_refused_before_any_request(tmp_path):
    scenario = build_scenario(tmp_path)
    store = PRODUCT_ROOT / "protocol" / "cycle-store"

    result = run_cycle(
        CycleOptions(
            store_root=store,
            transport=scenario.transport,
            api=scenario.api,
            clock=scenario.options().clock,
        )
    )

    assert result["exit_code"] == EXIT_NOT_RECORDED
    assert result["reason"] == REASON_UNSAFE
    assert result["capture_attempted"] is False
    assert result["capture_recorded"] is False
    assert C.STORE_OVERLAPS_PROTECTED in result["error"]
    # The proof that matters: the transport was never asked for anything.
    assert scenario.transport.calls == []
    assert not store.exists()


def test_an_output_inside_the_store_is_refused_before_any_request(tmp_path):
    scenario = build_scenario(tmp_path)
    result = _cycle(scenario, report_path=scenario.store_root / "report.md")

    assert result["exit_code"] == EXIT_NOT_RECORDED
    assert result["reason"] == REASON_UNSAFE
    assert "OUTPUT_PATHS_COLLIDE" in result["error"]
    assert scenario.transport.calls == []
    assert not (scenario.store_root / "report.md").exists()


def test_a_report_target_inside_a_sealed_path_is_refused(tmp_path):
    scenario = build_scenario(tmp_path)
    sealed = PRODUCT_ROOT / "protocol" / "cycle-report.md"

    result = _cycle(scenario, report_path=sealed)

    assert result["exit_code"] == EXIT_NOT_RECORDED
    assert result["reason"] == REASON_UNSAFE
    assert "OUTPUT_OVERLAPS_PROTECTED" in result["error"]
    assert scenario.transport.calls == []
    assert not sealed.exists()


# ------------------------------------------------------------ no retrying
def test_a_failed_source_is_requested_exactly_once(tmp_path):
    scenario = build_scenario(tmp_path, epss="unavailable")
    _cycle(scenario)

    calls = scenario.transport.calls
    assert calls.count(epss_url(OBSERVATION)) == 1
    # Six requests for one cycle: CISA feed, KEV commit/tree/blob, EPSS, cvelistV5.
    assert len(calls) == 6
    assert calls.count(calls[0]) == 1


def test_a_cycle_runs_its_capture_once_even_when_the_store_fails_verification(tmp_path):
    scenario = build_scenario(tmp_path)
    _cycle(scenario)
    _run_files(scenario.store_root)[0].write_text("{ not valid json")
    before = len(scenario.transport.calls)

    _cycle(scenario, clock=_later_clock())

    # The second cycle issued one more request set, not a retry loop over it.
    assert len(scenario.transport.calls) - before == 6


# ------------------------------------------------------------- idempotent
def test_repeating_the_cycle_at_the_same_instant_is_idempotent(tmp_path):
    scenario = build_scenario(tmp_path)
    first = _cycle(scenario)
    second = _cycle(scenario)

    assert first["exit_code"] == second["exit_code"] == EXIT_OK
    assert second["outcome"] == C.OUTCOME_ALREADY_CAPTURED
    assert second["run_id"] == first["run_id"]
    assert second["report_digest"] == first["report_digest"]
    assert second["integrity"]["captures"] == 1
    assert len(_run_files(scenario.store_root)) == 1


# --------------------------------------------------------------- reporting
def test_the_cycle_writes_the_markdown_report(tmp_path):
    scenario = build_scenario(tmp_path)
    report_path = scenario.root / "cycle.md"

    result = _cycle(scenario, report_path=report_path)

    assert result["exit_code"] == EXIT_OK
    assert result["report_written"] is True
    body = report_path.read_text()
    assert result["report_digest"] in body
    assert body.startswith("# VULNOVA 1.9 — prospective evidence capture")


def test_the_cycle_writes_a_json_report(tmp_path):
    scenario = build_scenario(tmp_path)
    report_path = scenario.root / "cycle.json"

    result = _cycle(scenario, report_path=report_path, report_format="json")

    assert result["report_written"] is True
    payload = json.loads(report_path.read_text())
    assert payload["report_digest"] == result["report_digest"]


def test_a_report_that_cannot_be_written_keeps_the_capture(tmp_path):
    scenario = build_scenario(tmp_path)
    blocker = scenario.root / "not-a-directory"
    blocker.write_text("in the way")

    result = _cycle(scenario, report_path=blocker / "cycle.md")

    assert result["exit_code"] == EXIT_NOT_RECORDED
    assert result["reason"] == REASON_REPORT
    # The capture is evidence and stays; only the regenerable output failed.
    assert result["capture_recorded"] is True
    assert result["report_written"] is False
    assert "could not be written" in result["error"]
    assert len(_run_files(scenario.store_root)) == 1


# --------------------------------------------------------------------- CLI
def _wire_cli(monkeypatch, scenario, *, clock="2026-10-20T14:00:00Z"):
    monkeypatch.setattr(cli_module, "UrllibTransport", lambda: scenario.transport)
    monkeypatch.setattr(cli_module, "GitHubApi", lambda transport: scenario.api)
    monkeypatch.setattr(cli_module, "utc_now", lambda: clock)


def test_the_parser_exposes_cycle_without_removing_the_other_commands():
    parser = cli_module.build_parser()
    choices = parser._subparsers._group_actions[0].choices
    for command in ("capture", "cycle", "verify", "report"):
        assert command in choices


def test_the_cycle_command_has_no_date_override():
    parser = cli_module.build_parser()
    args = parser.parse_args(["cycle", "--store", "/tmp/store"])
    assert not hasattr(args, "date")
    assert not hasattr(args, "as_of")
    assert args.json is False
    assert args.out is None


def test_the_cli_prints_the_summary_and_exits_zero(monkeypatch, capsys, tmp_path):
    scenario = build_scenario(tmp_path)
    _wire_cli(monkeypatch, scenario)

    code = cli_module.main(["cycle", "--store", str(scenario.store_root)])

    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "prospective cycle" in out
    assert "capture status: VERIFIED (3/3 sources verified)" in out
    assert "KEV-CAPTURE" in out and "OK_VERIFIED" in out
    assert "integrity: VERIFIED" in out
    assert "report digest: " in out


def test_the_cli_json_carries_the_exit_code_and_reason(monkeypatch, capsys, tmp_path):
    scenario = build_scenario(tmp_path, epss="unavailable")
    _wire_cli(monkeypatch, scenario)

    code = cli_module.main(
        ["cycle", "--store", str(scenario.store_root), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_INCOMPLETE
    assert payload["exit_code"] == EXIT_INCOMPLETE
    assert payload["reason"] == REASON_INCOMPLETE
    assert payload["capture_recorded"] is True
    assert payload["capture_status"] == A.UNAVAILABLE
    assert payload["integrity"]["status"] == A.VERIFIED
    assert payload["report_digest"]


def test_the_cli_refuses_an_unsafe_store_without_a_transport(monkeypatch, capsys, tmp_path):
    scenario = build_scenario(tmp_path)
    _wire_cli(monkeypatch, scenario)

    code = cli_module.main(
        ["cycle", "--store", str(PRODUCT_ROOT / "protocol" / "store"), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_NOT_RECORDED
    assert payload["reason"] == REASON_UNSAFE
    assert payload["capture_attempted"] is False
    assert scenario.transport.calls == []


def test_the_cli_writes_the_report_with_out(monkeypatch, capsys, tmp_path):
    scenario = build_scenario(tmp_path)
    _wire_cli(monkeypatch, scenario)
    report_path = scenario.root / "cycle.json"

    code = cli_module.main(
        [
            "cycle",
            "--store",
            str(scenario.store_root),
            "--out",
            str(report_path),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_OK
    assert payload["report_written"] is True
    assert json.loads(report_path.read_text())["report_digest"] == payload["report_digest"]


def test_verify_and_report_still_work_on_a_cycle_store(monkeypatch, capsys, tmp_path):
    scenario = build_scenario(tmp_path)
    _wire_cli(monkeypatch, scenario)
    assert cli_module.main(["cycle", "--store", str(scenario.store_root)]) == EXIT_OK
    capsys.readouterr()

    assert cli_module.main(["verify", "--store", str(scenario.store_root)]) == 0
    assert "integrity: VERIFIED" in capsys.readouterr().out

    assert cli_module.main(["report", "--store", str(scenario.store_root)]) == 0
    assert "prospective evidence capture" in capsys.readouterr().out
