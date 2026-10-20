"""The report: deterministic, honest about gaps, and free of implied success."""

from __future__ import annotations

import json
from pathlib import Path

from vulnova.acquisition import constants as A
from vulnova.prospective import cli
from vulnova.prospective.capture import run_capture
from vulnova.prospective.report import (
    build_report,
    render_markdown,
    verify_digest,
    write_json,
    write_markdown,
)

from tests.acquisition_fixtures import kev_catalog_bytes
from tests.prospective_fixtures import build_scenario


def _captured(tmp_path: Path, **kwargs):
    scenario = build_scenario(tmp_path, **kwargs)
    run_capture(scenario.options())
    return scenario


# --------------------------------------------------------------- the report
def test_a_complete_day_is_reported_per_source(tmp_path):
    scenario = _captured(tmp_path)
    report = build_report(scenario.store_root)

    assert report["captures"] == 1
    assert report["observation_dates"] == ["2026-10-20"]
    assert report["status_counts"] == {A.VERIFIED: 1, A.UNAVAILABLE: 0, A.BLOCKED: 0}
    day = report["days"][0]
    assert day["kev"] == A.VERIFIED
    assert day["epss"] == A.VERIFIED
    assert day["cvelistv5"] == A.VERIFIED
    assert report["conflicts"] == []
    assert report["unreadable_runs"] == []
    assert verify_digest(report)[0] is True


def test_a_partial_day_is_never_shown_as_a_good_day(tmp_path):
    scenario = _captured(tmp_path, epss="unavailable")
    report = build_report(scenario.store_root)
    day = report["days"][0]

    assert day["kev"] == A.VERIFIED
    assert day["epss"] == A.UNAVAILABLE
    assert report["status_counts"][A.UNAVAILABLE] == 1
    markdown = render_markdown(report)
    assert "UNAVAILABLE" in markdown
    assert "VERIFIED" in markdown


def test_the_report_is_byte_identical_on_repeat(tmp_path):
    scenario = _captured(tmp_path)
    first = build_report(scenario.store_root)
    second = build_report(scenario.store_root)
    assert first == second
    assert render_markdown(first) == render_markdown(second)


def test_two_machines_with_the_same_store_get_the_same_digest(tmp_path):
    left = _captured(tmp_path / "left")
    right = _captured(tmp_path / "right")
    assert build_report(left.store_root)["report_digest"] == (
        build_report(right.store_root)["report_digest"]
    )


def test_the_report_contains_no_absolute_paths(tmp_path):
    scenario = _captured(tmp_path)
    body = json.dumps(build_report(scenario.store_root), sort_keys=True)
    assert str(tmp_path) not in body
    assert "/home/" not in body


def test_an_empty_store_is_reported_as_empty_not_as_absence(tmp_path):
    report = build_report(tmp_path / "nothing")
    assert report["captures"] == 0
    assert report["observation_dates"] == []
    markdown = render_markdown(report)
    assert "empty store" in markdown
    assert "not evidence of absence" in markdown


def test_the_markdown_states_what_the_report_does_not_prove(tmp_path):
    scenario = _captured(tmp_path)
    markdown = render_markdown(build_report(scenario.store_root))
    assert "What this does not prove" in markdown
    assert "does not prove historical correctness or completeness" in markdown
    assert "does not by itself satisfy the three-block protocol" in markdown
    assert "report digest:" in markdown


def test_a_conflict_is_reported_not_resolved(tmp_path):
    scenario = _captured(tmp_path)
    other = build_scenario(
        tmp_path / "other",
        kev_body=kev_catalog_bytes("2026.10.17", "2026-10-17T17:15:48Z"),
    )
    other.store_root = scenario.store_root
    run_capture(other.options())

    report = build_report(scenario.store_root)
    assert len(report["conflicts"]) == 1
    assert len(report["conflicts"][0]["run_ids"]) == 2
    markdown = render_markdown(report)
    assert "Conflicting captures" in markdown
    assert "neither is preferred" in markdown


def test_an_unreadable_run_is_reported_and_not_counted(tmp_path):
    scenario = _captured(tmp_path)
    bad = scenario.store_root / "runs" / "20260101T000000Z-000000000000.json"
    bad.write_text("{not json")

    report = build_report(scenario.store_root)
    assert report["captures"] == 1
    assert len(report["unreadable_runs"]) == 1
    assert "JSONDecodeError" in report["unreadable_runs"][0]
    assert "Unreadable runs" in render_markdown(report)


def test_the_digest_changes_when_the_store_changes(tmp_path):
    scenario = _captured(tmp_path)
    before = build_report(scenario.store_root)["report_digest"]
    other = build_scenario(
        tmp_path / "other",
        kev_body=kev_catalog_bytes("2026.10.17", "2026-10-17T17:15:48Z"),
    )
    other.store_root = scenario.store_root
    run_capture(other.options())
    assert build_report(scenario.store_root)["report_digest"] != before


# ------------------------------------------------------------------ writers
def test_write_json_and_markdown_round_trip(tmp_path):
    scenario = _captured(tmp_path)
    report = build_report(scenario.store_root)

    json_path = tmp_path / "out" / "report.json"
    md_path = tmp_path / "out" / "report.md"
    write_json(report, json_path)
    write_markdown(report, md_path)

    assert json.loads(json_path.read_text()) == report
    assert md_path.read_text() == render_markdown(report)


def test_a_written_report_still_verifies(tmp_path):
    scenario = _captured(tmp_path)
    report = build_report(scenario.store_root)
    path = tmp_path / "report.json"
    write_json(report, path)
    assert verify_digest(json.loads(path.read_text()))[0] is True


def test_a_tampered_report_digest_is_detected(tmp_path):
    scenario = _captured(tmp_path)
    report = build_report(scenario.store_root)
    report["captures"] = 99
    ok, _recomputed = verify_digest(report)
    assert ok is False


# -------------------------------------------------------------------- the CLI
def test_cli_verify_exits_zero_on_a_healthy_store(tmp_path, capsys):
    scenario = _captured(tmp_path)
    assert cli.main(["verify", "--store", str(scenario.store_root)]) == 0
    out = capsys.readouterr().out
    assert "integrity: VERIFIED" in out
    assert "network used: no" in out


def test_cli_verify_exits_one_on_a_tampered_store(tmp_path, capsys):
    scenario = _captured(tmp_path)
    artifact = next((scenario.store_root / "artifacts" / "kev").glob("*.json"))
    artifact.write_bytes(artifact.read_bytes() + b" ")
    assert cli.main(["verify", "--store", str(scenario.store_root)]) == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_cli_verify_json_is_machine_readable(tmp_path, capsys):
    scenario = _captured(tmp_path)
    assert cli.main(["verify", "--store", str(scenario.store_root), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == A.VERIFIED
    assert payload["network_used"] is False


def test_cli_report_prints_markdown_to_stdout(tmp_path, capsys):
    scenario = _captured(tmp_path)
    assert cli.main(["report", "--store", str(scenario.store_root)]) == 0
    body = capsys.readouterr().out
    assert body.startswith("# VULNOVA 1.9")


def test_cli_report_writes_json_to_a_file(tmp_path, capsys):
    scenario = _captured(tmp_path)
    out = tmp_path / "json" / "report.json"
    assert (
        cli.main(
            ["report", "--store", str(scenario.store_root), "--json", "--out", str(out)]
        )
        == 0
    )
    payload = json.loads(out.read_text())
    assert payload["captures"] == 1
    assert payload["report_digest"]
    captured = capsys.readouterr().out
    assert "report:" in captured
    assert "digest:" in captured


def test_cli_report_on_an_empty_store_still_exits_zero(tmp_path, capsys):
    assert cli.main(["report", "--store", str(tmp_path / "nothing")]) == 0
    assert "empty store" in capsys.readouterr().out


def test_cli_without_a_command_prints_help(capsys):
    assert cli.main([]) == 0
    assert "capture" in capsys.readouterr().out


def test_a_verified_github_fallback_is_a_verified_kev_day(tmp_path):
    """The failed direct-feed attempt must not colour the day as unavailable.

    The attempt is still in the run record -- nothing is hidden -- but the day
    grid answers "what did this day capture", so KEV is VERIFIED.
    """
    scenario = _captured(tmp_path, direct_feed=False)
    report = build_report(scenario.store_root)
    assert report["days"][0]["kev"] == A.VERIFIED
    assert report["sources"]["kev"][A.VERIFIED] == 1
    assert report["sources"]["kev"][A.UNAVAILABLE] == 0

    run = json.loads(next((scenario.store_root / "runs").glob("*.json")).read_text())
    attempts = [r for r in run["records"] if r["source"] == "kev"]
    assert len(attempts) == 2
    assert {r["content_status"] for r in attempts} == {A.VERIFIED, A.UNAVAILABLE}


def test_a_source_that_never_verified_is_unavailable_in_the_grid(tmp_path):
    scenario = _captured(tmp_path, direct_feed=False, github=False)
    report = build_report(scenario.store_root)
    assert report["days"][0]["kev"] == A.UNAVAILABLE
    assert report["sources"]["kev"][A.UNAVAILABLE] == 1


def test_a_malformed_record_does_not_break_the_report(tmp_path):
    scenario = _captured(tmp_path)
    run_file = next((scenario.store_root / "runs").glob("*.json"))
    payload = json.loads(run_file.read_text())
    payload["records"].append("junk")
    run_file.write_text(json.dumps(payload))

    report = build_report(scenario.store_root)
    assert report["captures"] == 1
    assert report["days"][0]["kev"] == A.VERIFIED


def test_the_report_explains_that_a_missing_date_is_a_gap(tmp_path):
    scenario = _captured(tmp_path)
    markdown = render_markdown(build_report(scenario.store_root))
    assert "A date with no row was not observed" in markdown
    assert "not a negative label" in markdown


def test_a_programmatic_report_writer_cannot_overwrite_the_sealed_report(tmp_path):
    import pytest

    from vulnova.prospective import constants as C
    from vulnova.prospective.report import build_report
    from vulnova.refresh.errors import PathSafetyError

    scenario = _captured(tmp_path)
    report = build_report(scenario.store_root)
    sealed = (
        Path(__file__).resolve().parents[1]
        / "reports"
        / "evaluation_readiness_1_6"
        / "readiness_report.json"
    )
    before = sealed.read_bytes()
    with pytest.raises(PathSafetyError):
        write_json(report, sealed)
    assert sealed.read_bytes() == before
    assert C.SCHEMA_VERSION.startswith("vulnova.prospective/")


def test_a_summary_that_is_not_an_object_does_not_break_the_report(tmp_path):
    scenario = _captured(tmp_path)
    run_file = next((scenario.store_root / "runs").glob("*.json"))
    payload = json.loads(run_file.read_text())
    payload["summary"] = "looks fine"
    payload["requirements"] = {"KEV-CAPTURE": "VERIFIED"}
    run_file.write_text(json.dumps(payload))

    report = build_report(scenario.store_root)
    assert report["captures"] == 1
    assert report["status_counts"][A.BLOCKED] == 1
