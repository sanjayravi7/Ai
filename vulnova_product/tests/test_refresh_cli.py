"""The 1.8 CLI: offline commands only.

``run`` is not driven here because it always uses the real clock and the network;
its code path is covered by ``test_refresh_workflow`` through the same
``run_refresh`` function the CLI calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.refresh import cli
from vulnova.refresh.workflow import run_refresh

from tests.refresh_fixtures import build_scenario


def test_the_network_command_has_no_date_override():
    """Production acquisition must never be told what day it is."""
    parser = cli.build_parser()
    run = next(
        action for action in parser._actions if getattr(action, "dest", None) == "command"
    )
    run_parser = run.choices["run"]
    options = {option.dest for option in run_parser._actions}
    assert "as_of" not in options
    # The offline gate view *may* accept a date; it writes no acquisition record.
    gate_parser = run.choices["gate"]
    assert "as_of" in {option.dest for option in gate_parser._actions}


def test_no_subcommand_prints_help_and_exits_zero(capsys):
    assert cli.main([]) == 0
    output = capsys.readouterr().out
    assert "maturity gate" in output.lower()
    assert "run" in output


def test_gate_command_reports_the_boundary_offline(tmp_path, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    code = cli.main(
        [
            "gate",
            "--archive-manifest",
            str(scenario.baseline_manifest_path),
            "--as-of",
            "2026-10-20",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "maturity gate" in out
    assert "2026-10-28" in out
    assert "final block maturity observable: no" in out


def test_gate_command_json_mode_is_machine_readable(tmp_path, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    # The sealed fixture archive has no VERIFIED catalog record, so the gate must
    # say the catalog is unavailable rather than inventing one.
    code = cli.main(
        [
            "gate",
            "--archive-manifest",
            str(scenario.baseline_manifest_path),
            "--as-of",
            "2026-10-20",
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["as_of"] == "2026-10-20"
    assert payload["gate_summary"]["final_block_maturity_observable"] is False
    assert len(payload["gates"]) == 3


def test_gate_command_rejects_a_bad_date(tmp_path, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    code = cli.main(
        [
            "gate",
            "--archive-manifest",
            str(scenario.baseline_manifest_path),
            "--as-of",
            "20-10-2026",
        ]
    )
    assert code == 2
    assert "not an ISO date" in capsys.readouterr().err


def test_gate_command_reports_a_missing_manifest(tmp_path, capsys):
    code = cli.main(
        ["gate", "--archive-manifest", str(Path(tmp_path) / "absent.json")]
    )
    assert code == 2
    assert "error" in capsys.readouterr().err


def test_gate_command_reads_the_committed_archive(capsys):
    """The real committed 1.7 manifest is the default input."""
    product = Path(__file__).resolve().parents[1]
    manifest = product / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
    if not manifest.is_file():  # pragma: no cover - repository incomplete
        pytest.skip("committed 1.7 manifest is absent")
    code = cli.main(["gate", "--as-of", "2026-10-27", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["catalog"]["key"] == "current#github"
    assert payload["catalog"]["catalog_version"] == "2026.10.16"
    final = payload["gates"][-1]
    assert final["cutoff"] == "2026-04-01"
    assert final["maturity_date"] == "2026-10-28"
    assert final["status"] == "NOT_MATURED"
    assert final["days_remaining"] == 1


def test_verify_command_exits_zero_for_an_intact_report(tmp_path, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    report = run_refresh(scenario.options())
    report_path = Path(tmp_path) / "refresh_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    code = cli.main(
        [
            "verify",
            "--report",
            str(report_path),
            "--store",
            str(scenario.store.root),
            "--archive-manifest",
            str(scenario.baseline_manifest_path),
            "--archive-store",
            str(scenario.baseline_store_path),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "integrity: VERIFIED" in out
    assert "evidence: BLOCKED" in out
    assert "network used: no" in out


def test_verify_command_fails_on_a_tampered_report(tmp_path, capsys):
    scenario = build_scenario(tmp_path)
    report = run_refresh(scenario.options())
    report["summary"]["refresh_status"] = "EVIDENCE_COMPLETE_FOR_REASSESSMENT"
    report_path = Path(tmp_path) / "refresh_report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    code = cli.main(
        ["verify", "--report", str(report_path), "--store", str(scenario.store.root)]
    )
    assert code == 1
    assert "integrity: BLOCKED" in capsys.readouterr().out


def test_verify_command_reports_a_missing_report(tmp_path, capsys):
    code = cli.main(["verify", "--report", str(Path(tmp_path) / "absent.json")])
    assert code == 2
    assert "cannot read refresh report" in capsys.readouterr().err
