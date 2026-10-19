"""CLI surface: offline commands, paths and exit codes."""

from __future__ import annotations

import json

from vulnova.acquisition import constants as C
from vulnova.acquisition.cli import build_parser, main
from vulnova.acquisition.manifest import manifest_digest
from vulnova.acquisition.workflow import AcquisitionOptions, run_acquisition

from tests.acquisition_fixtures import CUTOFFS, GRID, RUN_AT, build_scenario


def _write_manifest(tmp_path):
    scenario = build_scenario(tmp_path / "data")
    options = AcquisitionOptions(
        store=scenario.store,
        transport=scenario.transport,
        api=scenario.api,
        cutoffs=CUTOFFS,
        grid=GRID,
        clock=lambda: RUN_AT,
    )
    manifest = run_acquisition(options)
    path = tmp_path / "acquisition_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return path, scenario, manifest


def test_parser_exposes_the_documented_commands():
    parser = build_parser()
    for command in ("acquire", "manifest", "verify", "check", "report"):
        assert command in parser._subparsers._group_actions[0].choices


def test_no_command_prints_help_and_succeeds(capsys):
    assert main([]) == 0
    assert "acquire" in capsys.readouterr().out


def test_manifest_command_re_attests_the_digest(tmp_path, capsys):
    path, _, manifest = _write_manifest(tmp_path)
    assert main(["manifest", "--manifest", str(path)]) == 0
    out = capsys.readouterr().out
    assert manifest["manifest_digest"] in out


def test_manifest_command_rejects_a_tampered_file(tmp_path, capsys):
    path, _, manifest = _write_manifest(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["summary"]["records"] = 1
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["manifest", "--manifest", str(path)]) == 1
    assert "does not match" in capsys.readouterr().err


def test_verify_command_succeeds_on_an_intact_archive(tmp_path, capsys):
    path, scenario, _ = _write_manifest(tmp_path)
    code = main(["verify", "--manifest", str(path), "--store", str(scenario.store.root)])
    out = capsys.readouterr().out
    assert code == 0
    assert "integrity: VERIFIED" in out
    assert "network used: no" in out


def test_verify_command_fails_on_tampering(tmp_path, capsys):
    path, scenario, manifest = _write_manifest(tmp_path)
    record = next(item for item in manifest["records"] if item["artifact_path"])
    scenario.store.path(record["artifact_path"]).write_bytes(b"tampered")
    code = main(["verify", "--manifest", str(path), "--store", str(scenario.store.root)])
    assert code == 1
    assert "ARTIFACT_SHA256" in capsys.readouterr().out


def test_verify_command_emits_json_on_request(tmp_path, capsys):
    path, scenario, _ = _write_manifest(tmp_path)
    assert (
        main(
            [
                "verify",
                "--manifest",
                str(path),
                "--store",
                str(scenario.store.root),
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == C.VERIFIED


def test_check_command_lists_every_source_and_cutoff(tmp_path, capsys):
    path, _, _ = _write_manifest(tmp_path)
    assert main(["check", "--manifest", str(path)]) == 0
    out = capsys.readouterr().out
    for source in ("cvelistv5", "kev", "epss"):
        assert source in out
    assert "9 source/cutoff pairs" in out


def test_check_command_require_verified_fails_on_unavailable_epss(tmp_path, capsys):
    path, _, _ = _write_manifest(tmp_path)
    assert main(["check", "--manifest", str(path), "--require-verified"]) == 1
    capsys.readouterr()


def test_report_command_writes_markdown(tmp_path, capsys):
    path, scenario, manifest = _write_manifest(tmp_path)
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--manifest",
            str(path),
            "--store",
            str(scenario.store.root),
            "--out",
            str(out),
        ]
    )
    text = out.read_text(encoding="utf-8")
    assert code == 0
    assert "Missing or blocked evidence" in text
    assert "FINAL_BLOCK_MATURITY_NOT_CLAIMED" in text
    assert manifest["manifest_digest"] in text
    assert "network used: no" in text


def test_report_records_the_epss_gap_explicitly(tmp_path):
    path, scenario, _ = _write_manifest(tmp_path)
    out = tmp_path / "report.md"
    main(
        [
            "report",
            "--manifest",
            str(path),
            "--store",
            str(scenario.store.root),
            "--out",
            str(out),
        ]
    )
    text = out.read_text(encoding="utf-8")
    assert "OFFICIAL_SOURCE_UNREACHABLE" in text
    assert "EPSS-01_EXACT_DAILY_FILE" in text


def test_acquire_parser_defaults_to_the_three_candidate_cutoffs():
    parser = build_parser()
    args = parser.parse_args(["acquire"])
    assert args.cutoffs == ["2025-02-01", "2025-09-01", "2026-04-01"]
    assert args.store.name == "acquisition_store"


def test_acquire_rejects_a_cutoff_outside_the_grid(tmp_path, capsys):
    code = main(["acquire", "--cutoffs", "2025-03-15", "--grid", "2025-02-01", "--no-reference"])
    assert code == 2
    assert "outside the cutoff grid" in capsys.readouterr().err


def test_manifest_digest_in_the_written_file_is_self_consistent(tmp_path):
    path, _, _ = _write_manifest(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert manifest_digest(payload) == payload["manifest_digest"]
