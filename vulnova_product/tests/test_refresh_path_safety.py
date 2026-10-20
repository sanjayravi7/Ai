"""Write safety: every destination is judged before anything is fetched or written.

The refresh writes in three places — the artifact store, the JSON report and the
Markdown summary.  Before 1.8.1 only the store was checked against the sealed
paths; a ``--report`` aimed at the committed 1.6 readiness report would have
overwritten it *after* the archive guard had already reported the archive intact.

These tests pin the corrected order of operations:

* a rejected destination raises before a transport exists, so no socket is
  opened and ``FakeTransport.calls`` stays empty;
* a rejected destination raises before ``mkdir`` or ``write_text``, so no file
  or directory is created and the protected bytes are unchanged;
* the accepted destinations are exactly the ones checked, including custom
  paths outside the defaults.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.acquisition.store import ArtifactStore
from vulnova.refresh import cli
from vulnova.refresh import constants as C
from vulnova.refresh.errors import PathSafetyError
from vulnova.refresh.paths import (
    assert_safe_write_targets,
    default_protected_paths,
    resolve_path,
)
from vulnova.refresh.workflow import protected_inputs, run_refresh

from tests.refresh_fixtures import build_scenario

PRODUCT = Path(__file__).resolve().parents[1]
REPOSITORY = PRODUCT.parent
READINESS_REPORT = (
    PRODUCT / "reports" / "evaluation_readiness_1_6" / "readiness_report.json"
)
ACQUISITION_MANIFEST = (
    PRODUCT / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
)
ACQUISITION_STORE = PRODUCT / "data" / "acquisition_store"
SNAPSHOTS = PRODUCT / "data" / "snapshots"
EXPORT = REPOSITORY / "phase2.3k-export"
PROTOCOL = PRODUCT / "protocol" / "evaluation_protocol.json"


# --------------------------------------------------------------------- helpers
def _sha(path: Path) -> str:
    import hashlib

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _refuse_transport(monkeypatch):
    """Make constructing the network transport a test failure."""

    class Guard:
        constructed = False

        def __init__(self, *args, **kwargs):  # pragma: no cover - must not run
            Guard.constructed = True
            raise AssertionError(
                "the transport was constructed before the write-safety check"
            )

    monkeypatch.setattr(cli, "UrllibTransport", Guard)
    return Guard


def _run_args(tmp_path, scenario, *, store=None, report=None, markdown=None):
    return [
        "run",
        "--store",
        str(store if store is not None else tmp_path / "refresh_store"),
        "--report",
        str(report if report is not None else tmp_path / "out" / "refresh_report.json"),
        "--markdown",
        str(markdown if markdown is not None else tmp_path / "out" / "REFRESH_1_8_REPORT.md"),
        "--archive-manifest",
        str(scenario.baseline_manifest_path),
        "--archive-store",
        str(scenario.baseline_store_path),
        "--no-readiness",
    ]


def _assert_rejected(capsys, code: int, reason: str) -> str:
    assert code == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert reason in err
    return err


# ---------------------------------------------------------------- protected set
def test_the_protected_set_names_every_sealed_input(tmp_path):
    args = cli.build_parser().parse_args(["run"])
    guarded = {resolve_path(path) for path in cli.protected_paths(args)}
    for path in (
        ACQUISITION_STORE,
        PRODUCT / "reports" / "acquisition_1_7",
        PRODUCT / "reports" / "evaluation_readiness_1_6",
        SNAPSHOTS,
        EXPORT,
        READINESS_REPORT,
        ACQUISITION_MANIFEST,
        PROTOCOL,
    ):
        assert resolve_path(path) in guarded, path


def test_configured_inputs_outside_the_defaults_are_protected_too(tmp_path):
    custom_protocol = tmp_path / "elsewhere" / "protocol.json"
    custom_protocol.parent.mkdir()
    custom_protocol.write_text("{}", encoding="utf-8")
    args = cli.build_parser().parse_args(
        [
            "run",
            "--protocol",
            str(custom_protocol),
            "--baseline",
            str(tmp_path / "elsewhere" / "baseline.json"),
        ]
    )
    guarded = {resolve_path(path) for path in cli.protected_paths(args)}
    assert resolve_path(custom_protocol) in guarded
    assert resolve_path(tmp_path / "elsewhere" / "baseline.json") in guarded


# ------------------------------------------------------------ CLI refuses early
def test_report_cannot_overwrite_the_committed_1_6_readiness_report(
    tmp_path, monkeypatch, capsys
):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    before = _sha(READINESS_REPORT)

    code = cli.main(
        _run_args(tmp_path, scenario, report=READINESS_REPORT)
    )

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert scenario.transport.calls == []
    assert _sha(READINESS_REPORT) == before


def test_report_cannot_overwrite_the_sealed_1_7_manifest(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    before = _sha(ACQUISITION_MANIFEST)

    code = cli.main(_run_args(tmp_path, scenario, report=ACQUISITION_MANIFEST))

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert scenario.transport.calls == []
    assert _sha(ACQUISITION_MANIFEST) == before


def test_markdown_cannot_write_inside_a_protected_directory(
    tmp_path, monkeypatch, capsys
):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    target = SNAPSHOTS / "REFRESH_1_8_REPORT.md"

    code = cli.main(_run_args(tmp_path, scenario, markdown=target))

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert scenario.transport.calls == []
    assert not target.exists()


def test_outputs_cannot_overwrite_a_stored_source_artifact(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    target = ACQUISITION_STORE / "kev" / "current" / "known_exploited_vulnerabilities.json"
    assert target.is_file()
    before = _sha(target)

    code = cli.main(_run_args(tmp_path, scenario, report=target))

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert _sha(target) == before


def test_a_report_aimed_at_the_protocol_is_refused(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    before = _sha(PROTOCOL)

    code = cli.main(_run_args(tmp_path, scenario, report=PROTOCOL))

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert _sha(PROTOCOL) == before


# --------------------------------------------------------------- collisions
def test_a_report_inside_the_refresh_store_is_refused(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    store = tmp_path / "bundle"

    code = cli.main(
        _run_args(tmp_path, scenario, store=store, report=store / "refresh_report.json")
    )

    _assert_rejected(capsys, code, C.OUTPUT_PATHS_COLLIDE)
    assert guard.constructed is False
    assert not store.exists()


def test_a_store_inside_a_protected_directory_is_refused_by_the_cli(
    tmp_path, monkeypatch, capsys
):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    store = ACQUISITION_STORE / "nested_refresh"

    code = cli.main(_run_args(tmp_path, scenario, store=store))

    _assert_rejected(capsys, code, C.REFRESH_STORE_OVERLAPS_ARCHIVE)
    assert guard.constructed is False
    assert scenario.transport.calls == []
    assert not store.exists()


def test_the_sealed_phase_2_3k_export_is_refused(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)

    code = cli.main(
        _run_args(tmp_path, scenario, markdown=EXPORT / "REFRESH_1_8_REPORT.md")
    )

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert not (EXPORT / "REFRESH_1_8_REPORT.md").exists()


def test_a_report_that_contains_a_protected_directory_is_refused(
    tmp_path, monkeypatch, capsys
):
    """A directory-shaped destination is judged as a directory, not a filename."""
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)

    code = cli.main(_run_args(tmp_path, scenario, report=PRODUCT / "reports"))

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False


def test_report_and_markdown_at_the_same_path_are_refused(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    guard = _refuse_transport(monkeypatch)
    same = tmp_path / "out" / "report.json"

    code = cli.main(_run_args(tmp_path, scenario, report=same, markdown=same))

    _assert_rejected(capsys, code, C.OUTPUT_PATHS_COLLIDE)
    assert guard.constructed is False
    assert not same.exists()
    assert not (tmp_path / "out").exists()


def test_relative_and_dot_dot_paths_are_resolved_before_comparison(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sealed").mkdir()
    with pytest.raises(PathSafetyError) as excinfo:
        assert_safe_write_targets("store", ("sealed/report.json",), ("sealed",))
    assert C.OUTPUT_OVERLAPS_PROTECTED in str(excinfo.value)

    with pytest.raises(PathSafetyError) as excinfo:
        assert_safe_write_targets(
            "store", ("store/../sealed/report.json",), ("sealed",)
        )
    assert C.OUTPUT_OVERLAPS_PROTECTED in str(excinfo.value)


def test_a_symlinked_directory_cannot_launder_a_protected_path(tmp_path, monkeypatch):
    scenario = build_scenario(tmp_path, archive=True)
    link = tmp_path / "link_to_snapshots"
    try:
        link.symlink_to(SNAPSHOTS, target_is_directory=True)
    except OSError:  # pragma: no cover - platforms without symlink support
        pytest.skip("symlinks are not supported here")
    guard = _refuse_transport(monkeypatch)

    code = cli.main(_run_args(tmp_path, scenario, markdown=link / "report.md"))

    assert code == 2
    assert guard.constructed is False


def test_a_symlink_to_a_protected_file_is_refused(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True)
    link = tmp_path / "readiness.json"
    try:
        link.symlink_to(READINESS_REPORT)
    except OSError:  # pragma: no cover - platforms without symlink support
        pytest.skip("symlinks are not supported here")
    guard = _refuse_transport(monkeypatch)
    before = _sha(READINESS_REPORT)

    code = cli.main(_run_args(tmp_path, scenario, report=link))

    _assert_rejected(capsys, code, C.OUTPUT_OVERLAPS_PROTECTED)
    assert guard.constructed is False
    assert _sha(READINESS_REPORT) == before


# ------------------------------------------------------------- workflow layer
def test_run_refresh_checks_outputs_before_any_network_call(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    assert scenario.transport.calls == []

    with pytest.raises(PathSafetyError) as excinfo:
        run_refresh(
            scenario.options(output_paths=(scenario.baseline_manifest_path,))
        )

    assert C.OUTPUT_OVERLAPS_PROTECTED in str(excinfo.value)
    assert scenario.transport.calls == []
    assert not scenario.store.root.exists()


def test_run_refresh_accepts_safe_outputs_and_does_not_write_them_itself(tmp_path):
    scenario = build_scenario(tmp_path)
    targets = (tmp_path / "out" / "refresh_report.json", tmp_path / "out" / "report.md")

    report = run_refresh(scenario.options(output_paths=targets))

    assert scenario.transport.calls  # the run really happened
    assert report["refresh_digest"]
    # The workflow returns the report; writing it belongs to the caller.
    assert not targets[0].exists()
    assert not targets[1].exists()


# ------------------------------------- workflow derives its own sealed paths
def test_a_direct_call_cannot_store_inside_the_sealed_1_7_archive(tmp_path):
    """No CLI, no protected_paths: the workflow still knows what is sealed."""
    scenario = build_scenario(tmp_path)
    assert scenario.options().protected_paths == ()
    store = ACQUISITION_STORE / "must_not_be_created"

    with pytest.raises(PathSafetyError) as excinfo:
        run_refresh(scenario.options(store=ArtifactStore(store)))

    assert C.REFRESH_STORE_OVERLAPS_ARCHIVE in str(excinfo.value)
    assert scenario.transport.calls == []
    assert not store.exists()


def test_a_direct_call_cannot_store_inside_the_snapshots(tmp_path):
    scenario = build_scenario(tmp_path)
    store = SNAPSHOTS / "must_not_be_created"

    with pytest.raises(PathSafetyError) as excinfo:
        run_refresh(scenario.options(store=ArtifactStore(store)))

    assert C.REFRESH_STORE_OVERLAPS_ARCHIVE in str(excinfo.value)
    assert scenario.transport.calls == []
    assert not store.exists()


def test_a_direct_call_cannot_write_its_report_over_the_1_6_report(tmp_path):
    scenario = build_scenario(tmp_path)
    before = _sha(READINESS_REPORT)

    with pytest.raises(PathSafetyError) as excinfo:
        run_refresh(scenario.options(output_paths=(READINESS_REPORT,)))

    assert C.OUTPUT_OVERLAPS_PROTECTED in str(excinfo.value)
    assert scenario.transport.calls == []
    assert not scenario.store.root.exists()
    assert _sha(READINESS_REPORT) == before


def test_configured_baseline_inputs_stay_protected_without_caller_paths(tmp_path):
    """The options themselves are read-only inputs, not just the caller's list."""
    scenario = build_scenario(tmp_path, archive=True)
    assert scenario.options(protected_paths=()).protected_paths == ()

    with pytest.raises(PathSafetyError) as excinfo:
        run_refresh(
            scenario.options(
                protected_paths=(),
                output_paths=(scenario.baseline_manifest_path,),
            )
        )

    assert C.OUTPUT_OVERLAPS_PROTECTED in str(excinfo.value)
    assert scenario.transport.calls == []


def test_a_configured_protocol_and_baseline_are_protected(tmp_path):
    scenario = build_scenario(tmp_path)
    protocol = tmp_path / "custom_protocol.json"
    protocol.write_text("{}", encoding="utf-8")
    baseline = tmp_path / "custom_baseline.json"
    baseline.write_text("{}", encoding="utf-8")

    for target in (protocol, baseline):
        with pytest.raises(PathSafetyError) as excinfo:
            run_refresh(
                scenario.options(
                    protected_paths=(),
                    protocol_path=protocol,
                    baseline_report_path=baseline,
                    output_paths=(target,),
                )
            )
        assert C.OUTPUT_OVERLAPS_PROTECTED in str(excinfo.value)
    assert scenario.transport.calls == []


def test_protected_inputs_union_and_deduplicate(tmp_path):
    scenario = build_scenario(tmp_path)
    extra = tmp_path / "extra"
    options = scenario.options(
        protocol_path=tmp_path / "protocol.json",
        baseline_report_path=tmp_path / "baseline.json",
        baseline_manifest_path=tmp_path / "manifest.json",
        baseline_store_path=tmp_path / "archive_store",
        artifacts_path=tmp_path / "export",
        protected_paths=(extra, extra),
    )
    merged = protected_inputs(options)
    guarded = set(merged)

    for fixed in default_protected_paths():
        assert resolve_path(fixed) in guarded
    for configured in (
        tmp_path / "protocol.json",
        tmp_path / "baseline.json",
        tmp_path / "manifest.json",
        tmp_path / "archive_store",
        tmp_path / "export",
        extra,
    ):
        assert resolve_path(configured) in guarded
    assert len(merged) == len(guarded)
    # The empty tuple must not shrink the fixed set.
    assert guarded >= {resolve_path(path) for path in default_protected_paths()}


def test_an_empty_protected_tuple_does_not_weaken_a_caller_supplied_path(tmp_path):
    """Caller paths are additive: empty means "no extra", never "none"."""
    scenario = build_scenario(tmp_path)
    caller = tmp_path / "caller_sealed"
    caller.mkdir()

    with pytest.raises(PathSafetyError):
        run_refresh(
            scenario.options(
                protected_paths=(caller,),
                output_paths=(caller / "report.json",),
            )
        )
    assert scenario.transport.calls == []


# ------------------------------------------------------------------ happy path
def test_safe_custom_output_paths_still_work(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path, archive=True, direct_feed=True)
    monkeypatch.setattr(cli, "UrllibTransport", lambda: scenario.transport)
    monkeypatch.setattr(cli, "GitHubApi", lambda transport: scenario.api)
    report_path = tmp_path / "out" / "refresh_report.json"
    markdown_path = tmp_path / "out" / "REFRESH_1_8_REPORT.md"

    code = cli.main(
        _run_args(
            tmp_path,
            scenario,
            store=tmp_path / "store",
            report=report_path,
            markdown=markdown_path,
        )
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "refresh status:" in out
    assert report_path.is_file()
    assert markdown_path.is_file()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["summary"]["refresh_status"] in C.REFRESH_STATUSES
    assert payload["refresh_digest"] in markdown_path.read_text(encoding="utf-8")
    # The run wrote only its own store and the two requested outputs.
    assert (tmp_path / "store").is_dir()


def test_the_committed_defaults_are_safe():
    """The shipped defaults must pass the very check they enforce."""
    args = cli.build_parser().parse_args(["run"])
    guarded = cli.protected_paths(args)
    resolved = assert_safe_write_targets(
        args.store, (args.report, args.markdown), guarded
    )
    assert resolved[0] == resolve_path(args.report)
    assert resolved[1] == resolve_path(args.markdown)


def test_a_store_inside_a_protected_directory_is_still_refused(tmp_path):
    scenario = build_scenario(tmp_path, archive=True)
    with pytest.raises(PathSafetyError) as excinfo:
        run_refresh(
            scenario.options(
                store=ArtifactStore(Path(scenario.baseline_store_path) / "nested")
            )
        )
    assert C.REFRESH_STORE_OVERLAPS_ARCHIVE in str(excinfo.value)
    assert scenario.transport.calls == []
