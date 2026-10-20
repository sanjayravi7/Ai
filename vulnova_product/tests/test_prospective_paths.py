"""Path safety for prospective capture: judged before the first socket or byte.

The 1.8 guard already refuses any destination overlapping a sealed path.  1.9
reuses it -- the check is not reimplemented here -- and adds the 1.8 refresh
store, its reports and the protocol directory to the fixed set.  These tests pin
three properties:

* a refused destination raises before the clock is read and before any network
  request, so ``FakeTransport.calls`` stays empty and no directory is created;
* a programmatic caller passing ``protected_paths=()`` is still protected,
  because the fixed paths never come from the caller;
* an existing symlink or ``..`` segment cannot launder a protected path.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnova.prospective import cli
from vulnova.prospective import constants as C
from vulnova.prospective.capture import run_capture
from vulnova.prospective.paths import (
    assert_capture_safety,
    capture_protected_paths,
    historical_protected_paths,
)
from vulnova.refresh.errors import PathSafetyError

from tests import prospective_fixtures as fixtures
from tests.prospective_fixtures import build_scenario

PRODUCT = Path(__file__).resolve().parents[1]
REPOSITORY = PRODUCT.parent
ARCHIVE = PRODUCT / "data" / "acquisition_store"
REFRESH_STORE = PRODUCT / "data" / "refresh_store_1_8"
READINESS_REPORT = PRODUCT / "reports" / "evaluation_readiness_1_6"
EXPORT = REPOSITORY / "phase2.3k-export"
PROTOCOL = PRODUCT / "protocol"


class Guard:
    """A transport that fails the test if it is ever constructed."""

    def __init__(self, *args, **kwargs):  # noqa: ARG002 - signature compatibility
        raise AssertionError("a refused capture must not build a transport")

    def get(self, url, *, accept=None):  # noqa: ARG002 - never reached
        raise AssertionError("a refused capture must not perform a request")


class GuardApi:
    def __init__(self, *args, **kwargs):  # noqa: ARG002
        raise AssertionError("a refused capture must not build a GitHub client")


def test_the_protected_set_names_every_sealed_path():
    protected = historical_protected_paths()
    for sealed in (
        ARCHIVE,
        READINESS_REPORT,
        REFRESH_STORE,
        PRODUCT / "reports" / "acquisition_1_7",
        PRODUCT / "reports" / "refresh_1_8",
        PRODUCT / "data" / "snapshots",
        PROTOCOL,
        EXPORT,
    ):
        assert sealed.resolve() in protected


def test_the_1_9_protected_set_extends_the_1_8_one_without_replacing_it():
    from vulnova.refresh.paths import default_protected_paths

    base = set(default_protected_paths())
    extended = set(historical_protected_paths())
    assert base <= extended
    assert REFRESH_STORE.resolve() in extended - base
    assert PROTOCOL.resolve() in extended


def test_a_store_inside_the_1_7_archive_is_refused():
    with pytest.raises(PathSafetyError) as excinfo:
        assert_capture_safety(ARCHIVE / "prospective")
    assert C.STORE_OVERLAPS_PROTECTED in str(excinfo.value)


def test_a_store_inside_the_1_8_refresh_store_is_refused():
    with pytest.raises(PathSafetyError) as excinfo:
        assert_capture_safety(REFRESH_STORE / "prospective")
    assert C.STORE_OVERLAPS_PROTECTED in str(excinfo.value)


def test_a_store_that_contains_a_sealed_path_is_refused():
    # A store at ``reports/`` would be one mkdir away from the 1.6 report.
    with pytest.raises(PathSafetyError):
        assert_capture_safety(PRODUCT / "reports")


def test_a_store_at_the_repository_root_is_refused():
    with pytest.raises(PathSafetyError):
        assert_capture_safety(REPOSITORY)


def test_a_store_at_the_export_is_refused():
    with pytest.raises(PathSafetyError):
        assert_capture_safety(EXPORT)


def test_report_output_inside_a_protected_path_is_refused(tmp_path):
    with pytest.raises(PathSafetyError) as excinfo:
        assert_capture_safety(tmp_path / "store", [READINESS_REPORT / "report.json"])
    assert "OUTPUT_OVERLAPS_PROTECTED" in str(excinfo.value)


def test_report_output_inside_the_store_is_refused(tmp_path):
    with pytest.raises(PathSafetyError) as excinfo:
        assert_capture_safety(tmp_path / "store", [tmp_path / "store" / "report.md"])
    assert "OUTPUT_PATHS_COLLIDE" in str(excinfo.value)


def test_two_outputs_at_one_path_are_refused(tmp_path):
    with pytest.raises(PathSafetyError):
        assert_capture_safety(
            tmp_path / "store", [tmp_path / "report.json", tmp_path / "report.json"]
        )


def test_dot_dot_cannot_launder_a_protected_path(tmp_path):
    # Spelled through two parent segments and a sibling directory, but it
    # resolves to the sealed 1.7 archive.
    spelling = PRODUCT / "reports" / ".." / "data" / "acquisition_store" / ".." / "acquisition_store"
    assert spelling.resolve() == ARCHIVE.resolve()
    with pytest.raises(PathSafetyError):
        assert_capture_safety(spelling)


def test_an_existing_symlink_cannot_launder_a_protected_path(tmp_path):
    link = tmp_path / "innocent"
    os.symlink(ARCHIVE, link)
    with pytest.raises(PathSafetyError):
        assert_capture_safety(link / "prospective")


def test_a_symlink_to_the_refresh_store_is_refused(tmp_path):
    link = tmp_path / "store-link"
    os.symlink(REFRESH_STORE, link)
    with pytest.raises(PathSafetyError):
        assert_capture_safety(link)


def test_an_empty_protected_tuple_does_not_disable_the_fixed_paths():
    protected = capture_protected_paths(())
    assert ARCHIVE.resolve() in protected
    assert REFRESH_STORE.resolve() in protected


def test_caller_paths_are_additive():
    extra = PRODUCT / "extra-protected"
    protected = capture_protected_paths((extra,))
    assert extra.resolve() in protected
    assert ARCHIVE.resolve() in protected


def test_a_caller_cannot_protect_its_way_out_of_a_real_sealed_path():
    # Passing the sealed archive as a "protected path" does not make it a valid
    # store: it is already fixed, and the overlap check still refuses it.
    with pytest.raises(PathSafetyError):
        assert_capture_safety(ARCHIVE, (), (ARCHIVE,))


# ------------------------------------------------------ refusals stay offline
def test_a_refused_direct_call_reads_no_clock_and_opens_no_socket(tmp_path, monkeypatch):
    scenario = build_scenario(tmp_path)
    ticks = []

    def clock():
        ticks.append(True)
        return fixtures.DEFAULT_AS_OF

    monkeypatch.setattr(
        "vulnova.prospective.capture.kev_source.acquire_current",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network reached")),
    )
    options = scenario.options(clock=clock, store_root=ARCHIVE / "prospective")
    with pytest.raises(PathSafetyError):
        run_capture(options)
    assert ticks == []
    assert scenario.transport.calls == []
    assert not (ARCHIVE / "prospective").exists()


def test_a_refused_direct_call_creates_no_store_directory(tmp_path):
    target = tmp_path / "sealed"
    target.mkdir()
    protected = target / "child"
    with pytest.raises(PathSafetyError):
        assert_capture_safety(target / "store", (), (target,))
    assert not (target / "store").exists()
    assert protected.exists() is False


# ------------------------------------------------------------------- the CLI
def test_the_cli_refuses_a_protected_store_before_building_a_transport(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(cli, "UrllibTransport", Guard)
    monkeypatch.setattr(cli, "GitHubApi", GuardApi)
    code = cli.main(["capture", "--store", str(ARCHIVE / "prospective")])
    assert code == 2
    assert "STORE_OVERLAPS_PROTECTED" in capsys.readouterr().err
    assert not (ARCHIVE / "prospective").exists()


def test_the_cli_report_refuses_a_protected_output(tmp_path, monkeypatch, capsys):
    scenario = build_scenario(tmp_path)
    from vulnova.prospective.capture import run_capture as capture

    capture(scenario.options())
    code = cli.main(
        [
            "report",
            "--store",
            str(scenario.store_root),
            "--out",
            str(READINESS_REPORT / "report.md"),
        ]
    )
    assert code == 2
    assert "OUTPUT_OVERLAPS_PROTECTED" in capsys.readouterr().err


def test_the_cli_report_writes_a_safe_output(tmp_path, capsys):
    scenario = build_scenario(tmp_path)
    from vulnova.prospective.capture import run_capture as capture

    capture(scenario.options())
    out = tmp_path / "reports" / "report.md"
    code = cli.main(["report", "--store", str(scenario.store_root), "--out", str(out)])
    assert code == 0
    assert out.is_file()
    assert "VULNOVA 1.9" in out.read_text()


def test_write_markdown_does_not_follow_a_symlink_into_a_protected_path(tmp_path):
    # The guard is the caller's contract; this pins that ``report --out`` uses
    # it.  A symlink whose resolved target is sealed is refused by the CLI, not
    # silently followed by the writer.
    scenario = build_scenario(tmp_path)
    from vulnova.prospective.capture import run_capture as capture

    capture(scenario.options())
    link = tmp_path / "link.md"
    os.symlink(ARCHIVE / "report.md", link)
    with pytest.raises(PathSafetyError):
        assert_capture_safety(scenario.store_root, [link])


def test_a_safe_store_outside_the_repository_is_accepted(tmp_path):
    store = tmp_path / "evidence"
    resolved = assert_capture_safety(store)
    assert resolved == ()
    assert not store.exists()  # validation never creates anything
