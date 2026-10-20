"""The schedule preflight: timezone arithmetic and configuration checks.

Two things are tested here.

1. The UTC → local conversion that the scheduling documentation now depends on.
   A schedule written as "13:10" is a different instant depending on which clock
   interprets it, and in some zones it is a different *date*.
2. The preflight itself, against real temporary directories.  It must fail a
   store inside the repository, a store overlapping a sealed path, a relative
   path, a store on a filesystem without hard links, and a tampered store — and
   it must do so without capturing anything, opening a socket or writing evidence.

No test asserts prose.  Every assertion is about a computed value, a check id, an
exit status or a filesystem effect.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

from vulnova.prospective import constants as C
from vulnova.prospective.cycle import CycleOptions, run_cycle
from vulnova.prospective.preflight import (
    EXIT_FAILED,
    EXIT_OK,
    FAIL,
    INFO,
    PASS,
    WARN,
    local_time_for_utc,
    run_preflight,
)

from tests.prospective_fixtures import build_scenario

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
TOOL = PRODUCT_ROOT / "tools" / "check_schedule.py"
IST = dt.timezone(dt.timedelta(hours=5, minutes=30), "IST")


def _by_id(result: dict) -> dict:
    return {check["id"]: check for check in result["checks"]}


def _tree(root: Path) -> list[tuple[str, int]]:
    """Every file under ``root`` with its size, to prove nothing was written."""
    return sorted(
        (str(path.relative_to(root)), path.stat().st_size)
        for path in root.rglob("*")
        if path.is_file()
    )


# ------------------------------------------------------------- timezone math
def test_ist_trigger_is_1840_local():
    fired = local_time_for_utc(dt.time(13, 10), IST, dt.date(2026, 10, 20))
    assert fired.strftime("%Y-%m-%d %H:%M") == "2026-10-20 18:40"


def test_utc_trigger_is_unchanged_when_the_machine_runs_on_utc():
    fired = local_time_for_utc(dt.time(13, 10), dt.timezone.utc, dt.date(2026, 10, 20))
    assert fired.strftime("%H:%M") == "13:10"


def test_a_negative_offset_falls_before_the_utc_instant():
    pacific = dt.timezone(dt.timedelta(hours=-8))
    fired = local_time_for_utc(dt.time(13, 10), pacific, dt.date(2026, 10, 20))
    assert fired.strftime("%H:%M") == "05:10"
    assert fired.date() == dt.date(2026, 10, 20)


def test_a_far_eastern_offset_lands_on_the_next_local_date():
    auckland = dt.timezone(dt.timedelta(hours=13))
    fired = local_time_for_utc(dt.time(13, 10), auckland, dt.date(2026, 10, 20))
    assert fired.strftime("%Y-%m-%d %H:%M") == "2026-10-21 02:10"


# ------------------------------------------------------------- fresh install
def test_a_fresh_store_outside_the_repository_passes_with_warnings(tmp_path):
    store = tmp_path / "evidence"
    result = run_preflight(store)

    checks = _by_id(result)
    assert result["status"] == PASS
    assert result["failed"] == []
    assert checks["STORE_ABSOLUTE"]["status"] == PASS
    assert checks["STORE_OUTSIDE_REPOSITORY"]["status"] == PASS
    assert checks["STORE_LOCATION"]["status"] == WARN  # does not exist yet
    assert checks["STORE_INTEGRITY"]["status"] == WARN
    assert checks["STORE_HARDLINKS"]["status"] == PASS
    assert result["network_used"] is False
    # A preflight creates nothing: no store, no probe directory left behind.
    assert not store.exists()
    assert list(tmp_path.glob(".preflight-*")) == []


def test_an_empty_store_is_a_warning_not_a_failure(tmp_path):
    store = tmp_path / "evidence"
    store.mkdir()
    result = run_preflight(store)

    checks = _by_id(result)
    assert result["status"] == PASS
    assert checks["STORE_INTEGRITY"]["status"] == WARN
    assert "empty store" in checks["STORE_INTEGRITY"]["detail"]


# --------------------------------------------------------------- refusals
def test_a_store_inside_the_repository_is_refused():
    store = PRODUCT_ROOT / "var" / "evidence"
    result = run_preflight(store)

    checks = _by_id(result)
    assert result["status"] == FAIL
    assert checks["STORE_OUTSIDE_REPOSITORY"]["status"] == FAIL
    assert "STORE_OUTSIDE_REPOSITORY" in result["failed"]
    assert not store.exists()


def test_a_store_overlapping_a_sealed_path_is_refused():
    sealed = PRODUCT_ROOT / "protocol" / "evidence"
    result = run_preflight(sealed)

    checks = _by_id(result)
    assert result["status"] == FAIL
    assert checks["PATH_SAFETY"]["status"] == FAIL
    assert C.STORE_OVERLAPS_PROTECTED in checks["PATH_SAFETY"]["detail"]
    assert not sealed.exists()


def test_a_relative_store_path_is_refused(tmp_path):
    result = run_preflight(Path("evidence"))

    checks = _by_id(result)
    assert checks["STORE_ABSOLUTE"]["status"] == FAIL
    assert result["status"] == FAIL


def test_a_report_inside_the_store_is_refused(tmp_path):
    store = tmp_path / "evidence"
    result = run_preflight(store, store / "report.md")

    checks = _by_id(result)
    assert result["status"] == FAIL
    assert checks["PATH_SAFETY"]["status"] == FAIL
    assert "OUTPUT_PATHS_COLLIDE" in checks["PATH_SAFETY"]["detail"]


def test_a_report_inside_a_sealed_path_is_refused(tmp_path):
    sealed = PRODUCT_ROOT / "protocol" / "schedule-report.md"
    result = run_preflight(tmp_path / "evidence", sealed)

    checks = _by_id(result)
    assert checks["PATH_SAFETY"]["status"] == FAIL
    assert "OUTPUT_OVERLAPS_PROTECTED" in checks["PATH_SAFETY"]["detail"]
    assert not sealed.exists()


def test_a_report_inside_the_repository_is_refused(tmp_path):
    report = PRODUCT_ROOT / "reports" / "schedule-report.md"
    result = run_preflight(tmp_path / "evidence", report)

    checks = _by_id(result)
    assert checks["REPORT_OUTSIDE_REPOSITORY"]["status"] == FAIL
    assert result["status"] == FAIL
    assert not report.exists()


def test_a_filesystem_without_hard_links_fails_the_preflight(tmp_path, monkeypatch):
    store = tmp_path / "evidence"

    def no_links(*_args, **_kwargs):
        raise OSError("operation not supported")

    monkeypatch.setattr(os, "link", no_links)
    result = run_preflight(store)

    checks = _by_id(result)
    assert checks["STORE_HARDLINKS"]["status"] == FAIL
    assert C.ATOMIC_CREATE_UNAVAILABLE in checks["STORE_HARDLINKS"]["detail"]
    assert result["status"] == FAIL
    # The probe directory is cleaned up even on the failure path.
    assert list(tmp_path.glob(".preflight-*")) == []


# --------------------------------------------------------------- integrity
def test_a_tampered_store_fails_the_preflight(tmp_path):
    scenario = build_scenario(tmp_path)
    run_cycle(
        CycleOptions(
            store_root=scenario.store_root,
            transport=scenario.transport,
            api=scenario.api,
            clock=scenario.options().clock,
        )
    )
    run_file = sorted((scenario.store_root / "runs").glob("*.json"))[0]
    run_file.write_text("{ not valid json")

    result = run_preflight(scenario.store_root)

    checks = _by_id(result)
    assert checks["STORE_INTEGRITY"]["status"] == FAIL
    assert "SCHEMA" in checks["STORE_INTEGRITY"]["detail"]
    assert result["status"] == FAIL


def test_a_healthy_store_passes_the_integrity_check(tmp_path):
    scenario = build_scenario(tmp_path)
    run_cycle(
        CycleOptions(
            store_root=scenario.store_root,
            transport=scenario.transport,
            api=scenario.api,
            clock=scenario.options().clock,
        )
    )

    result = run_preflight(scenario.store_root)

    checks = _by_id(result)
    assert result["status"] == PASS
    assert checks["STORE_INTEGRITY"]["status"] == PASS
    assert "1 capture(s) verified" in checks["STORE_INTEGRITY"]["detail"]
    assert checks["STORE_HARDLINKS"]["status"] == PASS


def test_the_preflight_never_writes_to_the_store(tmp_path):
    scenario = build_scenario(tmp_path)
    run_cycle(
        CycleOptions(
            store_root=scenario.store_root,
            transport=scenario.transport,
            api=scenario.api,
            clock=scenario.options().clock,
        )
    )
    before = _tree(scenario.store_root)

    result = run_preflight(scenario.store_root, tmp_path / "reports" / "cycle.md")
    assert result["status"] == PASS

    assert _tree(scenario.store_root) == before


# ------------------------------------------------------------------ timezone
def test_the_preflight_reports_this_machine_locale_as_information_only(tmp_path):
    result = run_preflight(tmp_path / "evidence", trigger=dt.time(13, 10))

    checks = _by_id(result)
    tz = result["timezone"]
    assert checks["LOCAL_TRIGGER_TIME"]["status"] == INFO
    assert tz["trigger_utc"] == "13:10"
    assert tz["trigger_local"].count(":") == 1
    # The reported local time must equal the conversion of the reported instant.
    fired = local_time_for_utc(
        dt.time(13, 10),
        dt.datetime.fromisoformat(tz["utc_now"].replace("Z", "+00:00")).astimezone().tzinfo,
        dt.date.fromisoformat(tz["utc_now"][:10]),
    )
    assert tz["trigger_local"] == fired.strftime("%H:%M")
    # Information never changes the verdict for an otherwise valid configuration.
    assert checks["LOCAL_TRIGGER_TIME"]["status"] != FAIL


# ---------------------------------------------------------------------- tool
def _run_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        cwd=str(PRODUCT_ROOT),
        timeout=120,
    )


def test_the_tool_describes_itself():
    completed = _run_tool("--help")
    assert completed.returncode == 0
    assert "--store" in completed.stdout
    assert "--trigger-utc" in completed.stdout


def test_the_tool_passes_on_a_usable_configuration_and_prints_the_timezone_line(tmp_path):
    completed = _run_tool("--store", str(tmp_path / "evidence"))

    assert completed.returncode == EXIT_OK
    assert "preflight: PASS" in completed.stdout
    assert "network used: no" in completed.stdout
    assert "LOCAL_TRIGGER_TIME" in completed.stdout


def test_the_tool_exits_one_on_a_refused_configuration():
    completed = _run_tool("--store", str(PRODUCT_ROOT / "var" / "evidence"))

    assert completed.returncode == EXIT_FAILED == 1
    assert "preflight: FAIL" in completed.stdout
    assert "STORE_OUTSIDE_REPOSITORY" in completed.stdout


def test_the_tool_emits_parseable_json(tmp_path):
    completed = _run_tool("--store", str(tmp_path / "evidence"), "--json")

    payload = json.loads(completed.stdout)
    assert completed.returncode == EXIT_OK
    assert payload["status"] == PASS
    assert payload["network_used"] is False
    assert payload["timezone"]["trigger_utc"] == "13:10"
    assert {check["id"] for check in payload["checks"]} >= {
        "PYTHON_RUNTIME",
        "STORE_ABSOLUTE",
        "PATH_SAFETY",
        "STORE_HARDLINKS",
        "STORE_INTEGRITY",
        "LOCAL_TRIGGER_TIME",
    }


def test_the_tool_rejects_a_malformed_trigger(tmp_path):
    completed = _run_tool("--store", str(tmp_path / "evidence"), "--trigger-utc", "13:10:00")

    assert completed.returncode == 2
    assert "HH:MM" in completed.stderr


def test_the_tool_accepts_a_custom_trigger_and_reports_it(tmp_path):
    completed = _run_tool(
        "--store", str(tmp_path / "evidence"), "--trigger-utc", "06:05", "--json"
    )

    payload = json.loads(completed.stdout)
    assert payload["timezone"]["trigger_utc"] == "06:05"
    assert completed.returncode == EXIT_OK


def test_the_preflight_does_not_import_the_capture_transport():
    """A scheduling check must not be able to start a capture.

    ``vulnova.prospective.preflight`` deliberately imports verification and path
    safety only.  If it ever imports the capture module, this guard fails and the
    reviewer is told that a "dry run" gained the ability to record evidence.
    """
    import ast

    module = ast.parse(
        (PRODUCT_ROOT / "vulnova" / "prospective" / "preflight.py").read_text()
    )
    imported = set()
    for node in ast.walk(module):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)

    assert not any(name.endswith("capture") for name in imported), imported
    assert not any("transport" in name for name in imported), imported
    assert not any("urllib" in name for name in imported), imported
