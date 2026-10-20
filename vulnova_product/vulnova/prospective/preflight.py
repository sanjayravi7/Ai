"""Offline preflight for a scheduled prospective cycle.

A scheduler is configured once and then trusted for months, so the failure modes
that matter are configuration failure modes: a relative path that means something
different under cron, a store on the wrong side of the repository, a report path
inside a sealed directory, a filesystem that cannot hard-link (the store requires
links and fails closed without them), or a trigger time that was written as UTC
but will be interpreted in local time.

This module answers those questions **without performing a capture and without
opening a socket**.  It reads the store, probes the destination filesystem, and
verifies the existing archive — nothing here writes evidence, deletes evidence or
contacts a publisher.  ``cycle`` itself is untouched: this is a check an operator
runs after editing a crontab or a Task Scheduler entry, and again after moving a
machine between timezones.

Every check has an outcome:

* ``PASS`` — the configuration is usable as written;
* ``WARN`` — usable, but something is worth knowing (an empty store, a report
  that will be replaced, a filesystem that could not be probed);
* ``FAIL`` — a scheduled cycle would misbehave or refuse to run;
* ``INFO`` — a fact, not a verdict (the machine's timezone offset).

``status`` is ``FAIL`` if any check failed, otherwise ``PASS``.  The exit status
is ``0`` for ``PASS`` and ``1`` for ``FAIL``, so the check itself can be wired
into a deployment gate.
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

from ..acquisition import constants as A
from ..refresh.errors import PathSafetyError
from ..refresh.paths import package_roots
from . import constants as C
from .paths import assert_capture_safety
from .verify import verify_failure_reasons, verify_store

SCHEMA_VERSION = "vulnova.prospective.preflight/1.9"

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
INFO = "INFO"

EXIT_OK = 0
EXIT_FAILED = 1

#: The documented schedule target: 13:10 UTC, after the EPSS daily file normally
#: appears.  Kept here so the preflight reports the same instant the docs use.
TRIGGER_UTC = dt.time(13, 10)

NOTE = (
    "A preflight checks configuration only. It does not capture, does not prove "
    "a source is reachable, and cannot verify that a scheduler is configured to "
    "fire at the intended UTC instant."
)


def _check(check_id: str, status: str, detail: str) -> dict:
    return {"id": check_id, "status": status, "detail": detail}


def _nearest_existing(path: Path) -> Optional[Path]:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return None


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _format_offset(moment: dt.datetime) -> str:
    offset = moment.utcoffset() or dt.timedelta(0)
    total = int(offset.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def local_time_for_utc(
    trigger: dt.time, tz: dt.tzinfo, reference: Optional[dt.date] = None
) -> dt.datetime:
    """The instant ``trigger`` UTC falls on, expressed in ``tz``.

    Date-aware on purpose: 13:10 UTC is 18:40 in Asia/Kolkata but 02:10 the *next
    day* in Pacific/Auckland, and a schedule written for the wrong day fires on
    the wrong date.
    """
    day = reference or dt.datetime.now(dt.timezone.utc).date()
    instant = dt.datetime.combine(day, trigger, tzinfo=dt.timezone.utc)
    return instant.astimezone(tz)


def _timezone_report(trigger: dt.time) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    local = now.astimezone()
    tz = local.tzinfo or dt.timezone.utc
    fired = local_time_for_utc(trigger, tz, now.date())
    offset_hours = (local.utcoffset() or dt.timedelta(0)).total_seconds() / 3600
    return {
        "utc_now": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "local_now": local.strftime("%Y-%m-%d %H:%M:%S"),
        "utc_offset": _format_offset(local),
        "zone_name": getattr(tz, "key", None) or os.environ.get("TZ") or "",
        "trigger_utc": trigger.strftime("%H:%M"),
        "trigger_local": fired.strftime("%H:%M"),
        "trigger_local_date": fired.strftime("%Y-%m-%d"),
        "trigger_crosses_date": fired.date() != now.date(),
        "local_is_utc": offset_hours == 0,
    }


def _store_checks(store: Path, store_text: Path | str) -> list[dict]:
    checks: list[dict] = []

    if Path(store_text).is_absolute():
        checks.append(_check("STORE_ABSOLUTE", PASS, f"store is absolute: {store}"))
    else:
        checks.append(
            _check(
                "STORE_ABSOLUTE",
                FAIL,
                f"store {str(store_text)!r} is relative; a scheduler's working "
                "directory is not the one you tested in — use an absolute path",
            )
        )

    product_root, repository_root = package_roots()
    if _is_within(store, Path(repository_root).resolve()):
        checks.append(
            _check(
                "STORE_OUTSIDE_REPOSITORY",
                FAIL,
                f"store {store} is inside the repository {repository_root}; "
                "evidence and generated reports must live outside it",
            )
        )
    else:
        checks.append(
            _check("STORE_OUTSIDE_REPOSITORY", PASS, f"store is outside {repository_root}")
        )

    if store.exists():
        if not store.is_dir():
            checks.append(
                _check("STORE_LOCATION", FAIL, f"store {store} exists and is not a directory")
            )
        elif os.access(store, os.W_OK | os.X_OK):
            checks.append(_check("STORE_LOCATION", PASS, f"store exists and is writable: {store}"))
        else:
            checks.append(
                _check("STORE_LOCATION", FAIL, f"store {store} exists but is not writable")
            )
    else:
        parent = _nearest_existing(store.parent)
        if parent is None:
            checks.append(
                _check("STORE_LOCATION", FAIL, f"no existing parent directory for {store}")
            )
        elif os.access(parent, os.W_OK | os.X_OK):
            checks.append(
                _check(
                    "STORE_LOCATION",
                    WARN,
                    f"store does not exist yet; the first cycle will create it under {parent}",
                )
            )
        else:
            checks.append(
                _check(
                    "STORE_LOCATION",
                    FAIL,
                    f"store does not exist and {parent} is not writable",
                )
            )

    return checks


def _hardlink_check(store: Path) -> dict:
    """Prove the destination filesystem can hard-link, which the store requires.

    The probe runs in a temporary directory that is removed afterwards.  It never
    writes into ``artifacts/`` or ``runs/``, so it cannot create evidence or an
    inventory finding, and the store keeps its create-once guarantee: nothing
    here can overwrite a captured file.
    """
    base = store if store.exists() else _nearest_existing(store.parent)
    if base is None:  # pragma: no cover - defensive; STORE_LOCATION already failed
        return _check("STORE_HARDLINKS", FAIL, "no directory available to probe")
    if not os.access(base, os.W_OK | os.X_OK):
        return _check(
            "STORE_HARDLINKS",
            WARN,
            f"could not probe hard-link support: {base} is not writable",
        )
    probe = None
    try:
        probe = Path(tempfile.mkdtemp(dir=base, prefix=".preflight-"))
        target = probe / "probe"
        target.write_bytes(b"preflight")
        os.link(target, probe / "probe-link")
    except OSError as exc:
        return _check(
            "STORE_HARDLINKS",
            FAIL,
            f"{base} cannot hard-link ({exc.__class__.__name__}: {exc}); the store "
            f"would fail closed with {C.ATOMIC_CREATE_UNAVAILABLE} and store nothing",
        )
    finally:
        if probe is not None:
            shutil.rmtree(probe, ignore_errors=True)
    return _check("STORE_HARDLINKS", PASS, f"hard links work on {base}")


def _report_checks(report: Optional[Path], report_text: Optional[Path | str]) -> list[dict]:
    if report is None:
        return [_check("REPORT_PATH", INFO, "no report path configured (--out is optional)")]

    checks: list[dict] = []
    if Path(report_text).is_absolute():
        checks.append(_check("REPORT_ABSOLUTE", PASS, f"report path is absolute: {report}"))
    else:
        checks.append(
            _check(
                "REPORT_ABSOLUTE",
                FAIL,
                f"report path {str(report_text)!r} is relative; use an absolute path",
            )
        )

    _product_root, repository_root = package_roots()
    if _is_within(report, Path(repository_root).resolve()):
        checks.append(
            _check(
                "REPORT_OUTSIDE_REPOSITORY",
                FAIL,
                f"report path {report} is inside the repository {repository_root}",
            )
        )
    else:
        checks.append(
            _check("REPORT_OUTSIDE_REPOSITORY", PASS, f"report path is outside {repository_root}")
        )

    parent = _nearest_existing(report.parent)
    if parent is None:
        checks.append(_check("REPORT_LOCATION", FAIL, f"no existing parent for {report}"))
    elif not os.access(parent, os.W_OK | os.X_OK):
        checks.append(_check("REPORT_LOCATION", FAIL, f"{parent} is not writable"))
    elif report.exists():
        checks.append(
            _check(
                "REPORT_LOCATION",
                WARN,
                f"{report} exists and will be replaced atomically; reports are "
                "regenerable, evidence is not",
            )
        )
    else:
        checks.append(_check("REPORT_LOCATION", PASS, f"report will be written to {report}"))
    return checks


def _safety_check(store: Path, outputs: tuple[Path, ...]) -> dict:
    try:
        assert_capture_safety(store, outputs)
    except PathSafetyError as exc:
        return _check("PATH_SAFETY", FAIL, str(exc))
    return _check(
        "PATH_SAFETY",
        PASS,
        "store and report targets clear the sealed 1.6/1.7/1.8 paths and the "
        "protocol directory",
    )


def _integrity_check(store: Path) -> dict:
    if not store.exists():
        return _check(
            "STORE_INTEGRITY",
            WARN,
            "no store yet: there is nothing to verify and the first cycle will create it",
        )
    result = verify_store(store)
    if result["status"] == A.VERIFIED:
        return _check(
            "STORE_INTEGRITY",
            PASS,
            f"{result['captures']} capture(s) verified; "
            f"{result['artifacts_hashed']} artifact(s) re-hashed",
        )
    failed = verify_failure_reasons(result)
    if failed == ["CAPTURES_PRESENT"]:
        return _check(
            "STORE_INTEGRITY",
            WARN,
            "the store holds no captures yet; an empty store is not a verified "
            "store and not a failure of this configuration",
        )
    return _check(
        "STORE_INTEGRITY",
        FAIL,
        "the store does not verify: " + (", ".join(failed) or result["status"])
        + " — a scheduled cycle would exit 4 until this is understood",
    )


def _runtime_check() -> dict:
    version = sys.version_info
    if version < (3, 11):
        return _check(
            "PYTHON_RUNTIME",
            FAIL,
            f"python {version.major}.{version.minor} is too old; 3.11+ is required",
        )
    try:
        import vulnova  # noqa: PLC0415 - reported, not used
    except Exception as exc:  # pragma: no cover - import failure is the point
        return _check(
            "PYTHON_RUNTIME", FAIL, f"cannot import vulnova from this interpreter: {exc}"
        )
    return _check(
        "PYTHON_RUNTIME",
        PASS,
        f"python {version.major}.{version.minor}.{version.micro} at {sys.executable}; "
        f"vulnova {vulnova.__version__}",
    )


def run_preflight(
    store_root: Path | str,
    report_path: Optional[Path | str] = None,
    trigger: dt.time = TRIGGER_UTC,
) -> dict:
    """Check a schedule configuration without capturing anything.

    Read-only with respect to evidence: the store is verified, never written.  The
    one filesystem mutation is a temporary directory used to prove hard links,
    removed in a ``finally`` block.
    """
    store = Path(store_root).expanduser()
    # ``abspath`` rather than ``resolve``: a store reached through a symlink is
    # still the store, and resolving it here would report a path the operator
    # never wrote.
    resolved_store = Path(os.path.abspath(store))
    report = Path(report_path).expanduser() if report_path is not None else None
    resolved_report = Path(os.path.abspath(report)) if report is not None else None

    checks = [_runtime_check()]
    checks.extend(_store_checks(resolved_store, store_root))
    checks.extend(_report_checks(resolved_report, report_path))
    checks.append(_safety_check(resolved_store, (resolved_report,) if resolved_report else ()))
    checks.append(_hardlink_check(resolved_store))
    checks.append(_integrity_check(resolved_store))

    timezone = _timezone_report(trigger)
    trigger_local = timezone["trigger_local"] + (
        f" on {timezone['trigger_local_date']} (the previous/next UTC day)"
        if timezone["trigger_crosses_date"]
        else ""
    )
    checks.append(
        _check(
            "LOCAL_TRIGGER_TIME",
            INFO,
            f"{timezone['trigger_utc']} UTC is {trigger_local} in this machine's "
            f"timezone (UTC{timezone['utc_offset']}). If the scheduler fires on "
            "local time, that is the time to configure.",
        )
    )

    failed = [check for check in checks if check["status"] == FAIL]
    return {
        "schema_version": SCHEMA_VERSION,
        "store": str(resolved_store),
        "report_path": str(resolved_report) if resolved_report is not None else None,
        "status": FAIL if failed else PASS,
        "checks": checks,
        "failed": [check["id"] for check in failed],
        "timezone": timezone,
        "network_used": False,
        "note": NOTE,
    }


__all__ = [
    "EXIT_FAILED",
    "EXIT_OK",
    "FAIL",
    "INFO",
    "NOTE",
    "PASS",
    "SCHEMA_VERSION",
    "TRIGGER_UTC",
    "WARN",
    "local_time_for_utc",
    "run_preflight",
]
