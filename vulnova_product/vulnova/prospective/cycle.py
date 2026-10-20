"""One scheduled cycle: capture once, verify the store, report what happened.

A scheduler needs one command and one exit status that says whether a human must
look.  This module is that command's engine: it validates every configured path,
performs exactly one capture with the real UTC clock, verifies the store offline,
builds the deterministic report, and returns a summary a monitoring script can
parse.  The CLI supplies the production transport; tests inject a fake one, so
nothing here opens a socket.

Nothing here retries.  A source that fails is recorded as failed and the cycle
ends: a retry loop against a publisher turns one outage into a burst of traffic
and would make the stored evidence depend on how patient the scheduler was.

Exit status is about *this run*, never about the world:

* ``0`` — the capture verified every source and the store verified;
* ``2`` — nothing was recorded: an unsafe destination, or a capture that failed
  before its run record could be written;
* ``3`` — the run was recorded, but at least one source did not verify;
* ``4`` — the store did not verify (or could not be verified).

A non-zero exit never deletes a capture that was written.  The record of a
partial capture is the evidence; it is not a failure to be cleaned up.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..acquisition import constants as A
from ..acquisition.github import GitHubApi
from ..acquisition.transport import Transport
from ..provenance import utc_now
from ..refresh.errors import PathSafetyError
from .capture import CaptureError, CaptureOptions, run_capture
from .paths import assert_capture_safety
from .report import build_report, write_json, write_markdown
from .store import StoreError
from .verify import verify_failure_reasons, verify_store

SCHEMA_VERSION = "vulnova.prospective.cycle/1.9"

#: Only a capture that verified every source *and* a store that verified is a
#: success.  Everything else is a status a person or a monitoring rule must see.
EXIT_OK = 0
EXIT_NOT_RECORDED = 2
EXIT_INCOMPLETE = 3
EXIT_INTEGRITY = 4

REASON_OK = "OK"
REASON_UNSAFE = "UNSAFE_CONFIGURATION"
REASON_NOT_RECORDED = "CAPTURE_NOT_RECORDED"
REASON_INCOMPLETE = "CAPTURE_INCOMPLETE"
REASON_INTEGRITY = "INTEGRITY_FAILED"
REASON_REPORT = "REPORT_NOT_WRITTEN"

#: Printed in every result so a failure cannot be read as an absence finding.
NOTE = (
    "A cycle captures, verifies and reports. It does not evaluate, and a missing "
    "source is a gap in observation, never evidence that nothing was exploited."
)


@dataclass
class CycleOptions:
    """Inputs for one cycle.

    ``transport``, ``api`` and ``clock`` are injected so tests run offline; the
    CLI passes the production HTTPS transport and the real UTC clock.  A capture
    that its caller could date would be worth no more than the backdated
    historical evidence this subsystem exists to avoid repeating, so no CLI flag
    sets the clock.
    """

    store_root: Path | str
    transport: Transport
    api: GitHubApi
    clock: Callable[[], str] = utc_now
    protected_paths: tuple[Path, ...] = ()
    report_path: Optional[Path] = None
    report_format: str = "markdown"


def _integrity(verification: Optional[dict]) -> Optional[dict]:
    if verification is None:
        return None
    return {
        "status": verification["status"],
        "captures": verification["captures"],
        "artifacts_hashed": verification["artifacts_hashed"],
        "failed_checks": verify_failure_reasons(verification),
    }


def _result(
    *,
    store_root: Path | str,
    reason: str,
    exit_code: int,
    capture_attempted: bool,
    capture: Optional[dict] = None,
    verification: Optional[dict] = None,
    report: Optional[dict] = None,
    report_path: Optional[Path] = None,
    report_written: bool = False,
    error: Optional[str] = None,
) -> dict:
    """One stable shape, so a monitoring script parses every outcome the same way."""
    run = capture["run"] if capture is not None else None
    summary = run["summary"] if run is not None else None

    return {
        "schema_version": SCHEMA_VERSION,
        "store": str(store_root),
        "capture_attempted": capture_attempted,
        "capture_recorded": run is not None,
        "reason": reason,
        "exit_code": exit_code,
        "outcome": capture["outcome"] if capture is not None else None,
        "run_id": run["run_id"] if run is not None else None,
        "observation_date": run["observation_date"] if run is not None else None,
        "capture_started_at": run["capture_started_at"] if run is not None else None,
        "capture_completed_at": run["capture_completed_at"] if run is not None else None,
        "capture_status": summary["capture_status"] if summary is not None else None,
        "sources_verified": summary["sources_verified"] if summary is not None else None,
        "sources_total": summary["sources_total"] if summary is not None else None,
        "sources": [
            {
                "id": requirement["id"],
                "status": requirement["status"],
                "reason_code": requirement["reason_code"],
                "detail": requirement["detail"],
            }
            for requirement in (run["requirements"] if run is not None else [])
        ],
        "integrity": _integrity(verification),
        "report_digest": report["report_digest"] if report is not None else None,
        "report_path": str(report_path) if report_path is not None else None,
        "report_written": report_written,
        "error": error,
        "note": NOTE,
    }


def _write_report(report: dict, path: Path, report_format: str) -> None:
    if report_format == "json":
        write_json(report, path)
    else:
        write_markdown(report, path)


def run_cycle(options: CycleOptions) -> dict:
    """Run one capture, verify the store, build the report, and classify the run.

    Path safety comes first: an unsafe destination is refused before the clock is
    read and before the first request, exactly as ``capture`` does.  The capture
    itself is ``run_capture`` unchanged — one call, no retry loop.
    """
    outputs = (options.report_path,) if options.report_path is not None else ()

    try:
        assert_capture_safety(options.store_root, outputs, options.protected_paths)
    except PathSafetyError as exc:
        return _result(
            store_root=options.store_root,
            reason=REASON_UNSAFE,
            exit_code=EXIT_NOT_RECORDED,
            capture_attempted=False,
            report_path=options.report_path,
            error=str(exc),
        )

    try:
        capture = run_capture(
            CaptureOptions(
                store_root=options.store_root,
                transport=options.transport,
                api=options.api,
                clock=options.clock,
                protected_paths=options.protected_paths,
                output_paths=outputs,
            )
        )
    except (CaptureError, PathSafetyError) as exc:
        # Nothing was recorded.  Any artifact already written stays where it is:
        # an orphan is a finding for `verify`, not something to sweep away.
        return _result(
            store_root=options.store_root,
            reason=REASON_NOT_RECORDED,
            exit_code=EXIT_NOT_RECORDED,
            capture_attempted=True,
            report_path=options.report_path,
            error=str(exc),
        )

    # The capture is on disk.  From here on, nothing may discard it.
    try:
        verification = verify_store(options.store_root)
        report = build_report(options.store_root)
    except Exception as exc:  # noqa: BLE001 - an unreadable store is an integrity finding
        return _result(
            store_root=options.store_root,
            reason=REASON_INTEGRITY,
            exit_code=EXIT_INTEGRITY,
            capture_attempted=True,
            capture=capture,
            report_path=options.report_path,
            error=f"the store could not be verified or reported: {exc}",
        )

    report_written = False
    write_error: Optional[str] = None
    if options.report_path is not None:
        try:
            _write_report(report, options.report_path, options.report_format)
            report_written = True
        except (OSError, StoreError, PathSafetyError) as exc:
            write_error = f"the report could not be written to {options.report_path}: {exc}"

    integrity_ok = verification["status"] == A.VERIFIED
    capture_ok = capture["run"]["summary"]["capture_status"] == A.VERIFIED

    if not integrity_ok:
        # The store's own checks outrank the capture: if the archive cannot be
        # trusted, the fact that one run observed three sources proves little.
        reason, exit_code = REASON_INTEGRITY, EXIT_INTEGRITY
    elif write_error is not None:
        reason, exit_code = REASON_REPORT, EXIT_NOT_RECORDED
    elif not capture_ok:
        reason, exit_code = REASON_INCOMPLETE, EXIT_INCOMPLETE
    else:
        reason, exit_code = REASON_OK, EXIT_OK

    return _result(
        store_root=options.store_root,
        reason=reason,
        exit_code=exit_code,
        capture_attempted=True,
        capture=capture,
        verification=verification,
        report=report,
        report_path=options.report_path,
        report_written=report_written,
        error=write_error,
    )


__all__ = [
    "EXIT_INCOMPLETE",
    "EXIT_INTEGRITY",
    "EXIT_NOT_RECORDED",
    "EXIT_OK",
    "NOTE",
    "REASON_INCOMPLETE",
    "REASON_INTEGRITY",
    "REASON_NOT_RECORDED",
    "REASON_OK",
    "REASON_REPORT",
    "REASON_UNSAFE",
    "SCHEMA_VERSION",
    "CycleOptions",
    "run_cycle",
]
