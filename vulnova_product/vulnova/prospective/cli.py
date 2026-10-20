"""Command-line interface for prospective evidence capture.

    python -m vulnova.prospective capture   # record one observation (network)
    python -m vulnova.prospective cycle     # capture + verify + report (network)
    python -m vulnova.prospective verify    # offline re-hash of the store
    python -m vulnova.prospective report    # deterministic summary

``capture`` and ``cycle`` are the only commands that touch the network, and both
always use the real UTC clock: a prospective capture that could be dated by its
caller would be worth no more than the backdated historical evidence this
subsystem exists to avoid repeating.  Tests inject a clock through
:class:`vulnova.prospective.capture.CaptureOptions` or
:class:`vulnova.prospective.cycle.CycleOptions`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from ..acquisition import constants as A
from ..acquisition.github import GitHubApi
from ..acquisition.transport import UrllibTransport
from ..provenance import utc_now
from ..refresh.errors import PathSafetyError
from . import constants as C
from .capture import CaptureError, CaptureOptions, run_capture
from .cycle import CycleOptions, run_cycle
from .paths import assert_capture_safety
from .report import build_report, render_markdown, write_json, write_markdown
from .verify import verify_store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulnova.prospective",
        description=(
            "VULNOVA 1.9 prospective evidence capture. Preserves first-party KEV, "
            "EPSS and cvelistV5 observations with their real retrieval times. "
            "It captures evidence; it does not evaluate anything."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    capture = subparsers.add_parser(
        "capture", help="record one observation of KEV, EPSS and cvelistV5"
    )
    capture.add_argument(
        "--store",
        type=Path,
        default=C.default_store_root(),
        help="evidence store (default: %(default)s)",
    )
    capture.add_argument("--json", action="store_true", help="emit the run record as JSON")
    capture.add_argument("--quiet", action="store_true", help="print the status lines only")

    cycle = subparsers.add_parser(
        "cycle",
        help="capture once, verify the store and report (one scheduler run)",
        description=(
            "Run one complete prospective cycle: validate every destination, "
            "capture once with the real UTC clock, verify the store offline and "
            "build the deterministic report. Exits 0 only when the capture and "
            "the store both verify; 2 when nothing was recorded, 3 when the run "
            "was recorded but a source did not verify, 4 when the store did not "
            "verify. A non-zero exit never removes a recorded capture."
        ),
    )
    cycle.add_argument(
        "--store",
        type=Path,
        default=C.default_store_root(),
        help="evidence store (default: %(default)s)",
    )
    cycle.add_argument(
        "--out",
        type=Path,
        default=None,
        help="also write the deterministic report to this path",
    )
    cycle.add_argument(
        "--json",
        action="store_true",
        help="emit the cycle summary as JSON, and write --out as JSON",
    )

    verify = subparsers.add_parser(
        "verify", help="offline: re-hash every capture and re-derive every id"
    )
    verify.add_argument(
        "--store",
        type=Path,
        default=C.default_store_root(),
        help="evidence store (default: %(default)s)",
    )
    verify.add_argument("--json", action="store_true", help="emit JSON")

    report = subparsers.add_parser(
        "report", help="offline: deterministic summary of what was captured"
    )
    report.add_argument(
        "--store",
        type=Path,
        default=C.default_store_root(),
        help="evidence store (default: %(default)s)",
    )
    report.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write the report to this path instead of stdout",
    )
    report.add_argument(
        "--json",
        action="store_true",
        help="emit the machine-readable report instead of Markdown",
    )
    return parser


def _print_summary(result: dict) -> None:
    run = result["run"]
    summary = run["summary"]
    print("VULNOVA 1.9 — prospective evidence capture")
    print(f"store: {result['store']}")
    print(f"observation date: {run['observation_date']}")
    print(
        f"capture status: {summary['capture_status']} "
        f"({summary['sources_verified']}/{summary['sources_total']} sources verified)"
    )
    for requirement in run["requirements"]:
        print(
            f"  {requirement['status']:<9} {requirement['id']} — "
            f"{requirement['reason_code']}"
        )
    print(f"run: {result['run_path']} ({result['outcome']})")
    print(f"digest: {run['run_digest']}")


def _cmd_capture(args) -> int:
    # Path safety before the transport exists: a refused run opens no socket.
    try:
        assert_capture_safety(args.store, ())
    except PathSafetyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    transport = UrllibTransport()
    options = CaptureOptions(
        store_root=args.store,
        transport=transport,
        api=GitHubApi(transport),
    )
    try:
        result = run_capture(options)
    except (CaptureError, PathSafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.quiet:
        summary = result["run"]["summary"]
        print(f"{result['run']['observation_date']} {summary['capture_status']} "
              f"{result['run']['run_id']}")
    else:
        _print_summary(result)
    return 0


def _print_cycle(result: dict) -> None:
    print("VULNOVA 1.9 — prospective cycle")
    print(f"store: {result['store']}")
    if not result["capture_recorded"]:
        print(f"capture: NOT RECORDED — {result['reason']}")
        return
    print(f"run: {result['run_id']} ({result['outcome']})")
    print(f"observation date: {result['observation_date']}")
    print(
        f"capture status: {result['capture_status']} "
        f"({result['sources_verified']}/{result['sources_total']} sources verified)"
    )
    for source in result["sources"]:
        print(f"  {source['status']:<9} {source['id']} — {source['reason_code']}")
    integrity = result["integrity"]
    if integrity is None:
        print("integrity: NOT ESTABLISHED (the store could not be verified)")
    else:
        detail = (
            f"{integrity['captures']} capture(s), "
            f"{integrity['artifacts_hashed']} artifact(s) hashed"
        )
        if integrity["failed_checks"]:
            detail += f"; failed: {', '.join(integrity['failed_checks'])}"
        print(f"integrity: {integrity['status']} ({detail})")
    digest = result["report_digest"] or "NOT AVAILABLE"
    print(f"report digest: {digest}")
    if result["report_path"] is not None:
        state = "written" if result["report_written"] else "NOT WRITTEN"
        print(f"report: {result['report_path']} ({state})")
    print(f"result: {result['reason']}")


def _cmd_cycle(args) -> int:
    # Path safety runs inside run_cycle before the clock and before the first
    # request; constructing the transport opens no socket.
    transport = UrllibTransport()
    result = run_cycle(
        CycleOptions(
            store_root=args.store,
            transport=transport,
            api=GitHubApi(transport),
            # The real UTC clock is chosen here and is not a flag: a cycle whose
            # caller could date it would not be a prospective observation.
            clock=utc_now,
            report_path=args.out,
            report_format="json" if args.json else "markdown",
        )
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_cycle(result)
        if result["error"]:
            print(f"error: {result['error']}", file=sys.stderr)
    return result["exit_code"]


def _cmd_verify(args) -> int:
    result = verify_store(args.store)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("VULNOVA 1.9 — offline verification")
        for check in result["checks"]:
            print(f"  {check['status']:<14} {check['id']} — {check['detail']}")
        print(f"integrity: {result['status']}")
        print(f"captures: {result['captures']} · artifacts hashed: {result['artifacts_hashed']}")
        if result["conflicts"]:
            print(f"conflicts preserved: {len(result['conflicts'])}")
        print("network used: no")
    return 0 if result["status"] == A.VERIFIED else 1


def _cmd_report(args) -> int:
    outputs = (args.out,) if args.out is not None else ()
    try:
        assert_capture_safety(args.store, outputs)
    except PathSafetyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = build_report(args.store)
    if args.json:
        body = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        body = render_markdown(report)

    if args.out is None:
        sys.stdout.write(body)
        return 0
    if args.json:
        write_json(report, args.out)
    else:
        write_markdown(report, args.out)
    print(f"report: {args.out}")
    print(f"digest: {report['report_digest']}")
    return 0


COMMANDS = {
    "capture": _cmd_capture,
    "cycle": _cmd_cycle,
    "verify": _cmd_verify,
    "report": _cmd_report,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in COMMANDS:
        parser.print_help()
        return 0
    return COMMANDS[args.command](args)


__all__ = ["build_parser", "main"]
