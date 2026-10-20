"""Command-line interface for prospective evidence capture.

    python -m vulnova.prospective capture   # record one observation (network)
    python -m vulnova.prospective verify    # offline re-hash of the store
    python -m vulnova.prospective report    # deterministic summary

``capture`` is the only command that touches the network, and it always uses the
real UTC clock: a prospective capture that could be dated by its caller would be
worth no more than the backdated historical evidence this subsystem exists to
avoid repeating.  Tests inject a clock through
:class:`vulnova.prospective.capture.CaptureOptions`.
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
from ..refresh.errors import PathSafetyError
from . import constants as C
from .capture import CaptureError, CaptureOptions, run_capture
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


COMMANDS = {"capture": _cmd_capture, "verify": _cmd_verify, "report": _cmd_report}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in COMMANDS:
        parser.print_help()
        return 0
    return COMMANDS[args.command](args)


__all__ = ["build_parser", "main"]
