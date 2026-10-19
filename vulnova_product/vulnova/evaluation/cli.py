"""Command-line interface for evaluation readiness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import constants as C
from .protocol import ProtocolError
from .readiness import ReadinessError, ReadinessOptions, build_report
from .report import set_reproducibility, write_json, write_markdown


def _product_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def build_parser() -> argparse.ArgumentParser:
    product = _product_root()
    repository = _repository_root()
    parser = argparse.ArgumentParser(
        prog="python -m vulnova.evaluation",
        description=(
            "VULNOVA 1.6 evaluation-readiness checks. Reads Phase 2.3K evidence and "
            "writes a machine-readable readiness report. Trains nothing, scores "
            "nothing, approves nothing."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    readiness = subparsers.add_parser(
        "readiness", help="run the readiness check suite and write a report"
    )
    readiness.add_argument(
        "--artifacts",
        type=Path,
        default=repository / "phase2.3k-export",
        help="phase2.3k-export directory (default: %(default)s)",
    )
    readiness.add_argument(
        "--protocol",
        type=Path,
        default=product / "protocol" / "evaluation_protocol.json",
        help="machine-readable protocol file (default: %(default)s)",
    )
    readiness.add_argument(
        "--as-of",
        default=None,
        help=(
            "ISO date used for maturity decisions; defaults to the protocol "
            "reference date so runs are reproducible"
        ),
    )
    readiness.add_argument(
        "--export-archive",
        type=Path,
        default=None,
        help="override the full export tarball path",
    )
    readiness.add_argument(
        "--core-bundle",
        type=Path,
        default=None,
        help="override the core bundle tarball path",
    )
    readiness.add_argument(
        "--extract-dir",
        type=Path,
        default=None,
        help="cache directory for extracted artifacts (default: build/evaluation_artifacts)",
    )
    readiness.add_argument(
        "--no-extract",
        action="store_true",
        help="never extract archives; use an already extracted dataset",
    )
    readiness.add_argument(
        "--no-deep",
        action="store_true",
        help="skip the 6.85 M-row membership partition scan",
    )
    readiness.add_argument(
        "--previous-report",
        type=Path,
        default=None,
        help="optional prior report for digest self-consistency verification",
    )
    readiness.add_argument(
        "--out",
        type=Path,
        default=product / "reports" / "evaluation_readiness_1_6" / "readiness_report.json",
        help="JSON report path (default: %(default)s)",
    )
    readiness.add_argument(
        "--markdown",
        type=Path,
        default=None,
        help="optional Markdown report path",
    )
    readiness.add_argument(
        "--check-reproducible",
        action="store_true",
        help="run the suite twice and compare canonical digests",
    )
    readiness.add_argument(
        "--require-ready",
        action="store_true",
        help="exit 1 unless readiness is READY_FOR_PROTOCOL_EXECUTION",
    )
    readiness.add_argument(
        "--quiet", action="store_true", help="print only the readiness status line"
    )
    return parser


def _print_summary(report: dict, out_path: Path, reproducible: Optional[bool]) -> None:
    summary = report["summary"]
    readiness = report["readiness"]
    protocol = report["protocol"]
    print("VULNOVA 1.6 — evaluation readiness")
    print(
        f"as of {report['as_of']} · reference {report['reference_date']} · "
        f"protocol {protocol['protocol_id']} · approval {protocol['approval_state']}"
    )
    print(
        f"checks: PASS {summary[C.STATUS_PASS]} · FAIL {summary[C.STATUS_FAIL]} · "
        f"BLOCKED {summary[C.STATUS_BLOCKED]} · "
        f"NOT_APPLICABLE {summary[C.STATUS_NOT_APPLICABLE]} "
        f"(total {summary['total']})"
    )
    print(f"READINESS: {readiness['status']}")
    for blocker in readiness.get("blockers", []):
        if blocker.get("primary"):
            print(f"primary blocker: {blocker['code']} — {blocker['detail']}")
    if reproducible is not None:
        print(f"double-run digest match: {'yes' if reproducible else 'NO'}")
    print(f"report: {out_path}")
    print(f"digest: {report['report_digest']}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "readiness":
        parser.print_help()
        return 0

    options = ReadinessOptions(
        artifact_dir=args.artifacts,
        protocol_path=args.protocol,
        as_of=args.as_of,
        deep=not args.no_deep,
        export_archive=args.export_archive,
        core_bundle=args.core_bundle,
        extract_dir=args.extract_dir,
        previous_report_path=args.previous_report,
        repository_root=_repository_root(),
        extract=not args.no_extract,
    )
    try:
        report = build_report(options)
    except (ReadinessError, ProtocolError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    second_digest = None
    if args.check_reproducible:
        try:
            second = build_report(options)
        except (ReadinessError, ProtocolError) as exc:
            print(f"error: reproducibility re-run failed: {exc}", file=sys.stderr)
            return 2
        second_digest = second["report_digest"]
        if second_digest != report["report_digest"]:
            print(
                "error: the readiness report is not reproducible: "
                f"{report['report_digest']} != {second_digest}",
                file=sys.stderr,
            )
    previous_digest = None
    if args.previous_report is not None:
        try:
            previous = json.loads(Path(args.previous_report).read_text(encoding="utf-8"))
            previous_digest = previous.get("report_digest")
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: could not read previous report: {exc}", file=sys.stderr)

    set_reproducibility(
        report, second_digest=second_digest, previous_digest=previous_digest
    )
    out_path = write_json(report, args.out)
    if args.markdown is not None:
        write_markdown(report, args.markdown)

    if second_digest is not None and second_digest != report["report_digest"]:
        # The report itself is unchanged; the mismatch is already in its
        # reproducibility block.  Fail loudly so CI cannot ignore it.
        _print_summary(report, out_path, False)
        return 1

    if args.quiet:
        print(report["readiness"]["status"])
    else:
        _print_summary(
            report,
            out_path,
            None if second_digest is None else second_digest == report["report_digest"],
        )
    if args.require_ready and report["readiness"]["status"] != "READY_FOR_PROTOCOL_EXECUTION":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
