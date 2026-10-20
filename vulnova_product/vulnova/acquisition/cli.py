"""Command-line interface for VULNOVA 1.7 evidence acquisition.

    python -m vulnova.acquisition acquire   # fetch, store bytes, write manifest
    python -m vulnova.acquisition manifest  # re-serialise and re-attest a manifest
    python -m vulnova.acquisition verify    # offline hash/integrity verification
    python -m vulnova.acquisition check     # required sources and cutoff coverage
    python -m vulnova.acquisition report    # readable missing-evidence report

``acquire`` is the only command that touches the network.  Everything else is
offline and deterministic, so the archive can be re-audited without connectivity.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from ..evaluation.temporal import parse_date
from . import constants as C
from .github import GitHubApi
from .manifest import ManifestError, manifest_digest, read_json, write_json
from .report import render_markdown, write_markdown
from .store import ArtifactStore, StoreError
from .transport import Transport, TransportError, UrllibTransport
from .verify import check_coverage, verify_manifest
from .workflow import (
    AcquisitionOptions,
    ReferenceError,
    load_reference_pins,
    run_acquisition,
    summary_lines,
)


def _product_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def build_parser() -> argparse.ArgumentParser:
    product = _product_root()
    repository = _repository_root()
    parser = argparse.ArgumentParser(
        prog="python -m vulnova.acquisition",
        description=(
            "VULNOVA 1.7 historical data acquisition and provenance. Retrieves "
            "official source snapshots, records exact retrieval times and hashes, "
            "and verifies the archive offline. Trains nothing, approves nothing."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    acquire = subparsers.add_parser(
        "acquire", help="fetch artifacts, store bytes and write the provenance manifest"
    )
    acquire.add_argument(
        "--store",
        type=Path,
        default=product / "data" / "acquisition_store",
        help="artifact store directory (default: %(default)s)",
    )
    acquire.add_argument(
        "--manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="manifest output path (default: %(default)s)",
    )
    acquire.add_argument(
        "--markdown",
        type=Path,
        default=None,
        help="optional Markdown report output path",
    )
    acquire.add_argument(
        "--reference",
        type=Path,
        default=repository / "phase2.3k-export",
        help="Phase 2.3K export used for revision/contents cross-checks",
    )
    acquire.add_argument(
        "--no-reference",
        action="store_true",
        help="skip Phase 2.3K cross-checks (recorded as PIN_CROSSCHECK_SKIPPED)",
    )
    acquire.add_argument(
        "--cutoffs",
        nargs="+",
        default=[cutoff.isoformat() for cutoff in C.CANDIDATE_CUTOFFS],
        help="cutoffs to acquire (default: the three candidate blocks)",
    )
    acquire.add_argument(
        "--grid",
        nargs="+",
        default=None,
        help="full cutoff grid for validation (default: from the reference bundle)",
    )
    acquire.add_argument("--no-cve", action="store_true", help="skip cvelistV5")
    acquire.add_argument("--no-kev", action="store_true", help="skip KEV")
    acquire.add_argument("--no-epss", action="store_true", help="skip EPSS")
    acquire.add_argument(
        "--json", action="store_true", help="print the manifest digest line only"
    )
    acquire.add_argument("--quiet", action="store_true", help="suppress the summary")

    manifest_cmd = subparsers.add_parser(
        "manifest", help="re-serialise a manifest and re-attest its digest"
    )
    manifest_cmd.add_argument(
        "--manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="manifest path (default: %(default)s)",
    )
    manifest_cmd.add_argument(
        "--out",
        type=Path,
        default=None,
        help="optional rewrite path (default: print only)",
    )

    verify = subparsers.add_parser(
        "verify", help="verify stored artifacts and timestamps offline (no network)"
    )
    verify.add_argument(
        "--manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="manifest path (default: %(default)s)",
    )
    verify.add_argument(
        "--store",
        type=Path,
        default=product / "data" / "acquisition_store",
        help="artifact store directory (default: %(default)s)",
    )
    verify.add_argument("--json", action="store_true", help="emit JSON")
    verify.add_argument(
        "--markdown", type=Path, default=None, help="optional Markdown verification report"
    )

    check = subparsers.add_parser(
        "check", help="check required sources and cutoff coverage (no network)"
    )
    check.add_argument(
        "--manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="manifest path (default: %(default)s)",
    )
    check.add_argument("--json", action="store_true", help="emit JSON")
    check.add_argument(
        "--require-verified",
        action="store_true",
        help="also fail when a source/cutoff pair exists but is not VERIFIED",
    )

    report = subparsers.add_parser(
        "report", help="render the readable missing-evidence report"
    )
    report.add_argument(
        "--manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="manifest path (default: %(default)s)",
    )
    report.add_argument(
        "--store",
        type=Path,
        default=product / "data" / "acquisition_store",
        help="artifact store directory used for the verification section",
    )
    report.add_argument(
        "--out",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "DATA_ACQUISITION_1_7_REPORT.md",
        help="Markdown output path (default: %(default)s)",
    )
    report.add_argument(
        "--no-verify", action="store_true", help="omit the offline verification section"
    )
    return parser


# ------------------------------------------------------------------ commands
def _cmd_acquire(args) -> int:
    store = ArtifactStore(args.store)
    transport: Transport = UrllibTransport()
    api = GitHubApi(transport)

    cutoffs = tuple(parse_date(value) for value in args.cutoffs)
    explicit_grid = tuple(parse_date(value) for value in args.grid) if args.grid else None

    # Validate against an explicit grid before doing any I/O at all.
    if explicit_grid is not None:
        outside = [cutoff for cutoff in cutoffs if cutoff not in explicit_grid]
        if outside:
            print(
                "error: cutoff(s) outside the cutoff grid: "
                + ", ".join(cutoff.isoformat() for cutoff in outside),
                file=sys.stderr,
            )
            return 2

    reference = None
    if not args.no_reference:
        try:
            reference = load_reference_pins(args.reference)
        except ReferenceError as exc:
            print(
                f"warning: no Phase 2.3K pins available ({exc}); "
                "revision cross-checks will be recorded as skipped",
                file=sys.stderr,
            )

    if explicit_grid is not None:
        grid = explicit_grid
    elif reference is not None and reference.grid:
        grid = reference.grid
    else:
        grid = C.CANDIDATE_CUTOFFS
    outside = [cutoff for cutoff in cutoffs if cutoff not in grid]
    if outside:
        print(
            "error: cutoff(s) outside the cutoff grid: "
            + ", ".join(cutoff.isoformat() for cutoff in outside),
            file=sys.stderr,
        )
        return 2

    options = AcquisitionOptions(
        store=store,
        transport=transport,
        api=api,
        cutoffs=cutoffs,
        grid=grid,
        reference=reference,
        fetch_cve=not args.no_cve,
        fetch_kev=not args.no_kev,
        fetch_epss=not args.no_epss,
    )
    try:
        manifest = run_acquisition(options)
    except TransportError as exc:
        print(f"error: acquisition transport failed: {exc}", file=sys.stderr)
        return 2

    manifest["manifest_digest"] = manifest_digest(manifest)
    out = write_json(manifest, args.manifest)
    if args.markdown is not None:
        write_markdown(
            render_markdown(manifest, store_dir=_relative(store.root)), args.markdown
        )

    if args.json:
        print(json.dumps({"manifest": str(out), "digest": manifest["manifest_digest"]}))
    elif not args.quiet:
        print("VULNOVA 1.7 — historical data acquisition")
        print(f"as of {manifest['as_of']} · protocol {C.PHASE_TITLE}")
        for line in summary_lines(manifest):
            print(line)
        print(f"manifest: {out}")
        print(f"digest: {manifest['manifest_digest']}")
    return 0


def _cmd_manifest(args) -> int:
    try:
        manifest = read_json(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    recomputed = manifest_digest(manifest)
    recorded = manifest.get("manifest_digest")
    print(f"manifest: {args.manifest}")
    print(f"recorded digest: {recorded}")
    print(f"recomputed digest: {recomputed}")
    if recorded is not None and recorded != recomputed:
        print("error: the manifest digest does not match its contents", file=sys.stderr)
        return 1
    if args.out is not None:
        manifest["manifest_digest"] = recomputed
        write_json(manifest, args.out)
        print(f"rewritten: {args.out}")
    return 0


def _cmd_verify(args) -> int:
    try:
        manifest = read_json(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        result = verify_manifest(manifest, ArtifactStore(args.store))
    except StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.markdown is not None:
        write_markdown(
            render_markdown(manifest, result, store_dir=_relative(args.store)), args.markdown
        )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("VULNOVA 1.7 — offline verification")
        for check in result["checks"]:
            print(f"  {check['status']:<9} {check['id']} — {check['detail']}")
        print(f"integrity: {result['status']}")
        print(f"evidence: {result['evidence_status']} (from the manifest)")
        print(f"artifacts hashed: {result['summary']['artifacts_hashed']} · network used: no")
    return 0 if result["status"] == C.VERIFIED else 1


def _cmd_check(args) -> int:
    try:
        manifest = read_json(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    coverage = check_coverage(manifest)
    if args.json:
        print(json.dumps(coverage, indent=2, sort_keys=True))
    else:
        print("VULNOVA 1.7 — required source coverage")
        for row in coverage["rows"]:
            status = row["content_status"] or "ABSENT"
            print(
                f"  {row['source']:<10} {row['cutoff']}  {status:<11} {row['reason_code']}"
            )
        print(coverage["summary"])
        if coverage["cutoffs_outside_grid"]:
            print(
                "cutoffs outside the grid: " + ", ".join(coverage["cutoffs_outside_grid"]),
                file=sys.stderr,
            )
    if coverage["missing"] or coverage["cutoffs_outside_grid"]:
        return 1
    if args.require_verified and coverage["unverified"]:
        return 1
    return 0


def _cmd_report(args) -> int:
    try:
        manifest = read_json(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    verification = None if args.no_verify else verify_manifest(manifest, ArtifactStore(args.store))
    out = write_markdown(
        render_markdown(manifest, verification, store_dir=_relative(args.store)), args.out
    )
    print(f"report: {out}")
    if verification is not None:
        print(f"integrity: {verification['status']}")
    print(f"evidence: {manifest['summary']['evidence_status']}")
    return 0


def _relative(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(_product_root()))
    except (OSError, ValueError):
        return str(path)


COMMANDS = {
    "acquire": _cmd_acquire,
    "manifest": _cmd_manifest,
    "verify": _cmd_verify,
    "check": _cmd_check,
    "report": _cmd_report,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in COMMANDS:
        parser.print_help()
        return 0
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
