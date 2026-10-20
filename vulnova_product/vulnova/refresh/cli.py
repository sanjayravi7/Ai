"""Command-line interface for VULNOVA 1.8 maturity gate and evidence refresh.

    python -m vulnova.refresh run      # gate + refresh + readiness comparison
    python -m vulnova.refresh gate     # offline: is the block mature yet?
    python -m vulnova.refresh verify   # offline: re-hash the refresh and the archive

``run`` is the only command that touches the network, and it always uses the
**actual** UTC clock.  There is deliberately no ``--as-of`` on it: backdating a
production acquisition is exactly the defect the 1.7 provenance rules exist to
prevent.  Tests drive the identical code path through
:class:`vulnova.refresh.workflow.RefreshOptions` with an injected clock.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from ..acquisition import constants as A
from ..acquisition.github import GitHubApi
from ..acquisition.manifest import ManifestError, read_json
from ..acquisition.store import ArtifactStore
from ..acquisition.transport import Transport, UrllibTransport
from ..evaluation.protocol import ProtocolError
from ..evaluation.readiness import ReadinessError, ReadinessOptions, build_report
from ..provenance import utc_now
from . import constants as C
from .errors import PathSafetyError
from .gate import CatalogFacts, evaluate_gate, gate_summary
from .paths import assert_safe_write_targets, resolve_path
from .report import write_json, write_markdown
from .verify import verify_report_file
from .workflow import RefreshError, RefreshOptions, run_refresh


def _product_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def protected_paths(
    args,
    *,
    product: Optional[Path] = None,
    repository: Optional[Path] = None,
) -> tuple[Path, ...]:
    """Every input the refresh must never write to.

    Two groups, deliberately kept separate:

    * the fixed sealed directories — the 1.7 archive store and manifest, the
      committed 1.6 readiness report, the original snapshots and the sealed
      Phase 2.3K export;
    * the paths actually configured for this run — the protocol, the baseline
      report, the Phase 2.3K directory, the sealed manifest and archive store.

    The second group matters because a caller may point ``--baseline`` or
    ``--archive-store`` somewhere outside the defaults; protecting only the
    defaults would leave the configured file writable.
    """
    product = _product_root() if product is None else product
    repository = _repository_root() if repository is None else repository
    guarded = [product / relative for relative in C.PROTECTED_RELATIVE_PATHS]
    guarded.append(repository / "phase2.3k-export")
    guarded.extend(
        (
            args.protocol,
            args.baseline,
            args.artifacts,
            args.archive_manifest,
            args.archive_store,
        )
    )
    # The defaults make several of these identical (the Phase 2.3K directory is
    # both a fixed sealed path and the configured --artifacts, for instance).
    # Deduplicate on the resolved path so each guarded location is named once.
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in guarded:
        key = resolve_path(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return tuple(unique)


def _validate_write_targets(args, protected: tuple[Path, ...]) -> Optional[int]:
    """Run the shared check, returning an exit code when it refuses.

    Called before the transport is constructed, so a rejected invocation opens
    neither a socket nor a file.
    """
    try:
        assert_safe_write_targets(
            args.store, (args.report, args.markdown), protected
        )
    except PathSafetyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return None


def build_parser() -> argparse.ArgumentParser:
    product = _product_root()
    repository = _repository_root()
    parser = argparse.ArgumentParser(
        prog="python -m vulnova.refresh",
        description=(
            "VULNOVA 1.8 maturity gate and evidence refresh. Determines whether the "
            "final candidate block has matured, refreshes the official evidence, and "
            "compares feasibility against the committed 1.6 readiness report. Trains "
            "nothing, approves nothing."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser(
        "run", help="gate + refresh + readiness comparison (uses the network)"
    )
    run.add_argument(
        "--store",
        type=Path,
        default=product / C.DEFAULT_STORE_RELATIVE,
        help="refresh artifact store (default: %(default)s)",
    )
    run.add_argument(
        "--report",
        type=Path,
        default=product / C.DEFAULT_REPORT_RELATIVE,
        help="refresh report JSON (default: %(default)s)",
    )
    run.add_argument(
        "--markdown",
        type=Path,
        default=product / C.DEFAULT_MARKDOWN_RELATIVE,
        help="refresh report Markdown (default: %(default)s)",
    )
    run.add_argument(
        "--protocol",
        type=Path,
        default=product / "protocol" / "evaluation_protocol.json",
        help="machine-readable protocol file (default: %(default)s)",
    )
    run.add_argument(
        "--baseline",
        type=Path,
        default=product / "reports" / "evaluation_readiness_1_6" / "readiness_report.json",
        help="committed 1.6 readiness report to compare against (default: %(default)s)",
    )
    run.add_argument(
        "--artifacts",
        type=Path,
        default=repository / "phase2.3k-export",
        help="Phase 2.3K export used for the readiness re-run (default: %(default)s)",
    )
    run.add_argument(
        "--archive-manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="sealed 1.7 manifest guarded against modification (default: %(default)s)",
    )
    run.add_argument(
        "--archive-store",
        type=Path,
        default=product / "data" / "acquisition_store",
        help="sealed 1.7 artifact store (default: %(default)s)",
    )
    run.add_argument(
        "--no-readiness",
        action="store_true",
        help="skip the readiness re-run and compare acquisition evidence only",
    )
    run.add_argument("--quiet", action="store_true", help="print the status lines only")

    gate = subparsers.add_parser(
        "gate", help="offline: evaluate the maturity gate from the committed 1.7 catalog"
    )
    gate.add_argument(
        "--archive-manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="committed 1.7 manifest (default: %(default)s)",
    )
    gate.add_argument(
        "--as-of",
        default=None,
        help=(
            "evaluate the gate at an ISO date instead of today. Offline only; "
            "production acquisition always uses the real clock."
        ),
    )
    gate.add_argument("--json", action="store_true", help="emit JSON")

    verify = subparsers.add_parser(
        "verify", help="offline: re-hash the refresh report and the sealed archive"
    )
    verify.add_argument(
        "--report",
        type=Path,
        default=product / C.DEFAULT_REPORT_RELATIVE,
        help="refresh report JSON (default: %(default)s)",
    )
    verify.add_argument(
        "--store",
        type=Path,
        default=product / C.DEFAULT_STORE_RELATIVE,
        help="refresh artifact store (default: %(default)s)",
    )
    verify.add_argument(
        "--archive-manifest",
        type=Path,
        default=product / "reports" / "acquisition_1_7" / "acquisition_manifest.json",
        help="sealed 1.7 manifest (default: %(default)s)",
    )
    verify.add_argument(
        "--archive-store",
        type=Path,
        default=product / "data" / "acquisition_store",
        help="sealed 1.7 artifact store (default: %(default)s)",
    )
    verify.add_argument("--json", action="store_true", help="emit JSON")
    return parser


# ------------------------------------------------------------- catalog re-read
def catalog_facts_from_manifest(manifest: dict) -> CatalogFacts:
    """Rebuild catalog facts from a committed manifest, offline.

    Only a ``VERIFIED`` first-party record is considered, and the release time
    is the artifact's own ``dateReleased``.  Nothing is re-derived from the
    manifest's label observations, which are a derived view.
    """
    candidates = [
        record
        for record in manifest.get("records", [])
        if record.get("source") == "kev"
        and record.get("channel") in (A.CHANNEL_OFFICIAL, A.CHANNEL_OFFICIAL_GITHUB)
        and record.get("content_status") == A.VERIFIED
    ]
    for channel in (A.CHANNEL_OFFICIAL, A.CHANNEL_OFFICIAL_GITHUB):
        for record in candidates:
            if record.get("channel") != channel:
                continue
            details = record.get("details") or {}
            released = record.get("source_timestamp") or details.get("date_released")
            released_day = None
            if isinstance(released, str) and released:
                try:
                    released_day = dt.date.fromisoformat(released[:10])
                except ValueError:
                    released_day = None
            return CatalogFacts(
                available=True,
                key=record.get("key"),
                channel=record.get("channel"),
                revision=record.get("revision"),
                catalog_version=details.get("catalog_version"),
                released=released,
                released_day=released_day,
                declared_count=details.get("declared_count"),
                parsed_count=details.get("parsed_count"),
                sha256=record.get("sha256"),
                artifact_path=record.get("artifact_path"),
                retrieved_at=record.get("retrieved_at"),
                request_url=record.get("request_url"),
                final_url=record.get("final_url"),
                content_status=record.get("content_status"),
                reason_code=record.get("reason_code"),
            )
    return CatalogFacts(available=False)


# ------------------------------------------------------------------- commands
def _cmd_run(args) -> int:
    product = _product_root()
    repository = _repository_root()
    protected = protected_paths(args, product=product, repository=repository)

    # Write safety comes first: no network request, no directory creation and no
    # store write happens until every destination has been judged safe.
    refusal = _validate_write_targets(args, protected)
    if refusal is not None:
        return refusal

    transport: Transport = UrllibTransport()
    api = GitHubApi(transport)

    readiness_factory = None
    if not args.no_readiness:

        def run_readiness(as_of: dt.date) -> Optional[dict]:
            try:
                return build_report(
                    ReadinessOptions(
                        artifact_dir=args.artifacts,
                        protocol_path=args.protocol,
                        as_of=as_of.isoformat(),
                        deep=True,
                        repository_root=repository,
                        extract=True,
                    )
                )
            except (ReadinessError, ProtocolError) as exc:
                print(f"warning: readiness re-run skipped: {exc}", file=sys.stderr)
                return None

        readiness_factory = run_readiness

    options = RefreshOptions(
        store=ArtifactStore(args.store),
        transport=transport,
        api=api,
        cutoffs=_cutoffs(),
        protocol_path=args.protocol,
        baseline_report_path=args.baseline,
        baseline_manifest_path=args.archive_manifest,
        baseline_store_path=args.archive_store,
        protected_paths=protected,
        output_paths=(args.report, args.markdown),
        readiness_factory=readiness_factory,
        repository_root=repository,
    )
    try:
        report = run_refresh(options)
    except RefreshError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Re-check immediately before writing.  The acquisition ran since the first
    # check, so this catches a destination that was replaced by a symlink while
    # the network calls were in flight.
    refusal = _validate_write_targets(args, protected)
    if refusal is not None:
        return refusal
    out = write_json(report, args.report)
    write_markdown(report, args.markdown)

    summary = report["summary"]
    print("VULNOVA 1.8 — maturity gate and evidence refresh")
    print(
        f"as of {report['as_of']} · final cutoff "
        f"{report['final_candidate']['cutoff']} matures "
        f"{report['final_candidate']['maturity_date']} "
        f"({report['final_candidate']['days_remaining']} days remaining)"
    )
    print(f"refresh status: {summary['refresh_status']}")
    print(f"evidence status: {summary['evidence_status']}")
    if not args.quiet:
        print("requirements:")
        for requirement in report["requirements"]:
            print(
                f"  {requirement['status']:<9} {requirement['id']} — "
                f"{requirement['reason_code']}"
            )
        comparison = report["readiness_comparison"]
        changed = comparison.get("checks", {}).get("changed", [])
        print(f"readiness comparison: {len(changed)} check status change(s)")
        for key, value in comparison.get("questions", {}).items():
            print(f"  {key}: {'yes' if value else 'no'}")
    print(f"report: {out}")
    print(f"digest: {report['refresh_digest']}")
    return 0


def _cutoffs() -> tuple[dt.date, ...]:
    return A.CANDIDATE_CUTOFFS


def _cmd_gate(args) -> int:
    if args.as_of:
        try:
            as_of = dt.date.fromisoformat(args.as_of)
        except ValueError:
            print(f"error: --as-of is not an ISO date: {args.as_of}", file=sys.stderr)
            return 2
    else:
        as_of = dt.date.fromisoformat(utc_now()[:10])

    try:
        manifest = read_json(args.archive_manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    facts = catalog_facts_from_manifest(manifest)
    gates = [
        evaluate_gate(cutoff, as_of=as_of, catalog=facts) for cutoff in _cutoffs()
    ]
    summary = gate_summary(gates)

    payload = {
        "as_of": as_of.isoformat(),
        "catalog": facts.as_dict(),
        "gates": [gate.as_dict() for gate in gates],
        "gate_summary": summary,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print("VULNOVA 1.8 — maturity gate (offline)")
    print(f"as of {as_of.isoformat()} · catalog from the committed 1.7 manifest")
    print(
        f"catalog: {facts.channel}:{facts.key} {facts.catalog_version} "
        f"released {facts.released}"
    )
    for gate in gates:
        print(
            f"  {gate.cutoff.isoformat()} -> mature {gate.maturity_date.isoformat()} · "
            f"{gate.status:<24} days_remaining={gate.days_remaining:>4} "
            f"observable={'yes' if gate.catalog_observes_maturity else 'no'}"
        )
    print(f"final block maturity observable: {'yes' if summary['final_block_maturity_observable'] else 'no'}")
    print(
        "note: calendar maturity is necessary but not sufficient; a catalog released "
        "before the maturity date cannot observe it."
    )
    return 0


def _cmd_verify(args) -> int:
    try:
        result = verify_report_file(
            args.report,
            store_root=args.store,
            archive_manifest_path=args.archive_manifest,
            archive_store_root=args.archive_store,
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read refresh report: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("VULNOVA 1.8 — offline verification")
        for check in result["checks"]:
            print(f"  {check['status']:<9} {check['id']} — {check['detail']}")
        print(f"integrity: {result['status']}")
        print(f"evidence: {result['evidence_status']} (from the refresh report)")
        print(
            f"artifacts hashed: {result['summary']['artifacts_hashed']} · "
            "network used: no"
        )
    return 0 if result["status"] == A.VERIFIED else 1


COMMANDS = {"run": _cmd_run, "gate": _cmd_gate, "verify": _cmd_verify}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in COMMANDS:
        parser.print_help()
        return 0
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
