"""Assemble the evaluation-readiness report.

This module is read-only with respect to every research artifact.  It produces a
machine-readable report, never a score or a model.
"""

from __future__ import annotations

import datetime as dt
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import constants as C
from .checks import run_checks
from .checks_base import Check, CheckContext
from .datasets import (
    Dataset,
    DatasetError,
    input_fingerprints,
    load_dataset,
    locate_dataset_root,
    scan_memberships,
)
from .evidence import (
    ABSENCE_INTERPRETATION,
    MISSING_INTERPRETATION,
    classification_vocabulary,
)
from .integrity import (
    IntegrityError,
    extract_if_needed,
    sha256_file,
    verify_archive_sidecar,
    verify_manifest,
)
from .protocol import (
    Protocol,
    load_protocol,
    protocol_summary,
    require_reference_date,
)
from .temporal import (
    DesignEvaluation,
    evaluate_design,
    label_maturity_date,
    matches_phase2_3k,
    maturity_summary,
    parse_date,
)

READINESS_NOT_READY_VALIDATION_FAILED = "NOT_READY_VALIDATION_FAILED"
READINESS_BLOCKED_PROTOCOL = "BLOCKED_PROTOCOL_NOT_APPROVED"
READINESS_BLOCKED_NO_DESIGN = "BLOCKED_NO_ADOPTED_DESIGN"
READINESS_BLOCKED_EVIDENCE = "BLOCKED_EVIDENCE_UNAVAILABLE"
READINESS_BLOCKED_DESIGN = "BLOCKED_ADOPTED_DESIGN_INFEASIBLE"
READINESS_READY = "READY_FOR_PROTOCOL_EXECUTION"


class ReadinessError(RuntimeError):
    pass


@dataclass
class ReadinessOptions:
    artifact_dir: Path
    protocol_path: Path
    as_of: Optional[str] = None
    deep: bool = True
    export_archive: Optional[Path] = None
    core_bundle: Optional[Path] = None
    extract_dir: Optional[Path] = None
    previous_report_path: Optional[Path] = None
    repository_root: Optional[Path] = None
    extract: bool = True


def _default_artifact_paths(options: ReadinessOptions) -> dict:
    artifact_dir = Path(options.artifact_dir)
    export_archive = options.export_archive or (
        artifact_dir / "VULNOVA_Phase2.3K_export.tar.gz"
    )
    core_bundle = options.core_bundle or (
        artifact_dir / "VULNOVA_Phase2.3K_core_bundle.tar.gz"
    )
    extract_dir = options.extract_dir or (
        Path(options.repository_root or ".")
        / "vulnova_product"
        / "build"
        / "evaluation_artifacts"
    )
    return {
        "artifact_dir": artifact_dir,
        "export_archive": Path(export_archive),
        "core_bundle": Path(core_bundle),
        "extract_dir": Path(extract_dir),
    }


def _verify_export_manifest(manifest_path: Path, root: Path) -> dict:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    members = payload.get("members", [])
    checked = 0
    missing = []
    mismatched = []
    root_resolved = root.resolve()
    for member in members:
        relative = member.get("path", "")
        target = (root / relative).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError:
            mismatched.append({"path": relative, "problem": "path escapes export root"})
            continue
        if not target.is_file():
            missing.append(relative)
            continue
        checked += 1
        actual_bytes = target.stat().st_size
        actual_sha = sha256_file(target)
        if actual_bytes != member.get("bytes") or actual_sha != member.get("sha256"):
            mismatched.append(
                {
                    "path": relative,
                    "expected_bytes": member.get("bytes"),
                    "actual_bytes": actual_bytes,
                    "expected_sha256": member.get("sha256"),
                    "actual_sha256": actual_sha,
                }
            )
    return {
        "manifest": str(manifest_path),
        "declared_members": len(members),
        "checked_members": checked,
        "missing_members": missing,
        "mismatched_members": mismatched,
        "member_root": payload.get("member_root"),
    }


def _load_previous(path: Optional[Path]) -> Optional[dict]:
    if not path:
        return None
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _discover_roots(
    paths: dict, extract_records: list[dict]
) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for record in extract_records:
        if record.get("root"):
            roots[str(record["kind"])] = Path(record["root"])
    if not roots:
        for kind, subdir, marker in (
            ("full_export", "full", Path("phase2_3k") / "cvelistv5_inventory_manifest.csv"),
            ("core_bundle", "core", Path("cvelistv5_inventory_manifest.csv")),
        ):
            base = paths["extract_dir"] / subdir
            if not base.is_dir():
                continue
            for child in sorted(base.iterdir()):
                if child.is_dir() and (child / marker).is_file():
                    roots[kind] = child
                    break
    return roots


def _select_dataset(
    options: ReadinessOptions,
    paths: dict,
    roots: dict[str, Path],
) -> tuple[Dataset, dict]:
    candidates = []
    artifact_dir = paths["artifact_dir"]
    if artifact_dir.exists():
        try:
            locate_dataset_root(artifact_dir)
        except DatasetError:
            pass
        else:
            # An explicitly supplied artifact directory always wins over a stale
            # extraction cache: mixing the two would validate the wrong dataset.
            candidates.append((artifact_dir, "artifact_directory"))
    full_root = roots.get("full_export")
    core_root = roots.get("core_bundle")
    if full_root is not None and (full_root / "phase2_3k").is_dir():
        candidates.append((full_root, "full_export"))
    if core_root is not None:
        candidates.append((core_root, "core_bundle"))
    for root, mode in candidates:
        try:
            dataset = load_dataset(root)
        except DatasetError:
            continue
        return dataset, {"mode": mode, "source_root": str(root)}
    raise ReadinessError(
        "No Phase 2.3K dataset could be loaded. Supply --artifacts pointing at "
        "phase2.3k-export/, or allow extraction of the archived export."
    )


def build_report(options: ReadinessOptions) -> dict:
    protocol = load_protocol(options.protocol_path)
    as_of = require_reference_date(options.as_of, protocol)
    paths = _default_artifact_paths(options)
    repository_root = Path(options.repository_root or ".")

    archive_results = []
    for kind, archive in (
        ("full_export", paths["export_archive"]),
        ("core_bundle", paths["core_bundle"]),
    ):
        if not archive.exists():
            continue
        sidecar = Path(str(archive) + ".sha256")
        result = verify_archive_sidecar(archive, sidecar)
        result["kind"] = kind
        archive_results.append(result)

    extract_records: list[dict] = []
    if options.extract:
        for kind, archive, subdir, required in (
            (
                "full_export",
                paths["export_archive"],
                "full",
                ("phase2_3k/cvelistv5_inventory_manifest.csv",),
            ),
            (
                "core_bundle",
                paths["core_bundle"],
                "core",
                ("cvelistv5_inventory_manifest.csv",),
            ),
        ):
            if not archive.exists():
                continue
            result = next(
                (item for item in archive_results if item.get("kind") == kind), None
            )
            if result is not None and result.get("status") == "FAIL":
                extract_records.append(
                    {
                        "kind": kind,
                        "archive": str(archive),
                        "extracted": False,
                        "reused_cache": False,
                        "error": "archive digest mismatch; extraction refused",
                    }
                )
                continue
            try:
                record = extract_if_needed(
                    archive,
                    paths["extract_dir"] / subdir,
                    expected_sha256=(
                        result.get("sha256") if result and result.get("status") == "PASS" else None
                    ),
                    required_paths=required,
                )
                record["kind"] = kind
                extract_records.append(record)
            except (IntegrityError, OSError, tarfile.TarError) as exc:
                extract_records.append(
                    {
                        "kind": kind,
                        "archive": str(archive),
                        "extracted": False,
                        "reused_cache": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

    # Extraction bookkeeping differs between a first run and a cache hit.  Keep
    # only the evidence-bearing fields so the report digest is reproducible.
    extract_records = [
        {
            key: value
            for key, value in record.items()
            if key not in ("extracted", "reused_cache", "destination")
        }
        for record in extract_records
    ]

    roots = _discover_roots(paths, extract_records)
    dataset, dataset_info = _select_dataset(options, paths, roots)

    full_manifest = None
    core_manifest = None
    export_manifest = None
    full_root = roots.get("full_export")
    if full_root is not None and (full_root / "phase2_3k").is_dir():
        manifest_path = full_root / "phase2_3k" / "phase2_3k_integrity_manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            full_manifest = verify_manifest(full_root / "phase2_3k", manifest)
        export_path = full_root / "EXPORT_MANIFEST.json"
        if export_path.is_file():
            export_manifest = _verify_export_manifest(export_path, full_root)
    core_root = roots.get("core_bundle")
    if core_root is not None:
        manifest_path = core_root / "phase2_3k_integrity_manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            core_manifest = verify_manifest(core_root, manifest)
    if full_manifest is None and dataset.export_root is not None:
        manifest_path = dataset.path("phase2_3k_integrity_manifest.json")
        if manifest_path.is_file():
            full_manifest = verify_manifest(
                dataset.root, json.loads(manifest_path.read_text(encoding="utf-8"))
            )
        export_path = dataset.export_root / "EXPORT_MANIFEST.json"
        if export_path.is_file():
            export_manifest = _verify_export_manifest(export_path, dataset.export_root)

    events_by_cutoff, event_problems = dataset.events_by_cutoff
    scans = {}
    scan_problems = []
    deep_performed = False
    if options.deep and dataset.has_membership and dataset.has_inventory_ids:
        scans, scan_problems = scan_memberships(dataset, events_by_cutoff)
        deep_performed = bool(scans)

    source_coverage_end = dataset.source_coverage_end
    designs = [
        evaluate_design(
            spec,
            events_by_cutoff=events_by_cutoff,
            as_of=as_of,
            source_coverage_end=source_coverage_end,
        )
        for spec in protocol.candidate_designs
    ]
    # Phase 2.3K's verdicts were recorded at its reference date.  Compare against
    # a second evaluation at that date so a later --as-of does not turn a
    # historical feasibility finding into a spurious validation failure.
    reference_designs = {
        design.id: evaluate_design(
            spec,
            events_by_cutoff=events_by_cutoff,
            as_of=protocol.reference_date,
            source_coverage_end=source_coverage_end,
        )
        for spec, design in zip(protocol.candidate_designs, designs)
    }
    for design in designs:
        matches_phase2_3k(design, reference_designs[design.id])
        design.comparison_as_of = protocol.reference_date.isoformat()

    # Archives are already pinned by their own SHA-256 sidecars and reported under
    # ``inputs.archives``; do not hash the same 21 MB twice or double-count it.
    fingerprint_paths = list(dataset.key_files()) + [protocol.path]
    fingerprints = input_fingerprints(fingerprint_paths, relative_to=repository_root)
    previous_report = _load_previous(options.previous_report_path)

    ctx = CheckContext(
        dataset=dataset,
        protocol=protocol,
        as_of=as_of,
        reference_date=protocol.reference_date,
        archive_results=archive_results,
        core_manifest=core_manifest,
        full_manifest=full_manifest,
        export_manifest=export_manifest,
        extract_records=extract_records,
        scans=scans,
        scan_problems=scan_problems,
        deep_requested=options.deep,
        deep_performed=deep_performed,
        events_by_cutoff=events_by_cutoff,
        event_problems=event_problems,
        first_seen_day=dataset.first_seen_day,
        source_coverage_end=source_coverage_end,
        designs=designs,
        input_fingerprints=fingerprints,
        previous_report=previous_report,
    )
    checks = run_checks(ctx)

    summary = _summarize_checks(checks)
    readiness = _readiness(checks, protocol, designs, as_of, source_coverage_end)
    report = {
        "schema_version": C.SCHEMA_VERSION,
        "phase": {
            "product": "VULNOVA",
            "release": "1.6",
            "title": "Evaluation Readiness and Temporal Data Validation",
        },
        "as_of": as_of.isoformat(),
        "reference_date": protocol.reference_date.isoformat(),
        "parameters": {
            "horizon_days": C.HORIZON_DAYS,
            "maturity_lag_days": C.MATURITY_LAG_DAYS,
            "maturity_span_days": C.MATURITY_SPAN_DAYS,
            "required_distinct_test_events": C.REQUIRED_DISTINCT_TEST_EVENTS,
            "required_sequential_blocks": C.REQUIRED_SEQUENTIAL_BLOCKS,
        },
        "protocol": protocol_summary(protocol),
        "inputs": {
            **dataset_info,
            "artifact_directory": str(paths["artifact_dir"]),
            "dataset_root": str(dataset.root),
            "archives": archive_results,
            "extraction": extract_records,
            "files": fingerprints,
            "scan_performed": deep_performed,
            "scan_errors": scan_problems[:50],
        },
        "checks": [check.as_dict() for check in checks],
        "summary": summary,
        "designs": [design.as_dict() for design in designs],
        "maturity": [
            maturity_summary(
                cutoff, as_of=as_of, source_coverage_end=source_coverage_end
            )
            for cutoff in dataset.cutoffs
        ],
        "evidence_classification": _evidence_classification(ctx, checks),
        "readiness": readiness,
        "limitations": _limitations(ctx, designs, as_of),
        "reproducibility": {
            "canonicalization": (
                "JSON with sorted keys and compact separators; report_digest and "
                "reproducibility are excluded from the digest"
            ),
            "volatile_fields_excluded": ["report_digest", "reproducibility"],
        },
    }
    from .report import attach_digest, relativize_paths

    anchor = Path(options.repository_root or options.artifact_dir)
    report = relativize_paths(report, anchor)
    return attach_digest(report)


def _summarize_checks(checks: list[Check]) -> dict:
    counts = {status: 0 for status in C.CHECK_STATUSES}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    return {
        "total": len(checks),
        **counts,
        "blocking_failures": [
            check.id
            for check in checks
            if check.blocking and check.status == C.STATUS_FAIL
        ],
        "blocking_blocked": [
            check.id
            for check in checks
            if check.blocking and check.status == C.STATUS_BLOCKED
        ],
        "non_blocking_gaps": [
            check.id
            for check in checks
            if not check.blocking and check.status in (C.STATUS_BLOCKED, C.STATUS_FAIL)
        ],
    }


def _readiness(
    checks: list[Check],
    protocol: Protocol,
    designs: list[DesignEvaluation],
    as_of: dt.date,
    source_coverage_end: Optional[dt.date],
) -> dict:
    failures = [
        check for check in checks if check.blocking and check.status == C.STATUS_FAIL
    ]
    blocked = [
        check for check in checks if check.blocking and check.status == C.STATUS_BLOCKED
    ]
    earliest = next(
        (design for design in designs if design.id == C.EARLIEST_THREE_BLOCK_DESIGN_ID),
        None,
    )
    earliest_final = None
    if earliest is not None:
        final_cutoff = max(
            (parse_date(cutoff) for block in earliest.blocks for cutoff in block.cutoffs),
            default=None,
        )
        if final_cutoff is not None:
            earliest_final = label_maturity_date(final_cutoff)

    adopted = protocol.adopted_design
    adopted_design = next((design for design in designs if design.id == adopted), None)

    blockers: list[dict] = []
    for check in failures:
        blockers.append(
            {
                "code": "VALIDATION_FAILURE",
                "check_id": check.id,
                "detail": "; ".join(check.reasons[:3]),
                "primary": True,
            }
        )
    if not protocol.approved:
        blockers.append(
            {
                "code": "PROTOCOL_NOT_APPROVED",
                "detail": (
                    f"approval_state={protocol.approval_state}; adoption requires the "
                    "project owner's documented approval, which this command cannot grant."
                ),
                "primary": not failures,
            }
        )
    if adopted is None:
        blockers.append(
            {
                "code": "NO_ADOPTED_DESIGN",
                "detail": (
                    "No design is adopted. The two-block and three-block candidates "
                    "remain candidates only."
                ),
                "primary": not failures and protocol.approved,
            }
        )
    if earliest_final is not None and earliest_final > as_of:
        blockers.append(
            {
                "code": "LABEL_MATURITY_NOT_REACHED",
                "detail": (
                    f"the earliest three-block design's final labels mature "
                    f"{earliest_final.isoformat()}, {(earliest_final - as_of).days} days after "
                    f"the as-of date {as_of.isoformat()}"
                ),
                "primary": False,
            }
        )
    if (
        adopted is not None
        and adopted_design is not None
        and not adopted_design.protocol_admissible
        and protocol.approved
    ):
        blockers.append(
            {
                "code": "ADOPTED_DESIGN_INFEASIBLE",
                "detail": (
                    f"adopted design {adopted} fails protocol admission: "
                    + ", ".join(adopted_design.reason_codes)
                ),
                "primary": not failures,
            }
        )
    if (
        earliest_final is not None
        and source_coverage_end is not None
        and earliest_final > source_coverage_end
    ):
        blockers.append(
            {
                "code": "LABEL_STABILITY_NOT_OBSERVABLE_IN_PROVIDED_SOURCE",
                "detail": (
                    f"the served KEV timeline ends {source_coverage_end.isoformat()}, "
                    f"before the final maturity date {earliest_final.isoformat()}; a fresh "
                    "retrieval is required even after the calendar date passes"
                ),
                "primary": False,
            }
        )
    for check in blocked:
        blockers.append(
            {
                "code": "EVIDENCE_UNAVAILABLE",
                "check_id": check.id,
                "detail": "; ".join(check.reasons[:3]),
                "primary": not failures and protocol.approved and adopted is None,
            }
        )
    for check in checks:
        if check.blocking or check.status not in (C.STATUS_FAIL, C.STATUS_BLOCKED):
            continue
        blockers.append(
            {
                "code": "NON_BLOCKING_EVIDENCE_GAP",
                "check_id": check.id,
                "detail": "; ".join(check.reasons[:3]),
                "primary": False,
            }
        )

    if failures:
        status = READINESS_NOT_READY_VALIDATION_FAILED
        primary = "VALIDATION_FAILURE"
    elif not protocol.approved:
        status = READINESS_BLOCKED_PROTOCOL
        primary = "PROTOCOL_NOT_APPROVED"
    elif adopted is None:
        status = READINESS_BLOCKED_NO_DESIGN
        primary = "NO_ADOPTED_DESIGN"
    elif blocked:
        status = READINESS_BLOCKED_EVIDENCE
        primary = "EVIDENCE_UNAVAILABLE"
    elif adopted_design is None or not adopted_design.protocol_admissible:
        status = READINESS_BLOCKED_DESIGN
        primary = "ADOPTED_DESIGN_INFEASIBLE"
    else:
        status = READINESS_READY
        primary = None

    for blocker in blockers:
        blocker["primary"] = blocker["code"] == primary
    secondary = [blocker for blocker in blockers if not blocker["primary"]]

    return {
        "status": status,
        "primary_blocker": primary,
        "blockers": blockers,
        "secondary_blockers": secondary,
        "protocol_approved": protocol.approved,
        "adopted_design": adopted,
        "protocol_execution_authorized": status == READINESS_READY,
        "model_training_authorized": False,
        "confirmatory_no_go": "RETAINED",
        "approval_granted_by_this_command": False,
        "model_training_performed": False,
        "predictive_performance_claimed": False,
        "event_gate_relaxed": False,
        "ranking_weights_changed": False,
        "source_data_changed": False,
        "status_definitions": {
            READINESS_NOT_READY_VALIDATION_FAILED: "At least one blocking check failed.",
            READINESS_BLOCKED_PROTOCOL: "The protocol is not approved; no design can be used.",
            READINESS_BLOCKED_NO_DESIGN: "The protocol is approved but adopts no design.",
            READINESS_BLOCKED_EVIDENCE: "A blocking check could not be evaluated.",
            READINESS_BLOCKED_DESIGN: "The adopted design fails a protocol admission rule.",
            READINESS_READY: "All checks pass under an approved, adopted design.",
        },
    }


def _evidence_classification(ctx: CheckContext, checks: list[Check]) -> dict:
    event_rows = sum(len(ids) for ids in ctx.events_by_cutoff.values())
    distinct_events = {cve for ids in ctx.events_by_cutoff.values() for cve in ids}
    risk_pairs = sum(
        int(row.get("risk_set_size") or 0) for row in ctx.dataset.denominators
    )
    state_check = next(
        (check for check in checks if check.id == "LKG-07_evidence_classification_preserved"),
        None,
    )
    return {
        "states": classification_vocabulary(),
        "counts": {
            "confirmed_kev_inclusion_event_rows": event_rows,
            "confirmed_kev_inclusion_distinct_events": len(distinct_events),
            "absent_from_kev_risk_set_observations": risk_pairs,
            "missing_historical_evidence": {
                "sources_unavailable": ["Phase 2.3F", "Phase 2.3G"],
                "epss_backfilled_cutoffs": sum(
                    1
                    for row in ctx.dataset.features
                    if row.get("epss_availability_verdict") == "BACKFILLED_AFTER_CUTOFF"
                ),
                "census_payloads_unavailable": True,
                "cvelistv5_retrieval_time_unrecorded": True,
                "kev_unparseable_revisions": len(
                    ctx.dataset.kev_timeline_summary.get("unparseable_revisions", [])
                ),
            },
        },
        "absence_interpretation": ABSENCE_INTERPRETATION,
        "missing_interpretation": MISSING_INTERPRETATION,
        "absence_used_as_negative_label": False,
        "missing_used_as_absence": False,
        "classification_check_status": state_check.status if state_check else "UNKNOWN",
    }


def _cutoff_label(design: Optional[DesignEvaluation]) -> str:
    if design is None:
        return "unavailable"
    cutoffs = [cutoff for block in design.blocks for cutoff in block.cutoffs]
    return " / ".join(cutoffs) if cutoffs else "unavailable"


def _limitations(
    ctx: CheckContext, designs: list[DesignEvaluation], as_of: dt.date
) -> list[str]:
    earliest = next(
        (design for design in designs if design.id == C.EARLIEST_THREE_BLOCK_DESIGN_ID),
        None,
    )
    earliest_final = None
    if earliest is not None and earliest.blocks:
        earliest_final = max(
            (
                parse_date(block.maturity_date)
                for block in earliest.blocks
                if block.maturity_date
            ),
            default=None,
        )
    two_block = next(
        (design for design in designs if design.id == C.LARGEST_TWO_BLOCK_DESIGN_ID),
        None,
    )
    source_end = ctx.source_coverage_end

    matured_cutoffs = [
        cutoff
        for cutoff in ctx.dataset.cutoffs
        if label_maturity_date(cutoff) <= ctx.reference_date
    ]
    matured_rows = sum(len(ctx.events_by_cutoff.get(cutoff, ())) for cutoff in matured_cutoffs)
    matured_distinct = len(
        {cve for cutoff in matured_cutoffs for cve in ctx.events_by_cutoff.get(cutoff, ())}
    )
    if matured_distinct:
        reuse = (
            f"{matured_rows} matured rows cover {matured_distinct} distinct events, "
            f"{matured_rows / matured_distinct:.2f} rows/event"
        )
    else:
        reuse = "event rows are reused across overlapping cutoffs"

    backfilled = sorted(
        row.get("cutoff_T", "")
        for row in ctx.dataset.features
        if row.get("epss_availability_verdict") == "BACKFILLED_AFTER_CUTOFF"
    )
    epss_usable = sum(
        1
        for row in ctx.dataset.features
        if row.get("epss_availability_verdict") == "HISTORICALLY_AVAILABLE"
    )
    if backfilled:
        epss_text = (
            f"EPSS has no demonstrable point-in-time availability at {len(backfilled)} "
            f"cutoff(s) ({backfilled[0]} to {backfilled[-1]}); those score files are "
            "backfills and are not treated as historical. "
            f"{epss_usable} cutoff(s) have demonstrable historical availability."
        )
    else:
        epss_text = (
            "EPSS is used only where historical availability is demonstrable; "
            "backfilled score files are never treated as point-in-time evidence."
        )

    coverage_values = []
    for row in sorted(ctx.dataset.features, key=lambda item: item.get("cutoff_T", "")):
        try:
            coverage_values.append(float(row.get("cvss_coverage_pct")))
        except (TypeError, ValueError):
            continue
    if coverage_values:
        cvss_text = (
            f"CVSS coverage is {coverage_values[0]:.2f}% to {coverage_values[-1]:.2f}% "
            "across the cutoff grid; missing values are reported, never imputed."
        )
    else:
        cvss_text = (
            "CVSS coverage is incomplete at some cutoffs; missing values are reported, "
            "never imputed."
        )

    clone = str(ctx.dataset.inventory_method.get("oldest_commit_in_clone", ""))
    clone_date = clone.split()[-1][:10] if clone else ""
    unparseable = ctx.dataset.kev_timeline_summary.get("unparseable_revision_count")
    if unparseable is None:
        unparseable = len(ctx.dataset.kev_timeline_summary.get("unparseable_revisions", []))
    removals = ctx.dataset.kev_timeline_summary.get("total_removals")

    limitations = [
        (
            "The evaluation protocol remains NOT_APPROVED. This report is technical "
            "readiness evidence, not approval and not an evaluation."
        ),
        (
            f"The earliest three-block design ({_cutoff_label(earliest)}) has its final "
            f"labels mature on {earliest_final or 'an unrecorded date'}. Adopting it is a "
            "protocol amendment requiring the project owner's written approval."
        ),
    ]
    if source_end is not None and earliest_final is not None:
        if earliest_final <= source_end:
            limitations.append(
                f"The served KEV timeline ends {source_end.isoformat()} and covers the "
                f"earliest design's final maturity date {earliest_final}; label "
                "observability is limited to that retrieval."
            )
        else:
            limitations.append(
                f"The served KEV timeline ends {source_end.isoformat()}, before the "
                f"earliest design's final maturity date {earliest_final}. Even when the "
                "calendar date passes, a fresh retrieval through the maturity date is "
                "required before the final block's labels are observable in evidence."
            )
    else:
        limitations.append(
            "The served KEV timeline's end is not recorded, so label observability "
            "cannot be assumed even after the calendar maturity date."
        )
    limitations.extend(
        [
            (
                "No model was trained, tuned, scored or evaluated. No predictive "
                "performance is claimed, and no ranking weight or source datum was changed."
            ),
            (
                "Phase 2.3F and Phase 2.3G source directories are UNAVAILABLE in this "
                "environment; their digests remain historical claims."
            ),
            epss_text,
        ]
    )
    if clone_date:
        limitations.append(
            f"The cvelistV5 working clone carries revisions from {clone_date} onward only; "
            "no cutoff before the first cloned revision is offered."
        )
    limitations.append(cvss_text)
    limitations.append(
        (
            f"{unparseable} KEV catalog revision{'s are' if unparseable != 1 else ' is'} "
            "truncated upstream and recorded as unparseable rather than repaired."
            if unparseable
            else "No KEV catalog revision is recorded as unparseable."
        )
    )
    limitations.append(
        (
            "KEV is not exhaustive. Absence from the catalog is never proof that a "
            "vulnerability was not exploited, and no negative exploitation label is built "
            "from it."
        )
    )
    limitations.append(
        (
            "The staged per-record census payloads are not shipped; their recorded hashes "
            "and counts are verified, but the payload bytes cannot be re-hashed here."
        )
    )
    limitations.append(
        (
            "Per-revision retrieval timestamps are not recorded where the artifacts only "
            "carry source commit times and the artifact sealing time."
        )
    )
    limitations.append(
        (
            f"Event rows are reused across overlapping cutoffs ({reuse}); reuse is not "
            "independent evidence."
        )
    )
    limitations.append(
        (
            "Labels are first-observed KEV catalog inclusions within the forward window, "
            "not a complete record of exploitation or of all exploitation activity."
        )
    )
    if two_block is not None and two_block.blocks:
        limitations.append(
            (
                f"The two-block design ({_cutoff_label(two_block)}) is constructible but "
                "lacks a separate validation block; it is not a protocol-compliant "
                "substitute."
            )
        )
    if removals:
        limitations.append(
            (
                f"{removals} KEV removal{'s are' if removals != 1 else ' is'} replayed; "
                "membership is removal-aware, so a removed CVE is still a valid event at "
                "cutoffs before its removal."
            )
        )
    limitations.append(
        (
            f"The as-of date for this run is {as_of.isoformat()}; maturity status can "
            "change with the calendar, while evidence coverage changes only with a new "
            "retrieval."
        )
    )
    return limitations
