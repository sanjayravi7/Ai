"""The 1.8 refresh run: gate, acquire, filter, compare, report.

The workflow is additive.  It reuses the 1.7 acquisition sources and vocabulary
verbatim — no second definition of ``VERIFIED``/``UNAVAILABLE``/``BLOCKED``, no
second KEV parser, no second transport — and it writes only into its own store
and its own report directory.

Three guarantees are structural rather than aspirational:

* **The sealed archive is read-only.**  The refresh store is checked against the
  protected 1.7 paths before a single byte is written, and the 1.7 manifest and
  artifacts are fingerprinted before and after the run.
* **Maturity is never claimed early.**  The gate's ``maturity_claimed`` can only
  be true when the run's own as-of date is at or past the maturity date; an
  invariant re-checks that before the report is emitted.
* **Integrity is not viability.**  The report carries an explicit honesty block
  saying so, and the refresh status never becomes "complete" just because the
  bytes hash correctly.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..acquisition import constants as A
from ..acquisition.github import GitHubApi
from ..acquisition.records import Requirement, to_instant
from ..acquisition.sources import epss as epss_source
from ..acquisition.sources import kev as kev_source
from ..acquisition.store import ArtifactStore
from ..acquisition.transport import Transport
from ..evaluation import constants as E
from ..provenance import utc_now
from . import constants as C
from .comparison import build_comparison
from .gate import (
    CatalogFacts,
    DateAddedFilter,
    MaturityGateResult,
    catalog_facts,
    evaluate_gate,
    filter_entries_by_date_added,
    gate_summary,
)


class RefreshError(RuntimeError):
    """The refresh cannot proceed without violating a safety invariant."""


# ------------------------------------------------------------------- options
@dataclass
class RefreshOptions:
    store: ArtifactStore
    transport: Transport
    api: GitHubApi
    clock: Callable[[], str] = utc_now
    cutoffs: tuple[dt.date, ...] = A.CANDIDATE_CUTOFFS
    protocol_path: Optional[Path] = None
    baseline_report_path: Optional[Path] = None
    baseline_manifest_path: Optional[Path] = None
    baseline_store_path: Optional[Path] = None
    protected_paths: tuple[Path, ...] = ()
    readiness_factory: Optional[Callable[[dt.date], Optional[dict]]] = None
    repository_root: Optional[Path] = None


# --------------------------------------------------------------- path safety
def _resolve(path: Path | str) -> Path:
    try:
        return Path(path).resolve()
    except OSError:  # pragma: no cover - defensive
        return Path(path).absolute()


def assert_separate_store(store_root: Path | str, protected: Iterable[Path | str]) -> None:
    """Refuse a refresh store that overlaps a sealed archive directory.

    Overlap in *either* direction is refused: a refresh store inside the 1.7
    archive would add files to it, and an archive directory inside the refresh
    store would let a later cleanup delete it.
    """
    target = _resolve(store_root)
    for item in protected:
        guarded = _resolve(item)
        if target == guarded or guarded in target.parents or target in guarded.parents:
            raise RefreshError(
                f"{C.REFRESH_STORE_OVERLAPS_ARCHIVE}: refresh store {store_root} "
                f"overlaps the sealed path {item}; refusing to write"
            )


def _fingerprint(path: Optional[Path]) -> Optional[dict]:
    if not path:
        return None
    target = Path(path)
    if not target.is_file():
        return {"path": str(target), "available": False}
    data = target.read_bytes()
    return {
        "path": str(target),
        "available": True,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def archive_fingerprint(
    manifest_path: Optional[Path], store_path: Optional[Path]
) -> dict:
    """Fingerprint the sealed 1.7 manifest and every artifact it names.

    Reading ``artifact_path`` values from the manifest and re-hashing them here
    means "the archive is unchanged" is measured, not asserted.
    """
    record = _fingerprint(manifest_path)
    artifacts: list[dict] = []
    manifest = None
    if manifest_path and Path(manifest_path).is_file():
        try:
            manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = None
    if manifest and store_path:
        store = ArtifactStore(store_path)
        for item in manifest.get("records", []):
            relative = item.get("artifact_path")
            if not relative:
                continue
            digest = store.digest(relative)
            artifacts.append(
                {
                    "key": item.get("key"),
                    "source": item.get("source"),
                    "artifact_path": relative,
                    "recorded_sha256": item.get("sha256"),
                    "actual_sha256": (digest or {}).get("sha256"),
                    "unchanged": bool(
                        digest and digest.get("sha256") == item.get("sha256")
                    ),
                }
            )
    return {
        "manifest": record,
        "manifest_digest": (manifest or {}).get("manifest_digest"),
        "artifacts": sorted(artifacts, key=lambda row: (row["source"] or "", row["key"] or "")),
        "artifact_count": len(artifacts),
        "all_artifacts_unchanged": bool(artifacts) and all(
            row["unchanged"] for row in artifacts
        ),
    }


# ------------------------------------------------------------------ selection
def select_catalog(records: Iterable) -> Optional[object]:
    """Prefer the publisher's canonical feed, then CISA's own repository.

    Only a ``VERIFIED`` record with a parseable catalog is eligible.  A policy
    refusal or an outage is never selected, and a third-party mirror is never
    considered at all.
    """
    candidates = [
        record
        for record in records
        if record is not None
        and record.channel in (A.CHANNEL_OFFICIAL, A.CHANNEL_OFFICIAL_GITHUB)
        and record.content_status == A.VERIFIED
    ]
    for channel in (A.CHANNEL_OFFICIAL, A.CHANNEL_OFFICIAL_GITHUB):
        for record in candidates:
            if record.channel == channel:
                return record
    return None


def explain_rejected_catalog(records: Iterable) -> Optional[object]:
    """Pick the record that best explains why no catalog was selected.

    A publisher that answered but served an unusable artifact (``BLOCKED``) is
    more informative than one that never answered (``UNAVAILABLE``), and an
    unknown cause must never be reported as an outage.  Keeping the explanation
    is what stops "no catalog" from silently becoming "the source was down".
    """
    ordered = [record for record in records if record is not None]
    for status in (A.BLOCKED, A.UNAVAILABLE):
        for record in ordered:
            if record.content_status == status:
                return record
    return ordered[0] if ordered else None


def _catalog_entries(
    record, store: ArtifactStore
) -> tuple[Optional[list[dict]], Optional[str]]:
    """Read the stored catalog bytes back and return the vulnerability list."""
    relative = getattr(record, "artifact_path", None)
    if not relative:
        return None, A.ARTIFACT_NOT_STORED
    try:
        body = store.read(relative)
    except Exception:  # noqa: BLE001 - StoreError, OSError: report, never raise
        return None, A.ARTIFACT_MISSING
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, A.MALFORMED_RESPONSE
    entries = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return None, A.MALFORMED_RESPONSE
    return entries, None


# --------------------------------------------------------------- requirements
def _requirement(
    requirement_id: str,
    title: str,
    status: str,
    reason_code: str,
    detail: str,
    *,
    records: Optional[list[str]] = None,
    evidence: Optional[dict] = None,
) -> Requirement:
    return Requirement(
        id=requirement_id,
        title=title,
        status=status,
        reason_code=reason_code,
        detail=detail,
        records=records or [],
        evidence=evidence or {},
    )


def _worst(values: Iterable[str]) -> str:
    return A.worst(values)


# ------------------------------------------------------------------- the run
def run_refresh(options: RefreshOptions) -> dict:
    started_at = options.clock()
    try:
        as_of = dt.date.fromisoformat(started_at[:10])
    except ValueError as exc:  # pragma: no cover - a clock returning junk
        raise RefreshError(f"clock returned a non-ISO timestamp: {started_at!r}") from exc

    assert_separate_store(options.store.root, options.protected_paths)
    archive_before = archive_fingerprint(
        options.baseline_manifest_path, options.baseline_store_path
    )

    cutoffs = tuple(sorted(options.cutoffs))
    if not cutoffs:
        raise RefreshError("no cutoffs to refresh")
    final_cutoff = max(cutoffs)
    final_maturity = C.maturity_of(final_cutoff)

    # ---- KEV: direct publisher first, then the publisher's own repository.
    direct_records, _facts = kev_source.acquire_current(
        options.transport,
        store=options.store,
        relative=C.REFRESH_KEV_DIRECT_PATH,
    )
    github_record = kev_source.acquire_current_github(
        options.api,
        store=options.store,
        maturity=final_maturity,
        relative=C.REFRESH_KEV_GITHUB_PATH,
    )
    catalog = select_catalog([*direct_records, github_record])
    facts = catalog_facts(
        catalog if catalog is not None else explain_rejected_catalog([*direct_records, github_record])
    )

    # ---- EPSS: retry the exact official daily files for each cutoff.
    epss_records = [
        epss_source.acquire_daily(options.transport, cutoff, store=options.store)
        for cutoff in cutoffs
    ]

    # ---- Gate each block against the one selected catalog.
    gates = [
        evaluate_gate(cutoff, as_of=as_of, catalog=facts) for cutoff in cutoffs
    ]
    gate_answers = gate_summary(gates)

    # ---- A dateAdded view only for the block the gate actually observes.
    filters: dict[str, DateAddedFilter] = {}
    entries: Optional[list[dict]] = None
    entries_error: Optional[str] = None
    if catalog is not None:
        entries, entries_error = _catalog_entries(catalog, options.store)
    for gate in gates:
        if not gate.filter_applied:
            filters[gate.cutoff.isoformat()] = filter_entries_by_date_added(
                (),
                maturity=gate.maturity_date,
                applied=False,
                catalog_released=gate.catalog_released,
            )
            continue
        if entries is None:
            filters[gate.cutoff.isoformat()] = filter_entries_by_date_added(
                (),
                maturity=gate.maturity_date,
                applied=True,
                catalog_released=gate.catalog_released,
            )
            filters[gate.cutoff.isoformat()].trustworthy = False
            filters[gate.cutoff.isoformat()].basis = entries_error or A.ARTIFACT_NOT_STORED
            filters[gate.cutoff.isoformat()].reason_code = (
                entries_error or A.ARTIFACT_NOT_STORED
            )
            filters[gate.cutoff.isoformat()].note = (
                "The gate permits a filtered view, but the catalog bytes could not be "
                "read back from the refresh store; no view is reported."
            )
            continue
        filters[gate.cutoff.isoformat()] = filter_entries_by_date_added(
            entries,
            maturity=gate.maturity_date,
            applied=True,
            catalog_released=gate.catalog_released,
        )

    # ---- Requirements.  Same three-state vocabulary as 1.7.
    kev_records = [*direct_records, github_record]
    requirements: list[Requirement] = []

    direct = [record for record in direct_records if record.channel == A.CHANNEL_OFFICIAL]
    requirements.append(
        _requirement(
            "KEV-R1_DIRECT_CISA_FEED",
            "The direct CISA feed is reachable and preserved",
            _worst([record.content_status for record in direct]) if direct else A.BLOCKED,
            direct[0].reason_code if direct else A.NO_RECORDS,
            (
                f"direct feed: {direct[0].content_status} ({direct[0].reason_code})"
                if direct
                else "no direct-feed record was produced"
            ),
            records=[f"kev:{record.key}" for record in direct],
        )
    )

    catalog_status = facts.content_status if facts.available else A.UNAVAILABLE
    requirements.append(
        _requirement(
            "KEV-R2_CURRENT_CATALOG",
            "A current KEV catalog is preserved from a first-party channel",
            catalog_status,
            facts.reason_code,
            (
                f"selected {facts.channel}:{facts.key} "
                f"(catalog {facts.catalog_version}, released {facts.released}, "
                f"{facts.parsed_count} entries, sha256 {facts.sha256})"
                if facts.verified
                else "; ".join(
                    f"{record.channel}:{record.key} {record.content_status} "
                    f"({record.reason_code})"
                    for record in kev_records
                )
            ),
            records=[f"kev:{record.key}" for record in kev_records],
            evidence={"selected_catalog": facts.as_dict()},
        )
    )

    gate_statuses = []
    for gate in gates:
        if gate.matured:
            gate_statuses.append(A.VERIFIED)
        elif not gate.calendar_matured:
            gate_statuses.append(A.BLOCKED)
        elif gate.status == C.GATE_MATURED_SOURCE_MISSING:
            gate_statuses.append(A.UNAVAILABLE)
        else:
            gate_statuses.append(A.BLOCKED)
    gate_status = _worst(gate_statuses) if gate_statuses else A.BLOCKED
    gate_reason = next(
        (
            gate.reason_code
            for gate in gates
            if (gate.matured is False)
        ),
        A.OK_VERIFIED,
    )
    requirements.append(
        _requirement(
            "KEV-R3_MATURITY_OBSERVABLE",
            "Every block's labels can be observed at its maturity date",
            gate_status,
            gate_reason,
            "; ".join(
                f"{gate.cutoff.isoformat()}: {gate.status} ({gate.reason_code})"
                for gate in gates
            ),
            records=[f"kev:{facts.key}"] if facts.key else [],
            evidence={
                "gates": [gate.as_dict() for gate in gates],
                "filter": {key: value.as_dict() for key, value in filters.items()},
            },
        )
    )

    epss_statuses = [record.content_status for record in epss_records]
    requirements.append(
        _requirement(
            "EPSS-R1_EXACT_DAILY_FILE",
            "The exact daily EPSS file exists for every cutoff",
            _worst(epss_statuses) if epss_statuses else A.BLOCKED,
            next(
                (
                    record.reason_code
                    for record in epss_records
                    if record.content_status != A.VERIFIED
                ),
                A.OK_VERIFIED,
            ),
            "; ".join(
                f"{record.key}: {record.content_status} ({record.reason_code})"
                for record in epss_records
            ),
            records=[f"epss:{record.key}" for record in epss_records],
        )
    )
    requirements.append(
        _requirement(
            "EPSS-R2_HISTORICAL_PROVENANCE",
            "EPSS scores were observed at their cutoffs, not downloaded later",
            _worst([record.status for record in epss_records]) if epss_records else A.BLOCKED,
            next(
                (
                    A.RETRIEVAL_NOT_CONTEMPORANEOUS
                    if record.content_status == A.VERIFIED
                    else record.reason_code
                    for record in epss_records
                    if record.status != A.VERIFIED
                ),
                A.OK_VERIFIED,
            ),
            "; ".join(
                f"{record.key}: {record.access_provenance}"
                for record in epss_records
            ),
            records=[f"epss:{record.key}" for record in epss_records],
        )
    )

    # ---- Hard invariant: never claim maturity before the date.
    early_claims = [
        gate.cutoff.isoformat()
        for gate in gates
        if gate.matured and gate.maturity_date > as_of
    ]
    requirements.append(
        _requirement(
            "PROV-R1_NO_PREMATURE_MATURITY",
            "Premature maturity of the final candidate block is impossible",
            A.BLOCKED if early_claims else A.VERIFIED,
            C.MATURITY_CLAIMED_EARLY if early_claims else A.OK_VERIFIED,
            (
                "maturity claimed early for " + ", ".join(early_claims)
                if early_claims
                else (
                    f"final candidate cutoff {final_cutoff.isoformat()} matures "
                    f"{final_maturity.isoformat()}; this run is as of {as_of.isoformat()} "
                    f"({(final_maturity - as_of).days} days remaining). Maturity is not "
                    "claimed and fresh evidence is required after that date."
                )
            ),
            evidence={
                "final_candidate_cutoff": final_cutoff.isoformat(),
                "final_candidate_maturity": final_maturity.isoformat(),
                "as_of": as_of.isoformat(),
                "maturity_claimed": any(gate.matured for gate in gates),
                "fresh_evidence_required_after_maturity": True,
            },
        )
    )

    # ---- Archive guard: measure the 1.7 archive before and after.
    archive_after = archive_fingerprint(
        options.baseline_manifest_path, options.baseline_store_path
    )
    if options.baseline_manifest_path:
        unchanged = (
            archive_before.get("manifest", {}).get("sha256")
            == archive_after.get("manifest", {}).get("sha256")
            and archive_before.get("all_artifacts_unchanged", False)
            == archive_after.get("all_artifacts_unchanged", False)
            and archive_after.get("all_artifacts_unchanged", False)
        )
        requirements.append(
            _requirement(
                "PROV-R2_SEALED_ARCHIVE_UNCHANGED",
                "The sealed 1.7 archive was not rewritten by the refresh",
                A.VERIFIED if unchanged else A.BLOCKED,
                A.OK_VERIFIED if unchanged else C.ARCHIVE_CHANGED_DURING_REFRESH,
                (
                    f"{archive_after.get('artifact_count')} artifact(s) still hash to "
                    "their recorded digests; the manifest is byte-identical"
                    if unchanged
                    else "the sealed 1.7 manifest or its artifacts changed during the refresh"
                ),
                evidence={"before": archive_before, "after": archive_after},
            )
        )

    # ---- Statuses.
    summary_statuses = [requirement.status for requirement in requirements]
    evidence_status = _worst(summary_statuses) if summary_statuses else A.BLOCKED
    final_gate = max(gates, key=lambda gate: gate.cutoff)
    if any(gate.status == C.GATE_NOT_MATURED for gate in gates):
        refresh_status = C.REFRESH_BLOCKED_MATURITY
    elif any(not gate.matured for gate in gates):
        refresh_status = C.REFRESH_BLOCKED_SOURCE
    elif evidence_status != A.VERIFIED:
        refresh_status = C.REFRESH_BLOCKED_EVIDENCE
    else:
        refresh_status = C.REFRESH_EVIDENCE_COMPLETE

    # The invariant is re-checked on the *final* status, not just per block.
    if refresh_status == C.REFRESH_EVIDENCE_COMPLETE and not (
        final_gate.matured and final_gate.maturity_date <= as_of
    ):  # pragma: no cover - defensive
        raise RefreshError(
            f"{C.MATURITY_CLAIMED_EARLY}: refresh claims completeness before "
            f"{final_gate.maturity_date.isoformat()}"
        )

    # ---- Readiness comparison (optional, injected so tests stay offline).
    current_readiness = None
    if options.readiness_factory is not None:
        current_readiness = options.readiness_factory(as_of)
    baseline_readiness = None
    if options.baseline_report_path and Path(options.baseline_report_path).is_file():
        try:
            baseline_readiness = json.loads(
                Path(options.baseline_report_path).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            baseline_readiness = None
    comparison = build_comparison(
        baseline=baseline_readiness,
        current=current_readiness,
        gates=[gate.as_dict() for gate in gates],
        epss_records=[record.as_dict() for record in epss_records],
        baseline_path=str(options.baseline_report_path)
        if options.baseline_report_path
        else None,
    )

    generated_at = options.clock()
    report = {
        "schema_version": C.SCHEMA_VERSION,
        "phase": {
            "product": "VULNOVA",
            "release": C.RELEASE,
            "title": C.PHASE_TITLE,
        },
        "generated_at": generated_at,
        "as_of": as_of.isoformat(),
        "final_candidate": {
            "cutoff": final_cutoff.isoformat(),
            "maturity_date": final_maturity.isoformat(),
            "calendar_matured": final_maturity <= as_of,
            "days_remaining": (final_maturity - as_of).days,
            "maturity_claimed": final_gate.matured,
        },
        "parameters": {
            "horizon_days": E.HORIZON_DAYS,
            "maturity_lag_days": E.MATURITY_LAG_DAYS,
            "maturity_span_days": E.MATURITY_SPAN_DAYS,
            "required_distinct_test_events": E.REQUIRED_DISTINCT_TEST_EVENTS,
            "required_sequential_blocks": E.REQUIRED_SEQUENTIAL_BLOCKS,
        },
        "protocol": _protocol_summary(options.protocol_path),
        "maturity_gate": [gate.as_dict() for gate in gates],
        "gate_summary": gate_answers,
        "date_added_filters": {
            key: value.as_dict() for key, value in filters.items()
        },
        "catalog": facts.as_dict(),
        "kev_records": [record.as_dict() for record in kev_records],
        "epss_records": [record.as_dict() for record in epss_records],
        "requirements": [requirement.as_dict() for requirement in requirements],
        "summary": {
            "refresh_status": refresh_status,
            "evidence_status": evidence_status,
            "requirements": len(requirements),
            "requirements_by_status": _count_requirements(requirements),
            "maturity_claimed": bool(final_gate.matured),
            "final_block_calendar_matured": bool(final_maturity <= as_of),
            "final_block_maturity_observable": bool(final_gate.matured),
            "reassessment": _reassessment(
                final_gate, epss_records, requirements, refresh_status
            ),
        },
        "readiness_comparison": comparison,
        "archive_guard": {
            "before": archive_before,
            "after": archive_after,
            "protected_paths": [str(path) for path in options.protected_paths],
        },
        "honesty": dict(C.POLICIES),
        "limitations": _limitations(gates, facts, epss_records, comparison),
        "runtime": {
            "store": _portable_path(options.store.root),
            "transport": type(options.transport).__name__,
            "requests": _request_count(options.transport),
        },
    }
    from .report import attach_digest, relativize_paths

    anchor = Path(options.repository_root or options.store.root)
    report = relativize_paths(report, anchor)
    return attach_digest(report)


# ------------------------------------------------------------------- helpers
def _protocol_summary(path: Optional[Path]) -> dict:
    if not path:
        return {
            "path": None,
            "protocol_id": None,
            "version": None,
            "approval_state": "MISSING",
            "adopted_design": None,
            "approved": False,
            "protocol_execution_authorized": False,
        }
    from ..evaluation.protocol import load_protocol

    protocol = load_protocol(path)
    return {
        "path": str(path),
        "protocol_id": protocol.protocol_id,
        "version": protocol.version,
        "approval_state": protocol.approval_state,
        "adopted_design": protocol.adopted_design,
        "approved": protocol.approved,
        "reference_date": protocol.reference_date.isoformat(),
        "protocol_execution_authorized": False,
    }


def _count_requirements(requirements: Iterable[Requirement]) -> dict:
    counts = {status: 0 for status in A.STATUSES}
    for requirement in requirements:
        counts[requirement.status] = counts.get(requirement.status, 0) + 1
    return counts


def _limitations(
    gates: list[MaturityGateResult],
    facts: CatalogFacts,
    epss_records: list,
    comparison: dict,
) -> list[str]:
    items: list[str] = []
    early = [gate for gate in gates if not gate.calendar_matured]
    if early:
        gate = max(early, key=lambda item: item.cutoff)
        items.append(
            f"The final candidate block matures {gate.maturity_date.isoformat()}; this "
            f"run is {gate.days_remaining} day(s) earlier, so no final-block label set "
            "is produced and maturity is not claimed."
        )
    if facts.verified and facts.released_day:
        late = [gate for gate in gates if gate.maturity_date > facts.released_day]
        if late:
            items.append(
                f"The catalog ({facts.catalog_version}, released {facts.released}) "
                "predates " + ", ".join(gate.maturity_date.isoformat() for gate in late)
                + "; those observations are right-censored and are not filtered."
            )
    if not facts.verified:
        items.append(
            "No first-party KEV catalog was acquired in this run; the maturity gate "
            "cannot be evaluated against a fresh artifact."
        )
    unavailable = [
        record.key for record in epss_records if record.content_status != A.VERIFIED
    ]
    if unavailable:
        items.append(
            "Exact historical EPSS files were not obtained for "
            + ", ".join(sorted(unavailable))
            + "; those requirements stay UNAVAILABLE and no newer file or mirror is "
            "substituted."
        )
    if any(record.content_status == A.VERIFIED for record in epss_records):
        items.append(
            "Any EPSS file retrieved now is a LATE_RETRIEVAL of a historical date, not "
            "contemporaneous provenance; the provenance requirement remains unmet."
        )
    questions = comparison.get("questions", {})
    if comparison.get("current", {}).get("available"):
        items.append(
            "Readiness checks were re-run at this as-of date. Their statuses "
            f"({'unchanged' if questions.get('semantic_check_statuses_match_baseline') else 'changed'}) "
            "are technical evidence, not an approval."
        )
    else:
        items.append(
            "No refreshed readiness run was produced, so the feasibility comparison is "
            "limited to the acquisition evidence."
        )
    items.append(
        "A green integrity result proves the bytes are intact. It does not prove the "
        "historical evaluation is viable."
    )
    # Carry the comparison's own caveats into the report so a reader of the
    # Markdown cannot miss them; keep first occurrence order.
    for extra in comparison.get("limitations", []):
        if extra not in items:
            items.append(extra)
    return items


def _reassessment(
    final_gate: MaturityGateResult,
    epss_records: list,
    requirements: list[Requirement],
    refresh_status: str,
) -> dict:
    """Answer "may this be reassessed?" without ever answering "yes" by itself.

    A protocol re-assessment needs matured and observable labels, complete
    provenance and — above all — an approved protocol.  This block names which of
    those is missing instead of returning a bare boolean that a reader could
    mistake for permission.
    """
    by_id = {requirement.id: requirement for requirement in requirements}
    exact_epss = bool(epss_records) and all(
        record.content_status == A.VERIFIED for record in epss_records
    )
    provenance = by_id.get("EPSS-R2_HISTORICAL_PROVENANCE")
    provenance_complete = bool(
        provenance and provenance.status == A.VERIFIED
    )
    blockers: list[str] = []
    if not final_gate.matured:
        blockers.append(final_gate.status)
    if not exact_epss:
        blockers.append("EXACT_HISTORICAL_EPSS_UNAVAILABLE")
    if not provenance_complete:
        blockers.append("CONTEMPORANEOUS_PROVENANCE_UNAVAILABLE")
    blockers.append("PROTOCOL_NOT_APPROVED")
    blockers.append("NO_ADOPTED_DESIGN")
    return {
        "final_block_maturity_observable": final_gate.matured,
        "exact_historical_epss_available": exact_epss,
        "contemporaneous_provenance_complete": provenance_complete,
        "eligible_for_protocol_reassessment": False,
        "blockers": blockers,
        "refresh_status": refresh_status,
        "note": (
            "Eligibility is false by construction: protocol approval and design "
            "adoption are human decisions recorded outside this workflow. This block "
            "exists to make the remaining blockers explicit, not to grant permission."
        ),
    }


def _request_count(transport: Transport) -> int:
    count = getattr(transport, "request_count", None)
    if isinstance(count, int):
        return count
    calls = getattr(transport, "calls", None)
    return len(calls) if isinstance(calls, list) else 0


def _portable_path(path: Path) -> str:
    target = Path(path)
    try:
        resolved = target.resolve()
    except OSError:
        return str(target)
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            try:
                return str(resolved.relative_to(parent))
            except ValueError:
                break
    return str(target)


def is_instant(value: str) -> bool:
    """True when ``value`` parses as an ISO instant (used by the CLI gate view)."""
    try:
        to_instant(value)
    except (TypeError, ValueError):
        return False
    return True


__all__ = [
    "RefreshError",
    "RefreshOptions",
    "archive_fingerprint",
    "assert_separate_store",
    "is_instant",
    "run_refresh",
    "select_catalog",
]
