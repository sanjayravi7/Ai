"""The acquisition workflow: fetch, record, summarise.

One call resolves every required artifact, stores the exact bytes, and produces
a manifest whose requirements distinguish *authentic content* from
*contemporaneous access*.  Nothing here is allowed to upgrade a late retrieval
into historical provenance, and nothing is allowed to substitute a fresher file
for a missing historical one.
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..evaluation.integrity import IntegrityError, extract_if_needed
from ..provenance import utc_now
from . import constants as C
from .github import GitHubApi
from .manifest import build_manifest
from .records import (
    ArtifactRecord,
    Requirement,
    cutoff_instant,
    requirement_from_records,
    to_instant,
)
from .sources import cvelistv5, epss, kev
from .store import ArtifactStore
from .transport import Transport

CORE_BUNDLE_NAME = "VULNOVA_Phase2.3K_core_bundle.tar.gz"
CVE_MANIFEST_NAME = "cvelistv5_inventory_manifest.csv"
KEV_REVISIONS_NAME = "raw/kev_revisions.csv"


class ReferenceError(RuntimeError):
    pass


# --------------------------------------------------------------- reference pins
@dataclass
class ReferencePins:
    """Revision pins recorded by the Phase 2.3K export.

    Used only for cross-checking: the live source is always queried, and a
    disagreement is reported instead of being resolved in either direction.
    """

    root: Path
    cve_by_cutoff: dict[str, dict] = field(default_factory=dict)
    kev_by_commit: dict[str, dict] = field(default_factory=dict)
    kev_rows: list[dict] = field(default_factory=list)
    grid: tuple[dt.date, ...] = ()

    def cve_revision(self, cutoff: dt.date) -> Optional[str]:
        row = self.cve_by_cutoff.get(cutoff.isoformat())
        return row.get("revision_sha") if row else None

    def kev_entry_at(self, cutoff: dt.date) -> Optional[dict]:
        """Latest recorded revision whose committer time is at or before cutoff."""
        boundary = cutoff_instant(cutoff)
        best: Optional[dict] = None
        best_at: Optional[dt.datetime] = None
        for row in self.kev_rows:
            stamp = row.get("commit_date")
            if not stamp:
                continue
            try:
                committed = to_instant(stamp)
            except (TypeError, ValueError):
                continue
            if committed > boundary:
                continue
            if best_at is None or committed > best_at:
                best, best_at = row, committed
        return best

    def kev_digest(self) -> str:
        digest = hashlib.sha256()
        for row in sorted(self.kev_rows, key=lambda item: item.get("commit_sha", "")):
            digest.update(
                f"{row.get('commit_sha')}\x00{row.get('content_sha256')}\n".encode("utf-8")
            )
        return digest.hexdigest()


def load_reference_pins(
    path: Path | str, *, cache_dir: Optional[Path | str] = None
) -> ReferencePins:
    """Load Phase 2.3K pins from an extracted directory or the core bundle.

    ``cache_dir`` defaults to ``vulnova_product/build/acquisition_reference``,
    which is git-ignored; the extracted pins are a cache, not an artifact.
    """
    root = Path(path)
    if not (root / CVE_MANIFEST_NAME).is_file():
        root = _extract_core(root, cache_dir=cache_dir)
    re_root = root
    cve_rows = _read_csv(re_root / CVE_MANIFEST_NAME)
    kev_rows = _read_csv(re_root / KEV_REVISIONS_NAME)
    pins = ReferencePins(
        root=re_root,
        cve_by_cutoff={row.get("cutoff_T", ""): row for row in cve_rows},
        kev_by_commit={row.get("commit_sha", ""): row for row in kev_rows},
        kev_rows=kev_rows,
        grid=_read_grid(re_root / "cutoffs.txt"),
    )
    if not pins.cve_by_cutoff:
        raise ReferenceError(f"{re_root} contains no CVE revision pins")
    if not pins.kev_rows:
        raise ReferenceError(f"{re_root} contains no KEV revisions")
    return pins


def _read_grid(path: Path) -> tuple[dt.date, ...]:
    """Read the Phase 2.3K cutoff grid, if the export ships one."""
    try:
        values = [
            dt.date.fromisoformat(line.strip())
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, ValueError):
        return ()
    return tuple(sorted(set(values)))


def _read_csv(path: Path) -> list[dict]:
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except OSError as exc:
        raise ReferenceError(f"cannot read {path}: {exc}") from exc


def _extract_core(path: Path, *, cache_dir: Optional[Path | str] = None) -> Path:
    """Extract the Phase 2.3K core bundle, reusing the 1.6 extraction cache."""
    candidate = path / CORE_BUNDLE_NAME
    if not candidate.is_file():
        matches = sorted(path.glob("*core*bundle*.tar.gz"))
        if not matches:
            raise ReferenceError(
                f"no extracted core bundle and no {CORE_BUNDLE_NAME} under {path}"
            )
        candidate = matches[0]

    sidecar = candidate.with_name(candidate.name + ".sha256")
    expected_sha = None
    if sidecar.is_file():
        expected_sha = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()

    destination = Path(
        cache_dir
        or Path(__file__).resolve().parents[2] / "build" / "acquisition_reference"
    ).resolve()
    try:
        record = extract_if_needed(
            candidate,
            destination,
            expected_sha256=expected_sha,
            required_paths=(CVE_MANIFEST_NAME, KEV_REVISIONS_NAME),
        )
    except IntegrityError as exc:
        raise ReferenceError(str(exc)) from exc
    if not record.get("digest_matches_expected"):
        raise ReferenceError(
            f"{candidate.name} does not match its published sidecar; refusing to "
            "trust its revision pins"
        )
    root = record.get("root")
    if not root:
        raise ReferenceError(f"{candidate.name} extracted without a root directory")
    return Path(root)


# ------------------------------------------------------------------- options
@dataclass
class AcquisitionOptions:
    store: ArtifactStore
    transport: Transport
    api: GitHubApi
    cutoffs: tuple[dt.date, ...]
    grid: tuple[dt.date, ...]
    clock: Callable[[], str] = utc_now
    reference: Optional[ReferencePins] = None
    fetch_cve: bool = True
    fetch_kev: bool = True
    fetch_epss: bool = True


# --------------------------------------------------------------- requirement
def _requirement(
    requirement_id: str,
    title: str,
    records: list[ArtifactRecord],
    *,
    content_only: bool,
    detail_when_verified: Optional[str] = None,
    evidence: Optional[dict] = None,
) -> Requirement:
    requirement = requirement_from_records(
        requirement_id,
        title,
        records,
        use_access_provenance=not content_only,
        empty_detail="No records were produced for this source.",
        evidence=evidence,
    )
    if requirement.status == C.VERIFIED and detail_when_verified:
        requirement.detail = detail_when_verified
    return requirement


def _best_of(requirement_id: str, title: str, records: list[ArtifactRecord]) -> Requirement:
    """A channel-independent requirement: one trusted channel is enough."""
    trusted = [record for record in records if record.channel in C.TRUSTED_CHANNELS]
    verified = [record for record in trusted if record.content_status == C.VERIFIED]
    if verified:
        failed = [record for record in trusted if record.content_status != C.VERIFIED]
        detail = (
            f"{len(verified)} trusted channel(s) verified: "
            + ", ".join(f"{r.channel}:{r.key}" for r in verified)
        )
        if failed:
            detail += "; unavailable: " + ", ".join(
                f"{r.channel}:{r.key} ({r.reason_code})" for r in failed
            )
        return Requirement(
            id=requirement_id,
            title=title,
            status=C.VERIFIED,
            reason_code=C.OK_VERIFIED,
            detail=detail,
            records=[f"{r.source}:{r.key}" for r in records],
        )
    return requirement_from_records(
        requirement_id,
        title,
        trusted,
        use_access_provenance=False,
        empty_detail="No trusted channel produced a record.",
    )


def _label_observations(
    cutoff_list: Iterable[dt.date], catalog: Optional[ArtifactRecord], as_of: dt.date
) -> dict:
    observations: dict[str, dict] = {}
    released_at = None
    if catalog is not None and catalog.source_timestamp:
        try:
            released_at = to_instant(catalog.source_timestamp)
        except (TypeError, ValueError):
            released_at = None
    for cutoff in sorted(cutoff_list):
        maturity = C.cutoff_maturity(cutoff)
        covers = bool(released_at and released_at.date() >= maturity)
        mature_at_as_of = maturity <= as_of
        if catalog is None or catalog.content_status != C.VERIFIED:
            status, reason = C.UNAVAILABLE, C.NO_RECORDS
        elif not covers:
            status, reason = C.BLOCKED, C.CATALOG_PREDATES_MATURITY
        elif not mature_at_as_of:
            status, reason = C.BLOCKED, C.LABELS_NOT_MATURE
        else:
            status, reason = C.VERIFIED, C.OK_VERIFIED
        observations[cutoff.isoformat()] = {
            "cutoff": cutoff.isoformat(),
            "maturity_date": maturity.isoformat(),
            "as_of": as_of.isoformat(),
            "matured_at_as_of": mature_at_as_of,
            "days_until_matured": (maturity - as_of).days,
            "catalog_released": released_at.isoformat() if released_at else None,
            "catalog_covers_maturity": covers,
            "status": status,
            "reason_code": reason,
            "filter_basis": (
                "dateAdded <= maturity_date"
                if covers
                else "RIGHT_CENSORED_NOT_FILTERED"
            ),
        }
    return observations


POLICIES = {
    "kev_absence": (
        "Absence from the KEV catalog is recorded as NOT_LISTED_IN_CATALOG. It is "
        "never treated as proof that a vulnerability was not exploited."
    ),
    "epss_substitution": (
        "A daily EPSS file is used only when its own score_date equals the cutoff. "
        "Newer files, later model versions and backfilled values are never substituted."
    ),
    "mirrors": (
        "Third-party mirrors are recorded as mirrors and never satisfy a requirement."
    ),
    "retrieval_timestamps": (
        "Retrieval timestamps are captured after the response body is read. They are "
        "never derived from the artifact, never backdated, and never edited."
    ),
    "historical_access": (
        "Authentic historical content retrieved now is LATE_RETRIEVAL, not "
        "contemporaneous provenance, and is reported BLOCKED for that requirement."
    ),
    "maturity": (
        f"The final candidate block matures {C.final_candidate_maturity().isoformat()}. "
        "Maturity is never claimed before that date, and fresh evidence is required "
        "after it."
    ),
    "model_training": "No model is trained, scored or approved by this workflow.",
    "protocol_approval": "The evaluation protocol remains NOT_APPROVED and unamended.",
}


# ------------------------------------------------------------------- run
def run_acquisition(options: AcquisitionOptions) -> dict:
    # The as-of date is fixed at the start of the run; ``generated_at`` is read
    # again at the end so the manifest is always stamped after the last byte was
    # retrieved.  A manifest that predates its own artifacts would be impossible.
    started_at = options.clock()
    as_of_date = dt.date.fromisoformat(started_at[:10])
    records: list[ArtifactRecord] = []

    cve_records: list[ArtifactRecord] = []
    kev_current_records: list[ArtifactRecord] = []
    kev_current_github: Optional[ArtifactRecord] = None
    kev_historical: list[ArtifactRecord] = []
    epss_records: list[ArtifactRecord] = []

    if options.fetch_cve:
        for cutoff in options.cutoffs:
            expected = (
                options.reference.cve_revision(cutoff)
                if options.reference is not None
                else None
            )
            cve_records.append(
                cvelistv5.acquire_revision(
                    options.api, cutoff, store=options.store, expected_revision=expected
                )
            )

    if options.fetch_kev:
        current, _facts = kev.acquire_current(options.transport, store=options.store)
        kev_current_records.extend(current)
        kev_current_github = kev.acquire_current_github(
            options.api,
            store=options.store,
            maturity=C.final_candidate_maturity(),
        )
        kev_current_records.append(kev_current_github)
        for cutoff in options.cutoffs:
            expected = (
                options.reference.kev_entry_at(cutoff)
                if options.reference is not None
                else None
            )
            record = kev.acquire_at_cutoff(
                options.api,
                cutoff,
                store=options.store,
                maturity=None,
                expected_revision=(
                    expected.get("commit_sha") if expected else None
                ),
            )
            if expected is not None:
                pinned_sha = expected.get("content_sha256")
                if record.sha256 and pinned_sha:
                    record.details["recorded_content_sha256"] = pinned_sha
                    if record.sha256 == pinned_sha:
                        record.details["content_crosscheck"] = "MATCH"
                    else:
                        record.content_status = C.BLOCKED
                        record.reason_code = C.SHA256_MISMATCH
                        record.details["content_crosscheck"] = "MISMATCH"
            kev_historical.append(record)

    if options.fetch_epss:
        for cutoff in options.cutoffs:
            epss_records.append(
                epss.acquire_daily(options.transport, cutoff, store=options.store)
            )
        for cutoff in options.cutoffs:
            epss_records.append(epss.mirror_record(cutoff))

    records.extend(cve_records)
    records.extend(kev_current_records)
    records.extend(kev_historical)
    records.extend(epss_records)

    label_catalog = (
        kev_current_github if kev_current_github is not None else None
    )
    if label_catalog is not None and label_catalog.content_status != C.VERIFIED:
        label_catalog = None
    observations = _label_observations(options.cutoffs, label_catalog, as_of_date)

    requirements: list[Requirement] = []
    if options.fetch_cve:
        requirements.append(
            _requirement(
                "CVE-01_REVISION_PIN_RESOLVED",
                "A cvelistV5 revision is resolved and hashed at every cutoff",
                cve_records,
                content_only=True,
                detail_when_verified=(
                    f"{len(cve_records)} cutoff(s) resolved to an exact commit, with "
                    "response bytes stored and SHA-256 recorded."
                ),
            )
        )
        crosscheck = [
            record for record in cve_records if "recorded_revision" in record.details
        ]
        skipped = [
            record
            for record in cve_records
            if record.details.get("pin_crosscheck") == C.PIN_CROSSCHECK_SKIPPED
        ]
        if skipped:
            requirements.append(
                Requirement(
                    id="CVE-02_PIN_CROSSCHECK",
                    title="Live revisions agree with the Phase 2.3K pins",
                    status=C.BLOCKED,
                    reason_code=C.PIN_CROSSCHECK_SKIPPED,
                    detail=(
                        f"{len(skipped)} cutoff(s) had no reference pin to compare "
                        "against; agreement is not claimed."
                    ),
                    records=[f"cvelistv5:{r.key}" for r in skipped],
                )
            )
        else:
            requirements.append(
                _requirement(
                    "CVE-02_PIN_CROSSCHECK",
                    "Live revisions agree with the Phase 2.3K pins",
                    crosscheck,
                    content_only=True,
                    detail_when_verified=(
                        f"All {len(crosscheck)} live revision(s) match the pins "
                        "recorded in the Phase 2.3K export."
                    ),
                )
            )
        requirements.append(
            _requirement(
                "CVE-03_HISTORICAL_RETRIEVAL_PROVENANCE",
                "cvelistV5 was observed at each cutoff, not reconstructed later",
                cve_records,
                content_only=False,
            )
        )

    if options.fetch_kev:
        direct = [r for r in kev_current_records if r.channel == C.CHANNEL_OFFICIAL]
        requirements.append(
            _requirement(
                "KEV-01_DIRECT_CISA_FEED",
                "The direct CISA feed is reachable and preserved",
                direct,
                content_only=True,
            )
        )
        requirements.append(
            _best_of(
                "KEV-02_CURRENT_CATALOG",
                "The current KEV catalog is preserved from a first-party channel",
                kev_current_records,
            )
        )
        requirements.append(
            _requirement(
                "KEV-03_HISTORICAL_REVISION_AT_CUTOFF",
                "The KEV catalog as published at each cutoff is preserved and hashed",
                kev_historical,
                content_only=True,
            )
        )
        label_statuses = [item["status"] for item in observations.values()]
        label_reasons = [item["reason_code"] for item in observations.values()]
        label_status = C.worst(label_statuses) if label_statuses else C.BLOCKED
        requirements.append(
            Requirement(
                id="KEV-04_LABEL_MATURITY_COVERAGE",
                title="Every block's labels can be observed at its maturity date",
                status=label_status,
                reason_code=next(
                    (reason for reason in label_reasons if reason != C.OK_VERIFIED),
                    C.OK_VERIFIED,
                ),
                detail="; ".join(
                    f"{key}: {value['reason_code']}"
                    for key, value in observations.items()
                    if value["status"] != C.VERIFIED
                )
                or "All blocks observe their maturity date.",
                records=["kev:current#github"],
                evidence={"label_observations": observations},
            )
        )
        requirements.append(
            _requirement(
                "KEV-05_HISTORICAL_RETRIEVAL_PROVENANCE",
                "KEV revisions were observed at their cutoffs, not downloaded later",
                kev_historical,
                content_only=False,
            )
        )

    if options.fetch_epss:
        # A third-party mirror must never drag a satisfied requirement down, so
        # the requirements consider official records only.  Mirrors are still
        # recorded and attached as evidence.
        epss_official = [
            record for record in epss_records if record.channel != C.CHANNEL_THIRD_PARTY_MIRROR
        ]
        epss_mirrors = [
            record for record in epss_records if record.channel == C.CHANNEL_THIRD_PARTY_MIRROR
        ]
        mirror_evidence = {
            "third_party_mirrors": [record.as_dict() for record in epss_mirrors],
            "mirrors_satisfy_requirement": False,
        }
        requirements.append(
            _requirement(
                "EPSS-01_EXACT_DAILY_FILE",
                "The exact daily EPSS file exists for every cutoff",
                epss_official,
                content_only=True,
                evidence=mirror_evidence,
            )
        )
        requirements.append(
            _requirement(
                "EPSS-02_HISTORICAL_RETRIEVAL_PROVENANCE",
                "EPSS scores were observed at their cutoff dates",
                epss_official,
                content_only=False,
                evidence=mirror_evidence,
            )
        )

    final_maturity = C.final_candidate_maturity()
    requirements.append(
        Requirement(
            id="PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED",
            title="Premature maturity of the final candidate block is impossible",
            status=C.VERIFIED,
            reason_code=C.OK_VERIFIED,
            detail=(
                f"Final candidate cutoff {C.FINAL_CANDIDATE_CUTOFF.isoformat()} matures "
                f"{final_maturity.isoformat()}; this run is as of {as_of_date.isoformat()} "
                f"({(final_maturity - as_of_date).days} days remaining). "
                "Maturity is not claimed and fresh evidence is still required afterwards."
            ),
            evidence={
                "final_candidate_cutoff": C.FINAL_CANDIDATE_CUTOFF.isoformat(),
                "final_candidate_maturity": final_maturity.isoformat(),
                "as_of": as_of_date.isoformat(),
                "maturity_claimed": False,
                "fresh_evidence_required_after_maturity": True,
            },
        )
    )

    runtime = {
        "requests": _request_count(options),
        "reference_pins": {
            "available": options.reference is not None,
            "root": (
                _portable_path(options.reference.root)
                if options.reference
                else None
            ),
            "kev_revisions_digest": (
                options.reference.kev_digest() if options.reference else None
            ),
        },
        "store_dir": _portable_path(options.store.root),
        "transport": type(options.transport).__name__,
    }

    generated_at = options.clock()
    return build_manifest(
        records=records,
        requirements=requirements,
        generated_at=generated_at,
        cutoffs=[cutoff.isoformat() for cutoff in options.cutoffs],
        grid_cutoffs=[cutoff.isoformat() for cutoff in options.grid],
        as_of=as_of_date.isoformat(),
        runtime=runtime,
        label_observations=observations,
        policies=POLICIES,
    )


def _request_count(options: AcquisitionOptions) -> int:
    transport = options.transport
    count = getattr(transport, "request_count", None)
    if isinstance(count, int):
        return count
    calls = getattr(transport, "calls", None)
    return len(calls) if isinstance(calls, list) else 0


def _portable_path(path: Path) -> str:
    """Render a path relative to the repository root when possible.

    The manifest is a committed artifact; embedding one machine's absolute
    checkout path would make it useless to every other machine.
    """
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


def summary_lines(manifest: dict) -> list[str]:
    summary = manifest["summary"]
    lines = [
        f"records: {summary['records']} "
        f"(VERIFIED {summary['by_status'][C.VERIFIED]}, "
        f"UNAVAILABLE {summary['by_status'][C.UNAVAILABLE]}, "
        f"BLOCKED {summary['by_status'][C.BLOCKED]})",
        f"evidence status: {summary['evidence_status']}",
        "requirements:",
    ]
    for requirement in manifest["requirements"]:
        lines.append(
            f"  {requirement['status']:<9} {requirement['id']} — "
            f"{requirement['reason_code']}"
        )
    return lines


__all__ = [
    "AcquisitionOptions",
    "CORE_BUNDLE_NAME",
    "POLICIES",
    "ReferenceError",
    "ReferencePins",
    "load_reference_pins",
    "run_acquisition",
    "summary_lines",
]
