"""Prospective capture: preserve evidence from the moment capture begins.

A capture run attempts three first-party observations and records each one,
including its failures:

* the CISA KEV catalog, from the publisher's feed and from CISA's own repository;
* the exact EPSS daily file for the run's UTC observation date;
* the cvelistV5 revision observable right now, identified by its commit SHA.

The run never re-dates anything, never substitutes a mirror, and never turns a
failed request into a negative label.  A capture that obtains two of three
sources is a *partial* capture, reported as ``UNAVAILABLE`` at the run level —
not a success, and not a reason to fabricate the missing source.

The record is written once.  Re-running the same capture at the same instant with
the same responses produces the same run id and is reported as
``ALREADY_CAPTURED`` without touching the stored bytes; a genuinely different
capture gets a different id and lives beside the first.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..acquisition import constants as A
from ..acquisition.github import GitHubApi
from ..acquisition.records import Requirement, to_instant
from ..acquisition.sources import cvelistv5 as cve_source
from ..acquisition.sources import epss as epss_source
from ..acquisition.sources import kev as kev_source
from ..acquisition.transport import Transport
from ..provenance import utc_now
from . import constants as C
from .paths import assert_capture_safety
from .store import CREATED, ProspectiveStore, StoreConflict, StoreError


class CaptureError(RuntimeError):
    """The capture cannot be recorded without violating an invariant."""


# ------------------------------------------------------------------- options
@dataclass
class CaptureOptions:
    """Inputs for one capture run.

    ``transport`` and ``api`` are injected so tests are completely offline; the
    CLI passes the production HTTPS transport.  ``protected_paths`` is additive:
    the fixed historical paths are always guarded, whatever is passed here.
    """

    store_root: Path | str
    transport: Transport
    api: GitHubApi
    clock: Callable[[], str] = utc_now
    protected_paths: tuple[Path, ...] = ()
    output_paths: tuple[Path, ...] = ()


# -------------------------------------------------------------- store adapter
class _KindStore:
    """Duck-typed ``ArtifactStore`` that writes into one capture kind.

    The 1.7 source adapters are reused unchanged: they call ``write(relative,
    bytes)`` and receive a :class:`StoredArtifact`.  Here the ``relative``
    argument is ignored and the bytes are filed by their own digest under the
    capture kind, which is what makes repeated captures idempotent and
    conflicting captures non-destructive.
    """

    def __init__(self, store: ProspectiveStore, kind: str) -> None:
        self.store = store
        self.kind = kind
        self.root = store.root

    def write(self, relative: str, data: bytes):  # noqa: ARG002 - API compatibility
        return self.store.store_artifact(self.kind, data)

    def read(self, relative: str) -> bytes:
        return self.store.read_artifact(relative)

    def digest(self, relative: str) -> Optional[dict]:
        return self.store.artifact_digest(relative)

    def path(self, relative: str) -> Path:
        return self.store.artifact_path(relative)


# ----------------------------------------------------------------- utilities
def _digest(payload: dict) -> str:
    """Canonical digest over a run payload, excluding the digest and its id."""
    clone = {key: value for key, value in payload.items() if key not in C.RUN_DIGEST_EXCLUDED}
    body = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def run_id_for(started_at: str, digest: str) -> str:
    """Deterministic identifier: capture instant plus content digest."""
    instant = to_instant(started_at)
    stamp = instant.strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{digest[:12]}"


def _annotate(record, kind: str, observation: dt.date) -> None:
    """Add the capture context without touching the source's own metadata."""
    record.details.setdefault("capture_kind", kind)
    record.details["observation_date"] = observation.isoformat()
    record.details["prospective"] = True


def _requirement(
    requirement_id: str,
    title: str,
    records: list,
    *,
    selected=None,
) -> Requirement:
    """Summarise one source's capture.

    A requirement is ``VERIFIED`` only when at least one record actually holds
    verified bytes.  Otherwise it takes the worst content status of its records,
    so a policy refusal (``BLOCKED``) outranks an outage (``UNAVAILABLE``).
    """
    verified = [
        record
        for record in records
        if record.content_status == A.VERIFIED and record.sha256 and record.artifact_path
    ]
    if verified:
        chosen = selected or verified[0]
        detail = (
            f"captured {chosen.key} from {chosen.channel}: "
            f"{chosen.bytes} bytes, sha256 {chosen.sha256}"
        )
        failures = [record for record in records if record.content_status != A.VERIFIED]
        if failures:
            detail += "; "
            detail += "; ".join(
                f"{record.key}: {record.reason_code}" for record in failures[:4]
            )
        return Requirement(
            id=requirement_id,
            title=title,
            status=A.VERIFIED,
            reason_code=A.OK_VERIFIED,
            detail=detail,
            records=[f"{record.source}:{record.key}" for record in records],
        )

    status = A.worst([record.content_status for record in records]) if records else A.BLOCKED
    reason = next(
        (
            record.reason_code
            for record in records
            if record.content_status == status
        ),
        A.NO_RECORDS,
    )
    detail = "; ".join(
        f"{record.key}: {record.content_status} ({record.reason_code})"
        for record in records
    ) or "no records were produced"
    return Requirement(
        id=requirement_id,
        title=title,
        status=status,
        reason_code=reason,
        detail=detail,
        records=[f"{record.source}:{record.key}" for record in records],
    )


def _select_kev(records: list):
    """Prefer the publisher's canonical feed, then CISA's own repository."""
    for channel in (A.CHANNEL_OFFICIAL, A.CHANNEL_OFFICIAL_GITHUB):
        for record in records:
            if record.channel == channel and record.content_status == A.VERIFIED:
                return record
    return None


def _assert_record_integrity(store: ProspectiveStore, records: list) -> None:
    """A verified record must be backed by bytes that hash to what it claims."""
    for record in records:
        if record.cutoff is not None:
            raise CaptureError(
                f"{C.HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE}: record "
                f"{record.source}:{record.key} carries cutoff {record.cutoff!r}"
            )
        if record.content_status != A.VERIFIED:
            continue
        if not (record.artifact_path and record.sha256 and record.retrieved_at):
            raise CaptureError(
                f"{record.source}:{record.key} is VERIFIED but is missing its "
                "artifact path, digest or retrieval time"
            )
        digest = store.artifact_digest(record.artifact_path)
        if digest is None:
            raise CaptureError(
                f"{record.source}:{record.key} claims an artifact that is not stored: "
                f"{record.artifact_path}"
            )
        if digest["sha256"] != record.sha256:
            raise CaptureError(
                f"{record.source}:{record.key} artifact hash mismatch: "
                f"{digest['sha256']} != {record.sha256}"
            )
        if digest["bytes"] != record.bytes:
            raise CaptureError(
                f"{record.source}:{record.key} artifact size mismatch: "
                f"{digest['bytes']} != {record.bytes}"
            )


# ------------------------------------------------------------------- capture
def run_capture(options: CaptureOptions) -> dict:
    """Perform one prospective capture and record it immutably.

    Path safety is checked before the clock is read, before the first network
    request and before any directory is created.
    """
    assert_capture_safety(
        options.store_root, options.output_paths, options.protected_paths
    )

    started_at = options.clock()
    try:
        # The observation date is the UTC date.  Slicing the first ten characters
        # would take the *local* date from an offset timestamp, which would put
        # the capture under a day it does not belong to.
        observation = to_instant(started_at).date()
    except (TypeError, ValueError) as exc:
        raise CaptureError(f"clock returned a non-ISO timestamp: {started_at!r}") from exc

    store = ProspectiveStore(options.store_root)
    records: list = []

    try:
        # ---- KEV: the publisher's feed, then the publisher's own repository.
        direct_records, _facts = kev_source.acquire_current(
            options.transport,
            store=_KindStore(store, C.KEV),
            relative=kev_source.CURRENT_ARTIFACT_PATH,
        )
        github_record = kev_source.acquire_current_github(
            options.api,
            store=_KindStore(store, C.KEV),
            maturity=None,
            relative=kev_source.CURRENT_ARTIFACT_PATH,
        )
        kev_records = [*direct_records, github_record]

        # ---- EPSS: the exact official file for this UTC observation date.
        epss_record = epss_source.acquire_daily(
            options.transport,
            observation,
            store=_KindStore(store, C.EPSS),
            historical=False,
        )

        # ---- cvelistV5: the revision observable now, by commit SHA.
        cve_record = cve_source.capture_current(
            options.api, store=_KindStore(store, C.CVELISTV5)
        )
    except StoreError as exc:
        raise CaptureError(f"capture store refused a write: {exc}") from exc

    for kind, record in (
        (C.KEV, direct_records[0]),
        (C.KEV, github_record),
        (C.EPSS, epss_record),
        (C.CVELISTV5, cve_record),
    ):
        _annotate(record, kind, observation)
    records = [*kev_records, epss_record, cve_record]

    _assert_record_integrity(store, records)

    kev_selected = _select_kev(kev_records)
    requirements = [
        _requirement(
            C.KEV_REQUIREMENT,
            "A KEV catalog was captured from a first-party channel",
            kev_records,
            selected=kev_selected,
        ),
        _requirement(
            C.EPSS_REQUIREMENT,
            "The exact EPSS daily file for the observation date was captured",
            [epss_record],
        ),
        _requirement(
            C.CVELISTV5_REQUIREMENT,
            "The cvelistV5 revision observable at capture time was recorded",
            [cve_record],
        ),
    ]

    statuses = [requirement.status for requirement in requirements]
    capture_status = A.worst(statuses)
    verified_sources = sum(1 for status in statuses if status == A.VERIFIED)
    summary = {
        "capture_status": capture_status,
        "observation_date": observation.isoformat(),
        "sources_total": len(requirements),
        "sources_verified": verified_sources,
        "partial_capture": capture_status != A.VERIFIED,
        "selected_kev": (
            {
                "channel": kev_selected.channel,
                "key": kev_selected.key,
                "sha256": kev_selected.sha256,
                "catalog_version": kev_selected.details.get("catalog_version"),
                "date_released": kev_selected.details.get("date_released"),
            }
            if kev_selected is not None
            else None
        ),
        "note": (
            "A capture records what was observed. It is not an evaluation, it "
            "does not mature labels, and a missing source is a gap in observation, "
            "never a negative label."
        ),
    }

    completed_at = options.clock()
    try:
        if to_instant(completed_at) < to_instant(started_at):
            raise CaptureError(
                "the capture clock moved backwards: "
                f"{completed_at} precedes {started_at}"
            )
    except (TypeError, ValueError) as exc:
        raise CaptureError(
            f"clock returned a non-ISO completion timestamp: {completed_at!r}"
        ) from exc

    payload = {
        "schema_version": C.SCHEMA_VERSION,
        "phase": C.PHASE_TITLE,
        "release": C.RELEASE,
        "observation_date": observation.isoformat(),
        "capture_started_at": started_at,
        "capture_completed_at": completed_at,
        "records": [record.as_dict() for record in records],
        "requirements": [requirement.as_dict() for requirement in requirements],
        "summary": summary,
        "honesty": dict(C.POLICIES),
    }
    digest = _digest(payload)
    run_id = run_id_for(started_at, digest)
    payload["run_id"] = run_id
    payload["run_digest"] = digest

    body = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        outcome = store.store_run(run_id, body)
    except StoreConflict as exc:
        raise CaptureError(f"{C.CAPTURE_ID_COLLISION}: {exc}") from exc
    except StoreError as exc:
        raise CaptureError(f"capture store refused the run record: {exc}") from exc

    return {
        "outcome": C.OUTCOME_CAPTURED if outcome == CREATED else C.OUTCOME_ALREADY_CAPTURED,
        "run": payload,
        "run_path": f"{C.RUNS_DIR}/{run_id}.json",
        "store": str(Path(options.store_root)),
    }


__all__ = [
    "CaptureError",
    "CaptureOptions",
    "run_capture",
    "run_id_for",
]
