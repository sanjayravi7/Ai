"""Offline verification of a prospective evidence store.

Verification answers one question only: **are these the bytes that were captured,
and does the record that describes them hold together?**  It never touches the
network, because re-downloading would verify the publisher rather than the
archive.

It checks:

* every run parses, carries the 1.9 schema, and its ``run_digest`` recomputes;
* the run id is exactly the one derived from that digest and capture instant;
* every verified record is backed by a stored artifact whose size and SHA-256
  match the record, and no record carries a historical cutoff;
* the summary status equals the worst recomputed requirement status;
* the sealed 1.7 archive still matches its manifest (when this is a repository
  checkout).

Two captures of the same observation date that disagree are *not* a verification
failure.  They are reported as conflicts: both were preserved, and choosing
between them is not this tool's job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..acquisition import constants as A
from ..refresh.paths import package_roots
from ..refresh.workflow import archive_fingerprint
from . import constants as C
from .capture import _digest, run_id_for
from .store import ProspectiveStore, StoreError

PASS = A.VERIFIED
FAIL = A.BLOCKED
NOT_APPLICABLE = "NOT_APPLICABLE"


def _check(
    check_id: str,
    ok: bool,
    detail: str,
    *,
    reason: Optional[str] = None,
    not_applicable: bool = False,
) -> dict:
    if not_applicable:
        return {
            "id": check_id,
            "status": NOT_APPLICABLE,
            "reason_code": "NOT_APPLICABLE",
            "detail": detail,
        }
    return {
        "id": check_id,
        "status": PASS if ok else FAIL,
        "reason_code": A.OK_VERIFIED if ok else (reason or A.INTEGRITY_FAILURE),
        "detail": detail,
    }


def _describe_error(exc: BaseException) -> str:
    """Error text without machine-specific absolute paths.

    ``read_run`` lets ``FileNotFoundError`` surface with the full path, and a
    report that embedded that path would no longer be reproducible on another
    machine -- which is exactly what its digest is supposed to guarantee.
    """
    if isinstance(exc, OSError):
        reason = exc.strerror or (exc.args[0] if exc.args else "")
        return f"{type(exc).__name__}: {reason}"
    return f"{type(exc).__name__}: {exc}"


def _artifact_rows(records: list) -> list[dict]:
    rows = []
    for record in records:
        if not isinstance(record, dict):
            continue
        relative = record.get("artifact_path")
        if not relative:
            continue
        rows.append(
            {
                "kind": record.get("source"),
                "key": record.get("key"),
                "artifact_path": relative,
                "sha256": record.get("sha256"),
                "bytes": record.get("bytes"),
                "status": record.get("content_status"),
            }
        )
    return rows


def _conflicts(runs: list[dict]) -> list[dict]:
    """Group verified observations by (date, kind) and report disagreements."""
    grouped: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for run in runs:
        observation = str(run.get("observation_date", ""))
        for record in run.get("records", []):
            if not isinstance(record, dict):
                continue
            if record.get("content_status") != A.VERIFIED or not record.get("sha256"):
                continue
            if record.get("source") in (C.KEV, C.CVELISTV5) and not _is_selected(run, record):
                continue
            key = (observation, str(record.get("source")))
            grouped.setdefault(key, {}).setdefault(record["sha256"], []).append(
                {
                    "run_id": run.get("run_id"),
                    "key": record.get("key"),
                }
            )
    conflicts = []
    for (observation, kind), digests in sorted(grouped.items()):
        if len(digests) <= 1:
            continue
        conflicts.append(
            {
                "observation_date": observation,
                "kind": kind,
                "sha256": sorted(digests),
                "run_ids": sorted(
                    {entry["run_id"] for entries in digests.values() for entry in entries}
                ),
                "reason_code": C.CONFLICTING_CAPTURES,
                "note": (
                    "Both captures were preserved. Neither is preferred here; a "
                    "later assessment must state which one it uses and why."
                ),
            }
        )
    return conflicts


def _is_selected(run: dict, record: dict) -> bool:
    """True when ``record`` is the catalog this run selected for its date.

    KEV keeps the failed direct-feed attempt beside the successful fallback, so
    only the selected catalog should participate in conflict detection.
    """
    if record.get("source") == C.CVELISTV5:
        return True
    summary = run.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    selected = summary.get("selected_kev") or {}
    return selected.get("sha256") == record.get("sha256")


def verify_store(store_root: Path | str) -> dict:
    """Verify every run and artifact in the store, offline."""
    store = ProspectiveStore(store_root)
    run_ids = store.run_ids()

    schema_errors: list[str] = []
    identity_errors: list[str] = []
    digest_errors: list[str] = []
    record_errors: list[str] = []
    artifact_errors: list[str] = []
    status_errors: list[str] = []
    runs: list[dict] = []
    hashed: set[str] = set()
    artifact_hashes = 0

    for run_id in run_ids:
        try:
            raw = store.read_run(run_id)
            run = json.loads(raw.decode("utf-8"))
        except (StoreError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            schema_errors.append(f"{run_id}: unreadable ({_describe_error(exc)})")
            continue
        if not isinstance(run, dict):
            schema_errors.append(f"{run_id}: not a JSON object")
            continue
        if run.get("schema_version") != C.SCHEMA_VERSION:
            schema_errors.append(
                f"{run_id}: schema_version {run.get('schema_version')!r}"
            )
            continue
        runs.append(run)

        recorded = run.get("run_digest")
        recomputed = _digest(run)
        if recorded != recomputed:
            digest_errors.append(f"{run_id}: {recorded} != {recomputed}")
        try:
            expected_id = run_id_for(str(run.get("capture_started_at", "")), recomputed)
        except (TypeError, ValueError, AttributeError) as exc:
            identity_errors.append(
                f"{run_id}: capture instant is not an ISO timestamp ({exc})"
            )
        else:
            if run.get("run_id") != run_id or expected_id != run_id:
                identity_errors.append(
                    f"{run_id}: recorded {run.get('run_id')!r}, derived {expected_id!r}"
                )

        records = run.get("records")
        if not isinstance(records, list) or not records:
            record_errors.append(f"{run_id}: no records")
            records = []
        for record in records:
            if not isinstance(record, dict):
                record_errors.append(f"{run_id}: a record is not a JSON object")
                continue
            label = f"{run_id}:{record.get('source')}:{record.get('key')}"
            if record.get("cutoff") is not None:
                record_errors.append(
                    f"{label}: carries cutoff {record.get('cutoff')!r}"
                )
            if record.get("content_status") == A.VERIFIED:
                missing = [
                    field
                    for field in ("artifact_path", "sha256", "retrieved_at")
                    if not record.get(field)
                ]
                if missing:
                    record_errors.append(
                        f"{label}: VERIFIED but missing {', '.join(missing)}"
                    )
        for row in _artifact_rows(records):
            relative = row["artifact_path"]
            try:
                digest = store.artifact_digest(relative)
            except StoreError as exc:
                artifact_errors.append(f"{row['kind']}:{row['key']}: {exc}")
                continue
            if digest is None:
                artifact_errors.append(f"{row['kind']}:{row['key']}: {relative} is missing")
                continue
            if relative not in hashed:
                hashed.add(relative)
                artifact_hashes += 1
            if digest["sha256"] != row["sha256"]:
                artifact_errors.append(
                    f"{row['kind']}:{row['key']}: {digest['sha256']} != {row['sha256']}"
                )
            elif digest["bytes"] != row["bytes"]:
                artifact_errors.append(
                    f"{row['kind']}:{row['key']}: {digest['bytes']} != {row['bytes']}"
                )

        requirements = run.get("requirements")
        if requirements is None:
            requirements = []
        elif not isinstance(requirements, list):
            status_errors.append(f"{run_id}: requirements is not a list")
            requirements = []
        statuses = [
            requirement.get("status")
            for requirement in requirements
            if isinstance(requirement, dict)
        ]
        expected_status = A.worst(statuses) if statuses else A.BLOCKED
        summary = run.get("summary")
        summary = summary if isinstance(summary, dict) else {}
        recorded_status = summary.get("capture_status")
        if recorded_status != expected_status:
            status_errors.append(
                f"{run_id}: summary {recorded_status!r} != derived {expected_status!r}"
            )

    checks = [
        _check(
            "SCHEMA",
            not schema_errors,
            "all run records parse with the 1.9 schema"
            if not schema_errors
            else "; ".join(schema_errors[:5]),
            reason=A.MALFORMED_RESPONSE,
        ),
        _check(
            "RUN_DIGEST",
            not digest_errors,
            "every run digest recomputes"
            if not digest_errors
            else "; ".join(digest_errors[:5]),
            reason=C.RUN_DIGEST_MISMATCH,
        ),
        _check(
            "RUN_IDENTITY",
            not identity_errors,
            "every run id matches its capture instant and content digest"
            if not identity_errors
            else "; ".join(identity_errors[:5]),
            reason=A.INTEGRITY_FAILURE,
        ),
        _check(
            "RECORD_INVARIANTS",
            not record_errors,
            "no record carries a historical cutoff; every verified record is backed"
            if not record_errors
            else "; ".join(record_errors[:5]),
            reason=C.HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE,
        ),
        _check(
            "ARTIFACTS",
            not artifact_errors,
            f"{artifact_hashes} unique artifact(s) re-hashed; all match"
            if not artifact_errors
            else "; ".join(artifact_errors[:5]),
            reason=C.ARTIFACT_TAMPERED,
        ),
        _check(
            "CAPTURE_STATUS",
            not status_errors,
            "every summary status equals its recomputed requirement status"
            if not status_errors
            else "; ".join(status_errors[:5]),
            reason=A.INTEGRITY_FAILURE,
        ),
    ]

    # ---- The sealed historical archive must not have moved underneath us.
    product, _repository = package_roots()
    manifest = product / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
    archive_store = product / "data" / "acquisition_store"
    if manifest.is_file() and archive_store.is_dir():
        fingerprint = archive_fingerprint(manifest, archive_store)
        # The invariant is "the manifest is readable, it names artifacts, and
        # every one still hashes to what it recorded".  A hard-coded count
        # would fail a legitimate checkout whose archive has a different size,
        # and would pass a manifest that names nothing.
        intact = (
            fingerprint["manifest"]["available"]
            and fingerprint["artifact_count"] > 0
            and fingerprint["all_artifacts_unchanged"]
        )
        checks.append(
            _check(
                "HISTORICAL_ARCHIVE",
                intact,
                (
                    f"{fingerprint['artifact_count']} sealed 1.7 artifact(s) re-hashed; "
                    "all match"
                )
                if intact
                else "the sealed 1.7 manifest or one of its artifacts changed",
                reason=A.INTEGRITY_FAILURE,
            )
        )
    else:
        checks.append(
            _check(
                "HISTORICAL_ARCHIVE",
                True,
                "no committed 1.7 archive in this checkout; nothing to compare",
                not_applicable=True,
            )
        )

    if not run_ids:
        # An empty store is not a verified store.  Saying VERIFIED here would let
        # "no evidence" read as "evidence checked", which is the confusion this
        # subsystem exists to prevent.
        checks.append(
            _check(
                "CAPTURES_PRESENT",
                False,
                "the store contains no captures; there is nothing to verify and "
                "this is not a success",
                reason=C.NO_CAPTURES,
            )
        )

    failed = [check for check in checks if check["status"] == FAIL]
    return {
        "schema_version": "vulnova.prospective.verification/1.9",
        "status": A.BLOCKED if failed else A.VERIFIED,
        "checks": checks,
        "captures": len(run_ids),
        "artifacts_hashed": artifact_hashes,
        "observation_dates": sorted({str(run.get("observation_date")) for run in runs}),
        "conflicts": _conflicts(runs),
        "network_used": False,
        "note": (
            "Integrity proves the stored bytes are the captured bytes. It does not "
            "prove historical correctness, completeness or research viability."
        ),
    }


def verify_failure_reasons(result: dict) -> list[str]:
    return [check["id"] for check in result["checks"] if check["status"] == FAIL]


__all__ = ["NOT_APPLICABLE", "verify_failure_reasons", "verify_store"]
