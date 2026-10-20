"""Offline integrity verification of an acquisition manifest.

Verification answers two questions and keeps them apart:

* **integrity** — are the stored bytes the bytes that were recorded, and are the
  recorded times internally consistent?
* **evidence** — which requirements are actually supported?

The verifier never touches the network.  A verifier that re-downloaded files
would be verifying the network, not the archive.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..evaluation.temporal import parse_date
from . import constants as C
from .manifest import manifest_digest, validate_schema
from .records import ArtifactRecord, to_instant
from .store import ArtifactStore

CHECK_PASS = C.VERIFIED
CHECK_FAIL = C.BLOCKED


def _check(check_id: str, ok: bool, detail: str, *, reason: Optional[str] = None) -> dict:
    return {
        "id": check_id,
        "status": CHECK_PASS if ok else CHECK_FAIL,
        "reason_code": (C.OK_VERIFIED if ok else (reason or "INTEGRITY_FAILURE")),
        "detail": detail,
    }


def verify_manifest(manifest: dict, store: ArtifactStore) -> dict:
    checks: list[dict] = []
    problems = validate_schema(manifest)
    checks.append(
        _check(
            "SCHEMA",
            not problems,
            "structure and digest are valid"
            if not problems
            else "; ".join(problems[:8]),
            reason=C.MALFORMED_RESPONSE,
        )
    )

    if "manifest_digest" in manifest:
        actual = manifest_digest(manifest)
        checks.append(
            _check(
                "MANIFEST_DIGEST",
                actual == manifest["manifest_digest"],
                f"recorded {manifest['manifest_digest']}, recomputed {actual}",
                reason=C.SHA256_MISMATCH,
            )
        )

    generated_at = manifest.get("generated_at")
    grid = set(manifest.get("grid_cutoffs", []))
    records = manifest.get("records", [])

    missing: list[str] = []
    size_mismatch: list[str] = []
    hash_mismatch: list[str] = []
    unreadable: list[str] = []
    hash_checked = 0
    for record in records:
        relative = record.get("artifact_path")
        if not relative:
            continue
        digest = store.digest(relative)
        if digest is None:
            if record.get("content_status") == C.VERIFIED:
                missing.append(relative)
            continue
        hash_checked += 1
        if record.get("bytes") is not None and record["bytes"] != digest["bytes"]:
            size_mismatch.append(
                f"{relative}: recorded {record['bytes']}, actual {digest['bytes']}"
            )
        if record.get("sha256") and record["sha256"] != digest["sha256"]:
            hash_mismatch.append(
                f"{relative}: recorded {record['sha256'][:12]}, "
                f"actual {digest['sha256'][:12]}"
            )
        elif not record.get("sha256"):
            unreadable.append(f"{relative}: no recorded sha256")

    checks.append(
        _check(
            "ARTIFACT_PRESENT",
            not missing,
            f"{hash_checked} artifact(s) present"
            if not missing
            else f"{len(missing)} artifact(s) missing: " + ", ".join(missing[:5]),
            reason=C.ARTIFACT_MISSING,
        )
    )
    checks.append(
        _check(
            "ARTIFACT_SIZE",
            not size_mismatch,
            "all sizes match" if not size_mismatch else "; ".join(size_mismatch[:5]),
            reason=C.SIZE_MISMATCH,
        )
    )
    checks.append(
        _check(
            "ARTIFACT_SHA256",
            not hash_mismatch and not unreadable,
            f"all {hash_checked} artifact digest(s) match"
            if not hash_mismatch and not unreadable
            else "; ".join((hash_mismatch + unreadable)[:5]),
            reason=C.SHA256_MISMATCH,
        )
    )

    missing_stamp: list[str] = []
    reordered: list[str] = []
    future: list[str] = []
    access_wrong: list[str] = []
    overstated: list[str] = []
    for record in records:
        identity = f"{record.get('source')}:{record.get('key')}"
        retrieved_at = record.get("retrieved_at")
        access = record.get("access_provenance")
        if access != C.NOT_RETRIEVED and not retrieved_at:
            missing_stamp.append(identity)
        if retrieved_at and generated_at:
            try:
                if to_instant(retrieved_at) > to_instant(generated_at):
                    future.append(f"{identity}: {retrieved_at} after {generated_at}")
            except (TypeError, ValueError):
                missing_stamp.append(f"{identity}: unparseable retrieval time")
        source_timestamp = record.get("source_timestamp")
        if retrieved_at and source_timestamp:
            try:
                if to_instant(retrieved_at) < to_instant(source_timestamp):
                    reordered.append(
                        f"{identity}: retrieved {retrieved_at} before source {source_timestamp}"
                    )
            except (TypeError, ValueError):
                reordered.append(f"{identity}: unparseable source timestamp")

        rebuilt = ArtifactRecord(
            source=str(record.get("source")),
            key=str(record.get("key")),
            channel=str(record.get("channel")),
            source_url=str(record.get("source_url")),
            request_url=str(record.get("request_url")),
            content_status=str(record.get("content_status")),
            reason_code=str(record.get("reason_code")),
            access_provenance=str(record.get("access_provenance")),
            cutoff=record.get("cutoff"),
            retrieved_at=retrieved_at,
            source_timestamp=source_timestamp,
            sha256=record.get("sha256"),
            artifact_path=record.get("artifact_path"),
        )
        derived = rebuilt.classify_access()
        if derived != access:
            access_wrong.append(f"{identity}: recorded {access}, derived {derived}")
        if record.get("historical_retrieval_verified") and derived != C.CONTEMPORANEOUS:
            overstated.append(f"{identity}: claims contemporaneous access ({derived})")

    checks.append(
        _check(
            "RETRIEVAL_TIMESTAMP_PRESENT",
            not missing_stamp,
            "every retrieved record carries an actual retrieval timestamp"
            if not missing_stamp
            else "; ".join(missing_stamp[:5]),
            reason=C.RETRIEVAL_TIMESTAMP_MISSING,
        )
    )
    checks.append(
        _check(
            "RETRIEVAL_AFTER_SOURCE",
            not reordered,
            "no retrieval timestamp precedes its source timestamp"
            if not reordered
            else "; ".join(reordered[:5]),
            reason=C.RETRIEVAL_BEFORE_SOURCE_TIME,
        )
    )
    checks.append(
        _check(
            "RETRIEVAL_BEFORE_MANIFEST",
            not future,
            "no record was retrieved after the manifest was generated"
            if not future
            else "; ".join(future[:5]),
            reason=C.RETRIEVAL_TIMESTAMP_MISSING,
        )
    )
    checks.append(
        _check(
            "ACCESS_PROVENANCE_RECONSISTENT",
            not access_wrong,
            "access provenance matches the recorded timestamps"
            if not access_wrong
            else "; ".join(access_wrong[:5]),
            reason=C.MALFORMED_RESPONSE,
        )
    )
    checks.append(
        _check(
            "HISTORICAL_RETRIEVAL_NOT_OVERSTATED",
            not overstated,
            "no late retrieval is reported as contemporaneous"
            if not overstated
            else "; ".join(overstated[:5]),
            reason=C.RETRIEVAL_NOT_CONTEMPORANEOUS,
        )
    )

    outside = sorted(
        {
            str(record.get("cutoff"))
            for record in records
            if record.get("cutoff") and str(record.get("cutoff")) not in grid
        }
    )
    checks.append(
        _check(
            "CUTOFFS_IN_GRID",
            not outside,
            f"all cutoffs belong to the {len(grid)}-date grid"
            if not outside
            else "cutoffs outside the grid: " + ", ".join(outside[:5]),
            reason=C.CUTOFF_OUTSIDE_GRID,
        )
    )

    final_maturity = C.final_candidate_maturity()
    as_of_text = manifest.get("as_of")
    as_of_date = parse_date(as_of_text) if as_of_text else None
    premature = False
    if as_of_date is not None and as_of_date < final_maturity:
        for key, observation in (manifest.get("label_observations") or {}).items():
            if observation.get("status") != C.VERIFIED:
                continue
            try:
                maturity = parse_date(str(observation.get("maturity_date")))
            except ValueError:
                premature = True
                break
            if maturity > as_of_date and key == C.FINAL_CANDIDATE_CUTOFF.isoformat():
                premature = True
                break
    checks.append(
        _check(
            "FINAL_BLOCK_MATURITY_NOT_CLAIMED",
            not premature,
            (
                f"maturity {final_maturity.isoformat()} is not claimed as of "
                f"{manifest.get('as_of')}"
            )
            if not premature
            else "a premature maturity claim was found",
            reason=C.LABELS_NOT_MATURE,
        )
    )

    status = C.worst(check["status"] for check in checks)
    return {
        "schema_version": manifest.get("schema_version"),
        "manifest_digest": manifest.get("manifest_digest"),
        "generated_at": generated_at,
        "status": status,
        "integrity_status": status,
        "evidence_status": manifest.get("summary", {}).get("evidence_status"),
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "verified": sum(1 for check in checks if check["status"] == C.VERIFIED),
            "blocked": sum(1 for check in checks if check["status"] == C.BLOCKED),
            "artifacts_hashed": hash_checked,
            "network_used": False,
        },
    }


def verify_paths(manifest: dict, store_dir: Path | str) -> dict:
    return verify_manifest(manifest, ArtifactStore(store_dir))


def required_source_matrix(manifest: dict) -> list[dict]:
    """Every required source must have a record for every declared cutoff."""
    cutoffs = manifest.get("cutoffs", [])
    rows: list[dict] = []
    for source in ("cvelistv5", "kev", "epss"):
        for cutoff in cutoffs:
            record = next(
                (
                    item
                    for item in manifest.get("records", [])
                    if item.get("source") == source
                    and item.get("cutoff") == cutoff
                    and item.get("channel") != C.CHANNEL_THIRD_PARTY_MIRROR
                ),
                None,
            )
            rows.append(
                {
                    "source": source,
                    "cutoff": cutoff,
                    "present": record is not None,
                    "content_status": record.get("content_status") if record else None,
                    "reason_code": record.get("reason_code") if record else C.NO_RECORDS,
                }
            )
    return rows


def check_coverage(manifest: dict) -> dict:
    rows = required_source_matrix(manifest)
    missing = [row for row in rows if not row["present"]]
    unverified = [
        row
        for row in rows
        if row["present"] and row["content_status"] != C.VERIFIED
    ]
    grid = set(manifest.get("grid_cutoffs", []))
    outside = [cutoff for cutoff in manifest.get("cutoffs", []) if cutoff not in grid]
    status = C.VERIFIED
    if missing or outside:
        status = C.BLOCKED
    elif unverified:
        status = C.UNAVAILABLE
    return {
        "status": status,
        "rows": rows,
        "missing": missing,
        "unverified": unverified,
        "cutoffs_outside_grid": outside,
        "summary": (
            f"{len(rows)} source/cutoff pairs; "
            f"{len(missing)} missing, {len(unverified)} unverified"
        ),
    }


__all__ = [
    "CHECK_FAIL",
    "CHECK_PASS",
    "check_coverage",
    "required_source_matrix",
    "verify_manifest",
    "verify_paths",
]
