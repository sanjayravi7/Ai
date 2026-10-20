"""Offline verification of a prospective evidence store.

Verification answers one question only: **are these the bytes that were captured,
does the record that describes them hold together, and is the physical store
fully accounted for?**  It never touches the network, because re-downloading
would verify the publisher rather than the archive.

It checks:

* every run parses, carries the 1.9 schema, and its ``run_digest`` recomputes;
* the run id is exactly the one derived from that digest and capture instant;
* every record has well-typed fields, a status in the three-state vocabulary, no
  historical cutoff, and — when ``VERIFIED`` — a stored artifact whose size and
  SHA-256 match;
* every requirement names a known requirement and carries a valid status, the
  requirements block holds **exactly one entry per required ID** (a duplicate
  contributes no second status and a missing ID is an error), the capture did
  not finish before it started, and the summary status equals the worst
  recomputed requirement status;
* **every physical file** under ``artifacts/`` is inventoried, content-addressed,
  and referenced by a readable run (see below);
* the sealed 1.7 archive still matches its manifest (when this is a repository
  checkout).

The inventory is the part that run records alone cannot provide.  A capture
writes an artifact and *then* its run record; a crash in between leaves an
orphaned artifact.  An orphan whose bytes match its content address is **not
corrupt** — it is an incomplete capture — but it is still reported, with
``UNREFERENCED_ARTIFACT``, and the store does not verify.  Symlinks are never
followed, and a temporary file left by an interrupted write is reported as
``ABANDONED_TEMPORARY_FILE`` rather than silently ignored.

Two captures of the same observation date that disagree are *not* a verification
failure.  They are reported as conflicts: both were preserved, and choosing
between them is not this tool's job.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Optional

from ..acquisition import constants as A
from ..acquisition.records import to_instant
from ..refresh.paths import package_roots
from ..refresh.workflow import archive_fingerprint
from . import constants as C
from .capture import _digest, run_id_for
from .store import SHA256_HEX, ProspectiveStore, StoreEntry, StoreError

PASS = A.VERIFIED
FAIL = A.BLOCKED
NOT_APPLICABLE = "NOT_APPLICABLE"

#: Priority used to pick the single reason code when an inventory check reports
#: several findings.  Corruption outranks unsafe paths, which outrank an
#: unexpected layout, an unreadable file, an abandoned write and an incomplete
#: capture whose bytes are intact.
INVENTORY_PRIORITY = (
    C.ARTIFACT_TAMPERED,
    C.UNSAFE_ARTIFACT_PATH,
    A.ARTIFACT_MISSING,
    C.UNEXPECTED_ARTIFACT,
    C.ARTIFACT_UNREADABLE,
    C.ABANDONED_TEMPORARY_FILE,
    C.UNREFERENCED_ARTIFACT,
)

INVENTORY_CATEGORIES = {
    C.ARTIFACT_TAMPERED: "corrupt",
    A.ARTIFACT_MISSING: "missing",
    C.ARTIFACT_UNREADABLE: "unreadable",
    C.UNSAFE_ARTIFACT_PATH: "unsafe",
    C.UNEXPECTED_ARTIFACT: "unexpected",
    C.ABANDONED_TEMPORARY_FILE: "temporary",
    C.UNREFERENCED_ARTIFACT: "unreferenced",
}

#: How many paths of each category are reported.  Counts are always exact.
MAX_REPORTED_PATHS = 20


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


def _short(value, limit: int = 60) -> str:
    """A type-safe, bounded rendering for an error message.

    Values come from JSON that may be arbitrarily shaped.  Only scalars are
    rendered; everything else is named by type so a malformed record cannot
    produce a huge or machine-specific message.
    """
    if isinstance(value, (str, int, float, bool)) or value is None:
        text = repr(value)
    else:
        text = f"<{type(value).__name__}>"
    return text if len(text) <= limit else text[: limit - 1] + "…"


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
        if not isinstance(relative, str) or not relative:
            continue
        rows.append(
            {
                "kind": record.get("source"),
                "key": record.get("key"),
                "artifact_path": relative,
                "sha256": record.get("sha256"),
                "bytes": record.get("bytes"),
            }
        )
    return rows


def _conflicts(runs: list[dict]) -> list[dict]:
    """Group verified observations by (date, kind) and report disagreements."""
    grouped: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for run in runs:
        observation = run.get("observation_date")
        if not isinstance(observation, str):
            continue
        records = run.get("records")
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            digest = record.get("sha256")
            if record.get("content_status") != A.VERIFIED:
                continue
            if not isinstance(digest, str) or not SHA256_HEX.match(digest):
                continue
            source = record.get("source")
            if not isinstance(source, str) or source not in C.CAPTURE_KINDS:
                continue
            if source in (C.KEV, C.CVELISTV5) and not _is_selected(run, record):
                continue
            key = (observation, source)
            grouped.setdefault(key, {}).setdefault(digest, []).append(
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
                    {str(entry["run_id"]) for entries in digests.values() for entry in entries}
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
    selected = summary.get("selected_kev")
    selected = selected if isinstance(selected, dict) else {}
    recorded = selected.get("sha256")
    return isinstance(recorded, str) and recorded == record.get("sha256")


def _inventory(
    entries: list[StoreEntry], referenced: set[str]
) -> tuple[bool, str, str, dict]:
    """Compare the physical store with the artifacts the runs reference.

    Returns ``(ok, detail, reason, payload)``.  Every finding is a deterministic
    reason code; the payload carries exact counts and capped path lists.
    """
    findings: list[dict] = []
    categories: dict[str, list[str]] = {
        name: [] for name in INVENTORY_CATEGORIES.values()
    }
    artifact_files = 0
    hashed = 0

    for entry in entries:
        if entry.relative.startswith(C.ARTIFACTS_DIR + "/") and entry.entry_type == "file":
            artifact_files += 1
            if entry.sha256 is not None:
                hashed += 1

        reason = entry.problem
        if reason is None:
            if (
                entry.relative.startswith(C.ARTIFACTS_DIR + "/")
                and entry.entry_type == "file"
                and entry.relative not in referenced
            ):
                reason = C.UNREFERENCED_ARTIFACT
            else:
                continue
        category = INVENTORY_CATEGORIES.get(reason)
        if category is None:  # pragma: no cover - defensive
            category = "unexpected"
        categories[category].append(entry.relative)
        findings.append({"path": entry.relative, "reason": reason})

    # Referenced artifacts that are not on disk at all.  They are evidence the
    # run says it captured and the store no longer holds: corruption or loss, not
    # an inventory gap, so they outrank an unreferenced file.
    present = {entry.relative for entry in entries}
    missing = sorted(referenced - present)
    for relative in missing:
        categories["missing"].append(relative)
        findings.append({"path": relative, "reason": A.ARTIFACT_MISSING})

    reason = None
    for candidate in INVENTORY_PRIORITY:
        if any(finding["reason"] == candidate for finding in findings):
            reason = candidate
            break

    payload = {
        "artifact_files": artifact_files,
        "hashed": hashed,
        "referenced": len(referenced),
        "findings": findings[:MAX_REPORTED_PATHS],
        "finding_count": len(findings),
        "counts": {name: len(paths) for name, paths in categories.items()},
        **{name: sorted(paths)[:MAX_REPORTED_PATHS] for name, paths in categories.items()},
    }

    if not findings and not missing:
        return (
            True,
            f"{artifact_files} artifact file(s) inventoried; all content-addressed "
            f"and referenced; {hashed} re-hashed",
            A.OK_VERIFIED,
            payload,
        )

    parts = []
    for name in (
        "corrupt",
        "unsafe",
        "missing",
        "unexpected",
        "unreadable",
        "temporary",
        "unreferenced",
    ):
        if categories[name]:
            parts.append(f"{len(categories[name])} {name}")
    detail = "; ".join(parts) or "inventory mismatch"
    detail = f"{detail} ({artifact_files} artifact file(s) inventoried)"
    if missing:
        detail += f"; missing: {', '.join(missing[:3])}"
    return False, detail, reason or A.INTEGRITY_FAILURE, payload


def verify_store(store_root: Path | str) -> dict:
    """Verify every run and every physical artifact in the store, offline."""
    store = ProspectiveStore(store_root)
    try:
        run_ids = store.run_ids()
    except StoreError as exc:
        # The run directory cannot be read.  That is not an empty store; it is a
        # verification failure, and no claim about the artifacts can be made.
        return {
            "schema_version": "vulnova.prospective.verification/1.9",
            "status": A.BLOCKED,
            "checks": [
                _check(
                    "SCHEMA",
                    False,
                    f"the run directory could not be read: {_describe_error(exc)}",
                    reason=A.MALFORMED_RESPONSE,
                )
            ],
            "captures": 0,
            "artifacts_hashed": 0,
            "artifacts_referenced": 0,
            "artifacts_unreferenced": 0,
            "inventory": {},
            "observation_dates": [],
            "conflicts": [],
            "network_used": False,
            "note": "The store could not be read, so nothing was verified.",
        }

    schema_errors: list[str] = []
    identity_errors: list[str] = []
    digest_errors: list[str] = []
    record_errors: list[str] = []
    record_reasons: list[str] = []
    artifact_errors: list[str] = []
    artifact_reasons: list[str] = []
    status_errors: list[str] = []
    runs: list[dict] = []
    referenced: set[str] = set()

    for run_id in run_ids:
        try:
            raw = store.read_run(run_id)
            run = json.loads(raw.decode("utf-8"))
        except (
            StoreError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            schema_errors.append(f"{run_id}: unreadable ({_describe_error(exc)})")
            continue
        if not isinstance(run, dict):
            schema_errors.append(f"{run_id}: not a JSON object")
            continue
        if run.get("schema_version") != C.SCHEMA_VERSION:
            schema_errors.append(
                f"{run_id}: schema_version {_short(run.get('schema_version'))}"
            )
            continue
        missing_fields = sorted(C.RUN_FIELDS - set(run))
        unexpected_fields = sorted(set(run) - C.RUN_FIELDS)
        if missing_fields:
            schema_errors.append(
                f"{run_id}: missing field(s) {', '.join(missing_fields)}"
            )
        if unexpected_fields:
            schema_errors.append(
                f"{run_id}: unexpected field(s) {', '.join(unexpected_fields)}"
            )
        observation = run.get("observation_date")
        try:
            if not isinstance(observation, str):
                raise ValueError
            dt.date.fromisoformat(observation)
        except (TypeError, ValueError):
            schema_errors.append(
                f"{run_id}: observation_date {_short(observation)} is not an ISO date"
            )
            continue
        if not isinstance(run.get("run_id"), str):
            schema_errors.append(f"{run_id}: run_id is not a string")
            continue
        started = run.get("capture_started_at")
        instants: dict[str, dt.datetime] = {}
        for field in ("capture_started_at", "capture_completed_at"):
            value = run.get(field)
            try:
                if not isinstance(value, str):
                    raise TypeError
                instants[field] = to_instant(value)
            except (TypeError, ValueError):
                schema_errors.append(
                    f"{run_id}: {field} {_short(value)} is not an ISO timestamp"
                )
        # A capture cannot finish before it starts.  Capture refuses a clock that
        # moves backwards; verification refuses a record that claims it did.
        if (
            "capture_started_at" in instants
            and "capture_completed_at" in instants
            and instants["capture_completed_at"] < instants["capture_started_at"]
        ):
            schema_errors.append(
                f"{run_id}: capture_completed_at precedes capture_started_at"
            )
        # The observation date is the UTC date of the capture instant.  Capture
        # computes it that way; a run that claims a different day is misdated,
        # however well its digest recomputes.
        if "capture_started_at" in instants:
            if instants["capture_started_at"].date().isoformat() != observation:
                schema_errors.append(
                    f"{run_id}: observation_date {observation} is not the UTC date of "
                    f"capture_started_at {_short(started)}"
                )
        runs.append(run)

        recorded = run.get("run_digest")
        try:
            recomputed = _digest(run)
        except (TypeError, ValueError, RecursionError) as exc:
            # A pathological value (deep nesting, an unserializable shape) must
            # be a failed check, never a crash.
            digest_errors.append(
                f"{run_id}: run_digest could not be recomputed "
                f"({type(exc).__name__})"
            )
            recomputed = None
        if recomputed is not None and recorded != recomputed:
            digest_errors.append(
                f"{run_id}: {_short(recorded)} != {recomputed}"
            )
        try:
            if recomputed is None:
                raise ValueError("digest unavailable")
            expected_id = run_id_for(str(run.get("capture_started_at", "")), recomputed)
        except (TypeError, ValueError, AttributeError) as exc:
            identity_errors.append(
                f"{run_id}: capture instant is not an ISO timestamp ({_short(exc)})"
            )
        else:
            if run.get("run_id") != run_id or expected_id != run_id:
                identity_errors.append(
                    f"{run_id}: recorded {_short(run.get('run_id'))}, derived {expected_id!r}"
                )

        records = run.get("records")
        if not isinstance(records, list):
            record_errors.append(f"{run_id}: records is not a list")
            records = []
        elif not records:
            record_errors.append(f"{run_id}: no records")

        for record in records:
            if not isinstance(record, dict):
                record_errors.append(f"{run_id}: a record is not a JSON object")
                continue
            source = record.get("source")
            key = record.get("key")
            label = f"{run_id}:{_short(source, 20)}:{_short(key, 20)}"
            if not isinstance(source, str) or not source:
                record_errors.append(f"{label}: source is not a non-empty string")
            if not isinstance(key, str) or not key:
                record_errors.append(f"{label}: key is not a non-empty string")

            content_status = record.get("content_status")
            if not C.is_status(content_status):
                record_errors.append(
                    f"{label}: content_status {_short(content_status)} is outside the "
                    "three-state vocabulary"
                )

            if record.get("cutoff") is not None:
                record_errors.append(
                    f"{label}: carries cutoff {_short(record.get('cutoff'))}"
                )
                record_reasons.append(C.HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE)
            if not C.is_status(content_status):
                record_reasons.append(C.INVALID_STATUS)

            sha = record.get("sha256")
            if sha is not None and not (isinstance(sha, str) and SHA256_HEX.match(sha)):
                record_errors.append(f"{label}: sha256 is not a lower-case SHA-256")
            size = record.get("bytes")
            if size is not None and (
                not isinstance(size, int) or isinstance(size, bool) or size < 0
            ):
                record_errors.append(f"{label}: bytes is not a non-negative integer")
            relative = record.get("artifact_path")
            if relative is not None and not isinstance(relative, str):
                record_errors.append(f"{label}: artifact_path is not a string")
            elif isinstance(relative, str) and relative:
                if not relative.startswith(C.ARTIFACTS_DIR + "/"):
                    record_errors.append(
                        f"{label}: artifact_path {_short(relative)} is not under artifacts/"
                    )
                else:
                    try:
                        store.artifact_path(relative)
                    except StoreError as exc:
                        record_errors.append(
                            f"{label}: artifact_path {_short(relative)} is unsafe "
                            f"({_describe_error(exc)})"
                        )
                    if isinstance(source, str) and source in C.CAPTURE_KINDS:
                        prefix = f"{C.ARTIFACTS_DIR}/{source}/"
                        if not relative.startswith(prefix):
                            record_errors.append(
                                f"{label}: artifact_path {_short(relative)} is not under "
                                f"{prefix}"
                            )
                        elif isinstance(sha, str) and SHA256_HEX.match(sha):
                            expected = f"{prefix}{sha}{C.ARTIFACT_SUFFIX[source]}"
                            if relative != expected:
                                record_errors.append(
                                    f"{label}: artifact_path does not match its content "
                                    "address"
                                )
            for field in ("retrieved_at", "source_timestamp"):
                value = record.get(field)
                if value is None:
                    continue
                if not isinstance(value, str):
                    record_errors.append(f"{label}: {field} is not a string")
                    continue
                try:
                    to_instant(value)
                except (TypeError, ValueError):
                    record_errors.append(f"{label}: {field} is not an ISO timestamp")
            value = record.get("revision")
            if value is not None and not isinstance(value, str):
                record_errors.append(f"{label}: revision is not a string")

            if content_status == A.VERIFIED:
                missing = [
                    field
                    for field in ("artifact_path", "sha256", "retrieved_at")
                    if not isinstance(record.get(field), str) or not record.get(field)
                ]
                if missing:
                    record_errors.append(
                        f"{label}: VERIFIED but missing {', '.join(missing)}"
                    )
                if (
                    not isinstance(size, int)
                    or isinstance(size, bool)
                    or size < 0
                ):
                    record_errors.append(
                        f"{label}: VERIFIED but missing a valid byte count"
                    )
            if isinstance(relative, str) and relative:
                referenced.add(relative)

        requirements = run.get("requirements")
        if not isinstance(requirements, list):
            status_errors.append(f"{run_id}: requirements is not a list")
            requirements = []
        elif not requirements:
            status_errors.append(f"{run_id}: requirements is empty")

        statuses: list[str] = []
        seen_requirement_ids: set[str] = set()
        for requirement in requirements:
            if not isinstance(requirement, dict):
                status_errors.append(f"{run_id}: a requirement is not a JSON object")
                continue
            requirement_id = requirement.get("id")
            if (
                not isinstance(requirement_id, str)
                or requirement_id not in C.REQUIREMENT_KINDS
            ):
                status_errors.append(
                    f"{run_id}: unknown requirement id {_short(requirement_id)}"
                )
                continue
            if requirement_id in seen_requirement_ids:
                # Never let a repeated entry contribute a second status: that
                # would inflate sources_verified and could manufacture VERIFIED.
                status_errors.append(
                    f"{run_id}: duplicate requirement id {requirement_id}"
                )
                continue
            seen_requirement_ids.add(requirement_id)
            status = requirement.get("status")
            if not C.is_status(status):
                status_errors.append(
                    f"{run_id}: requirement {requirement_id} status "
                    f"{_short(status)} is outside the three-state vocabulary"
                )
                continue
            statuses.append(status)

        missing_requirement_ids = sorted(
            set(C.REQUIREMENT_KINDS) - seen_requirement_ids
        )
        if missing_requirement_ids:
            status_errors.append(
                f"{run_id}: missing required requirement(s) "
                f"{', '.join(missing_requirement_ids)}"
            )

        complete = (
            bool(statuses)
            and len(statuses) == len(requirements)
            and len(statuses) == len(C.REQUIREMENT_KINDS)
        )
        expected_status = A.worst(statuses) if complete else A.BLOCKED
        summary = run.get("summary")
        summary = summary if isinstance(summary, dict) else {}
        recorded_status = summary.get("capture_status")
        if not C.is_status(recorded_status):
            status_errors.append(
                f"{run_id}: summary capture_status {_short(recorded_status)} is outside "
                "the three-state vocabulary"
            )
        elif recorded_status != expected_status:
            status_errors.append(
                f"{run_id}: summary {recorded_status!r} != derived {expected_status!r}"
            )

        # The summary's own counters must agree with the requirements it
        # summarizes.  A wrong-typed field is a malformed record even when the
        # top-level status happens to be right.
        if isinstance(run.get("summary"), dict):
            summary_date = summary.get("observation_date")
            if summary_date != run.get("observation_date"):
                status_errors.append(
                    f"{run_id}: summary observation_date {_short(summary_date)} != "
                    f"{_short(run.get('observation_date'))}"
                )
            if complete:
                verified = sum(1 for status in statuses if status == A.VERIFIED)
                counts = {
                    "sources_total": len(requirements),
                    "sources_verified": verified,
                }
                for field, expected in counts.items():
                    value = summary.get(field)
                    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
                        status_errors.append(
                            f"{run_id}: summary {field} {_short(value)} != {expected}"
                        )
                partial = summary.get("partial_capture")
                if not isinstance(partial, bool) or partial != (expected_status != A.VERIFIED):
                    status_errors.append(
                        f"{run_id}: summary partial_capture {_short(partial)} is "
                        f"inconsistent with {expected_status}"
                    )

    # ---- Physical inventory.  Never trusts run JSON to enumerate the store.
    # Both scans happen once; the same entries feed the inventory check and the
    # referenced-artifact check, so no file is hashed twice.
    try:
        artifact_entries = store.artifact_entries()
        inventory_entries = artifact_entries + store.run_directory_entries()
        inventory_ok, inventory_detail, inventory_reason, inventory_payload = _inventory(
            inventory_entries, referenced
        )
    except StoreError as exc:
        artifact_entries = []
        inventory_ok = False
        inventory_detail = f"the store could not be inventoried: {_describe_error(exc)}"
        inventory_reason = A.INTEGRITY_FAILURE
        inventory_payload = {"error": _describe_error(exc)}

    # ---- Referenced artifacts must exist and match their records.
    by_relative = {
        entry.relative: entry
        for entry in artifact_entries
        if entry.entry_type == "file"
    }
    for run in runs:
        records = run.get("records")
        records = records if isinstance(records, list) else []
        for row in _artifact_rows(records):
            label = f"{_short(row['kind'], 20)}:{_short(row['key'], 20)}"
            entry = by_relative.get(row["artifact_path"])
            if entry is None or entry.entry_type != "file":
                artifact_errors.append(f"{label}: {row['artifact_path']} is missing")
                artifact_reasons.append(A.ARTIFACT_MISSING)
                continue
            if entry.problem in (C.UNSAFE_ARTIFACT_PATH, C.ARTIFACT_UNREADABLE):
                artifact_errors.append(
                    f"{label}: {row['artifact_path']} is {entry.problem}"
                )
                artifact_reasons.append(entry.problem)
                continue
            if entry.sha256 is None:
                artifact_errors.append(f"{label}: {row['artifact_path']} could not be read")
                artifact_reasons.append(C.ARTIFACT_UNREADABLE)
                continue
            recorded_sha = row["sha256"]
            if isinstance(recorded_sha, str) and entry.sha256 != recorded_sha:
                artifact_errors.append(
                    f"{label}: {entry.sha256} != {recorded_sha}"
                )
                artifact_reasons.append(C.ARTIFACT_TAMPERED)
            recorded_size = row["bytes"]
            if (
                isinstance(recorded_size, int)
                and not isinstance(recorded_size, bool)
                and entry.bytes != recorded_size
            ):
                artifact_errors.append(
                    f"{label}: {entry.bytes} bytes != recorded {recorded_size}"
                )
                artifact_reasons.append(C.ARTIFACT_TAMPERED)

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
            "every record is well-typed, carries no historical cutoff and every "
            "VERIFIED record is backed"
            if not record_errors
            else "; ".join(record_errors[:5]),
            reason=next(
                (
                    reason
                    for reason in (
                        C.HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE,
                        C.INVALID_STATUS,
                        A.INTEGRITY_FAILURE,
                    )
                    if reason in record_reasons
                ),
                A.INTEGRITY_FAILURE,
            ),
        ),
        _check(
            "ARTIFACTS",
            not artifact_errors,
            f"{len(referenced)} referenced artifact(s) present and matching"
            if not artifact_errors
            else "; ".join(artifact_errors[:5]),
            reason=(
                A.ARTIFACT_MISSING
                if artifact_reasons and all(
                    reason == A.ARTIFACT_MISSING for reason in artifact_reasons
                )
                else C.ARTIFACT_TAMPERED
            ),
        ),
        _check(
            "STORE_INVENTORY",
            inventory_ok,
            inventory_detail,
            reason=inventory_reason,
        ),
        _check(
            "CAPTURE_STATUS",
            not status_errors,
            "every summary status equals its recomputed requirement status"
            if not status_errors
            else "; ".join(status_errors[:5]),
            reason=C.INVALID_STATUS,
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
        "artifacts_hashed": inventory_payload.get("hashed", 0),
        "artifacts_referenced": len(referenced),
        "artifacts_unreferenced": inventory_payload.get("counts", {}).get("unreferenced", 0),
        "inventory": inventory_payload,
        "observation_dates": sorted(
            {str(run.get("observation_date")) for run in runs}
        ),
        "conflicts": _conflicts(runs),
        "network_used": False,
        "note": (
            "Integrity proves the stored bytes are the captured bytes and that the "
            "physical store is accounted for. It does not prove historical "
            "correctness, completeness or research viability."
        ),
    }


def verify_failure_reasons(result: dict) -> list[str]:
    return [check["id"] for check in result["checks"] if check["status"] == FAIL]


__all__ = ["NOT_APPLICABLE", "verify_failure_reasons", "verify_store"]
