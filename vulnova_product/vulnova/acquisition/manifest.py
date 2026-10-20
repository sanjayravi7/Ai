"""The provenance manifest: schema, canonical serialisation, digest.

The manifest is the audit trail.  It is written as deterministic JSON so a
reviewer can diff two acquisitions and see exactly which byte changed, and it
carries a digest over everything except the digest itself and the wall-clock
``generated_at`` label, so the digest attests the *content* of the acquisition
rather than the moment the file was written.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Optional

from . import constants as C
from .records import ArtifactRecord, Requirement

#: ``generated_at`` is the wall clock and ``runtime`` describes the local
#: checkout; neither is evidence, so neither enters the digest.  Everything that
#: identifies an artifact, its source time or its retrieval time does.
DIGEST_EXCLUDED_FIELDS = ("manifest_digest", "generated_at", "runtime")

REQUIRED_RECORD_FIELDS = (
    "source",
    "key",
    "channel",
    "source_url",
    "request_url",
    "content_status",
    "reason_code",
    "access_provenance",
    "historical_retrieval_verified",
)


class ManifestError(RuntimeError):
    pass


def canonical_payload(manifest: dict) -> dict:
    return {
        key: value
        for key, value in manifest.items()
        if key not in DIGEST_EXCLUDED_FIELDS
    }


def manifest_digest(manifest: dict) -> str:
    encoded = json.dumps(
        canonical_payload(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def attach_digest(manifest: dict) -> dict:
    manifest["manifest_digest"] = manifest_digest(manifest)
    return manifest


def write_json(payload: dict, path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return target


def read_json(path: Path | str) -> dict:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError(f"manifest {path} is not a JSON object")
    return payload


def validate_schema(manifest: dict) -> list[str]:
    """Return a list of structural problems; empty means structurally valid."""
    problems: list[str] = []
    if manifest.get("schema_version") != C.SCHEMA_VERSION:
        problems.append(
            f"schema_version {manifest.get('schema_version')!r} != {C.SCHEMA_VERSION!r}"
        )
    records = manifest.get("records")
    if not isinstance(records, list):
        problems.append("records is not a list")
        return problems
    seen: set[tuple[str, str]] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            problems.append(f"record {index} is not an object")
            continue
        for field in REQUIRED_RECORD_FIELDS:
            if field not in record:
                problems.append(f"record {index} missing {field}")
        identity = (str(record.get("source")), str(record.get("key")))
        if identity in seen:
            problems.append(f"duplicate record {identity}")
        seen.add(identity)
        if record.get("content_status") not in C.STATUSES:
            problems.append(
                f"record {index} has unknown content_status {record.get('content_status')!r}"
            )
        if record.get("access_provenance") not in C.ACCESS_PROVENANCE_VALUES:
            problems.append(
                f"record {index} has unknown access_provenance "
                f"{record.get('access_provenance')!r}"
            )
    for requirement in manifest.get("requirements", []):
        if requirement.get("status") not in C.STATUSES:
            problems.append(
                f"requirement {requirement.get('id')!r} has unknown status "
                f"{requirement.get('status')!r}"
            )
    if "manifest_digest" in manifest:
        expected = manifest_digest(manifest)
        if manifest["manifest_digest"] != expected:
            problems.append(
                f"manifest_digest mismatch: recorded {manifest['manifest_digest']}, "
                f"recomputed {expected}"
            )
    return problems


def build_manifest(
    *,
    records: Iterable[ArtifactRecord],
    requirements: Iterable[Requirement],
    generated_at: str,
    cutoffs: Iterable[str],
    grid_cutoffs: Iterable[str],
    as_of: str,
    runtime: Optional[dict] = None,
    label_observations: Optional[dict] = None,
    policies: Optional[dict] = None,
) -> dict:
    record_list = [record.as_dict() for record in records]
    requirement_list = [requirement.as_dict() for requirement in requirements]

    counts = {status: 0 for status in C.STATUSES}
    content_counts = {status: 0 for status in C.STATUSES}
    for record in record_list:
        counts[record["status"]] = counts.get(record["status"], 0) + 1
        content_counts[record["content_status"]] = (
            content_counts.get(record["content_status"], 0) + 1
        )
    requirement_counts = {status: 0 for status in C.STATUSES}
    for requirement in requirement_list:
        requirement_counts[requirement["status"]] += 1

    blocking = [
        requirement["id"]
        for requirement in requirement_list
        if requirement["status"] != C.VERIFIED
    ]
    manifest = {
        "schema_version": C.SCHEMA_VERSION,
        "phase": C.PHASE_TITLE,
        "generated_at": generated_at,
        "as_of": as_of,
        "cutoffs": sorted(set(cutoffs)),
        "grid_cutoffs": sorted(set(grid_cutoffs)),
        "final_candidate_maturity": C.final_candidate_maturity().isoformat(),
        "records": record_list,
        "requirements": requirement_list,
        "label_observations": label_observations or {},
        "policies": policies or {},
        "summary": {
            "records": len(record_list),
            "by_status": counts,
            "by_content_status": content_counts,
            "by_access_provenance": _count(record_list, "access_provenance"),
            "requirements": len(requirement_list),
            "requirements_by_status": requirement_counts,
            "unverified_requirements": blocking,
            "evidence_status": C.worst(
                requirement["status"] for requirement in requirement_list
            )
            if requirement_list
            else C.BLOCKED,
        },
        "runtime": runtime or {},
    }
    return attach_digest(manifest)


def _count(records: list[dict], field: str) -> dict:
    counts: dict[str, int] = {}
    for record in records:
        value = str(record.get(field))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "DIGEST_EXCLUDED_FIELDS",
    "ManifestError",
    "REQUIRED_RECORD_FIELDS",
    "attach_digest",
    "build_manifest",
    "canonical_payload",
    "manifest_digest",
    "read_json",
    "validate_schema",
    "write_json",
]
