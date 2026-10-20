"""Offline verification of a committed refresh report.

Mirrors the 1.7 verifier's two-axis answer:

* **integrity** — is the report internally consistent, are the refresh artifacts
  byte-identical to their recorded hashes, and is the sealed 1.7 archive still
  untouched?
* **evidence** — what does the report say is still unmet?

The verifier never touches the network.  Re-downloading would verify the
network, not the archive, and would also defeat the point of a committed,
auditable record.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..acquisition import constants as A
from ..acquisition.manifest import read_json
from ..acquisition.store import ArtifactStore
from . import constants as C
from .report import verify_digest

PASS = A.VERIFIED
FAIL = A.BLOCKED


def _check(check_id: str, ok: bool, detail: str, *, reason: Optional[str] = None) -> dict:
    return {
        "id": check_id,
        "status": PASS if ok else FAIL,
        "reason_code": A.OK_VERIFIED if ok else (reason or A.INTEGRITY_FAILURE),
        "detail": detail,
    }


def _artifact_rows(report: dict) -> list[dict]:
    rows = []
    for section in ("kev_records", "epss_records"):
        for record in report.get(section, []):
            if record.get("artifact_path"):
                rows.append(
                    {
                        "source": record.get("source"),
                        "key": record.get("key"),
                        "artifact_path": record["artifact_path"],
                        "sha256": record.get("sha256"),
                    }
                )
    return sorted(rows, key=lambda row: (row["source"] or "", row["key"] or ""))


def verify_report(
    report: dict,
    *,
    store_root: Optional[Path | str] = None,
    archive_manifest_path: Optional[Path | str] = None,
    archive_store_root: Optional[Path | str] = None,
) -> dict:
    checks: list[dict] = []

    schema_ok = (
        report.get("schema_version") == C.SCHEMA_VERSION
        and isinstance(report.get("maturity_gate"), list)
        and isinstance(report.get("requirements"), list)
    )
    checks.append(
        _check(
            "SCHEMA",
            schema_ok,
            "schema_version and required sections are present"
            if schema_ok
            else f"unexpected schema_version {report.get('schema_version')!r}",
            reason=A.MALFORMED_RESPONSE,
        )
    )

    digest_ok, recomputed = verify_digest(report)
    checks.append(
        _check(
            "REPORT_DIGEST",
            digest_ok,
            f"recorded {report.get('refresh_digest')}, recomputed {recomputed}",
            reason=A.SHA256_MISMATCH,
        )
    )

    as_of = str(report.get("as_of", ""))
    early = [
        gate.get("cutoff")
        for gate in report.get("maturity_gate", [])
        if gate.get("maturity_claimed") and str(gate.get("maturity_date")) > as_of
    ]
    checks.append(
        _check(
            "MATURITY_INVARIANT",
            not early,
            "no block claims maturity before its maturity date"
            if not early
            else "maturity claimed early for " + ", ".join(str(item) for item in early),
            reason=C.MATURITY_CLAIMED_EARLY,
        )
    )

    status_claimed = report.get("summary", {}).get("refresh_status")
    status_known = status_claimed in C.REFRESH_STATUSES
    checks.append(
        _check(
            "REFRESH_STATUS",
            status_known,
            f"refresh status {status_claimed!r}",
            reason=A.MALFORMED_RESPONSE,
        )
    )

    approval = report.get("protocol", {}).get("approval_state")
    authorized = bool(report.get("protocol", {}).get("protocol_execution_authorized"))
    checks.append(
        _check(
            "PROTOCOL_NOT_APPROVED",
            approval != "APPROVED" and not authorized,
            f"approval_state={approval}, protocol_execution_authorized={authorized}",
            reason=A.INTEGRITY_FAILURE,
        )
    )

    artifact_rows = _artifact_rows(report)
    hashed = 0
    if store_root is not None and artifact_rows:
        store = ArtifactStore(store_root)
        bad = []
        for row in artifact_rows:
            digest = store.digest(row["artifact_path"])
            if digest is None or digest.get("sha256") != row["sha256"]:
                bad.append(row["artifact_path"])
        hashed = len(artifact_rows)
        checks.append(
            _check(
                "REFRESH_ARTIFACTS",
                not bad,
                f"{len(artifact_rows)} refresh artifact(s) re-hashed; "
                + ("all match" if not bad else "mismatch: " + ", ".join(bad)),
                reason=A.SHA256_MISMATCH,
            )
        )
    else:
        checks.append(
            _check(
                "REFRESH_ARTIFACTS",
                True,
                "no refresh store supplied or no stored artifacts recorded",
            )
        )

    if archive_manifest_path is not None and archive_store_root is not None:
        try:
            manifest = read_json(archive_manifest_path)
        except Exception as exc:  # noqa: BLE001 - report, never raise
            checks.append(
                _check(
                    "SEALED_ARCHIVE",
                    False,
                    f"cannot read the sealed 1.7 manifest: {type(exc).__name__}",
                    reason=A.ARTIFACT_UNREADABLE,
                )
            )
        else:
            store = ArtifactStore(archive_store_root)
            rows = [
                record
                for record in manifest.get("records", [])
                if record.get("artifact_path")
            ]
            bad = []
            for record in rows:
                digest = store.digest(record["artifact_path"])
                if digest is None or digest.get("sha256") != record.get("sha256"):
                    bad.append(record["artifact_path"])
            checks.append(
                _check(
                    "SEALED_ARCHIVE",
                    not bad,
                    f"{len(rows)} sealed 1.7 artifact(s) re-hashed; "
                    + ("all match" if not bad else "mismatch: " + ", ".join(bad)),
                    reason=A.SHA256_MISMATCH,
                )
            )
    else:
        checks.append(
            _check(
                "SEALED_ARCHIVE",
                True,
                "no sealed archive paths supplied; archive guard not re-checked",
            )
        )

    status = A.VERIFIED if all(c["status"] == PASS for c in checks) else A.BLOCKED
    return {
        "schema_version": C.SCHEMA_VERSION,
        "status": status,
        "evidence_status": report.get("summary", {}).get("evidence_status", A.BLOCKED),
        "refresh_status": report.get("summary", {}).get("refresh_status"),
        "checks": checks,
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for c in checks if c["status"] == PASS),
            "failed": sum(1 for c in checks if c["status"] == FAIL),
            "artifacts_hashed": hashed,
            "network_used": False,
        },
    }


def verify_report_file(
    path: Path | str,
    *,
    store_root: Optional[Path | str] = None,
    archive_manifest_path: Optional[Path | str] = None,
    archive_store_root: Optional[Path | str] = None,
) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return verify_report(
        payload,
        store_root=store_root,
        archive_manifest_path=archive_manifest_path,
        archive_store_root=archive_store_root,
    )


__all__ = ["verify_report", "verify_report_file"]
