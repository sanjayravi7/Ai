"""Fetch and snapshot authoritative CVE status records for dataset auditing.

Source: the official CVE Program repository ``CVEProject/cvelistV5`` (CVE
Services 5.x records). Each record is fetched through the GitHub contents API
at a pinned commit, decoded, and integrity-checked with the repository's own Git
blob SHA before anything is written. A payload that fails validation is never
written, so a malformed response cannot silently become the cached snapshot.

Snapshots are written under ``data/external/raw/cve_status/`` as the verbatim
record files plus one JSON manifest that records the repository, the resolved
commit SHA, the requested URLs, the UTC retrieval time (the audit's verification
date), per-record SHA-256 and Git blob SHA values, and the normalized status
metadata used by the audit. Files are named by CVE id and commit, so a snapshot
is never overwritten by a different commit.

Offline import is supported for reproducing the audit without network access:
``--from-directory`` reads a local directory of ``CVE-*.json`` files (for
example a partial checkout of ``cves/``), and ``--record-file`` accepts
individual files.

Usage::

    python -m src.fetch_cve_status --input data/processed/vulnerabilities_clean.csv
    python -m src.fetch_cve_status --cve-id CVE-2007-3004 --cve-id CVE-2017-9410
    python -m src.fetch_cve_status --from-directory PATH --origin-url URL
"""

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from .cve_status_sources import (
    CVE_STATUS_SOURCE,
    CVELISTV5_REPOSITORY,
    DEFAULT_API_BASE,
    SNAPSHOT_SCHEMA,
    CveRecord,
    CveStatusSchemaError,
    CveStatusValidationError,
    cvelistv5_api_url,
    cvelistv5_blob_url,
    cvelistv5_record_path,
    is_reject_placeholder,
    parse_cve_record,
    verify_supported_identifier,
)
from .fetch_threat_intelligence import (
    DEFAULT_SNAPSHOT_ROOT,
    SourceUnavailableError,
    download_bytes,
    sha256_bytes,
    sha256_file,
    utc_now,
)


PIPELINE_VERSION = "vulnova-cve-status-1"
DEFAULT_REF = "main"
MAX_RECORD_BYTES = 5 * 1024 * 1024
MISSING_REFERENCED_RECORDS = "not_found"


class MissingStatusSnapshotError(RuntimeError):
    """No CVE status snapshot is available for the audit."""


def git_blob_sha(content: bytes) -> str:
    """Return Git's content-addressed blob SHA-1 for ``content``."""
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def _iso(stamp: datetime) -> str:
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_snapshot_directory(root: Path = DEFAULT_SNAPSHOT_ROOT) -> Path:
    return Path(root) / CVE_STATUS_SOURCE


def _resolve_commit(
    repository: str,
    ref: str,
    *,
    api_base: str,
    opener: Optional[Callable[..., Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Resolve a branch/tag/commit reference to a full commit SHA."""
    if len(str(ref)) == 40 and all(character in "0123456789abcdefABCDEF" for character in str(ref)):
        return str(ref).lower()
    url = f"{api_base.rstrip('/')}/repos/{repository}/commits/{ref}"
    result = download_bytes(url, max_bytes=MAX_RECORD_BYTES, opener=opener, sleep=sleep)
    try:
        document = json.loads(result.content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CveStatusSchemaError(f"Cannot resolve {repository}@{ref}: {error}") from error
    sha = str(document.get("sha", ""))
    if len(sha) != 40:
        raise CveStatusValidationError(
            f"Cannot resolve {repository}@{ref}: response lacks a commit 'sha'."
        )
    return sha


def fetch_record_bytes(
    cve_id: str,
    *,
    repository: str,
    ref: str,
    api_base: str,
    opener: Optional[Callable[..., Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """Fetch one raw CVE record; return ``(content, metadata)``.

    A missing record (HTTP 404) returns ``(None, metadata)`` with
    ``"present": False`` so the caller can record it as unverified rather than
    guessing a status. Any other failure raises ``SourceUnavailableError``.
    """
    url = cvelistv5_api_url(cve_id, repository=repository, ref=ref, api_base=api_base)
    try:
        result = download_bytes(url, max_bytes=MAX_RECORD_BYTES, opener=opener, sleep=sleep)
    except SourceUnavailableError as error:
        if "HTTP 404" in str(error):
            return None, {"present": False, "url": url, "reason": "http_404_not_found"}
        raise
    try:
        document = json.loads(result.content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CveStatusSchemaError(f"{cve_id}: contents API response is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise CveStatusSchemaError(f"{cve_id}: contents API response must be a JSON object.")
    encoding = str(document.get("encoding", ""))
    encoded = document.get("content")
    if encoding != "base64" or not encoded:
        raise CveStatusSchemaError(
            f"{cve_id}: contents API returned encoding={encoding!r} with no inline content "
            "(GitHub inlines files up to 1 MB; use --from-directory for larger records)."
        )
    content = base64.b64decode(encoded)
    blob_sha = str(document.get("sha", ""))
    computed = git_blob_sha(content)
    if blob_sha and computed != blob_sha:
        raise CveStatusValidationError(
            f"{cve_id}: Git blob SHA mismatch (repository={blob_sha}, decoded={computed}); "
            "the response is not the record at that path."
        )
    return content, {
        "present": True,
        "url": url,
        "repository_path": str(document.get("path", cvelistv5_record_path(cve_id))),
        "git_blob_sha": blob_sha or computed,
        "bytes": len(content),
        "html_url": str(document.get("html_url", "")),
    }


def write_status_snapshot(
    records: Dict[str, bytes],
    *,
    repository: str = CVELISTV5_REPOSITORY,
    requested_ref: str = DEFAULT_REF,
    commit_sha: str,
    retrieval_method: str,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    api_base: str = DEFAULT_API_BASE,
    retrieved_utc: Optional[datetime] = None,
    origin_url: Optional[str] = None,
    missing: Optional[Sequence[str]] = None,
    record_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Validate and write a CVE status snapshot; return its manifest.

    Every record must parse as a CVE 5.x record whose identifier matches its
    filename key, so a mismatched or malformed payload cannot be written.
    """
    if not commit_sha:
        raise CveStatusValidationError("A resolved commit SHA is required to write a snapshot.")
    retrieved = retrieved_utc or utc_now()
    directory = status_snapshot_directory(root)
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{CVE_STATUS_SOURCE}-{retrieved.date().isoformat()}-{commit_sha[:12]}"

    manifest_records: Dict[str, Dict[str, Any]] = {}
    parsed: Dict[str, CveRecord] = {}
    for cve_id, content in sorted(records.items()):
        normalized = verify_supported_identifier(cve_id)
        if not isinstance(content, (bytes, bytearray)):
            raise CveStatusValidationError(f"{normalized}: record payload must be bytes.")
        record = parse_cve_record(bytes(content), expected_cve_id=normalized)
        parsed[normalized] = record
        metadata = dict((record_metadata or {}).get(normalized, {}))
        metadata.setdefault("url", cvelistv5_api_url(normalized, repository=repository, ref=commit_sha, api_base=api_base))
        metadata.setdefault("html_url", cvelistv5_blob_url(normalized, repository=repository, ref=commit_sha))
        payload = bytes(content)
        manifest_records[normalized] = {
            "file": f"record-{normalized}-{commit_sha[:12]}.json",
            "sha256": sha256_bytes(payload),
            "git_blob_sha": git_blob_sha(payload),
            "bytes": len(payload),
            "state": record.state,
            "record_id": record.cve_id,
            "date_rejected": record.date_rejected,
            "date_updated": record.date_updated,
            "date_published": record.date_published,
            "assigner_short_name": record.assigner_short_name,
            "consult_ids": list(record.consult_ids),
            "present": True,
            **metadata,
        }

    for missing_id in sorted(set(missing or ())):
        normalized = verify_supported_identifier(missing_id)
        manifest_records[normalized] = {
            "file": None,
            "sha256": None,
            "bytes": 0,
            "state": "",
            "record_id": normalized,
            "present": False,
            "reason": record_metadata.get(normalized, {}).get("reason", MISSING_REFERENCED_RECORDS)
            if record_metadata
            else MISSING_REFERENCED_RECORDS,
            "url": (record_metadata or {}).get(normalized, {}).get(
                "url",
                cvelistv5_api_url(normalized, repository=repository, ref=commit_sha, api_base=api_base),
            ),
            "html_url": cvelistv5_blob_url(normalized, repository=repository, ref=commit_sha),
        }

    for cve_id, entry in manifest_records.items():
        if not entry["present"]:
            continue
        data_path = directory / entry["file"]
        payload = records[cve_id]
        if data_path.exists() and sha256_file(data_path) != entry["sha256"]:
            raise CveStatusValidationError(f"Refusing to overwrite differing snapshot {data_path}")
        if not data_path.exists():
            data_path.write_bytes(payload)

    manifest = {
        "pipeline_version": PIPELINE_VERSION,
        "schema": SNAPSHOT_SCHEMA,
        "source": CVE_STATUS_SOURCE,
        "source_name": "CVE Program (cvelistV5)",
        "repository": repository,
        "requested_ref": requested_ref,
        "commit_sha": commit_sha,
        "api_base": api_base,
        "retrieval_method": retrieval_method,
        "declared_origin": origin_url,
        "retrieved_utc": _iso(retrieved),
        "snapshot_date": retrieved.date().isoformat(),
        "record_count": sum(1 for entry in manifest_records.values() if entry["present"]),
        "missing_count": sum(1 for entry in manifest_records.values() if not entry["present"]),
        "records": manifest_records,
    }
    manifest_path = directory / f"{stem}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    manifest["_manifest_path"] = str(manifest_path)
    return manifest


def fetch_status_snapshot(
    cve_ids: Sequence[str],
    *,
    repository: str = CVELISTV5_REPOSITORY,
    ref: str = DEFAULT_REF,
    api_base: str = DEFAULT_API_BASE,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    refresh: bool = False,
    opener: Optional[Callable[..., Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Download and snapshot authoritative records for ``cve_ids``.

    The requested reference is resolved to a full commit SHA and every URL is
    pinned to it. When a snapshot for the same commit already exists and
    ``refresh`` is false, it is reused without another download.
    """
    identifiers = sorted({verify_supported_identifier(cve_id) for cve_id in cve_ids})
    if not identifiers:
        raise CveStatusValidationError("No CVE identifiers were supplied to fetch.")

    commit_sha = _resolve_commit(repository, ref, api_base=api_base, opener=opener, sleep=sleep)
    if not refresh:
        reusable = find_reusable_status_snapshot(commit_sha=commit_sha, repository=repository, root=root)
        if reusable is not None:
            reusable["_reused_cached_snapshot"] = True
            return reusable

    records: Dict[str, bytes] = {}
    metadata: Dict[str, Dict[str, Any]] = {}
    missing: List[str] = []
    for cve_id in identifiers:
        content, record_meta = fetch_record_bytes(
            cve_id, repository=repository, ref=commit_sha, api_base=api_base,
            opener=opener, sleep=sleep,
        )
        metadata[cve_id] = record_meta
        if content is None:
            missing.append(cve_id)
            continue
        records[cve_id] = content

    return write_status_snapshot(
        records,
        repository=repository,
        requested_ref=ref,
        commit_sha=commit_sha,
        retrieval_method="https_download",
        root=root,
        api_base=api_base,
        retrieved_utc=now or utc_now(),
        missing=missing,
        record_metadata=metadata,
    )


def import_status_snapshot(
    paths: Sequence[Path],
    *,
    repository: str = CVELISTV5_REPOSITORY,
    ref: str = "local",
    commit_sha: str,
    origin_url: str,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Snapshot locally obtained CVE records (offline reproduction)."""
    records: Dict[str, bytes] = {}
    metadata: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        path = Path(path)
        if not path.is_file():
            raise SourceUnavailableError(f"Local CVE record not found: {path}")
        payload = path.read_bytes()
        record = parse_cve_record(payload)
        records[record.cve_id] = payload
        metadata[record.cve_id] = {
            "url": f"{origin_url.rstrip('/')}/{path.name}",
            "html_url": "",
            "reason": "local_import",
        }
    if not records:
        raise SourceUnavailableError("No CVE record files were found to import.")
    return write_status_snapshot(
        records,
        repository=repository,
        requested_ref=ref,
        commit_sha=commit_sha,
        retrieval_method="local_import",
        root=root,
        retrieved_utc=now or utc_now(),
        origin_url=origin_url,
        record_metadata=metadata,
    )


def list_status_manifests(root: Path = DEFAULT_SNAPSHOT_ROOT) -> List[Dict[str, Any]]:
    """Return every CVE status manifest, oldest snapshot first."""
    directory = status_snapshot_directory(root)
    if not directory.is_dir():
        return []
    manifests = []
    for path in sorted(directory.glob("*.manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["_manifest_path"] = str(path)
        manifests.append(manifest)
    manifests.sort(
        key=lambda item: (
            item.get("snapshot_date", ""),
            item.get("retrieved_utc", ""),
            item.get("commit_sha", ""),
        )
    )
    return manifests


def find_reusable_status_snapshot(
    *,
    commit_sha: str,
    repository: str = CVELISTV5_REPOSITORY,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
) -> Optional[Dict[str, Any]]:
    """Return an existing verified snapshot for the same repository commit."""
    for manifest in reversed(list_status_manifests(root)):
        if manifest.get("commit_sha") != commit_sha or manifest.get("repository") != repository:
            continue
        try:
            load_status_snapshot(manifest)
        except (SourceUnavailableError, CveStatusSchemaError, CveStatusValidationError):
            continue
        return manifest
    return None


def load_status_snapshot(
    manifest: Dict[str, Any],
) -> Dict[str, Tuple[CveRecord, str]]:
    """Checksum-verify and re-parse every record of a snapshot.

    Returns:
        Mapping of CVE id to ``(record, sha256)``. Records listed in the
        manifest as absent are omitted; the caller reports them as unverified.

    Raises:
        CveStatusValidationError: A file is missing, changed on disk, or no
            longer matches the state recorded in the manifest.
    """
    manifest_path = Path(manifest["_manifest_path"])
    directory = manifest_path.parent
    loaded: Dict[str, Tuple[CveRecord, str]] = {}
    for cve_id, entry in sorted(manifest.get("records", {}).items()):
        if not entry.get("present"):
            continue
        data_path = directory / str(entry["file"])
        if not data_path.is_file():
            raise CveStatusValidationError(f"Snapshot record is missing: {data_path}")
        actual = sha256_file(data_path)
        if actual != entry["sha256"]:
            raise CveStatusValidationError(
                f"Snapshot checksum mismatch for {data_path}: "
                f"manifest={entry['sha256']} actual={actual}"
            )
        record = parse_cve_record(data_path.read_bytes(), expected_cve_id=cve_id)
        if entry.get("state") and record.state != entry["state"]:
            raise CveStatusValidationError(
                f"{cve_id}: snapshot state {record.state!r} differs from manifest {entry['state']!r}"
            )
        loaded[cve_id] = (record, actual)
    return loaded


def select_status_manifest(
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    explicit: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Return the explicit manifest, or the newest snapshot for the source."""
    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            raise MissingStatusSnapshotError(f"CVE status manifest not found: {path}")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["_manifest_path"] = str(path)
        return manifest
    manifests = list_status_manifests(root)
    return manifests[-1] if manifests else None


def placeholder_cve_ids(dataset: pd.DataFrame, column: str = "summary") -> List[str]:
    """Return the sorted CVE ids whose dataset summary starts with the marker."""
    if column not in dataset.columns:
        return []
    mask = dataset[column].map(is_reject_placeholder)
    if not bool(mask.any()):
        return []
    values = dataset.loc[mask, "cve_id"]
    return sorted({verify_supported_identifier(value) for value in values})


def _read_placeholder_ids(path: Path) -> List[str]:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "cve_id" not in frame.columns or "summary" not in frame.columns:
        raise ValueError(f"{path} must contain 'cve_id' and 'summary' columns.")
    return placeholder_cve_ids(frame)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch authoritative CVE status records from CVEProject/cvelistV5 "
            "(GitHub contents API, commit-pinned) and snapshot them."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="CSV with cve_id/summary columns (default: data/processed/vulnerabilities_clean.csv).",
    )
    parser.add_argument("--cve-id", action="append", default=[], help="Fetch this CVE id (repeatable).")
    parser.add_argument("--cve-ids-file", type=Path, help="Text file with one CVE id per line.")
    parser.add_argument("--repository", default=CVELISTV5_REPOSITORY)
    parser.add_argument("--ref", default=DEFAULT_REF, help=f"Branch, tag, or commit (default: {DEFAULT_REF}).")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--refresh", action="store_true", help="Fetch again even if a snapshot for this commit exists.")
    parser.add_argument(
        "--from-directory",
        type=Path,
        help="Import local CVE-*.json record files from this directory instead of downloading.",
    )
    parser.add_argument("--origin-url", help="URL the local records were obtained from (required with --from-directory).")
    parser.add_argument(
        "--commit-sha",
        default="",
        help="Commit SHA the local records correspond to (required with --from-directory).",
    )
    args = parser.parse_args(argv)

    if args.input and not Path(args.input).is_file():
        parser.error(f"--input not found: {args.input}")

    identifiers = list(args.cve_id)
    if args.cve_ids_file:
        identifiers += [
            line.strip()
            for line in Path(args.cve_ids_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    if args.input:
        identifiers += _read_placeholder_ids(Path(args.input))
    elif not identifiers and not args.from_directory:
        default_input = Path("data/processed/vulnerabilities_clean.csv")
        if not default_input.is_file():
            parser.error(
                "Provide --input, --cve-id/--cve-ids-file, or --from-directory "
                f"(default input not found: {default_input})."
            )
        identifiers += _read_placeholder_ids(default_input)

    try:
        if args.from_directory:
            if not args.origin_url or not args.commit_sha:
                parser.error("--from-directory requires --origin-url and --commit-sha")
            paths = sorted(Path(args.from_directory).glob("CVE-*.json"))
            manifest = import_status_snapshot(
                paths,
                repository=args.repository,
                ref=args.ref,
                commit_sha=args.commit_sha,
                origin_url=args.origin_url,
                root=args.snapshot_root,
            )
        else:
            manifest = fetch_status_snapshot(
                identifiers,
                repository=args.repository,
                ref=args.ref,
                api_base=args.api_base,
                root=args.snapshot_root,
                refresh=args.refresh,
            )
    except (SourceUnavailableError, CveStatusSchemaError, CveStatusValidationError, OSError, ValueError) as error:
        print(f"ERROR: {error}")
        return 1

    reused = " (reused cached snapshot)" if manifest.get("_reused_cached_snapshot") else ""
    print(
        f"[cve_status] snapshot {manifest['snapshot_date']} commit={manifest['commit_sha'][:12]} "
        f"records={manifest['record_count']} missing={manifest['missing_count']} "
        f"method={manifest['retrieval_method']}{reused}"
    )
    print(f"[cve_status] manifest: {manifest['_manifest_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
