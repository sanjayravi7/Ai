"""Fetch commit-pinned authoritative CVE records for every disputed dataset row.

Phase 2.1 verified the 17 ``** REJECT **`` records. Phase 2.2 needs the same
treatment for the 455 ``** DISPUTED **`` records, but with two differences:

* disputed records are **not** placeholders, so the volume is much larger and a
  single unreachable record must not abort the run - it is recorded as
  ``present: false`` with a reason and re-reported by the audit as an
  unverifiable case; and
* GitHub's unauthenticated contents API allows 60 requests per hour, which
  cannot cover 455 records. This module therefore supports an optional token
  read from an environment variable at run time. The token is added to the
  request headers only: it is never written to a snapshot, a manifest, a log,
  or this repository.

The snapshot format, manifest schema, checksum rules and directory helpers are
the ones already used by ``src.fetch_cve_status``; only the source directory
differs (``data/external/raw/disputed/cve_status/``) so the Phase 2.1 snapshot is
never overwritten. Everything the audit reads is pinned to one commit SHA, and
each record is checked against the Git blob SHA reported by the contents API
before it is written.

Usage::

    # Normal run (needs network access to api.github.com)
    python -m src.fetch_disputed_status --input data/processed/vulnerabilities_clean.csv

    # Offline reproduction from already-downloaded record files
    python -m src.fetch_disputed_status --from-directory PATH \\
        --origin-url URL --commit-sha <40-hex-sha>
"""

import argparse
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from .cve_status_sources import (
    CVELISTV5_REPOSITORY,
    DEFAULT_API_BASE,
    CveStatusSchemaError,
    CveStatusValidationError,
    cvelistv5_api_url,
    has_disputed_marker,
    verify_supported_identifier,
)
from .fetch_cve_status import (
    DEFAULT_REF,
    PIPELINE_VERSION,
    _resolve_commit,
    fetch_record_bytes,
    find_reusable_status_snapshot,
    import_status_snapshot,
    write_status_snapshot,
)
from .fetch_threat_intelligence import (
    PROJECT_ROOT,
    SourceUnavailableError,
    utc_now,
)


#: Snapshot root for disputed-record evidence. The CVE status directory helpers
#: append ``cve_status``, so records land in
#: ``data/external/raw/disputed/cve_status/`` and never collide with Phase 2.1.
DEFAULT_DISPUTED_ROOT = PROJECT_ROOT / "data" / "external" / "raw" / "disputed"
DEFAULT_INPUT_PATH = PROJECT_ROOT / "data" / "processed" / "vulnerabilities_clean.csv"
TOKEN_ENVIRONMENTS = ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_API_TOKEN")
DEFAULT_WORKERS = 4
MAX_WORKERS = 16


class MissingTokenError(RuntimeError):
    """No GitHub API token was available and the run requires one."""


def disputed_cve_ids(dataset: pd.DataFrame, column: str = "summary") -> List[str]:
    """Return the sorted, normalized CVE ids of every ``** DISPUTED **`` row.

    The rule is the existing ``has_disputed_marker`` parser, so this set is
    exactly the set reported by Phase 2.1's ``disputed_cve_report.csv``.
    """
    if column not in dataset.columns:
        raise ValueError(f"Dataset must contain a '{column}' column to find disputed records.")
    if "cve_id" not in dataset.columns:
        raise ValueError("Dataset must contain a 'cve_id' column to find disputed records.")
    mask = dataset[column].map(has_disputed_marker)
    values = dataset.loc[mask, "cve_id"]
    identifiers = []
    for value in values:
        try:
            identifiers.append(verify_supported_identifier(value))
        except CveStatusValidationError:
            # A malformed identifier cannot be looked up; it stays in the
            # audit as an unverifiable row rather than being silently dropped.
            continue
    return sorted(set(identifiers))


def make_authorized_opener(token: str, base: Optional[Callable[..., Any]] = None) -> Callable[..., Any]:
    """Return a urlopen-compatible callable that adds an Authorization header.

    The token is captured in the closure for the lifetime of the process only.
    Snapshot files, manifests, and error messages never contain it.
    """
    opener = base or urllib.request.urlopen

    def authorized(request, *args, **kwargs):  # pragma: no cover - exercised via fakes
        request.add_header("Authorization", f"token {token}")
        request.add_header("Accept", "application/vnd.github+json")
        return opener(request, *args, **kwargs)

    return authorized


def token_from_environment(
    environments: Sequence[str] = TOKEN_ENVIRONMENTS,
    *,
    environ: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[str], str]:
    """Return ``(token, variable_name)`` for the first populated variable."""
    source = environ if environ is not None else os.environ
    for name in environments:
        value = source.get(name)
        if value and value.strip():
            return value.strip(), name
    return None, ""


def _failure_reason(error: BaseException) -> str:
    """Return a token-free, deterministic reason string for one failure."""
    message = str(error)
    if isinstance(error, SourceUnavailableError):
        if "HTTP 404" in message:
            return "http_404_not_found"
        return f"source_unavailable:{message.split(';')[0][:120]}"
    if isinstance(error, CveStatusSchemaError):
        return f"schema_error:{message[:120]}"
    if isinstance(error, CveStatusValidationError):
        return f"validation_error:{message[:120]}"
    if isinstance(error, (OSError, TimeoutError)):
        return f"transport_error:{type(error).__name__}"
    return f"unexpected_error:{type(error).__name__}"


def _fetch_one(
    cve_id: str,
    *,
    repository: str,
    ref: str,
    api_base: str,
    opener: Optional[Callable[..., Any]],
    sleep: Callable[[float], None],
) -> Tuple[str, Optional[bytes], Dict[str, Any]]:
    """Fetch a single record, converting any failure into recorded metadata."""
    url = cvelistv5_api_url(cve_id, repository=repository, ref=ref, api_base=api_base)
    try:
        content, metadata = fetch_record_bytes(
            cve_id,
            repository=repository,
            ref=ref,
            api_base=api_base,
            opener=opener,
            sleep=sleep,
        )
    except (SourceUnavailableError, CveStatusSchemaError, CveStatusValidationError, OSError, ValueError) as error:
        return cve_id, None, {"present": False, "url": url, "reason": _failure_reason(error)}
    if content is None:
        metadata.setdefault("url", url)
        metadata.setdefault("reason", "http_404_not_found")
        metadata["present"] = False
        return cve_id, None, metadata
    metadata.setdefault("url", url)
    return cve_id, content, metadata


def fetch_disputed_snapshot(
    cve_ids: Sequence[str],
    *,
    repository: str = CVELISTV5_REPOSITORY,
    requested_ref: str = DEFAULT_REF,
    commit_sha: Optional[str] = None,
    api_base: str = DEFAULT_API_BASE,
    root: Path = DEFAULT_DISPUTED_ROOT,
    token: Optional[str] = None,
    workers: int = 1,
    opener: Optional[Callable[..., Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Optional[datetime] = None,
    request_delay: float = 0.0,
    reuse: bool = False,
) -> Dict[str, Any]:
    """Download, verify and snapshot authoritative records for ``cve_ids``.

    Every request is pinned to a single commit SHA (resolved from
    ``requested_ref`` unless ``commit_sha`` is supplied). Failures are recorded
    per identifier instead of aborting, so a partial snapshot is still an
    auditable, checksum-verified artifact and the audit can disclose exactly
    which identifiers could not be verified.

    Returns the snapshot manifest (also written next to the record files).
    """
    identifiers = sorted({str(value).strip().upper() for value in cve_ids if str(value).strip()})
    if not identifiers:
        raise CveStatusValidationError("No CVE identifiers were supplied to fetch.")
    if workers < 1 or workers > MAX_WORKERS:
        raise CveStatusValidationError(f"--workers must be between 1 and {MAX_WORKERS}.")

    authorized = opener if opener is not None else (make_authorized_opener(token) if token else None)

    resolved = commit_sha or _resolve_commit(
        repository, requested_ref, api_base=api_base, opener=authorized, sleep=sleep
    )
    if len(str(resolved)) != 40:
        raise CveStatusValidationError(f"Resolved commit is not a full 40-character SHA: {resolved!r}")

    if reuse:
        cached = find_reusable_status_snapshot(commit_sha=resolved, repository=repository, root=root)
        if cached is not None:
            cached["_reused_cached_snapshot"] = True
            return cached

    records: Dict[str, bytes] = {}
    metadata: Dict[str, Dict[str, Any]] = {}
    missing: List[str] = []

    def work(cve_id: str) -> Tuple[str, Optional[bytes], Dict[str, Any]]:
        result = _fetch_one(
            cve_id, repository=repository, ref=resolved, api_base=api_base, opener=authorized, sleep=sleep
        )
        if request_delay:
            sleep(request_delay)
        return result

    if workers == 1:
        results = [work(cve_id) for cve_id in identifiers]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(work, identifiers))

    for cve_id, content, entry in sorted(results, key=lambda item: item[0]):
        metadata[cve_id] = entry
        if content is None:
            missing.append(cve_id)
            continue
        records[cve_id] = content

    manifest = write_status_snapshot(
        records,
        repository=repository,
        requested_ref=requested_ref,
        commit_sha=resolved,
        retrieval_method="https_download",
        root=root,
        api_base=api_base,
        retrieved_utc=now or utc_now(),
        missing=missing,
        record_metadata=metadata,
    )
    manifest["requested_record_count"] = len(identifiers)
    manifest["authenticated"] = bool(token)
    manifest["pipeline_version"] = PIPELINE_VERSION
    manifest["failed_records"] = {
        cve_id: metadata[cve_id].get("reason", "") for cve_id in sorted(missing)
    }
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch authoritative CVEProgram/cvelistV5 records for every '** DISPUTED **' "
            "dataset row (GitHub contents API, commit-pinned) and snapshot them."
        )
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_PATH,
                        help=f"CSV with cve_id/summary columns (default: {DEFAULT_INPUT_PATH.name}).")
    parser.add_argument("--cve-id", action="append", default=[], help="Fetch this CVE id (repeatable).")
    parser.add_argument("--cve-ids-file", type=Path, help="Text file with one CVE id per line.")
    parser.add_argument("--repository", default=CVELISTV5_REPOSITORY)
    parser.add_argument("--ref", default=DEFAULT_REF, help=f"Branch, tag or commit (default: {DEFAULT_REF}).")
    parser.add_argument("--commit-sha", default="", help="Pin to this commit instead of resolving --ref.")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_DISPUTED_ROOT)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Parallel requests (1-{MAX_WORKERS}; default {DEFAULT_WORKERS}).")
    parser.add_argument("--request-delay", type=float, default=0.0,
                        help="Seconds to wait after each request (politeness / rate limiting).")
    parser.add_argument("--refresh", action="store_true",
                        help="Download again even when a verified snapshot for this commit exists.")
    parser.add_argument("--token-env", default=TOKEN_ENVIRONMENTS[0],
                        help="Environment variable holding a GitHub API token (never written to disk).")
    parser.add_argument("--allow-missing-token", action="store_true",
                        help="Continue unauthenticated (GitHub allows 60 requests/hour).")
    parser.add_argument("--from-directory", type=Path,
                        help="Import local CVE-*.json files instead of downloading.")
    parser.add_argument("--origin-url", help="URL the local records were obtained from.")
    args = parser.parse_args(argv)

    identifiers = list(args.cve_id)
    if args.cve_ids_file:
        identifiers += [
            line.strip()
            for line in Path(args.cve_ids_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    if not identifiers and not args.from_directory:
        if not Path(args.input).is_file():
            parser.error(f"--input not found: {args.input}")
        dataset = pd.read_csv(args.input, dtype=str, keep_default_na=False)
        identifiers = disputed_cve_ids(dataset)
        if not identifiers:
            parser.error(f"No '** DISPUTED **' records found in {args.input}")

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
            token, variable = token_from_environment([args.token_env])
            if token is None and not args.allow_missing_token:
                print(
                    f"ERROR: no token found in {args.token_env!r}. Export one (e.g. `gh auth token`) or pass "
                    "--allow-missing-token to use the unauthenticated 60-request/hour limit.",
                    file=sys.stderr,
                )
                return 2
            if token is None:
                print(
                    f"[disputed_status] warning: no token in {args.token_env!r}; "
                    "unauthenticated requests are limited to 60 per hour.",
                    file=sys.stderr,
                )
            manifest = fetch_disputed_snapshot(
                identifiers,
                repository=args.repository,
                requested_ref=args.ref,
                commit_sha=args.commit_sha or None,
                api_base=args.api_base,
                root=args.snapshot_root,
                token=token,
                workers=args.workers,
                request_delay=args.request_delay,
                reuse=not args.refresh,
            )
    except (SourceUnavailableError, CveStatusSchemaError, CveStatusValidationError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    reused = " (reused verified snapshot for this commit)" if manifest.get("_reused_cached_snapshot") else ""
    print(
        f"[disputed_status] snapshot {manifest['snapshot_date']} commit={manifest['commit_sha'][:12]} "
        f"records={manifest['record_count']} missing={manifest['missing_count']} "
        f"method={manifest['retrieval_method']}{reused}"
    )
    print(f"[disputed_status] manifest: {manifest['_manifest_path']}")
    failed = manifest.get("failed_records") or {}
    if failed:
        print(f"[disputed_status] {len(failed)} identifier(s) could not be verified:")
        for cve_id, reason in list(failed.items())[:20]:
            print(f"  - {cve_id}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
