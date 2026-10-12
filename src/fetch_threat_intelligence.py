"""Download, validate, and snapshot official threat-intelligence sources.

Sources (official endpoints are the defaults):

* CISA KEV catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
* FIRST EPSS daily bulk CSV: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz

Each successful retrieval is validated first and only then written to
``data/external/raw/<source>/`` as an immutable, checksum-named file plus a JSON
manifest recording the UTC retrieval time, requested and final URLs, SHA-256,
byte size, snapshot date, and version metadata. A payload that fails validation
is never written, so a broken source cannot silently become the cached snapshot.

Snapshots already on disk are reused when they were retrieved within
``--max-age-hours`` from the same URL; ``--refresh`` forces a new download.
Offline/local import of an already-obtained file is supported with
``--kev-file``/``--epss-file`` and records its declared origin in the manifest.

Usage::

    python -m src.fetch_threat_intelligence --source all
    python -m src.fetch_threat_intelligence --source kev --refresh
"""

import argparse
import hashlib
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .threat_intel_sources import EPSS_SOURCE, KEV_SOURCE, PARSERS, ParsedSnapshot
from .threat_intel_sources import SourceSchemaError, SourceValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT_ROOT = PROJECT_ROOT / "data" / "external" / "raw"

OFFICIAL_URLS = {
    KEV_SOURCE: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    EPSS_SOURCE: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}
SNAPSHOT_EXTENSIONS = {KEV_SOURCE: "json", EPSS_SOURCE: "csv.gz"}  # default; see _extension_for
MAX_PAYLOAD_BYTES = {KEV_SOURCE: 100 * 1024 * 1024, EPSS_SOURCE: 200 * 1024 * 1024}
USER_AGENT = "VULNOVA-threat-intel-ingest/1.0 (research; +https://github.com/sanjayravi7/Ai)"
PIPELINE_VERSION = "vulnova-threat-intel-1"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 2.0
DEFAULT_MAX_AGE_HOURS = 24.0
_CHUNK_SIZE = 64 * 1024
_RETRYABLE_HTTP = {429, 500, 502, 503, 504}


class SourceUnavailableError(RuntimeError):
    """A source could not be retrieved after the configured retries."""


@dataclass
class DownloadResult:
    content: bytes
    requested_url: str
    final_url: str
    http_status: int
    attempts: int


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    opener: Optional[Callable[..., Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> DownloadResult:
    """Fetch ``url`` over HTTPS with bounded retries and a size limit.

    Transient failures (timeouts, connection errors, HTTP 429/5xx) are retried
    with exponential backoff. Other HTTP errors fail immediately. Redirects that
    leave HTTPS are refused. ``opener`` and ``sleep`` are injectable for tests.
    """
    if not url.lower().startswith("https://"):
        raise ValueError(f"Refusing non-HTTPS source URL: {url}")
    open_url = opener or urllib.request.urlopen
    last_error: Optional[BaseException] = None
    attempts = 0
    for attempt in range(1, retries + 2):
        attempts = attempt
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"},
        )
        try:
            with open_url(request, timeout=timeout) as response:
                final_url = response.geturl() if hasattr(response, "geturl") else url
                if not str(final_url).lower().startswith("https://"):
                    raise SourceUnavailableError(
                        f"Redirect from {url} ended at non-HTTPS URL {final_url}; refusing."
                    )
                status = getattr(response, "status", None) or response.getcode()
                chunks = []
                total = 0
                while True:
                    chunk = response.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise SourceValidationError(
                            f"Payload from {url} exceeds the {max_bytes:,}-byte safety limit."
                        )
                    chunks.append(chunk)
                content = b"".join(chunks)
            if not content:
                raise SourceUnavailableError(f"Empty response body from {url}.")
            return DownloadResult(content, url, str(final_url), int(status), attempts)
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code not in _RETRYABLE_HTTP:
                raise SourceUnavailableError(
                    f"HTTP {error.code} {error.reason} from {url}; not retrying."
                ) from error
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as error:
            last_error = error
        if attempt <= retries:
            sleep(backoff_seconds * (2 ** (attempt - 1)))
    raise SourceUnavailableError(
        f"Could not retrieve {url} after {attempts} attempt(s): {last_error}. "
        "Check network access to the official host; no snapshot was written."
    )


def _iso(stamp: datetime) -> str:
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_retrieval(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def snapshot_directory(source: str, root: Path = DEFAULT_SNAPSHOT_ROOT) -> Path:
    return Path(root) / source


def list_manifests(source: str, root: Path = DEFAULT_SNAPSHOT_ROOT) -> List[Dict[str, Any]]:
    """Return every manifest for ``source``, oldest snapshot first."""
    directory = snapshot_directory(source, root)
    if not directory.is_dir():
        return []
    manifests = []
    for path in sorted(directory.glob("*.manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["_manifest_path"] = str(path)
        manifests.append(manifest)
    manifests.sort(key=lambda m: (m["snapshot_date"], m["retrieved_utc"], m["sha256"]))
    return manifests


def verify_snapshot(manifest: Dict[str, Any]) -> Path:
    """Return the snapshot file path after confirming its SHA-256 matches."""
    path = Path(manifest["_manifest_path"]).parent / manifest["file"]
    if not path.is_file():
        raise SourceUnavailableError(f"Snapshot file is missing: {path}")
    actual = sha256_file(path)
    if actual != manifest["sha256"]:
        raise SourceValidationError(
            f"Snapshot checksum mismatch for {path}: manifest={manifest['sha256']} actual={actual}"
        )
    return path


def find_reusable_snapshot(
    source: str,
    url: str,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    now: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """Return the newest verified snapshot from ``url`` younger than the limit."""
    current = now or utc_now()
    candidates = [
        manifest
        for manifest in list_manifests(source, root)
        if manifest.get("requested_url") == url and manifest.get("retrieval_method") == "https_download"
    ]
    for manifest in reversed(candidates):
        retrieved = _parse_retrieval(manifest["retrieved_utc"])
        if retrieved is None or current - retrieved > timedelta(hours=max_age_hours):
            continue
        try:
            verify_snapshot(manifest)
        except (SourceUnavailableError, SourceValidationError):
            continue
        return manifest
    return None


def _extension_for(source: str, payload: bytes) -> str:
    """Name a payload by its actual encoding (gzip magic bytes), not by assumption."""
    if source == EPSS_SOURCE:
        return "csv.gz" if payload[:2] == b"\x1f\x8b" else "csv"
    return SNAPSHOT_EXTENSIONS[source]


def _write_snapshot(
    source: str,
    parsed: ParsedSnapshot,
    payload: bytes,
    root: Path,
    *,
    requested_url: str,
    final_url: str,
    http_status: Optional[int],
    retrieval_method: str,
    retrieved: datetime,
    declared_origin: Optional[str] = None,
) -> Dict[str, Any]:
    digest = sha256_bytes(payload)
    directory = snapshot_directory(source, root)
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{source}-{parsed.metadata['snapshot_date']}-{digest[:12]}"
    extension = _extension_for(source, payload)
    data_path = directory / f"{stem}.{extension}"
    manifest_path = directory / f"{stem}.manifest.json"

    if data_path.exists() and sha256_file(data_path) != digest:
        raise SourceValidationError(f"Refusing to overwrite differing snapshot {data_path}")
    if not data_path.exists():
        data_path.write_bytes(payload)

    manifest = {
        "pipeline_version": PIPELINE_VERSION,
        "source": source,
        "requested_url": requested_url,
        "final_url": final_url,
        "declared_origin": declared_origin,
        "retrieval_method": retrieval_method,
        "http_status": http_status,
        "retrieved_utc": _iso(retrieved),
        "snapshot_date": parsed.metadata["snapshot_date"],
        "file": data_path.name,
        "sha256": digest,
        "bytes": len(payload),
        "metadata": parsed.metadata,
        "validation_findings": parsed.findings,
        "row_count": int(len(parsed.frame)),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    manifest["_manifest_path"] = str(manifest_path)
    return manifest


def fetch_source(
    source: str,
    *,
    url: Optional[str] = None,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    refresh: bool = False,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    opener: Optional[Callable[..., Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Return a validated snapshot manifest for ``source``, downloading if needed."""
    if source not in PARSERS:
        raise ValueError(f"Unknown source {source!r}; expected one of {sorted(PARSERS)}.")
    requested = url or OFFICIAL_URLS[source]
    if not refresh:
        reusable = find_reusable_snapshot(source, requested, root, max_age_hours, now=now)
        if reusable is not None:
            reusable["_reused_cached_snapshot"] = True
            return reusable

    result = download_bytes(
        requested,
        max_bytes=MAX_PAYLOAD_BYTES[source],
        opener=opener,
        sleep=sleep,
    )
    retrieved = now or utc_now()
    parsed = _parse_or_explain(source, result.content, requested)
    return _write_snapshot(
        source,
        parsed,
        result.content,
        root,
        requested_url=requested,
        final_url=result.final_url,
        http_status=result.http_status,
        retrieval_method="https_download",
        retrieved=retrieved,
    )


def import_local_snapshot(
    source: str,
    path: Path,
    *,
    origin_url: str,
    root: Path = DEFAULT_SNAPSHOT_ROOT,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Validate and snapshot a local copy of an official file.

    ``origin_url`` records where the file was obtained (for example a verified
    official mirror). It is stored as ``declared_origin``; it is not treated as a
    retrieval by this process.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Local {source} file not found: {path}")
    payload = path.read_bytes()
    parsed = _parse_or_explain(source, payload, str(path))
    return _write_snapshot(
        source,
        parsed,
        payload,
        root,
        requested_url=origin_url,
        final_url=origin_url,
        http_status=None,
        retrieval_method="local_import",
        retrieved=now or utc_now(),
        declared_origin=origin_url,
    )


def _parse_or_explain(source: str, payload: bytes, location: str) -> ParsedSnapshot:
    try:
        return PARSERS[source](payload)
    except (SourceSchemaError, SourceValidationError) as error:
        raise type(error)(
            f"{source.upper()} validation failed for {location}; nothing was written. {error}"
        ) from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch and snapshot CISA KEV and FIRST EPSS over HTTPS (or import a local copy)."
    )
    parser.add_argument("--source", choices=["kev", "epss", "all"], default="all")
    parser.add_argument("--refresh", action="store_true", help="Ignore cached snapshots and download again.")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=DEFAULT_MAX_AGE_HOURS,
        help="Reuse a cached snapshot retrieved within this many hours (default: 24).",
    )
    parser.add_argument("--kev-url", default=OFFICIAL_URLS[KEV_SOURCE])
    parser.add_argument("--epss-url", default=OFFICIAL_URLS[EPSS_SOURCE])
    parser.add_argument("--kev-file", type=Path, help="Import a local KEV JSON instead of downloading.")
    parser.add_argument("--kev-origin", help="Official URL the --kev-file was obtained from (required with --kev-file).")
    parser.add_argument("--epss-file", type=Path, help="Import a local EPSS .csv.gz instead of downloading.")
    parser.add_argument("--epss-origin", help="Official URL the --epss-file was obtained from (required with --epss-file).")
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    args = parser.parse_args(argv)

    if args.kev_file and not args.kev_origin:
        parser.error("--kev-file requires --kev-origin")
    if args.epss_file and not args.epss_origin:
        parser.error("--epss-file requires --epss-origin")

    sources = [KEV_SOURCE, EPSS_SOURCE] if args.source == "all" else [args.source]
    exit_code = 0
    for source in sources:
        try:
            if source == KEV_SOURCE and args.kev_file:
                manifest = import_local_snapshot(source, args.kev_file, origin_url=args.kev_origin, root=args.snapshot_root)
            elif source == EPSS_SOURCE and args.epss_file:
                manifest = import_local_snapshot(source, args.epss_file, origin_url=args.epss_origin, root=args.snapshot_root)
            else:
                url = args.kev_url if source == KEV_SOURCE else args.epss_url
                manifest = fetch_source(
                    source,
                    url=url,
                    root=args.snapshot_root,
                    refresh=args.refresh,
                    max_age_hours=args.max_age_hours,
                )
        except (SourceUnavailableError, SourceSchemaError, SourceValidationError, OSError, ValueError) as error:
            print(f"[{source}] ERROR: {error}")
            exit_code = 1
            continue
        reused = " (reused cached snapshot)" if manifest.get("_reused_cached_snapshot") else ""
        print(
            f"[{source}] snapshot {manifest['snapshot_date']} sha256={manifest['sha256'][:16]}… "
            f"rows={manifest['row_count']:,} method={manifest['retrieval_method']}{reused}"
        )
        print(f"[{source}] manifest: {manifest['_manifest_path']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
