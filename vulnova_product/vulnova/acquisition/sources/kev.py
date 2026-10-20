"""CISA KEV acquisition: the current catalog and exact historical revisions.

Two channels are distinguished and never conflated:

``OFFICIAL``
    The CISA feed at ``www.cisa.gov`` — the publisher's canonical distribution
    endpoint.

``OFFICIAL_GITHUB``
    ``github.com/cisagov/kev-data`` — the same agency's own repository.  This is
    a first-party publication channel, not a third-party mirror.

A catalog is only usable if its declared ``count`` equals the number of entries
it actually contains; truncated revisions are rejected as ``TRUNCATED_CATALOG``.
Absence of a CVE from the catalog is *not* evidence that it was not exploited,
so that interpretation is never recorded here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Optional

from .. import constants as C
from ..github import BlobNotInline, GitHubApi, MalformedGitHubResponse
from ..records import (
    ArtifactRecord,
    cutoff_instant,
    is_policy_refusal,
    to_instant,
    transport_reason,
)
from ..store import ArtifactStore
from ..transport import Transport, TransportError

SOURCE = "kev"
CISA_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
REPO = "cisagov/kev-data"
CATALOG_PATH = "known_exploited_vulnerabilities.json"
REPO_URL = f"https://github.com/{REPO}"

CURRENT_ARTIFACT_PATH = "kev/current/known_exploited_vulnerabilities.json"
HISTORICAL_ARTIFACT_TEMPLATE = "kev/revisions/{cutoff}/known_exploited_vulnerabilities.json"


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _mark_refusal(record: ArtifactRecord, exc: Exception) -> None:
    """A policy refusal is BLOCKED, never a publisher outage."""
    if isinstance(exc, TransportError) and is_policy_refusal(exc):
        record.content_status = C.BLOCKED


def inspect_catalog(body: bytes) -> dict:
    """Parse a KEV catalog and validate its internal consistency.

    Raises ``ValueError`` carrying a stable reason code.
    """
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(C.MALFORMED_RESPONSE) from exc
    if not isinstance(payload, dict):
        raise ValueError(C.MALFORMED_RESPONSE)

    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValueError(C.MALFORMED_RESPONSE)

    declared = payload.get("count")
    parsed = len(entries)
    if declared is not None and declared != parsed:
        raise ValueError(C.TRUNCATED_CATALOG)

    cves = [entry.get("cveID") for entry in entries if isinstance(entry, dict)]
    ids = {cve for cve in cves if isinstance(cve, str) and cve.startswith("CVE-")}
    if len(ids) != len(entries):
        # Duplicates or non-CVE identifiers mean the catalog is not the artifact
        # it claims to be; refuse rather than silently shrink it.
        raise ValueError(C.MALFORMED_RESPONSE)

    date_released = payload.get("dateReleased")
    if not isinstance(date_released, str):
        raise ValueError(C.SOURCE_TIMESTAMP_MISSING)

    return {
        "catalog_version": payload.get("catalogVersion"),
        "date_released": date_released,
        "declared_count": declared,
        "parsed_count": parsed,
        "title": payload.get("title"),
    }


def _observe(
    record: ArtifactRecord, facts: dict, *, maturity: Optional[date]
) -> ArtifactRecord:
    """Check whether the catalog's release can observe a maturity date."""
    released = facts["date_released"]
    released_day = to_instant(released).date()
    record.source_timestamp = released
    record.details["catalog_version"] = facts["catalog_version"]
    record.details["declared_count"] = facts["declared_count"]
    record.details["parsed_count"] = facts["parsed_count"]
    record.details["date_released"] = released
    if maturity is None:
        return record
    record.details["maturity_date"] = maturity.isoformat()
    record.details["maturity_observable"] = released_day >= maturity
    if released_day < maturity:
        # The catalog predates the labels it would need to observe.  Its entries
        # are still authentic; its coverage of the block is not complete.
        record.details["observation"] = C.CATALOG_PREDATES_MATURITY
        record.details["right_censored_at"] = released
    else:
        record.details["observation"] = "OBSERVES_MATURITY"
    return record


def _store(
    store: Optional[ArtifactStore], relative: str, body: bytes
) -> tuple[Optional[str], int, str]:
    digest = _sha(body)
    if store is None:
        return None, len(body), digest
    stored = store.write(relative, body)
    return stored.relative_path, stored.bytes, stored.sha256


# ------------------------------------------------------------------ current
def acquire_current(transport: Transport, *, store: Optional[ArtifactStore] = None):
    """Fetch the current catalog from CISA, then from CISA's GitHub repository.

    Returns ``(records, facts)``.  Both records are kept: the CISA attempt is
    recorded even when it fails, so an unreachable official endpoint can never
    disappear from the provenance record.
    """
    records: list[ArtifactRecord] = []
    official = ArtifactRecord(
        source=SOURCE,
        key="current",
        channel=C.CHANNEL_OFFICIAL,
        source_url=CISA_FEED_URL,
        request_url=CISA_FEED_URL,
        content_status=C.UNAVAILABLE,
        reason_code=C.NO_RECORDS,
    )
    facts: Optional[dict] = None
    try:
        response = transport.get(CISA_FEED_URL, accept="application/json")
    except TransportError as exc:
        official.request_url = exc.url
        official.http_status = exc.status
        official.retrieved_at = exc.retrieved_at
        official.reason_code = transport_reason(exc)
        if is_policy_refusal(exc):
            official.content_status = C.BLOCKED
        official.details["error"] = exc.reason
        records.append(official.finalize())
    else:
        official.retrieved_at = response.retrieved_at
        official.final_url = response.final_url
        official.http_status = response.status
        official.bytes = len(response.body)
        official.sha256 = _sha(response.body)
        try:
            facts = inspect_catalog(response.body)
        except ValueError as exc:
            official.content_status = C.BLOCKED
            official.reason_code = str(exc)
            records.append(official.finalize())
        else:
            official.content_status = C.VERIFIED
            official.reason_code = C.OK_VERIFIED
            path, size, digest = _store(store, CURRENT_ARTIFACT_PATH, response.body)
            official.artifact_path = path
            official.bytes = size
            official.sha256 = digest
            records.append(_observe(official.finalize(), facts, maturity=None))
    return records, facts


def acquire_current_github(
    api: GitHubApi,
    *,
    store: Optional[ArtifactStore] = None,
    maturity: Optional[date] = None,
) -> ArtifactRecord:
    """Fetch the current catalog from CISA's own GitHub repository."""
    record = ArtifactRecord(
        source=SOURCE,
        key="current#github",
        channel=C.CHANNEL_OFFICIAL_GITHUB,
        source_url=REPO_URL,
        request_url="",
        content_status=C.UNAVAILABLE,
        reason_code=C.NO_RECORDS,
    )
    try:
        commit_result = api.latest_commit(REPO)
    except (MalformedGitHubResponse, TransportError) as exc:
        record.request_url = getattr(exc, "url", "")
        record.reason_code = (
            C.MALFORMED_RESPONSE
            if isinstance(exc, MalformedGitHubResponse)
            else transport_reason(exc)
        )
        _mark_refusal(record, exc)
        record.details["error"] = getattr(exc, "reason", "MALFORMED_RESPONSE")
        return record.finalize()
    if not commit_result.payload:
        record.reason_code = C.REVISION_NOT_FOUND
        return record.finalize()

    commit = commit_result.payload[0]
    revision = commit.get("sha")
    source_timestamp = GitHubApi.commit_date(commit)
    record.revision = revision if isinstance(revision, str) else None
    record.source_timestamp = source_timestamp
    record.retrieved_at = commit_result.retrieved_at
    record.details["commit_url"] = commit_result.url

    if not record.revision or not source_timestamp:
        record.reason_code = (
            C.MALFORMED_RESPONSE if not record.revision else C.SOURCE_TIMESTAMP_MISSING
        )
        return record.finalize()

    tree_sha = GitHubApi.tree_sha(commit)
    body, blob_meta = _fetch_blob_at(api, record, tree_sha)
    if body is None:
        return record.finalize()

    return _finish_catalog(
        record,
        body,
        blob_meta,
        store=store,
        relative=CURRENT_ARTIFACT_PATH,
        maturity=maturity,
    )


# ------------------------------------------------------------------ history
def _fetch_blob_at(api: GitHubApi, record: ArtifactRecord, tree_sha: Optional[str]):
    if not tree_sha:
        record.reason_code = C.MALFORMED_RESPONSE
        record.details["error"] = "commit carries no tree sha"
        return None, None
    try:
        tree_result = api.tree(REPO, tree_sha)
    except (MalformedGitHubResponse, TransportError) as exc:
        record.request_url = getattr(exc, "url", record.request_url)
        record.reason_code = (
            C.MALFORMED_RESPONSE
            if isinstance(exc, MalformedGitHubResponse)
            else transport_reason(exc)
        )
        _mark_refusal(record, exc)
        record.details["error"] = getattr(exc, "reason", "MALFORMED_RESPONSE")
        return None, None

    entry = next(
        (item for item in tree_result.payload["tree"] if item.get("path") == CATALOG_PATH),
        None,
    )
    if entry is None:
        record.reason_code = C.REVISION_NOT_FOUND
        record.details["error"] = f"{CATALOG_PATH} absent from tree {tree_sha}"
        return None, None

    blob_sha = entry.get("sha")
    record.details["tree_sha"] = tree_sha
    record.details["blob_sha"] = blob_sha
    record.details["blob_declared_bytes"] = entry.get("size")
    try:
        body, blob_result = api.blob(REPO, blob_sha)
    except BlobNotInline:
        # Files above 1 MB come back with encoding "none"; fetch the raw bytes
        # instead.  The media type is recorded so the provenance shows which
        # representation produced the stored bytes.
        try:
            raw = api.blob_raw(REPO, blob_sha)
        except (MalformedGitHubResponse, TransportError) as exc:
            record.request_url = getattr(exc, "url", record.request_url)
            record.reason_code = (
                C.MALFORMED_RESPONSE
                if isinstance(exc, MalformedGitHubResponse)
                else transport_reason(exc)
            )
            _mark_refusal(record, exc)
            record.details["error"] = getattr(exc, "reason", "MALFORMED_RESPONSE")
            return None, None
        record.details["blob_media_type"] = "application/vnd.github.raw"
        body, blob_result = raw.body, raw
    except (MalformedGitHubResponse, TransportError) as exc:
        record.request_url = getattr(exc, "url", record.request_url)
        record.reason_code = (
            C.MALFORMED_RESPONSE
            if isinstance(exc, MalformedGitHubResponse)
            else transport_reason(exc)
        )
        _mark_refusal(record, exc)
        record.details["error"] = getattr(exc, "reason", "MALFORMED_RESPONSE")
        return None, None

    declared = entry.get("size")
    if isinstance(declared, int) and declared != len(body):
        record.content_status = C.BLOCKED
        record.reason_code = C.SIZE_MISMATCH
        record.details["decoded_bytes"] = len(body)
        record.sha256 = _sha(body)
        record.bytes = len(body)
        record.retrieved_at = blob_result.retrieved_at
        return None, None
    return body, blob_result


def _finish_catalog(
    record: ArtifactRecord,
    body: bytes,
    blob_meta,
    *,
    store: Optional[ArtifactStore],
    relative: str,
    maturity: Optional[date],
) -> ArtifactRecord:
    """Attach the catalog bytes and the two URLs that describe them.

    ``request_url`` is the URL that was asked for the catalog bytes — the blob
    endpoint — not the commit listing that merely located them; that one is kept
    separately in ``details``.  ``final_url`` is the URL that actually served
    those bytes.  When nothing redirected the two are equal, and
    :meth:`ArtifactRecord.as_dict` then omits ``final_url`` rather than recording
    a redundant copy of ``request_url``.
    """
    record.request_url = blob_meta.url
    record.final_url = blob_meta.final_url or blob_meta.url
    record.retrieved_at = blob_meta.retrieved_at
    record.details["blob_url"] = blob_meta.url
    record.bytes = len(body)
    record.sha256 = _sha(body)
    try:
        facts = inspect_catalog(body)
    except ValueError as exc:
        record.content_status = C.BLOCKED
        record.reason_code = str(exc)
        return record.finalize()
    path, size, digest = _store(store, relative, body)
    record.artifact_path = path
    record.bytes = size
    record.sha256 = digest
    record.content_status = C.VERIFIED
    record.reason_code = C.OK_VERIFIED
    _observe(record, facts, maturity=maturity)
    return record.finalize()


def acquire_at_cutoff(
    api: GitHubApi,
    cutoff: date,
    *,
    store: Optional[ArtifactStore] = None,
    maturity: Optional[date] = None,
    expected_revision: Optional[str] = None,
) -> ArtifactRecord:
    """Resolve the KEV catalog as published at ``cutoff`` (``T 00:00:00Z``)."""
    until = cutoff_instant(cutoff).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = ArtifactRecord(
        source=SOURCE,
        key=cutoff.isoformat(),
        channel=C.CHANNEL_OFFICIAL_GITHUB,
        source_url=REPO_URL,
        request_url="",
        cutoff=cutoff.isoformat(),
        content_status=C.UNAVAILABLE,
        reason_code=C.REVISION_NOT_FOUND,
    )
    try:
        commit_result = api.commits_until(REPO, until)
    except (MalformedGitHubResponse, TransportError) as exc:
        record.request_url = getattr(exc, "url", "")
        record.retrieved_at = getattr(exc, "retrieved_at", None)
        record.reason_code = (
            C.MALFORMED_RESPONSE
            if isinstance(exc, MalformedGitHubResponse)
            else transport_reason(exc)
        )
        _mark_refusal(record, exc)
        record.details["error"] = getattr(exc, "reason", "MALFORMED_RESPONSE")
        return record.finalize()

    record.details["commit_query_url"] = commit_result.url
    record.retrieved_at = commit_result.retrieved_at
    if not commit_result.payload:
        return record.finalize()

    commit = commit_result.payload[0]
    revision = commit.get("sha")
    source_timestamp = GitHubApi.commit_date(commit)
    record.revision = revision if isinstance(revision, str) else None
    record.source_timestamp = source_timestamp
    if not record.revision:
        record.reason_code = C.MALFORMED_RESPONSE
        return record.finalize()
    if not source_timestamp:
        record.reason_code = C.SOURCE_TIMESTAMP_MISSING
        return record.finalize()

    committed_at = to_instant(source_timestamp)
    record.details["committed_at"] = committed_at.isoformat()
    if committed_at > cutoff_instant(cutoff):
        record.reason_code = C.REVISION_AFTER_CUTOFF
        return record.finalize()

    if expected_revision is not None:
        record.details["recorded_revision"] = expected_revision
        if expected_revision != record.revision:
            record.content_status = C.BLOCKED
            record.reason_code = C.PIN_CONFLICT
            record.details["conflict"] = (
                f"Phase 2.3K recorded {expected_revision}; "
                f"live source resolves {record.revision}"
            )
            return record.finalize()
        record.details["pin_crosscheck"] = "MATCH"

    body, blob_meta = _fetch_blob_at(api, record, GitHubApi.tree_sha(commit))
    if body is None:
        return record.finalize()

    relative = HISTORICAL_ARTIFACT_TEMPLATE.format(cutoff=cutoff.isoformat())
    return _finish_catalog(
        record, body, blob_meta, store=store, relative=relative, maturity=maturity
    )


def maturity_entry(record: ArtifactRecord, maturity: date) -> dict:
    """Describe how a catalog record relates to a block's maturity date."""
    released = record.source_timestamp or record.details.get("date_released")
    released_day = to_instant(released).date() if released else None
    covered = bool(released_day and released_day >= maturity)
    return {
        "catalog_available": record.content_status == C.VERIFIED,
        "catalog_revision": record.revision,
        "catalog_released": released,
        "maturity_date": maturity.isoformat(),
        "covers_maturity": covered,
        "filter_basis": (
            "dateAdded <= maturity_date"
            if covered
            else "RIGHT_CENSORED_NOT_FILTERED"
        ),
        "note": (
            "Filtering to dateAdded <= maturity_date is valid only when the "
            "catalog was released at or after the maturity date; otherwise the "
            "observation is right-censored and is not reported as complete."
        ),
    }


__all__ = [
    "CATALOG_PATH",
    "CISA_FEED_URL",
    "CURRENT_ARTIFACT_PATH",
    "HISTORICAL_ARTIFACT_TEMPLATE",
    "REPO",
    "REPO_URL",
    "SOURCE",
    "acquire_at_cutoff",
    "acquire_current",
    "acquire_current_github",
    "inspect_catalog",
    "maturity_entry",
]
