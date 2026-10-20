"""cvelistV5 revision resolution with explicit retrieval provenance.

For each historical cutoff the tool resolves the greatest ``main`` commit whose
committer timestamp is at or before ``T 00:00:00Z``, using the official CVE
Program repository over the GitHub API.  It records:

* the resolved commit SHA and tree SHA,
* the source's own committer timestamp (historical time),
* the actual UTC time the API response was received (retrieval time),
* the response URL, byte size and SHA-256 of the response body.

The two timestamps are never conflated.  An old commit downloaded today is
verified *content* with *late* access; that distinction is exactly the gap the
1.6 readiness report exposed as ``CVELISTV5_RETRIEVAL_TIMESTAMP_NOT_RECORDED``.
"""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Optional

from .. import constants as C
from ..github import SHA_RE, GitHubApi, MalformedGitHubResponse
from ..records import (
    ArtifactRecord,
    cutoff_instant,
    is_policy_refusal,
    to_instant,
    transport_reason,
)
from ..store import ArtifactStore
from ..transport import TransportError

SOURCE = "cvelistv5"
REPO = "CVEProject/cvelistV5"
SOURCE_URL = f"https://github.com/{REPO}"
CHANNEL = C.CHANNEL_OFFICIAL_GITHUB

ARTIFACT_TEMPLATE = "cvelistv5/commits/{cutoff}.json"


LATEST_KEY = "HEAD"


def _store_body(
    store: Optional[ArtifactStore], relative: str, body: bytes
) -> tuple[Optional[str], int, str]:
    digest = hashlib.sha256(body).hexdigest()
    if store is None:
        return None, len(body), digest
    stored = store.write(relative, body)
    return stored.relative_path, stored.bytes, stored.sha256


def _store_response(
    store: Optional[ArtifactStore], cutoff: date, body: bytes
) -> tuple[Optional[str], int, str]:
    return _store_body(store, ARTIFACT_TEMPLATE.format(cutoff=cutoff.isoformat()), body)


def capture_current(
    api: GitHubApi, *, store: Optional[ArtifactStore] = None
) -> ArtifactRecord:
    """Record the cvelistV5 revision observable right now — without a clone.

    The CVE Program repository is far too large to clone on every daily capture,
    and cloning it would add nothing: the revision is fully identified by the
    commit SHA reported by the official API.  The API response bytes are stored
    so the identifier can be re-derived offline, and the retrieval time is the
    transport's real receipt time rather than the commit's own timestamp.
    """
    record = ArtifactRecord(
        source=SOURCE,
        key=LATEST_KEY,
        channel=CHANNEL,
        source_url=SOURCE_URL,
        request_url="",
        content_status=C.BLOCKED,
        reason_code=C.NO_RECORDS,
    )
    try:
        result = api.latest_commit(REPO)
    except MalformedGitHubResponse as exc:
        record.request_url = exc.url
        record.retrieved_at = exc.retrieved_at
        record.reason_code = C.MALFORMED_RESPONSE
        record.details["error"] = exc.detail
        return record.finalize()
    except TransportError as exc:
        record.request_url = exc.url
        record.http_status = exc.status
        record.retrieved_at = exc.retrieved_at
        record.reason_code = transport_reason(exc, not_found=C.REVISION_NOT_FOUND)
        if is_policy_refusal(exc):
            # We declined to follow the request; the source never answered.
            record.content_status = C.BLOCKED
        else:
            record.content_status = C.UNAVAILABLE
        record.details["error"] = exc.reason
        return record.finalize()

    record.request_url = result.url
    record.final_url = result.final_url or result.url
    record.retrieved_at = result.retrieved_at
    record.http_status = 200
    record.artifact_path, record.bytes, record.sha256 = _store_body(
        store, ARTIFACT_TEMPLATE.format(cutoff=LATEST_KEY), result.body
    )

    commits = result.payload
    if not isinstance(commits, list) or not commits:
        record.content_status = C.UNAVAILABLE
        record.reason_code = C.REVISION_NOT_FOUND
        record.details["commits_returned"] = len(commits) if isinstance(commits, list) else 0
        return record.finalize()

    commit = commits[0]
    if not isinstance(commit, dict):
        record.content_status = C.BLOCKED
        record.reason_code = C.MALFORMED_RESPONSE
        record.details["error"] = "first commit is not a JSON object"
        return record.finalize()
    revision = commit.get("sha")
    source_timestamp = GitHubApi.commit_date(commit)
    if not isinstance(revision, str) or not SHA_RE.match(revision):
        record.content_status = C.BLOCKED
        record.reason_code = C.MALFORMED_RESPONSE
        record.details["error"] = "commit carries no 40-hex sha"
        return record.finalize()
    if not source_timestamp:
        record.content_status = C.BLOCKED
        record.reason_code = C.SOURCE_TIMESTAMP_MISSING
        return record.finalize()

    record.revision = revision
    record.source_timestamp = source_timestamp
    try:
        record.details["committed_at"] = to_instant(source_timestamp).isoformat()
    except (TypeError, ValueError):
        record.content_status = C.BLOCKED
        record.reason_code = C.SOURCE_TIMESTAMP_MISSING
        return record.finalize()
    record.details["tree_sha"] = GitHubApi.tree_sha(commit)
    record.details["selection_rule"] = (
        "latest commit on the default branch at retrieval time"
    )
    record.details["clone_required"] = False
    record.details["revision_identifier"] = "git commit sha (40 hex)"
    record.content_status = C.VERIFIED
    record.reason_code = C.OK_VERIFIED
    return record.finalize()


def acquire_revision(
    api: GitHubApi,
    cutoff: date,
    *,
    store: Optional[ArtifactStore] = None,
    expected_revision: Optional[str] = None,
) -> ArtifactRecord:
    """Resolve and record the cvelistV5 revision in force at ``cutoff``.

    ``expected_revision`` is the revision recorded by the Phase 2.3K export.  A
    disagreement is reported as ``PIN_CONFLICT`` rather than silently preferred
    in either direction.
    """
    until = cutoff_instant(cutoff).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = ArtifactRecord(
        source=SOURCE,
        key=cutoff.isoformat(),
        channel=CHANNEL,
        source_url=SOURCE_URL,
        request_url="",
        cutoff=cutoff.isoformat(),
        content_status=C.BLOCKED,
        reason_code=C.NO_RECORDS,
    )

    try:
        result = api.commits_until(REPO, until)
    except MalformedGitHubResponse as exc:
        record.request_url = exc.url
        record.reason_code = C.MALFORMED_RESPONSE
        record.details["error"] = exc.detail
        return record.finalize()
    except TransportError as exc:
        record.request_url = exc.url
        record.http_status = exc.status
        record.retrieved_at = exc.retrieved_at
        record.reason_code = transport_reason(exc, not_found=C.REVISION_NOT_FOUND)
        if is_policy_refusal(exc):
            # We declined to follow the request; the source never answered.
            record.content_status = C.BLOCKED
        record.details["error"] = exc.reason
        return record.finalize()

    record.request_url = result.url
    record.final_url = result.final_url or result.url
    record.retrieved_at = result.retrieved_at
    record.http_status = 200
    record.artifact_path, record.bytes, record.sha256 = _store_response(
        store, cutoff, result.body
    )

    commits = result.payload
    if not commits:
        record.reason_code = C.REVISION_NOT_FOUND
        record.details["commits_returned"] = 0
        return record.finalize()

    commit = commits[0]
    revision = commit.get("sha")
    source_timestamp = GitHubApi.commit_date(commit)
    record.revision = revision if isinstance(revision, str) else None
    record.source_timestamp = source_timestamp

    if not isinstance(revision, str) or not revision:
        record.reason_code = C.MALFORMED_RESPONSE
        record.details["error"] = "commit carries no sha"
        return record.finalize()
    if not source_timestamp:
        record.reason_code = C.SOURCE_TIMESTAMP_MISSING
        return record.finalize()

    try:
        committed_at = to_instant(source_timestamp)
    except (TypeError, ValueError):
        record.reason_code = C.SOURCE_TIMESTAMP_MISSING
        return record.finalize()

    if committed_at > cutoff_instant(cutoff):
        record.reason_code = C.REVISION_AFTER_CUTOFF
        record.details["committed_at"] = committed_at.isoformat()
        return record.finalize()

    record.details["committed_at"] = committed_at.isoformat()
    record.details["tree_sha"] = GitHubApi.tree_sha(commit)
    record.details["selection_rule"] = (
        "greatest main-branch commit with committer timestamp <= T 00:00:00Z"
    )

    if expected_revision is not None:
        record.details["recorded_revision"] = expected_revision
        if expected_revision != revision:
            record.content_status = C.BLOCKED
            record.reason_code = C.PIN_CONFLICT
            record.details["conflict"] = (
                f"Phase 2.3K recorded {expected_revision}; "
                f"live source resolves {revision}"
            )
            return record.finalize()
        record.details["pin_crosscheck"] = "MATCH"
    else:
        record.details["pin_crosscheck"] = C.PIN_CROSSCHECK_SKIPPED

    record.content_status = C.VERIFIED
    record.reason_code = C.OK_VERIFIED
    return record.finalize()


__all__ = [
    "ARTIFACT_TEMPLATE",
    "CHANNEL",
    "LATEST_KEY",
    "REPO",
    "SOURCE",
    "SOURCE_URL",
    "acquire_revision",
    "capture_current",
]
