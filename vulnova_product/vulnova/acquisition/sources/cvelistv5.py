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
from ..github import GitHubApi, MalformedGitHubResponse
from ..records import ArtifactRecord, cutoff_instant, to_instant
from ..store import ArtifactStore
from ..transport import TransportError

SOURCE = "cvelistv5"
REPO = "CVEProject/cvelistV5"
SOURCE_URL = f"https://github.com/{REPO}"
CHANNEL = C.CHANNEL_OFFICIAL_GITHUB

ARTIFACT_TEMPLATE = "cvelistv5/commits/{cutoff}.json"


def _store_response(
    store: Optional[ArtifactStore], cutoff: date, body: bytes
) -> tuple[Optional[str], int, str]:
    digest = hashlib.sha256(body).hexdigest()
    if store is None:
        return None, len(body), digest
    stored = store.write(ARTIFACT_TEMPLATE.format(cutoff=cutoff.isoformat()), body)
    return stored.relative_path, stored.bytes, stored.sha256


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
        if exc.reason == "RATE_LIMITED":
            record.reason_code = C.RATE_LIMITED
        elif exc.status == 404:
            record.reason_code = C.REVISION_NOT_FOUND
        elif exc.reason == "UNREACHABLE":
            record.reason_code = C.OFFICIAL_SOURCE_UNREACHABLE
        else:
            record.reason_code = C.HTTP_ERROR
        record.details["error"] = exc.reason
        return record.finalize()

    record.request_url = result.url
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


__all__ = ["ARTIFACT_TEMPLATE", "CHANNEL", "REPO", "SOURCE", "SOURCE_URL", "acquire_revision"]
