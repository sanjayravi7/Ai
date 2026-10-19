"""cvelistV5 revision resolution: pins, malformed answers, and honest gaps."""

from __future__ import annotations

import datetime as dt

from vulnova.acquisition import constants as C
from vulnova.acquisition.github import GitHubApi
from vulnova.acquisition.sources import cvelistv5
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import FakeTransport

from tests.acquisition_fixtures import CUTOFFS, CVE_PINS, cve_url, commit_payload


def _api(tmp_path, responses):
    transport = FakeTransport()
    for url, payload, retrieved_at in responses:
        transport.add_json(url, payload, retrieved_at=retrieved_at)
    return GitHubApi(transport), transport, ArtifactStore(tmp_path / "store")


def test_resolves_the_commit_in_force_at_the_cutoff(tmp_path):
    day = CUTOFFS[0]
    sha, committed, tree = CVE_PINS[day.isoformat()]
    api, _, store = _api(
        tmp_path, [(cve_url(day), [commit_payload(sha, committed, tree)], "2026-10-20T10:00:00Z")]
    )
    record = cvelistv5.acquire_revision(api, day, store=store)
    assert record.content_status == C.VERIFIED
    assert record.revision == sha
    assert record.source_timestamp == committed
    assert record.retrieved_at == "2026-10-20T10:00:00Z"
    assert record.access_provenance == C.LATE_RETRIEVAL
    assert record.details["tree_sha"] == tree
    assert store.exists(record.artifact_path)


def test_source_time_and_retrieval_time_are_kept_apart(tmp_path):
    day = CUTOFFS[0]
    sha, committed, tree = CVE_PINS[day.isoformat()]
    api, _, _ = _api(
        tmp_path, [(cve_url(day), [commit_payload(sha, committed, tree)], "2026-10-20T10:00:00Z")]
    )
    record = cvelistv5.acquire_revision(api, day)
    assert record.source_timestamp != record.retrieved_at
    assert record.source_timestamp.startswith("2025-01-31")
    assert record.retrieved_at.startswith("2026-10-20")


def test_pin_mismatch_is_blocked_and_not_resolved_silently(tmp_path):
    day = CUTOFFS[0]
    sha, committed, tree = CVE_PINS[day.isoformat()]
    api, _, _ = _api(
        tmp_path, [(cve_url(day), [commit_payload(sha, committed, tree)], "2026-10-20T10:00:00Z")]
    )
    record = cvelistv5.acquire_revision(
        api, day, expected_revision="0" * 40
    )
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.PIN_CONFLICT
    assert record.historical_retrieval_verified is False


def test_pin_match_is_recorded(tmp_path):
    day = CUTOFFS[0]
    sha, committed, tree = CVE_PINS[day.isoformat()]
    api, _, _ = _api(
        tmp_path, [(cve_url(day), [commit_payload(sha, committed, tree)], "2026-10-20T10:00:00Z")]
    )
    record = cvelistv5.acquire_revision(api, day, expected_revision=sha)
    assert record.details["pin_crosscheck"] == "MATCH"
    assert record.content_status == C.VERIFIED


def test_revision_after_the_cutoff_is_rejected(tmp_path):
    day = CUTOFFS[0]
    api, _, _ = _api(
        tmp_path,
        [(cve_url(day), [commit_payload("a" * 40, "2025-02-02T00:00:00Z", "b" * 40)], "2026-10-20T10:00:00Z")],
    )
    record = cvelistv5.acquire_revision(api, day)
    assert record.reason_code == C.REVISION_AFTER_CUTOFF
    assert record.content_status == C.BLOCKED


def test_missing_source_timestamp_is_reported_not_invented(tmp_path):
    day = CUTOFFS[0]
    payload = [{"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}}]
    api, _, _ = _api(tmp_path, [(cve_url(day), payload, "2026-10-20T10:00:00Z")])
    record = cvelistv5.acquire_revision(api, day)
    assert record.reason_code == C.SOURCE_TIMESTAMP_MISSING
    assert record.retrieved_at == "2026-10-20T10:00:00Z"


def test_empty_commit_list_means_no_revision_exists(tmp_path):
    day = CUTOFFS[0]
    api, _, _ = _api(tmp_path, [(cve_url(day), [], "2026-10-20T10:00:00Z")])
    record = cvelistv5.acquire_revision(api, day)
    assert record.reason_code == C.REVISION_NOT_FOUND
    assert record.content_status == C.BLOCKED


def test_malformed_payload_is_reported(tmp_path):
    day = CUTOFFS[0]
    api, _, _ = _api(tmp_path, [(cve_url(day), {"not": "a list"}, "2026-10-20T10:00:00Z")])
    record = cvelistv5.acquire_revision(api, day)
    assert record.reason_code == C.MALFORMED_RESPONSE


def test_unreachable_source_is_unreachable_not_verified(tmp_path):
    day = CUTOFFS[0]
    transport = FakeTransport().add_error(cve_url(day), reason="UNREACHABLE")
    api = GitHubApi(transport)
    record = cvelistv5.acquire_revision(api, day)
    assert record.reason_code == C.OFFICIAL_SOURCE_UNREACHABLE
    assert record.content_status == C.BLOCKED
    assert record.retrieved_at is None


def test_rate_limit_is_named_as_such(tmp_path):
    day = CUTOFFS[0]
    transport = FakeTransport().add_error(cve_url(day), reason="RATE_LIMITED", status=403)
    record = cvelistv5.acquire_revision(GitHubApi(transport), day)
    assert record.reason_code == C.RATE_LIMITED


def test_missing_commit_has_no_reviewed_timestamp_and_is_blocked(tmp_path):
    day = CUTOFFS[0]
    api, _, _ = _api(
        tmp_path, [(cve_url(day), [{"commit": {"tree": {"sha": "b" * 40}}}], "2026-10-20T10:00:00Z")]
    )
    record = cvelistv5.acquire_revision(api, day)
    assert record.reason_code == C.MALFORMED_RESPONSE
    assert record.revision is None
    assert isinstance(dt.date(2025, 2, 1), dt.date)
