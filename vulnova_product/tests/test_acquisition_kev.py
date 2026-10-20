"""KEV: raw catalog preservation, truncation rejection and maturity censoring."""

from __future__ import annotations

import datetime as dt
import json

from vulnova.acquisition import constants as C
from vulnova.acquisition.github import GitHubApi
from vulnova.acquisition.sources import kev
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import FakeTransport

from tests.acquisition_fixtures import (
    CUTOFFS,
    KEV_CURRENT_COMMIT,
    KEV_CURRENT_COMMITTED,
    KEV_CURRENT_RELEASED,
    KEV_CURRENT_VERSION,
    KEV_HISTORY,
    blob_payload,
    commit_payload,
    kev_blob_url,
    kev_catalog_bytes,
    kev_latest_url,
    kev_tree_url,
    kev_until_url,
    tree_payload,
)

DAY = CUTOFFS[0]


def test_current_catalog_prefers_the_direct_cisa_feed(tmp_path):
    body = kev_catalog_bytes("2026.10.16", "2026-10-16T17:15:48Z", count=4)
    transport = FakeTransport().add_bytes(
        kev.CISA_FEED_URL, body, content_type="application/json", retrieved_at="2026-10-20T10:00:00Z"
    )
    store = ArtifactStore(tmp_path / "store")
    records, facts = kev.acquire_current(transport, store=store)
    assert len(records) == 1
    assert records[0].channel == C.CHANNEL_OFFICIAL
    assert records[0].content_status == C.VERIFIED
    assert facts["parsed_count"] == 4
    assert store.exists(records[0].artifact_path)


def test_unreachable_cisa_feed_is_recorded_even_when_github_succeeds(tmp_path):
    transport = FakeTransport().add_error(kev.CISA_FEED_URL, reason="UNREACHABLE")
    records, facts = kev.acquire_current(transport, store=ArtifactStore(tmp_path / "store"))
    assert facts is None
    assert len(records) == 1
    assert records[0].channel == C.CHANNEL_OFFICIAL
    assert records[0].content_status == C.UNAVAILABLE
    assert records[0].reason_code == C.OFFICIAL_SOURCE_UNREACHABLE


def test_truncated_catalog_is_rejected(tmp_path):
    body = kev_catalog_bytes("2026.10.16", "2026-10-16T17:15:48Z", count=3, declared=1280)
    transport = FakeTransport().add_bytes(
        kev.CISA_FEED_URL, body, content_type="application/json", retrieved_at="2026-10-20T10:00:00Z"
    )
    records, facts = kev.acquire_current(transport, store=ArtifactStore(tmp_path / "store"))
    assert records[0].content_status == C.BLOCKED
    assert records[0].reason_code == C.TRUNCATED_CATALOG
    assert facts is None


def test_catalog_without_release_timestamp_is_rejected():
    payload = json.dumps({"catalogVersion": "1", "count": 0, "vulnerabilities": []})
    try:
        kev.inspect_catalog(payload.encode())
    except ValueError as exc:
        assert str(exc) == C.SOURCE_TIMESTAMP_MISSING
    else:  # pragma: no cover
        raise AssertionError("expected a rejection")


def test_duplicate_identifiers_are_rejected():
    payload = {
        "catalogVersion": "1",
        "dateReleased": "2026-01-01T00:00:00Z",
        "count": 2,
        "vulnerabilities": [{"cveID": "CVE-2024-0001"}, {"cveID": "CVE-2024-0001"}],
    }
    try:
        kev.inspect_catalog(json.dumps(payload).encode())
    except ValueError as exc:
        assert str(exc) == C.MALFORMED_RESPONSE
    else:  # pragma: no cover
        raise AssertionError("expected a rejection")


def _historical_api(tmp_path, *, declared=None, committed=None):
    sha, source_time, version, released, count = KEV_HISTORY[DAY.isoformat()]
    body = kev_catalog_bytes(version, released, count=3, declared=declared)
    tree_sha = "1" * 40
    blob_sha = "2" * 40
    transport = FakeTransport().add_json(
        kev_until_url(DAY),
        [commit_payload(sha, committed or source_time, tree_sha)],
        retrieved_at="2026-10-20T10:00:00Z",
    )
    transport.add_json(
        kev_tree_url(tree_sha), tree_payload(blob_sha, len(body)), retrieved_at="2026-10-20T10:00:01Z"
    )
    transport.add_json(
        kev_blob_url(blob_sha), blob_payload(body, blob_sha), retrieved_at="2026-10-20T10:00:02Z"
    )
    return GitHubApi(transport), body, blob_sha


def test_historical_revision_preserves_raw_bytes_and_hashes(tmp_path):
    api, body, blob_sha = _historical_api(tmp_path)
    store = ArtifactStore(tmp_path / "store")
    record = kev.acquire_at_cutoff(api, DAY, store=store)
    assert record.content_status == C.VERIFIED
    assert record.revision == KEV_HISTORY[DAY.isoformat()][0]
    assert record.details["blob_sha"] == blob_sha
    assert store.read(record.artifact_path) == body
    assert store.digest(record.artifact_path)["sha256"] == record.sha256
    assert record.details["catalog_version"] == KEV_HISTORY[DAY.isoformat()][2]


def test_historical_record_remembers_that_it_was_downloaded_late(tmp_path):
    api, _, _ = _historical_api(tmp_path)
    record = kev.acquire_at_cutoff(api, DAY)
    assert record.access_provenance == C.LATE_RETRIEVAL
    assert record.historical_retrieval_verified is False
    assert record.status == C.BLOCKED


def test_truncated_historical_revision_is_rejected(tmp_path):
    api, _, _ = _historical_api(tmp_path, declared=9999)
    record = kev.acquire_at_cutoff(api, DAY)
    assert record.reason_code == C.TRUNCATED_CATALOG
    assert record.content_status == C.BLOCKED


def test_revision_newer_than_the_cutoff_is_refused(tmp_path):
    api, _, _ = _historical_api(tmp_path, committed="2025-02-05T00:00:00Z")
    record = kev.acquire_at_cutoff(api, DAY)
    assert record.reason_code == C.REVISION_AFTER_CUTOFF


def test_revision_pin_conflict_is_blocked(tmp_path):
    api, _, _ = _historical_api(tmp_path)
    record = kev.acquire_at_cutoff(api, DAY, expected_revision="9" * 40)
    assert record.reason_code == C.PIN_CONFLICT
    assert record.content_status == C.BLOCKED


def test_revision_pin_match_is_recorded(tmp_path):
    api, _, _ = _historical_api(tmp_path)
    expected = KEV_HISTORY[DAY.isoformat()][0]
    record = kev.acquire_at_cutoff(api, DAY, expected_revision=expected)
    assert record.details["pin_crosscheck"] == "MATCH"
    assert record.content_status == C.VERIFIED


def test_size_mismatch_between_tree_and_blob_is_blocked(tmp_path):
    sha, source_time, version, released, _ = KEV_HISTORY[DAY.isoformat()]
    tree_sha, blob_sha = "1" * 40, "2" * 40
    body = kev_catalog_bytes(version, released, count=3)
    transport = FakeTransport().add_json(
        kev_until_url(DAY), [commit_payload(sha, source_time, tree_sha)], retrieved_at="2026-10-20T10:00:00Z"
    )
    transport.add_json(
        kev_tree_url(tree_sha), tree_payload(blob_sha, len(body) + 10), retrieved_at="2026-10-20T10:00:01Z"
    )
    transport.add_json(
        kev_blob_url(blob_sha), blob_payload(body, blob_sha), retrieved_at="2026-10-20T10:00:02Z"
    )
    record = kev.acquire_at_cutoff(GitHubApi(transport), DAY)
    assert record.reason_code == C.SIZE_MISMATCH
    assert record.content_status == C.BLOCKED


def test_bad_base64_blob_is_malformed():
    transport = FakeTransport().add_json(
        kev_until_url(DAY),
        [commit_payload("a" * 40, "2025-01-29T00:00:00Z", "1" * 40)],
        retrieved_at="2026-10-20T10:00:00Z",
    )
    transport.add_json(
        kev_tree_url("1" * 40),
        tree_payload("2" * 40, 10),
        retrieved_at="2026-10-20T10:00:01Z",
    )
    transport.add_json(
        kev_blob_url("2" * 40),
        {"encoding": "base64", "content": "!!!not base64!!!", "size": 10},
        retrieved_at="2026-10-20T10:00:02Z",
    )
    record = kev.acquire_at_cutoff(GitHubApi(transport), DAY)
    assert record.reason_code == C.MALFORMED_RESPONSE


def test_catalog_published_before_maturity_is_right_censored(tmp_path):
    body = kev_catalog_bytes(KEV_CURRENT_VERSION, KEV_CURRENT_RELEASED, count=3)
    transport = FakeTransport().add_json(
        kev_latest_url(),
        [commit_payload(KEV_CURRENT_COMMIT, KEV_CURRENT_COMMITTED, "1" * 40)],
        retrieved_at="2026-10-20T10:00:00Z",
    )
    transport.add_json(
        kev_tree_url("1" * 40), tree_payload("2" * 40, len(body)), retrieved_at="2026-10-20T10:00:01Z"
    )
    transport.add_json(
        kev_blob_url("2" * 40), blob_payload(body, "2" * 40), retrieved_at="2026-10-20T10:00:02Z"
    )
    record = kev.acquire_current_github(
        GitHubApi(transport), store=ArtifactStore(tmp_path / "store"), maturity=dt.date(2026, 10, 28)
    )
    assert record.content_status == C.VERIFIED
    assert record.details["observation"] == C.CATALOG_PREDATES_MATURITY
    assert record.details["maturity_observable"] is False


def test_catalog_published_after_maturity_observes_it(tmp_path):
    body = kev_catalog_bytes(KEV_CURRENT_VERSION, KEV_CURRENT_RELEASED, count=3)
    transport = FakeTransport().add_json(
        kev_latest_url(),
        [commit_payload(KEV_CURRENT_COMMIT, KEV_CURRENT_COMMITTED, "1" * 40)],
        retrieved_at="2026-10-20T10:00:00Z",
    )
    transport.add_json(
        kev_tree_url("1" * 40), tree_payload("2" * 40, len(body)), retrieved_at="2026-10-20T10:00:01Z"
    )
    transport.add_json(
        kev_blob_url("2" * 40), blob_payload(body, "2" * 40), retrieved_at="2026-10-20T10:00:02Z"
    )
    record = kev.acquire_current_github(
        GitHubApi(transport), maturity=dt.date(2025, 8, 30)
    )
    assert record.details["observation"] == "OBSERVES_MATURITY"
    assert record.details["maturity_observable"] is True


def test_maturity_entry_never_filters_a_right_censored_catalog(tmp_path):
    api, _, _ = _historical_api(tmp_path)
    record = kev.acquire_at_cutoff(api, DAY)
    entry = kev.maturity_entry(record, dt.date(2025, 8, 30))
    assert entry["covers_maturity"] is False
    assert entry["filter_basis"] == "RIGHT_CENSORED_NOT_FILTERED"


def test_kev_records_never_claim_absence_means_not_exploited(tmp_path):
    """A catalog only records presence; absence must never read as safety."""
    api, _, _ = _historical_api(tmp_path)
    record = kev.acquire_at_cutoff(api, DAY)
    payload = json.dumps(record.as_dict()).lower()
    assert "not exploited" not in payload
    assert "not_exploited" not in payload
    assert "non-exploitation" not in payload


def test_a_refused_redirect_on_the_direct_feed_is_blocked_not_unreachable(tmp_path):
    transport = FakeTransport().add_error(
        kev.CISA_FEED_URL, reason="HTTPS_DOWNGRADE_BLOCKED", status=301
    )
    records, facts = kev.acquire_current(transport, store=ArtifactStore(tmp_path / "store"))
    assert facts is None
    assert records[0].channel == C.CHANNEL_OFFICIAL
    assert records[0].content_status == C.BLOCKED
    assert records[0].reason_code == C.REDIRECT_BLOCKED
