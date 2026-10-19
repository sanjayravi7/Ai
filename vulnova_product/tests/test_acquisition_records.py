"""The two-axis record model: content authenticity versus access provenance."""

from __future__ import annotations

import datetime as dt

import pytest

from vulnova.acquisition import constants as C
from vulnova.acquisition.records import (
    ArtifactRecord,
    cutoff_instant,
    requirement_from_records,
    to_instant,
)


def _record(**overrides) -> ArtifactRecord:
    base = dict(
        source="kev",
        key="2025-02-01",
        channel=C.CHANNEL_OFFICIAL_GITHUB,
        source_url="https://github.com/cisagov/kev-data",
        request_url="https://api.github.com/repos/cisagov/kev-data/commits",
        content_status=C.VERIFIED,
        reason_code=C.OK_VERIFIED,
        cutoff="2025-02-01",
        retrieved_at="2026-10-20T10:00:00Z",
        source_timestamp="2025-01-29T17:59:10Z",
        sha256="a" * 64,
        artifact_path="kev/revisions/2025-02-01/known_exploited_vulnerabilities.json",
    )
    base.update(overrides)
    return ArtifactRecord(**base).finalize()


def test_cutoff_instant_is_midnight_utc():
    assert cutoff_instant(dt.date(2025, 2, 1)) == dt.datetime(
        2025, 2, 1, tzinfo=dt.timezone.utc
    )


def test_to_instant_treats_naive_values_as_utc():
    assert to_instant("2025-01-29T17:59:10").tzinfo is dt.timezone.utc
    assert to_instant("2025-01-29T17:59:10Z").hour == 17


def test_old_content_retrieved_now_is_late_not_historical():
    record = _record()
    assert record.content_status == C.VERIFIED
    assert record.access_provenance == C.LATE_RETRIEVAL
    assert record.historical_retrieval_verified is False
    assert record.status == C.BLOCKED


def test_contemporaneous_access_requires_retrieval_at_or_before_cutoff():
    record = _record(retrieved_at="2025-02-01T00:00:00Z")
    assert record.access_provenance == C.CONTEMPORANEOUS
    assert record.historical_retrieval_verified is True
    assert record.status == C.VERIFIED


def test_one_second_after_cutoff_is_already_late():
    record = _record(retrieved_at="2025-02-01T00:00:01Z")
    assert record.access_provenance == C.LATE_RETRIEVAL
    assert record.historical_retrieval_verified is False


def test_failed_request_is_not_a_late_retrieval():
    record = _record(sha256=None, artifact_path=None, content_status=C.UNAVAILABLE)
    assert record.access_provenance == C.NOT_RETRIEVED
    assert record.historical_retrieval_verified is False


def test_missing_retrieval_timestamp_is_never_contemporaneous():
    record = _record(retrieved_at=None)
    assert record.access_provenance == C.NOT_RETRIEVED
    assert record.historical_retrieval_verified is False


def test_retrieval_before_source_time_is_blocked_and_flagged():
    record = _record(
        retrieved_at="2024-01-01T00:00:00Z", source_timestamp="2025-01-29T17:59:10Z"
    )
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.RETRIEVAL_BEFORE_SOURCE_TIME


def test_current_snapshot_without_cutoff_is_contemporaneous():
    record = _record(cutoff=None, retrieved_at="2026-10-20T10:00:00Z")
    assert record.access_provenance == C.CONTEMPORANEOUS
    assert record.historical_retrieval_verified is False  # no cutoff => not historical


def test_record_serialises_both_axes():
    payload = _record().as_dict()
    assert payload["content_status"] == C.VERIFIED
    assert payload["status"] == C.BLOCKED
    assert payload["access_provenance"] == C.LATE_RETRIEVAL
    assert payload["historical_retrieval_verified"] is False


def test_requirement_uses_worst_status_and_names_the_access_reason():
    records = [
        _record(),
        _record(key="2025-09-01", cutoff="2025-09-01", retrieved_at="2026-10-20T10:00:00Z"),
    ]
    requirement = requirement_from_records("CVE-03", "provenance", records)
    assert requirement.status == C.BLOCKED
    assert requirement.reason_code == C.RETRIEVAL_NOT_CONTEMPORANEOUS


def test_content_only_requirement_ignores_access_provenance():
    requirement = requirement_from_records(
        "CVE-01", "pins", [_record()], use_access_provenance=False
    )
    assert requirement.status == C.VERIFIED
    assert requirement.reason_code == C.OK_VERIFIED


def test_empty_record_set_is_blocked_not_verified():
    requirement = requirement_from_records("EPSS-01", "epss", [])
    assert requirement.status == C.BLOCKED
    assert requirement.reason_code == C.NO_RECORDS


def test_unknown_cutoff_text_degrades_to_not_retrieved():
    record = _record(cutoff="not-a-date")
    assert record.access_provenance == C.NOT_RETRIEVED


@pytest.mark.parametrize("status", C.STATUSES)
def test_status_vocabulary_is_closed(status):
    assert status in C.STATUSES
