"""EPSS: exact-date files or nothing. A fresher file is never substituted."""

from __future__ import annotations

import datetime as dt
import gzip

from vulnova.acquisition import constants as C
from vulnova.acquisition.sources import epss
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import FakeTransport

from tests.acquisition_fixtures import CUTOFFS, epss_bytes, epss_url

DAY = CUTOFFS[0]


def _record(body, *, day=DAY, retrieved_at="2026-10-20T10:00:00Z", store=None):
    transport = FakeTransport().add_bytes(
        epss_url(day), body, content_type="application/gzip", retrieved_at=retrieved_at
    )
    return epss.acquire_daily(transport, day, store=store)


def test_exact_daily_file_is_verified_and_stored(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    record = _record(epss_bytes(DAY), store=store)
    assert record.content_status == C.VERIFIED
    assert record.details["rows"] == 3
    assert record.details["model_version"] == "v2026.06.15"
    assert record.details["file_score_date"] == DAY.isoformat()
    assert store.exists(record.artifact_path)
    assert store.digest(record.artifact_path)["sha256"] == record.sha256


def test_newer_score_file_is_refused_not_substituted():
    newer = epss_bytes(dt.date(2026, 10, 16), score_date="2026-10-16T12:02:51Z")
    record = _record(newer)
    assert record.content_status == C.UNAVAILABLE
    assert record.reason_code == C.SCORE_DATE_MISMATCH
    assert record.details["file_score_date"] == "2026-10-16"
    assert record.details["requested_date"] == DAY.isoformat()


def test_refused_substitute_is_still_hashed_for_inspection():
    newer = epss_bytes(dt.date(2026, 10, 16), score_date="2026-10-16T12:02:51Z")
    record = _record(newer)
    assert record.sha256 is not None
    assert record.artifact_path is None  # not stored as if it satisfied the cutoff


def test_missing_file_is_unavailable_with_the_exact_date_named():
    transport = FakeTransport().add_error(epss_url(DAY), reason="HTTP_ERROR", status=404)
    record = epss.acquire_daily(transport, DAY)
    assert record.reason_code == C.EPSS_FILE_MISSING
    assert record.content_status == C.UNAVAILABLE
    assert record.details["requested_date"] == DAY.isoformat()


def test_unreachable_publisher_is_reported_honestly():
    transport = FakeTransport().add_error(epss_url(DAY), reason="UNREACHABLE")
    record = epss.acquire_daily(transport, DAY)
    assert record.reason_code == C.OFFICIAL_SOURCE_UNREACHABLE
    assert record.retrieved_at is None
    assert "empiricalsec" in record.details["mirror_available"]


def test_corrupt_gzip_is_unreadable_not_empty():
    record = _record(b"\x1f\x8bnot really gzip")
    assert record.reason_code == C.ARTIFACT_UNREADABLE


def test_header_without_score_date_is_malformed():
    record = _record(epss_bytes(DAY, raw_header="#model_version:v1"))
    assert record.reason_code == C.MALFORMED_RESPONSE


def test_file_with_no_score_rows_is_malformed():
    record = _record(epss_bytes(DAY, rows=0))
    assert record.reason_code == C.MALFORMED_RESPONSE


def test_row_with_wrong_columns_is_malformed():
    body = gzip.compress(
        b"#model_version:v1,score_date:2025-02-01T00:00:00Z\nCVE-2024-0001,notanumber,0.5\n"
    )
    record = _record(body)
    assert record.reason_code == C.MALFORMED_RESPONSE


def test_uncompressed_payload_is_readable():
    body = b"#model_version:v1,score_date:2025-02-01T00:00:00Z\nCVE-2024-0001,0.5,0.9\n"
    record = _record(body)
    assert record.content_status == C.VERIFIED


def test_mirror_record_is_never_verified():
    record = epss.mirror_record(DAY)
    assert record.channel == C.CHANNEL_THIRD_PARTY_MIRROR
    assert record.content_status == C.UNAVAILABLE
    assert record.reason_code == C.THIRD_PARTY_MIRROR_ONLY
    assert record.retrieved_at is None
    assert record.historical_retrieval_verified is False


def test_late_retrieval_of_an_exact_file_is_not_historical_provenance():
    record = _record(epss_bytes(DAY))
    assert record.content_status == C.VERIFIED
    assert record.access_provenance == C.LATE_RETRIEVAL
    assert record.historical_retrieval_verified is False
    assert record.status == C.BLOCKED


def test_epss_header_parser_agrees_with_the_existing_reader(tmp_path):
    path = tmp_path / "epss_scores-2025-02-01.csv.gz"
    path.write_bytes(epss_bytes(DAY))
    from vulnova.sources.epss import read_header

    header = read_header(path)
    assert header["score_date"].startswith(DAY.isoformat())
    facts = epss.inspect_payload(path.read_bytes())
    assert facts["score_date"] == header["score_date"]
    assert facts["model_version"] == header["model_version"]


def test_a_redirect_is_recorded_as_a_final_url(tmp_path):
    transport = FakeTransport().add_bytes(
        epss_url(DAY),
        epss_bytes(DAY),
        content_type="application/gzip",
        retrieved_at="2026-10-20T10:00:00Z",
        final_url="https://epss.empiricalsecurity.com/daily/epss_scores-2025-02-01.csv.gz",
    )
    record = epss.acquire_daily(transport, DAY)
    payload = record.as_dict()
    assert payload["request_url"] == epss_url(DAY)
    assert payload["final_url"].endswith("daily/epss_scores-2025-02-01.csv.gz")
    assert record.content_status == C.VERIFIED


def test_a_refused_redirect_is_blocked_and_not_reported_as_a_publisher_outage():
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="DISALLOWED_REDIRECT_HOST", status=302
    )
    record = epss.acquire_daily(transport, DAY)
    assert record.reason_code == C.REDIRECT_BLOCKED
    assert record.content_status == C.BLOCKED
    assert record.reason_code != C.OFFICIAL_SOURCE_UNREACHABLE
