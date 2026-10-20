"""EPSS: exact-date files or nothing. A fresher file is never substituted."""

from __future__ import annotations

import datetime as dt
import gzip
import io
import urllib.error

from vulnova.acquisition import constants as C
from vulnova.acquisition.sources import epss
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import FakeTransport, UrllibTransport

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


# ---------------------------------------------------------------- diagnostics
# A failed request keeps its classification; the patch only adds a bounded
# excerpt of what the transport was told.  Nothing below decides a status.


def test_a_403_records_the_bounded_response_detail():
    body = '{"message": "Request was blocked by the security rules"}'
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail=body
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.http_status == 403
    assert record.reason_code == C.RATE_LIMITED
    assert record.content_status == C.UNAVAILABLE
    assert record.details["error"] == "RATE_LIMITED"
    assert record.details["error_detail"] == body
    # A failed capture still stores nothing.
    assert record.sha256 is None and record.artifact_path is None


def test_a_429_records_the_bounded_response_detail():
    body = "Too Many Requests: retry after 900 seconds"
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=429, detail=body
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.http_status == 429
    assert record.reason_code == C.RATE_LIMITED
    assert record.details["error_detail"] == body


def test_an_empty_detail_is_omitted_rather_than_written_empty():
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.reason_code == C.RATE_LIMITED
    assert "error_detail" not in record.details
    # The rest of the record is exactly what it was before the field existed.
    assert record.details["error"] == "RATE_LIMITED"
    assert record.details["requested_date"] == DAY.isoformat()
    assert record.details["mirror_available"] == epss.MIRROR_NOTE


def test_a_whitespace_only_detail_is_treated_as_empty():
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail=" \n\t\r\n  "
    )
    record = epss.acquire_daily(transport, DAY)

    assert "error_detail" not in record.details


def test_a_multi_line_detail_is_collapsed_to_one_line():
    transport = FakeTransport().add_error(
        epss_url(DAY),
        reason="RATE_LIMITED",
        status=403,
        detail="<html>\n  <head>\n\t<title>Access Denied</title>\n  </head>\n</html>",
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.details["error_detail"] == (
        "<html> <head> <title>Access Denied</title> </head> </html>"
    )
    assert "\n" not in record.details["error_detail"]


def test_a_detail_longer_than_the_limit_is_capped_at_exactly_the_limit():
    detail = "A" * 5000 + "TAIL"
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail=detail
    )
    record = epss.acquire_daily(transport, DAY)

    recorded = record.details["error_detail"]
    assert len(recorded) == epss.ERROR_DETAIL_LIMIT == 400
    assert recorded.endswith("…")
    assert "TAIL" not in recorded
    assert recorded.startswith("A" * 399)


def test_a_detail_of_exactly_the_limit_is_kept_verbatim():
    detail = "B" * epss.ERROR_DETAIL_LIMIT
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail=detail
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.details["error_detail"] == detail


def test_a_detail_one_over_the_limit_is_truncated_with_an_ellipsis():
    detail = "C" * (epss.ERROR_DETAIL_LIMIT + 1)
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail=detail
    )
    record = epss.acquire_daily(transport, DAY)

    recorded = record.details["error_detail"]
    assert len(recorded) == epss.ERROR_DETAIL_LIMIT
    assert recorded == "C" * (epss.ERROR_DETAIL_LIMIT - 1) + "…"


def test_a_non_string_detail_is_not_recorded():
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail={"unexpected": "object"}
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.reason_code == C.RATE_LIMITED
    assert "error_detail" not in record.details


def test_bounded_error_detail_handles_untrusted_input():
    assert epss.bounded_error_detail("") == ""
    assert epss.bounded_error_detail(None) == ""
    assert epss.bounded_error_detail(1234) == ""
    assert epss.bounded_error_detail(["a", "b"]) == ""
    assert epss.bounded_error_detail("  two   words \n") == "two words"


def test_an_unreachable_source_keeps_its_classification_and_gains_no_verdict():
    transport = FakeTransport().add_error(
        epss_url(DAY),
        reason="UNREACHABLE",
        detail="<urlopen error [Errno -2] Name or service not known>",
    )
    record = epss.acquire_daily(transport, DAY)

    # Behaviour that must not change: an outage is UNAVAILABLE, never an absence
    # of exploitation and never a policy refusal.
    assert record.content_status == C.UNAVAILABLE
    assert record.reason_code == C.OFFICIAL_SOURCE_UNREACHABLE
    assert record.details["error"] == "UNREACHABLE"
    assert record.details["error_detail"].startswith("<urlopen error")
    assert record.sha256 is None


def test_an_unreachable_source_without_detail_adds_no_field():
    transport = FakeTransport().add_error(epss_url(DAY), reason="UNREACHABLE")
    record = epss.acquire_daily(transport, DAY)

    assert record.reason_code == C.OFFICIAL_SOURCE_UNREACHABLE
    assert "error_detail" not in record.details


def test_a_refused_redirect_keeps_its_classification():
    transport = FakeTransport().add_error(
        epss_url(DAY),
        reason="DISALLOWED_REDIRECT_HOST",
        status=302,
        detail="allowed hosts: api.github.com, epss.empiricalsecurity.com",
    )
    record = epss.acquire_daily(transport, DAY)

    # A policy refusal is still BLOCKED/REDIRECT_BLOCKED, not a publisher outage.
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.REDIRECT_BLOCKED
    assert record.details["error"] == "DISALLOWED_REDIRECT_HOST"
    assert record.sha256 is None
    # The diagnostic is bounded like every other detail, and says what was refused.
    assert len(record.details["error_detail"]) <= epss.ERROR_DETAIL_LIMIT


def test_a_404_is_still_a_missing_daily_file():
    transport = FakeTransport().add_error(
        epss_url(DAY), reason="HTTP_ERROR", status=404, detail="Not Found"
    )
    record = epss.acquire_daily(transport, DAY)

    assert record.reason_code == C.EPSS_FILE_MISSING
    assert record.http_status == 404
    assert record.details["error_detail"] == "Not Found"


# ----------------------------------------------- end to end through transport
class _StubOpener:
    """An opener that raises a scripted error, used instead of a socket."""

    def __init__(self, error):
        self.error = error
        self.requested: list[str] = []

    def open(self, request, timeout=None):  # noqa: ARG002 - urllib signature
        self.requested.append(request.full_url)
        raise self.error


def test_a_403_body_reaches_the_record_through_the_real_transport():
    """The transport's 400-byte excerpt must survive into the record.

    This is the half that was missing before the patch: ``UrllibTransport``
    captured the body, and ``_record_error`` dropped it.
    """
    url = epss_url(DAY)
    error = urllib.error.HTTPError(
        url, 403, "Forbidden", {}, io.BytesIO(b"<html>Access Denied</html>")
    )
    transport = UrllibTransport(clock=lambda: "2026-10-20T10:00:00Z")
    transport._opener = _StubOpener(error)

    record = epss.acquire_daily(transport, DAY)

    assert record.request_url == url
    assert record.http_status == 403
    assert record.reason_code == C.RATE_LIMITED
    assert record.retrieved_at == "2026-10-20T10:00:00Z"
    assert record.details["error_detail"] == "<html>Access Denied</html>"
    assert record.sha256 is None


def test_the_real_transport_excerpt_is_already_bounded_by_400_bytes():
    url = epss_url(DAY)
    body = b"D" * 900
    error = urllib.error.HTTPError(url, 429, "Too Many Requests", {}, io.BytesIO(body))
    transport = UrllibTransport(clock=lambda: "2026-10-20T10:00:00Z")
    transport._opener = _StubOpener(error)

    record = epss.acquire_daily(transport, DAY)

    assert record.http_status == 429
    assert record.details["error_detail"] == "D" * 400
    assert len(record.details["error_detail"]) == epss.ERROR_DETAIL_LIMIT


def test_the_record_is_json_serialisable_after_the_change():
    import json

    transport = FakeTransport().add_error(
        epss_url(DAY), reason="RATE_LIMITED", status=403, detail="blocked\nby edge"
    )
    payload = json.dumps(epss.acquire_daily(transport, DAY).as_dict(), sort_keys=True)

    assert "error_detail" in payload
    assert "blocked by edge" in payload
