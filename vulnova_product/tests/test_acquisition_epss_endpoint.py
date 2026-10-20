"""EPSS endpoint hotfix: the documented host, and only that host.

FIRST's current documentation names ``epss.empiricalsecurity.com`` as the daily
CSV host and publishes the current-file URL.  The date-specific filename pattern
``epss_scores-YYYY-MM-DD.csv.gz`` appeared on an older FIRST-hosted statistics
page (``www.first.org/epss/data_stats``) that now returns 404.  The legacy
``epss.cyentia.com`` host is no longer named by FIRST.

These tests pin the narrow behaviour the hotfix must not drift from:

* the exact-date request goes to the documented host and names the date;
* a valid file for that date verifies, and its ``score_date`` is the only
  accepted one;
* a redirect to an unapproved host, or a plaintext response, is ``BLOCKED`` --
  including through a transport that performs no policy checks of its own;
* a mirror or a newer score file is never substituted;
* the sealed historical evidence and the protocol are untouched.

Every response is canned.  No test opens a socket.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import pytest

from vulnova.acquisition import constants as C
from vulnova.acquisition.sources import epss
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import (
    DEFAULT_ALLOWED_HOSTS,
    FakeTransport,
    HostPolicy,
    HttpResponse,
    UrllibTransport,
)

from tests.acquisition_fixtures import CUTOFFS, epss_bytes, epss_url

DAY = CUTOFFS[0]
RETRIEVED = "2026-10-20T10:00:00Z"
PRODUCT_ROOT = Path(__file__).resolve().parents[1]

#: Recorded in the sealed 1.7 manifest and the sealed 1.8 report.  These are the
#: expected file digests, not values to recompute; a mismatch is an incident.
SEALED_FILES = {
    "reports/acquisition_1_7/acquisition_manifest.json": (
        "581696e799d7d6e9ed2353fda038b82f20c632d0f52d2997ea67674f3a8d2069"
    ),
    "reports/refresh_1_8/refresh_report.json": (
        "1fb6202ece9f8ec3dc4b989612c0f500e9dad8f8c46e014cdadf20f6adf71a2b"
    ),
    "protocol/evaluation_protocol.json": (
        "7b37e2bbe03fd5299d9fc5b785d5a2922769c7db4eaa093f4e495a15f3a9cdd6"
    ),
}


def _record(body, *, day=DAY, store=None):
    transport = FakeTransport().add_bytes(
        epss_url(day), body, content_type="application/gzip", retrieved_at=RETRIEVED
    )
    return epss.acquire_daily(transport, day, store=store), transport


# ------------------------------------------------------------------ endpoint
def test_the_documented_endpoint_is_the_one_constructed():
    assert epss.OFFICIAL_HOST == "epss.empiricalsecurity.com"
    assert (
        epss.official_url(DAY)
        == f"https://epss.empiricalsecurity.com/epss_scores-{DAY.isoformat()}.csv.gz"
    )


def test_the_official_endpoint_is_an_https_url_naming_the_exact_date():
    url = epss.official_url(dt.date(2026, 10, 20))
    assert url == "https://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz"
    assert url.startswith("https://")
    assert url.endswith("/epss_scores-2026-10-20.csv.gz")


def test_the_exact_date_request_targets_the_documented_host():
    """One request, for one date, to the documented host -- nothing else."""
    record, transport = _record(epss_bytes(DAY))
    assert transport.calls == [epss_url(DAY)]
    assert record.request_url == (
        f"https://epss.empiricalsecurity.com/epss_scores-{DAY.isoformat()}.csv.gz"
    )
    payload = record.as_dict()
    assert payload["request_url"] == payload["source_url"]
    assert "empiricalsecurity.com" in payload["request_url"]


def test_the_legacy_host_is_no_longer_requested_or_allowed():
    assert "epss.cyentia.com" not in DEFAULT_ALLOWED_HOSTS
    policy = HostPolicy(DEFAULT_ALLOWED_HOSTS)
    policy.check("https://epss.empiricalsecurity.com/x")
    with pytest.raises(Exception) as excinfo:
        policy.check("https://epss.cyentia.com/x")
    assert getattr(excinfo.value, "reason", None) == "DISALLOWED_HOST"


def test_the_source_endpoint_is_in_the_transport_allowlist():
    """The URL the source builds must pass the transport's own policy."""
    UrllibTransport().policy.check(epss.official_url(DAY))


# ------------------------------------------------------------- valid payload
def test_a_valid_file_for_the_requested_date_is_verified(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    record, _ = _record(epss_bytes(DAY), store=store)
    assert record.content_status == C.VERIFIED
    assert record.reason_code == C.OK_VERIFIED
    assert record.details["file_score_date"] == DAY.isoformat()
    assert record.details["requested_date"] == DAY.isoformat()
    assert record.http_status == 200
    assert store.exists(record.artifact_path)


def test_a_valid_response_for_another_date_is_not_substituted():
    newer = epss_bytes(dt.date(2026, 10, 16), score_date="2026-10-16T12:02:51Z")
    record, _ = _record(newer)
    assert record.content_status == C.UNAVAILABLE
    assert record.reason_code == C.SCORE_DATE_MISMATCH
    assert record.artifact_path is None


def test_a_mirror_is_never_fetched_or_promoted():
    """The archive on GitHub is described as official, but it is not the feed."""
    record = epss.mirror_record(DAY)
    assert record.channel == C.CHANNEL_THIRD_PARTY_MIRROR
    assert record.content_status == C.UNAVAILABLE
    assert record.reason_code == C.THIRD_PARTY_MIRROR_ONLY
    assert record.request_url == ""
    assert record.artifact_path is None
    assert record.sha256 is None


def test_a_missing_file_does_not_fall_back_to_a_newer_one():
    transport = FakeTransport().add_error(epss_url(DAY), reason="HTTP_ERROR", status=404)
    record = epss.acquire_daily(transport, DAY)
    assert record.content_status == C.UNAVAILABLE
    assert record.reason_code == C.EPSS_FILE_MISSING
    # Exactly one URL was requested: no "-current" file, no other date.
    assert transport.calls == [epss_url(DAY)]


# ----------------------------------------------------------------- redirects
def test_a_redirect_to_an_unapproved_host_is_blocked():
    transport = FakeTransport().add_bytes(
        epss_url(DAY),
        epss_bytes(DAY),
        content_type="application/gzip",
        retrieved_at=RETRIEVED,
        final_url="https://mirror.example/epss_scores-2026-10-20.csv.gz",
    )
    record = epss.acquire_daily(transport, DAY)
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.REDIRECT_BLOCKED
    assert record.details["error"] == "DISALLOWED_REDIRECT_HOST"
    # The refusal is visible in the record; the bytes were never hashed.
    assert record.final_url == "https://mirror.example/epss_scores-2026-10-20.csv.gz"
    assert record.sha256 is None
    assert record.artifact_path is None


def test_a_plaintext_response_is_blocked():
    transport = FakeTransport().add_bytes(
        epss_url(DAY),
        epss_bytes(DAY),
        content_type="application/gzip",
        retrieved_at=RETRIEVED,
        final_url="http://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz",
    )
    record = epss.acquire_daily(transport, DAY)
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.REDIRECT_BLOCKED
    assert record.details["error"] == "HTTPS_DOWNGRADE_BLOCKED"
    assert record.sha256 is None


def test_a_transport_without_its_own_policy_cannot_bypass_the_source_check():
    """``acquire_daily`` accepts any Transport; the source must not trust it."""
    transport = FakeTransport()  # no policy attached: it checks no hosts at all
    transport.add_bytes(
        epss_url(DAY),
        epss_bytes(DAY),
        content_type="application/gzip",
        retrieved_at=RETRIEVED,
        final_url="https://evil.example/epss_scores-2026-10-20.csv.gz",
    )
    assert transport.policy is None
    record = epss.acquire_daily(transport, DAY)
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.REDIRECT_BLOCKED


def test_a_same_host_redirect_is_allowed_and_both_urls_are_recorded():
    redirected = (
        f"https://epss.empiricalsecurity.com/daily/epss_scores-{DAY.isoformat()}.csv.gz"
    )
    transport = FakeTransport().add_bytes(
        epss_url(DAY),
        epss_bytes(DAY),
        content_type="application/gzip",
        retrieved_at=RETRIEVED,
        final_url=redirected,
    )
    record = epss.acquire_daily(transport, DAY)
    assert record.content_status == C.VERIFIED
    payload = record.as_dict()
    assert payload["request_url"] == epss_url(DAY)
    assert payload["final_url"] == redirected
    assert payload["request_url"] != payload["final_url"]


def test_a_redirect_to_the_publisher_documentation_site_is_refused():
    """FIRST's docs site is not an EPSS data endpoint and is not allowlisted.

    The transport here performs no policy checks, so this exercises the
    source-level rule: a plausible-sounding first-party host is still refused
    when nothing shows the data endpoint redirecting to it.
    """
    redirected = f"https://www.first.org/epss/epss_scores-{DAY.isoformat()}.csv.gz"
    transport = FakeTransport().add_bytes(
        epss_url(DAY),
        epss_bytes(DAY),
        content_type="application/gzip",
        retrieved_at=RETRIEVED,
        final_url=redirected,
    )
    record = epss.acquire_daily(transport, DAY)
    assert record.content_status == C.BLOCKED
    assert record.reason_code == C.REDIRECT_BLOCKED
    assert record.details["error"] == "DISALLOWED_REDIRECT_HOST"
    assert record.sha256 is None
    assert record.artifact_path is None


def test_response_url_problem_classifies_each_case():
    assert epss.response_url_problem(epss_url(DAY)) is None
    # The default HTTPS port, explicit, is the same destination.
    assert (
        epss.response_url_problem("https://epss.empiricalsecurity.com:443/x.csv.gz")
        is None
    )
    assert (
        epss.response_url_problem("https://www.first.org/x.csv.gz")
        == "DISALLOWED_REDIRECT_HOST"
    )
    assert (
        epss.response_url_problem("https://unknown.example/x.csv.gz")
        == "DISALLOWED_REDIRECT_HOST"
    )
    assert (
        epss.response_url_problem("http://epss.empiricalsecurity.com/x.csv.gz")
        == "HTTPS_DOWNGRADE_BLOCKED"
    )
    # A host that merely *ends* with the approved name is not approved.
    assert (
        epss.response_url_problem("https://epss.empiricalsecurity.com.evil.example/x")
        == "DISALLOWED_REDIRECT_HOST"
    )
    # Nor is the approved name used as a userinfo prefix for another host.
    assert (
        epss.response_url_problem("https://epss.empiricalsecurity.com@evil.example/x")
        == "DISALLOWED_REDIRECT_HOST"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://epss.empiricalsecurity.com:8443/epss_scores-2026-10-20.csv.gz",
        "https://epss.empiricalsecurity.com:80/epss_scores-2026-10-20.csv.gz",
        "https://epss.empiricalsecurity.com:0/epss_scores-2026-10-20.csv.gz",
        "https://epss.empiricalsecurity.com:99999999/x",
        "https://epss.empiricalsecurity.com:abc/x",
        "https://epss.empiricalsecurity.com:/x",
    ],
    ids=["8443", "80", "0", "out-of-range", "non-numeric", "empty-port"],
)
def test_a_non_default_or_malformed_port_is_refused(url):
    """Only the default HTTPS port, or no port at all, is the same destination."""
    assert epss.response_url_problem(url) == "DISALLOWED_REDIRECT_HOST"


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@epss.empiricalsecurity.com/x",
        "https://user@epss.empiricalsecurity.com/x",
        "https://evil.example@epss.empiricalsecurity.com/x",
        "https://user:secret@epss.empiricalsecurity.com:8443/x",
    ],
    ids=["user-and-password", "user-only", "lookalike-prefix", "user-and-port"],
)
def test_embedded_user_information_is_refused(url):
    """Credentials would also be persisted verbatim into the run record."""
    assert epss.response_url_problem(url) == "DISALLOWED_REDIRECT_HOST"


@pytest.mark.parametrize(
    "value",
    [None, 7, 3.5, b"https://epss.empiricalsecurity.com/x", ["x"], {"url": "x"}],
    ids=["none", "int", "float", "bytes", "list", "dict"],
)
def test_non_string_input_is_refused_without_raising(value):
    """The URL comes from an injectable transport; it is untrusted input."""
    assert epss.response_url_problem(value) == "DISALLOWED_REDIRECT_HOST"


@pytest.mark.parametrize(
    "url",
    [
        "https://[::1/x",  # malformed IPv6 authority
        "https://epss.empiricalsecurity.com%5C@evil.example/x",
        "https://epss.empiricalsecurity.com%2f@evil.example/x",
        "https://epss.empiricalsecurity.com%0A.evil.example/x",
        "https://epss.empiricalsecurity.com./x",
        "//epss.empiricalsecurity.com/x",
        "",
    ],
    ids=[
        "bad-ipv6",
        "encoded-backslash",
        "encoded-slash",
        "encoded-newline",
        "trailing-dot",
        "scheme-relative",
        "empty",
    ],
)
def test_malformed_or_ambiguous_urls_are_refused(url):
    """Ambiguity is refused wherever it would change the destination's meaning."""
    assert epss.response_url_problem(url) is not None


def test_an_insecure_initial_url_is_still_refused_by_the_real_transport():
    transport = UrllibTransport(clock=lambda: RETRIEVED)
    transport._opener = _NoOpen()  # must never be reached
    with pytest.raises(Exception) as excinfo:
        transport.get("http://epss.empiricalsecurity.com/x")
    assert getattr(excinfo.value, "reason", None) == "INSECURE_TRANSPORT"


class _NoOpen:
    def open(self, *args, **kwargs):  # pragma: no cover - the guard must fire first
        raise AssertionError("the opener must not be reached for a non-HTTPS URL")


# ----------------------------------------------------------- sealed evidence
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("relative, expected", sorted(SEALED_FILES.items()))
def test_sealed_evidence_and_protocol_are_untouched(relative, expected):
    path = PRODUCT_ROOT / relative
    assert path.is_file(), relative
    assert _sha256(path) == expected, (
        f"{relative} differs from its recorded digest; investigate, do not rewrite"
    )


def test_the_sealed_manifest_still_records_the_url_that_was_actually_requested():
    """History is not rewritten: the closed 1.7 run keeps its recorded URL."""
    manifest = json.loads(
        (PRODUCT_ROOT / "reports/acquisition_1_7/acquisition_manifest.json").read_text()
    )
    epss_records = [
        record for record in manifest["records"] if record["source"] == "epss"
    ]
    assert epss_records
    for record in epss_records:
        if record["request_url"]:
            assert record["request_url"].startswith(
                "https://epss.cyentia.com/epss_scores-"
            )


def test_the_protocol_is_still_not_approved():
    protocol = json.loads(
        (PRODUCT_ROOT / "protocol/evaluation_protocol.json").read_text()
    )
    assert protocol["approval"]["state"] == "NOT_APPROVED"


# ------------------------------------------------------------------ address
def test_the_source_allowlist_holds_exactly_the_documented_host():
    """The response allowlist is one host, and it is inside the transport's list."""
    assert epss.APPROVED_RESPONSE_HOSTS == (epss.OFFICIAL_HOST,)
    assert set(epss.APPROVED_RESPONSE_HOSTS) <= set(DEFAULT_ALLOWED_HOSTS)
    # Neither the legacy host nor the documentation site is a data endpoint.
    assert "epss.cyentia.com" not in epss.APPROVED_RESPONSE_HOSTS
    assert "www.first.org" not in epss.APPROVED_RESPONSE_HOSTS
    for host in ("epss.cyentia.com", "www.first.org"):
        assert host not in DEFAULT_ALLOWED_HOSTS


def test_a_canned_response_dataclass_defaults_final_url_to_the_request():
    response = HttpResponse(
        url=epss_url(DAY), status=200, headers={}, body=b"", retrieved_at=RETRIEVED
    )
    assert response.final_url == response.url
    assert response.redirected is False


# ------------------------------------------------- end-to-end capture path
def _epss_record(run: dict) -> dict:
    return next(record for record in run["records"] if record["source"] == "epss")


def test_a_prospective_capture_requests_the_documented_epss_endpoint(tmp_path):
    from vulnova.acquisition import constants as A
    from vulnova.prospective.capture import run_capture

    from tests.prospective_fixtures import build_scenario

    scenario = build_scenario(tmp_path)
    run = run_capture(scenario.options())["run"]
    record = _epss_record(run)
    assert record["request_url"] == (
        "https://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz"
    )
    assert record["content_status"] == A.VERIFIED
    urls = json.dumps(
        [
            {key: item.get(key) for key in ("request_url", "source_url", "final_url")}
            for item in run["records"]
        ]
    )
    assert "cyentia" not in urls
    # The one EPSS URL requested for the observation date is the only EPSS URL
    # the run consulted: no "-current" file and no other date.
    epss_calls = [url for url in scenario.transport.calls if "epss" in url]
    assert epss_calls == [
        "https://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz"
    ]


def test_a_blocked_epss_redirect_is_still_honest_evidence(tmp_path):
    """The reported defect's shape: EPSS BLOCKED, stored bytes still verify."""
    from vulnova.acquisition import constants as A
    from vulnova.prospective.capture import run_capture
    from vulnova.prospective.verify import verify_store

    from tests.prospective_fixtures import build_scenario

    scenario = build_scenario(
        tmp_path, epss_redirect="https://mirror.example/epss_scores-2026-10-20.csv.gz"
    )
    run = run_capture(scenario.options())["run"]
    record = _epss_record(run)
    assert record["content_status"] == A.BLOCKED
    assert record["reason_code"] == A.REDIRECT_BLOCKED
    assert run["summary"]["capture_status"] == A.BLOCKED
    assert run["summary"]["sources_verified"] == 2

    # Integrity is still verifiable: the run is an honest record of a refusal,
    # not a malformed one.  Nothing may claim the EPSS requirement was met.
    result = verify_store(scenario.store_root)
    assert result["status"] == A.VERIFIED
    requirement = next(
        item for item in run["requirements"] if item["id"] == "EPSS-CAPTURE"
    )
    assert requirement["status"] == A.BLOCKED


def test_a_preserved_legacy_capture_is_not_invalidated_or_repaired(tmp_path):
    """A store recorded before the hotfix must keep verifying as it was.

    The first real capture requested the legacy host and recorded EPSS
    ``BLOCKED``.  Changing the endpoint must not make that record fail
    verification (it is honest evidence) and must not rewrite it into a success.
    """
    from vulnova.acquisition import constants as A
    from vulnova.prospective.capture import _digest, run_capture, run_id_for
    from vulnova.prospective.verify import verify_store

    from tests.prospective_fixtures import build_scenario

    scenario = build_scenario(
        tmp_path, epss_redirect="https://mirror.example/epss_scores-2026-10-20.csv.gz"
    )
    run = run_capture(scenario.options())["run"]

    run_file = scenario.store_root / "runs" / f"{run['run_id']}.json"
    payload = json.loads(run_file.read_text())
    record = _epss_record(payload)
    record["request_url"] = (
        f"https://epss.cyentia.com/epss_scores-{DAY.isoformat()}.csv.gz"
    )
    record["source_url"] = record["request_url"]
    record["details"]["legacy_host"] = True

    payload.pop("run_digest", None)
    payload.pop("run_id", None)
    digest = _digest(payload)
    payload["run_digest"] = digest
    payload["run_id"] = run_id_for(payload["capture_started_at"], digest)
    run_file.unlink()
    new_file = scenario.store_root / "runs" / f"{payload['run_id']}.json"
    new_file.write_text(json.dumps(payload))

    result = verify_store(scenario.store_root)
    assert result["status"] == A.VERIFIED, [
        check for check in result["checks"] if check["status"] != A.VERIFIED
    ]
    stored = json.loads(new_file.read_text())
    assert _epss_record(stored)["content_status"] == A.BLOCKED
    assert _epss_record(stored)["reason_code"] == A.REDIRECT_BLOCKED
    # Nothing rewrote the file on disk: verification is read-only.
    assert json.loads(new_file.read_text()) == stored
