"""Prospective capture: what is recorded, and what is never claimed.

Every test drives the real ``run_capture`` against canned responses.  No test
opens a socket, reads the system clock, or depends on a source being reachable.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from vulnova.acquisition import constants as A
from vulnova.prospective import constants as C
from vulnova.prospective.capture import CaptureError, run_capture
from vulnova.prospective.store import ProspectiveStore

from tests.acquisition_fixtures import epss_url, kev_catalog_bytes
from tests.prospective_fixtures import (
    CVE_LATEST_URL,
    CVE_REVISION,
    DEFAULT_AS_OF,
    DEFAULT_RETRIEVED,
    KEV_RELEASED,
    build_scenario,
)


def _requirements(run: dict) -> dict:
    return {requirement["id"]: requirement for requirement in run["requirements"]}


def _records(run: dict, source: str) -> list[dict]:
    return [record for record in run["records"] if record["source"] == source]


# ------------------------------------------------------------------ complete
def test_a_complete_capture_verifies_all_three_sources(tmp_path):
    scenario = build_scenario(tmp_path)
    result = run_capture(scenario.options())
    run = result["run"]

    assert result["outcome"] == C.OUTCOME_CAPTURED
    assert run["summary"]["capture_status"] == A.VERIFIED
    assert run["summary"]["sources_verified"] == 3
    assert run["summary"]["partial_capture"] is False
    for requirement in run["requirements"]:
        assert requirement["status"] == A.VERIFIED, requirement

    artifacts = {record["artifact_path"] for record in run["records"] if record.get("artifact_path")}
    assert len(artifacts) == 3
    for relative in artifacts:
        assert (scenario.store_root / relative).is_file()


def test_the_direct_feed_is_preferred_when_both_channels_verify(tmp_path):
    scenario = build_scenario(tmp_path, direct_feed=True)
    run = run_capture(scenario.options())["run"]
    assert run["summary"]["selected_kev"]["channel"] == A.CHANNEL_OFFICIAL
    assert len(_records(run, "kev")) == 2


def test_a_failed_direct_feed_keeps_both_attempts_and_selects_github(tmp_path):
    scenario = build_scenario(tmp_path, direct_feed=False)
    run = run_capture(scenario.options())["run"]

    kev = _requirements(run)["KEV-CAPTURE"]
    assert kev["status"] == A.VERIFIED
    assert run["summary"]["selected_kev"]["channel"] == A.CHANNEL_OFFICIAL_GITHUB
    assert len(kev["records"]) == 2
    assert "OFFICIAL_SOURCE_UNREACHABLE" in kev["detail"]


def test_the_run_records_real_retrieval_and_source_timestamps_separately(tmp_path):
    scenario = build_scenario(tmp_path)
    run = run_capture(scenario.options())["run"]
    for record in _records(run, "kev"):
        assert record["retrieved_at"] == DEFAULT_RETRIEVED
        assert record["source_timestamp"] == KEV_RELEASED
        assert record["retrieved_at"] != record["source_timestamp"]
        assert record["access_provenance"] == A.CONTEMPORANEOUS
        assert record["historical_retrieval_verified"] is False


def test_a_prospective_record_never_carries_a_historical_cutoff(tmp_path):
    scenario = build_scenario(tmp_path)
    run = run_capture(scenario.options())["run"]
    for record in run["records"]:
        assert record["cutoff"] is None
        assert record["details"]["prospective"] is True
        assert record["details"]["observation_date"] == "2026-10-20"


def test_cvelistv5_records_a_revision_without_a_clone(tmp_path):
    scenario = build_scenario(tmp_path)
    run = run_capture(scenario.options())["run"]
    record = _records(run, "cvelistv5")[0]
    assert record["revision"] == CVE_REVISION
    assert record["details"]["clone_required"] is False
    assert record["details"]["revision_identifier"].startswith("git commit sha")
    assert record["artifact_path"].startswith("artifacts/cvelistv5/")


# ------------------------------------------------------------------- EPSS
def test_a_missing_epss_file_is_unavailable_not_absence_of_risk(tmp_path):
    scenario = build_scenario(tmp_path, epss="unavailable")
    run = run_capture(scenario.options())["run"]

    assert run["summary"]["capture_status"] == A.UNAVAILABLE
    assert run["summary"]["sources_verified"] == 2
    epss = _requirements(run)["EPSS-CAPTURE"]
    assert epss["status"] == A.UNAVAILABLE
    # The publisher did not answer at all.  That is an outage, not a statement
    # that the file does not exist.
    assert epss["reason_code"] == A.OFFICIAL_SOURCE_UNREACHABLE
    # A gap in observation must not be written up as a negative label.
    assert "not_exploited" not in json.dumps(run).lower()
    assert "absence_is_not_evidence" in run["honesty"]
    assert "gap in observation" in run["summary"]["note"]


def test_a_404_is_reported_as_a_missing_daily_file(tmp_path):
    scenario = build_scenario(tmp_path, epss="missing")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["content_status"] == A.UNAVAILABLE
    assert record["reason_code"] == A.EPSS_FILE_MISSING
    assert record["http_status"] == 404


def test_an_empty_epss_response_is_unavailable(tmp_path):
    scenario = build_scenario(tmp_path, epss="empty")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["content_status"] == A.UNAVAILABLE
    assert record["reason_code"] == A.EPSS_FILE_MISSING
    assert record["artifact_path"] is None


def test_a_malformed_epss_response_is_unavailable(tmp_path):
    scenario = build_scenario(tmp_path, epss="malformed")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["content_status"] == A.UNAVAILABLE
    assert record["reason_code"] == A.MALFORMED_RESPONSE
    assert record["artifact_path"] is None


def test_a_score_date_mismatch_is_never_substituted(tmp_path):
    scenario = build_scenario(tmp_path, epss="mismatch")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["content_status"] == A.UNAVAILABLE
    assert record["reason_code"] == A.SCORE_DATE_MISMATCH
    # The bytes were inspected but not filed as the requested day's evidence.
    assert record["artifact_path"] is None
    assert record["details"]["file_score_date"] == "2026-10-01"


# ---------------------------------------------------------------- redirects
def test_a_same_host_redirect_records_both_urls(tmp_path):
    redirect = (
        "https://epss.empiricalsecurity.com/daily/epss_scores-2026-10-20.csv.gz"
    )
    scenario = build_scenario(tmp_path, epss_redirect=redirect)
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["request_url"] == (
        "https://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz"
    )
    assert record["final_url"] == redirect
    assert record["content_status"] == A.VERIFIED


def test_a_cross_host_redirect_to_the_publisher_docs_is_blocked(tmp_path):
    """www.first.org is FIRST's documentation site, not an EPSS data endpoint.

    No observed response shows the data endpoint redirecting there, so the
    attempt is refused rather than trusted.  This goes through
    ``PolicyTransport``, which applies the real host policy, so the refusal
    happens *before the hop is issued*: no follow-up response exists, and the
    record honestly carries no ``final_url`` at all.
    """
    redirect = "https://www.first.org/epss/epss_scores-2026-10-20.csv.gz"
    scenario = build_scenario(tmp_path, epss_redirect=redirect)
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["request_url"] == (
        "https://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz"
    )
    assert record["content_status"] == A.BLOCKED
    assert record["reason_code"] == A.REDIRECT_BLOCKED
    assert record["details"]["error"] == "DISALLOWED_REDIRECT_HOST"
    assert record["sha256"] is None
    assert record["artifact_path"] is None
    # The refused destination was never requested, so nothing answered it.
    assert "final_url" not in record
    assert run["summary"]["capture_status"] == A.BLOCKED


def test_a_redirect_to_an_unapproved_host_is_blocked(tmp_path):
    scenario = build_scenario(
        tmp_path, epss_redirect="https://evil.example/epss_scores-2026-10-20.csv.gz"
    )
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["content_status"] == A.BLOCKED
    assert record["reason_code"] == A.REDIRECT_BLOCKED
    assert run["summary"]["capture_status"] == A.BLOCKED


def test_an_https_downgrade_is_blocked(tmp_path):
    scenario = build_scenario(
        tmp_path, epss_redirect="http://epss.empiricalsecurity.com/epss_scores-2026-10-20.csv.gz"
    )
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["content_status"] == A.BLOCKED
    assert record["reason_code"] == A.REDIRECT_BLOCKED


# ------------------------------------------------------------- timestamps
def test_a_source_timestamp_after_retrieval_is_corrupt(tmp_path):
    future = kev_catalog_bytes("2026.10.21", "2026-10-20T15:00:00Z")
    scenario = build_scenario(tmp_path, kev_body=future)
    run = run_capture(scenario.options())["run"]
    for record in _records(run, "kev"):
        assert record["content_status"] == A.BLOCKED
        assert record["reason_code"] == A.RETRIEVAL_BEFORE_SOURCE_TIME
    assert _requirements(run)["KEV-CAPTURE"]["status"] == A.BLOCKED


# ---------------------------------------------------------------- partial
def test_a_partial_capture_is_never_upgraded_to_success(tmp_path):
    scenario = build_scenario(tmp_path, epss="unavailable")
    run = run_capture(scenario.options())["run"]
    assert run["summary"]["partial_capture"] is True
    assert run["summary"]["capture_status"] != A.VERIFIED


def test_all_sources_failing_produces_no_fabricated_evidence(tmp_path):
    scenario = build_scenario(
        tmp_path, direct_feed=False, github=False, epss="unavailable", cve="unavailable"
    )
    run = run_capture(scenario.options())["run"]

    assert run["summary"]["capture_status"] == A.UNAVAILABLE
    assert run["summary"]["sources_verified"] == 0
    for record in run["records"]:
        assert record["content_status"] != A.VERIFIED
        assert record["artifact_path"] is None
    artifacts = scenario.store_root / "artifacts"
    assert not artifacts.exists() or not any(artifacts.rglob("*"))
    # The run itself is still recorded: a failed attempt is evidence of an
    # attempt, never evidence of absence.
    assert (scenario.store_root / "runs").is_dir()


def test_a_malformed_github_catalog_is_blocked(tmp_path):
    scenario = build_scenario(
        tmp_path, direct_feed=False, kev_body=kev_catalog_bytes("2026.10.16", "2026-10-16T17:15:48Z", declared=9)
    )
    run = run_capture(scenario.options())["run"]
    kev = _requirements(run)["KEV-CAPTURE"]
    assert kev["status"] == A.BLOCKED
    assert kev["reason_code"] == A.TRUNCATED_CATALOG


# ---------------------------------------------------------------- repeat
def test_repeating_the_same_capture_is_idempotent(tmp_path):
    scenario = build_scenario(tmp_path)
    first = run_capture(scenario.options())
    second = run_capture(scenario.options())

    assert first["outcome"] == C.OUTCOME_CAPTURED
    assert second["outcome"] == C.OUTCOME_ALREADY_CAPTURED
    assert first["run"]["run_id"] == second["run"]["run_id"]
    assert len(list((scenario.store_root / "runs").glob("*.json"))) == 1


def test_a_different_capture_on_the_same_date_is_preserved(tmp_path):
    scenario = build_scenario(tmp_path)
    first = run_capture(scenario.options())

    second_scenario = build_scenario(
        tmp_path / "second",
        kev_body=kev_catalog_bytes("2026.10.17", "2026-10-17T17:15:48Z"),
    )
    # Same store and clock, different bytes: a distinct run id, written beside.
    second_scenario.store_root = scenario.store_root
    second = run_capture(second_scenario.options())

    assert second["run"]["run_id"] != first["run"]["run_id"]
    assert len(list((scenario.store_root / "runs").glob("*.json"))) == 2


# ---------------------------------------------------------------- integrity
def test_a_verified_record_without_bytes_is_refused(tmp_path, monkeypatch):
    scenario = build_scenario(tmp_path)
    store = ProspectiveStore(scenario.store_root)

    def missing(relative):
        return None

    monkeypatch.setattr(store, "artifact_digest", missing)
    from vulnova.prospective import capture as capture_module

    monkeypatch.setattr(capture_module, "ProspectiveStore", lambda root: store)
    with pytest.raises(CaptureError) as excinfo:
        run_capture(scenario.options())
    assert "not stored" in str(excinfo.value)


def test_the_run_record_is_written_once_and_is_valid_json(tmp_path):
    scenario = build_scenario(tmp_path)
    result = run_capture(scenario.options())
    body = (scenario.store_root / result["run_path"]).read_bytes()
    payload = json.loads(body)
    assert payload["run_digest"] == result["run"]["run_digest"]
    assert payload["schema_version"] == C.SCHEMA_VERSION


def test_the_default_as_of_is_used_for_the_epss_url(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    assert any("epss_scores-2026-10-20" in call for call in scenario.transport.calls)
    assert DEFAULT_AS_OF.startswith("2026-10-20")


# ------------------------------------------------------- cvelistV5 specifics
def test_cvelistv5_capture_reads_one_endpoint_and_clones_nothing(tmp_path):
    from vulnova.acquisition.sources import cvelistv5 as cve_source

    scenario = build_scenario(tmp_path)
    record = cve_source.capture_current(scenario.api)
    assert record.content_status == A.VERIFIED
    assert scenario.transport.calls == [CVE_LATEST_URL]
    assert record.details["clone_required"] is False


def test_an_empty_cvelistv5_commit_list_is_unavailable(tmp_path):
    scenario = build_scenario(tmp_path, cve="empty")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "cvelistv5")[0]
    assert record["content_status"] == A.UNAVAILABLE
    assert record["reason_code"] == A.REVISION_NOT_FOUND
    assert run["summary"]["capture_status"] == A.UNAVAILABLE


def test_a_malformed_cvelistv5_revision_is_blocked(tmp_path):
    scenario = build_scenario(tmp_path, cve="malformed")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "cvelistv5")[0]
    assert record["content_status"] == A.BLOCKED
    assert record["reason_code"] == A.MALFORMED_RESPONSE
    assert run["summary"]["capture_status"] == A.BLOCKED


def test_an_unreachable_cvelistv5_api_is_unavailable(tmp_path):
    scenario = build_scenario(tmp_path, cve="unavailable")
    run = run_capture(scenario.options())["run"]
    record = _records(run, "cvelistv5")[0]
    assert record["content_status"] == A.UNAVAILABLE
    assert record["reason_code"] == A.OFFICIAL_SOURCE_UNREACHABLE


# ---------------------------------------------------------------- KEV specifics
def test_an_empty_catalog_is_refused_on_both_channels(tmp_path):
    from tests.acquisition_fixtures import kev_catalog_bytes

    empty = kev_catalog_bytes("2026.10.16", "2026-10-16T17:15:48Z", count=0)
    scenario = build_scenario(tmp_path, kev_body=empty)
    run = run_capture(scenario.options())["run"]

    kev = _requirements(run)["KEV-CAPTURE"]
    assert kev["status"] == A.BLOCKED
    assert kev["reason_code"] == A.NO_RECORDS
    assert all(
        record["artifact_path"] is None
        for record in _records(run, "kev")
        if record["content_status"] != A.VERIFIED
    )


# -------------------------------------------------------------- EPSS mode
def test_epss_prospective_capture_records_no_historical_cutoff(tmp_path):
    scenario = build_scenario(tmp_path)
    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]
    assert record["cutoff"] is None
    assert record["details"]["historical_cutoff"] is False
    assert record["sha256"]
    assert record["details"]["file_score_date"] == "2026-10-20"
    assert record["source_timestamp"] != record["retrieved_at"]


def test_acquire_daily_keeps_its_historical_default():
    import inspect

    from vulnova.acquisition.sources import epss as epss_source

    signature = inspect.signature(epss_source.acquire_daily)
    assert signature.parameters["historical"].default is True


# ------------------------------------------------------- defensive failures
def test_a_clock_that_moves_backwards_is_refused(tmp_path):
    scenario = build_scenario(tmp_path)
    ticks = iter([DEFAULT_AS_OF, "2026-10-20T13:00:00Z"])
    with pytest.raises(CaptureError) as excinfo:
        run_capture(scenario.options(clock=lambda: next(ticks)))
    assert "moved backwards" in str(excinfo.value)


def test_a_clock_that_is_not_iso_is_refused(tmp_path):
    scenario = build_scenario(tmp_path)
    with pytest.raises(CaptureError) as excinfo:
        run_capture(scenario.options(clock=lambda: "yesterday"))
    assert "non-ISO" in str(excinfo.value)


def test_the_fixture_epss_file_is_byte_stable():
    """Captured bytes must not depend on when the fixture was built.

    ``gzip.compress`` embeds the current time in its header by default, which
    made every captured EPSS artifact -- and every run and report digest --
    differ between runs of the same test.
    """
    import datetime as dt

    from tests.acquisition_fixtures import epss_bytes

    day = dt.date(2026, 10, 20)
    assert epss_bytes(day) == epss_bytes(day, model="v2026.06.15")
    assert epss_bytes(day) == epss_bytes(day)


def test_a_store_with_a_file_where_a_directory_belongs_fails_cleanly(tmp_path):
    scenario = build_scenario(tmp_path)
    scenario.store_root.mkdir(parents=True)
    (scenario.store_root / "artifacts").write_text("not a directory")
    with pytest.raises(CaptureError) as excinfo:
        run_capture(scenario.options())
    assert "cannot create the directory" in str(excinfo.value)


def test_a_run_directory_that_is_a_file_fails_cleanly(tmp_path):
    scenario = build_scenario(tmp_path)
    scenario.store_root.mkdir(parents=True)
    (scenario.store_root / "runs").write_text("not a directory")
    with pytest.raises(CaptureError) as excinfo:
        run_capture(scenario.options())
    assert "run record" in str(excinfo.value)


def test_a_catalog_with_an_unparseable_release_time_is_blocked_not_a_crash(tmp_path):
    body = json.dumps(
        {
            "catalogVersion": "2026.10.16",
            "dateReleased": "last Tuesday",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2024-0001"}],
        }
    ).encode()
    scenario = build_scenario(tmp_path, kev_body=body)
    run = run_capture(scenario.options())["run"]
    kev = _requirements(run)["KEV-CAPTURE"]
    assert kev["status"] == A.BLOCKED
    assert kev["reason_code"] == A.SOURCE_TIMESTAMP_MISSING


def test_a_non_object_cvelist_commit_is_blocked_not_a_crash(tmp_path):
    from vulnova.acquisition.github import GitHubApi
    from vulnova.acquisition.sources import cvelistv5 as cve_source
    from vulnova.acquisition.transport import FakeTransport

    transport = FakeTransport().add_json(
        CVE_LATEST_URL, ["not a commit"], retrieved_at=DEFAULT_RETRIEVED
    )
    record = cve_source.capture_current(GitHubApi(transport))
    assert record.content_status == A.BLOCKED
    assert record.reason_code == A.MALFORMED_RESPONSE


def test_an_offset_clock_is_normalised_to_the_utc_observation_date(tmp_path):
    scenario = build_scenario(tmp_path)
    run = run_capture(
        scenario.options(clock=lambda: "2026-10-20T23:30:00-05:00")
    )["run"]
    # 2026-10-20T23:30:00-05:00 is 2026-10-21T04:30:00Z.
    assert run["observation_date"] == "2026-10-21"
    assert run["capture_started_at"] == "2026-10-20T23:30:00-05:00"
    assert any("epss_scores-2026-10-21" in call for call in scenario.transport.calls)


def test_a_rate_limited_epss_failure_keeps_a_bounded_detail_in_the_run_record(tmp_path):
    """The detail must survive the whole path: transport → source → run record.

    Before this patch the stored run kept ``403`` and ``RATE_LIMITED`` and lost
    the response text, which is exactly the evidence that would say whether the
    publisher rate-limited us or a WAF refused the request.
    """
    scenario = build_scenario(tmp_path)
    observation = dt.date.fromisoformat(DEFAULT_AS_OF[:10])
    scenario.transport.add_error(
        epss_url(observation),
        reason="RATE_LIMITED",
        status=403,
        detail="<html>\n  <title>Access Denied</title>\n  Reference: 18.abc\n</html>",
    )

    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]

    assert record["http_status"] == 403
    assert record["reason_code"] == A.RATE_LIMITED
    assert record["content_status"] == A.UNAVAILABLE
    assert record["sha256"] is None
    assert record["artifact_path"] is None
    assert record["details"]["error"] == "RATE_LIMITED"
    assert record["details"]["error_detail"] == (
        "<html> <title>Access Denied</title> Reference: 18.abc </html>"
    )
    # The run remains a partial capture, never a success and never an absence.
    assert run["summary"]["capture_status"] == A.UNAVAILABLE
    assert "not_exploited" not in json.dumps(run).lower()


def test_a_rate_limit_without_a_body_stores_no_detail_field(tmp_path):
    scenario = build_scenario(tmp_path)
    observation = dt.date.fromisoformat(DEFAULT_AS_OF[:10])
    scenario.transport.add_error(
        epss_url(observation), reason="RATE_LIMITED", status=429
    )

    run = run_capture(scenario.options())["run"]
    record = _records(run, "epss")[0]

    assert record["http_status"] == 429
    assert record["reason_code"] == A.RATE_LIMITED
    assert "error_detail" not in record["details"]


def test_the_stored_run_verifies_after_a_failed_capture_with_a_detail(tmp_path):
    """A diagnostic field must not disturb the append-only store or its verifier."""
    from vulnova.prospective.verify import verify_failure_reasons, verify_store

    scenario = build_scenario(tmp_path)
    observation = dt.date.fromisoformat(DEFAULT_AS_OF[:10])
    scenario.transport.add_error(
        epss_url(observation), reason="RATE_LIMITED", status=403, detail="blocked"
    )

    run_capture(scenario.options())

    result = verify_store(scenario.store_root)
    assert result["status"] == A.VERIFIED
    assert verify_failure_reasons(result) == []
