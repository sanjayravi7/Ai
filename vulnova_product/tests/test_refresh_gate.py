"""The maturity gate: calendar maturity is not observability.

These tests pin the boundary that VULNOVA 1.8 exists to defend.  On the maturity
date itself a catalog released the day before is still censored; only a catalog
released on or after that date may be filtered by ``dateAdded``.
"""

from __future__ import annotations

import datetime as dt

from vulnova.refresh import constants as C
from vulnova.refresh.gate import (
    CatalogFacts,
    catalog_facts,
    evaluate_gate,
    filter_entries_by_date_added,
    gate_summary,
)

FINAL = dt.date(2026, 4, 1)
MATURITY = dt.date(2026, 10, 28)


def _catalog(released_day: dt.date, *, verified: bool = True) -> CatalogFacts:
    return CatalogFacts(
        available=True,
        key="current#github",
        channel="OFFICIAL_GITHUB",
        catalog_version="2026.10.16",
        released=f"{released_day.isoformat()}T06:00:00Z",
        released_day=released_day,
        parsed_count=3,
        declared_count=3,
        sha256="a" * 64,
        content_status="VERIFIED" if verified else "BLOCKED",
        reason_code="OK_VERIFIED" if verified else "MALFORMED_RESPONSE",
    )


# ------------------------------------------------------------------ calendar
def test_gate_is_closed_before_the_maturity_date():
    gate = evaluate_gate(FINAL, as_of=dt.date(2026, 10, 20), catalog=_catalog(MATURITY))
    assert gate.maturity_date == MATURITY
    assert gate.calendar_matured is False
    assert gate.days_remaining == 8
    assert gate.status == C.GATE_NOT_MATURED
    assert gate.reason_code == C.MATURITY_NOT_REACHED
    assert gate.matured is False
    assert gate.filter_applied is False
    assert gate.filter_basis == C.RIGHT_CENSORED_NOT_FILTERED
    assert gate.as_dict()["maturity_claimed"] is False


def test_gate_never_claims_maturity_early_even_if_a_catalog_is_dated_later():
    # A catalog cannot be released after the run that retrieved it; the guard
    # must hold whatever the artifact says.
    gate = evaluate_gate(
        FINAL, as_of=dt.date(2026, 10, 20), catalog=_catalog(dt.date(2026, 10, 29))
    )
    assert gate.catalog_observes_maturity is True
    assert gate.matured is False
    assert gate.status == C.GATE_NOT_MATURED


def test_gate_closes_on_the_maturity_date_but_the_stale_catalog_still_censors():
    gate = evaluate_gate(FINAL, as_of=MATURITY, catalog=_catalog(dt.date(2026, 10, 16)))
    assert gate.calendar_matured is True
    assert gate.days_remaining == 0
    assert gate.catalog_observes_maturity is False
    assert gate.status == C.GATE_MATURED_SOURCE_PREDATES
    assert gate.reason_code == "CATALOG_PREDATES_MATURITY"
    assert gate.secondary_reason == C.RIGHT_CENSORED_NOT_FILTERED
    assert gate.matured is False
    assert gate.filter_applied is False


def test_gate_opens_on_the_maturity_date_with_a_catalog_released_that_day():
    gate = evaluate_gate(FINAL, as_of=MATURITY, catalog=_catalog(MATURITY))
    assert gate.status == C.GATE_MATURED_OBSERVED
    assert gate.reason_code == "OK_VERIFIED"
    assert gate.matured is True
    assert gate.filter_applied is True
    assert gate.filter_basis == C.FILTERED_BY_DATE_ADDED


def test_gate_stays_open_after_maturity_with_a_later_catalog():
    gate = evaluate_gate(
        FINAL, as_of=dt.date(2026, 11, 5), catalog=_catalog(dt.date(2026, 10, 29))
    )
    assert gate.status == C.GATE_MATURED_OBSERVED
    assert gate.days_remaining == -8
    assert gate.matured is True


def test_gate_reports_a_missing_catalog_after_maturity():
    gate = evaluate_gate(FINAL, as_of=MATURITY, catalog=None)
    assert gate.status == C.GATE_MATURED_SOURCE_MISSING
    assert gate.reason_code == "NO_RECORDS"
    assert gate.matured is False


def test_gate_treats_a_record_without_a_source_timestamp_as_unobservable():
    facts = CatalogFacts(
        available=True,
        key="current#github",
        channel="OFFICIAL_GITHUB",
        released=None,
        released_day=None,
        content_status="VERIFIED",
        reason_code="OK_VERIFIED",
    )
    gate = evaluate_gate(FINAL, as_of=MATURITY, catalog=facts)
    assert gate.catalog_observes_maturity is False
    assert gate.status == C.GATE_MATURED_SOURCE_PREDATES


def test_gate_ignores_a_record_that_is_not_verified():
    gate = evaluate_gate(
        FINAL, as_of=MATURITY, catalog=_catalog(MATURITY, verified=False)
    )
    assert gate.catalog_available is False
    assert gate.status == C.GATE_MATURED_SOURCE_MISSING


def test_catalog_facts_reject_an_unparseable_release_time():
    class _Record:
        key = "current#github"
        channel = "OFFICIAL_GITHUB"
        revision = "0" * 40
        source_timestamp = "not-a-timestamp"
        sha256 = "b" * 64
        artifact_path = "kev/current/x.json"
        retrieved_at = "2026-10-20T09:00:00Z"
        request_url = "https://example.invalid/x"
        final_url = None
        content_status = "VERIFIED"
        reason_code = "OK_VERIFIED"
        details: dict = {}

    facts = catalog_facts(_Record())
    assert facts.released == "not-a-timestamp"
    assert facts.released_day is None


# -------------------------------------------------------------------- filter
def test_filter_does_not_run_when_the_gate_is_closed():
    result = filter_entries_by_date_added(
        [{"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"}],
        maturity=MATURITY,
        applied=False,
    )
    assert result.applied is False
    assert result.basis == C.RIGHT_CENSORED_NOT_FILTERED
    assert result.entries_total is None
    assert "not an observed" not in result.note  # it makes no claim at all
    assert result.reason_code == C.RIGHT_CENSORED_NOT_FILTERED


def test_filter_counts_entries_at_or_before_maturity():
    entries = [
        {"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"},
        {"cveID": "CVE-2025-2", "dateAdded": "2025-03-01"},
        {"cveID": "CVE-2026-3", "dateAdded": MATURITY.isoformat()},
        {"cveID": "CVE-2026-4", "dateAdded": "2026-10-29"},
        {"cveID": "CVE-2026-5", "dateAdded": "2026-11-15"},
    ]
    result = filter_entries_by_date_added(entries, maturity=MATURITY, applied=True)
    assert result.applied is True
    assert result.trustworthy is True
    assert result.entries_total == 5
    assert result.entries_observable == 3
    assert result.entries_after_maturity == 2
    assert result.entries_invalid == 0
    assert result.basis == C.FILTERED_BY_DATE_ADDED
    assert result.sample_after_maturity == ["CVE-2026-4", "CVE-2026-5"]
    assert "lower bound" in result.note


def test_filter_marks_a_view_untrustworthy_when_a_date_added_is_invalid():
    entries = [
        {"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"},
        {"cveID": "CVE-2024-2"},
        {"cveID": "CVE-2024-3", "dateAdded": "01/01/2024"},
    ]
    result = filter_entries_by_date_added(entries, maturity=MATURITY, applied=True)
    assert result.applied is True
    assert result.trustworthy is False
    assert result.entries_invalid == 2
    assert result.basis == C.DATE_ADDED_INVALID
    assert result.reason_code == C.DATE_ADDED_INVALID
    assert "not trusted" in result.note


def test_filter_of_an_empty_catalog_is_empty_not_verified():
    result = filter_entries_by_date_added([], maturity=MATURITY, applied=True)
    assert result.entries_total == 0
    assert result.entries_observable == 0
    assert result.trustworthy is True


# ------------------------------------------------------------------- summary
def test_gate_summary_reports_the_worst_block():
    gates = [
        evaluate_gate(dt.date(2025, 2, 1), as_of=MATURITY, catalog=_catalog(MATURITY)),
        evaluate_gate(dt.date(2025, 9, 1), as_of=MATURITY, catalog=_catalog(MATURITY)),
        evaluate_gate(FINAL, as_of=MATURITY, catalog=_catalog(dt.date(2026, 10, 16))),
    ]
    summary = gate_summary(gates)
    assert summary["all_calendar_matured"] is True
    assert summary["all_maturity_observable"] is False
    assert summary["final_block_maturity_observable"] is False
    assert summary["worst_status"] == C.GATE_MATURED_SOURCE_PREDATES
    assert summary["final_days_remaining"] == 0
