"""Explanation payloads: conflicts, adequacy, recency and provenance."""

from __future__ import annotations

import pytest

from vulnova import explain, store


def test_unknown_cve_returns_none(conn):
    assert explain.explain_one(conn, "CVE-1999-9999") is None


def test_payload_has_required_sections(conn):
    payload = explain.explain_one(conn, "CVE-2023-0001")
    assert set(payload) >= {
        "as_of", "cve_id", "record", "observed", "priority", "assessment",
        "publication_recency_context", "coverage", "provenance",
    }
    assert payload["as_of"] == "2026-10-16"
    assert payload["priority"]["method"].startswith("Provisional, rule-based")


def test_insufficient_evidence_is_surfaced(conn):
    payload = explain.explain_one(conn, "CVE-2023-0002")
    assert payload["assessment"]["status"] == "INSUFFICIENT_EVIDENCE"
    assert payload["assessment"]["review_required"] is True
    assert payload["priority"]["band"] == "P4_LOW"
    assert payload["priority"]["missing_signals"] == ["epss_probability", "cvss_severity"]


def test_conflicting_sources_are_all_present(conn):
    payload = explain.explain_one(conn, "CVE-2019-0005")
    cvss = payload["observed"]["cvss"]
    assert len(cvss["candidates"]) == 3
    assert cvss["conflict"]["has_conflict"] is True
    assert cvss["conflict"]["distinct_values"] == [6.8, 7.5, 9.8]
    assert cvss["conflict"]["comparable"] is False
    assert cvss["selected"]["source"] == "cvelistv5"
    assert cvss["selected"]["container"] == "cna"
    # every candidate keeps its own organisation and retrieval timestamp
    for cand in cvss["candidates"]:
        assert cand["retrieved_at"]
        assert "scoring_organization" in cand


def test_legacy_record_is_exposed_as_alternate_source(conn):
    payload = explain.explain_one(conn, "CVE-2019-0005")
    assert "legacy_cve_csv" in payload["record"]["sources"]
    assert payload["record"]["alternate_source_records"]
    assert any(
        alt["source"] == "legacy_cve_csv"
        for alt in payload["record"]["alternate_source_records"]
    )


def test_record_exposes_primary_source_and_state_basis(conn):
    payload = explain.explain_one(conn, "CVE-2023-0001")
    assert payload["record"]["source"] == "cvelistv5"
    assert payload["record"]["state"] == "PUBLISHED"
    assert payload["record"]["state_basis"] == "stated"


def test_conflicting_state_is_preserved_not_resolved(conn):
    """DEF-4: each source keeps its own state and basis.

    The cvelistV5 row states PUBLISHED; the legacy extract has no state column.
    Neither is used to overwrite the other, and the alternate record carries its
    own basis and retrieval timestamp.
    """
    conn.execute(
        "INSERT INTO cve_record (cve_id, source, source_revision, retrieved_at,"
        " published, updated, state, state_basis, reject_marker, assigner, title,"
        " description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("CVE-2023-0001", "legacy_cve_csv", None, "2026-10-17T00:00:01Z",
         "2023-06-01", "2023-06-01", None, "not_stated", 0, None, None,
         "Legacy copy."),
    )
    payload = explain.explain_one(conn, "CVE-2023-0001")
    assert payload["record"]["source"] == "cvelistv5"
    assert payload["record"]["state"] == "PUBLISHED"
    assert payload["record"]["state_basis"] == "stated"
    assert set(payload["record"]["sources"]) == {"cvelistv5", "legacy_cve_csv"}
    alternate = {
        alt["source"]: alt for alt in payload["record"]["alternate_source_records"]
    }["legacy_cve_csv"]
    assert alternate["state"] is None
    assert alternate["state_basis"] == "not_stated"
    assert alternate["retrieved_at"] == "2026-10-17T00:00:01Z"
    # both rows still exist independently; nothing was merged
    assert conn.execute(
        "SELECT COUNT(*) FROM cve_record WHERE cve_id='CVE-2023-0001'"
    ).fetchone()[0] == 2


def test_provenance_lists_only_sources_with_rows(conn):
    payload = explain.explain_one(conn, "CVE-2023-0001")
    assert payload["provenance"]["sources_present"] == ["cvelistv5", "epss"]
    assert "kev" not in payload["provenance"]["retrieved"]


def test_publication_recency_context_distinguishes_dates(conn):
    payload = explain.explain_one(conn, "CVE-2019-0005")
    context = payload["publication_recency_context"]
    assert context["component"] == "publication_recency"
    assert context["component_basis"] == "publication_date"
    assert context["kev_listing_date"] == "2026-10-08"
    assert context["days_since_kev_listing"] == 8
    assert "must not be described as having no recent activity" in context["statement"]


def test_publication_recency_states_what_it_does_not_represent(conn):
    context = explain.explain_one(conn, "CVE-2019-0005")["publication_recency_context"]
    assert context["does_not_represent"] == [
        "recent exploitation activity",
        "recent KEV inclusion",
        "an independently verified increase in threat activity",
    ]
    statement = context["statement"]
    assert "does not represent recent exploitation activity" in statement
    assert "recent KEV inclusion" in statement
    assert "independently verified increase in threat activity" in statement
    assert "CVE publication date only" in statement


def test_non_kev_record_states_absence_is_not_evidence(conn):
    payload = explain.explain_one(conn, "CVE-2023-0003")
    statement = payload["publication_recency_context"]["statement"]
    assert "No KEV listing date is available" in statement
    assert "not evidence of no exploitation" in statement
    assert "no recent activity" not in statement.lower()


def test_coverage_report_has_year_totals_and_gap_list(conn):
    coverage = explain.coverage_report(conn)
    years = {row["year"]: row for row in coverage["published_year_totals"]}
    assert years["2019"]["records"] == 1
    assert years["2023"]["records"] == 2
    assert "gaps" in coverage
    assert coverage["epss"]["total"] == 4


def test_absent_message_explains_uncovered_year(conn):
    message = explain.absent_message(conn, "CVE-1999-9999")
    assert "No loaded source covers publication year 1999" in message


def test_absent_message_rejects_malformed_identifier(conn):
    assert "not a CVE identifier" in explain.absent_message(conn, "NOT-A-CVE")


def test_store_status_includes_coverage_and_counts(db):
    status = store.store_status(db)
    assert status["counts"]["cve_record"] == 8
    assert status["reference_date"] == "2026-10-16"
    assert status["coverage"]["epss"]["total"] == 4


def test_kev_identifier_with_only_a_rejected_record_is_surfaced(conn):
    conn.execute(
        "INSERT INTO cve_record (cve_id, source, source_revision, retrieved_at,"
        " published, updated, state, state_basis, reject_marker, assigner, title,"
        " description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("CVE-2023-0099", "cvelistv5", "r", "2026-10-17T00:00:00Z",
         "2023-01-01", "2023-01-01", "REJECTED", "stated", 1, None, None, None),
    )
    conn.execute(
        "INSERT INTO kev (cve_id, date_added, vendor, product, name, ransom_known,"
        " source_revision, retrieved_at) VALUES (?,?,?,?,?,?,?,?)",
        ("CVE-2023-0099", "2026-10-15", "v", "p", "n", 0, "r", "2026-10-17T00:00:00Z"),
    )
    conn.commit()
    coverage = explain.coverage_report(conn)
    assert {"cve_id": "CVE-2023-0099", "date_added": "2026-10-15",
            "reason": "CVE_RECORD_REJECTED"} in coverage["kev_unranked"]
