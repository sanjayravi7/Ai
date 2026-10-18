"""Store schema and missingness representation."""

from __future__ import annotations

from vulnova import store


def test_schema_tables_exist(conn):
    names = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {
        "ingest_run", "cve_record", "cvss_observation", "kev", "epss",
        "ranking", "ranking_meta",
    } <= names


def test_missing_cvss_is_a_row_not_an_absence(conn):
    row = conn.execute(
        "SELECT status, value FROM cvss_observation WHERE cve_id='CVE-2023-0002'"
    ).fetchone()
    assert row["status"] == "MISSING_FROM_SOURCE"
    assert row["value"] is None


def test_one_row_per_source_keeps_conflicts(conn):
    rows = conn.execute(
        "SELECT source FROM cve_record WHERE cve_id='CVE-2019-0005' ORDER BY source"
    ).fetchall()
    assert [r["source"] for r in rows] == ["cvelistv5", "legacy_cve_csv"]


def test_legacy_state_is_never_invented(conn):
    row = conn.execute(
        "SELECT state, state_basis FROM cve_record"
        " WHERE source='legacy_cve_csv'"
    ).fetchone()
    assert row["state"] is None
    assert row["state_basis"] == "not_stated"


def test_counts_and_reference_date(conn):
    counts = store.counts(conn)
    assert counts["cve_record"] == 8
    assert counts["kev"] == 2
    assert counts["epss"] == 4
    assert counts["rejected"] == 1
    assert store.reference_date(conn) == "2026-10-16"


def test_reference_date_falls_back_to_publication(conn):
    conn.execute("DELETE FROM epss")
    conn.commit()
    assert store.reference_date(conn) == "2026-10-15"
