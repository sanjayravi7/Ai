"""Ingest reconciliation and source guards."""

from __future__ import annotations

import json

import pytest

from vulnova import ingest, store
from vulnova.sources import kev, legacy_csv


def write_cve(root, relative, cve_id, published, state="PUBLISHED", cvss=None):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    metrics = []
    if cvss is not None:
        metrics.append({
            "cvssV3_1": {
                "version": "3.1", "baseScore": cvss,
                "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N",
            }
        })
    payload = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id, "state": state, "assignerShortName": "acme",
            "datePublished": published, "dateUpdated": published,
        },
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "acme"},
                "title": "t", "descriptions": [{"lang": "en", "value": "d"}],
                "metrics": metrics,
            }
        },
    }
    path.write_text(json.dumps(payload))
    return path


def test_kev_truncated_catalog_is_rejected(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({
        "catalogVersion": "x",
        "count": 1280,
        "vulnerabilities": [{"cveID": "CVE-2021-0001", "dateAdded": "2021-01-01"}],
    }))
    with pytest.raises(kev.CatalogTruncated):
        kev.load(path, revision="r", retrieved_at="now")


def test_legacy_header_must_match(tmp_path):
    import zipfile

    path = tmp_path / "cve.csv.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("cve.csv", "wrong,header\nCVE-2019-0001,x\n")
    with pytest.raises(ValueError):
        list(legacy_csv.iter_rows(path))


def test_cvelistv5_reconciliation_counts(tmp_path):
    root = tmp_path / "root"
    write_cve(root, "cves/2023/1xxx/CVE-2023-1001.json", "CVE-2023-1001", "2023-01-01")
    write_cve(root, "cves/2023/1xxx/CVE-2023-1002.json", "CVE-2023-1002", "2023-02-01", cvss=7.5)
    # duplicate identifier under a different path
    write_cve(root, "cves/2023/2xxx/CVE-2023-1001.json", "CVE-2023-1001", "2023-01-01")
    # rejected record
    write_cve(root, "cves/2023/1xxx/CVE-2023-1003.json", "CVE-2023-1003", "2023-03-01",
              state="REJECTED")

    db = tmp_path / "store.db"
    conn = store.initialise(db)
    result = ingest.load_cvelistv5(
        conn, root, years=[2023], revision="rev1", published_from="2020-01-01",
    )
    counters = result["counters"]
    assert counters["records_in"] == 4
    assert counters["records_new"] == 3
    assert counters["records_duplicate"] == 1
    assert counters["records_rejected"] == 1

    # second run: everything already present
    result2 = ingest.load_cvelistv5(
        conn, root, years=[2023], revision="rev1", published_from="2020-01-01",
    )
    assert result2["counters"]["records_new"] == 0
    assert result2["counters"]["records_existing"] == 3
    assert result2["counters"]["records_duplicate"] == 1

    runs = conn.execute("SELECT COUNT(*) FROM ingest_run").fetchone()[0]
    assert runs == 2
    conn.close()


def test_window_excludes_pre_2020(tmp_path):
    root = tmp_path / "root"
    write_cve(root, "cves/2019/1xxx/CVE-2019-1001.json", "CVE-2019-1001", "2019-01-01")
    write_cve(root, "cves/2020/1xxx/CVE-2020-1001.json", "CVE-2020-1001", "2020-01-02")

    db = tmp_path / "store.db"
    conn = store.initialise(db)
    result = ingest.load_cvelistv5(
        conn, root, years=[2019, 2020], revision="rev1", published_from="2020-01-01",
    )
    assert result["counters"]["records_in"] == 2
    assert result["counters"]["records_new"] == 1
    assert result["counters"]["records_skipped"] == 1
    ids = {row[0] for row in conn.execute("SELECT cve_id FROM cve_record")}
    assert ids == {"CVE-2020-1001"}


def test_missing_cvss_produces_a_missing_row(tmp_path):
    root = tmp_path / "root"
    write_cve(root, "cves/2023/1xxx/CVE-2023-1001.json", "CVE-2023-1001", "2023-01-01")

    db = tmp_path / "store.db"
    conn = store.initialise(db)
    ingest.load_cvelistv5(conn, root, years=[2023], revision="rev1",
                          published_from="2020-01-01")
    row = conn.execute(
        "SELECT status, value FROM cvss_observation WHERE cve_id='CVE-2023-1001'"
    ).fetchone()
    assert row["status"] == "MISSING_FROM_SOURCE"
    assert row["value"] is None
