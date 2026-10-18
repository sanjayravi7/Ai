"""Fixtures: a small synthetic store that exercises every evidence case."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnova import store  # noqa: E402

REFERENCE = "2026-10-16"

CVES = [
    # both signals, no KEV
    {
        "cve_id": "CVE-2023-0001",
        "published": "2023-06-01",
        "state": "PUBLISHED",
        "kev": False,
        "epss": 0.5,
        "cvss": [("cvelistv5", "cna", "ACME", "3.1", 9.8, "CRITICAL")],
    },
    # neither signal
    {
        "cve_id": "CVE-2023-0002",
        "published": "2026-10-15",
        "state": "PUBLISHED",
        "kev": False,
        "epss": None,
        "cvss": [],
    },
    # CVSS only
    {
        "cve_id": "CVE-2023-0003",
        "published": "2024-01-10",
        "state": "PUBLISHED",
        "kev": False,
        "epss": None,
        "cvss": [("cvelistv5", "cna", "ACME", "3.1", 7.5, "HIGH")],
    },
    # EPSS only
    {
        "cve_id": "CVE-2023-0004",
        "published": "2025-02-01",
        "state": "PUBLISHED",
        "kev": False,
        "epss": 0.9,
        "cvss": [],
    },
    # conflicting sources, KEV, old publication with recent KEV listing
    {
        "cve_id": "CVE-2019-0005",
        "published": "2019-03-01",
        "state": "PUBLISHED",
        "kev": True,
        "kev_date_added": "2026-10-08",
        "epss": 0.4,
        "cvss": [
            ("cvelistv5", "cna", "ACME", "3.1", 9.8, "CRITICAL"),
            ("cvelistv5", "adp", "NVD", "3.1", 7.5, "HIGH"),
            ("legacy_cve_csv", "legacy", None, "2.0", 6.8, "MEDIUM"),
        ],
    },
    # KEV but no CVSS and no EPSS
    {
        "cve_id": "CVE-2023-0006",
        "published": "2026-09-01",
        "state": "PUBLISHED",
        "kev": True,
        "kev_date_added": "2026-10-01",
        "epss": None,
        "cvss": [],
    },
    # rejected record
    {
        "cve_id": "CVE-2023-0007",
        "published": "2023-07-01",
        "state": "REJECTED",
        "kev": False,
        "epss": 0.1,
        "cvss": [],
    },
]


def _insert(conn, cve):
    conn.execute(
        "INSERT INTO cve_record (cve_id, source, source_revision, retrieved_at,"
        " published, updated, state, state_basis, reject_marker, assigner, title,"
        " description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            cve["cve_id"], "cvelistv5", "testrev", "2026-10-17T00:00:00Z",
            cve["published"], cve["published"], cve["state"], "stated",
            int(cve["state"] == "REJECTED"), "acme", "Test " + cve["cve_id"],
            "Synthetic record for tests.",
        ),
    )
    if cve["cve_id"] == "CVE-2019-0005":
        conn.execute(
            "INSERT INTO cve_record (cve_id, source, source_revision, retrieved_at,"
            " published, updated, state, state_basis, reject_marker, assigner, title,"
            " description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                cve["cve_id"], "legacy_cve_csv", None, "2026-10-17T00:00:00Z",
                cve["published"], cve["published"], None, "not_stated", 0, None, None,
                "Legacy description for CVE-2019-0005.",
            ),
        )
    if cve["cvss"]:
        for source, container, org, version, value, severity in cve["cvss"]:
            conn.execute(
                "INSERT INTO cvss_observation (cve_id, source, source_record_id,"
                " container, scoring_organization, version, value, severity, vector,"
                " status, retrieved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (cve["cve_id"], source, cve["cve_id"], container, org, version,
                 value, severity, "CVSS:%s/AV:N" % version, "OBSERVED",
                 "2026-10-17T00:00:00Z"),
            )
    else:
        conn.execute(
            "INSERT INTO cvss_observation (cve_id, source, source_record_id, container,"
            " scoring_organization, version, value, severity, vector, status, retrieved_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (cve["cve_id"], "cvelistv5", cve["cve_id"], "cna", "acme", None, None,
             None, None, "MISSING_FROM_SOURCE", "2026-10-17T00:00:00Z"),
        )
    if cve["kev"]:
        conn.execute(
            "INSERT INTO kev (cve_id, date_added, vendor, product, name, ransom_known,"
            " source_revision, retrieved_at) VALUES (?,?,?,?,?,?,?,?)",
            (cve["cve_id"], cve.get("kev_date_added", "2026-01-01"), "acme", "widget",
             "Test", 0, "testrev", "2026-10-17T00:00:00Z"),
        )
    if cve["epss"] is not None:
        conn.execute(
            "INSERT INTO epss (cve_id, probability, percentile, score_date,"
            " model_version, retrieved_at) VALUES (?,?,?,?,?,?)",
            (cve["cve_id"], cve["epss"], 0.5, REFERENCE, "v2026.06.15",
             "2026-10-17T00:00:00Z"),
        )


def build_store(path):
    conn = store.initialise(path)
    for cve in CVES:
        _insert(conn, cve)
    conn.commit()
    conn.close()
    return path


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "vulnova.db"
    build_store(path)
    return path


@pytest.fixture()
def conn(db):
    connection = store.connect(db)
    yield connection
    connection.close()
