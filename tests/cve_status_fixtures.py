"""Synthetic fixtures for the rejected-CVE audit tests.

Nothing here contacts a live service. CVE record documents follow the CVE
Services 5.x shape published in ``CVEProject/cvelistV5`` (the structure was
checked against the real files for the 17 ``** REJECT **`` records on
2026-10-12); values are invented so the tests stay self-contained.
"""

import json
from pathlib import Path

import pandas as pd

from src.threat_intel_sources import EPSS_SOURCE, KEV_SOURCE, ParsedSnapshot


REJECT_SUMMARY = (
    "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: {consult}.  "
    "Reason: This candidate is a duplicate of {consult}.  Notes: All CVE users "
    "should reference {consult} instead of this candidate.  All references and "
    "descriptions in this candidate have been removed to prevent accidental usage."
)

DISPUTED_SUMMARY = (
    "** DISPUTED ** The vendor states that the reported behaviour is intended."
)


def reject_summary_marker():
    """The bare withdrawal marker, without surrounding text."""
    return "** REJECT **"


def rejected_summary(consult="CVE-2019-0002"):
    return REJECT_SUMMARY.format(consult=consult)


def cve_record(
    cve_id,
    state,
    *,
    date_published="2020-01-02T03:04:05.000Z",
    date_updated="2021-02-03T04:05:06.000Z",
    date_reserved="2019-12-31T00:00:00.000Z",
    date_rejected=None,
    assigner="mitre",
    reasons=None,
    cvss_version=None,
    cvss_base_score=None,
):
    """Build a CVE Services 5.x document dict."""
    metadata = {
        "cveId": cve_id,
        "assignerOrgId": "00000000-0000-0000-0000-000000000000",
        "assignerShortName": assigner,
        "datePublished": date_published,
        "dateReserved": date_reserved,
        "dateUpdated": date_updated,
        "state": state,
    }
    if date_rejected is not None:
        metadata["dateRejected"] = date_rejected
    cna = {"providerMetadata": {"orgId": "00000000-0000-0000-0000-000000000000", "shortName": assigner}}
    if reasons:
        cna["rejectedReasons"] = [{"lang": "en", "value": value} for value in reasons]
    if cvss_version:
        cna["metrics"] = [{cvss_version: {"baseScore": cvss_base_score, "vectorString": "TEST"}}]
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": metadata,
        "containers": {"cna": cna},
    }


def rejected_record(cve_id, consult="CVE-2019-0002", **overrides):
    payload = dict(
        state="REJECTED",
        date_rejected="2022-10-03T00:00:00.000Z",
        reasons=[rejected_summary(consult)],
    )
    payload.update(overrides)
    return cve_record(cve_id, **payload)


def published_record(cve_id, **overrides):
    payload = dict(
        state="PUBLISHED",
        reasons=None,
        assigner="redhat",
        cvss_version="cvssV3_1",
        cvss_base_score=7.5,
    )
    payload.update(overrides)
    return cve_record(cve_id, **payload)


def reserved_record(cve_id, **overrides):
    payload = dict(state="RESERVED", reasons=None)
    payload.update(overrides)
    return cve_record(cve_id, **payload)


def record_bytes(record):
    return json.dumps(record).encode("utf-8")


DATASET_COLUMNS = (
    "cve_id",
    "mod_date",
    "pub_date",
    "cvss",
    "cwe_code",
    "cwe_name",
    "summary",
    "access_authentication",
    "access_complexity",
    "access_vector",
    "impact_availability",
    "impact_confidentiality",
    "impact_integrity",
)


def synthetic_dataset():
    """Nine synthetic records covering every policy branch.

    CVE-2020-0003  rejected placeholder, authoritative REJECTED      -> excluded
    CVE-2020-0004  rejected placeholder, authoritative PUBLISHED     -> ranked 8.4
    CVE-2020-0005  rejected placeholder, authoritative PUBLISHED     -> ranked last
                   (its 5.0 equals the derived placeholder value)
    CVE-2020-0009  rejected placeholder, no authoritative record     -> unverified
    CVE-2020-0006  disputed, untouched                               -> ranked 4.3
    CVE-2020-0007  missing CVSS                                      -> ranked last
    """
    rows = [
        {
            "cve_id": "CVE-2020-0001",
            "mod_date": "2020-02-01 00:00:00",
            "pub_date": "2020-01-01 00:00:00",
            "cvss": "9.8",
            "summary": "Critical remote code execution.",
        },
        {
            "cve_id": "CVE-2020-0002",
            "mod_date": "2020-02-02 00:00:00",
            "pub_date": "2020-01-02 00:00:00",
            "cvss": "6.5",
            "summary": "Moderate information disclosure.",
        },
        {
            "cve_id": "CVE-2020-0003",
            "mod_date": "2020-02-03 00:00:00",
            "pub_date": "2020-01-03 00:00:00",
            "cvss": "5.0",
            "summary": rejected_summary("CVE-2019-0003"),
        },
        {
            "cve_id": "CVE-2020-0004",
            "mod_date": "2020-02-04 00:00:00",
            "pub_date": "2020-01-04 00:00:00",
            "cvss": "8.4",
            "summary": rejected_summary("CVE-2019-0004"),
        },
        {
            "cve_id": "CVE-2020-0005",
            "mod_date": "2020-02-05 00:00:00",
            "pub_date": "2020-01-05 00:00:00",
            "cvss": "5.0",
            "summary": rejected_summary("CVE-2019-0005"),
        },
        {
            "cve_id": "CVE-2020-0006",
            "mod_date": "2020-02-06 00:00:00",
            "pub_date": "2020-01-06 00:00:00",
            "cvss": "4.3",
            "summary": DISPUTED_SUMMARY,
        },
        {
            "cve_id": "CVE-2020-0007",
            "mod_date": "2020-02-07 00:00:00",
            "pub_date": "2020-01-07 00:00:00",
            "cvss": "",
            "summary": "Score not published in this snapshot.",
        },
        {
            "cve_id": "CVE-2020-0008",
            "mod_date": "2020-02-08 00:00:00",
            "pub_date": "2020-01-08 00:00:00",
            "cvss": "6.5",
            "summary": "Moderate denial of service.",
        },
        {
            "cve_id": "CVE-2020-0009",
            "mod_date": "2020-02-09 00:00:00",
            "pub_date": "2020-01-09 00:00:00",
            "cvss": "5.0",
            "summary": rejected_summary("CVE-2019-0009"),
        },
    ]
    frame = pd.DataFrame(rows)
    for column in DATASET_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    return frame[list(DATASET_COLUMNS)]


def status_records():
    """Authoritative records matching :func:`synthetic_dataset`."""
    return {
        "CVE-2020-0003": record_bytes(rejected_record("CVE-2020-0003", consult="CVE-2019-0003")),
        "CVE-2020-0004": record_bytes(
            published_record("CVE-2020-0004", cvss_base_score=8.4)
        ),
        "CVE-2020-0005": record_bytes(
            published_record("CVE-2020-0005", cvss_base_score=6.1)
        ),
    }


def kev_snapshot():
    frame = pd.DataFrame(
        {
            "cve_id": ["CVE-2020-0001"],
            "kev_date_added": ["2021-11-03"],
            "kev_vendor_project": ["Example"],
            "kev_product": ["Widget"],
            "kev_vulnerability_name": ["Example Widget RCE"],
            "kev_short_description": ["Example description."],
            "kev_required_action": ["Apply vendor update."],
            "kev_due_date": ["2021-11-17"],
            "kev_known_ransomware_campaign_use": ["Unknown"],
            "kev_cwes": ["CWE-78"],
        }
    )
    metadata = {
        "catalog_version": "test.01",
        "snapshot_date": "2021-11-03",
        "record_count": 1,
    }
    return ParsedSnapshot(KEV_SOURCE, frame, metadata, {})


def epss_snapshot():
    frame = pd.DataFrame(
        {
            "cve_id": ["CVE-2020-0001", "CVE-2020-0003", "CVE-2020-0006"],
            "epss_score": [0.5, 0.01, 0.2],
            "epss_percentile": [0.9, 0.3, 0.7],
        }
    )
    metadata = {"model_version": "test-model", "snapshot_date": "2021-11-03", "record_count": 3}
    return ParsedSnapshot(EPSS_SOURCE, frame, metadata, {})


def write_dataset(path: Path, frame=None) -> Path:
    (frame if frame is not None else synthetic_dataset()).to_csv(path, index=False)
    return Path(path)
