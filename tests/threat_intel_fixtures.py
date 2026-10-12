"""Shared synthetic fixtures for threat-intelligence tests.

KEV entry fields and EPSS rows are copied from the official sources (CISA KEV
catalog retrieved 2026-10-12, FIRST EPSS daily file scored 2026-10-11) and
trimmed to the fields this pipeline reads. Nothing here contacts a live service.
"""

import json

KEV_ENTRY_STRUCT = {
    "cveID": "CVE-2016-3081",
    "vendorProject": "Apache",
    "product": "Struts",
    "vulnerabilityName": "Apache Struts Command Injection Vulnerability",
    "dateAdded": "2026-10-08",
    "shortDescription": "Apache Struts contains a command injection vulnerability.",
    "requiredAction": "Apply mitigations in accordance with vendor instructions.",
    "dueDate": "2026-10-11",
    "knownRansomwareCampaignUse": "Unknown",
    "notes": "",
    "cwes": ["CWE-77"],
}


def kev_document(entries=None, count=None, **overrides):
    """Build a KEV JSON payload; the declared count defaults to the entry total."""
    records = entries if entries is not None else [dict(KEV_ENTRY_STRUCT)]
    document = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.10.08",
        "dateReleased": "2026-10-08T20:09:18.9833Z",
        "count": len(records) if count is None else count,
        "vulnerabilities": records,
    }
    document.update(overrides)
    return json.dumps(document).encode("utf-8")


def second_kev_entry():
    entry = dict(KEV_ENTRY_STRUCT)
    entry.update(
        {
            "cveID": "CVE-2015-5477",
            "vendorProject": "ISC",
            "product": "BIND",
            "vulnerabilityName": "ISC BIND Data Processing Errors Vulnerability",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-19"],
        }
    )
    return entry


# Verbatim first rows of the FIRST EPSS daily bulk file (score_date 2026-10-11).
EPSS_REAL_EXCERPT = (
    "#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z\n"
    "cve,epss,percentile\n"
    "CVE-1999-0001,0.03351,0.88387\n"
    "CVE-1999-0002,0.27858,0.98059\n"
    "CVE-1999-0003,0.24565,0.97838\n"
    "CVE-1999-0016,0.95667,0.99871\n"
).encode("utf-8")
