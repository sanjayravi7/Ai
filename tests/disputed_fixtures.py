"""Synthetic fixtures for the Phase 2.2 disputed-CVE audit tests.

Nothing here contacts a live service. CVE record documents follow the CVE
Services 5.x shape published in ``CVEProject/cvelistV5`` (the structure was
checked against the real files for the disputed records on 2026-10-12); all
values are invented so the tests stay self-contained. The real records are
fetched by ``python -m src.fetch_disputed_status`` and are never needed by the
test suite.
"""

import json
from pathlib import Path

import pandas as pd

from src.fetch_cve_status import write_status_snapshot

PIPELINE_COMMIT = "c" * 40

DISPUTED_TEXT_SUMMARY = (
    "** DISPUTED ** Example widget firmware does not validate updates.  "
    "NOTE: third parties dispute the relevance of this because the device must "
    "already be configured for debug access."
)
DISPUTED_TAG_ONLY_SUMMARY = (
    "** DISPUTED ** Example portal allows command execution through an "
    "administrative interface."
)
DISPUTED_SILENT_SUMMARY = (
    "** DISPUTED ** Example service accepts unsigned messages from the local "
    "network segment."
)
DISPUTED_CONTRADICTION_SUMMARY = (
    "** DISPUTED ** Example daemon allows memory exhaustion through repeated "
    "requests."
)

REJECTION_REASON = (
    "DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: CVE-2019-9000.  Reason: This "
    "candidate is a duplicate of CVE-2019-9000.  Notes: All CVE users should "
    "reference CVE-2019-9000 instead of this candidate."
)


def cve_5x_record(
    cve_id,
    state="PUBLISHED",
    *,
    descriptions=(),
    tags=(),
    adp_tags=(),
    rejected_reasons=(),
    references=(),
    timeline=(),
    legacy_description="",
    date_published="2019-11-18T05:24:15.000Z",
    date_updated="2024-08-05T02:09:38.691Z",
    date_reserved="2019-11-18T00:00:00.000Z",
    date_rejected="",
    assigner="mitre",
    data_version="5.0",
    cvss_version="cvssV3_1",
    cvss_base_score=7.5,
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
    if date_rejected:
        metadata["dateRejected"] = date_rejected
    cna = {
        "providerMetadata": {
            "orgId": "00000000-0000-0000-0000-000000000000",
            "shortName": assigner,
            "dateUpdated": date_updated,
        },
        "descriptions": [
            {"lang": "en", "value": value} for value in descriptions
        ],
        "references": [
            {
                "url": url,
                "name": url.rsplit("/", 1)[-1],
                "tags": list(tags_for_url),
            }
            for url, tags_for_url in references
        ],
    }
    if tags:
        cna["tags"] = list(tags)
    if rejected_reasons:
        cna["rejectedReasons"] = [{"lang": "en", "value": value} for value in rejected_reasons]
    if timeline:
        cna["timeline"] = [{"time": stamp, "lang": "en", "value": value} for stamp, value in timeline]
    if legacy_description:
        cna["x_legacyV4Record"] = {
            "CVE_data_meta": {"ID": cve_id, "STATE": "PUBLIC"},
            "description": {"description_data": [{"lang": "en", "value": legacy_description}]},
        }
    if cvss_version:
        cna["metrics"] = [{cvss_version: {"baseScore": cvss_base_score, "vectorString": "TEST"}}]
    adp = []
    if adp_tags:
        adp.append(
            {
                "providerMetadata": {"orgId": "11111111-1111-1111-1111-111111111111", "shortName": "CVE"},
                "title": "CVE Program Container",
                "tags": list(adp_tags),
            }
        )
    containers = {"cna": cna}
    if adp:
        containers["adp"] = adp
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": data_version,
        "cveMetadata": metadata,
        "containers": containers,
    }


def disputed_text_record(cve_id="CVE-2020-1001"):
    return cve_5x_record(
        cve_id,
        descriptions=[
            "Example widget firmware does not validate updates, which allows remote attackers to "
            "execute arbitrary code.  NOTE: third parties dispute the relevance of this because the "
            "device must already be configured for debug access."
        ],
        tags=["disputed"],
        references=[
            ("https://example.test/advisory/1", ["vendor-advisory"]),
            ("https://example.test/bug/2", ["vdb-entry"]),
        ],
    )


def disputed_tag_only_record(cve_id="CVE-2020-1002"):
    return cve_5x_record(
        cve_id,
        descriptions=[
            "Example portal allows command execution through an administrative interface, which is "
            "documented behaviour for administrators."
        ],
        tags=["disputed"],
    )


def disputed_contradiction_record(cve_id="CVE-2020-1007"):
    return cve_5x_record(
        cve_id,
        descriptions=[
            "Example daemon allows memory exhaustion through repeated requests.  NOTE: the dispute "
            "has been resolved and the record is no longer disputed."
        ],
        tags=[],
    )


def disputed_silent_record(cve_id="CVE-2020-1004"):
    return cve_5x_record(
        cve_id,
        descriptions=["Example service accepts unsigned messages from the local network segment."],
        tags=[],
    )


def disputed_reserved_record(cve_id="CVE-2020-1006"):
    return cve_5x_record(
        cve_id,
        state="RESERVED",
        descriptions=[],
        tags=[],
        date_published="",
    )


def disputed_withdrawn_record(cve_id="CVE-2020-1003"):
    return cve_5x_record(
        cve_id,
        state="REJECTED",
        descriptions=[],
        rejected_reasons=[REJECTION_REASON],
        date_rejected="2022-10-03T00:00:00.000Z",
    )


def disputed_consult_record(cve_id="CVE-2020-1013"):
    return cve_5x_record(
        cve_id,
        descriptions=["Example library mishandles input; this is a duplicate of CVE-2019-9000."],
        tags=["disputed"],
    )


def record_bytes(record):
    return json.dumps(record).encode("utf-8")


def synthetic_disputed_records():
    """Authoritative records keyed by CVE id, matching :func:`synthetic_dataset`.

    ``CVE-2020-1005`` is deliberately absent (a 404 at the pinned commit) and the
    manifest for ``CVE-2020-1008`` is written with a file whose identifier does
    not match its key, which exercises the malformed-record path.
    """
    return {
        "CVE-2020-1001": record_bytes(disputed_text_record()),
        "CVE-2020-1002": record_bytes(disputed_tag_only_record()),
        "CVE-2020-1003": record_bytes(disputed_withdrawn_record()),
        "CVE-2020-1004": record_bytes(disputed_silent_record()),
        "CVE-2020-1006": record_bytes(disputed_reserved_record()),
        "CVE-2020-1007": record_bytes(disputed_contradiction_record()),
        "CVE-2020-1013": record_bytes(disputed_consult_record()),
    }


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
    """Twelve synthetic records covering every disputed-evidence branch.

    Disputed rows (8): 1001 text-disputed, 1002 tag-only, 1003 withdrawn
    (REJECTED), 1004 source silent, 1005 no authoritative record, 1006
    non-final state, 1007 explicit contradiction, 1008 malformed record.

    Baselines (4): 1009 (9.0), 1010 (8.0), 1011 (7.0), 1012 (4.0).
    """
    rows = [
        {"cve_id": "CVE-2020-1001", "cvss": "9.8", "summary": DISPUTED_TEXT_SUMMARY},
        {"cve_id": "CVE-2020-1002", "cvss": "8.5", "summary": DISPUTED_TAG_ONLY_SUMMARY},
        {"cve_id": "CVE-2020-1003", "cvss": "9.5", "summary": "** DISPUTED ** " + REJECTION_REASON},
        {"cve_id": "CVE-2020-1004", "cvss": "7.5", "summary": DISPUTED_SILENT_SUMMARY},
        {"cve_id": "CVE-2020-1005", "cvss": "5.0", "summary": "** DISPUTED ** Example device driver flushes memory on error."},
        {"cve_id": "CVE-2020-1006", "cvss": "6.5", "summary": "** DISPUTED ** Example gateway accepts duplicate session identifiers."},
        {"cve_id": "CVE-2020-1007", "cvss": "10.0", "summary": DISPUTED_CONTRADICTION_SUMMARY},
        {"cve_id": "CVE-2020-1008", "cvss": "6.0", "summary": "** DISPUTED ** Example daemon mishandles malformed headers."},
        {"cve_id": "CVE-2020-1009", "cvss": "9.0", "summary": "Undisputed critical issue."},
        {"cve_id": "CVE-2020-1010", "cvss": "8.0", "summary": "Undisputed high issue."},
        {"cve_id": "CVE-2020-1011", "cvss": "7.0", "summary": "Undisputed moderate issue."},
        {"cve_id": "CVE-2020-1012", "cvss": "4.0", "summary": "Undisputed low issue."},
    ]
    frame = pd.DataFrame(rows)
    frame["mod_date"] = "2019-11-20 00:00:00"
    frame["pub_date"] = "2019-11-18 00:00:00"
    for column in DATASET_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    return frame[list(DATASET_COLUMNS)]


def write_dataset(path: Path, frame=None) -> Path:
    (frame if frame is not None else synthetic_dataset()).to_csv(path, index=False)
    return Path(path)


def write_disputed_snapshot(
    root: Path,
    *,
    records=None,
    missing=("CVE-2020-1005",),
    commit_sha=PIPELINE_COMMIT,
    retrieved_utc=None,
    mutate=None,
):
    """Write a checksum-verified disputed-record snapshot for the tests.

    Args:
        records: Mapping of CVE id to record bytes; defaults to
            :func:`synthetic_disputed_records`.
        missing: Identifiers recorded as absent at the pinned commit.
        mutate: Optional callable ``(manifest_path, directory)`` used by tests to
            simulate a malformed-but-checksum-consistent file.
    """
    from datetime import datetime, timezone

    payload = dict(records if records is not None else synthetic_disputed_records())
    now = retrieved_utc or datetime(2026, 10, 12, tzinfo=timezone.utc)
    manifest = write_status_snapshot(
        payload,
        repository="CVEProject/cvelistV5",
        requested_ref="main",
        commit_sha=commit_sha,
        retrieval_method="local_import",
        root=Path(root),
        retrieved_utc=now,
        missing=list(missing),
        record_metadata={
            **{cve_id: {"url": "https://example.test/" + cve_id} for cve_id in payload},
            **{
                cve_id: {"url": "https://example.test/" + cve_id, "reason": "http_404_not_found"}
                for cve_id in missing
            },
        },
    )
    if mutate is not None:
        mutate(Path(manifest["_manifest_path"]), Path(manifest["_manifest_path"]).parent)
    return manifest


def write_phase21_audit(path: Path, *, scores=("5.0",)) -> Path:
    """A minimal Phase 2.1 rejected-CVE audit table (for placeholder derivation)."""
    frame = pd.DataFrame(
        {
            "cve_id": [f"CVE-1999-{9000 + index:04d}" for index, _ in enumerate(scores)],
            "record_status": ["REJECTED"] * len(scores),
            "source_cvss": list(scores),
        }
    )
    frame.to_csv(Path(path), index=False)
    return Path(path)


def write_phase21_disputed_report(path: Path, frame=None) -> Path:
    """A stand-in for the preserved Phase 2.1 marker inventory."""
    target = synthetic_dataset() if frame is None else frame
    disputed = target[target["summary"].str.contains("** DISPUTED **", regex=False)]
    disputed.to_csv(Path(path), index=False)
    return Path(path)
