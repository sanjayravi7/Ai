"""cvelistV5 adapter.

Each CVE is one JSON file under ``cves/<year>/<block>/CVE-*.json``.  A record
can carry CVSS metrics from the CNA container *and* from one or more ADP
containers (typically NVD).  All of them are retained: the console is required
to show every source-specific value, not just the one used for ranking.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SOURCE = "cvelistv5"

CVSS_KEYS = {
    "cvssV4_0": "4.0",
    "cvssV3_1": "3.1",
    "cvssV3_0": "3.0",
    "cvssV2_0": "2.0",
}

DAY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _day(value):
    if not value:
        return None
    match = DAY_RE.match(str(value))
    return match.group(1) if match else None


def _state_basis(value) -> str:
    """Whether the source itself states a state.

    ``state`` is copied verbatim by :func:`parse_file`; nothing is inferred from
    ``reject_marker`` or from the legacy extract.  The basis records only
    whether ``cveMetadata.state`` carried a non-empty value.
    """
    return "stated" if isinstance(value, str) and value.strip() else "not_stated"


def _description(cna) -> str | None:
    for item in cna.get("descriptions") or []:
        if item.get("lang", "").startswith("en") and item.get("value"):
            return item["value"]
    for item in cna.get("descriptions") or []:
        if item.get("value"):
            return item["value"]
    return None


def _candidates(record: dict) -> list:
    """Collect every CVSS metric with its container and scoring organisation."""
    out = []
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    cna_org = (cna.get("providerMetadata") or {}).get("shortName")

    for metric in cna.get("metrics") or []:
        for key, version in CVSS_KEYS.items():
            body = metric.get(key)
            if not isinstance(body, dict):
                continue
            out.append(
                {
                    "container": "cna",
                    "scoring_organization": metric.get("source") or cna_org,
                    "version": str(body.get("version") or version),
                    "value": body.get("baseScore"),
                    "severity": body.get("baseSeverity"),
                    "vector": body.get("vectorString"),
                }
            )

    for adp in containers.get("adp") or []:
        adp_org = (adp.get("providerMetadata") or {}).get("shortName")
        for metric in adp.get("metrics") or []:
            for key, version in CVSS_KEYS.items():
                body = metric.get(key)
                if not isinstance(body, dict):
                    continue
                out.append(
                    {
                        "container": "adp",
                        "scoring_organization": metric.get("source") or adp_org,
                        "version": str(body.get("version") or version),
                        "value": body.get("baseScore"),
                        "severity": body.get("baseSeverity"),
                        "vector": body.get("vectorString"),
                    }
                )
    return out


def parse_file(path) -> dict | None:
    path = Path(path)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    meta = record.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id or not CVE_RE.fullmatch(cve_id):
        return None

    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    state = meta.get("state")

    return {
        "cve_id": cve_id,
        "state": state,
        "state_basis": _state_basis(state),
        "published": _day(meta.get("datePublished")),
        "updated": _day(meta.get("dateUpdated")),
        "assigner": meta.get("assignerShortName") or meta.get("assignerOrgId"),
        "title": cna.get("title"),
        "description": _description(cna),
        "reject_marker": state == "REJECTED",
        "candidates": _candidates(record),
        "path": str(path),
    }


def iter_year(root, year: int):
    """Yield parsed records for one ``cves/<year>`` directory."""
    base = Path(root) / "cves" / str(year)
    if not base.is_dir():
        return
    for path in sorted(base.rglob("CVE-*.json")):
        record = parse_file(path)
        if record is not None:
            yield record
