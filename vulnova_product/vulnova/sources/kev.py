"""CISA Known Exploited Vulnerabilities catalog adapter.

Membership is *observed exploitation evidence*; absence from the catalog is
recorded as ``NOT_LISTED_IN_CATALOG`` and is never described as proof that a
vulnerability was not exploited.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..provenance import sha256_file

SOURCE = "kev"


class CatalogTruncated(RuntimeError):
    """Raised when the catalog's declared count disagrees with its contents.

    The public kev-data repository has shipped at least one genuinely
    truncated revision (blob a7fa9428cc13, 2025-02-25, declared count 1280).
    Loading such a revision must fail loudly rather than silently shrink the
    catalog.
    """


def load(path, *, revision: str, retrieved_at: str) -> dict:
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise CatalogTruncated(f"{path} has no 'vulnerabilities' list")

    declared = payload.get("count")
    if isinstance(declared, int) and declared != len(entries):
        raise CatalogTruncated(
            f"declared count {declared} != parsed entries {len(entries)}"
        )

    by_cve = {}
    for entry in entries:
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        by_cve[cve_id] = {
            "cve_id": cve_id,
            "date_added": entry.get("dateAdded"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "name": entry.get("vulnerabilityName"),
            "ransom_known": bool(entry.get("knownRansomwareCampaignUse") == "Known"),
        }

    return {
        "entries": by_cve,
        "meta": {
            "source": SOURCE,
            "revision": revision,
            "retrieved_at": retrieved_at,
            "content_sha256": sha256_file(path),
            "catalog_version": payload.get("catalogVersion"),
            "declared_count": declared,
            "parsed_count": len(by_cve),
        },
    }
