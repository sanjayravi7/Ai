"""Legacy CVE extract adapter (``cve.csv.zip``).

The file has an empty first header cell, no state column, and carries CVSS v2
base scores only.  Because the source never states a rejection state, the
adapter records a *prose marker* separately (``reject_marker``) instead of
inventing a ``state`` value; ``state`` stays ``None`` for every row.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from pathlib import Path

from ..provenance import sha256_file

SOURCE = "legacy_cve_csv"

DAY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
REJECT_RE = re.compile(r"\*\*\s*REJECT|REJECTED?\s+DO\s+NOT\s+USE", re.IGNORECASE)

EXPECTED_HEADER = [
    "", "mod_date", "pub_date", "cvss", "cwe_code", "cwe_name", "summary",
    "access_authentication", "access_complexity", "access_vector",
    "impact_availability", "impact_confidentiality", "impact_integrity",
]


def _day(value):
    if not value:
        return None
    match = DAY_RE.match(str(value).strip())
    return match.group(1) if match else None


def _score(value):
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if 0.0 <= score <= 10.0:
        return score
    return None


def iter_rows(path):
    """Yield parsed legacy rows from the zip (or an uncompressed csv)."""
    path = Path(path)
    if zipfile.is_zipfile(path):
        archive = zipfile.ZipFile(path)
        member = archive.namelist()[0]
        raw = archive.open(member).read()
        stream = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="replace")
    else:
        stream = open(path, "rt", encoding="utf-8", errors="replace")

    reader = csv.reader(stream)
    header = next(reader, None)
    if header != EXPECTED_HEADER:
        raise ValueError(f"unexpected legacy header: {header!r}")

    for row in reader:
        if not row or not row[0].startswith("CVE-"):
            continue
        summary = row[6] if len(row) > 6 else ""
        yield {
            "cve_id": row[0].strip(),
            "modified": _day(row[1]),
            "published": _day(row[2]),
            "cvss": _score(row[3]),
            "cwe_code": (row[4] or "").strip() or None,
            "cwe_name": (row[5] or "").strip() or None,
            "description": summary or None,
            "reject_marker": bool(REJECT_RE.search(summary or "")),
        }


def meta(path, *, retrieved_at: str) -> dict:
    path = Path(path)
    return {
        "source": SOURCE,
        "revision": None,
        "retrieved_at": retrieved_at,
        "content_sha256": sha256_file(path),
        "note": "Legacy extract; revision/date of the extract is not stated by the source.",
    }
