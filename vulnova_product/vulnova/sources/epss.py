"""EPSS daily-score adapter.

The published file carries a single comment line whose first key is the only
one prefixed with ``#``::

    #model_version:v2026.06.15,score_date:2026-10-16T12:02:51Z

so the header is parsed with a regex rather than by splitting on ``#``.
Rows are streamed: the full table is ~390k rows and must not be materialised
as Python objects.
"""

from __future__ import annotations

import gzip
import re
from pathlib import Path

from ..provenance import sha256_file

SOURCE = "epss"

HEADER_RE = re.compile(r"(model_version|score_date):([^,\s]+)")
ROW_RE = re.compile(r"^(CVE-\d{4}-\d{4,}),([0-9.eE+-]+),([0-9.eE+-]+)\s*$")


class MalformedEpss(RuntimeError):
    pass


def read_header(path) -> dict:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        first = handle.readline().strip()
    if not first.startswith("#"):
        raise MalformedEpss(f"first line is not an EPSS header: {first[:60]!r}")
    fields = dict(HEADER_RE.findall(first))
    if "score_date" not in fields or "model_version" not in fields:
        raise MalformedEpss(f"header missing keys: {first[:120]!r}")
    return fields


def iter_rows(path):
    """Yield ``(cve_id, probability, percentile)`` for well-formed rows."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        handle.readline()  # comment header
        for line in handle:
            if not line.strip():
                continue
            if line.startswith("#"):
                continue
            match = ROW_RE.match(line)
            if not match:
                continue
            cve_id, probability, percentile = match.groups()
            try:
                prob = float(probability)
                pct = float(percentile)
            except ValueError:
                continue
            if not 0.0 <= prob <= 1.0:
                continue
            yield cve_id, prob, pct


def load(path, *, retrieved_at: str) -> dict:
    path = Path(path)
    header = read_header(path)
    return {
        "header": header,
        "meta": {
            "source": SOURCE,
            "revision": header.get("model_version"),
            "retrieved_at": retrieved_at,
            "content_sha256": sha256_file(path),
            "score_date": header.get("score_date", "")[:10],
        },
    }
