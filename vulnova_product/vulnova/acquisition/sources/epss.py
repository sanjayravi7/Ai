"""EPSS daily score-file acquisition for one exact historical date.

The rule for this source is deliberately narrow: a cutoff either has *its own*
daily file or it has nothing.  A newer file, a later model version, or a
backfilled snapshot is never substituted, because substituting one would rewrite
history and make the resulting evaluation untraceable.

The header of every EPSS file states its own ``score_date``.  That internal date
is checked against the requested cutoff; a mismatch is reported as
``SCORE_DATE_MISMATCH`` rather than quietly accepted.
"""

from __future__ import annotations

import gzip
import hashlib
import re
from datetime import date
from typing import Optional

from .. import constants as C
from ..records import ArtifactRecord, is_policy_refusal, transport_reason
from ..store import ArtifactStore
from ..transport import Transport, TransportError

SOURCE = "epss"
OFFICIAL_HOST = "epss.cyentia.com"
OFFICIAL_URL_TEMPLATE = f"https://{OFFICIAL_HOST}/epss_scores-{{date}}.csv.gz"
#: Documented but *not* used: only reachable copy in some environments.
MIRROR_NOTE = "github.com/empiricalsec/epss_scores (third party, not used)"

HEADER_RE = re.compile(r"(model_version|score_date):([^,\s]+)")
ROW_RE = re.compile(r"^CVE-\d{4}-\d{4,},[0-9.eE+-]+,[0-9.eE+-]+\s*$")


def official_url(day: date) -> str:
    return OFFICIAL_URL_TEMPLATE.format(date=day.isoformat())


def artifact_path(day: date) -> str:
    return f"epss/epss_scores-{day.isoformat()}.csv.gz"


def _decompress(body: bytes) -> str:
    if body[:2] == b"\x1f\x8b":
        return gzip.decompress(body).decode("utf-8", "strict")
    return body.decode("utf-8", "strict")


def inspect_payload(body: bytes) -> dict:
    """Parse an EPSS payload and return its header facts.

    Raises ``ValueError`` with a stable reason code for unusable payloads.
    """
    try:
        text = _decompress(body)
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise ValueError(C.ARTIFACT_UNREADABLE) from exc

    lines = text.splitlines()
    if not lines or not lines[0].startswith("#"):
        raise ValueError(C.MALFORMED_RESPONSE)
    fields = dict(HEADER_RE.findall(lines[0]))
    if "score_date" not in fields or "model_version" not in fields:
        raise ValueError(C.MALFORMED_RESPONSE)

    rows = 0
    for index, line in enumerate(lines[1:]):
        if not line.strip() or line.startswith("#"):
            continue
        if index == 0 and line.strip().lower() == "cve,epss,percentile":
            continue  # the published column header, not a data row
        if not ROW_RE.match(line):
            raise ValueError(C.MALFORMED_RESPONSE)
        rows += 1
    if rows == 0:
        raise ValueError(C.MALFORMED_RESPONSE)

    return {
        "model_version": fields["model_version"],
        "score_date": fields["score_date"],
        "rows": rows,
        "declared_header": lines[0][:200],
    }


def _record_error(
    record: ArtifactRecord, exc: TransportError, *, day: date
) -> ArtifactRecord:
    record.request_url = exc.url
    record.http_status = exc.status
    record.retrieved_at = exc.retrieved_at
    record.reason_code = transport_reason(exc, not_found=C.EPSS_FILE_MISSING)
    if is_policy_refusal(exc):
        # We declined to follow the request; the publisher never answered.
        record.content_status = C.BLOCKED
    record.details["error"] = exc.reason
    record.details["requested_date"] = day.isoformat()
    record.details["mirror_available"] = MIRROR_NOTE
    return record.finalize()


def acquire_daily(
    transport: Transport,
    day: date,
    *,
    store: Optional[ArtifactStore] = None,
    historical: bool = True,
) -> ArtifactRecord:
    """Fetch the exact EPSS file for ``day`` from the official publisher.

    ``historical=True`` describes a block cutoff: the record carries the cutoff
    date and an on-the-day retrieval is still ``LATE_RETRIEVAL`` relative to
    ``T 00:00:00Z``.  ``historical=False`` is for prospective capture, where the
    date is an *observation date*, not a block boundary; the record then carries
    no cutoff and its access provenance simply says the bytes were retrieved at
    the recorded time.  The two are never mixed, because a prospective capture
    must not look like a retrospective cutoff acquisition.
    """
    url = official_url(day)
    record = ArtifactRecord(
        source=SOURCE,
        key=day.isoformat(),
        channel=C.CHANNEL_OFFICIAL,
        source_url=url,
        request_url=url,
        cutoff=day.isoformat() if historical else None,
        content_status=C.UNAVAILABLE,
        reason_code=C.EPSS_FILE_MISSING,
    )
    record.details["historical_cutoff"] = historical

    try:
        response = transport.get(url, accept="application/gzip, text/csv")
    except TransportError as exc:
        return _record_error(record, exc, day=day)

    record.retrieved_at = response.retrieved_at
    record.final_url = response.final_url
    record.http_status = response.status
    body = response.body
    record.bytes = len(body)
    record.sha256 = hashlib.sha256(body).hexdigest()

    if not body:
        record.reason_code = C.EPSS_FILE_MISSING
        record.details["error"] = "empty body"
        return record.finalize()

    try:
        facts = inspect_payload(body)
    except ValueError as exc:
        record.reason_code = str(exc)
        return record.finalize()

    record.details.update(facts)
    internal_date = facts["score_date"][:10]
    record.source_timestamp = facts["score_date"]
    record.details["file_score_date"] = internal_date
    record.details["requested_date"] = day.isoformat()

    if internal_date != day.isoformat():
        record.content_status = C.UNAVAILABLE
        record.reason_code = C.SCORE_DATE_MISMATCH
        record.details["note"] = (
            "Refusing to substitute a score file whose own date differs from the "
            "cutoff; the bytes are kept for inspection but do not satisfy the "
            "requirement."
        )
        return record.finalize()

    if store is not None:
        stored = store.write(artifact_path(day), body)
        record.artifact_path = stored.relative_path
        record.bytes = stored.bytes
        record.sha256 = stored.sha256
    else:
        record.details["stored"] = False

    record.content_status = C.VERIFIED
    record.reason_code = C.OK_VERIFIED
    return record.finalize()


def mirror_record(day: date) -> ArtifactRecord:
    """Record that a third-party mirror exists, without fetching or using it."""
    record = ArtifactRecord(
        source=SOURCE,
        key=f"{day.isoformat()}#mirror",
        channel=C.CHANNEL_THIRD_PARTY_MIRROR,
        source_url="https://github.com/empiricalsec/epss_scores",
        request_url="",
        cutoff=day.isoformat(),
        content_status=C.UNAVAILABLE,
        reason_code=C.THIRD_PARTY_MIRROR_ONLY,
        details={
            "mirror_path": f"YYYY/epss_scores-{day.isoformat()}.csv.gz",
            "note": "Not requested. A mirror cannot satisfy an official-source requirement.",
        },
    )
    return record.finalize()


__all__ = [
    "HEADER_RE",
    "MIRROR_NOTE",
    "OFFICIAL_HOST",
    "SOURCE",
    "acquire_daily",
    "artifact_path",
    "inspect_payload",
    "mirror_record",
    "official_url",
]
