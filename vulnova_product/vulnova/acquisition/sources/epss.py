"""EPSS daily score-file acquisition for one exact historical date.

The rule for this source is deliberately narrow: a cutoff either has *its own*
daily file or it has nothing.  A newer file, a later model version, or a
backfilled snapshot is never substituted, because substituting one would rewrite
history and make the resulting evaluation untraceable.

The header of every EPSS file states its own ``score_date``.  That internal date
is checked against the requested cutoff; a mismatch is reported as
``SCORE_DATE_MISMATCH`` rather than quietly accepted.

**Host, and how well it is established.**  Four different claims are kept apart
here.  Collapsing them is how a plausible URL becomes a claimed fact:

1. *Published now.*  FIRST's "Get the Data" page names
   ``epss.empiricalsecurity.com`` as the host for the daily CSV, gives the
   current-day file as
   ``https://epss.empiricalsecurity.com/epss_scores-current.csv.gz``, and states
   that *that* URL redirects.  It does not show the date-specific pattern.
2. *Historically documented, not retrievable now.*  FIRST's EPSS statistics page
   at ``https://www.first.org/epss/data_stats`` listed the date-specific pattern
   ``epss_scores-YYYY-MM-DD.csv.gz`` explicitly.  It survives in search indexes
   and in third-party reports that cite it, but a direct request now returns 404,
   so it is documented history rather than a live page that can be re-checked.
   The pattern therefore *has* appeared in FIRST-hosted documentation; saying
   otherwise would be wrong.
3. *Observed.*  A date-specific file fetched from
   ``https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`` for
   2026-10-19 declared ``score_date:2026-10-19T12:00:27Z`` in its own header.
   That retrieval path returns the file body only — no HTTP status and no
   ``Location`` header — so it establishes the payload, not the transport
   behaviour.
4. *Not established.*  The HTTP status, the ``Location`` header and the redirect
   destination of a date-specific request are all **unobserved**.

This module therefore requests the current host directly rather than relying on a
redirect from the legacy ``epss.cyentia.com``, which FIRST no longer names.

**Redirects.**  In production the transport refuses an unapproved redirect before
the follow-up request is issued, and refuses HTTPS downgrades on every hop.  A
:class:`~vulnova.acquisition.transport.Transport` is injectable, though, so this
module *also* re-checks the URL that actually answered, using the narrower
:data:`APPROVED_RESPONSE_HOSTS`.  The distinction matters: the transport check
covers hosts the transport allows, while this check is what holds when a caller
supplies its own transport (or a broader policy).

A refused response is recorded as ``BLOCKED`` / ``REDIRECT_BLOCKED``.  Its body is
never parsed, never hashed and never written to the store.  When this check is
what refuses it, both ``final_url`` and ``request_url`` are kept so the refusal is
visible; when the transport refuses first, no response exists and ``final_url`` is
absent.  The transport has already read the bytes into memory before this check
runs — unavoidable without a streaming API — so the guarantee is about what is
*done* with them, not about whether they were received.

If the date-specific endpoint does redirect to an infrastructure host, capture
will fail closed with ``BLOCKED`` until an evidence-backed allowance is added.
That is the intended trade: an unverified redirect is not silently trusted.
"""

from __future__ import annotations

import gzip
import hashlib
import re
import urllib.parse
from datetime import date
from typing import Optional

from .. import constants as C
from ..records import ArtifactRecord, is_policy_refusal, transport_reason
from ..store import ArtifactStore
from ..transport import Transport, TransportError

SOURCE = "epss"

#: The daily-CSV host named by FIRST's current documentation.
OFFICIAL_HOST = "epss.empiricalsecurity.com"
OFFICIAL_URL_TEMPLATE = f"https://{OFFICIAL_HOST}/epss_scores-{{date}}.csv.gz"

#: Hosts a response may legitimately come from.  Exactly one: the host FIRST
#: publishes for the daily CSV, and the host the observed exact-date response came
#: from.  ``www.first.org`` is deliberately absent.  It is FIRST's documentation
#: site, but nothing shows the *data* endpoint redirecting there, and an allowlist
#: entry needs evidence rather than plausibility.
#:
#: This tuple is narrower than the transport allowlist on purpose.  It is not a
#: duplicate of it: a caller can inject a transport, or one configured with a
#: broader policy, and this check is what still holds.
APPROVED_RESPONSE_HOSTS = (OFFICIAL_HOST,)

#: Recorded on a run whose source is unavailable.  The GitHub archive is
#: described by its publisher as the official historical archive, but it is *not*
#: fetched or substituted here: a daily file that was not retrieved from the
#: documented daily-CSV endpoint cannot satisfy the requirement.  The channel and
#: reason labels are unchanged from 1.7, whose sealed manifest carries them.
MIRROR_NOTE = "github.com/empiricalsec/epss_scores (third party, not used)"

HEADER_RE = re.compile(r"(model_version|score_date):([^,\s]+)")
ROW_RE = re.compile(r"^CVE-\d{4}-\d{4,},[0-9.eE+-]+,[0-9.eE+-]+\s*$")


def official_url(day: date) -> str:
    return OFFICIAL_URL_TEMPLATE.format(date=day.isoformat())


def artifact_path(day: date) -> str:
    return f"epss/epss_scores-{day.isoformat()}.csv.gz"


def response_url_problem(url: object) -> Optional[str]:
    """Reason code when the URL that answered is not an approved EPSS target.

    ``None`` means the bytes may be parsed.  ``HTTPS_DOWNGRADE_BLOCKED`` means the
    response was not HTTPS; every other rejection is
    ``DISALLOWED_REDIRECT_HOST``.  Those are the two codes the transport already
    uses for redirect refusals, so a refusal reads the same whichever layer
    caught it.

    The URL reaches this function from an injectable transport, so it is treated
    as untrusted input: a non-string, an unparseable URL, a malformed or
    non-default port, or embedded credentials are all refusals rather than
    exceptions or silent acceptance.  Only an exact hostname match on the default
    HTTPS port passes.
    """
    if not isinstance(url, str):
        return "DISALLOWED_REDIRECT_HOST"
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        # ``.port`` raises ValueError for a non-numeric or out-of-range port and
        # ``urlsplit`` does the same for a malformed authority such as a broken
        # IPv6 literal.  Both are untrusted input, not programming errors.
        port = parts.port
    except ValueError:
        return "DISALLOWED_REDIRECT_HOST"
    if parts.scheme.lower() != "https":
        return "HTTPS_DOWNGRADE_BLOCKED"
    if parts.username is not None or parts.password is not None:
        # The source never builds such a URL.  A credential-bearing final URL
        # would also be persisted verbatim into the run record.
        return "DISALLOWED_REDIRECT_HOST"
    # "host:/path" parses with no port, which would make a malformed authority
    # indistinguishable from a clean one.  The source never builds that form.
    if parts.netloc.rsplit("@", 1)[-1].endswith(":"):
        return "DISALLOWED_REDIRECT_HOST"
    if port not in (None, 443):
        return "DISALLOWED_REDIRECT_HOST"
    if host not in APPROVED_RESPONSE_HOSTS:
        return "DISALLOWED_REDIRECT_HOST"
    return None


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

    # The transport already refuses an unapproved redirect before issuing it, but
    # a Transport is injectable and may carry a broader policy.  Re-check the URL
    # that actually answered before the body is parsed, hashed or stored, so the
    # guarantee does not depend on which transport implementation was passed in.
    # (The bytes themselves have already been read by then; the check governs
    # what is done with them.)
    problem = response_url_problem(response.final_url)
    if problem is not None:
        record.content_status = C.BLOCKED
        record.reason_code = C.REDIRECT_BLOCKED
        record.details["error"] = problem
        record.details["refused_final_url"] = response.final_url
        record.details["requested_date"] = day.isoformat()
        return record.finalize()

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
    "APPROVED_RESPONSE_HOSTS",
    "HEADER_RE",
    "MIRROR_NOTE",
    "OFFICIAL_HOST",
    "SOURCE",
    "acquire_daily",
    "artifact_path",
    "inspect_payload",
    "mirror_record",
    "official_url",
    "response_url_problem",
]
