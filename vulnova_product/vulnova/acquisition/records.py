"""Record types shared by the acquisition sources.

The two-axis model lives here.  ``content_status`` answers "are these bytes what
they claim to be?", ``access_provenance`` answers "did we observe this at the
time it describes?".  Only both together can verify *historical retrieval*
provenance, which is why a freshly downloaded 2025 revision is verified content
with late access — never verified historical provenance.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..evaluation.temporal import parse_date
from . import constants as C


def to_instant(value: str) -> dt.datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def cutoff_instant(cutoff: dt.date) -> dt.datetime:
    """The cutoff is the instant ``T 00:00:00Z``."""
    return dt.datetime.combine(cutoff, dt.time.min, tzinfo=dt.timezone.utc)


@dataclass
class ArtifactRecord:
    source: str
    key: str
    channel: str
    source_url: str
    request_url: str
    content_status: str
    reason_code: str
    access_provenance: str = C.NOT_RETRIEVED
    cutoff: Optional[str] = None
    retrieved_at: Optional[str] = None
    source_timestamp: Optional[str] = None
    revision: Optional[str] = None
    http_status: Optional[int] = None
    artifact_path: Optional[str] = None
    bytes: Optional[int] = None
    sha256: Optional[str] = None
    historical_retrieval_verified: bool = False
    details: dict = field(default_factory=dict)

    # ------------------------------------------------------------ derivation
    def classify_access(self) -> str:
        """Derive access provenance from the recorded timestamps.

        A record whose retrieval time is unknown can never be contemporaneous.
        A record retrieved after its cutoff is a late retrieval even if the
        content is authentic and even if the source timestamp is old.  Records
        without a cutoff describe a current snapshot, whose retrieval is by
        definition contemporaneous with the source state it captures.

        A failed request still records *when* it was attempted, but no bytes
        were obtained, so its access provenance is ``NOT_RETRIEVED`` rather than
        ``LATE_RETRIEVAL``: nothing was retrieved to be late.
        """
        if not self.retrieved_at:
            return C.NOT_RETRIEVED
        if not self.sha256:
            return C.NOT_RETRIEVED
        try:
            retrieved = to_instant(self.retrieved_at)
        except (TypeError, ValueError):
            return C.NOT_RETRIEVED
        if not self.cutoff:
            return C.CONTEMPORANEOUS
        try:
            boundary = cutoff_instant(parse_date(self.cutoff))
        except (TypeError, ValueError):
            return C.NOT_RETRIEVED
        return C.CONTEMPORANEOUS if retrieved <= boundary else C.LATE_RETRIEVAL

    def finalize(self) -> "ArtifactRecord":
        self.access_provenance = self.classify_access()
        self.historical_retrieval_verified = bool(
            self.content_status == C.VERIFIED
            and self.access_provenance == C.CONTEMPORANEOUS
            and self.cutoff is not None
            and self.sha256
            and self.retrieved_at
        )
        if self.source_timestamp and self.retrieved_at:
            try:
                if to_instant(self.retrieved_at) < to_instant(self.source_timestamp):
                    self.content_status = C.BLOCKED
                    self.reason_code = C.RETRIEVAL_BEFORE_SOURCE_TIME
                    self.historical_retrieval_verified = False
            except (TypeError, ValueError):
                pass
        return self

    @property
    def status(self) -> str:
        """Status this record contributes, including access provenance.

        Content that is authentic but was retrieved late contributes
        ``BLOCKED`` to a *historical retrieval* requirement; callers that only
        care about content read ``content_status`` directly.
        """
        if self.content_status != C.VERIFIED:
            return self.content_status
        if self.cutoff and self.access_provenance != C.CONTEMPORANEOUS:
            return C.BLOCKED
        return C.VERIFIED

    def as_dict(self) -> dict:
        payload = {
            "source": self.source,
            "key": self.key,
            "channel": self.channel,
            "source_url": self.source_url,
            "request_url": self.request_url,
            "cutoff": self.cutoff,
            "content_status": self.content_status,
            "status": self.status,
            "reason_code": self.reason_code,
            "access_provenance": self.access_provenance,
            "historical_retrieval_verified": self.historical_retrieval_verified,
            "retrieved_at": self.retrieved_at,
            "source_timestamp": self.source_timestamp,
            "revision": self.revision,
            "http_status": self.http_status,
            "artifact_path": self.artifact_path,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass
class Requirement:
    id: str
    title: str
    status: str
    reason_code: str
    detail: str
    records: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        payload = {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "records": list(self.records),
        }
        if self.evidence:
            payload["evidence"] = self.evidence
        return payload


def _effective_status(record: ArtifactRecord, use_access_provenance: bool) -> str:
    return record.status if use_access_provenance else record.content_status


def _effective_reason(record: ArtifactRecord, status: str) -> str:
    """Explain a status, preferring the access axis when that is what failed."""
    if status == C.BLOCKED and record.content_status == C.VERIFIED:
        return C.RETRIEVAL_NOT_CONTEMPORANEOUS
    return record.reason_code


def requirement_from_records(
    requirement_id: str,
    title: str,
    records: list[ArtifactRecord],
    *,
    empty_detail: str = "No records were produced.",
    use_access_provenance: bool = True,
    evidence: Optional[dict] = None,
) -> Requirement:
    """Summarise a set of records into one requirement.

    An empty record set is ``BLOCKED``: nothing was inspected, so nothing can be
    reported as verified.
    """
    if not records:
        return Requirement(
            id=requirement_id,
            title=title,
            status=C.BLOCKED,
            reason_code=C.NO_RECORDS,
            detail=empty_detail,
            evidence=evidence or {},
        )
    evaluated = [
        (record, _effective_status(record, use_access_provenance))
        for record in records
    ]
    statuses = [record_status for _, record_status in evaluated]
    status = C.worst(statuses)
    reason = next(
        (
            _effective_reason(record, record_status)
            for record, record_status in evaluated
            if record_status == status
        ),
        C.OK_VERIFIED,
    )
    failed = [
        (record, record_status)
        for record, record_status in evaluated
        if record_status != C.VERIFIED
    ]
    if failed:
        detail = "; ".join(
            f"{record.key}: {_effective_reason(record, record_status)}"
            for record, record_status in failed[:6]
        )
        if len(failed) > 6:
            detail += f"; and {len(failed) - 6} more"
    else:
        detail = f"All {len(records)} record(s) verified."
    return Requirement(
        id=requirement_id,
        title=title,
        status=status,
        reason_code=reason,
        detail=detail,
        records=[f"{record.source}:{record.key}" for record in records],
        evidence=evidence or {},
    )


def late_retrievals(records: Iterable[ArtifactRecord]) -> list[ArtifactRecord]:
    return [record for record in records if record.access_provenance == C.LATE_RETRIEVAL]


__all__ = [
    "ArtifactRecord",
    "Requirement",
    "cutoff_instant",
    "late_retrievals",
    "requirement_from_records",
    "to_instant",
]
