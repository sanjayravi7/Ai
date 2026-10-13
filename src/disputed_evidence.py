"""Pure evidence parsing and classification for ``** DISPUTED **`` CVE records.

This module performs no network access and never writes files. It answers one
question per disputed dataset record, using only text that an authoritative
source actually contains:

* what the bundled snapshot's ``** DISPUTED **`` marker says (the *claim* under
  audit), quoted verbatim;
* what the official CVE Program record (CVE Services 5.x, as published in
  ``CVEProject/cvelistV5``) says about that claim; and
* how confident that reading is, with the JSON path of the field that was read.

Important boundaries, stated once and enforced by the code:

* A dispute marker is **not** proof that a CVE is invalid, and ``PUBLISHED`` is
  **not** proof that a disputed technical claim is true. The two are recorded
  separately: :data:`POSITION_*` describes the *administrative* position of the
  authoritative record, and :data:`RESOLUTION_*` describes whether any retrieved
  source actually resolves the technical claim.
* Missing evidence is never treated as negative evidence. A record that could
  not be retrieved is ``NOT_VERIFIABLE``, and a record that says nothing about a
  dispute is ``INSUFFICIENT`` evidence, not a refutation.
* Rationale text is only ever copied verbatim from the source, together with the
  JSON path it came from. Nothing is paraphrased, summarised, or invented.

Vocabulary
----------

``POSITION_*`` -- does the official record support, contradict, or fail to
resolve the dataset's disputed claim?

``RESOLUTION_*`` -- the audit-level outcome for the record, grouped by
:data:`BUCKET_*` (``RESOLVED`` / ``UNRESOLVED`` / ``NOT_VERIFIABLE``).

``EXCLUSION_*`` -- whether the retrieved evidence would justify removing the
record from a vulnerability ranking. Only a withdrawn identifier
(``state == REJECTED``) sets :data:`EXCLUSION_SUPPORTED`.

Malformed official records raise :class:`cve_status_sources.CveStatusSchemaError`
or :class:`cve_status_sources.CveStatusValidationError`, the same exceptions the
Phase 2.1 status parser uses, so a caller cannot confuse "unreadable" with
"absent".
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .cve_status_sources import (
    CveStatusSchemaError,
    CveStatusValidationError,
    DISPUTED_MARKER,
    parse_consult_ids,
)

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

#: Administrative position of the authoritative record relative to the marker.
POSITION_SUPPORTS = "SUPPORTS_DISPUTE_RECORDED"
POSITION_CONTRADICTS = "CONTRADICTS_DISPUTE_RECORDED"
POSITION_DOES_NOT_RESOLVE = "DOES_NOT_RESOLVE"
POSITION_NO_RECORD = "NO_AUTHORITATIVE_RECORD"
POSITIONS = (
    POSITION_SUPPORTS,
    POSITION_CONTRADICTS,
    POSITION_DOES_NOT_RESOLVE,
    POSITION_NO_RECORD,
)

#: Audit-level outcome for the disputed claim.
RESOLUTION_WITHDRAWN = "RESOLVED_WITHDRAWN"
RESOLUTION_CONTRADICTED = "RESOLVED_DISPUTE_CONTRADICTED"
RESOLUTION_OPEN = "OPEN_DISPUTE_DOCUMENTED"
RESOLUTION_UNRESOLVED = "UNRESOLVED_NO_DISPUTE_SIGNAL"
RESOLUTION_NON_FINAL = "UNRESOLVED_NON_FINAL_STATE"
RESOLUTION_NOT_VERIFIABLE = "NOT_VERIFIABLE"
RESOLUTIONS = (
    RESOLUTION_WITHDRAWN,
    RESOLUTION_CONTRADICTED,
    RESOLUTION_OPEN,
    RESOLUTION_UNRESOLVED,
    RESOLUTION_NON_FINAL,
    RESOLUTION_NOT_VERIFIABLE,
)

BUCKET_RESOLVED = "RESOLVED"
BUCKET_UNRESOLVED = "UNRESOLVED"
BUCKET_NOT_VERIFIABLE = "NOT_VERIFIABLE"
BUCKETS = (BUCKET_RESOLVED, BUCKET_UNRESOLVED, BUCKET_NOT_VERIFIABLE)

_RESOLUTION_BUCKET = {
    RESOLUTION_WITHDRAWN: BUCKET_RESOLVED,
    RESOLUTION_CONTRADICTED: BUCKET_RESOLVED,
    RESOLUTION_OPEN: BUCKET_UNRESOLVED,
    RESOLUTION_UNRESOLVED: BUCKET_UNRESOLVED,
    RESOLUTION_NON_FINAL: BUCKET_UNRESOLVED,
    RESOLUTION_NOT_VERIFIABLE: BUCKET_NOT_VERIFIABLE,
}

#: Evidence classification (what kind of authoritative evidence exists).
CLASS_WITHDRAWN = "AUTHORITATIVE_WITHDRAWN"
CLASS_DISPUTE_TEXT = "AUTHORITATIVE_DISPUTE_DOCUMENTED_TEXT"
CLASS_DISPUTE_TAG = "AUTHORITATIVE_DISPUTE_DOCUMENTED_TAG_ONLY"
CLASS_CONTRADICTED = "AUTHORITATIVE_DISPUTE_CONTRADICTED"
CLASS_SILENT = "AUTHORITATIVE_SILENT_ON_DISPUTE"
CLASS_NON_FINAL = "AUTHORITATIVE_NON_FINAL_STATE"
CLASS_NONE = "NO_AUTHORITATIVE_EVIDENCE"
CLASSIFICATIONS = (
    CLASS_WITHDRAWN,
    CLASS_DISPUTE_TEXT,
    CLASS_DISPUTE_TAG,
    CLASS_CONTRADICTED,
    CLASS_SILENT,
    CLASS_NON_FINAL,
    CLASS_NONE,
)

#: How well the retrieved evidence answers the disputed claim.
STATUS_SUFFICIENT = "SUFFICIENT"
STATUS_INSUFFICIENT = "INSUFFICIENT"
STATUS_CONTRADICTORY = "CONTRADICTORY"
STATUS_NOT_VERIFIABLE = "NOT_VERIFIABLE"
EVIDENCE_STATUSES = (
    STATUS_SUFFICIENT,
    STATUS_INSUFFICIENT,
    STATUS_CONTRADICTORY,
    STATUS_NOT_VERIFIABLE,
)

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_NONE = "NONE"
CONFIDENCES = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW, CONFIDENCE_NONE)

EXCLUSION_SUPPORTED = "SUPPORTED"
EXCLUSION_NOT_SUPPORTED = "NOT_SUPPORTED"
EXCLUSION_NOT_EVALUABLE = "NOT_EVALUABLE"
EXCLUSION_VALUES = (EXCLUSION_SUPPORTED, EXCLUSION_NOT_SUPPORTED, EXCLUSION_NOT_EVALUABLE)

#: Retrieval outcome for the authoritative record of one dataset row.
RETRIEVAL_RETRIEVED = "RETRIEVED"
RETRIEVAL_NOT_FOUND = "HTTP_404_NOT_FOUND"
RETRIEVAL_FAILED = "FETCH_FAILED"
RETRIEVAL_MALFORMED = "MALFORMED_RECORD"
RETRIEVAL_NOT_ATTEMPTED = "NOT_ATTEMPTED"
RETRIEVAL_VALUES = (
    RETRIEVAL_RETRIEVED,
    RETRIEVAL_NOT_FOUND,
    RETRIEVAL_FAILED,
    RETRIEVAL_MALFORMED,
    RETRIEVAL_NOT_ATTEMPTED,
)

#: States the CVE Program treats as final.
FINAL_STATES = ("PUBLISHED", "REJECTED")
STATE_REJECTED = "REJECTED"
STATE_PUBLISHED = "PUBLISHED"

DISPUTE_TAG = "disputed"

#: Text patterns that document a dispute. ``\b`` boundaries stop the word
#: "undisputed" from being read as "disputed". Each rule name is written to the
#: audit table, so a reader can see which wording produced the label.
_DISPUTE_LANGUAGE_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("disputed_marker_text", re.compile(r"\*\*\s*DISPUTED\s*\*\*", re.IGNORECASE)),
    ("disputed_word", re.compile(r"\bdisput(?:e|es|ed)\b", re.IGNORECASE)),
    # A recorded counter-position counts as dispute language even when the source
    # never uses the word "dispute" (for example "NOTE: Third parties claim/state
    # this is not an issue").
    (
        "counter_position_language",
        re.compile(
            r"\b(?:not\s+(?:a|an)\s+(?:valid\s+|real\s+)?(?:security\s+)?(?:issue|vulnerability|problem)\b"
            r"|does\s+not\s+consider\s+(?:this|it)\b"
            r"|do\s+not\s+consider\s+(?:this|it)\b"
            r"|no\s+general\s+agreement\s+that\s+this\s+is\s+a\s+vulnerability\b)",
            re.IGNORECASE,
        ),
    ),
    ("rejection_notice", re.compile(r"\*\*\s*REJECT\s*\*\*", re.IGNORECASE)),
    ("withdrawn_candidate", re.compile(r"do\s+not\s+use\s+this\s+candidate\s+number", re.IGNORECASE)),
    ("withdrawn_word", re.compile(r"\bwithdrawn\b", re.IGNORECASE)),
)

#: Text patterns that explicitly resolve a dispute *in favour of validity*.
#: These are deliberately narrow: only an explicit statement counts, so a
#: ``PUBLISHED`` record on its own can never be read as a refutation.
_CONTRADICTION_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (
        "dispute_resolved",
        re.compile(
            r"\bdispute\s+(?:has|have|was|were|is|are)\s+(?:been\s+)?"
            r"(?:resolved|withdrawn|dismissed|lifted|dropped)\b",
            re.IGNORECASE,
        ),
    ),
    ("no_longer_disputed", re.compile(r"\bno\s+longer\s+disputed\b", re.IGNORECASE)),
    ("not_disputed", re.compile(r"\b(?:is|was)\s+not\s+disputed\b", re.IGNORECASE)),
    ("reinstated", re.compile(r"\breinstated\b", re.IGNORECASE)),
    (
        "dispute_resolution_notice",
        re.compile(r"\bdispute\s+(?:has\s+been|is)\s+resolved\s+in\s+favou?r\b", re.IGNORECASE),
    ),
)

#: Who the recorded text names as holding the counter-position. Rules are
#: ordered most specific first; the matched excerpt is always stored verbatim.
_ACTOR_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (
        "vendor_or_upstream",
        re.compile(
            r"\b(?:disputed|disputes)\s+by\s+(?:the\s+)?(?:upstream\s+)?"
            r"(?:vendor|manufacturer|supplier|developer|maintainer)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "vendor_or_upstream",
        re.compile(
            r"\b(?:upstream\s+)?(?:vendor|manufacturer|supplier|maintainer|developer|author)s?"
            r"(?:'s)?\s+(?:has\s+|have\s+|is\s+|was\s+|are\s+|were\s+|reportedly\s+)?"
            r"(?:disput(?:e|es|ed)|claim(?:s|ed)?|stat(?:es|ed)|sa(?:ys|id)|report(?:s|ed)?|"
            r"indicat(?:es|ed)|assert(?:s|ed)?|respond(?:s|ed)?|contend(?:s|ed)?|maintain(?:s|ed)?|"
            r"does\s+not\s+consider|do\s+not\s+consider)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "vendor_or_upstream",
        re.compile(
            r"\b(?:upstream\s+)?(?:vendor|manufacturer|supplier|maintainer|developer|author)s?"
            r"(?:'s)?\s+position\s+is\b",
            re.IGNORECASE,
        ),
    ),
    (
        "third_party",
        re.compile(
            r"\b(?:some\s+|a\s+|the\s+|several\s+|certain\s+)?third\s+part(?:y|ies)\b[^.]{0,40}?"
            r"\b(?:disput|claim|stat|report|indicat|assert|sa(?:ys|id))\w*\b",
            re.IGNORECASE,
        ),
    ),
    (
        "third_party",
        re.compile(r"\bdisputed\s+by\s+(?:some\s+|a\s+|the\s+|several\s+)?third\s+part(?:y|ies)\b", re.IGNORECASE),
    ),
    (
        "cna_or_assigner",
        re.compile(r"\bdisputed\s+by\s+(?:the\s+)?(?:CNA|assigner|CVE)\b", re.IGNORECASE),
    ),
    (
        "researcher_or_reporter",
        re.compile(r"\bdisputed\s+by\s+(?:a\s+|the\s+)?(?:reporter|researcher|security\s+researcher)\b", re.IGNORECASE),
    ),
)

#: What the recorded text says is being contested. ``UNSPECIFIED`` means no
#: documented rule matched; it is never inferred from the marker alone.
_SUBJECT_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (
        "existence_or_validity",
        re.compile(
            r"\bnot\s+(?:a|an)\s+(?:valid\s+|real\s+)?(?:security\s+)?(?:vulnerability|issue|problem)\b"
            r"|\bdisput(?:e|es|ed)\s+that\s+this\s+is\s+a\s+vulnerability\b"
            r"|\bno\s+general\s+agreement\s+that\s+this\s+is\s+a\s+vulnerability\b"
            r"|\bdoes\s+not\s+consider\s+(?:this|it)\s+(?:as\s+)?(?:a\s+)?(?:security\s+)?(?:issue|vulnerability)\b"
            r"|\bdoes\s+not\s+exist\b|\bno\s+vulnerability\b",
            re.IGNORECASE,
        ),
    ),
    (
        "existence_or_validity",
        re.compile(
            r"\b(?:works?|behav(?:es|e|ing)|acts?|function(?:s|ing)?)\s+as\s+(?:intended|designed|documented)\b"
            r"|\bintended\s+(?:feature|functionality|behavior|behaviour)\b"
            r"|\bby\s+design\b",
            re.IGNORECASE,
        ),
    ),
    (
        "relevance_or_severity",
        re.compile(
            r"\bdisput(?:e|es|ed)\s+(?:the\s+|its\s+|this\s+)?(?:relevance|severity|impact|"
            r"rating|scoring|exploitability|risk|report)\b"
            r"|\bnot\s+an\s+attack\s+of\s+interest\b"
            r"|\bthreat\s+model\b"
            r"|\bdoes\s+not\s+cross\s+a\s+privilege\s+boundary\b",
            re.IGNORECASE,
        ),
    ),
    (
        "behavior_or_reproducibility",
        re.compile(
            r"\b(?:cannot|can\s+not|could\s+not|unable\s+to|not\s+able\s+to|not\s+been\s+able\s+to)\s+"
            r"(?:be\s+)?(?:reproduce|identify|confirm|verify)\b"
            r"|\bdisput(?:e|es|ed)\s+(?:that|whether)\b[^.]{0,120}?\b(?:cannot|can\s+not|not\s+able\s+to)\b",
            re.IGNORECASE,
        ),
    ),
)

#: Explicit documentation of a replacement identifier in record text.
_REPLACEMENT_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (
        "duplicate_of",
        re.compile(r"\bduplicate\s+of\s+(CVE-\d{4}-\d{4,})", re.IGNORECASE),
    ),
    (
        "superseded_by",
        re.compile(r"\bsupersed(?:ed|es)\s+by\s+(CVE-\d{4}-\d{4,})", re.IGNORECASE),
    ),
    (
        "replaced_by",
        re.compile(r"\breplaced\s+by\s+(CVE-\d{4}-\d{4,})", re.IGNORECASE),
    ),
    (
        "use_instead",
        re.compile(r"\b(?:use|reference)\s+(CVE-\d{4}-\d{4,})\s+instead\b", re.IGNORECASE),
    ),
)

_MAX_QUOTE_CHARS = 700


# ---------------------------------------------------------------------------
# Parsed view of one authoritative record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TextField:
    """One text field of an authoritative record, with its JSON path."""

    path: str
    value: str
    lang: str = ""


@dataclass(frozen=True)
class ReferenceField:
    """One reference of an authoritative record, with its JSON path."""

    path: str
    url: str
    name: str = ""
    tags: Tuple[str, ...] = ()


@dataclass
class DisputeRecordView:
    """Normalized, dispute-relevant view of one CVE Services 5.x record.

    Every field is copied from the source document without transformation
    except whitespace trimming. ``text_fields`` holds every free-text field that
    the classification rules scan, so the audit can disclose exactly which parts
    of the record were read.
    """

    cve_id: str
    state: str
    date_published: str = ""
    date_updated: str = ""
    date_reserved: str = ""
    date_rejected: str = ""
    assigner_short_name: str = ""
    assigner_org_id: str = ""
    data_version: str = ""
    data_type: str = ""
    cna_tags: Tuple[str, ...] = ()
    adp_tags: Tuple[str, ...] = ()
    metadata_tags: Tuple[str, ...] = ()
    provider_short_names: Tuple[str, ...] = ()
    text_fields: Tuple[TextField, ...] = ()
    rejected_reasons: Tuple[TextField, ...] = ()
    references: Tuple[ReferenceField, ...] = ()
    timeline: Tuple[TextField, ...] = ()
    replacement_ids: Tuple[str, ...] = ()
    replacement_evidence: Tuple[Tuple[str, str, str], ...] = ()
    cvss_version: str = ""
    cvss_base_score: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    # -- derived helpers ---------------------------------------------------

    @property
    def all_tags(self) -> Tuple[str, ...]:
        """Every tag seen on the record, lower-cased and de-duplicated."""
        seen: List[str] = []
        for tag in list(self.cna_tags) + list(self.adp_tags) + list(self.metadata_tags):
            lowered = str(tag).strip().lower()
            if lowered and lowered not in seen:
                seen.append(lowered)
        return tuple(seen)

    @property
    def dispute_tag_present(self) -> bool:
        return DISPUTE_TAG in self.all_tags

    @property
    def is_final_state(self) -> bool:
        return self.state in FINAL_STATES

    def scan_text(self) -> str:
        """Return the concatenated text the classification rules inspect."""
        return "\n".join(field.value for field in self.text_fields if field.value)

    def path_for_text(self, value: str) -> str:
        """Return the JSON path of the first text field holding ``value``."""
        for text_field in self.text_fields:
            if text_field.value == value:
                return text_field.path
        return ""


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:  # NaN without importing pandas
        return ""
    return str(value).strip()


def _load_document(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, (bytes, bytearray)):
        try:
            document = json.loads(bytes(payload).decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CveStatusSchemaError(f"CVE record is not valid UTF-8 JSON: {error}") from error
    elif isinstance(payload, str):
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as error:
            raise CveStatusSchemaError(f"CVE record is not valid JSON: {error}") from error
    else:
        document = payload
    if not isinstance(document, dict):
        raise CveStatusSchemaError("CVE record top level must be a JSON object.")
    return document


def _containers(document: Dict[str, Any]) -> Dict[str, Any]:
    containers = document.get("containers")
    if containers is None:
        return {}
    if not isinstance(containers, dict):
        raise CveStatusSchemaError("CVE record 'containers' must be a JSON object.")
    return containers


def _as_entries(value: Any) -> List[Dict[str, Any]]:
    """Return a container value as a list of dicts (5.x allows object or list)."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, dict)]
    return []


def _tags_of(entry: Dict[str, Any]) -> Tuple[str, ...]:
    tags = entry.get("tags")
    if not isinstance(tags, list):
        return ()
    return tuple(_text(tag) for tag in tags if _text(tag))


def _descriptions(entry: Dict[str, Any], prefix: str) -> List[TextField]:
    found: List[TextField] = []
    for position, description in enumerate(_as_entries(entry.get("descriptions"))):
        if not isinstance(description, dict):
            continue
        value = _text(description.get("value"))
        if value:
            found.append(
                TextField(
                    path=f"{prefix}/descriptions/{position}/value",
                    value=value,
                    lang=_text(description.get("lang")),
                )
            )
    return found


def _rejected_reasons(entry: Dict[str, Any], prefix: str) -> List[TextField]:
    found: List[TextField] = []
    reasons = entry.get("rejectedReasons")
    if not isinstance(reasons, list):
        return found
    for position, reason in enumerate(reasons):
        if isinstance(reason, dict):
            value = _text(reason.get("value"))
            lang = _text(reason.get("lang"))
        else:
            value, lang = _text(reason), ""
        if value:
            found.append(TextField(path=f"{prefix}/rejectedReasons/{position}/value", value=value, lang=lang))
    return found


def _timeline(entry: Dict[str, Any], prefix: str) -> List[TextField]:
    found: List[TextField] = []
    for position, entry_value in enumerate(_as_entries(entry.get("timeline"))):
        value = _text(entry_value.get("value"))
        if not value:
            continue
        stamp = _text(entry_value.get("time"))
        rendered = f"{stamp} {value}".strip() if stamp else value
        found.append(
            TextField(path=f"{prefix}/timeline/{position}/value", value=rendered, lang=_text(entry_value.get("lang")))
        )
    return found


def _legacy_description(entry: Dict[str, Any], prefix: str) -> List[TextField]:
    """Old-style (CVE 4.0) description carried inside ``x_legacyV4Record``."""
    legacy = entry.get("x_legacyV4Record")
    if not isinstance(legacy, dict):
        return []
    description = legacy.get("description")
    if not isinstance(description, dict):
        return []
    found: List[TextField] = []
    for position, item in enumerate(_as_entries(description.get("description_data"))):
        value = _text(item.get("value"))
        if value:
            found.append(
                TextField(
                    path=f"{prefix}/x_legacyV4Record/description/description_data/{position}/value",
                    value=value,
                    lang=_text(item.get("lang")),
                )
            )
    return found


def _references(entry: Dict[str, Any], prefix: str) -> List[ReferenceField]:
    found: List[ReferenceField] = []
    for position, reference in enumerate(_as_entries(entry.get("references"))):
        if not isinstance(reference, dict):
            continue
        url = _text(reference.get("url"))
        if not url:
            continue
        tags = reference.get("tags")
        found.append(
            ReferenceField(
                path=f"{prefix}/references/{position}",
                url=url,
                name=_text(reference.get("name")),
                tags=tuple(_text(tag) for tag in tags if _text(tag)) if isinstance(tags, list) else (),
            )
        )
    return found


def _first_cvss(containers: Dict[str, Any]) -> Tuple[str, Optional[float]]:
    """Return the first labelled CVSS base score found, for disclosure only."""
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for container_name in ("cna", "adp"):
            for entry in _as_entries(containers.get(container_name)):
                for metric in _as_entries(entry.get("metrics")):
                    value = metric.get(key)
                    if isinstance(value, dict) and value.get("baseScore") is not None:
                        try:
                            return key, float(value["baseScore"])
                        except (TypeError, ValueError):
                            continue
    return "", None


def _replacement_evidence(text_fields: Iterable[TextField]) -> Tuple[Tuple[str, str, str], ...]:
    """Return ``(rule, cve_id, json_path)`` for explicitly documented successors."""
    found: List[Tuple[str, str, str]] = []
    for text_field in text_fields:
        for rule, pattern in _REPLACEMENT_PATTERNS:
            for match in pattern.finditer(text_field.value):
                identifier = match.group(1).upper()
                entry = (rule, identifier, text_field.path)
                if entry not in found:
                    found.append(entry)
    return tuple(found)


def parse_dispute_record(payload: Any, *, expected_cve_id: Optional[str] = None) -> DisputeRecordView:
    """Parse one CVE Services 5.x record into a dispute-evidence view.

    Args:
        payload: Raw JSON bytes, text, or an already-decoded mapping.
        expected_cve_id: When given, the record's ``cveMetadata.cveId`` must
            match it (case-insensitive) or
            :class:`CveStatusValidationError` is raised.

    Raises:
        CveStatusSchemaError: The document is not a CVE 5.x record object.
        CveStatusValidationError: The identifier does not match
            ``expected_cve_id``.
    """
    document = _load_document(payload)
    metadata = document.get("cveMetadata")
    if not isinstance(metadata, dict):
        raise CveStatusSchemaError("CVE record is missing the 'cveMetadata' object.")
    cve_id = _text(metadata.get("cveId")).upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise CveStatusSchemaError(f"CVE record 'cveMetadata.cveId' is malformed: {metadata.get('cveId')!r}")
    if expected_cve_id is not None and cve_id != str(expected_cve_id).strip().upper():
        raise CveStatusValidationError(
            f"CVE record identifier mismatch: parsed {cve_id}, expected {expected_cve_id}."
        )

    containers = _containers(document)
    text_fields: List[TextField] = []
    rejected_reasons: List[TextField] = []
    references: List[ReferenceField] = []
    timeline: List[TextField] = []
    cna_tags: Tuple[str, ...] = ()
    adp_tags: Tuple[str, ...] = ()
    providers: List[str] = []

    for container_name in ("cna", "adp"):
        for index, entry in enumerate(_as_entries(containers.get(container_name))):
            prefix = f"containers/{container_name}" + (f"/{index}" if container_name == "adp" else "")
            tags = _tags_of(entry)
            if container_name == "cna":
                cna_tags = cna_tags + tags
            else:
                adp_tags = adp_tags + tags
            provider = entry.get("providerMetadata")
            if isinstance(provider, dict):
                short_name = _text(provider.get("shortName"))
                if short_name and short_name not in providers:
                    providers.append(short_name)
            text_fields.extend(_descriptions(entry, prefix))
            text_fields.extend(_legacy_description(entry, prefix))
            rejected_reasons.extend(_rejected_reasons(entry, prefix))
            timeline.extend(_timeline(entry, prefix))
            references.extend(_references(entry, prefix))

    metadata_tags = metadata.get("cveTags")
    metadata_tag_values = (
        tuple(_text(tag) for tag in metadata_tags if _text(tag)) if isinstance(metadata_tags, list) else ()
    )

    all_text: List[TextField] = list(text_fields) + list(rejected_reasons) + list(timeline)
    cvss_version, cvss_base_score = _first_cvss(containers)
    rejection_text = " ".join(field.value for field in rejected_reasons)
    replacements = _replacement_evidence(all_text)
    replacement_ids: List[str] = []
    for identifier in parse_consult_ids(rejection_text):
        if identifier not in replacement_ids:
            replacement_ids.append(identifier)
    for _, identifier, _path in replacements:
        if identifier not in replacement_ids:
            replacement_ids.append(identifier)

    return DisputeRecordView(
        cve_id=cve_id,
        state=_text(metadata.get("state")).upper(),
        date_published=_text(metadata.get("datePublished")),
        date_updated=_text(metadata.get("dateUpdated")),
        date_reserved=_text(metadata.get("dateReserved")),
        date_rejected=_text(metadata.get("dateRejected")),
        assigner_short_name=_text(metadata.get("assignerShortName")),
        assigner_org_id=_text(metadata.get("assignerOrgId")),
        data_version=_text(document.get("dataVersion")),
        data_type=_text(document.get("dataType")),
        cna_tags=cna_tags,
        adp_tags=adp_tags,
        metadata_tags=metadata_tag_values,
        provider_short_names=tuple(providers),
        text_fields=tuple(all_text),
        rejected_reasons=tuple(rejected_reasons),
        references=tuple(references),
        timeline=tuple(timeline),
        replacement_ids=tuple(replacement_ids),
        replacement_evidence=replacements,
        cvss_version=cvss_version,
        cvss_base_score=cvss_base_score,
    )


# ---------------------------------------------------------------------------
# Text scanning helpers
# ---------------------------------------------------------------------------


def sentence_containing(text: str, start: int, end: int, *, max_chars: int = _MAX_QUOTE_CHARS) -> str:
    """Return the sentence around ``text[start:end]``, trimmed to ``max_chars``.

    The excerpt is disclosure text only: it is copied from the source and never
    rewritten. When the sentence is longer than ``max_chars`` the excerpt is cut
    on a word boundary and suffixed with an ellipsis so a truncated quote is
    never mistaken for a complete one.
    """
    if not text:
        return ""
    left = max(text.rfind(". ", 0, start), text.rfind("\n", 0, start), text.rfind("; ", 0, start))
    left = 0 if left < 0 else left + 1
    candidates = [position for position in (text.find(". ", end), text.find("\n", end)) if position >= 0]
    right = min(candidates) + 1 if candidates else len(text)
    excerpt = text[left:right].strip()
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars].rsplit(" ", 1)[0].rstrip() + " ..."
    return excerpt


def match_patterns(
    text: str, patterns: Sequence[Tuple[str, "re.Pattern[str]"]]
) -> List[Tuple[str, str]]:
    """Return ``(rule_name, excerpt)`` for every pattern that matches ``text``.

    Rules are reported once each, in pattern order, using the first match.
    """
    if not text:
        return []
    found: List[Tuple[str, str]] = []
    for name, pattern in patterns:
        match = pattern.search(text)
        if match is None:
            continue
        found.append((name, sentence_containing(text, match.start(), match.end())))
    return found


def scan_record_text(view: DisputeRecordView, patterns: Sequence[Tuple[str, "re.Pattern[str]"]]):
    """Return ``(rule, excerpt, json_path)`` for the record's free-text fields.

    Fields are scanned in JSON-path order so the output is deterministic.
    """
    found: List[Tuple[str, str, str]] = []
    for text_field in sorted(view.text_fields, key=lambda item: item.path):
        for name, excerpt in match_patterns(text_field.value, patterns):
            entry = (name, excerpt, text_field.path)
            if entry not in found:
                found.append(entry)
    return found


def dataset_dispute_text(summary: Any) -> Dict[str, Any]:
    """Describe the ``** DISPUTED **`` marker of one dataset summary.

    Returns the exact marker position and the claim text that follows it. A
    marker that is not at the start of the summary is reported as
    ``marker_at_start = False`` rather than being treated as equivalent.
    """
    text = "" if summary is None else str(summary)
    index = text.find(DISPUTED_MARKER)
    stripped = text.lstrip()
    return {
        "disputed_marker_present": index >= 0,
        "disputed_marker_at_start": stripped.startswith(DISPUTED_MARKER),
        "disputed_marker_offset": index,
        "dataset_text_before_marker": text[:index].strip() if index > 0 else "",
        "disputed_claim_text": text[index + len(DISPUTED_MARKER) :].strip() if index >= 0 else text.strip(),
        "dataset_summary_original": text,
    }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _quote_for(view: DisputeRecordView, matches: Sequence[Tuple[str, str, str]]) -> Tuple[str, str, str]:
    """Return ``(rule, excerpt, json_path)`` for the first match, or blanks."""
    if not matches:
        return "", "", ""
    return matches[0]


def classify_dispute_evidence(
    view: Optional[DisputeRecordView],
    *,
    retrieval_status: str,
    dataset_claim_text: str = "",
) -> Dict[str, Any]:
    """Classify the evidence available for one disputed dataset record.

    Args:
        view: Parsed authoritative record, or ``None`` when none could be read.
        retrieval_status: One of :data:`RETRIEVAL_VALUES`; ``NOT_ATTEMPTED`` and
            failure statuses produce :data:`CLASS_NONE` and never a guess.
        dataset_claim_text: The text that followed ``** DISPUTED **`` in the
            snapshot, used only to describe who/what the marker disputes.

    Returns:
        A mapping with the classification fields the audit writes, including a
        verbatim ``authoritative_rationale`` and the JSON path it came from.
    """
    if retrieval_status not in RETRIEVAL_VALUES:
        raise CveStatusValidationError(f"Unknown retrieval status: {retrieval_status!r}")

    claim_actor = match_patterns(dataset_claim_text, _ACTOR_PATTERNS)
    claim_subject = match_patterns(dataset_claim_text, _SUBJECT_PATTERNS)

    if view is None:
        claim_actor_rule, claim_actor_quote = claim_actor[0] if claim_actor else ("", "")
        claim_subject_rule, claim_subject_quote = claim_subject[0] if claim_subject else ("", "")
        reason = {
            RETRIEVAL_NOT_FOUND: "official_cve_record_not_found_at_pinned_commit",
            RETRIEVAL_NOT_ATTEMPTED: "no_authoritative_lookup_was_performed",
        }.get(retrieval_status, f"official_cve_record_unreadable:{retrieval_status}")
        return {
            "official_record_position": POSITION_NO_RECORD,
            "dispute_resolution": RESOLUTION_NOT_VERIFIABLE,
            "resolution_bucket": BUCKET_NOT_VERIFIABLE,
            "evidence_classification": CLASS_NONE,
            "evidence_status": STATUS_NOT_VERIFIABLE,
            "evidence_confidence": CONFIDENCE_NONE,
            "confidence_rationale": (
                "No authoritative record was read for this identifier "
                f"({reason}); the disputed claim is neither supported nor refuted."
            ),
            "exclusion_evidence": EXCLUSION_NOT_EVALUABLE,
            "authoritative_rationale": "",
            "authoritative_rationale_field": "",
            "authoritative_rationale_status": "NOT_RECORDED_IN_SOURCE",
            "dispute_actor": claim_actor_rule.upper() if claim_actor_rule else "UNSPECIFIED",
            "dispute_actor_quote": claim_actor_quote,
            "dispute_actor_field": "dataset:summary" if claim_actor_rule else "",
            "dispute_subject": claim_subject_rule.upper() if claim_subject_rule else "UNSPECIFIED",
            "dispute_subject_quote": claim_subject_quote,
            "dispute_subject_field": "dataset:summary" if claim_subject_rule else "",
            "dispute_language_present": False,
            "dispute_language_rule": "",
            "dispute_language_field": "",
            "dispute_language_quote": "",
            "contradiction_rule": "",
            "contradiction_field": "",
            "contradiction_quote": "",
            "replacement_ids": (),
            "replacement_evidence_field": "",
            "review_reason": reason,
        }

    dispute_matches = scan_record_text(view, _DISPUTE_LANGUAGE_PATTERNS)
    contradiction_matches = scan_record_text(view, _CONTRADICTION_PATTERNS)
    record_actor = scan_record_text(view, _ACTOR_PATTERNS)
    record_subject = scan_record_text(view, _SUBJECT_PATTERNS)

    if record_actor:
        actor_rule, actor_excerpt, actor_field = record_actor[0]
    elif claim_actor:
        actor_rule, actor_excerpt, actor_field = claim_actor[0][0], claim_actor[0][1], "dataset:summary"
    else:
        actor_rule, actor_excerpt, actor_field = "", "", ""

    if record_subject:
        subject_rule, subject_excerpt, subject_field = record_subject[0]
    elif claim_subject:
        subject_rule, subject_excerpt, subject_field = claim_subject[0][0], claim_subject[0][1], "dataset:summary"
    else:
        subject_rule, subject_excerpt, subject_field = "", "", ""

    replacement_ids = view.replacement_ids
    replacement_field = view.replacement_evidence[0][2] if view.replacement_evidence else ""
    if not replacement_field and replacement_ids:
        replacement_field = "containers/cna/rejectedReasons/0/value"

    base = {
        "dispute_actor": actor_rule.upper() if actor_rule else "UNSPECIFIED",
        "dispute_actor_quote": actor_excerpt,
        "dispute_actor_field": actor_field,
        "dispute_subject": subject_rule.upper() if subject_rule else "UNSPECIFIED",
        "dispute_subject_quote": subject_excerpt,
        "dispute_subject_field": subject_field,
        "replacement_ids": replacement_ids,
        "replacement_evidence_field": replacement_field,
        "dispute_language_present": bool(dispute_matches),
        "dispute_language_rule": dispute_matches[0][0] if dispute_matches else "",
        "dispute_language_field": dispute_matches[0][2] if dispute_matches else "",
        "dispute_language_quote": dispute_matches[0][1] if dispute_matches else "",
        "contradiction_rule": contradiction_matches[0][0] if contradiction_matches else "",
        "contradiction_field": contradiction_matches[0][2] if contradiction_matches else "",
        "contradiction_quote": contradiction_matches[0][1] if contradiction_matches else "",
    }

    # 1. Withdrawn identifier: the authoritative source resolves the record in
    #    favour of withdrawal. This is the only evidence that supports removing
    #    a record from a vulnerability ranking.
    if view.state == STATE_REJECTED:
        reason_field = view.rejected_reasons[0].path if view.rejected_reasons else ""
        reason_text = view.rejected_reasons[0].value if view.rejected_reasons else ""
        base.update(
            {
                "official_record_position": POSITION_SUPPORTS,
                "dispute_resolution": RESOLUTION_WITHDRAWN,
                "resolution_bucket": BUCKET_RESOLVED,
                "evidence_classification": CLASS_WITHDRAWN,
                "evidence_status": STATUS_SUFFICIENT,
                "evidence_confidence": CONFIDENCE_HIGH,
                "confidence_rationale": (
                    "The authoritative record state is REJECTED, so the identifier is withdrawn; "
                    "the recorded rejection reason is quoted verbatim."
                    if reason_text
                    else "The authoritative record state is REJECTED, so the identifier is withdrawn; "
                    "no rejection-reason text is recorded in the record."
                ),
                "exclusion_evidence": EXCLUSION_SUPPORTED,
                "authoritative_rationale": reason_text,
                "authoritative_rationale_field": reason_field,
                "authoritative_rationale_status": "RECORDED" if reason_text else "NOT_RECORDED_IN_SOURCE",
                "review_reason": "" if reason_text else "withdrawn_without_recorded_reason",
            }
        )
        return base

    # 2. Explicit resolution of the dispute in favour of validity.
    if contradiction_matches:
        rule, excerpt, path = contradiction_matches[0]
        base.update(
            {
                "official_record_position": POSITION_CONTRADICTS,
                "dispute_resolution": RESOLUTION_CONTRADICTED,
                "resolution_bucket": BUCKET_RESOLVED,
                "evidence_classification": CLASS_CONTRADICTED,
                "evidence_status": STATUS_CONTRADICTORY,
                "evidence_confidence": CONFIDENCE_HIGH,
                "confidence_rationale": (
                    f"The authoritative record text contains an explicit dispute-resolution statement "
                    f"matched by rule '{rule}' at {path}."
                ),
                "exclusion_evidence": EXCLUSION_NOT_SUPPORTED,
                "authoritative_rationale": excerpt,
                "authoritative_rationale_field": path,
                "authoritative_rationale_status": "RECORDED",
                "review_reason": "authoritative_source_contradicts_dataset_marker",
            }
        )
        return base

    # 3. Dispute still documented by the authoritative source.
    if view.dispute_tag_present or dispute_matches:
        in_text = bool(dispute_matches)
        language_rule = dispute_matches[0][0] if in_text else ""
        language_field = dispute_matches[0][2] if in_text else ""
        if not in_text and view.rejected_reasons:
            reason_text = view.rejected_reasons[0].value
            base["authoritative_rationale"] = reason_text
            base["authoritative_rationale_field"] = view.rejected_reasons[0].path
            base["authoritative_rationale_status"] = "RECORDED"
        elif in_text:
            base["authoritative_rationale"] = dispute_matches[0][1]
            base["authoritative_rationale_field"] = dispute_matches[0][2]
            base["authoritative_rationale_status"] = "RECORDED"
        else:
            base["authoritative_rationale"] = ""
            base["authoritative_rationale_field"] = ""
            base["authoritative_rationale_status"] = "NOT_RECORDED_IN_SOURCE"
        base.update(
            {
                "official_record_position": POSITION_SUPPORTS,
                "dispute_resolution": RESOLUTION_OPEN,
                "resolution_bucket": BUCKET_UNRESOLVED,
                "evidence_classification": CLASS_DISPUTE_TEXT if in_text else CLASS_DISPUTE_TAG,
                "evidence_status": STATUS_SUFFICIENT,
                "evidence_confidence": CONFIDENCE_HIGH if in_text else CONFIDENCE_MEDIUM,
                "confidence_rationale": (
                    f"The authoritative record still carries dispute language in its own text "
                    f"(rule '{language_rule}' matched at {language_field}), so the dispute is "
                    "documented and open."
                    if in_text
                    else "The authoritative record carries the CNA tag 'disputed' but no dispute "
                    "language in its text; the dispute is documented administratively only."
                ),
                "exclusion_evidence": EXCLUSION_NOT_SUPPORTED,
                "review_reason": "" if in_text else "dispute_recorded_only_as_a_tag",
            }
        )
        return base

    # 4. Record exists but says nothing about a dispute.
    if not view.is_final_state:
        base.update(
            {
                "official_record_position": POSITION_DOES_NOT_RESOLVE,
                "dispute_resolution": RESOLUTION_NON_FINAL,
                "resolution_bucket": BUCKET_UNRESOLVED,
                "evidence_classification": CLASS_NON_FINAL,
                "evidence_status": STATUS_INSUFFICIENT,
                "evidence_confidence": CONFIDENCE_LOW,
                "confidence_rationale": (
                    f"The authoritative record state is {view.state or 'blank'}, which is not a final "
                    "state, so it cannot confirm or refute the disputed claim."
                ),
                "exclusion_evidence": EXCLUSION_NOT_SUPPORTED,
                "authoritative_rationale": "",
                "authoritative_rationale_field": "",
                "authoritative_rationale_status": "NOT_RECORDED_IN_SOURCE",
                "review_reason": f"authoritative_state_not_final:{view.state or 'blank'}",
            }
        )
        return base

    base.update(
        {
            "official_record_position": POSITION_DOES_NOT_RESOLVE,
            "dispute_resolution": RESOLUTION_UNRESOLVED,
            "resolution_bucket": BUCKET_UNRESOLVED,
            "evidence_classification": CLASS_SILENT,
            "evidence_status": STATUS_INSUFFICIENT,
            "evidence_confidence": CONFIDENCE_LOW,
            "confidence_rationale": (
                "The authoritative record is PUBLISHED and records no dispute: no 'disputed' tag, no "
                "dispute language, and no rejection reason. The source neither supports nor refutes the "
                "snapshot's disputed claim, so the claim is unresolved."
            ),
            "exclusion_evidence": EXCLUSION_NOT_SUPPORTED,
            "authoritative_rationale": "",
            "authoritative_rationale_field": "",
            "authoritative_rationale_status": "NOT_RECORDED_IN_SOURCE",
            "review_reason": "authoritative_source_is_silent_on_the_disputed_claim",
        }
    )
    return base


def classify_dataset_rows(
    rows: Iterable[Dict[str, Any]],
    records: Optional[Dict[str, DisputeRecordView]] = None,
) -> List[Dict[str, Any]]:
    """Classify an iterable of ``{"cve_id", "summary", "retrieval_status"}`` rows.

    Kept as a thin, pure convenience wrapper so tests can exercise the
    classification without building audit frames.
    """
    lookup = records or {}
    results: List[Dict[str, Any]] = []
    for row in rows:
        identifier = str(row.get("cve_id", "")).strip().upper()
        claim = dataset_dispute_text(row.get("summary", ""))
        retrieval_status = str(row.get("retrieval_status", RETRIEVAL_NOT_ATTEMPTED))
        classification = classify_dispute_evidence(
            lookup.get(identifier),
            retrieval_status=retrieval_status,
            dataset_claim_text=claim["disputed_claim_text"],
        )
        merged = dict(row)
        merged.update(claim)
        merged.update(classification)
        merged["cve_id"] = identifier
        results.append(merged)
    return results
