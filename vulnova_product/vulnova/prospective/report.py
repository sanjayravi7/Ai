"""Deterministic summary of a prospective evidence store.

The report is derived only from stored runs: no wall-clock timestamp, no absolute
path and no environment detail.  Two machines with the same store therefore
produce byte-identical reports, which is what makes the digest meaningful.

**A malformed run is never summarized as if it were sound.**  Run files are JSON
written by the capture tool, but the report must survive arbitrary bytes on
disk: a status can arrive as a list, an object or an invented label, a record as
a string, a timestamp as a number.  Values outside the three-state vocabulary
are rejected before they touch a dictionary key, a run whose record does not
validate is counted as ``BLOCKED`` -- never under the status it claims -- and
its per-source claims are excluded from the day grid.  It is then named in
``malformed_runs`` with the exact problems found.  This is deliberately
fail-closed: an unverifiable claim is not evidence of success.

The report states what was captured and what was not.  It never calls a capture
"complete evidence", never hides a partial day, and never resolves a conflict by
choosing a winner.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Optional

from ..acquisition import constants as A
from ..acquisition.records import to_instant
from ..refresh.paths import assert_safe_write_targets
from . import constants as C
from .capture import _digest as _run_digest
from .capture import run_id_for
from .paths import capture_protected_paths
from .store import ProspectiveStore, SHA256_HEX, StoreError, _safe_relative, atomic_replace
from .verify import _describe_error, _short

REPORT_SCHEMA = "vulnova.prospective.report/1.9"

#: Fields excluded from the report digest.
DIGEST_EXCLUDED = ("report_digest",)

#: How many malformed runs the Markdown rendering lists.  The JSON report always
#: carries every malformed run and every problem found.
MAX_RENDERED_RUNS = 20


def _digest(payload: dict) -> str:
    clone = {key: value for key, value in payload.items() if key not in DIGEST_EXCLUDED}
    body = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------- value validation
def _iso_date(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _iso_instant(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        to_instant(value)
    except (TypeError, ValueError):
        return False
    return True


def _safe_artifact_path(value) -> bool:
    if not isinstance(value, str) or not value.startswith(C.ARTIFACTS_DIR + "/"):
        return False
    try:
        _safe_relative(value)
    except StoreError:
        return False
    return True


def _requirement_statuses(run: dict) -> tuple[dict, list[str]]:
    """Per-source status, validated, plus every malformed requirement field.

    A requirement whose status is outside the vocabulary contributes
    ``BLOCKED`` for its source: the unknown value itself is discarded, and the
    source cannot be reported as anything better than blocked on the strength of
    a claim that does not parse.
    """
    collected: dict[str, list[str]] = {}
    problems: list[str] = []
    requirements = run.get("requirements")
    if not isinstance(requirements, list):
        return {}, ["requirements is not a list"]
    if not requirements:
        return {}, ["requirements is empty"]

    seen: set[str] = set()
    for index, requirement in enumerate(requirements):
        if not isinstance(requirement, dict):
            problems.append(f"requirements[{index}] is not an object")
            continue
        requirement_id = requirement.get("id")
        kind = (
            C.REQUIREMENT_KINDS.get(requirement_id)
            if isinstance(requirement_id, str)
            else None
        )
        if kind is None:
            problems.append(
                f"requirements[{index}]: unknown requirement id {_short(requirement_id)}"
            )
            continue
        if kind in seen:
            problems.append(f"requirements[{index}]: duplicate {requirement_id}")
        seen.add(kind)
        status = requirement.get("status")
        if not C.is_status(status):
            problems.append(
                f"requirements[{index}] ({kind}): status {_short(status)} is outside "
                "the three-state vocabulary"
            )
            collected.setdefault(kind, []).append(A.BLOCKED)
            continue
        collected.setdefault(kind, []).append(status)

    for kind in sorted(set(C.REQUIREMENT_KINDS.values()) - seen):
        problems.append(f"requirements: no entry for {kind}")

    return {kind: A.worst(values) for kind, values in collected.items()}, problems


def _record_status(run: dict, kind: str) -> Optional[str]:
    """Fallback for runs without a usable requirements block.

    Only values in the vocabulary are considered.  A malformed status is not a
    weaker status; it is not a status at all, and it is reported separately.
    """
    records = run.get("records")
    if not isinstance(records, list):
        return None
    statuses = [
        record.get("content_status")
        for record in records
        if isinstance(record, dict)
        and record.get("source") == kind
        and C.is_status(record.get("content_status"))
    ]
    if not statuses:
        return None
    return A.worst(statuses)


def _record_problems(run: dict) -> list[str]:
    """Type-check every record; a bad field is named, never silently coerced."""
    records = run.get("records")
    if not isinstance(records, list):
        return ["records is not a list"]
    if not records:
        return ["records is empty"]

    problems: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            problems.append(f"records[{index}] is not an object")
            continue
        label = f"records[{index}]"
        source = record.get("source")
        key = record.get("key")
        if not isinstance(source, str) or not source:
            problems.append(f"{label}: source is not a non-empty string")
        if not isinstance(key, str) or not key:
            problems.append(f"{label}: key is not a non-empty string")
        if not C.is_status(record.get("content_status")):
            problems.append(
                f"{label}: content_status {_short(record.get('content_status'))} is "
                "outside the three-state vocabulary"
            )
        sha = record.get("sha256")
        if sha is not None and not (isinstance(sha, str) and SHA256_HEX.match(sha)):
            problems.append(f"{label}: sha256 is not a lower-case SHA-256")
        size = record.get("bytes")
        if size is not None and (
            not isinstance(size, int) or isinstance(size, bool) or size < 0
        ):
            problems.append(f"{label}: bytes is not a non-negative integer")
        relative = record.get("artifact_path")
        if relative is not None and not _safe_artifact_path(relative):
            problems.append(f"{label}: artifact_path is not a safe store path")
        elif isinstance(relative, str) and relative and isinstance(source, str):
            if source in C.CAPTURE_KINDS:
                prefix = f"{C.ARTIFACTS_DIR}/{source}/"
                if not relative.startswith(prefix):
                    problems.append(
                        f"{label}: artifact_path {_short(relative)} is not under {prefix}"
                    )
                elif isinstance(sha, str) and SHA256_HEX.match(sha):
                    expected = f"{prefix}{sha}{C.ARTIFACT_SUFFIX[source]}"
                    if relative != expected:
                        problems.append(
                            f"{label}: artifact_path does not match its content address"
                        )
        for field in ("retrieved_at", "source_timestamp"):
            value = record.get(field)
            if value is not None and not _iso_instant(value):
                problems.append(f"{label}: {field} is not an ISO timestamp")
        if record.get("cutoff") is not None:
            problems.append(f"{label}: carries a historical cutoff")
        if record.get("content_status") == A.VERIFIED:
            for field in ("artifact_path", "sha256", "retrieved_at"):
                if not isinstance(record.get(field), str) or not record.get(field):
                    problems.append(f"{label}: VERIFIED but missing {field}")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                problems.append(f"{label}: VERIFIED but missing a valid byte count")
    return problems


def _run_problems(run: dict, filename_run_id: str) -> list[str]:
    """Every reason this run record cannot be summarized as written."""
    problems: list[str] = []

    if run.get("schema_version") != C.SCHEMA_VERSION:
        problems.append(f"schema_version {_short(run.get('schema_version'))}")
    missing_fields = sorted(C.RUN_FIELDS - set(run))
    unexpected_fields = sorted(set(run) - C.RUN_FIELDS)
    if missing_fields:
        problems.append(f"missing field(s) {', '.join(missing_fields)}")
    if unexpected_fields:
        problems.append(f"unexpected field(s) {', '.join(unexpected_fields)}")
    for field in ("phase", "release"):
        if not isinstance(run.get(field), str):
            problems.append(f"{field} is not a string")
    if not isinstance(run.get("honesty"), dict):
        problems.append("honesty is not an object")
    for field in ("capture_started_at", "capture_completed_at"):
        if not _iso_instant(run.get(field)):
            problems.append(f"{field} is not an ISO timestamp")
    if not _iso_date(run.get("observation_date")):
        problems.append(
            f"observation_date {_short(run.get('observation_date'))} is not an ISO date"
        )

    requirement_statuses, requirement_problems = _requirement_statuses(run)
    problems.extend(requirement_problems)
    problems.extend(_record_problems(run))

    recorded_digest = run.get("run_digest")
    try:
        recomputed_digest = _run_digest(run)
    except (TypeError, ValueError, RecursionError) as exc:  # non-JSON-serializable junk
        problems.append(f"run_digest cannot be recomputed ({_short(exc, 40)})")
        recomputed_digest = None
    if recomputed_digest is not None and recorded_digest != recomputed_digest:
        problems.append(
            f"run_digest {_short(recorded_digest)} does not recompute ({recomputed_digest})"
        )

    run_id = run.get("run_id")
    if not isinstance(run_id, str):
        problems.append(f"run_id is not a string ({type(run_id).__name__})")
    else:
        if run_id != filename_run_id:
            problems.append(f"run_id {_short(run_id)} does not match its filename")
        if recomputed_digest is not None and _iso_instant(run.get("capture_started_at")):
            derived = run_id_for(str(run.get("capture_started_at")), recomputed_digest)
            if run_id != derived:
                problems.append(f"run_id {_short(run_id)} does not derive from its digest")

    summary = run.get("summary")
    if not isinstance(summary, dict):
        problems.append(f"summary is not an object ({type(summary).__name__})")
    else:
        if summary.get("observation_date") != run.get("observation_date"):
            problems.append(
                "summary observation_date "
                f"{_short(summary.get('observation_date'))} does not match the run"
            )
        status = summary.get("capture_status")
        if not C.is_status(status):
            problems.append(
                f"summary capture_status {_short(status)} is outside the "
                "three-state vocabulary"
            )
        elif not requirement_problems and requirement_statuses:
            expected = A.worst(list(requirement_statuses.values()))
            if status != expected:
                problems.append(
                    f"summary capture_status {status} disagrees with its "
                    f"requirements ({expected})"
                )
            requirements = run.get("requirements")
            verified = sum(
                1 for value in requirement_statuses.values() if value == A.VERIFIED
            )
            expected_counts = {
                "sources_total": len(requirements) if isinstance(requirements, list) else None,
                "sources_verified": verified,
            }
            for field, expected_count in expected_counts.items():
                value = summary.get(field)
                if (
                    expected_count is not None
                    and (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or value != expected_count
                    )
                ):
                    problems.append(
                        f"summary {field} {_short(value)} != {expected_count}"
                    )
            partial = summary.get("partial_capture")
            if not isinstance(partial, bool) or partial != (expected != A.VERIFIED):
                problems.append(
                    f"summary partial_capture {_short(partial)} is inconsistent "
                    f"with {expected}"
                )
    return problems


def _load_runs(store: ProspectiveStore) -> tuple[list[dict], list[str], list[dict]]:
    """Read every run file, separate unreadable data from malformed records."""
    well_formed: list[dict] = []
    unreadable: list[str] = []
    malformed: list[dict] = []

    try:
        directory_entries = store.run_directory_entries()
    except StoreError as exc:
        # The message may name an absolute directory; the report digest must be
        # reproducible, so only the failure class is recorded.
        unreadable.append(f"{C.RUNS_DIR}: unreadable ({type(exc).__name__})")
        directory_entries = []
    for entry in directory_entries:
        # Temporary files, symlinks and unexpected names are reported rather
        # than hidden by the ``*.json`` glob.
        unreadable.append(f"{entry.relative}: {entry.problem}")

    try:
        run_ids = store.run_ids()
    except StoreError as exc:
        unreadable.append(f"{C.RUNS_DIR}: unreadable ({type(exc).__name__})")
        run_ids = []

    for run_id in run_ids:
        try:
            payload = json.loads(store.read_run(run_id).decode("utf-8"))
        except (
            StoreError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            RecursionError,
        ) as exc:
            unreadable.append(f"{run_id}: {_describe_error(exc)}")
            continue
        if not isinstance(payload, dict):
            unreadable.append(f"{run_id}: not a JSON object")
            continue
        problems = _run_problems(payload, run_id)
        if problems:
            malformed.append({"run_id": run_id, "problems": problems})
            continue
        well_formed.append(payload)

    well_formed.sort(key=lambda run: str(run.get("run_id")))
    malformed.sort(key=lambda item: item["run_id"])
    unreadable.sort()
    return well_formed, unreadable, malformed


def build_report(store_root) -> dict:
    """Build the machine-readable summary from the store."""
    store = ProspectiveStore(store_root)
    runs, unreadable, malformed = _load_runs(store)

    status_counts = {status: 0 for status in A.STATUSES}
    source_counts = {
        kind: {status: 0 for status in A.STATUSES} for kind in C.CAPTURE_KINDS
    }
    days: dict[str, dict] = {}

    # A malformed run is counted as BLOCKED, which is a statement about the
    # record rather than a status it supplied.  It never raises a count for any
    # status the run claims, and it never enters the per-source grid.
    status_counts[A.BLOCKED] += len(malformed)

    for run in runs:
        summary = run["summary"]
        status = summary["capture_status"]
        status_counts[status] += 1
        observation = run["observation_date"]
        day = days.setdefault(
            observation,
            {
                "observation_date": observation,
                "captures": 0,
                "capture_statuses": {},
                "kev": None,
                "epss": None,
                "cvelistv5": None,
            },
        )
        day["captures"] += 1
        day["capture_statuses"][status] = day["capture_statuses"].get(status, 0) + 1
        requirement_statuses, _problems = _requirement_statuses(run)
        for kind in C.CAPTURE_KINDS:
            # A verified GitHub fallback is a verified KEV capture even though
            # the direct-feed attempt failed; the attempt stays in the run
            # record, but it must not colour the day as unavailable.
            kind_status = requirement_statuses.get(kind) or _record_status(run, kind)
            if kind_status is None:
                continue
            source_counts[kind][kind_status] += 1
            current = day[kind]
            day[kind] = kind_status if current is None else A.worst([current, kind_status])

    payload = {
        "schema_version": REPORT_SCHEMA,
        "captures": len(runs) + len(malformed),
        "captures_well_formed": len(runs),
        "observation_dates": sorted(days),
        "status_counts": status_counts,
        "sources": source_counts,
        "days": [days[key] for key in sorted(days)],
        "conflicts": _conflicts(runs),
        "unreadable_runs": unreadable,
        "malformed_runs": malformed,
        "malformed_captures": len(malformed),
        "honesty": dict(C.POLICIES),
    }
    payload["report_digest"] = _digest(payload)
    return payload


def _conflicts(runs: list[dict]) -> list[dict]:
    """Same logic as the verifier, kept identical so both agree."""
    from .verify import _conflicts as verify_conflicts

    return verify_conflicts(runs)


def render_markdown(report: dict) -> str:
    lines = [
        "# VULNOVA 1.9 — prospective evidence capture",
        "",
        (
            f"{report['captures']} capture run(s) across "
            f"{len(report['observation_dates'])} observation date(s)."
        ),
        "",
    ]
    if report["captures"] == 0:
        if report["unreadable_runs"] or report["malformed_runs"]:
            # A store whose run directory cannot be read is not "empty".  Saying
            # so would turn unreadable evidence into evidence of absence.
            lines += [
                "No capture could be read from this store. The files below are "
                "present but unreadable or malformed: this is not evidence that "
                "sources were unavailable and not evidence of absence.",
                "",
            ]
        else:
            lines += [
                "No capture has been recorded in this store. This is an empty store, "
                "not evidence that sources were unavailable and not evidence of "
                "absence.",
                "",
            ]
    else:
        if report["malformed_captures"]:
            lines += [
                (
                    f"{report['malformed_captures']} of these run(s) are malformed and "
                    "counted as BLOCKED; their own status claims are not used."
                ),
                "",
            ]
        if report["days"]:
            lines += [
                "| observation date | captures | KEV | EPSS | cvelistV5 | day status |",
                "|---|---|---|---|---|---|",
            ]
            for day in report["days"]:
                day_status = A.worst(
                    [
                        status
                        for status in (day["kev"], day["epss"], day["cvelistv5"])
                        if status
                    ]
                    or [A.BLOCKED]
                )
                lines.append(
                    "| {date} | {captures} | {kev} | {epss} | {cve} | {status} |".format(
                        date=day["observation_date"],
                        captures=day["captures"],
                        kev=day["kev"] or "—",
                        epss=day["epss"] or "—",
                        cve=day["cvelistv5"] or "—",
                        status=day_status,
                    )
                )
            lines += [
                "",
                "A date with no row was not observed. It is a gap in the record, not "
                "evidence that a source was unavailable and not a negative label.",
            ]
        lines += [
            "",
            "## Status counts",
            "",
            "| status | runs |",
            "|---|---|",
        ]
        for status in A.STATUSES:
            lines.append(f"| {status} | {report['status_counts'][status]} |")

    if report["conflicts"]:
        lines += [
            "",
            "## Conflicting captures",
            "",
            "Two captures on the same observation date disagree about a source's "
            "bytes. Both are preserved; neither is preferred here.",
            "",
            "| observation date | source | run ids | digests |",
            "|---|---|---|---|",
        ]
        for conflict in report["conflicts"]:
            lines.append(
                "| {date} | {kind} | {runs} | {digests} |".format(
                    date=conflict["observation_date"],
                    kind=conflict["kind"],
                    runs=", ".join(conflict["run_ids"]),
                    digests=", ".join(item[:12] for item in conflict["sha256"]),
                )
            )

    if report["malformed_runs"]:
        lines += [
            "",
            "## Malformed runs",
            "",
            "These run files were read but do not validate. They are counted as "
            "BLOCKED and excluded from the source grid; nothing they claim is used.",
            "",
        ]
        for item in report["malformed_runs"][:MAX_RENDERED_RUNS]:
            lines.append(f"- `{item['run_id']}`")
            lines += [f"  - {problem}" for problem in item["problems"]]
        remaining = len(report["malformed_runs"]) - MAX_RENDERED_RUNS
        if remaining > 0:
            lines.append(f"- … and {remaining} more malformed run(s)")

    if report["unreadable_runs"]:
        lines += [
            "",
            "## Unreadable runs",
            "",
            "These files are present but could not be parsed; they are reported, "
            "never discarded.",
            "",
        ]
        lines += [f"- `{item}`" for item in report["unreadable_runs"]]

    lines += [
        "",
        "## What this does not prove",
        "",
        "- A capture is not an evaluation. It does not mature labels, admit a "
        "design or approve the protocol.",
        "- A matching SHA-256 proves the stored bytes are the captured bytes. It "
        "does not prove historical correctness or completeness.",
        "- A missing source is a gap in observation. It is never a negative label.",
        "- Collecting daily evidence does not by itself satisfy the three-block "
        "protocol; maturity, observability, event counts, source coverage, "
        "independence, provenance and written approval remain separate.",
        "",
        f"report digest: `{report['report_digest']}`",
        "",
    ]
    return "\n".join(lines)


def _assert_report_target(path) -> None:
    """Refuse to write a report over a sealed historical artifact.

    The CLI already checks this before it builds the report, but the writers are
    public: a programmatic caller must not be able to reach the seals just by
    skipping the CLI.
    """
    assert_safe_write_targets(None, (path,), capture_protected_paths())


def write_json(report: dict, path) -> None:
    _assert_report_target(path)
    atomic_replace(
        path,
        (
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8"),
    )


def write_markdown(report: dict, path) -> None:
    _assert_report_target(path)
    atomic_replace(path, render_markdown(report).encode("utf-8"))


def verify_digest(report: dict) -> tuple[bool, str]:
    recorded = report.get("report_digest")
    recomputed = _digest(report)
    return recorded == recomputed, recomputed


__all__ = [
    "DIGEST_EXCLUDED",
    "REPORT_SCHEMA",
    "build_report",
    "render_markdown",
    "verify_digest",
    "write_json",
    "write_markdown",
]
