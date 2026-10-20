"""Deterministic summary of a prospective evidence store.

The report is derived only from stored runs: no wall-clock timestamp, no absolute
path and no environment detail.  Two machines with the same store therefore
produce byte-identical reports, which is what makes the digest meaningful.

The report states what was captured and what was not.  It never calls a capture
"complete evidence", never hides a partial day, and never resolves a conflict by
choosing a winner.
"""

from __future__ import annotations

import hashlib
import json
from typing import Optional

from ..acquisition import constants as A
from ..refresh.paths import assert_safe_write_targets
from . import constants as C
from .paths import capture_protected_paths
from .store import ProspectiveStore, atomic_replace
from .verify import _describe_error

REPORT_SCHEMA = "vulnova.prospective.report/1.9"

#: Fields excluded from the report digest.
DIGEST_EXCLUDED = ("report_digest",)


def _digest(payload: dict) -> str:
    clone = {key: value for key, value in payload.items() if key not in DIGEST_EXCLUDED}
    body = json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


#: Requirement id -> capture kind.  The report summarizes what was *captured*
#: for a source, not what every attempt along the way did.
REQUIREMENT_KINDS = {
    "KEV-CAPTURE": C.KEV,
    "EPSS-CAPTURE": C.EPSS,
    "CVELISTV5-REVISION": C.CVELISTV5,
}


def _requirement_statuses(run: dict) -> dict:
    """Per-source status as the run itself summarized it."""
    statuses = {}
    requirements = run.get("requirements")
    if not isinstance(requirements, list):
        return statuses
    for requirement in requirements:
        if not isinstance(requirement, dict):
            continue
        kind = REQUIREMENT_KINDS.get(requirement.get("id"))
        if kind:
            statuses[kind] = requirement.get("status")
    return statuses


def _record_status(run: dict, kind: str) -> Optional[str]:
    """Fallback for runs without a requirements block: worst recorded attempt."""
    statuses = [
        record.get("content_status")
        for record in run.get("records", [])
        if isinstance(record, dict) and record.get("source") == kind
    ]
    if not statuses:
        return None
    return A.worst(statuses)


def _load_runs(store: ProspectiveStore) -> tuple[list[dict], list[str]]:
    runs: list[dict] = []
    unreadable: list[str] = []
    for run_id in store.run_ids():
        try:
            payload = json.loads(store.read_run(run_id).decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed silently
            unreadable.append(f"{run_id}: {_describe_error(exc)}")
            continue
        if not isinstance(payload, dict):
            unreadable.append(f"{run_id}: not a JSON object")
            continue
        runs.append(payload)
    runs.sort(key=lambda run: str(run.get("run_id")))
    return runs, unreadable


def build_report(store_root) -> dict:
    """Build the machine-readable summary from the store."""
    store = ProspectiveStore(store_root)
    runs, unreadable = _load_runs(store)

    status_counts = {status: 0 for status in A.STATUSES}
    source_counts = {
        kind: {status: 0 for status in A.STATUSES} for kind in C.CAPTURE_KINDS
    }
    days: dict[str, dict] = {}

    for run in runs:
        summary = run.get("summary")
        summary = summary if isinstance(summary, dict) else {}
        status = summary.get("capture_status", A.BLOCKED)
        status_counts[status] = status_counts.get(status, 0) + 1
        observation = str(run.get("observation_date", ""))
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
        requirement_statuses = _requirement_statuses(run)
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

    conflicts = _conflicts(runs)

    payload = {
        "schema_version": REPORT_SCHEMA,
        "captures": len(runs),
        "observation_dates": sorted(days),
        "status_counts": status_counts,
        "sources": source_counts,
        "days": [days[key] for key in sorted(days)],
        "conflicts": conflicts,
        "unreadable_runs": unreadable,
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
        lines += [
            "No capture has been recorded in this store. This is an empty store, "
            "not evidence that sources were unavailable and not evidence of absence.",
            "",
        ]
    else:
        lines += [
            "| observation date | captures | KEV | EPSS | cvelistV5 | day status |",
            "|---|---|---|---|---|---|",
        ]
        for day in report["days"]:
            day_status = A.worst(
                [status for status in (day["kev"], day["epss"], day["cvelistv5"]) if status]
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
            "## Status counts",
            "",
            "| status | runs |",
            "|---|---|",
        ]
        for status in A.STATUSES:
            lines.append(f"| {status} | {report['status_counts'][status]} |")
        lines += [
            "",
            "A date with no row was not observed. It is a gap in the record, not "
            "evidence that a source was unavailable and not a negative label.",
        ]

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
        path, (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
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
