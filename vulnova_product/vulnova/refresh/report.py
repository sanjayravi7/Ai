"""Canonical serialisation and readable rendering of the 1.8 refresh report.

The digest excludes exactly the three fields that are not evidence: the digest
itself, the wall-clock ``generated_at`` label, and ``runtime`` (transport class,
store path, request count).  Every retrieved timestamp, URL, hash and status
stays inside the digest, because those are what a reader is asked to trust.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

DIGEST_EXCLUDED_FIELDS = ("refresh_digest", "generated_at", "runtime")


def relativize_paths(value: Any, anchor: Path | str) -> Any:
    """Rewrite absolute paths under ``anchor`` as relative ones."""
    root = Path(anchor).resolve()

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: walk(inner) for key, inner in item.items()}
        if isinstance(item, (list, tuple)):
            return [walk(inner) for inner in item]
        if isinstance(item, str) and item.startswith("/"):
            try:
                return str(Path(item).resolve().relative_to(root))
            except (OSError, ValueError):
                return item
        return item

    return walk(value)


def canonical_payload(report: dict) -> dict:
    return {
        key: value
        for key, value in report.items()
        if key not in DIGEST_EXCLUDED_FIELDS
    }


def canonical_digest(report: dict) -> str:
    encoded = json.dumps(
        canonical_payload(report),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def attach_digest(report: dict) -> dict:
    report["refresh_digest"] = canonical_digest(report)
    return report


def verify_digest(report: dict) -> tuple[bool, str]:
    recorded = report.get("refresh_digest")
    recomputed = canonical_digest(report)
    return (recorded == recomputed, recomputed)


def write_json(report: dict, path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return target


def _or_dash(value) -> str:
    return "—" if value is None else str(value)


def _cell(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _truncate(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_markdown(report: dict) -> str:
    summary = report.get("summary", {})
    final = report.get("final_candidate", {})
    protocol = report.get("protocol", {})
    catalog = report.get("catalog", {})
    parameters = report.get("parameters", {})
    comparison = report.get("readiness_comparison", {})
    questions = comparison.get("questions", {})

    lines: list[str] = []
    lines.append("# VULNOVA 1.8 — Maturity Gate and Evidence Refresh")
    lines.append("")
    lines.append(
        f"**Refresh status:** `{summary.get('refresh_status')}` · "
        f"**Evidence status:** `{summary.get('evidence_status')}` · "
        f"**As of:** `{report.get('as_of')}`"
    )
    lines.append(
        f"**Protocol approval:** `{protocol.get('approval_state')}` · "
        f"**Adopted design:** `{protocol.get('adopted_design') or 'none'}` · "
        "**Protocol execution authorised:** no · **Model trained:** no"
    )
    lines.append("")
    lines.append(
        "This report measures whether the final candidate block has matured and what "
        "fresh evidence could be obtained. It **does not** approve the protocol, adopt "
        "a design, relax the event gate or authorise training. A green integrity "
        "result is not proof that the historical evaluation is viable."
    )
    lines.append("")

    lines.append("## The maturity boundary")
    lines.append("")
    lines.append("| Question | Answer |")
    lines.append("|---|---|")
    lines.append(
        f"| Final candidate cutoff | `{final.get('cutoff')}` |"
    )
    lines.append(
        f"| Label maturity date | `{final.get('maturity_date')}` "
        f"({parameters.get('maturity_span_days')} days = "
        f"{parameters.get('horizon_days')} horizon + "
        f"{parameters.get('maturity_lag_days')} lag) |"
    )
    lines.append(
        f"| Calendar mature at this as-of date | "
        f"{'**yes**' if final.get('calendar_matured') else '**no**'} |"
    )
    lines.append(
        f"| Days remaining | {final.get('days_remaining')} |"
    )
    lines.append(
        f"| Maturity claimed | {'**yes**' if final.get('maturity_claimed') else '**no**'} |"
    )
    lines.append("")
    lines.append(
        "Calendar maturity is necessary but not sufficient. A block is only "
        "observable when the catalog was published **on or after** its maturity "
        "date; a catalog released earlier cannot contain labels that settled later."
    )
    lines.append("")

    lines.append("## Gate, block by block")
    lines.append("")
    lines.append(
        "| Cutoff | Maturity | Calendar matured | Days remaining | "
        "Catalog released | Observes maturity | Status |"
    )
    lines.append("|---|---|---|---:|---|---|---|")
    for gate in report.get("maturity_gate", []):
        lines.append(
            f"| {gate.get('cutoff')} | {gate.get('maturity_date')} | "
            f"{'yes' if gate.get('calendar_matured') else 'no'} | "
            f"{gate.get('days_remaining')} | "
            f"{_cell(gate.get('catalog_released') or '—')} | "
            f"{'yes' if gate.get('catalog_observes_maturity') else 'no'} | "
            f"`{gate.get('status')}` |"
        )
    lines.append("")

    lines.append("## Catalog in hand")
    lines.append("")
    if catalog.get("verified"):
        lines.append(
            f"- **Selection:** `{catalog.get('channel')}:{catalog.get('key')}` "
            f"(catalog `{catalog.get('catalog_version')}`, released "
            f"`{catalog.get('released')}`)"
        )
        lines.append(
            f"- **Entries:** {catalog.get('parsed_count')} parsed / "
            f"{catalog.get('declared_count')} declared"
        )
        lines.append(f"- **Revision:** `{catalog.get('revision')}`")
        lines.append(f"- **SHA-256:** `{catalog.get('sha256')}`")
        lines.append(f"- **Request URL:** `{catalog.get('request_url')}`")
        if catalog.get("redirected"):
            lines.append(f"- **Final URL (redirect):** `{catalog.get('final_url')}`")
        lines.append(f"- **Retrieved (UTC):** `{catalog.get('retrieved_at')}`")
    else:
        lines.append(
            f"No first-party catalog was verified in this run "
            f"(`{catalog.get('content_status')}` / `{catalog.get('reason_code')}`)."
        )
    lines.append("")

    lines.append("## dateAdded filter")
    lines.append("")
    lines.append("| Block | Applied | Basis | Entries | Observable | After maturity | Trusted |")
    lines.append("|---|---|---|---:|---:|---:|---|")
    for cutoff, filt in sorted(report.get("date_added_filters", {}).items()):
        lines.append(
            f"| {cutoff} | {'yes' if filt.get('applied') else 'no'} | "
            f"`{filt.get('basis')}` | "
            f"{_or_dash(filt.get('entries_total'))} | "
            f"{_or_dash(filt.get('entries_observable'))} | "
            f"{_or_dash(filt.get('entries_after_maturity'))} | "
            f"{'yes' if filt.get('trustworthy') else 'no'} |"
        )
    lines.append("")
    lines.append(
        "A filtered view is a derived lower bound over one catalog, **not** an "
        "observed point-in-time membership set. The 1.6 event rules remain the only "
        "basis for a real label."
    )
    lines.append("")

    lines.append("## EPSS retry")
    lines.append("")
    if report.get("epss_records"):
        lines.append("| Cutoff | Content | Access | Reason | Retrieved | SHA-256 |")
        lines.append("|---|---|---|---|---|---|")
        for record in report["epss_records"]:
            lines.append(
                f"| {record.get('key')} | `{record.get('content_status')}` | "
                f"`{record.get('access_provenance')}` | `{record.get('reason_code')}` | "
                f"{_cell(record.get('retrieved_at') or '—')} | "
                f"{_cell((record.get('sha256') or '—')[:12])} |"
            )
    else:
        lines.append("No EPSS acquisition was attempted.")
    lines.append("")
    lines.append(
        "A historical EPSS file retrieved today is `LATE_RETRIEVAL`, not "
        "contemporaneous provenance. A newer file, a backfilled value or a "
        "third-party mirror is never substituted."
    )
    lines.append("")

    lines.append("## Requirements")
    lines.append("")
    lines.append("| Requirement | Status | Reason | Detail |")
    lines.append("|---|---|---|---|")
    for requirement in report.get("requirements", []):
        lines.append(
            f"| `{requirement.get('id')}`<br>{_cell(requirement.get('title'))} | "
            f"`{requirement.get('status')}` | `{requirement.get('reason_code')}` | "
            f"{_cell(_truncate(requirement.get('detail', '')))} |"
        )
    lines.append("")

    lines.append("## Comparison with the committed 1.6 readiness report")
    lines.append("")
    baseline = comparison.get("baseline", {})
    current = comparison.get("current", {})
    if baseline.get("available") and current.get("available"):
        lines.append("| | 1.6 baseline | this refresh |")
        lines.append("|---|---|---|")
        lines.append(f"| As of | `{baseline.get('as_of')}` | `{current.get('as_of')}` |")
        lines.append(
            f"| Readiness status | `{baseline.get('readiness_status')}` | "
            f"`{current.get('readiness_status')}` |"
        )
        base_summary = baseline.get("summary", {})
        cur_summary = current.get("summary", {})
        lines.append(
            f"| Checks PASS / FAIL / BLOCKED / N/A | "
            f"{base_summary.get('PASS')} / {base_summary.get('FAIL')} / "
            f"{base_summary.get('BLOCKED')} / {base_summary.get('NOT_APPLICABLE')} | "
            f"{cur_summary.get('PASS')} / {cur_summary.get('FAIL')} / "
            f"{cur_summary.get('BLOCKED')} / {cur_summary.get('NOT_APPLICABLE')} |"
        )
        lines.append(
            f"| Report digest | `{(baseline.get('report_digest') or '')[:12]}…` | "
            f"`{(current.get('report_digest') or '')[:12]}…` |"
        )
        lines.append("")
        changed = comparison.get("checks", {}).get("changed", [])
        if changed:
            lines.append("**Checks that changed status:**")
            lines.append("")
            lines.append("| Check | Baseline | Current |")
            lines.append("|---|---|---|")
            for row in changed:
                lines.append(
                    f"| `{row.get('id')}` | `{row.get('baseline_status')}` | "
                    f"`{row.get('current_status')}` |"
                )
        else:
            lines.append(
                "**No check changed status.** Every one of the "
                f"{comparison.get('checks', {}).get('current_total')} checks reports the "
                "same status as the committed 1.6 report."
            )
        lines.append("")
    else:
        lines.append(
            "No baseline comparison was performed in this run. "
            f"Baseline available: {baseline.get('available')}; "
            f"current readiness available: {current.get('available')}."
        )
        lines.append("")

    lines.append("## Feasibility questions")
    lines.append("")
    lines.append("| Question | Answer |")
    lines.append("|---|---|")
    for key, value in questions.items():
        lines.append(f"| `{key}` | {'**yes**' if value else 'no'} |")
    lines.append("")
    if comparison.get("note"):
        lines.append(comparison["note"])
        lines.append("")

    lines.append("## Designs")
    lines.append("")
    rows = comparison.get("designs", {}).get("rows", [])
    if rows:
        lines.append("| Design | Baseline verdict | Current verdict | Protocol-admissible |")
        lines.append("|---|---|---|---|")
        for row in rows:
            lines.append(
                f"| `{row.get('id')}` | `{row.get('baseline_verdict')}` | "
                f"`{row.get('current_verdict')}` | "
                f"{'yes' if row.get('protocol_admissible') else 'no'} |"
            )
    else:
        lines.append("No design comparison was produced.")
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    for item in report.get("limitations", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("cd vulnova_product")
    lines.append("python -m vulnova.refresh run          # the only network-using command")
    lines.append("python -m vulnova.refresh gate         # offline: is the block mature yet?")
    lines.append("python -m vulnova.refresh verify       # offline: re-hash and re-check")
    lines.append("```")
    lines.append("")
    lines.append(f"Refresh digest: `{report.get('refresh_digest')}`")
    lines.append("")
    return "\n".join(lines)


def write_markdown(report: dict, path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown(report), encoding="utf-8")
    return target


__all__ = [
    "DIGEST_EXCLUDED_FIELDS",
    "attach_digest",
    "canonical_digest",
    "canonical_payload",
    "relativize_paths",
    "render_markdown",
    "verify_digest",
    "write_json",
    "write_markdown",
]
