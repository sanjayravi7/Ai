"""Deterministic serialization and a human-readable rendering of the report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

DIGEST_EXCLUDED_FIELDS = ("report_digest", "reproducibility")


def relativize_paths(value: Any, anchor: Path | str) -> Any:
    """Rewrite absolute paths under ``anchor`` as relative paths.

    The readiness report must not depend on where the repository is checked out.
    Paths outside the anchor (for example a caller's temporary fixture) are left
    unchanged so they remain traceable.
    """
    root = Path(anchor).resolve()

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: walk(inner) for key, inner in item.items()}
        if isinstance(item, list):
            return [walk(inner) for inner in item]
        if isinstance(item, tuple):
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
    report["report_digest"] = canonical_digest(report)
    return report


def set_reproducibility(
    report: dict,
    *,
    second_digest: Optional[str] = None,
    previous_digest: Optional[str] = None,
) -> dict:
    block = {
        "canonicalization": (
            "JSON with sorted keys and compact separators; report_digest and "
            "reproducibility are excluded from the digest"
        ),
        "volatile_fields_excluded": list(DIGEST_EXCLUDED_FIELDS),
        "report_digest_sha256": report.get("report_digest"),
    }
    if second_digest is not None:
        block["independent_second_run_digest_sha256"] = second_digest
        block["double_run_match"] = second_digest == report.get("report_digest")
    if previous_digest is not None:
        block["previous_report_digest_sha256"] = previous_digest
        block["matches_previous_report"] = previous_digest == report.get("report_digest")
    report["reproducibility"] = block
    return block


def write_json(report: dict, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def write_markdown(report: dict, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def _cell(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _truncate(text: str, limit: int = 220) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_markdown(report: dict) -> str:
    checks = report.get("checks", [])
    summary = report.get("summary", {})
    readiness = report.get("readiness", {})
    protocol = report.get("protocol", {})
    parameters = report.get("parameters", {})
    lines: list[str] = []
    lines.append("# VULNOVA 1.6 — Evaluation Readiness")
    lines.append("")
    lines.append(
        f"**Status:** `{readiness.get('status')}` · **As of:** "
        f"`{report.get('as_of')}` · **Reference date:** `{report.get('reference_date')}`"
    )
    lines.append(
        f"**Protocol approval:** `{protocol.get('approval_state')}` · "
        f"**Adopted design:** `{protocol.get('adopted_design') or 'none'}` · "
        "**Model trained:** no · **Predictive claim:** none"
    )
    lines.append("")
    lines.append(
        "This is technical readiness evidence. It does **not** approve the protocol, "
        "adopt a design, relax the event gate, or authorise training."
    )
    lines.append("")

    lines.append("## Check summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("|---|---:|")
    for status in ("PASS", "FAIL", "BLOCKED", "NOT_APPLICABLE"):
        lines.append(f"| {status} | {summary.get(status, 0)} |")
    lines.append(f"| **Total** | **{summary.get('total', len(checks))}** |")
    lines.append("")

    lines.append("## Blockers")
    lines.append("")
    blockers = readiness.get("blockers", [])
    if blockers:
        lines.append("| Code | Primary | Detail |")
        lines.append("|---|---|---|")
        for blocker in blockers:
            lines.append(
                f"| `{_cell(blocker.get('code'))}` | "
                f"{'yes' if blocker.get('primary') else 'no'} | "
                f"{_cell(_truncate(blocker.get('detail', '')))} |"
            )
    else:
        lines.append("None.")
    lines.append("")

    lines.append("## Frozen parameters")
    lines.append("")
    lines.append("| Parameter | Value |")
    lines.append("|---|---:|")
    for key in (
        "horizon_days",
        "maturity_lag_days",
        "maturity_span_days",
        "required_distinct_test_events",
        "required_sequential_blocks",
    ):
        lines.append(f"| `{key}` | {parameters.get(key)} |")
    lines.append("")

    lines.append("## Candidate designs")
    lines.append("")
    lines.append(
        "| Design | Kind | Blocks | Cutoffs | Events per block | Final maturity | "
        "Verdict | Protocol-admissible |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for design in report.get("designs", []):
        blocks = design.get("blocks", [])
        cutoffs = "; ".join(",".join(block.get("cutoffs", [])) for block in blocks)
        events = " / ".join(str(block.get("distinct_events")) for block in blocks)
        final_maturity = max(
            (block.get("maturity_date") for block in blocks if block.get("maturity_date")),
            default="",
        )
        lines.append(
            f"| `{_cell(design.get('id'))}` | {_cell(design.get('kind'))} | "
            f"{len(blocks)} | {_cell(cutoffs)} | {_cell(events)} | "
            f"{_cell(final_maturity)} | `{_cell(design.get('verdict'))}` | "
            f"{'yes' if design.get('protocol_admissible') else 'no'} |"
        )
    lines.append("")

    lines.append("## Maturity calendar")
    lines.append("")
    lines.append(
        "| Cutoff | Horizon end | Label maturity | Matured at as-of | "
        "Source covers maturity |"
    )
    lines.append("|---|---|---|---|---|")
    for row in report.get("maturity", []):
        lines.append(
            f"| {row.get('cutoff')} | {row.get('horizon_end')} | "
            f"{row.get('label_maturity_date')} | "
            f"{'yes' if row.get('matured_at_as_of') else 'no'} | "
            f"{'yes' if row.get('source_covers_maturity') else 'no'} |"
        )
    lines.append("")

    lines.append("## Checks")
    lines.append("")
    lines.append("| Check | Status | Blocking | Reason |")
    lines.append("|---|---|---|---|")
    for check in checks:
        reason = check.get("reasons", [""])
        lines.append(
            f"| `{_cell(check.get('id'))}`<br>{_cell(check.get('title'))} | "
            f"`{check.get('status')}` | {'yes' if check.get('blocking') else 'no'} | "
            f"{_cell(_truncate(reason[0] if reason else ''))} |"
        )
    lines.append("")

    evidence = report.get("evidence_classification", {})
    counts = evidence.get("counts", {})
    lines.append("## Evidence classification")
    lines.append("")
    lines.append("| State | Count | Interpretation |")
    lines.append("|---|---:|---|")
    lines.append(
        f"| `CONFIRMED_KEV_INCLUSION` | "
        f"{counts.get('confirmed_kev_inclusion_event_rows')} event rows / "
        f"{counts.get('confirmed_kev_inclusion_distinct_events')} distinct | "
        "Observed in a readable catalog revision. |"
    )
    lines.append(
        f"| `ABSENT_FROM_KEV` | {counts.get('absent_from_kev_risk_set_observations')} "
        "risk-set observations | Not proof of non-exploitation; never a negative label. |"
    )
    missing = counts.get("missing_historical_evidence", {})
    lines.append(
        "| `MISSING_HISTORICAL_EVIDENCE` | "
        f"{missing.get('epss_backfilled_cutoffs')} EPSS cutoffs + unavailable sources | "
        "Unknown, never imputed as absence. |"
    )
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
    lines.append(
        "python -m vulnova.evaluation readiness \\"
    )
    lines.append("  --artifacts ../phase2.3k-export \\")
    lines.append(
        "  --out reports/evaluation_readiness_1_6/readiness_report.json"
    )
    lines.append("```")
    lines.append("")
    lines.append(f"Report digest: `{report.get('report_digest')}`")
    lines.append("")
    return "\n".join(lines)
