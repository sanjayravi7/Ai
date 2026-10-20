"""Compare a refresh readiness run against the committed 1.6 baseline.

The comparison has to answer two different questions and keep them apart:

* **Did the evidence change the verdicts?**  That is a comparison of check
  statuses and design verdicts, which are semantic and time-independent.
* **Do the two reports have the same digest?**  Almost certainly not, because a
  readiness report embeds its ``as_of`` date and the maturity rows derived from
  it.  A digest difference is *not* a status change, and this module says so
  explicitly rather than letting a reader conflate the two.

Every list is sorted so the comparison is deterministic and diffable.
"""

from __future__ import annotations

import datetime as dt
from typing import Iterable, Optional

from ..acquisition import constants as A
from ..evaluation import constants as C

#: Answers that are derived from the readiness reports themselves.
QUESTION_KEYS = (
    "final_kev_maturity_requirement_satisfied",
    "exact_historical_epss_available",
    "required_provenance_complete",
    "any_candidate_design_admissible",
    "protocol_remains_not_approved",
    "protocol_execution_authorized",
    "model_training_authorized",
    "report_digest_matches_baseline",
    "semantic_check_statuses_match_baseline",
)


def _checks(report: Optional[dict]) -> dict[str, dict]:
    if not report:
        return {}
    return {
        str(check.get("id")): check
        for check in report.get("checks", [])
        if isinstance(check, dict) and check.get("id")
    }


def _designs(report: Optional[dict]) -> dict[str, dict]:
    if not report:
        return {}
    return {
        str(design.get("id")): design
        for design in report.get("designs", [])
        if isinstance(design, dict) and design.get("id")
    }


def _diff_reasons(before: Iterable, after: Iterable) -> dict:
    left = [str(value) for value in before or []]
    right = [str(value) for value in after or []]
    return {
        "added": sorted(set(right) - set(left)),
        "removed": sorted(set(left) - set(right)),
    }


def _summary(report: Optional[dict]) -> dict:
    if not report:
        return {}
    summary = report.get("summary", {})
    return {
        key: summary.get(key)
        for key in ("total", C.STATUS_PASS, C.STATUS_FAIL, C.STATUS_BLOCKED, C.STATUS_NOT_APPLICABLE)
    }


def build_comparison(
    *,
    baseline: Optional[dict],
    current: Optional[dict],
    gates: Iterable[dict] = (),
    epss_records: Iterable[dict] = (),
    baseline_path: Optional[str] = None,
) -> dict:
    """Produce the auditable feasibility comparison carried by the refresh."""
    gate_list = list(gates)
    epss_list = list(epss_records)

    baseline_checks = _checks(baseline)
    current_checks = _checks(current)
    baseline_designs = _designs(baseline)
    current_designs = _designs(current)

    changed = []
    for check_id in sorted(set(baseline_checks) & set(current_checks)):
        before = baseline_checks[check_id]
        after = current_checks[check_id]
        if before.get("status") == after.get("status"):
            continue
        changed.append(
            {
                "id": check_id,
                "baseline_status": before.get("status"),
                "current_status": after.get("status"),
                "reasons": _diff_reasons(before.get("reasons"), after.get("reasons")),
                "blocking": bool(after.get("blocking")),
            }
        )

    only_in_baseline = sorted(set(baseline_checks) - set(current_checks))
    only_in_current = sorted(set(current_checks) - set(baseline_checks))
    unchanged_non_pass = [
        {
            "id": check_id,
            "status": current_checks[check_id].get("status"),
            "blocking": bool(current_checks[check_id].get("blocking")),
        }
        for check_id in sorted(current_checks)
        if current_checks[check_id].get("status") in (C.STATUS_BLOCKED, C.STATUS_FAIL)
    ]

    design_rows = []
    for design_id in sorted(set(baseline_designs) | set(current_designs)):
        before = baseline_designs.get(design_id, {})
        after = current_designs.get(design_id, {})
        design_rows.append(
            {
                "id": design_id,
                "baseline_verdict": before.get("verdict"),
                "current_verdict": after.get("verdict"),
                "changed": before.get("verdict") != after.get("verdict"),
                "protocol_admissible": bool(after.get("protocol_admissible")),
                "reason_codes": list(after.get("reason_codes", [])),
            }
        )

    baseline_statuses = {
        key: value.get("status") for key, value in baseline_checks.items()
    }
    current_statuses = {
        key: value.get("status") for key, value in current_checks.items()
    }

    final_gate = max(gate_list, key=lambda gate: gate["cutoff"]) if gate_list else None
    exact_epss = bool(epss_list) and all(
        record.get("content_status") == A.VERIFIED
        and record.get("details", {}).get("file_score_date") == record.get("cutoff")
        for record in epss_list
    )
    contemporaneous_epss = bool(epss_list) and all(
        record.get("historical_retrieval_verified") is True for record in epss_list
    )

    protocol = (current or {}).get("protocol", {})
    approval_state = protocol.get("approval_state")
    any_admissible = any(row["protocol_admissible"] for row in design_rows)

    questions = {
        "final_kev_maturity_requirement_satisfied": bool(
            final_gate and final_gate.get("maturity_claimed")
        ),
        "exact_historical_epss_available": exact_epss,
        # A fresh download of an old file is authentic content with late access;
        # it never becomes contemporary provenance.
        "required_provenance_complete": bool(exact_epss and contemporaneous_epss),
        "any_candidate_design_admissible": any_admissible,
        "protocol_remains_not_approved": approval_state != "APPROVED"
        if approval_state is not None
        else True,
        "protocol_execution_authorized": bool(
            (current or {}).get("readiness", {}).get("protocol_execution_authorized")
        ),
        "model_training_authorized": bool(
            (current or {}).get("readiness", {}).get("model_training_authorized")
        ),
        "report_digest_matches_baseline": bool(
            baseline
            and current
            and baseline.get("report_digest") == current.get("report_digest")
        ),
        "semantic_check_statuses_match_baseline": bool(
            baseline_statuses and baseline_statuses == current_statuses
        ),
    }

    limitations = []
    if baseline is None:
        limitations.append(
            "No baseline readiness report was supplied, so no comparison against "
            "the committed 1.6 report is claimed."
        )
    if current is None:
        limitations.append(
            "No refreshed readiness report was produced, so check statuses and design "
            "verdicts cannot be re-assessed in this run."
        )
    if gates and not questions["final_kev_maturity_requirement_satisfied"]:
        limitations.append(
            "The final KEV maturity requirement is not satisfied; the maturity gate "
            "remains the primary blocker and no label set is reported."
        )
    if baseline and current and not questions["report_digest_matches_baseline"]:
        limitations.append(
            "The two report digests differ. A readiness report embeds its as-of date "
            "and derived maturity rows, so a digest difference is expected even when "
            "every check status is identical; compare statuses, not digests."
        )
    if not questions["exact_historical_epss_available"]:
        limitations.append(
            "Exact historical EPSS files are not available; the EPSS requirement stays "
            "UNAVAILABLE and is never satisfied by a newer file or a mirror."
        )

    return {
        "baseline": {
            "path": baseline_path,
            "available": baseline is not None,
            "report_digest": (baseline or {}).get("report_digest"),
            "as_of": (baseline or {}).get("as_of"),
            "readiness_status": (baseline or {}).get("readiness", {}).get("status"),
            "summary": _summary(baseline),
            "protocol_approval_state": (baseline or {}).get("protocol", {}).get(
                "approval_state"
            ),
        },
        "current": {
            "available": current is not None,
            "report_digest": (current or {}).get("report_digest"),
            "as_of": (current or {}).get("as_of"),
            "readiness_status": (current or {}).get("readiness", {}).get("status"),
            "summary": _summary(current),
            "protocol_approval_state": approval_state,
        },
        "checks": {
            "changed": changed,
            "only_in_baseline": only_in_baseline,
            "only_in_current": only_in_current,
            "unchanged_blocked_or_failed": unchanged_non_pass,
            "baseline_total": len(baseline_checks),
            "current_total": len(current_checks),
        },
        "designs": {
            "rows": design_rows,
            "any_protocol_admissible": any_admissible,
        },
        "questions": questions,
        "limitations": limitations,
        "note": (
            "Maturity is necessary, not sufficient: the gate says whether a block's "
            "labels could be observed, while the readiness checks say whether the "
            "evidence and the protocol actually support an evaluation."
        ),
    }


def comparison_inputs_digest(gates: Iterable[dict], api_state: Optional[str] = None) -> str:
    """Small helper used by tests to assert the comparison is deterministic."""
    import hashlib
    import json

    payload = {
        "gates": [
            {key: gate.get(key) for key in ("cutoff", "status", "maturity_date")}
            for gate in gates
        ],
        "approval": api_state,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_report_date(report: Optional[dict]) -> Optional[dt.date]:
    if not report:
        return None
    try:
        return dt.date.fromisoformat(str(report.get("as_of")))
    except (TypeError, ValueError):
        return None


__all__ = [
    "QUESTION_KEYS",
    "build_comparison",
    "comparison_inputs_digest",
    "parse_report_date",
]
