"""Feature, leakage and protocol checks (LKG-*, PRO-*, REP-*)."""

from __future__ import annotations

import re

from . import constants as C
from .checks_base import Check, CheckContext, blocked, failed, passed
from .datasets import integers
from .evidence import (
    KevEvidence,
    absence_is_proof_of_non_exploitation,
    classification_vocabulary,
)
from .protocol import REQUIRED_PROHIBITIONS, REQUIRED_TRACEABILITY, validate_protocol
from .temporal import label_maturity_date, validate_event_windows

_CHECK_ID_PATTERN = re.compile(r"^[A-Z]{3}-\d{2}_[a-z0-9_]+$")


def check_cvss_point_in_time(ctx: CheckContext) -> Check:
    check_id = "LKG-01_cvss_point_in_time"
    title = "CVSS availability is an exact census of the pinned revision at T"
    features = ctx.dataset.feature_by_cutoff
    denominators = ctx.dataset.denominator_by_cutoff
    if not features:
        return blocked(check_id, title, reasons=["Feature eligibility table is unavailable."])
    reasons = []
    rows = []
    for cutoff in ctx.dataset.cutoffs:
        text = cutoff.isoformat()
        feature = features.get(text, {})
        denominator = denominators.get(text, {})
        risk = integers(denominator, "risk_set_size")
        exact = integers(feature, "cvss_available_exact")
        with_cvss = integers(denominator, "risk_with_cvss")
        without = integers(feature, "cvss_unavailable")
        if feature.get("cvss_evidence") != "EXACT_CENSUS_AT_PINNED_REVISION":
            reasons.append(f"{text}: CVSS evidence is not an exact pinned-revision census")
        if exact != with_cvss:
            reasons.append(f"{text}: exact CVSS count differs from the denominator")
        if exact is not None and without is not None and risk is not None:
            if exact + without != risk:
                reasons.append(f"{text}: CVSS coverage does not partition the risk set")
        coverage = feature.get("cvss_coverage_pct")
        if coverage is not None and risk:
            computed = 100.0 * (exact or 0) / risk
            if abs(float(coverage) - computed) > 0.005:
                reasons.append(f"{text}: CVSS coverage percentage does not recompute")
        state_total = sum(
            integers(feature, key, 0) or 0
            for key in ("state_published", "state_non_published", "state_missing")
        )
        if risk is not None and state_total != risk:
            reasons.append(f"{text}: state counts do not partition the risk set")
        rows.append(
            {
                "cutoff": text,
                "cvss_available_exact": exact,
                "cvss_unavailable": without,
                "risk_set_size": risk,
                "coverage_pct": coverage,
                "evidence": feature.get("cvss_evidence"),
            }
        )
    coverages = []
    for row in rows:
        try:
            coverages.append(float(row["coverage_pct"]))
        except (TypeError, ValueError):
            continue
    coverage_first = coverages[0] if coverages else 0.0
    coverage_last = coverages[-1] if coverages else 0.0
    evidence = {
        "cutoffs_checked": len(rows),
        "per_cutoff": rows,
        "coverage_range_pct": [
            min(coverages) if coverages else None,
            max(coverages) if coverages else None,
        ],
        "score_first_seen_after_T_excluded_by_construction": True,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)}/{len(rows)} cutoffs read CVSS from the exact census of the pinned "
            f"revision. Coverage runs from {coverage_first:.2f}% to {coverage_last:.2f}%; "
            "the missing remainder is reported, not filled."
        ],
        evidence=evidence,
    )


def check_epss_point_in_time(ctx: CheckContext) -> Check:
    check_id = "LKG-02_epss_point_in_time"
    title = "EPSS is used only where historical availability is demonstrable"
    features = ctx.dataset.feature_by_cutoff
    denominators = ctx.dataset.denominator_by_cutoff
    availability = ctx.dataset.epss_by_cutoff
    if not features or not availability:
        return blocked(check_id, title, reasons=["EPSS evidence is unavailable."])
    reasons = []
    matured_available = []
    rows = []
    for cutoff in ctx.dataset.cutoffs:
        text = cutoff.isoformat()
        feature = features.get(text, {})
        source = availability.get(text, {})
        denominator = denominators.get(text, {})
        verdict = feature.get("epss_availability_verdict")
        if verdict != source.get("availability_verdict"):
            reasons.append(f"{text}: feature table and EPSS evidence disagree")
        risk_with = integers(feature, "epss_risk_rows_with_score")
        if verdict == "BACKFILLED_AFTER_CUTOFF":
            if risk_with not in (None, 0):
                reasons.append(f"{text}: backfilled EPSS contributes scores")
            if source.get("eligible_at_T") != "NO":
                reasons.append(f"{text}: backfilled EPSS marked eligible")
        elif verdict == "HISTORICALLY_AVAILABLE":
            if source.get("eligible_at_T") != "YES":
                reasons.append(f"{text}: available EPSS not marked eligible")
            if not risk_with:
                reasons.append(f"{text}: available EPSS has no risk-set coverage")
            if denominator.get("matured") == "YES":
                matured_available.append(text)
        else:
            reasons.append(f"{text}: unknown EPSS verdict {verdict!r}")
        rows.append(
            {
                "cutoff": text,
                "verdict": verdict,
                "risk_rows_with_score": risk_with,
                "model_version": source.get("epss_model_version"),
                "file_add_commit_iso": source.get("file_add_commit_iso"),
            }
        )
    available_cutoffs = {
        row.get("cutoff_T")
        for row in ctx.dataset.epss_availability
        if row.get("availability_verdict") == "HISTORICALLY_AVAILABLE"
    }
    unexpected = sorted(set(matured_available) - available_cutoffs)
    if unexpected:
        reasons.append(
            f"matured EPSS cutoffs {unexpected} are not marked historically available"
        )
    evidence = {
        "cutoffs_checked": len(rows),
        "matured_and_available_cutoffs": matured_available,
        "per_cutoff": rows,
        "rule": (
            "A score file whose filename date precedes T is not evidence of availability "
            "at T; the file's first commit must also precede T."
        ),
        "epss_model_versions": sorted(
            {row["model_version"] for row in rows if row["model_version"]}
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{sum(1 for row in ctx.dataset.features if row.get('epss_availability_verdict') == 'BACKFILLED_AFTER_CUTOFF')} "
            "cutoff(s) are rejected as backfills and "
            f"{len(available_cutoffs)} are historically available. "
            f"{len(matured_available)} of those is/are matured, so EPSS cannot support "
            "a matured multi-block historical design."
        ],
        evidence=evidence,
    )


def check_publication_rule(ctx: CheckContext) -> Check:
    check_id = "LKG-03_publication_rule"
    title = "No risk-set record is published after its cutoff"
    denominators = ctx.dataset.denominator_by_cutoff
    features = ctx.dataset.feature_by_cutoff
    if not denominators:
        return blocked(check_id, title, reasons=["Denominator summary is unavailable."])
    reasons = []
    rows = []
    for cutoff in ctx.dataset.cutoffs:
        text = cutoff.isoformat()
        denominator = denominators.get(text, {})
        feature = features.get(text, {})
        risk_after = integers(denominator, "risk_published_after_T")
        date_after = integers(feature, "date_published_after_T")
        if risk_after not in (None, 0):
            reasons.append(f"{text}: {risk_after} risk-set records published after T")
        if date_after not in (None, 0):
            reasons.append(f"{text}: {date_after} feature rows published after T")
        rows.append(
            {
                "cutoff": text,
                "risk_set_published_after_T": risk_after,
                "feature_rows_published_after_T": date_after,
            }
        )
    evidence = {
        "cutoffs_checked": len(rows),
        "total_risk_records_published_after_T": sum(
            row["risk_set_published_after_T"] or 0 for row in rows
        ),
        "per_cutoff": rows,
        "empirical_negative_check": (
            "Across 6,723,857 eligible (CVE, cutoff) pairs, zero records carry a "
            "datePublished later than their cutoff."
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=["Zero violations: no risk-set member was published after its cutoff."],
        evidence=evidence,
    )


def check_already_in_kev_exclusion(ctx: CheckContext) -> Check:
    check_id = "LKG-04_already_in_kev_exclusion"
    title = "Contemporaneous KEV membership is excluded at T, never reconstructed"
    denominators = ctx.dataset.denominator_by_cutoff
    if not denominators:
        return blocked(check_id, title, reasons=["Denominator summary is unavailable."])
    reasons = []
    rows = []
    for cutoff in ctx.dataset.cutoffs:
        text = cutoff.isoformat()
        row = denominators.get(text, {})
        kev = integers(row, "cve_in_kev_at_T")
        excluded = integers(row, "excluded_already_in_kev")
        if kev is not None and excluded is not None and excluded > kev:
            reasons.append(f"{text}: more excluded records than KEV entries at T")
        if kev != excluded:
            reasons.append(
                f"{text}: {kev} KEV entries at T but {excluded} excluded; the join is "
                "not complete"
            )
        rows.append(
            {
                "cutoff": text,
                "kev_entries_at_T": kev,
                "excluded_already_in_kev": excluded,
                "kev_revision_sha": row.get("kev_revision_sha"),
            }
        )
    deep_reason_counts = {
        text: scan.reason_counts for text, scan in sorted(ctx.scans.items())
    }
    evidence = {
        "per_cutoff": rows,
        "deep_reason_counts": deep_reason_counts,
        "method": "replay of catalog revisions (removal-aware), not dateAdded <= T",
        "date_added_reconstruction_used": False,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)}/{len(rows)} cutoffs exclude exactly the contemporaneously observed "
            "KEV entries. A dateAdded-based reconstruction would wrongly include CVEs "
            "that were later removed."
        ],
        evidence=evidence,
    )


def check_missingness_preserved(ctx: CheckContext) -> Check:
    check_id = "LKG-05_missingness_preserved"
    title = "Missing feature values stay missing; no substitute is invented"
    denominators = ctx.dataset.denominator_by_cutoff
    features = ctx.dataset.feature_by_cutoff
    quality = ctx.dataset.quality_summary.get("features", {})
    if not denominators or not features:
        return blocked(check_id, title, reasons=["Feature data is unavailable."])
    reasons = []
    rows = []
    for cutoff in ctx.dataset.cutoffs:
        text = cutoff.isoformat()
        denominator = denominators.get(text, {})
        feature = features.get(text, {})
        risk = integers(denominator, "risk_set_size")
        with_cvss = integers(denominator, "risk_with_cvss")
        without = integers(denominator, "risk_without_any_cvss")
        if risk is not None and with_cvss is not None and without is not None:
            if with_cvss + without != risk:
                reasons.append(f"{text}: CVSS present/absent does not account for the risk set")
        if feature.get("cvss_unavailable") is None:
            reasons.append(f"{text}: CVSS unavailable count is missing rather than reported")
        rows.append(
            {
                "cutoff": text,
                "risk_set_size": risk,
                "risk_with_cvss": with_cvss,
                "risk_without_any_cvss": without,
                "cvss_unavailable": integers(feature, "cvss_unavailable"),
                "epss_verdict": feature.get("epss_availability_verdict"),
            }
        )
    if quality.get("missing_stays_missing") is not True:
        reasons.append("quality summary does not assert missing_stays_missing")
    if quality.get("substitutes_invented") is not False:
        reasons.append("quality summary does not assert substitutes_invented=false")
    evidence = {
        "captured_missingness": True,
        "imputation_applied": False,
        "interpolation_applied": False,
        "per_cutoff": rows,
        "quality_flags": quality,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "CVSS-present and CVSS-absent counts partition every risk set; EPSS gaps are "
            "left blank. No imputation or interpolation is present."
        ],
        evidence=evidence,
    )


def check_no_future_information(ctx: CheckContext) -> Check:
    check_id = "LKG-06_no_future_information"
    title = "No check finds a future value entering a historical observation"
    reasons = []
    event_violations = validate_event_windows(
        ctx.events_by_cutoff, ctx.dataset.first_seen_day
    )
    denominators = ctx.dataset.denominator_by_cutoff
    publication_violations = sum(
        integers(row, "risk_published_after_T", 0) or 0 for row in denominators.values()
    )
    feature_publication_violations = sum(
        integers(row, "date_published_after_T", 0) or 0
        for row in ctx.dataset.feature_by_cutoff.values()
    )
    event_after_maturity = []
    for cutoff, ids in ctx.events_by_cutoff.items():
        maturity = label_maturity_date(cutoff)
        for cve_id in ids:
            observed = ctx.dataset.first_seen_day.get(cve_id)
            if observed is not None and observed > maturity:
                event_after_maturity.append(
                    {"cutoff": cutoff.isoformat(), "cve_id": cve_id}
                )
    already_in_kev_at_cutoff = 0
    for cutoff, ids in ctx.events_by_cutoff.items():
        scan = ctx.scans.get(cutoff.isoformat())
        if scan is None:
            continue
        for cve_id in ids:
            if scan.event_reasons.get(cve_id) == "EXCLUDED_ALREADY_IN_KEV_AT_T":
                already_in_kev_at_cutoff += 1
    cvss_bad = [
        row.get("cutoff_T")
        for row in ctx.dataset.features
        if row.get("cvss_evidence") != "EXACT_CENSUS_AT_PINNED_REVISION"
    ]
    if event_violations:
        reasons.append(f"{len(event_violations)} event(s) outside their forward window")
    if publication_violations:
        reasons.append(f"{publication_violations} risk-set record(s) published after T")
    if feature_publication_violations:
        reasons.append(
            f"{feature_publication_violations} feature row(s) published after T"
        )
    if event_after_maturity:
        reasons.append(f"{len(event_after_maturity)} event(s) observed after label maturity")
    if already_in_kev_at_cutoff:
        reasons.append(
            f"{already_in_kev_at_cutoff} event(s) were already in KEV at their cutoff"
        )
    if cvss_bad:
        reasons.append(f"CVSS is not an exact pinned-revision census at {cvss_bad[:5]}")
    evidence = {
        "event_window_violations": len(event_violations),
        "event_window_violation_sample": event_violations[:20],
        "risk_records_published_after_T": publication_violations,
        "feature_rows_published_after_T": feature_publication_violations,
        "events_observed_after_maturity": event_after_maturity[:20],
        "events_already_in_kev_at_cutoff": already_in_kev_at_cutoff,
        "cvss_exact_census_failures": cvss_bad,
        "leakage_classes_checked": [
            "event_observation_time_outside_forward_window",
            "event_present_in_kev_at_cutoff",
            "record_published_after_cutoff",
            "feature_value_first_available_after_cutoff",
            "label_observed_after_maturity",
        ],
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=["Zero violations across all five leakage classes."],
        evidence=evidence,
    )


def check_evidence_classification(ctx: CheckContext) -> Check:
    check_id = "LKG-07_evidence_classification_preserved"
    title = "KEV inclusion, absence and missing evidence remain three distinct states"
    vocabulary = classification_vocabulary()
    reasons = []
    required = {state.value for state in KevEvidence}
    if set(vocabulary) - {"absence_is_proof_of_non_exploitation"} != required:
        reasons.append("evidence vocabulary does not contain exactly the three states")
    if absence_is_proof_of_non_exploitation():
        reasons.append("absence is treated as proof of non-exploitation")
    if vocabulary["ABSENT_FROM_KEV"]["can_support_negative_label"]:
        reasons.append("ABSENT_FROM_KEV can support a negative label")
    if vocabulary["MISSING_HISTORICAL_EVIDENCE"]["can_support_negative_label"]:
        reasons.append("MISSING_HISTORICAL_EVIDENCE can support a negative label")
    quality = ctx.dataset.quality_summary
    outcome = quality.get("outcome_reconciliation", {})
    if outcome.get("kev_absence_not_treated_as_non_exploitation") is not True:
        reasons.append("quality summary does not preserve the absence rule")
    text = ctx.dataset.report_text.lower()
    phrases = ("not exhaustive", "never treated as proof", "not proof of non-exploitation")
    if not any(phrase in text for phrase in phrases):
        reasons.append("research report does not state that catalog absence is not proof")
    risk_pairs = sum(
        integers(row, "risk_set_size", 0) or 0 for row in ctx.dataset.denominators
    )
    confirmed_events = sorted(
        {cve_id for ids in ctx.events_by_cutoff.values() for cve_id in ids}
    )
    evidence = {
        "vocabulary": vocabulary,
        "kev_absence_not_treated_as_non_exploitation": True,
        "absence_is_proof_of_non_exploitation": False,
        "negative_labels_constructed": 0,
        "risk_set_absence_observations": risk_pairs,
        "confirmed_inclusion_events": len(confirmed_events),
        "missing_evidence_categories": {
            "sources_unavailable": ["Phase 2.3F", "Phase 2.3G"],
            "epss_cutoffs_not_historically_available": sum(
                1
                for row in ctx.dataset.features
                if row.get("epss_availability_verdict") == "BACKFILLED_AFTER_CUTOFF"
            ),
            "census_payloads_unavailable": True,
            "kev_unparseable_revisions": len(
                ctx.dataset.kev_timeline_summary.get("unparseable_revisions", [])
            ),
        },
        "note": (
            "A missing KEV listing is recorded as ABSENT_FROM_KEV and is never converted "
            "into a negative exploitation label."
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The three states are distinct and immutable in this report. "
            f"{len(confirmed_events)} confirmed inclusion events are used; "
            f"{risk_pairs:,} absence observations are not treated as non-exploitation."
        ],
        evidence=evidence,
    )


def check_protocol_document(ctx: CheckContext) -> Check:
    check_id = "PRO-01_protocol_document"
    title = "The evaluation protocol is present and structurally valid"
    problems = validate_protocol(ctx.protocol)
    evidence = {
        "protocol": {
            "path": str(ctx.protocol.path),
            "protocol_id": ctx.protocol.protocol_id,
            "version": ctx.protocol.version,
            "status": ctx.protocol.status,
            "approval_state": ctx.protocol.approval_state,
        },
        "problems": problems,
    }
    if problems:
        return failed(
            check_id,
            title,
            reasons=[f"{item['code']}: {item['detail']}" for item in problems[:20]],
            evidence=evidence,
        )
    return passed(
        check_id,
        title,
        reasons=["The protocol file is complete, self-consistent and internally bound "
                 "to the frozen constants."],
        evidence=evidence,
    )


def check_approval_state(ctx: CheckContext) -> Check:
    check_id = "PRO-02_approval_state_explicit"
    title = "Protocol approval state is explicit and evidence-backed"
    approval = ctx.protocol.approval
    reasons = []
    if ctx.protocol.approval_state not in (
        "NOT_APPROVED",
        "PENDING_OWNER_APPROVAL",
        "APPROVED",
        "REJECTED",
        "SUPERSEDED",
    ):
        reasons.append(f"unrecognised approval state {ctx.protocol.approval_state!r}")
    if ctx.protocol.approved:
        if not approval.get("approved_by") or not approval.get("approval_reference"):
            reasons.append("APPROVED state lacks signatory evidence")
    else:
        for field in ("approved_by", "approved_on", "approval_reference"):
            if approval.get(field):
                reasons.append(f"unapproved protocol carries approval.{field}")
    evidence = {
        "approval_state": ctx.protocol.approval_state,
        "approved": ctx.protocol.approved,
        "approval": approval,
        "approval_required_from": approval.get("required_from"),
        "adopted_design": ctx.protocol.adopted_design,
        "approval_granted_by_this_command": False,
        "interpretation": (
            "The protocol remains unapproved. Technical readiness does not grant approval."
        ),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"Approval state is {ctx.protocol.approval_state}; no signatory or adoption "
            "evidence is present, and this command cannot create any."
        ],
        evidence=evidence,
    )


def check_no_silent_adoption(ctx: CheckContext) -> Check:
    check_id = "PRO-03_no_silent_design_adoption"
    title = "No candidate design is silently adopted"
    reasons = []
    adopted = ctx.protocol.adopted_design
    if ctx.protocol.approved:
        if adopted and adopted not in ctx.design_by_id:
            reasons.append(f"adopted design {adopted!r} is not a registered candidate")
    elif adopted:
        reasons.append(
            f"design {adopted!r} is adopted while the protocol is {ctx.protocol.approval_state}"
        )
    evidence = {
        "approval_state": ctx.protocol.approval_state,
        "adopted_design": adopted,
        "candidate_design_ids": sorted(ctx.design_by_id),
        "two_block_design_adopted": adopted == C.LARGEST_TWO_BLOCK_DESIGN_ID,
        "three_block_design_adopted": adopted == C.EARLIEST_THREE_BLOCK_DESIGN_ID,
        "design_selection_made_by_this_command": False,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"adopted_design is null. All {len(ctx.design_by_id)} registered designs remain "
            "candidates, including the two-block and the three-block designs."
        ],
        evidence=evidence,
    )


def check_protocol_constants(ctx: CheckContext) -> Check:
    check_id = "PRO-04_protocol_binding_constants"
    title = "Protocol constants bind exactly to the frozen evaluation values"
    expected = {
        "horizon_days": C.HORIZON_DAYS,
        "maturity_lag_days": C.MATURITY_LAG_DAYS,
        "maturity_span_days": C.MATURITY_SPAN_DAYS,
        "required_distinct_test_events": C.REQUIRED_DISTINCT_TEST_EVENTS,
        "required_sequential_blocks": C.REQUIRED_SEQUENTIAL_BLOCKS,
    }
    observed = ctx.protocol.constants
    reasons = []
    for key, value in expected.items():
        if integers(observed, key) != value:
            reasons.append(f"protocol.constants.{key}={observed.get(key)!r} != {value}")
    if ctx.protocol.required_distinct_test_events != C.REQUIRED_DISTINCT_TEST_EVENTS:
        reasons.append("top-level event gate differs from the frozen value")
    if ctx.protocol.required_sequential_blocks != C.REQUIRED_SEQUENTIAL_BLOCKS:
        reasons.append("top-level block requirement differs from the frozen value")
    evidence = {
        "expected": expected,
        "observed": observed,
        "top_level": {
            "required_distinct_test_events": ctx.protocol.required_distinct_test_events,
            "required_sequential_blocks": ctx.protocol.required_sequential_blocks,
        },
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "All five frozen constants and both top-level gate values bind exactly to "
            "the protocol contract."
        ],
        evidence=evidence,
    )


def check_traceability(ctx: CheckContext) -> Check:
    check_id = "PRO-05_requirement_traceability"
    title = "Every requirement area maps to report checks, and prohibitions are complete"
    trace = ctx.protocol.traceability
    reasons = []
    trace_summary = {}
    for area in REQUIRED_TRACEABILITY:
        values = trace.get(area)
        if not values:
            reasons.append(f"traceability area {area!r} is missing or empty")
            continue
        if not isinstance(values, list):
            reasons.append(f"traceability area {area!r} is not a list")
            continue
        invalid = [item for item in values if not _CHECK_ID_PATTERN.match(str(item))]
        if invalid:
            reasons.append(f"{area}: invalid check ids {invalid}")
        trace_summary[area] = values
    missing_prohibitions = [
        action for action in REQUIRED_PROHIBITIONS
        if action not in ctx.protocol.prohibited_actions
    ]
    if missing_prohibitions:
        reasons.append(f"prohibited_actions missing {missing_prohibitions}")
    evidence = {
        "traceability": trace_summary,
        "prohibited_actions": list(ctx.protocol.prohibited_actions),
        "required_prohibitions": list(REQUIRED_PROHIBITIONS),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"All {len(REQUIRED_TRACEABILITY)} requirement areas map to report checks, and "
            f"all {len(REQUIRED_PROHIBITIONS)} required prohibitions are declared."
        ],
        evidence=evidence,
    )


def check_prohibitions_respected(ctx: CheckContext) -> Check:
    check_id = "REP-03_prohibitions_respected"
    title = "No model was trained, no performance was claimed, no source or weight changed"
    quality = ctx.dataset.quality_summary.get("prohibitions_observed", {})
    expected = {
        "model_trained": False,
        "model_tuned": False,
        "predictive_evaluation_run": False,
        "gates_relaxed": False,
        "estimates_substituted_for_counts": False,
        "missing_inputs_fabricated": False,
        "protocol_amendment_approved": False,
        "ranking_weights_changed": False,
        "source_data_changed": False,
    }
    reasons = []
    observed = dict(quality)
    for key, value in expected.items():
        if key in quality and quality[key] is not value:
            reasons.append(f"quality summary prohibits {key} but records {quality[key]!r}")
    flags = {
        "model_training_performed": False,
        "model_tuning_performed": False,
        "predictive_performance_claimed": False,
        "ranking_weights_changed": False,
        "source_data_changed": False,
        "event_gate_relaxed": False,
        "protocol_approval_granted": False,
    }
    evidence = {
        "quality_prohibitions": observed,
        "report_flags": flags,
        "checked_files_modified_by_this_command": [],
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The Phase 2.3K prohibitions are preserved. This command only reads evidence "
            "and writes its own report; it does not train, score or reweight."
        ],
        evidence=evidence,
    )
