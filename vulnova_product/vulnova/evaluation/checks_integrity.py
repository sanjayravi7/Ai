"""Dataset, artifact and provenance checks (INT-*, PRV-*)."""

from __future__ import annotations

import datetime as dt
import re

from . import constants as C
from .checks_base import (
    Check,
    CheckContext,
    blocked,
    combine_status,
    failed,
    not_applicable,
    passed,
)
from .datasets import integers
from .temporal import parse_date, parse_instant

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SELECTION_RULE = "greatest committer timestamp <= T 00:00:00Z on main"
_ALLOWED_REASONS = {
    "ELIGIBLE_AT_RISK",
    "EXCLUDED_ALREADY_IN_KEV_AT_T",
    "EXCLUDED_UNPUBLISHED_AT_T",
}


def _cutoff_start(cutoff: dt.date) -> dt.datetime:
    return dt.datetime.combine(cutoff, dt.time.min, tzinfo=dt.timezone.utc)


def check_archive_digests(ctx: CheckContext) -> Check:
    check_id = "INT-01_archive_digests"
    title = "Research archive bytes match their published SHA-256 sidecars"
    if not ctx.archive_results:
        return not_applicable(
            check_id,
            title,
            reasons=["No archives were supplied; running against an extracted dataset."],
            blocking=False,
        )
    statuses = []
    reasons = []
    for result in ctx.archive_results:
        statuses.append("BLOCKED" if result["status"] == "MISSING" else result["status"])
        if result["status"] == "PASS":
            continue
        if result["status"] == "MISSING":
            reasons.append(f"{result['archive']}: {result.get('reason', 'missing')}")
        else:
            reasons.append(
                f"{result['archive']}: declared {result.get('sha256')}, "
                f"actual {result.get('actual_sha256')}"
            )
    status = combine_status(statuses)
    return make_archive_check(check_id, title, status, reasons, ctx)


def make_archive_check(
    check_id: str, title: str, status: str, reasons: list[str], ctx: CheckContext
) -> Check:
    evidence = {"archives": ctx.archive_results, "extraction": ctx.extract_records}
    if status == "FAIL":
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    if status == "BLOCKED":
        return blocked(check_id, title, reasons=reasons, evidence=evidence)
    if status == "NOT_APPLICABLE":
        return not_applicable(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(ctx.archive_results)} archive(s) match their published SHA-256 sidecars."
        ],
        evidence=evidence,
    )


def check_core_bundle_manifest(ctx: CheckContext) -> Check:
    check_id = "INT-02_core_bundle_manifest"
    title = "Core bundle matches its internal integrity manifest where present"
    result = ctx.core_manifest
    if result is None:
        return not_applicable(
            check_id,
            title,
            reasons=["Core bundle was not supplied."],
            blocking=False,
        )
    missing = {item["path"] for item in result["missing"]}
    expected_missing = {
        path
        for path in missing
        if path.startswith("risk_set_membership/cutoff_")
        or path == "inventory/inventory_method.json"
    }
    unexpected_missing = sorted(missing - expected_missing)
    reasons = []
    if result["mismatched_count"]:
        reasons.append(
            f"{result['mismatched_count']} file(s) do not match the manifest digest."
        )
    if unexpected_missing:
        reasons.append(
            "Unexpected missing file(s) in the core bundle: "
            + ", ".join(unexpected_missing[:5])
        )
    evidence = {
        "present_count": result["present_count"],
        "mismatched_count": result["mismatched_count"],
        "missing_count": result["missing_count"],
        "missing_expected_by_design": len(expected_missing),
        "unexpected_missing": unexpected_missing,
        "documented_expectation": "23 present, 0 mismatched, 22 absent",
        "absent_paths": sorted(missing),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence, blocking=False)
    return passed(
        check_id,
        title,
        reasons=[
            "The 22 absences are the bulk membership partitions plus the "
            "duplicate inventory_method.json that the core bundle documents as omitted."
        ],
        evidence=evidence,
        blocking=False,
    )


def check_full_export_manifest(ctx: CheckContext) -> Check:
    check_id = "INT-03_full_export_integrity_manifest"
    title = "Full export matches its internal integrity manifest"
    result = ctx.full_manifest
    if result is None:
        return blocked(
            check_id,
            title,
            reasons=[
                "Full export was not extracted; membership partitions and identifier "
                "lists cannot be verified."
            ],
            blocking=True,
        )
    reasons = []
    if result["missing_count"]:
        reasons.append(f"{result['missing_count']} manifest file(s) are absent.")
    if result["mismatched_count"]:
        reasons.append(f"{result['mismatched_count']} file(s) have a wrong digest/size.")
    evidence = {
        "present_count": result["present_count"],
        "missing_count": result["missing_count"],
        "mismatched_count": result["mismatched_count"],
        "entries": result["entries"],
        "total_bytes_present": result["total_bytes_present"],
        "missing_sample": [item["path"] for item in result["missing"][:10]],
        "mismatched_sample": result["mismatched"][:5],
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"All {result['present_count']} manifest entries are present with matching "
            "SHA-256 and size."
        ],
        evidence=evidence,
    )


def check_export_member_manifest(ctx: CheckContext) -> Check:
    check_id = "INT-04_export_member_manifest"
    title = "Every archive member matches EXPORT_MANIFEST.json"
    result = ctx.export_manifest
    if result is None:
        return not_applicable(
            check_id,
            title,
            reasons=["EXPORT_MANIFEST.json was not available for verification."],
            blocking=False,
        )
    reasons = []
    if result["declared_members"] != result["checked_members"]:
        reasons.append(
            f"manifest declares {result['declared_members']} members but "
            f"{result['checked_members']} were checked"
        )
    if result["missing_members"]:
        reasons.append(f"{len(result['missing_members'])} member(s) are absent")
    if result["mismatched_members"]:
        reasons.append(f"{len(result['mismatched_members'])} member(s) do not match")
    evidence = result
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(check_id, title, evidence=evidence)


def check_membership_partition_checksums(ctx: CheckContext) -> Check:
    check_id = "INT-05_membership_partition_checksums"
    title = "Membership partitions match INDEX.csv sizes and SHA-256"
    if not ctx.deep_requested:
        return blocked(
            check_id,
            title,
            reasons=["Deep scan was disabled (--no-deep); partition bytes were not read."],
        )
    if not ctx.dataset.has_membership:
        return blocked(
            check_id,
            title,
            reasons=[
                "Membership partitions are not present. The core bundle omits them; "
                "use the full export archive."
            ],
        )
    missing = [scan.cutoff for scan in ctx.scans.values() if scan.partition_bytes is None]
    bad = [
        scan
        for scan in ctx.scans.values()
        if scan.partition_bytes is not None
        and (scan.checksum_matches is not True or scan.bytes_match is not True)
    ]
    evidence = {
        "partitions_checked": len(ctx.scans) - len(missing),
        "partition_missing": missing,
        "checksum_mismatches": [scan.cutoff for scan in bad],
        "total_partition_bytes": sum(scan.partition_bytes or 0 for scan in ctx.scans.values()),
        "scan_problems": ctx.scan_problems[:50],
    }
    if missing:
        return blocked(
            check_id,
            title,
            reasons=[
                f"{len(missing)} partition(s) are missing, so their bytes cannot be "
                "verified against INDEX.csv: " + ", ".join(missing[:8])
            ],
            evidence=evidence,
        )
    if bad:
        return failed(
            check_id,
            title,
            reasons=[
                f"{len(bad)} partition(s) failed checksum/size verification: "
                + ", ".join(scan.cutoff for scan in bad[:8])
            ],
            evidence=evidence,
        )
    return passed(
        check_id,
        title,
        reasons=[
            f"All {len(ctx.scans)} partitions match INDEX.csv (byte size and SHA-256)."
        ],
        evidence=evidence,
    )


def check_membership_row_accounting(ctx: CheckContext) -> Check:
    check_id = "INT-06_membership_row_accounting"
    title = "Membership partitions reconcile exactly to the denominator summary"
    if not ctx.deep_requested or not ctx.dataset.has_membership or not ctx.scans:
        return blocked(
            check_id,
            title,
            reasons=["Deep membership scan was not performed; row accounting is unverified."],
            blocking=ctx.deep_requested,
        )
    missing = [scan.cutoff for scan in ctx.scans.values() if scan.partition_bytes is None]
    if missing:
        return blocked(
            check_id,
            title,
            reasons=[
                f"{len(missing)} membership partition(s) are missing, so row accounting "
                "cannot be reconciled: " + ", ".join(missing[:8])
            ],
            evidence={"partition_missing": missing},
        )
    unreadable = [scan for scan in ctx.scans.values() if scan.error]
    if unreadable:
        return blocked(
            check_id,
            title,
            reasons=[
                f"{len(unreadable)} membership partition(s) could not be parsed, so row "
                "accounting is unverified rather than inconsistent: "
                + ", ".join(f"{scan.cutoff} ({scan.error})" for scan in unreadable[:8])
            ],
            evidence={
                "unreadable": [
                    {"cutoff": scan.cutoff, "error": scan.error} for scan in unreadable[:50]
                ]
            },
        )
    denominators = ctx.dataset.denominator_by_cutoff
    index = ctx.dataset.index_by_cutoff
    reasons: list[str] = []
    per_cutoff = []
    total_rows = 0
    total_eligible = 0
    for cutoff_text, scan in sorted(ctx.scans.items()):
        denominator = denominators.get(cutoff_text, {})
        index_row = index.get(cutoff_text, {})
        expected_records = integers(denominator, "inventory_records")
        expected_risk = integers(denominator, "risk_set_size")
        expected_kev = integers(denominator, "excluded_already_in_kev")
        expected_unpublished = integers(denominator, "excluded_unpublished_at_T")
        actual_reasons = scan.reason_counts
        if scan.error:
            reasons.append(f"{cutoff_text}: scan error {scan.error}")
        if scan.duplicate_ids:
            reasons.append(f"{cutoff_text}: {scan.duplicate_ids} duplicate membership ids")
        if scan.cutoff_column_mismatches:
            reasons.append(
                f"{cutoff_text}: {scan.cutoff_column_mismatches} rows carry a different cutoff"
            )
        if scan.membership_not_in_inventory:
            reasons.append(
                f"{cutoff_text}: {scan.membership_not_in_inventory} rows absent from the "
                "inventory identifier list"
            )
        if scan.inventory_duplicates:
            reasons.append(
                f"{cutoff_text}: {scan.inventory_duplicates} duplicate inventory identifiers"
            )
        if scan.rows != expected_records:
            reasons.append(
                f"{cutoff_text}: partition rows {scan.rows} != inventory_records "
                f"{expected_records}"
            )
        if scan.inventory_rows != expected_records:
            reasons.append(
                f"{cutoff_text}: inventory id rows {scan.inventory_rows} != "
                f"inventory_records {expected_records}"
            )
        unknown = set(actual_reasons) - _ALLOWED_REASONS
        if unknown:
            reasons.append(f"{cutoff_text}: unknown reason code(s) {sorted(unknown)}")
        if actual_reasons.get("ELIGIBLE_AT_RISK", 0) != expected_risk:
            reasons.append(
                f"{cutoff_text}: ELIGIBLE_AT_RISK {actual_reasons.get('ELIGIBLE_AT_RISK', 0)} "
                f"!= risk_set_size {expected_risk}"
            )
        if actual_reasons.get("EXCLUDED_ALREADY_IN_KEV_AT_T", 0) != expected_kev:
            reasons.append(
                f"{cutoff_text}: EXCLUDED_ALREADY_IN_KEV_AT_T "
                f"{actual_reasons.get('EXCLUDED_ALREADY_IN_KEV_AT_T', 0)} != {expected_kev}"
            )
        if actual_reasons.get("EXCLUDED_UNPUBLISHED_AT_T", 0) != expected_unpublished:
            reasons.append(
                f"{cutoff_text}: EXCLUDED_UNPUBLISHED_AT_T "
                f"{actual_reasons.get('EXCLUDED_UNPUBLISHED_AT_T', 0)} != {expected_unpublished}"
            )
        if sum(actual_reasons.values()) != scan.rows:
            reasons.append(f"{cutoff_text}: reason counts do not sum to partition rows")
        if integers(index_row, "risk_set_size") != expected_risk:
            reasons.append(f"{cutoff_text}: INDEX risk_set_size differs from summary")
        if integers(index_row, "records_total") != expected_records:
            reasons.append(f"{cutoff_text}: INDEX records_total differs from summary")
        total_rows += scan.rows
        total_eligible += actual_reasons.get("ELIGIBLE_AT_RISK", 0)
        per_cutoff.append(
            {
                "cutoff": cutoff_text,
                "rows": scan.rows,
                "unique_ids": scan.unique_ids,
                "reason_counts": actual_reasons,
                "inventory_rows": scan.inventory_rows,
            }
        )

    facts = ctx.dataset.facts
    if integers(facts, "risk_set_sum_unique_pairs") != total_eligible:
        reasons.append(
            "facts.risk_set_sum_unique_pairs "
            f"{facts.get('risk_set_sum_unique_pairs')} != {total_eligible} eligible pairs"
        )
    evidence = {
        "cutoffs_checked": len(ctx.scans),
        "total_rows": total_rows,
        "total_eligible_pairs": total_eligible,
        "cross_cutoff_rows_are_expected": total_rows - total_eligible,
        "per_cutoff": per_cutoff,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{total_rows:,} rows across {len(ctx.scans)} partitions reconcile: every "
            "reason count, size and identifier membership agrees with the summary."
        ],
        evidence=evidence,
    )


def check_inventory_census_consistency(ctx: CheckContext) -> Check:
    check_id = "INT-07_inventory_census_consistency"
    title = "Inventory manifest and census index agree with each other and the summaries"
    dataset = ctx.dataset
    if not dataset.census:
        return blocked(
            check_id,
            title,
            reasons=["evidence/census_index.csv is unavailable."],
        )
    inventory = dataset.inventory_by_cutoff
    denominator = dataset.denominator_by_cutoff
    cutoffs = {cutoff.isoformat() for cutoff in dataset.cutoffs}
    reasons: list[str] = []
    rows = []
    for row in dataset.census:
        cutoff = row.get("cutoff_T", "")
        inv = inventory.get(cutoff, {})
        den = denominator.get(cutoff, {})
        expected = integers(inv, "record_count")
        members = integers(row, "census_record_members")
        distinct = integers(row, "distinct_cve_ids")
        if row.get("completeness_match", "").lower() != "true":
            reasons.append(f"{cutoff}: completeness_match is not true")
        if integers(row, "duplicate_ids", 0) != 0:
            reasons.append(f"{cutoff}: duplicate ids in census")
        if integers(row, "parse_errors", 0) != 0:
            reasons.append(f"{cutoff}: parse errors in census")
        if integers(row, "revision_expected_records") != expected:
            reasons.append(f"{cutoff}: census expectation differs from inventory manifest")
        if integers(row, "census_record_members") != expected:
            reasons.append(f"{cutoff}: census members differ from inventory record_count")
        if integers(row, "distinct_cve_ids") != members:
            reasons.append(f"{cutoff}: census distinct ids differ from member count")
        if integers(den, "inventory_records") != expected:
            reasons.append(f"{cutoff}: denominator inventory count differs")
        if not _HEX64.match(str(row.get("census_sha256", ""))):
            reasons.append(f"{cutoff}: census_sha256 is not a sha256 digest")
        rows.append(
            {
                "cutoff": cutoff,
                "members": members,
                "distinct_ids": distinct,
                "census_bytes": integers(row, "census_bytes"),
                "completeness_match": row.get("completeness_match"),
                "duplicate_ids": integers(row, "duplicate_ids"),
                "parse_errors": integers(row, "parse_errors"),
            }
        )
    observed = {row.get("cutoff_T") for row in dataset.census}
    if observed != cutoffs:
        reasons.append(
            "census cutoff set differs from cutoffs.txt: "
            f"missing={sorted(cutoffs - observed)}, extra={sorted(observed - cutoffs)}"
        )
    evidence = {
        "rows": len(dataset.census),
        "cutoffs_checked": len(rows),
        "total_record_members": sum(row["members"] or 0 for row in rows),
        "census_payloads_available": False,
        "census_payload_note": (
            "The staged per-record census files are not shipped. Their recorded "
            "sizes and SHA-256 values are checked, but the payload bytes cannot be "
            "re-hashed from this repository."
        ),
        "per_cutoff": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)}/{len(rows)} censuses report complete enumeration, zero duplicates "
            "and zero parse "
            "errors; counts agree with the inventory manifest and denominators. The "
            "staged census payloads themselves are not available for re-hashing."
        ],
        evidence=evidence,
    )


def check_denominator_reconciliation(ctx: CheckContext) -> Check:
    check_id = "INT-08_denominator_reconciliation"
    title = "Risk-set denominators satisfy every recorded exclusion identity"
    dataset = ctx.dataset
    if not dataset.denominators:
        return blocked(check_id, title, reasons=["Risk-set denominator summary is unavailable."])
    reasons: list[str] = []
    rows = []
    previous_inventory = -1
    previous_risk = -1
    total_risk = 0
    for row in sorted(dataset.denominators, key=lambda item: item.get("cutoff_T", "")):
        cutoff = row.get("cutoff_T", "")
        inventory = integers(row, "inventory_records", 0) or 0
        risk = integers(row, "risk_set_size", 0) or 0
        excluded = sum(
            integers(row, key, 0) or 0
            for key in (
                "excluded_already_in_kev",
                "excluded_rejected_record",
                "excluded_unpublished_at_T",
                "excluded_malformed_identifier",
                "unresolved_record_unreadable",
            )
        )
        with_cvss = integers(row, "risk_with_cvss", 0) or 0
        without_cvss = integers(row, "risk_without_any_cvss", 0) or 0
        if inventory - excluded != risk:
            reasons.append(
                f"{cutoff}: inventory {inventory} - exclusions {excluded} != risk set {risk}"
            )
        if with_cvss + without_cvss != risk:
            reasons.append(f"{cutoff}: CVSS-available + unavailable != risk set")
        if integers(row, "risk_published_after_T", 0) != 0:
            reasons.append(f"{cutoff}: risk set contains records published after T")
        if integers(row, "unresolved_record_unreadable", 0) != 0:
            reasons.append(f"{cutoff}: unresolved unreadable records present")
        coverage = float(row.get("cvss_coverage_pct") or 0.0)
        computed = 100.0 * with_cvss / risk if risk else 0.0
        if abs(coverage - computed) > 0.005:
            reasons.append(
                f"{cutoff}: CVSS coverage {coverage} != recomputed {computed:.2f}"
            )
        if integers(row, "cve_in_kev_at_T", 0) < integers(row, "excluded_already_in_kev", 0):
            reasons.append(f"{cutoff}: excluded-already-in-KEV exceeds KEV membership at T")
        if inventory < previous_inventory:
            reasons.append(f"{cutoff}: inventory count decreases")
        if risk < previous_risk:
            reasons.append(f"{cutoff}: risk-set size decreases")
        previous_inventory, previous_risk = inventory, risk
        total_risk += risk
        rows.append(
            {
                "cutoff": cutoff,
                "inventory": inventory,
                "excluded": excluded,
                "risk_set": risk,
                "kev_at_t": integers(row, "cve_in_kev_at_T"),
                "cvss_coverage_pct": coverage,
            }
        )
    facts = dataset.facts
    if integers(facts, "cutoffs") != len(dataset.denominators):
        reasons.append("facts.cutoffs differs from the number of denominator rows")
    if integers(facts, "risk_set_sum_unique_pairs") != total_risk:
        reasons.append(
            f"facts risk-set pair total differs from recomputed {total_risk}"
        )
    if integers(facts, "risk_set_min") != min(row["risk_set"] for row in rows):
        reasons.append("facts.risk_set_min differs from recomputed minimum")
    if integers(facts, "risk_set_max") != max(row["risk_set"] for row in rows):
        reasons.append("facts.risk_set_max differs from recomputed maximum")
    evidence = {
        "cutoffs": len(rows),
        "total_risk_set_rows": total_risk,
        "risk_set_min": min(row["risk_set"] for row in rows),
        "risk_set_max": max(row["risk_set"] for row in rows),
        "per_cutoff": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)} cutoffs reconcile exactly; risk set {rows[0]['risk_set']:,} → "
            f"{rows[-1]['risk_set']:,}, {total_risk:,} eligible (CVE, cutoff) pairs."
        ],
        evidence=evidence,
    )


def check_source_revision_pins(ctx: CheckContext) -> Check:
    check_id = "PRV-01_source_revision_pins"
    title = "Every cutoff carries a resolved cvelistV5 revision pin and tree hash"
    dataset = ctx.dataset
    if not dataset.inventory_manifest:
        return blocked(check_id, title, reasons=["Inventory manifest is unavailable."])
    reasons: list[str] = []
    rows = []
    for row in dataset.inventory_manifest:
        cutoff_text = row.get("cutoff_T", "")
        try:
            cutoff = parse_date(cutoff_text)
        except ValueError:
            reasons.append(f"{cutoff_text!r}: invalid cutoff")
            continue
        revision = str(row.get("revision_sha", "")).lower()
        tree = str(row.get("cves_tree_sha", "")).lower()
        if row.get("resolution") != "RESOLVED":
            reasons.append(f"{cutoff_text}: resolution is {row.get('resolution')!r}")
        if not _HEX40.match(revision):
            reasons.append(f"{cutoff_text}: revision_sha is not a 40-hex commit")
        if not _HEX40.match(tree):
            reasons.append(f"{cutoff_text}: cves_tree_sha is not a 40-hex tree")
        if str(row.get("selection_rule", "")).strip() != _SELECTION_RULE:
            reasons.append(f"{cutoff_text}: selection rule changed")
        try:
            committed = parse_instant(str(row.get("revision_committer_iso", "")))
        except ValueError:
            reasons.append(f"{cutoff_text}: committer timestamp is not ISO")
            committed = None
        if committed is not None and committed >= _cutoff_start(cutoff):
            reasons.append(
                f"{cutoff_text}: pinned commit timestamp {committed.isoformat()} is not "
                "before 00:00:00Z on the cutoff"
            )
        if integers(row, "record_count", 0) <= 0:
            reasons.append(f"{cutoff_text}: record_count is not positive")
        if not _HEX64.match(str(row.get("partition_sha256", ""))):
            reasons.append(f"{cutoff_text}: inventory partition digest missing")
        rows.append(
            {
                "cutoff": cutoff_text,
                "revision_sha": revision,
                "revision_committer_iso": row.get("revision_committer_iso"),
                "cves_tree_sha": tree,
                "record_count": integers(row, "record_count"),
                "selection_rule": row.get("selection_rule"),
            }
        )
    if len(rows) != len(dataset.cutoffs):
        reasons.append(
            f"inventory manifest has {len(rows)} rows but cutoffs.txt has "
            f"{len(dataset.cutoffs)}"
        )
    method = dataset.inventory_method
    method_available = bool(method)
    method_note = None
    if method_available:
        if str(method.get("clone_head", "")).lower() and not _HEX40.match(
            str(method.get("clone_head", "")).lower()
        ):
            reasons.append("inventory_method.clone_head is not a 40-hex commit")
        if method.get("covers_all_cutoffs") is not True:
            reasons.append("inventory_method does not claim coverage of all cutoffs")
        if integers(method, "resolved") != len(dataset.cutoffs):
            reasons.append("inventory_method.resolved differs from the cutoff count")
    else:
        method_note = "inventory_method.json is absent from the core bundle."
    evidence = {
        "cutoffs_pinned": len(rows),
        "revisions": rows,
        "selection_rule": _SELECTION_RULE,
        "inventory_method_available": method_available,
        "inventory_method_note": method_note,
        "retrieval_timestamp_per_revision": "NOT_RECORDED",
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)}/{len(rows)} revisions resolve under the frozen rule; every "
            "committer timestamp is "
            "before its cutoff, and every pin carries a cves tree hash and partition digest."
        ],
        evidence=evidence,
    )


def check_cutoff_grid(ctx: CheckContext) -> Check:
    check_id = "PRV-02_cutoff_grid"
    title = "All artifacts describe one consistent, non-duplicated cutoff grid"
    dataset = ctx.dataset
    cutoffs = dataset.cutoffs
    reasons: list[str] = []
    if not cutoffs:
        return blocked(check_id, title, reasons=["No cutoffs were declared."])
    if cutoffs != sorted(set(cutoffs)):
        reasons.append("cutoffs.txt is not sorted and unique")
    if any(cutoff.day != 1 for cutoff in cutoffs):
        reasons.append("at least one cutoff is not the first day of a month")
    gaps = []
    for previous, current in zip(cutoffs, cutoffs[1:]):
        months = (current.year - previous.year) * 12 + current.month - previous.month
        if months != 1:
            gaps.append({"from": previous.isoformat(), "to": current.isoformat(), "months": months})
        if current <= previous:
            reasons.append(f"cutoff {current} does not follow {previous}")
    sources = {
        "cutoffs.txt": {c.isoformat() for c in cutoffs},
        "cvelistv5_inventory_manifest.csv": {
            row.get("cutoff_T") for row in dataset.inventory_manifest
        },
        "risk_set_denominator_summary.csv": {
            row.get("cutoff_T") for row in dataset.denominators
        },
        "outcome_and_event_reconciliation.csv": {
            row.get("cutoff_T") for row in dataset.outcomes
        },
        "point_in_time_feature_eligibility.csv": {
            row.get("cutoff_T") for row in dataset.features
        },
        "evidence/census_index.csv": {row.get("cutoff_T") for row in dataset.census},
        "evidence/epss_availability_evidence.csv": {
            row.get("cutoff_T") for row in dataset.epss_availability
        },
        "risk_set_membership/INDEX.csv": {row.get("cutoff_T") for row in dataset.index},
    }
    if dataset.inventory_manifest and dataset.denominators:
        reference = sources["cutoffs.txt"]
        for name, observed in sources.items():
            if not observed:
                continue
            if observed != reference:
                reasons.append(
                    f"{name} cutoff set differs: missing={sorted(reference - observed)}, "
                    f"extra={sorted(observed - reference)}"
                )
    spacing = [
        (current - previous).days
        for previous, current in zip(cutoffs, cutoffs[1:])
    ]
    evidence = {
        "cutoff_count": len(cutoffs),
        "first": cutoffs[0].isoformat(),
        "last": cutoffs[-1].isoformat(),
        "gaps": gaps,
        "spacing_days_min": min(spacing) if spacing else None,
        "spacing_days_max": max(spacing) if spacing else None,
        "sources": {name: len(values) for name, values in sources.items()},
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(cutoffs)} monthly cutoffs from {cutoffs[0]} to {cutoffs[-1]}; every "
            "artifact agrees and no cutoff is repeated."
        ],
        evidence=evidence,
    )


def check_kev_revision_pins(ctx: CheckContext) -> Check:
    check_id = "PRV-03_kev_revision_pins"
    title = "KEV membership is pinned to readable, removal-aware catalog revisions"
    dataset = ctx.dataset
    if not dataset.denominators:
        return blocked(check_id, title, reasons=["Denominator summary is unavailable."])
    reasons: list[str] = []
    rows = []
    max_staleness = 0
    for row in dataset.denominators:
        cutoff_text = row.get("cutoff_T", "")
        try:
            cutoff = parse_date(cutoff_text)
        except ValueError:
            reasons.append(f"{cutoff_text!r}: invalid cutoff")
            continue
        revision = str(row.get("kev_revision_sha", "")).lower()
        if not _HEX40.match(revision):
            reasons.append(f"{cutoff_text}: kev_revision_sha is not a 40-hex commit")
        try:
            instant = parse_instant(str(row.get("kev_revision_iso", "")))
        except ValueError:
            reasons.append(f"{cutoff_text}: kev revision timestamp is not ISO")
            continue
        staleness = (cutoff - instant.date()).days
        recorded = integers(row, "kev_staleness_days")
        if recorded != staleness:
            reasons.append(
                f"{cutoff_text}: recorded staleness {recorded} != recomputed {staleness}"
            )
        if staleness < 0:
            reasons.append(f"{cutoff_text}: KEV revision postdates the cutoff")
        if staleness > C.MATURITY_LAG_DAYS:
            reasons.append(
                f"{cutoff_text}: KEV revision is {staleness} days stale (> {C.MATURITY_LAG_DAYS})"
            )
        max_staleness = max(max_staleness, staleness)
        rows.append(
            {
                "cutoff": cutoff_text,
                "kev_revision_sha": revision,
                "kev_revision_iso": row.get("kev_revision_iso"),
                "staleness_days": staleness,
                "kev_entries_at_T": integers(row, "kev_entries_at_T"),
            }
        )
    summary = dataset.kev_timeline_summary
    revisions = dataset.kev_revisions
    revision_shas = {str(row.get("commit_sha", "")).lower() for row in revisions}
    additions = sum(integers(row, "added_since_previous", 0) or 0 for row in revisions)
    removals = sum(integers(row, "removed_since_previous", 0) or 0 for row in revisions)
    for key, observed in (
        ("total_additions", additions),
        ("total_removals", removals),
        ("distinct_cves_ever_listed", len(dataset.first_seen_day)),
        ("readable_revisions", len(revisions)),
    ):
        recorded = integers(summary, key)
        if recorded is not None and recorded != observed:
            reasons.append(f"kev_timeline_summary.{key}={recorded} != recomputed {observed}")
    if len(revision_shas) != len(revisions):
        reasons.append("kev_revisions.csv contains duplicate commit SHAs")
    unparseable = summary.get("unparseable_revisions", [])
    if len(unparseable) != integers(summary, "unparseable_revision_count", 0):
        reasons.append("unparseable revision count does not match the recorded list")
    evidence = {
        "cutoffs_pinned": len(rows),
        "max_staleness_days": max_staleness,
        "readable_revisions": len(revisions),
        "additions": additions,
        "removals": removals,
        "distinct_cves_ever_listed": integers(summary, "distinct_cves_ever_listed"),
        "unparseable_revisions": unparseable,
        "revision_pins": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(rows)}/{len(rows)} cutoffs pin a KEV revision (max staleness "
            f"{max_staleness} days). "
            f"Replaying {len(revisions)} revisions reproduces {additions} additions and "
            f"{removals} removals with {len(unparseable)} unparseable revision(s) recorded."
        ],
        evidence=evidence,
    )


def check_epss_retrieval_provenance(ctx: CheckContext) -> Check:
    check_id = "PRV-04_epss_retrieval_provenance"
    title = "EPSS availability is decided by commit history, not by filename date"
    dataset = ctx.dataset
    if not dataset.epss_availability:
        return blocked(check_id, title, reasons=["EPSS availability evidence is unavailable."])
    denominators = dataset.denominator_by_cutoff
    reasons: list[str] = []
    backfilled = 0
    available = 0
    matured_and_available = 0
    rows = []
    for row in dataset.epss_availability:
        cutoff_text = row.get("cutoff_T", "")
        verdict = row.get("availability_verdict")
        try:
            cutoff = parse_date(cutoff_text)
            added = parse_instant(str(row.get("file_add_commit_iso", ""))).date()
        except ValueError:
            reasons.append(f"{cutoff_text}: invalid cutoff or commit timestamp")
            continue
        if verdict == "BACKFILLED_AFTER_CUTOFF":
            backfilled += 1
            if added <= cutoff:
                reasons.append(
                    f"{cutoff_text}: marked backfilled but its commit is not after the cutoff"
                )
            if integers(row, "risk_with_epss_score") not in (None, 0):
                reasons.append(f"{cutoff_text}: backfilled row reports scores")
            if row.get("eligible_at_T") != "NO":
                reasons.append(f"{cutoff_text}: backfilled row is marked eligible")
        elif verdict == "HISTORICALLY_AVAILABLE":
            available += 1
            if added > cutoff:
                reasons.append(
                    f"{cutoff_text}: marked available but its commit is after the cutoff"
                )
            try:
                score_date = parse_date(str(row.get("epss_score_date", "")))
            except ValueError:
                reasons.append(f"{cutoff_text}: EPSS score date is not ISO")
            else:
                if score_date > cutoff:
                    reasons.append(f"{cutoff_text}: EPSS score date exceeds the cutoff")
            risk_with = integers(row, "risk_with_epss_score")
            risk_size = integers(row, "risk_set_size") or integers(
                denominators.get(cutoff_text, {}), "risk_set_size"
            )
            if risk_with is None or not risk_size or risk_with > risk_size:
                reasons.append(f"{cutoff_text}: invalid EPSS coverage count")
            denominator = denominators.get(cutoff_text, {})
            if denominator.get("matured") == "YES":
                matured_and_available += 1
        else:
            reasons.append(f"{cutoff_text}: unknown EPSS verdict {verdict!r}")
        rows.append(
            {
                "cutoff": cutoff_text,
                "verdict": verdict,
                "file_add_commit_iso": row.get("file_add_commit_iso"),
                "backfill_lag_days": integers(row, "backfill_lag_days"),
                "risk_with_epss_score": integers(row, "risk_with_epss_score"),
            }
        )
    summary = dataset.epss_summary
    if integers(summary, "cutoffs_backfilled_only") not in (None, backfilled):
        reasons.append("EPSS summary backfilled cutoff count differs")
    if integers(summary, "cutoffs_historically_available") not in (None, available):
        reasons.append("EPSS summary available cutoff count differs")
    evidence = {
        "cutoffs": len(rows),
        "backfilled_cutoffs": backfilled,
        "historically_available_cutoffs": available,
        "matured_and_available_cutoffs": matured_and_available,
        "first_same_day_evidence": summary.get("first_same_day_evidence"),
        "rows": rows,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons[:40], evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{backfilled} cutoff(s) are backfills whose file was committed after the "
            f"cutoff and are excluded; {available} cutoff(s) are historically available. "
            f"Only {matured_and_available} available cutoff is also matured."
        ],
        evidence=evidence,
    )


def check_reference_and_generation_times(ctx: CheckContext) -> Check:
    check_id = "PRV-05_reference_and_generation_times"
    title = "Reference, generation and source-observation times are coherent"
    dataset = ctx.dataset
    reasons: list[str] = []
    manifest = dataset.integrity_manifest
    generated = manifest.get("generated_utc")
    generated_date = None
    if generated:
        try:
            generated_date = parse_instant(str(generated)).date()
        except ValueError:
            reasons.append("integrity manifest generated_utc is not ISO")
    else:
        reasons.append("integrity manifest lacks generated_utc")
    if manifest.get("reference_date") and manifest.get("reference_date") != ctx.reference_date.isoformat():
        reasons.append("integrity manifest reference_date differs from the protocol")
    if dataset.quality_summary.get("reference_date") and (
        dataset.quality_summary.get("reference_date") != ctx.reference_date.isoformat()
    ):
        reasons.append("quality summary reference_date differs from the protocol")
    kev_last = dataset.source_coverage_end
    if kev_last is None:
        reasons.append("KEV timeline end is unavailable")
    elif kev_last > ctx.reference_date:
        reasons.append(
            f"KEV timeline extends past the reference date: {kev_last} > {ctx.reference_date}"
        )
    if generated_date is not None and generated_date < ctx.reference_date:
        reasons.append("artifact was generated before its reference date")
    epss_last = (dataset.epss_summary.get("file_range") or [None, None])[-1]
    evidence = {
        "reference_date": ctx.reference_date.isoformat(),
        "as_of": ctx.as_of.isoformat(),
        "artifact_generated_utc": generated,
        "artifact_generated_date": generated_date.isoformat() if generated_date else None,
        "kev_timeline_end": kev_last.isoformat() if kev_last else None,
        "kev_commit_days_span": dataset.kev_timeline_summary.get("commit_days_span"),
        "epss_latest_file": epss_last,
        "cvelistv5_clone_head": dataset.inventory_method.get("clone_head"),
        "cvelistv5_oldest_commit": dataset.inventory_method.get("oldest_commit_in_clone"),
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The artifact sealing time, protocol reference date and KEV observation "
            "timeline are consistent."
        ],
        evidence=evidence,
    )


def check_retrieval_timestamp_provenance(ctx: CheckContext) -> Check:
    check_id = "PRV-06_retrieval_timestamp_provenance"
    title = "Per-source retrieval timestamps are recorded where the artifacts claim them"
    dataset = ctx.dataset
    # The export records commit/observation timestamps and an artifact sealing
    # time.  It does not record the wall-clock time at which cvelistV5 revisions
    # were fetched.  Say so rather than inventing one.
    recorded = []
    for row in dataset.denominators[:1]:
        recorded.append(
            {
                "source": "cvelistV5",
                "field": "revision_committer_iso",
                "value": row.get("revision_committer_iso"),
                "meaning": "source commit time, not retrieval time",
            }
        )
        recorded.append(
            {
                "source": "CISA KEV",
                "field": "kev_revision_iso",
                "value": row.get("kev_revision_iso"),
                "meaning": "catalog commit time, not retrieval time",
            }
        )
    for row in dataset.epss_availability[:1]:
        recorded.append(
            {
                "source": "EPSS",
                "field": "file_add_commit_iso",
                "value": row.get("file_add_commit_iso"),
                "meaning": "file add commit time, a retrieval proxy",
            }
        )
    if dataset.integrity_manifest.get("generated_utc"):
        recorded.append(
            {
                "source": "all artifacts",
                "field": "generated_utc",
                "value": dataset.integrity_manifest.get("generated_utc"),
                "meaning": "artifact sealing time",
            }
        )
    retrieval_fields = [
        key
        for document in (
            dataset.inventory_method,
            dataset.integrity_manifest,
            dataset.quality_summary,
        )
        for key in _walk_keys(document)
        if "retriev" in key.lower() or "fetched_at" in key.lower()
    ]
    evidence = {
        "timestamps_present": recorded,
        "cvelistv5_retrieval_time_recorded": bool(retrieval_fields),
        "retrieval_fields_found": sorted(set(retrieval_fields)),
        "consequence": (
            "Revision pins and commit times are verifiable, but the exact retrieval time "
            "of each cvelistV5 revision is not recorded in these artifacts."
        ),
    }
    if retrieval_fields:
        return passed(check_id, title, evidence=evidence)
    return blocked(
        check_id,
        title,
        reasons=[
            "CVELISTV5_RETRIEVAL_TIMESTAMP_NOT_RECORDED: revision committer timestamps "
            "and the artifact sealing time exist, but the fetch time of each pinned "
            "revision does not. This does not invalidate the revision pin; it limits "
            "retrieval-time provenance."
        ],
        evidence=evidence,
        blocking=False,
    )


def _walk_keys(value, prefix: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _walk_keys(item, prefix)
    elif isinstance(value, list):
        for item in value[:5]:
            yield from _walk_keys(item, prefix)


def check_unavailable_sources_declared(ctx: CheckContext) -> Check:
    check_id = "PRV-07_unavailable_sources_declared"
    title = "Unavailable sources remain declared as unavailable, not reconstructed"
    dataset = ctx.dataset
    limitations = dataset.quality_summary.get("limitations", [])
    text = " ".join(str(item) for item in limitations)
    report = dataset.report_text
    phrases = ("2.3F", "2.3G", "UNAVAILABLE")
    declared = all(phrase in text or phrase in report for phrase in phrases)
    reasons = []
    if not declared:
        reasons.append("The 2.3F/2.3G unavailability is not clearly declared.")
    evidence = {
        "declared_limitation": next(
            (item for item in limitations if "2.3F" in str(item) or "2.3G" in str(item)),
            None,
        ),
        "report_mentions_unavailable": "UNAVAILABLE" in report,
        "quality_summary_limitations": limitations,
        "reconstruction_attempted": False,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            "The unavailable Phase 2.3F/2.3G sources are carried as historical claims "
            "only; nothing was reconstructed from a filename or digest."
        ],
        evidence=evidence,
    )


def check_input_digests(ctx: CheckContext) -> Check:
    check_id = "REP-01_input_digests"
    title = "Every consumed input is identified by a SHA-256 digest"
    if not ctx.input_fingerprints:
        return blocked(check_id, title, reasons=["No input fingerprints were recorded."])
    reasons = []
    for record in ctx.input_fingerprints:
        if not _HEX64.match(str(record.get("sha256", ""))):
            reasons.append(f"{record.get('path')}: invalid digest")
        if not record.get("bytes"):
            reasons.append(f"{record.get('path')}: zero bytes")
    evidence = {
        "files_hashed": len(ctx.input_fingerprints),
        "total_bytes": sum(record["bytes"] for record in ctx.input_fingerprints),
        "files": ctx.input_fingerprints,
        "archives": ctx.archive_results,
    }
    if reasons:
        return failed(check_id, title, reasons=reasons, evidence=evidence)
    return passed(
        check_id,
        title,
        reasons=[
            f"{len(ctx.input_fingerprints)} consumed files plus "
            f"{len(ctx.archive_results)} archive(s) are pinned by SHA-256."
        ],
        evidence=evidence,
    )


def check_previous_report_digest(ctx: CheckContext) -> Check:
    check_id = "REP-02_previous_report_digest"
    title = "A supplied previous report re-hashes to its recorded digest"
    previous = ctx.previous_report
    if previous is None:
        return not_applicable(
            check_id,
            title,
            reasons=["No previous report was supplied."],
            blocking=False,
        )
    from .report import canonical_digest

    recorded = previous.get("report_digest")
    recomputed = canonical_digest(previous)
    evidence = {
        "recorded_digest": recorded,
        "recomputed_digest": recomputed,
        "match": recorded == recomputed,
    }
    if recorded != recomputed:
        return failed(
            check_id,
            title,
            reasons=["Previous report content does not match its recorded digest."],
            evidence=evidence,
        )
    return passed(
        check_id,
        title,
        reasons=["The previous report's digest is self-consistent."],
        evidence=evidence,
    )
