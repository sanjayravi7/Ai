"""The complete readiness check suite, in report order."""

from __future__ import annotations

from typing import Callable

from .checks_base import Check, CheckContext
from .checks_evidence import (
    check_already_in_kev_exclusion,
    check_approval_state,
    check_cvss_point_in_time,
    check_epss_point_in_time,
    check_evidence_classification,
    check_missingness_preserved,
    check_no_future_information,
    check_no_silent_adoption,
    check_prohibitions_respected,
    check_protocol_constants,
    check_protocol_document,
    check_publication_rule,
    check_traceability,
)
from .checks_integrity import (
    check_archive_digests,
    check_core_bundle_manifest,
    check_cutoff_grid,
    check_denominator_reconciliation,
    check_epss_retrieval_provenance,
    check_export_member_manifest,
    check_full_export_manifest,
    check_input_digests,
    check_inventory_census_consistency,
    check_kev_revision_pins,
    check_membership_partition_checksums,
    check_membership_row_accounting,
    check_previous_report_digest,
    check_reference_and_generation_times,
    check_retrieval_timestamp_provenance,
    check_source_revision_pins,
    check_unavailable_sources_declared,
)
from .checks_temporal import (
    check_candidate_design_sequence,
    check_censored_cutoffs_not_gated,
    check_distinct_event_gate,
    check_earliest_three_block_design,
    check_event_membership_at_cutoff,
    check_event_reuse,
    check_event_row_uniqueness,
    check_event_window_boundaries,
    check_frozen_constants,
    check_gate_not_relaxed,
    check_kev_removal_awareness,
    check_label_window_observability,
    check_maturity_dates,
    check_two_block_design,
)

CHECK_FUNCTIONS: tuple[Callable[[CheckContext], Check], ...] = (
    # Dataset and artifact integrity
    check_archive_digests,
    check_core_bundle_manifest,
    check_full_export_manifest,
    check_export_member_manifest,
    check_membership_partition_checksums,
    check_membership_row_accounting,
    check_inventory_census_consistency,
    check_denominator_reconciliation,
    # Provenance
    check_source_revision_pins,
    check_cutoff_grid,
    check_kev_revision_pins,
    check_epss_retrieval_provenance,
    check_reference_and_generation_times,
    check_retrieval_timestamp_provenance,
    check_unavailable_sources_declared,
    # Temporal boundaries
    check_frozen_constants,
    check_maturity_dates,
    check_candidate_design_sequence,
    check_earliest_three_block_design,
    check_two_block_design,
    check_gate_not_relaxed,
    check_label_window_observability,
    # Events
    check_distinct_event_gate,
    check_event_row_uniqueness,
    check_event_window_boundaries,
    check_event_membership_at_cutoff,
    check_event_reuse,
    check_censored_cutoffs_not_gated,
    check_kev_removal_awareness,
    # Features and leakage
    check_cvss_point_in_time,
    check_epss_point_in_time,
    check_publication_rule,
    check_already_in_kev_exclusion,
    check_missingness_preserved,
    check_no_future_information,
    check_evidence_classification,
    # Protocol
    check_protocol_document,
    check_approval_state,
    check_no_silent_adoption,
    check_protocol_constants,
    check_traceability,
    # Report integrity
    check_input_digests,
    check_previous_report_digest,
    check_prohibitions_respected,
)


def run_checks(ctx: CheckContext) -> list[Check]:
    checks = [function(ctx) for function in CHECK_FUNCTIONS]
    ids = [check.id for check in checks]
    if len(ids) != len(set(ids)):
        raise AssertionError("duplicate check ids in the readiness suite")
    return checks


CHECK_IDS = tuple(
    [
        "INT-01_archive_digests",
        "INT-02_core_bundle_manifest",
        "INT-03_full_export_integrity_manifest",
        "INT-04_export_member_manifest",
        "INT-05_membership_partition_checksums",
        "INT-06_membership_row_accounting",
        "INT-07_inventory_census_consistency",
        "INT-08_denominator_reconciliation",
        "PRV-01_source_revision_pins",
        "PRV-02_cutoff_grid",
        "PRV-03_kev_revision_pins",
        "PRV-04_epss_retrieval_provenance",
        "PRV-05_reference_and_generation_times",
        "PRV-06_retrieval_timestamp_provenance",
        "PRV-07_unavailable_sources_declared",
        "TMP-01_frozen_constants",
        "TMP-02_maturity_dates_recomputed",
        "TMP-03_candidate_design_sequence",
        "TMP-04_earliest_three_block_design",
        "TMP-05_two_block_design_not_adopted",
        "TMP-06_event_gate_not_relaxed",
        "TMP-07_label_window_observability",
        "EVT-01_distinct_event_gate",
        "EVT-02_event_row_uniqueness",
        "EVT-03_event_window_boundaries",
        "EVT-04_event_membership_at_cutoff",
        "EVT-05_event_reuse_and_independence",
        "EVT-06_censored_cutoffs_not_gated",
        "EVT-07_kev_removal_awareness",
        "LKG-01_cvss_point_in_time",
        "LKG-02_epss_point_in_time",
        "LKG-03_publication_rule",
        "LKG-04_already_in_kev_exclusion",
        "LKG-05_missingness_preserved",
        "LKG-06_no_future_information",
        "LKG-07_evidence_classification_preserved",
        "PRO-01_protocol_document",
        "PRO-02_approval_state_explicit",
        "PRO-03_no_silent_design_adoption",
        "PRO-04_protocol_binding_constants",
        "PRO-05_requirement_traceability",
        "REP-01_input_digests",
        "REP-02_previous_report_digest",
        "REP-03_prohibitions_respected",
    ]
)
