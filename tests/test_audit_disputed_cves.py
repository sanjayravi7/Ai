"""Synthetic end-to-end tests for the Phase 2.2 disputed-CVE audit.

No test contacts the network. The dataset, the authoritative CVE snapshot, the
KEV snapshot, and the Phase 2.1 inputs are all local fixtures written with the
same writers the pipeline uses, so the tests exercise the real parsing,
checksum, classification, and ranking-sensitivity code paths.
"""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.audit_disputed_cves import (
    KEV_STATUS_MATCHED,
    KEV_STATUS_NOT_LISTED,
    KEV_STATUS_UNAVAILABLE,
    REFERENCE_BASELINE,
    REFERENCE_REVIEWED,
    SCENARIO_CURRENT,
    SCENARIO_EVIDENCE_EXCLUSION,
    SCENARIO_FLAG_ONLY,
    SCENARIO_MARKER_ONLY,
    build_sensitivity,
    load_disputed_records,
    main,
    read_ranked_ids,
    run_audit,
    scenario_exclusions,
)
from src.baseline import create_baseline
from src.cve_status_sources import CveStatusValidationError
from src.disputed_evidence import (
    CLASS_CONTRADICTED,
    CLASS_DISPUTE_TAG,
    CLASS_DISPUTE_TEXT,
    CLASS_NONE,
    CLASS_NON_FINAL,
    CLASS_SILENT,
    CLASS_WITHDRAWN,
    EXCLUSION_NOT_EVALUABLE,
    EXCLUSION_NOT_SUPPORTED,
    EXCLUSION_SUPPORTED,
    RETRIEVAL_FAILED,
    RETRIEVAL_MALFORMED,
    RETRIEVAL_NOT_ATTEMPTED,
    RETRIEVAL_NOT_FOUND,
    RETRIEVAL_RETRIEVED,
)
from src.fetch_cve_status import write_status_snapshot
from src.fetch_threat_intelligence import import_local_snapshot, sha256_bytes, sha256_file
from src.threat_intel_sources import EPSS_SOURCE, KEV_SOURCE

from tests.cve_status_fixtures import cve_record
from tests.disputed_fixtures import (
    PIPELINE_COMMIT,
    cve_5x_record,
    record_bytes,
    synthetic_dataset,
    write_dataset,
    write_disputed_snapshot,
    write_phase21_audit,
    write_phase21_disputed_report,
)
from tests.threat_intel_fixtures import KEV_ENTRY_STRUCT, kev_document

GENERATED = "2026-10-12T00:00:00Z"
DISPUTED_IDS = ["CVE-2020-1001", "CVE-2020-1002", "CVE-2020-1003", "CVE-2020-1004",
                "CVE-2020-1005", "CVE-2020-1006", "CVE-2020-1007", "CVE-2020-1008"]
#: Full baseline order of the fixture dataset (12 rows).
EXPECTED_BASELINE_ORDER = [
    "CVE-2020-1007",
    "CVE-2020-1001",
    "CVE-2020-1003",
    "CVE-2020-1009",
    "CVE-2020-1002",
    "CVE-2020-1010",
    "CVE-2020-1004",
    "CVE-2020-1011",
    "CVE-2020-1006",
    "CVE-2020-1008",
    "CVE-2020-1005",
    "CVE-2020-1012",
]
#: The same order restricted to the disputed rows the evidence table holds.
EXPECTED_DISPUTED_BY_RANK = [
    cve_id for cve_id in EXPECTED_BASELINE_ORDER if cve_id in set(DISPUTED_IDS)
]


def build_epss_payload(rows):
    lines = ["#model_version:test-model,score_date:2026-10-11T12:00:00Z", "cve,epss,percentile"]
    lines.extend(f"{cve},{score},{percentile}" for cve, score, percentile in rows)
    return ("\n".join(lines) + "\n").encode("utf-8")


def malformed_record_mutation(manifest_path, directory):
    """Rewrite one record file (and its checksum) so its identifier mismatches."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    entry = manifest["records"]["CVE-2020-1008"]
    payload = json.dumps(cve_5x_record("CVE-2020-9999")).encode("utf-8")
    (Path(directory) / entry["file"]).write_bytes(payload)
    entry["sha256"] = sha256_bytes(payload)
    Path(manifest_path).write_text(json.dumps(manifest), encoding="utf-8")


class AuditHarness(unittest.TestCase):
    """Shared fixture tree for the audit tests."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.snapshot_root = self.root / "external"
        self.dataset_path = write_dataset(self.root / "clean.csv")
        self.dataset = pd.read_csv(self.dataset_path, dtype=str, keep_default_na=False)

        ranked, _ = create_baseline(self.dataset)
        self.baseline_path = self.root / "baseline.csv"
        ranked.to_csv(self.baseline_path, index=False, na_rep="")
        self.reviewed_path = self.root / "reviewed.csv"
        ranked.rename(columns={"baseline_rank": "reviewed_rank"}).to_csv(
            self.reviewed_path, index=False, na_rep=""
        )

        self.phase21_report = write_phase21_disputed_report(self.root / "phase21_disputed_report.csv")
        self.phase21_audit = write_phase21_audit(self.root / "phase21_audit.csv", scores=("5.0",))

        records = dict(
            {
                "CVE-2020-1001": record_bytes(cve_5x_record(
                    "CVE-2020-1001",
                    descriptions=[
                        "Example widget firmware does not validate updates.  NOTE: third parties dispute "
                        "the relevance of this because the device must already be configured for debug access."
                    ],
                    tags=["disputed"],
                    references=[("https://example.test/advisory/1", ["vendor-advisory"])],
                )),
                "CVE-2020-1002": record_bytes(cve_5x_record(
                    "CVE-2020-1002",
                    descriptions=["Example portal allows command execution through an administrative interface."],
                    tags=["disputed"],
                )),
                "CVE-2020-1003": record_bytes(cve_5x_record(
                    "CVE-2020-1003",
                    state="REJECTED",
                    descriptions=[],
                    rejected_reasons=[
                        "DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: CVE-2019-9000.  Reason: This "
                        "candidate is a duplicate of CVE-2019-9000."
                    ],
                    date_rejected="2022-10-03T00:00:00.000Z",
                )),
                "CVE-2020-1004": record_bytes(cve_5x_record(
                    "CVE-2020-1004", descriptions=["Example service accepts unsigned messages."], tags=[]
                )),
                "CVE-2020-1006": record_bytes(cve_5x_record(
                    "CVE-2020-1006", state="RESERVED", descriptions=[], tags=[]
                )),
                "CVE-2020-1007": record_bytes(cve_5x_record(
                    "CVE-2020-1007",
                    descriptions=[
                        "Example daemon allows memory exhaustion.  NOTE: the dispute has been resolved and "
                        "the record is no longer disputed."
                    ],
                    tags=[],
                )),
                "CVE-2020-1008": record_bytes(cve_5x_record(
                    "CVE-2020-1008", descriptions=["Example daemon mishandles malformed headers."], tags=[]
                )),
            }
        )
        write_disputed_snapshot(
            self.snapshot_root,
            records=records,
            missing=("CVE-2020-1005",),
            mutate=malformed_record_mutation,
        )
        self.write_sources()

    def write_sources(self):
        kev_entry = dict(KEV_ENTRY_STRUCT)
        kev_entry["cveID"] = "CVE-2020-1001"
        kev_path = self.root / "kev.json"
        kev_path.write_bytes(kev_document([kev_entry]))
        import_local_snapshot(KEV_SOURCE, kev_path, origin_url="https://example.test/kev", root=self.snapshot_root)

        epss_path = self.root / "epss.csv"
        epss_path.write_bytes(build_epss_payload([("CVE-2020-1002", "0.42000", "0.91000")]))
        import_local_snapshot(EPSS_SOURCE, epss_path, origin_url="https://example.test/epss", root=self.snapshot_root)

    def run_audit(self, **overrides):
        parameters = {
            "clean_path": self.dataset_path,
            "baseline_ranked_path": self.baseline_path,
            "reviewed_ranked_path": self.reviewed_path,
            "disputed_root": self.snapshot_root,
            "snapshot_root": self.snapshot_root,
            "audit_path": self.root / "evidence_audit.csv",
            "impact_path": self.root / "impact.csv",
            "review_queue_path": self.root / "review_queue.csv",
            "sensitivity_path": self.root / "sensitivity.csv",
            "summary_path": self.root / "summary.json",
            "manifest_path": self.root / "source_manifest.json",
            "phase21_disputed_report": self.phase21_report,
            "phase21_audit_path": self.phase21_audit,
            "generated_utc": GENERATED,
        }
        parameters.update(overrides)
        result = run_audit(**parameters)
        self.paths = parameters
        return result


class EvidenceAuditTests(AuditHarness):
    def test_every_disputed_record_is_audited_with_original_fields(self):
        result = self.run_audit()
        audit = result["audit"]
        self.assertEqual(len(audit), 8)
        self.assertEqual(sorted(audit["cve_id"]), sorted(DISPUTED_IDS))
        row = audit.set_index("cve_id").loc["CVE-2020-1001"]
        self.assertEqual(row["summary"], self.dataset.set_index("cve_id").loc["CVE-2020-1001", "summary"])
        self.assertEqual(row["dataset_cvss_snapshot"], "9.8")
        self.assertEqual(row["cvss"], "9.8")
        self.assertEqual(row["mod_date"], "2019-11-20 00:00:00")
        self.assertEqual(row["baseline_rank"], 2)
        self.assertEqual(row["baseline_band"], "TOP_100")
        self.assertEqual(row["reviewed_rank_current_policy"], 2)
        self.assertEqual(row["disputed_marker_at_start"], "True")
        self.assertEqual(row["official_record_state"], "PUBLISHED")
        self.assertEqual(
            row["official_source_commit"], PIPELINE_COMMIT
        )
        self.assertEqual(row["official_reference_bodies_retrieved"], "False")
        self.assertEqual(row["official_record_advisory_reference_count"], 1)
        self.assertIn("example.test", row["official_record_reference_hosts"])

    def test_evidence_classification_matrix(self):
        audit = self.run_audit()["audit"].set_index("cve_id")
        expected = {
            "CVE-2020-1001": (CLASS_DISPUTE_TEXT, "SUFFICIENT", "HIGH", "OPEN_DISPUTE_DOCUMENTED", "NOT_SUPPORTED"),
            "CVE-2020-1002": (CLASS_DISPUTE_TAG, "SUFFICIENT", "MEDIUM", "OPEN_DISPUTE_DOCUMENTED", "NOT_SUPPORTED"),
            "CVE-2020-1003": (CLASS_WITHDRAWN, "SUFFICIENT", "HIGH", "RESOLVED_WITHDRAWN", "SUPPORTED"),
            "CVE-2020-1004": (CLASS_SILENT, "INSUFFICIENT", "LOW", "UNRESOLVED_NO_DISPUTE_SIGNAL", "NOT_SUPPORTED"),
            "CVE-2020-1005": (CLASS_NONE, "NOT_VERIFIABLE", "NONE", "NOT_VERIFIABLE", "NOT_EVALUABLE"),
            "CVE-2020-1006": (CLASS_NON_FINAL, "INSUFFICIENT", "LOW", "UNRESOLVED_NON_FINAL_STATE", "NOT_SUPPORTED"),
            "CVE-2020-1007": (CLASS_CONTRADICTED, "CONTRADICTORY", "HIGH", "RESOLVED_DISPUTE_CONTRADICTED", "NOT_SUPPORTED"),
            "CVE-2020-1008": (CLASS_NONE, "NOT_VERIFIABLE", "NONE", "NOT_VERIFIABLE", "NOT_EVALUABLE"),
        }
        for cve_id, (classification, status, confidence, resolution, exclusion) in expected.items():
            self.assertEqual(audit.loc[cve_id, "evidence_classification"], classification, msg=cve_id)
            self.assertEqual(audit.loc[cve_id, "evidence_status"], status, msg=cve_id)
            self.assertEqual(audit.loc[cve_id, "evidence_confidence"], confidence, msg=cve_id)
            self.assertEqual(audit.loc[cve_id, "dispute_resolution"], resolution, msg=cve_id)
            self.assertEqual(audit.loc[cve_id, "exclusion_evidence"], exclusion, msg=cve_id)

    def test_retrieval_status_distinguishes_missing_malformed_and_missing_verdict(self):
        audit = self.run_audit()["audit"].set_index("cve_id")
        self.assertEqual(audit.loc["CVE-2020-1001", "official_record_retrieval_status"], RETRIEVAL_RETRIEVED)
        self.assertEqual(audit.loc["CVE-2020-1005", "official_record_retrieval_status"], RETRIEVAL_NOT_FOUND)
        self.assertEqual(audit.loc["CVE-2020-1008", "official_record_retrieval_status"], RETRIEVAL_MALFORMED)
        self.assertEqual(audit.loc["CVE-2020-1005", "official_lookup_attempted"], "True")
        self.assertIn("malformed_record", audit.loc["CVE-2020-1008", "official_record_failure_reason"])

    def test_record_not_in_the_manifest_is_reported_as_not_attempted(self):
        # A snapshot that simply does not mention CVE-2020-1008 must not be read
        # as evidence about it.
        write_disputed_snapshot(
            self.root / "partial",
            records={"CVE-2020-1001": record_bytes(cve_5x_record("CVE-2020-1001", tags=["disputed"]))},
            missing=(),
        )
        result = self.run_audit(disputed_root=self.root / "partial")
        row = result["audit"].set_index("cve_id").loc["CVE-2020-1008"]
        self.assertEqual(row["official_lookup_attempted"], "False")
        self.assertEqual(row["evidence_status"], "NOT_VERIFIABLE")

    def test_withdrawn_record_keeps_its_replacement_and_reason(self):
        audit = self.run_audit()["audit"].set_index("cve_id")
        row = audit.loc["CVE-2020-1003"]
        self.assertEqual(row["replacement_related_cve_ids"], "CVE-2019-9000")
        self.assertIn("DO NOT USE THIS CANDIDATE NUMBER", row["authoritative_rationale"])
        self.assertEqual(row["authoritative_rationale_status"], "RECORDED")
        self.assertEqual(row["cvss_genuine"], "False")
        self.assertEqual(row["cvss_note"], "withdrawn_identifier_score_not_a_severity")

    def test_placeholder_match_is_disclosed_not_assumed(self):
        result = self.run_audit()
        audit = result["audit"].set_index("cve_id")
        self.assertEqual(audit.loc["CVE-2020-1005", "cvss_placeholder_suspect"], "True")
        self.assertEqual(audit.loc["CVE-2020-1005", "cvss_genuine"], "False")
        self.assertEqual(audit.loc["CVE-2020-1001", "cvss_placeholder_suspect"], "False")
        self.assertEqual(result["summary"]["cvss_placeholder_values_reference"]["values"], [5.0])

    def test_placeholder_values_are_unavailable_without_the_phase_21_audit(self):
        result = self.run_audit(phase21_audit_path=None)
        self.assertEqual(result["summary"]["cvss_placeholder_values_reference"]["values"], [])
        self.assertIn("unavailable", result["summary"]["cvss_placeholder_values_reference"]["source"])

    def test_kev_and_epss_matches_carry_snapshot_dates(self):
        audit = self.run_audit()["audit"].set_index("cve_id")
        self.assertEqual(audit.loc["CVE-2020-1001", "kev_snapshot_status"], KEV_STATUS_MATCHED)
        self.assertEqual(audit.loc["CVE-2020-1002", "kev_snapshot_status"], KEV_STATUS_NOT_LISTED)
        self.assertIn("not evidence that it was never exploited", audit.loc["CVE-2020-1002", "exploitation_evidence_note"])
        self.assertEqual(audit.loc["CVE-2020-1002", "epss_snapshot_status"], KEV_STATUS_MATCHED)
        self.assertEqual(audit.loc["CVE-2020-1001", "epss_snapshot_status"], KEV_STATUS_NOT_LISTED)
        self.assertIn("not historical evidence", audit.loc["CVE-2020-1002", "exploitation_evidence_note"])

    def test_missing_sources_are_unavailable_not_negative(self):
        empty_root = self.root / "empty"
        empty_root.mkdir()
        result = self.run_audit(snapshot_root=empty_root, allow_missing_sources=True)
        audit = result["audit"]
        self.assertTrue(audit["kev_snapshot_status"].eq(KEV_STATUS_UNAVAILABLE).all())
        self.assertTrue(audit["epss_snapshot_status"].eq(KEV_STATUS_UNAVAILABLE).all())
        self.assertIn("unknown, not negative", audit.iloc[0]["exploitation_evidence_note"])
        self.assertFalse(result["summary"]["kev_evidence"]["snapshot_available"])
        self.assertEqual(result["summary"]["epss_evidence"]["matched"], 0)

    def test_review_queue_priorities(self):
        result = self.run_audit()
        queue = result["review_queue"].set_index("cve_id")
        self.assertEqual(len(queue), 8)
        self.assertEqual(queue.loc["CVE-2020-1007", "human_review_priority"], "P1_high_ranked_evidence_gap")
        self.assertEqual(queue.loc["CVE-2020-1003", "human_review_priority"], "P1_high_ranked_evidence_gap")
        self.assertEqual(queue.loc["CVE-2020-1001", "human_review_priority"], "P2_high_ranked_open_dispute")
        self.assertEqual(result["summary"]["review_priorities"]["P1_high_ranked_evidence_gap"], 6)
        self.assertEqual(result["summary"]["review_priorities"]["P2_high_ranked_open_dispute"], 2)


class RankingSensitivityTests(AuditHarness):
    def test_current_policy_is_unchanged(self):
        result = self.run_audit()
        audit = result["audit"]
        ordered = audit.assign(__rank=pd.to_numeric(audit["baseline_rank"])).sort_values("__rank")
        self.assertEqual(ordered["cve_id"].tolist(), EXPECTED_DISPUTED_BY_RANK)
        self.assertEqual(
            pd.to_numeric(ordered["baseline_rank"]).tolist(), sorted(pd.to_numeric(audit["baseline_rank"]).tolist())
        )
        self.assertTrue(audit["exclusion_evidence"].ne(EXCLUSION_SUPPORTED).sum() == 7)
        sensitivity = result["sensitivity"]
        current = sensitivity[
            sensitivity["scenario"].eq(SCENARIO_CURRENT)
            & sensitivity["reference_ranking"].eq(REFERENCE_REVIEWED)
            & sensitivity["level"].eq("100")
        ].iloc[0]
        self.assertEqual(int(current["records_excluded_by_scenario"]), 0)
        self.assertEqual(int(current["positions_changed_count"]), 0)
        self.assertEqual(current["evidence_justified"], "True")
        self.assertFalse(result["summary"]["ranking_policy_changed"])

    def test_evidence_supported_exclusion_removes_only_withdrawn_records(self):
        result = self.run_audit()
        row = result["sensitivity"][
            result["sensitivity"]["scenario"].eq(SCENARIO_EVIDENCE_EXCLUSION)
            & result["sensitivity"]["reference_ranking"].eq(REFERENCE_REVIEWED)
            & result["sensitivity"]["level"].eq("100")
        ].iloc[0]
        self.assertEqual(int(row["records_excluded_by_scenario"]), 1)
        self.assertEqual(row["ids_removed_from_top"], "CVE-2020-1003")
        self.assertEqual(int(row["first_position_changed"]), 3)
        self.assertEqual(int(row["positions_changed_count"]), 10)
        self.assertEqual(int(row["max_abs_rank_shift_within_head"]), 1)

    def test_flag_only_scenario_changes_no_rank(self):
        result = self.run_audit()
        row = result["sensitivity"][
            result["sensitivity"]["scenario"].eq(SCENARIO_FLAG_ONLY)
            & result["sensitivity"]["reference_ranking"].eq(REFERENCE_REVIEWED)
            & result["sensitivity"]["level"].eq("100")
        ].iloc[0]
        self.assertEqual(int(row["records_excluded_by_scenario"]), 0)
        self.assertEqual(int(row["records_flagged_for_review"]), 8)
        self.assertEqual(int(row["positions_changed_count"]), 0)
        self.assertEqual(row["evidence_justified"], "True")

    def test_marker_only_scenario_is_measured_and_labelled_unjustified(self):
        result = self.run_audit()
        row = result["sensitivity"][
            result["sensitivity"]["scenario"].eq(SCENARIO_MARKER_ONLY)
            & result["sensitivity"]["reference_ranking"].eq(REFERENCE_REVIEWED)
            & result["sensitivity"]["level"].eq("100")
        ].iloc[0]
        self.assertEqual(int(row["records_excluded_by_scenario"]), 8)
        self.assertEqual(int(row["disputed_records_removed_from_head"]), 8)
        self.assertEqual(int(row["first_position_changed"]), 1)
        self.assertEqual(int(row["max_abs_rank_shift_within_head"]), 8)
        self.assertEqual(row["max_rank_shift_cve"], "CVE-2020-1012")
        self.assertEqual(row["evidence_justified"], "False")
        self.assertIn("NOT evidence-justified", row["scenario_justification"])

    def test_scenario_exclusions_never_use_the_marker_alone(self):
        audit = self.run_audit()["audit"]
        evidence_excluded, flagged = scenario_exclusions(audit, SCENARIO_EVIDENCE_EXCLUSION)
        self.assertEqual(evidence_excluded, {"CVE-2020-1003"})
        self.assertEqual(flagged, set())
        _excluded, flagged_only = scenario_exclusions(audit, SCENARIO_FLAG_ONLY)
        self.assertEqual(len(flagged_only), 8)
        with self.assertRaises(ValueError):
            scenario_exclusions(audit, "S9_UNKNOWN")

    def test_scenario_ranking_uses_the_unmodified_ranking_rule(self):
        audit = self.run_audit()["audit"]
        reference = read_ranked_ids(self.reviewed_path, "reviewed_rank")
        frame, details = build_sensitivity(
            {REFERENCE_REVIEWED: reference}, audit, levels=(100,)
        )
        self.assertEqual(sorted(details), sorted(
            [SCENARIO_CURRENT, SCENARIO_EVIDENCE_EXCLUSION, SCENARIO_FLAG_ONLY, SCENARIO_MARKER_ONLY]
        ))
        self.assertEqual(len(frame), 8)
        self.assertEqual(set(frame["reference_ranking"]), {REFERENCE_REVIEWED})
        self.assertEqual(set(frame["level"]), {"100", "full"})


class ReproducibilityAndIntegrityTests(AuditHarness):
    def test_repeated_runs_are_byte_identical(self):
        first = self.run_audit()
        first_bytes = {
            "audit": (self.root / "evidence_audit.csv").read_bytes(),
            "impact": (self.root / "impact.csv").read_bytes(),
            "queue": (self.root / "review_queue.csv").read_bytes(),
            "sensitivity": (self.root / "sensitivity.csv").read_bytes(),
            "summary": (self.root / "summary.json").read_bytes(),
            "manifest": (self.root / "source_manifest.json").read_bytes(),
        }
        second = self.run_audit()
        for key, path in (
            ("audit", self.root / "evidence_audit.csv"),
            ("impact", self.root / "impact.csv"),
            ("queue", self.root / "review_queue.csv"),
            ("sensitivity", self.root / "sensitivity.csv"),
            ("summary", self.root / "summary.json"),
            ("manifest", self.root / "source_manifest.json"),
        ):
            self.assertEqual(first_bytes[key], path.read_bytes(), msg=key)
        self.assertEqual(
            first["summary"]["records"], second["summary"]["records"]
        )

    def test_snapshot_checksum_mismatch_is_refused(self):
        directory = self.snapshot_root / "cve_status"
        manifest_path = sorted(directory.glob("*.manifest.json"))[-1]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entry = manifest["records"]["CVE-2020-1001"]
        target = directory / entry["file"]
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaises(CveStatusValidationError):
            self.run_audit()

    def test_missing_snapshot_is_reported_with_instructions(self):
        with self.assertRaises(FileNotFoundError) as context:
            load_disputed_records(self.root / "absent")
        self.assertIn("fetch_disputed_status", str(context.exception))

    def test_phase_21_disputed_report_is_preserved_byte_for_byte(self):
        before = sha256_file(self.phase21_report)
        result = self.run_audit()
        self.assertEqual(before, sha256_file(self.phase21_report))
        verification = result["summary"]["ranking_verification"]
        self.assertTrue(verification["phase21_disputed_report_preserved"])
        self.assertEqual(verification["phase21_disputed_report_sha256_before"], before)
        self.assertEqual(result["source_manifest"]["phase21_disputed_report"]["sha256"], before)

    def test_ranking_verification_reports_recomputation(self):
        result = self.run_audit()
        verification = result["summary"]["ranking_verification"]["baseline"]
        self.assertTrue(verification["ranks_reproduced"])
        self.assertTrue(verification["matches_clean_dataset"])
        self.assertTrue(result["summary"]["ranking_verification"]["reviewed"]["ranks_reproduced"])
        self.assertEqual(
            result["summary"]["ranking_verification"]["snapshot_records_verified"], 6
        )

    def test_stored_baseline_that_does_not_reproduce_is_disclosed(self):
        tampered = pd.read_csv(self.baseline_path, dtype=str, keep_default_na=False)
        tampered = tampered.iloc[::-1].reset_index(drop=True)
        tampered_path = self.root / "tampered_baseline.csv"
        tampered.to_csv(tampered_path, index=False, na_rep="")
        result = self.run_audit(baseline_ranked_path=tampered_path)
        verification = result["summary"]["ranking_verification"]["baseline"]
        self.assertFalse(verification["ranks_reproduced"])
        self.assertIn("differs from a fresh recomputation", verification["note"])

    def test_both_sources_missing_fails_closed_unless_allowed(self):
        from src.enrich_vulnerabilities import MissingSnapshotError

        empty_root = self.root / "empty_fail_closed"
        empty_root.mkdir()
        with self.assertRaises(MissingSnapshotError):
            self.run_audit(snapshot_root=empty_root, write=False)

    def test_raw_dataset_and_archive_state_is_recorded(self):
        result = self.run_audit()
        state = result["summary"]["ranking_verification"]["raw_dataset_untouched"]
        self.assertIn("raw_csv", state)
        self.assertIn("archive", state)
        self.assertEqual(state["raw_csv"]["path"], "data/raw/vulnerabilities.csv")

    def test_outputs_are_configurable_and_no_write_skips_files(self):
        result = self.run_audit(
            write=False,
            audit_path=self.root / "never_written.csv",
        )
        self.assertFalse((self.root / "never_written.csv").exists())
        self.assertEqual(len(result["audit"]), 8)


class CommandLineTests(AuditHarness):
    def test_cli_refuses_to_overwrite_the_phase_21_report(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(
                [
                    "--input",
                    str(self.dataset_path),
                    "--baseline-ranked",
                    str(self.baseline_path),
                    "--reviewed-ranked",
                    str(self.reviewed_path),
                    "--disputed-root",
                    str(self.snapshot_root),
                    "--snapshot-root",
                    str(self.snapshot_root),
                    "--phase21-disputed-report",
                    str(self.phase21_report),
                    "--audit-output",
                    str(self.phase21_report),
                ]
            )
        self.assertEqual(code, 2)

    def test_cli_writes_every_artifact(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--input",
                    str(self.dataset_path),
                    "--baseline-ranked",
                    str(self.baseline_path),
                    "--reviewed-ranked",
                    str(self.reviewed_path),
                    "--disputed-root",
                    str(self.snapshot_root),
                    "--snapshot-root",
                    str(self.snapshot_root),
                    "--phase21-disputed-report",
                    str(self.phase21_report),
                    "--phase21-audit",
                    str(self.phase21_audit),
                    "--audit-output",
                    str(self.root / "out_audit.csv"),
                    "--impact-output",
                    str(self.root / "out_impact.csv"),
                    "--review-queue-output",
                    str(self.root / "out_queue.csv"),
                    "--sensitivity-output",
                    str(self.root / "out_sensitivity.csv"),
                    "--summary-output",
                    str(self.root / "out_summary.json"),
                    "--manifest-output",
                    str(self.root / "out_manifest.json"),
                    "--generated-utc",
                    GENERATED,
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("Current policy unchanged", output.getvalue())
        for name in ("out_audit.csv", "out_impact.csv", "out_queue.csv", "out_sensitivity.csv"):
            self.assertTrue((self.root / name).is_file(), msg=name)
        summary = json.loads((self.root / "out_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["records"]["audited"], 8)
        self.assertFalse(summary["ranking_policy_changed"])

    def test_cli_reports_a_missing_snapshot(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--input",
                    str(self.dataset_path),
                    "--baseline-ranked",
                    str(self.baseline_path),
                    "--disputed-root",
                    str(self.root / "absent"),
                    "--snapshot-root",
                    str(self.snapshot_root),
                    "--allow-missing-sources",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("ERROR", output.getvalue())


if __name__ == "__main__":
    unittest.main()
