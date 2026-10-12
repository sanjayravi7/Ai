"""Synthetic tests for the rejected-CVE audit and the status-aware ranking.

No test contacts the network: CVE status, KEV, and EPSS inputs are local
fixtures written with the same writers the pipeline uses.
"""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.audit_rejected_cves import build_audit_frames, main, run_audit
from src.fetch_cve_status import MissingStatusSnapshotError, write_status_snapshot
from src.fetch_threat_intelligence import import_local_snapshot
from src.threat_intel_sources import EPSS_SOURCE, KEV_SOURCE

from tests.cve_status_fixtures import (
    reject_summary_marker,
    status_records,
    synthetic_dataset,
    write_dataset,
)
from tests.threat_intel_fixtures import KEV_ENTRY_STRUCT, kev_document


EXPECTED_REVIEWED = [
    "CVE-2020-0001",
    "CVE-2020-0004",
    "CVE-2020-0002",
    "CVE-2020-0008",
    "CVE-2020-0006",
    "CVE-2020-0005",
    "CVE-2020-0007",
]
EXPECTED_BASELINE = [
    "CVE-2020-0001",
    "CVE-2020-0004",
    "CVE-2020-0002",
    "CVE-2020-0008",
    "CVE-2020-0003",
    "CVE-2020-0005",
    "CVE-2020-0009",
    "CVE-2020-0006",
    "CVE-2020-0007",
]


def build_epss_payload(rows):
    lines = [
        "#model_version:test-model,score_date:2021-11-03T12:00:00Z",
        "cve,epss,percentile",
    ]
    lines.extend(f"{cve},{score},{percentile}" for cve, score, percentile in rows)
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_kev_payload(entries):
    document = json.loads(kev_document(entries=entries).decode("utf-8"))
    return json.dumps(document).encode("utf-8")


class AuditHarness(unittest.TestCase):
    """Shared temporary workspace with dataset, status, KEV, and EPSS fixtures."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.dataset_path = write_dataset(self.root / "clean.csv")
        self.status_root = self.root / "snapshots"
        self.status_manifest = write_status_snapshot(
            status_records(),
            commit_sha="a" * 40,
            retrieval_method="https_download",
            root=self.status_root,
        )

    def write_sources(self):
        kev_entry = dict(KEV_ENTRY_STRUCT)
        kev_entry["cveID"] = "CVE-2020-0001"
        kev_path = self.root / "kev.json"
        kev_path.write_bytes(build_kev_payload([kev_entry]))
        import_local_snapshot(
            KEV_SOURCE, kev_path, origin_url="https://example.test/kev", root=self.status_root
        )
        epss_path = self.root / "epss.csv"
        epss_path.write_bytes(
            build_epss_payload(
                [
                    ("CVE-2020-0001", "0.50000", "0.90000"),
                    ("CVE-2020-0003", "0.01000", "0.30000"),
                    ("CVE-2020-0006", "0.20000", "0.70000"),
                ]
            )
        )
        import_local_snapshot(
            EPSS_SOURCE, epss_path, origin_url="https://example.test/epss", root=self.status_root
        )

    def _run_audit(self, **overrides):
        parameters = {
            "audit_path": self.root / "audit.csv",
            "reviewed_path": self.root / "reviewed.csv",
            "summary_path": self.root / "summary.json",
            "disputed_path": self.root / "disputed.csv",
            "baseline_ranked_path": None,
            "status_root": self.status_root,
            "snapshot_root": self.status_root,
            "allow_missing_sources": True,
        }
        parameters.update(overrides)
        self.summary = run_audit(self.dataset_path, **parameters)
        self.audit = pd.read_csv(parameters["audit_path"], dtype=str, keep_default_na=False)
        self.reviewed = pd.read_csv(parameters["reviewed_path"], dtype=str, keep_default_na=False)
        self.disputed = pd.read_csv(parameters["disputed_path"], dtype=str, keep_default_na=False)
        self.summary_file = Path(parameters["summary_path"])
        return self.summary


class RejectedRecordDetectionTests(AuditHarness):
    def test_marker_detection_and_audit_table_contents(self):
        self._run_audit(allow_missing_sources=True, status_manifest=Path(self.status_manifest["_manifest_path"]))
        self.assertEqual(sorted(self.audit["cve_id"].tolist()), sorted(
            ["CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005", "CVE-2020-0009"]
        ))
        rejected = self.audit.set_index("cve_id")
        row = rejected.loc["CVE-2020-0003"]
        self.assertEqual(row["record_status"], "REJECTED")
        self.assertEqual(row["source_cvss"], "5.0")
        self.assertEqual(row["cvss_genuine"], "False")
        self.assertEqual(row["consult_ids"], "CVE-2019-0003")
        self.assertEqual(row["authoritative_state"], "REJECTED")
        self.assertEqual(row["date_rejected"], "2022-10-03T00:00:00Z")
        self.assertEqual(row["verification_date_utc"], self.summary["verification"]["verification_date_utc"])
        self.assertEqual(row["verification_source"], "CVEProject/cvelistV5@" + "a" * 12)
        self.assertIn("github.com/CVEProject/cvelistV5/blob/" + "a" * 40, row["source_url"])
        self.assertIn("cves/2020/0xxx/CVE-2020-0003.json", row["source_url"])

    def test_non_marker_records_are_not_in_the_audit_table(self):
        self._run_audit(allow_missing_sources=True)
        self.assertNotIn("CVE-2020-0001", self.audit["cve_id"].tolist())
        self.assertNotIn("CVE-2020-0006", self.audit["cve_id"].tolist())


class RankingPolicyTests(AuditHarness):
    def test_rejected_records_are_excluded_from_the_primary_ranking(self):
        self._run_audit(allow_missing_sources=True)
        self.assertEqual(self.reviewed["cve_id"].tolist(), EXPECTED_REVIEWED)
        self.assertEqual(self.reviewed["reviewed_rank"].tolist(), [str(i) for i in range(1, 8)])
        self.assertNotIn("CVE-2020-0003", self.reviewed["cve_id"].tolist())
        self.assertNotIn("CVE-2020-0009", self.reviewed["cve_id"].tolist())

        counts = self.summary["counts"]
        self.assertEqual(counts["rows_input"], 9)
        self.assertEqual(counts["reject_placeholder_rows"], 4)
        self.assertEqual(counts["verified_rejected_rows"], 1)
        self.assertEqual(counts["reinstated_rows"], 2)
        self.assertEqual(counts["unverified_rows"], 1)
        self.assertEqual(counts["eligible_ranking_rows"], 7)
        self.assertEqual(counts["excluded_rows"], 2)
        self.assertEqual(counts["excluded_confirmed_rejected"], 1)
        self.assertEqual(counts["excluded_unverified"], 1)
        self.assertEqual(counts["rows_accounted_for"], 9)

    def test_placeholders_are_preserved_in_the_audit_output(self):
        self._run_audit(allow_missing_sources=True)
        counts = self.summary["counts"]
        self.assertEqual(counts["audited_rows"], 4)
        self.assertEqual(len(self.audit), 4)
        record = self.summary["rejected_records"][0]
        self.assertEqual(record["cve_id"], "CVE-2020-0003")
        self.assertEqual(record["baseline_rank"], 5)
        self.assertIn("CVE-2019-0003", record["consult_ids"])
        self.assertTrue(record["source_url"])
        written = self.summary_file.read_text(encoding="utf-8")
        self.assertIn("CVE-2020-0003", written)

    def test_reinstated_records_stay_eligible(self):
        self._run_audit(allow_missing_sources=True)
        reinstated = self.audit.set_index("cve_id")
        self.assertEqual(reinstated.loc["CVE-2020-0004", "record_status"], "REINSTATED")
        self.assertEqual(reinstated.loc["CVE-2020-0004", "ranking_eligible"], "True")
        self.assertEqual(reinstated.loc["CVE-2020-0004", "score_used_for_ranking"], "snapshot_cvss")
        self.assertEqual(reinstated.loc["CVE-2020-0004", "authoritative_state"], "PUBLISHED")
        # The authoritative base score is disclosed but never substituted.
        self.assertEqual(reinstated.loc["CVE-2020-0004", "authoritative_cvss"], "cvssV3_1=8.4")

        ranked = self.reviewed.set_index("cve_id")
        self.assertEqual(ranked.loc["CVE-2020-0004", "reviewed_rank"], "2")

    def test_reinstated_record_with_the_placeholder_value_ranks_last(self):
        self._run_audit(allow_missing_sources=True)
        reinstated = self.audit.set_index("cve_id")
        self.assertEqual(reinstated.loc["CVE-2020-0005", "record_status"], "REINSTATED")
        self.assertEqual(
            reinstated.loc["CVE-2020-0005", "score_used_for_ranking"], "none_missing_score"
        )
        self.assertEqual(
            reinstated.loc["CVE-2020-0005", "score_note"],
            "placeholder_value_unconfirmed_for_reinstated_record",
        )
        self.assertIn("CVE-2020-0005", self.reviewed["cve_id"].tolist())
        ranked = self.reviewed.set_index("cve_id")
        # 5.0 equals the derived placeholder value, so the record is ranked last
        # instead of competing with genuine scores.
        self.assertEqual(ranked.loc["CVE-2020-0005", "reviewed_rank"], "6")
        self.assertEqual(ranked.loc["CVE-2020-0005", "score_used_for_ranking"], "none_missing_score")

    def test_placeholder_values_are_derived_from_the_data_not_assumed(self):
        frame = synthetic_dataset()
        frame.loc[frame["cve_id"] == "CVE-2020-0003", "cvss"] = "7.0"
        test_root = self.root / "derived"
        test_root.mkdir()
        dataset_path = write_dataset(test_root / "clean.csv", frame)
        summary = run_audit(
            dataset_path,
            audit_path=test_root / "audit.csv",
            reviewed_path=test_root / "reviewed.csv",
            summary_path=test_root / "summary.json",
            disputed_path=test_root / "disputed.csv",
            baseline_ranked_path=None,
            status_root=self.status_root,
            snapshot_root=self.status_root,
            allow_missing_sources=True,
        )
        self.assertEqual(summary["placeholder_score_values"], [7.0])
        reviewed = pd.read_csv(test_root / "reviewed.csv", dtype=str, keep_default_na=False)
        ranked = reviewed.set_index("cve_id")
        # 5.0 is no longer a confirmed placeholder value, so the reinstated
        # record keeps its snapshot score of 5.0.
        self.assertEqual(ranked.loc["CVE-2020-0005", "score_used_for_ranking"], "snapshot_cvss")
        self.assertEqual(ranked.loc["CVE-2020-0005", "reviewed_rank"], "5")

    def test_unverified_records_are_excluded_and_disclosed(self):
        self._run_audit(allow_missing_sources=True)
        self.assertEqual(self.summary["unverified_records"][0]["cve_id"], "CVE-2020-0009")
        self.assertEqual(
            self.summary["unverified_records"][0]["ranking_decision"], "excluded_unverified_status"
        )
        row = self.audit.set_index("cve_id").loc["CVE-2020-0009"]
        self.assertEqual(row["record_status"], "UNVERIFIED")
        self.assertEqual(row["status_reason"], "no_authoritative_record_available")
        self.assertEqual(row["exclusion_reason"], "unverified_status")
        self.assertEqual(row["authoritative_record_present"], "False")

    def test_include_unverified_keeps_them_at_the_bottom(self):
        self._run_audit(allow_missing_sources=True, include_unverified=True)
        self.assertIn("CVE-2020-0009", self.reviewed["cve_id"].tolist())
        ranked = self.reviewed.set_index("cve_id")
        self.assertEqual(ranked.loc["CVE-2020-0009", "score_used_for_ranking"], "none_missing_score")
        self.assertEqual(ranked.loc["CVE-2020-0009", "score_note"], "unverified_status_score_not_used")
        self.assertEqual(ranked.loc["CVE-2020-0009", "reviewed_rank"], "8")
        self.assertEqual(self.summary["counts"]["excluded_unverified"], 0)
        self.assertTrue(self.summary["policy"]["include_unverified"])

    def test_disputed_records_are_reported_and_treatment_is_unchanged(self):
        self._run_audit(allow_missing_sources=True)
        self.assertEqual(self.disputed["cve_id"].tolist(), ["CVE-2020-0006"])
        row = self.disputed.iloc[0]
        self.assertEqual(row["record_status"], "UNMARKED")
        self.assertEqual(row["ranking_eligible"], "True")
        self.assertEqual(row["cvss"], "4.3")
        self.assertIn("unchanged", row["policy_note"])
        ranked = self.reviewed.set_index("cve_id")
        self.assertEqual(ranked.loc["CVE-2020-0006", "cvss"], "4.3")
        self.assertEqual(ranked.loc["CVE-2020-0006", "reviewed_rank"], "5")
        self.assertEqual(self.summary["disputed"]["marker_rows"], 1)
        self.assertIn("unchanged", self.summary["disputed"]["policy"])

    def test_ranking_is_cvss_descending_with_deterministic_tie_breaks(self):
        self._run_audit(allow_missing_sources=True)
        ranked = self.reviewed.set_index("cve_id")
        self.assertEqual(ranked.loc["CVE-2020-0002", "reviewed_rank"], "3")
        self.assertEqual(ranked.loc["CVE-2020-0008", "reviewed_rank"], "4")
        self.assertEqual(ranked.loc["CVE-2020-0007", "reviewed_rank"], "7")
        self.assertEqual(ranked.loc["CVE-2020-0001", "cvss"], "9.8")

        shift = self.summary["baseline_comparison"]["rank_shift"]
        self.assertEqual(shift["max_shift_positions"], 3)
        self.assertEqual(shift["first_affected_baseline_rank"], 8)
        top = self.summary["baseline_comparison"]["levels"][0]
        self.assertFalse(top["identical"])
        self.assertEqual(top["first_differing_rank"], 5)
        self.assertEqual(
            self.summary["baseline_comparison"]["reviewed_top_records"][0]["cve_id"],
            "CVE-2020-0001",
        )

    def test_missing_and_invalid_cvss_values(self):
        self._run_audit(allow_missing_sources=True)
        self.assertEqual(self.reviewed["cve_id"].tolist()[-1], "CVE-2020-0007")
        self.assertEqual(self.summary["counts"]["eligible_ranking_rows"], 7)

        broken = synthetic_dataset()
        broken.loc[broken["cve_id"] == "CVE-2020-0001", "cvss"] = "unknown"
        test_root = self.root / "invalid"
        test_root.mkdir()
        dataset_path = write_dataset(test_root / "clean.csv", broken)
        with self.assertRaisesRegex(ValueError, "non-numeric"):
            run_audit(
                dataset_path,
                audit_path=test_root / "audit.csv",
                reviewed_path=test_root / "reviewed.csv",
                summary_path=test_root / "summary.json",
                disputed_path=test_root / "disputed.csv",
                baseline_ranked_path=None,
                status_root=self.status_root,
                snapshot_root=self.status_root,
                allow_missing_sources=True,
            )


class SafetyAndReproducibilityTests(AuditHarness):
    def test_original_data_is_never_modified(self):
        frame = synthetic_dataset()
        before_frame = frame.copy(deep=True)
        dataset_path = write_dataset(self.root / "frozen.csv", frame)
        before_bytes = dataset_path.read_bytes()

        build_audit_frames(
            frame,
            status_records=None,
            status_manifest=None,
            include_unverified=False,
        )
        pd.testing.assert_frame_equal(frame, before_frame)

        run_audit(
            dataset_path,
            audit_path=self.root / "a.csv",
            reviewed_path=self.root / "r.csv",
            summary_path=self.root / "s.json",
            disputed_path=self.root / "d.csv",
            baseline_ranked_path=None,
            status_root=self.status_root,
            snapshot_root=self.status_root,
            allow_missing_sources=True,
        )
        self.assertEqual(hashlib.sha256(before_bytes).hexdigest(), hashlib.sha256(dataset_path.read_bytes()).hexdigest())

    def test_outputs_cannot_overwrite_the_input(self):
        with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
            run_audit(
                self.dataset_path,
                audit_path=self.root / "audit.csv",
                reviewed_path=self.dataset_path,
                summary_path=self.root / "summary.json",
                disputed_path=self.root / "disputed.csv",
                baseline_ranked_path=None,
                status_root=self.status_root,
                snapshot_root=self.status_root,
                allow_missing_sources=True,
            )

    def test_outputs_are_reproducible_byte_for_byte(self):
        self._run_audit(allow_missing_sources=True)
        first_root = self.root / "run1"
        first_root.mkdir()
        first = {name: (first_root / name) for name in ("audit.csv", "reviewed.csv", "summary.json", "disputed.csv")}
        first_summary = run_audit(
            self.dataset_path,
            audit_path=first["audit.csv"],
            reviewed_path=first["reviewed.csv"],
            summary_path=first["summary.json"],
            disputed_path=first["disputed.csv"],
            baseline_ranked_path=None,
            status_root=self.status_root,
            snapshot_root=self.status_root,
            allow_missing_sources=True,
        )
        second_root = self.root / "run2"
        second_root.mkdir()
        second = {name: (second_root / name) for name in ("audit.csv", "reviewed.csv", "summary.json", "disputed.csv")}
        second_summary = run_audit(
            self.dataset_path,
            audit_path=second["audit.csv"],
            reviewed_path=second["reviewed.csv"],
            summary_path=second["summary.json"],
            disputed_path=second["disputed.csv"],
            baseline_ranked_path=None,
            status_root=self.status_root,
            snapshot_root=self.status_root,
            allow_missing_sources=True,
        )
        # The only difference between the two runs is where the files live.
        self.assertEqual(
            json.dumps(first_summary, sort_keys=True).replace(str(first_root), ""),
            json.dumps(second_summary, sort_keys=True).replace(str(second_root), ""),
        )
        self.assertEqual(first_summary["counts"], second_summary["counts"])
        for name in ("audit.csv", "reviewed.csv", "disputed.csv"):
            self.assertEqual(
                hashlib.sha256(first[name].read_bytes()).hexdigest(),
                hashlib.sha256(second[name].read_bytes()).hexdigest(),
                f"{name} differs between runs",
            )
        # The summary embeds the output paths, so compare it after normalizing
        # them; every other byte must match.
        self.assertEqual(
            first["summary.json"].read_text(encoding="utf-8").replace(str(first_root), ""),
            second["summary.json"].read_text(encoding="utf-8").replace(str(second_root), ""),
        )
        self.assertEqual(
            second_summary["outputs"]["sha256"]["reviewed"],
            hashlib.sha256(second["reviewed.csv"].read_bytes()).hexdigest(),
        )
        self.assertNotIn("generated_at", json.dumps(second_summary))

    def test_missing_status_snapshot_is_an_error_unless_allowed(self):
        empty_root = self.root / "empty"
        empty_root.mkdir()
        with self.assertRaises(MissingStatusSnapshotError):
            run_audit(
                self.dataset_path,
                audit_path=self.root / "a.csv",
                reviewed_path=self.root / "r.csv",
                summary_path=self.root / "s.json",
                disputed_path=self.root / "d.csv",
                baseline_ranked_path=None,
                status_root=empty_root,
                snapshot_root=empty_root,
                allow_missing_sources=True,
            )

        summary = run_audit(
            self.dataset_path,
            audit_path=self.root / "a2.csv",
            reviewed_path=self.root / "r2.csv",
            summary_path=self.root / "s2.json",
            disputed_path=self.root / "d2.csv",
            baseline_ranked_path=None,
            status_root=empty_root,
            snapshot_root=empty_root,
            allow_missing_sources=True,
            allow_missing_status_source=True,
        )
        self.assertEqual(summary["verification"]["status"], "not_ingested")
        self.assertEqual(summary["counts"]["unverified_rows"], 4)
        self.assertEqual(summary["counts"]["verified_rejected_rows"], 0)
        self.assertEqual(summary["counts"]["excluded_unverified"], 4)
        self.assertEqual(summary["counts"]["eligible_ranking_rows"], 5)
        audit = pd.read_csv(self.root / "a2.csv", dtype=str, keep_default_na=False)
        self.assertEqual(audit.loc[audit["cve_id"] == "CVE-2020-0003", "status_reason"].iloc[0],
                         "no_authoritative_record_available")
        self.assertTrue(
            all(row["record_status"] == "UNVERIFIED" for _, row in audit.iterrows())
        )
        # Nothing about an unverifiable record's score can be confirmed.
        self.assertTrue(all(row["cvss_genuine"] == "False" for _, row in audit.iterrows()))
        self.assertEqual(summary["placeholder_score_values"], [])

    def test_threat_intel_columns_are_joined_when_snapshots_exist(self):
        self.write_sources()
        self._run_audit(allow_missing_sources=False, include_unverified=True)
        row = self.audit.set_index("cve_id").loc["CVE-2020-0003"]
        self.assertEqual(row["kev_listed"], "False")
        self.assertEqual(row["epss_matched"], "True")
        self.assertEqual(row["epss_score"], "0.01")
        ranked = self.reviewed.set_index("cve_id")
        self.assertEqual(ranked.loc["CVE-2020-0001", "record_status"], "UNMARKED")
        # Unchecked rows say so; only verified rows name the source.
        self.assertEqual(ranked.loc["CVE-2020-0001", "status_source"], "not_checked")
        self.assertEqual(
            self.audit.set_index("cve_id").loc["CVE-2020-0003", "verification_source"],
            "CVEProject/cvelistV5@" + "a" * 12,
        )
        self.assertEqual(self.summary["sources"]["kev"], "2026.10.08")
        self.assertEqual(self.summary["sources"]["epss"], "test-model")

    def test_missing_threat_intel_sources_are_reported_not_faked(self):
        self._run_audit(allow_missing_sources=True)
        self.assertEqual(self.summary["sources"]["kev"], "not_ingested")
        self.assertEqual(self.audit["kev_listed"].str.strip().eq("").all(), True)
        self.assertEqual(self.audit["epss_matched"].str.strip().eq("").all(), True)
        with self.assertRaisesRegex(Exception, "snapshot"):
            run_audit(
                self.dataset_path,
                audit_path=self.root / "x.csv",
                reviewed_path=self.root / "y.csv",
                summary_path=self.root / "z.json",
                disputed_path=self.root / "w.csv",
                baseline_ranked_path=None,
                status_root=self.status_root,
                snapshot_root=self.status_root,
                allow_missing_sources=False,
            )

    def test_dataset_without_markers_ranks_every_row(self):
        frame = synthetic_dataset()
        keep = ~frame["summary"].str.startswith("** REJECT **")
        frame = frame.loc[keep].reset_index(drop=True)
        test_root = self.root / "nomarkers"
        test_root.mkdir()
        dataset_path = write_dataset(test_root / "clean.csv", frame)
        summary = run_audit(
            dataset_path,
            audit_path=test_root / "audit.csv",
            reviewed_path=test_root / "reviewed.csv",
            summary_path=test_root / "summary.json",
            disputed_path=test_root / "disputed.csv",
            baseline_ranked_path=None,
            status_root=self.status_root,
            snapshot_root=self.status_root,
            allow_missing_sources=True,
        )
        self.assertEqual(summary["counts"]["reject_placeholder_rows"], 0)
        self.assertEqual(summary["counts"]["eligible_ranking_rows"], len(frame))
        self.assertEqual(summary["rejected_records"], [])
        self.assertEqual(summary["unverified_records"], [])
        self.assertTrue(all(level["identical"] for level in summary["baseline_comparison"]["levels"]))

    def test_baseline_file_is_compared_when_present(self):
        from src.baseline import rank_by_cvss

        baseline_path = self.root / "baseline.csv"
        rank_by_cvss(
            pd.read_csv(self.dataset_path, dtype=str, keep_default_na=False)[["cve_id", "cvss"]],
        ).to_csv(baseline_path, index=False)
        self._run_audit(allow_missing_sources=True, baseline_ranked_path=baseline_path)
        comparison = self.summary["baseline_comparison"]
        self.assertTrue(comparison["baseline_file_matches_recomputed_baseline"])
        self.assertEqual(comparison["baseline_rows"], 9)
        self.assertEqual(comparison["reviewed_rows"], 7)
        self.assertEqual(comparison["baseline_top_records"][0]["cve_id"], "CVE-2020-0001")


class CliTests(AuditHarness):
    def test_cli_runs_the_audit_and_reports_counts(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            exit_code = main(
                [
                    "--input",
                    str(self.dataset_path),
                    "--audit-output",
                    str(self.root / "cli_audit.csv"),
                    "--reviewed-output",
                    str(self.root / "cli_reviewed.csv"),
                    "--summary-output",
                    str(self.root / "cli_summary.json"),
                    "--disputed-output",
                    str(self.root / "cli_disputed.csv"),
                    "--status-root",
                    str(self.status_root),
                    "--snapshot-root",
                    str(self.status_root),
                    "--allow-missing-sources",
                ]
            )
        self.assertEqual(exit_code, 0)
        printed = buffer.getvalue()
        self.assertIn("verified rejected=1, reinstated=2, unverified=1", printed)
        self.assertIn("7 eligible of 9", printed)
        summary = json.loads((self.root / "cli_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["counts"]["excluded_rows"], 2)
        self.assertTrue((self.root / "cli_audit.csv").is_file())

    def test_cli_reports_a_missing_status_snapshot(self):
        empty_root = self.root / "empty_cli"
        empty_root.mkdir()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            exit_code = main(
                [
                    "--input",
                    str(self.dataset_path),
                    "--audit-output",
                    str(self.root / "bad_audit.csv"),
                    "--reviewed-output",
                    str(self.root / "bad_reviewed.csv"),
                    "--summary-output",
                    str(self.root / "bad_summary.json"),
                    "--disputed-output",
                    str(self.root / "bad_disputed.csv"),
                    "--status-root",
                    str(empty_root),
                    "--snapshot-root",
                    str(empty_root),
                    "--allow-missing-sources",
                ]
            )
        self.assertEqual(exit_code, 1)
        self.assertIn("ERROR", buffer.getvalue())
        self.assertFalse((self.root / "bad_reviewed.csv").exists())


class MarkerAuditReportingTests(AuditHarness):
    def test_marker_audit_discloses_every_variant(self):
        frame = synthetic_dataset()
        extra = pd.DataFrame(
            [
                {
                    "cve_id": "CVE-2020-0010",
                    "cvss": "3.3",
                    "summary": "   " + reject_summary_marker() + " DO NOT USE THIS CANDIDATE NUMBER.",
                },
                {
                    "cve_id": "CVE-2020-0011",
                    "cvss": "3.3",
                    "summary": "The word reject appears here but not as a marker.",
                },
            ]
        )
        frame = pd.concat([frame, extra], ignore_index=True)
        test_root = self.root / "markers"
        test_root.mkdir()
        dataset_path = write_dataset(test_root / "clean.csv", frame)
        summary = run_audit(
            dataset_path,
            audit_path=test_root / "audit.csv",
            reviewed_path=test_root / "reviewed.csv",
            summary_path=test_root / "summary.json",
            disputed_path=test_root / "disputed.csv",
            baseline_ranked_path=None,
            status_root=self.status_root,
            snapshot_root=self.status_root,
            allow_missing_sources=True,
        )
        markers = summary["marker_audit"]
        self.assertEqual(markers["rows"], 11)
        self.assertEqual(markers["reject_exact_prefix"], 4)
        self.assertEqual(markers["reject_prefix_after_leading_whitespace"], 1)
        self.assertEqual(markers["disputed_marker_present"], 1)
        self.assertEqual(summary["counts"]["reject_placeholder_rows"], 5)

    def test_policy_block_is_explicit_and_complete(self):
        self._run_audit(allow_missing_sources=True)
        policy = self.summary["policy"]
        for key in (
            "marker_rule",
            "verified_rejected",
            "verified_reinstated",
            "unverified",
            "unmarked_records",
            "disputed_records",
            "placeholder_values",
            "baseline_unchanged",
            "include_unverified",
        ):
            self.assertIn(key, policy)
        self.assertEqual(policy["placeholder_values"], ["5.0"])
        self.assertIn("Excluded", policy["verified_rejected"])
        self.assertTrue(self.summary["limitations"])


if __name__ == "__main__":
    unittest.main()
