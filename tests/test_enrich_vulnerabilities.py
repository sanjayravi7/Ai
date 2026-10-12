"""Synthetic tests for KEV/EPSS joins, coverage accounting, and reproducibility.

The clean dataset fixture mirrors the schema of data/processed/vulnerabilities_clean.csv
with a handful of rows. Snapshots are built from the same validated fixtures used
by the parser tests, and no test contacts a live service.
"""

import gzip
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.enrich_vulnerabilities import (
    MissingSnapshotError,
    enrich_dataset,
    read_clean_dataset,
    run_enrichment,
)
from src.fetch_threat_intelligence import import_local_snapshot
from src.threat_intel_sources import parse_epss_csv, parse_kev_json
from tests.threat_intel_fixtures import (
    EPSS_REAL_EXCERPT,
    KEV_ENTRY_STRUCT,
    kev_document,
    second_kev_entry,
)


NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
CLEAN_COLUMNS = [
    "cve_id", "mod_date", "pub_date", "cvss", "cwe_code", "cwe_name", "summary",
    "access_authentication", "access_complexity", "access_vector",
    "impact_availability", "impact_confidentiality", "impact_integrity",
]


def clean_dataset_frame():
    """Six rows: one KEV match, one EPSS match, one both, one unmatched, a blank field."""
    rows = [
        # KEV match (CVE-2016-3081 is in the synthetic KEV fixture), no EPSS.
        ["CVE-2016-3081", "2016-06-01 00:00:00", "2016-05-02 10:00:00", "9.3", "77", "Command injection",
         "Struts command injection.", "NONE", "MEDIUM", "NETWORK", "COMPLETE", "COMPLETE", "COMPLETE"],
        # EPSS match only (CVE-1999-0016 has a real EPSS score in the excerpt).
        ["CVE-1999-0016", "2019-01-01 00:00:00", "1999-03-01 00:00:00", "7.5", "20", "Input validation",
         "Legacy issue.", "NONE", "LOW", "NETWORK", "PARTIAL", "PARTIAL", "PARTIAL"],
        # Unmatched by every source.
        ["CVE-2010-0001", "2010-02-01 00:00:00", "2010-01-15 00:00:00", "", "", "", "No score.",
         "", "", "", "", "", ""],
        # Ordinary record with no threat-intelligence match.
        ["CVE-2018-1000", "2018-03-01 00:00:00", "2018-02-01 00:00:00", "5.0", "119", "Bounds",
         "Bounds issue.", "NONE", "LOW", "LOCAL", "NONE", "NONE", "NONE"],
        # Duplicate dataset identifier: both rows must survive the join.
        ["CVE-1999-0016", "2019-02-01 00:00:00", "1999-03-01 00:00:00", "7.5", "20", "Input validation",
         "Duplicate listing in dataset.", "NONE", "LOW", "NETWORK", "PARTIAL", "PARTIAL", "PARTIAL"],
        # Blank-heavy row: missing dates, score, and access fields are kept as blanks.
        ["CVE-2019-9999", "", "2019-11-01 00:00:00", "", "", "", "", "", "", "", "", "", ""],
    ]
    return pd.DataFrame(rows, columns=CLEAN_COLUMNS, dtype=str)


def write_clean(path: Path, frame: pd.DataFrame):
    frame.to_csv(path, index=False, na_rep="")
    return path


def epss_gzip_payload():
    return gzip.compress(EPSS_REAL_EXCERPT)


class EnrichDatasetTests(unittest.TestCase):
    def setUp(self):
        self.dataset = clean_dataset_frame()
        self.kev = parse_kev_json(kev_document([dict(KEV_ENTRY_STRUCT), second_kev_entry()]))
        self.epss = parse_epss_csv(EPSS_REAL_EXCERPT)

    def test_preserves_every_row_and_original_columns_verbatim(self):
        original = self.dataset.copy(deep=True)
        enriched, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)

        self.assertEqual(len(enriched), len(self.dataset))
        self.assertEqual(report["join"]["rows_preserved"], True)
        self.assertEqual(report["join"]["rows_dropped"], 0)
        for column in CLEAN_COLUMNS:
            self.assertEqual(enriched[column].tolist(), original[column].tolist(), column)
        pd.testing.assert_frame_equal(self.dataset, original)

    def test_ti_fields_are_prefixed_and_unmatched_rows_are_blank_not_negative(self):
        enriched, _ = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        ti_columns = [c for c in enriched.columns if c.startswith("ti_")]
        self.assertTrue(ti_columns)
        self.assertFalse(any(c in CLEAN_COLUMNS for c in ti_columns))

        unmatched = enriched[enriched["cve_id"] == "CVE-2010-0001"].iloc[0]
        self.assertEqual(unmatched["ti_kev_listed"], "False")
        self.assertEqual(unmatched["ti_epss_matched"], "False")
        self.assertEqual(unmatched["ti_kev_date_added"], "")
        self.assertEqual(unmatched["ti_epss_score"], "")

    def test_kev_match_fields_are_joined_by_normalized_identifier(self):
        enriched, _ = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        row = enriched[enriched["cve_id"] == "CVE-2016-3081"].iloc[0]
        self.assertEqual(row["ti_kev_listed"], "True")
        self.assertEqual(row["ti_kev_vendor_project"], "Apache")
        self.assertEqual(row["ti_kev_date_added"], "2026-10-08")
        self.assertEqual(row["ti_kev_due_date"], "2026-10-11")
        self.assertEqual(row["ti_kev_known_ransomware_campaign_use"], "Unknown")
        self.assertEqual(row["ti_kev_snapshot_date"], "2026-10-08")

    def test_epss_scores_are_joined_and_documented_with_model_version(self):
        enriched, _ = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        rows = enriched[enriched["cve_id"] == "CVE-1999-0016"]
        self.assertEqual(len(rows), 2, "duplicate dataset identifiers must both be preserved")
        for _, row in rows.iterrows():
            self.assertEqual(row["ti_epss_matched"], "True")
            self.assertEqual(row["ti_epss_score"], "0.95667")
            self.assertEqual(row["ti_epss_model_version"], "v2026.06.15")
            self.assertEqual(row["ti_epss_snapshot_date"], "2026-10-11")

    def test_coverage_report_counts_are_correct(self):
        _, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        coverage = report["coverage"]

        self.assertEqual(coverage["dataset_rows"], 6)
        self.assertEqual(coverage["dataset_unique_cves"], 5)
        self.assertEqual(report["dataset"]["duplicate_cve_id_count"], 1)
        self.assertEqual(report["dataset"]["duplicate_cve_id_rows"], 2)

        kev = coverage["kev"]
        self.assertEqual(kev["dataset_rows_listed"], 1)
        self.assertEqual(kev["dataset_unique_cves_listed"], 1)
        self.assertEqual(kev["catalog_entries_not_in_dataset"], 1)  # CVE-2015-5477
        self.assertEqual(kev["listed_ransomware_campaign_use"], {"Unknown": 1})

        epss = coverage["epss"]
        self.assertEqual(epss["dataset_rows_matched"], 2)
        self.assertEqual(epss["dataset_unique_cves_matched"], 1)
        self.assertEqual(epss["catalog_entries_not_in_dataset"], 3)

    def test_lag_between_publication_and_kev_addition_is_computed(self):
        _, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        lag = report["coverage"]["kev"]["lag_days_kev_date_added_minus_pub_date"]
        expected = (pd.Timestamp("2026-10-08") - pd.Timestamp("2016-05-02")).days
        self.assertEqual(lag["count"], 1)
        self.assertEqual(lag["median"], float(expected))
        self.assertEqual(lag["negative_lag_count"], 0)

    def test_reports_reject_placeholders_and_breaks_down_unmatched_rows(self):
        dataset = self.dataset.copy()
        dataset.loc[2, "summary"] = "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER."
        dataset.loc[2, "cvss"] = "5.0"
        _, report = enrich_dataset(dataset, kev=self.kev, epss=self.epss)
        quality = report["coverage"]["data_quality"]
        self.assertEqual(quality["reject_placeholder_rows"], 1)
        self.assertEqual(quality["reject_placeholder_cvss_values"], {"5.0": 1})
        epss = report["coverage"]["epss"]
        self.assertEqual(epss["dataset_rows_unmatched_reject_placeholders"], 1)
        # Unmatched non-placeholder rows: CVE-2016-3081, CVE-2018-1000, CVE-2019-9999.
        self.assertEqual(epss["dataset_rows_unmatched_other"], 3)

    def test_temporal_feasibility_and_dateadded_concentration_are_counted(self):
        _, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        rows = report["coverage"]["temporal_label_feasibility"]["rows"]
        self.assertEqual(len(rows), 8)  # 4 as-of dates x 2 horizons
        # Both fixture KEV entries were added in 2026, after every as-of date and its 365-day window.
        self.assertTrue(all(row["positive_cves"] == 0 for row in rows))
        self.assertTrue(all(row["eligible_cves"] == 6 for row in rows))

        concentration = report["coverage"]["kev"]["dateadded_concentration"]
        self.assertEqual(concentration["earliest_date_added"], "2026-10-08")
        self.assertEqual(concentration["catalog_entries_on_earliest_date"], 2)
        self.assertEqual(concentration["dataset_rows_listed_on_earliest_date"], 1)

    def test_temporal_feasibility_requires_kev(self):
        _, report = enrich_dataset(self.dataset, kev=None, epss=self.epss)
        self.assertEqual(report["coverage"]["temporal_label_feasibility"], {"status": "not_ingested"})

    def test_cvss_ranking_diagnostic_uses_fixed_ordering_without_training(self):
        _, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        diagnostic = report["coverage"]["kev"]["cvss_ranking_diagnostic"]
        # Scored rows: 9.3 (listed), 7.5, 5.0, 7.5 -> 4 rows; 1 positive, 3 unlabelled.
        self.assertEqual(diagnostic["scored_rows"], 4)
        self.assertEqual(diagnostic["listed_positive_rows"], 1)
        self.assertEqual(diagnostic["unlabelled_rows"], 3)
        self.assertTrue(diagnostic["not_a_model_evaluation"])
        # The only positive has the highest CVSS, so it is ranked first.
        self.assertEqual(diagnostic["roc_auc_cvss_as_score"], 1.0)
        self.assertEqual(diagnostic["recall_at_k"], [])  # no k <= 4 in the 100/1000/10000 grid

    def test_missing_sources_are_reported_as_not_ingested_rather_than_negative(self):
        enriched, report = enrich_dataset(self.dataset, kev=None, epss=self.epss)
        self.assertEqual(report["sources"]["kev"]["status"], "not_ingested")
        self.assertEqual(report["coverage"]["kev"], {"status": "not_ingested"})
        self.assertTrue((enriched["ti_kev_listed"] == "").all())
        self.assertTrue((enriched["ti_epss_matched"] != "").all())

    def test_missingness_table_reports_blank_ti_cells(self):
        _, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        table = report["ti_column_missingness"]
        self.assertEqual(table["ti_kev_listed"]["blank_count"], 0)
        self.assertEqual(table["ti_kev_vendor_project"]["blank_count"], 5)

    def test_examples_are_real_matches_from_the_inputs(self):
        _, report = enrich_dataset(self.dataset, kev=self.kev, epss=self.epss)
        kev_example = report["examples"]["kev_matches"][0]
        self.assertEqual(kev_example["cve_id"], "CVE-2016-3081")
        epss_example = report["examples"]["epss_matches_highest_score"][0]
        self.assertEqual(epss_example["cve_id"], "CVE-1999-0016")

    def test_does_not_mutate_inputs_and_rejects_malformed_dataset_ids(self):
        bad = self.dataset.copy()
        bad.loc[0, "cve_id"] = "not-a-cve"
        with self.assertRaisesRegex(ValueError, "malformed cve_id"):
            enrich_dataset(bad, kev=self.kev, epss=self.epss)
        with self.assertRaisesRegex(ValueError, "no rows"):
            enrich_dataset(self.dataset.iloc[0:0], kev=self.kev, epss=self.epss)


class RunEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.snapshot_root = self.base / "external" / "raw"
        self.clean = write_clean(self.base / "clean.csv", clean_dataset_frame())

        kev_file = self.base / "known_exploited_vulnerabilities.json"
        kev_file.write_bytes(kev_document([dict(KEV_ENTRY_STRUCT), second_kev_entry()]))
        epss_file = self.base / "epss_scores-current.csv.gz"
        epss_file.write_bytes(epss_gzip_payload())
        self.kev_manifest = import_local_snapshot(
            "kev", kev_file, origin_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            root=self.snapshot_root, now=NOW,
        )
        self.epss_manifest = import_local_snapshot(
            "epss", epss_file, origin_url="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
            root=self.snapshot_root, now=NOW,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, name, **kwargs):
        out = self.base / name
        out.mkdir(parents=True, exist_ok=True)
        return run_enrichment(
            self.clean,
            out / "enriched.csv",
            out / "coverage.json",
            snapshot_root=self.snapshot_root,
            **kwargs,
        )

    def test_end_to_end_writes_enriched_csv_and_coverage_json(self):
        report = self._run("run1")
        enriched = pd.read_csv(self.base / "run1" / "enriched.csv", dtype=str, keep_default_na=False)
        saved = json.loads((self.base / "run1" / "coverage.json").read_text(encoding="utf-8"))

        self.assertEqual(len(enriched), 6)
        self.assertEqual(saved["join"]["rows_output"], 6)
        self.assertEqual(saved["sources"]["kev"]["catalog_version"], "2026.10.08")
        self.assertEqual(saved["sources"]["kev"]["retrieval_method"], "local_import")
        self.assertEqual(saved["sources"]["epss"]["model_version"], "v2026.06.15")
        self.assertEqual(report["coverage"]["epss"]["dataset_rows_matched"], 2)

    def test_identical_snapshots_give_byte_identical_outputs(self):
        self._run("first")
        self._run("second")
        first_csv = (self.base / "first" / "enriched.csv").read_bytes()
        second_csv = (self.base / "second" / "enriched.csv").read_bytes()
        self.assertEqual(first_csv, second_csv)

        first = json.loads((self.base / "first" / "coverage.json").read_text(encoding="utf-8"))
        second = json.loads((self.base / "second" / "coverage.json").read_text(encoding="utf-8"))
        for document in (first, second):
            for key in ("input_file", "output_file", "coverage_file"):
                document.pop(key, None)
        self.assertEqual(first, second)

    def test_missing_snapshot_is_a_clear_error_unless_explicitly_allowed(self):
        empty_root = self.base / "empty"
        with self.assertRaisesRegex(MissingSnapshotError, "No KEV snapshot"):
            run_enrichment(
                self.clean, self.base / "x" / "e.csv", self.base / "x" / "c.json",
                snapshot_root=empty_root,
            )
        report = run_enrichment(
            self.clean, self.base / "y" / "e.csv", self.base / "y" / "c.json",
            snapshot_root=empty_root, allow_missing_sources=True,
        )
        self.assertEqual(report["sources"]["kev"]["status"], "not_ingested")
        self.assertEqual(report["sources"]["epss"]["status"], "not_ingested")

    def test_tampered_snapshot_is_refused_before_joining(self):
        snapshot_file = Path(self.kev_manifest["_manifest_path"]).parent / self.kev_manifest["file"]
        snapshot_file.write_bytes(snapshot_file.read_bytes() + b" ")
        with self.assertRaisesRegex(Exception, "checksum mismatch"):
            self._run("tampered")
        self.assertFalse((self.base / "tampered" / "enriched.csv").exists())

    def test_refuses_to_overwrite_the_clean_dataset(self):
        with self.assertRaisesRegex(ValueError, "must not overwrite"):
            run_enrichment(self.clean, self.clean, self.base / "c.json", snapshot_root=self.snapshot_root)

    def test_clean_dataset_must_not_already_contain_ti_columns(self):
        frame = clean_dataset_frame()
        frame["ti_kev_listed"] = "False"
        path = write_clean(self.base / "already.csv", frame)
        with self.assertRaisesRegex(ValueError, "already contains"):
            read_clean_dataset(path)


if __name__ == "__main__":
    unittest.main()
