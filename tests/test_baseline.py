"""Synthetic tests for CVSS-only deterministic ranking."""

import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.baseline import create_baseline, run_baseline


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.frame = pd.DataFrame(
            {
                "cve_id": [
                    "CVE-2024-0003",
                    "CVE-2024-0002",
                    "CVE-2024-0001",
                    "CVE-2024-0004",
                ],
                "cvss": ["7.5", "9.8", "9.8", ""],
                "summary": ["third", "second", "first", "no score"],
            }
        )

    def test_descending_scores_ties_and_missing_scores_are_ordered_deterministically(self):
        ranked, summary = create_baseline(self.frame)

        self.assertEqual(
            ranked["cve_id"].tolist(),
            ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"],
        )
        self.assertEqual(ranked["baseline_rank"].tolist(), [1, 2, 3, 4])
        self.assertEqual(summary["rows_input"], 4)
        self.assertEqual(summary["rows_ranked"], 4)
        self.assertEqual(summary["rows_dropped"], 0)
        self.assertEqual(summary["missing_cvss_count"], 1)
        self.assertEqual(summary["task_type"], "ranking_only")
        self.assertIsNone(summary["exploitation_label_column"])
        self.assertFalse(summary["exploitation_prediction"])
        self.assertFalse(summary["severity_column_present"])
        self.assertFalse(summary["epss_score_column_present"])
        self.assertEqual(summary["top_ranked_record"]["cve_id"], "CVE-2024-0001")

    def test_rejects_non_numeric_and_out_of_range_scores(self):
        non_numeric = self.frame.copy()
        non_numeric.loc[0, "cvss"] = "unknown"
        with self.assertRaisesRegex(ValueError, "non-numeric"):
            create_baseline(non_numeric)

        out_of_range = self.frame.copy()
        out_of_range.loc[0, "cvss"] = "10.1"
        with self.assertRaisesRegex(ValueError, "outside \[0, 10\]"):
            create_baseline(out_of_range)

    def test_writes_ranked_records_and_machine_readable_summary(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "clean.csv"
            ranked_path = root / "ranked.csv"
            summary_path = root / "summary.json"
            self.frame.to_csv(input_path, index=False)

            summary = run_baseline(input_path, ranked_path, summary_path)

            self.assertTrue(ranked_path.is_file())
            self.assertTrue(summary_path.is_file())
            saved_ranked = pd.read_csv(ranked_path)
            saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_ranked["baseline_rank"].tolist(), [1, 2, 3, 4])
            self.assertEqual(saved_summary["baseline"], "cvss_descending_ranking")
            self.assertEqual(saved_summary["rows_ranked"], 4)
            self.assertEqual(saved_summary["exploitation_prediction"], False)
            self.assertEqual(summary["summary_file"], str(summary_path))


if __name__ == "__main__":
    unittest.main()
