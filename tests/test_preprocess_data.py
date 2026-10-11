"""Synthetic tests for deterministic, non-destructive preprocessing."""

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.preprocess_data import preprocess_dataframe, preprocess_file


def synthetic_raw_frame():
    return pd.DataFrame(
        {
            "Unnamed: 0": [
                "CVE-2024-1001",
                "CVE-2024-1002",
                "CVE-2024-1003",
            ],
            "mod_date": [
                "2024-01-01 12:30:00",
                "not-a-date",
                "",
            ],
            "pub_date": [
                "2023-12-01 08:00:00",
                "2023-12-02 08:00:00",
                "2023-12-03 08:00:00",
            ],
            "cvss": ["9.8", "not-a-score", ""],
            "cwe_code": ["79", "119", "20"],
            "cwe_name": ["Cross-site scripting", "Out-of-bounds read", "Input validation"],
            "summary": ["first", "second", "third"],
            "access_authentication": ["", "NONE", "NONE"],
            "access_complexity": ["", "LOW", "LOW"],
            "access_vector": ["", "NETWORK", "LOCAL"],
            "impact_availability": ["", "PARTIAL", "NONE"],
            "impact_confidentiality": ["", "PARTIAL", "NONE"],
            "impact_integrity": ["", "PARTIAL", "NONE"],
        }
    )


class PreprocessDataTests(unittest.TestCase):
    def test_renames_verifies_parses_and_preserves_rows_and_missing_values(self):
        raw = synthetic_raw_frame()
        original = raw.copy(deep=True)

        cleaned, report = preprocess_dataframe(raw)

        self.assertEqual(cleaned.columns[0], "cve_id")
        self.assertNotIn("Unnamed: 0", cleaned.columns)
        self.assertEqual(len(cleaned), len(raw))
        self.assertEqual(report["rows_dropped"], 0)
        self.assertEqual(report["invalid_identifier_count"], 0)
        self.assertEqual(report["date_parse_failures"]["mod_date"]["count"], 1)
        self.assertEqual(report["cvss_parse_failure_count"], 1)
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(cleaned["mod_date"]))
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(cleaned["pub_date"]))
        self.assertTrue(pd.isna(cleaned.loc[0, "access_vector"]))
        self.assertTrue(pd.isna(cleaned.loc[1, "mod_date"]))
        self.assertTrue(pd.isna(cleaned.loc[2, "mod_date"]))
        self.assertTrue(pd.isna(cleaned.loc[1, "cvss"]))
        self.assertTrue(pd.isna(cleaned.loc[2, "cvss"]))
        self.assertEqual(report["missing_values_after_parsing"]["access_vector"], 1)
        pd.testing.assert_frame_equal(raw, original)

    def test_rejects_a_first_column_that_is_not_all_cve_ids(self):
        raw = synthetic_raw_frame()
        raw.loc[1, "Unnamed: 0"] = "not-a-cve"
        with self.assertRaisesRegex(ValueError, "CVE ID validation"):
            preprocess_dataframe(raw)

    def test_file_preprocessing_writes_canonical_headers_without_overwriting_input(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "raw.csv"
            output_path = root / "processed" / "clean.csv"
            synthetic_raw_frame().to_csv(input_path, index=False)

            report = preprocess_file(input_path, output_path)

            saved = pd.read_csv(output_path)
            self.assertEqual(saved.columns[0], "cve_id")
            self.assertEqual(len(saved), 3)
            self.assertEqual(report["rows_input"], 3)
            self.assertEqual(report["rows_output"], 3)
            self.assertEqual(report["rows_dropped"], 0)

            with self.assertRaisesRegex(ValueError, "must differ"):
                preprocess_file(input_path, input_path)
            self.assertEqual(len(pd.read_csv(input_path)), 3)


if __name__ == "__main__":
    unittest.main()
