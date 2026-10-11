"""Synthetic tests for read-only data validation."""

import tempfile
import unittest

import pandas as pd

from src.validate_data import validate_dataframe, validate_csv


def synthetic_validation_frame():
    return pd.DataFrame(
        {
            "Unnamed: 0": [
                "CVE-2024-0001",
                "not-a-cve",
                "CVE-2024-0001",
                "CVE-2024-0004",
            ],
            "mod_date": [
                "2024-01-01 00:00:00",
                "not-a-date",
                "2024-01-03 00:00:00",
                "2024-01-04 00:00:00",
            ],
            "pub_date": [
                "2023-12-01 00:00:00",
                "2023-12-02 00:00:00",
                "bad-date",
                "2023-12-04 00:00:00",
            ],
            "cvss": ["9.8", "10.1", "not-a-score", "5.0"],
            "cwe_code": ["79", "79", "", "119"],
            "cwe_name": [
                "Cross-site scripting",
                "Cross-site scripting",
                "",
                "Out-of-bounds read",
            ],
            "summary": ["one", "two", "three", "four"],
            "access_authentication": ["NONE", "NONE", "", "SINGLE"],
            "access_complexity": ["LOW", "LOW", "MEDIUM", "LOW"],
            "access_vector": ["NETWORK", " ", "LOCAL", "NETWORK"],
            "impact_availability": ["PARTIAL", "NONE", "NONE", "COMPLETE"],
            "impact_confidentiality": ["PARTIAL", "NONE", pd.NA, "COMPLETE"],
            "impact_integrity": ["PARTIAL", "NONE", "NONE", "COMPLETE"],
        }
    )


class ValidateDataTests(unittest.TestCase):
    def test_reports_identifier_missingness_dates_scores_and_distributions(self):
        frame = synthetic_validation_frame()
        original = frame.copy(deep=True)

        report = validate_dataframe(frame)

        self.assertEqual(report["row_count"], 4)
        self.assertEqual(report["column_count"], 13)
        self.assertEqual(report["identifier_column"], "Unnamed: 0")
        self.assertEqual(report["identifier"]["invalid_format_count"], 1)
        self.assertEqual(report["identifier"]["missing_count"], 0)
        self.assertEqual(report["identifier"]["duplicate_id_count"], 1)
        self.assertEqual(report["identifier"]["duplicate_row_count"], 1)

        self.assertEqual(report["missing_values"].loc["cwe_code", "missing_count"], 1)
        self.assertEqual(
            report["missing_values"].loc["access_vector", "missing_count"], 1
        )
        self.assertEqual(
            report["missing_values"].loc["impact_confidentiality", "missing_count"],
            1,
        )
        self.assertEqual(
            report["date_parse_failures"]["mod_date"]["parse_failure_count"], 1
        )
        self.assertEqual(
            report["date_parse_failures"]["pub_date"]["parse_failure_count"], 1
        )
        self.assertEqual(report["cvss"]["non_numeric_count"], 1)
        self.assertEqual(report["cvss"]["out_of_range_count"], 1)
        self.assertIn("datetime64", report["data_types"].loc["mod_date", "validation_dtype"])
        self.assertIn("float", report["data_types"].loc["cvss", "validation_dtype"])

        cwe_codes = set(report["cwe_distribution"]["cwe_code"])
        self.assertEqual(cwe_codes, {"79", "119", "<MISSING>"})
        cvss_labels = set(report["cvss_distribution"]["cvss"].astype(str))
        self.assertIn("<NON_NUMERIC>", cvss_labels)
        self.assertIn("10.1", cvss_labels)

        # Validation is observational only; it does not normalize the caller's data.
        pd.testing.assert_frame_equal(frame, original)

    def test_csv_reader_preserves_empty_fields_for_missingness_checks(self):
        frame = synthetic_validation_frame().iloc[:2].copy()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = f"{temporary_directory}/synthetic.csv"
            frame.to_csv(path, index=False)
            report = validate_csv(path)

        self.assertEqual(report["row_count"], 2)
        self.assertEqual(report["missing_values"].loc["access_authentication", "missing_count"], 0)
        self.assertEqual(report["missing_values"].loc["access_vector", "missing_count"], 1)
        self.assertEqual(report["data_types"].loc["cvss", "source_dtype"], "float64")


if __name__ == "__main__":
    unittest.main()
