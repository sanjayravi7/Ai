"""Synthetic tests for KEV/EPSS parsing, CVE identifier checks, and bounds.

Fixture rows are copied verbatim from the official sources (CISA KEV catalog
fetched 2026-10-12 and the FIRST EPSS daily file scored 2026-10-11) and trimmed
to the fields this pipeline reads. No live service is contacted.
"""

import gzip
import json
import math
import unittest

from tests.threat_intel_fixtures import (
    EPSS_REAL_EXCERPT,
    KEV_ENTRY_STRUCT,
    kev_document,
    second_kev_entry,
)
from src.threat_intel_sources import (
    SourceSchemaError,
    SourceValidationError,
    normalize_cve_id,
    parse_epss_csv,
    parse_kev_json,
)


class CveIdentifierTests(unittest.TestCase):
    def test_normalizes_case_and_whitespace(self):
        self.assertEqual(normalize_cve_id("  cve-2016-3081 "), "CVE-2016-3081")

    def test_rejects_malformed_identifiers(self):
        for value in ["CVE-19-1", "CVE-2019-12", "CVE2019-0001", "", None, "GHSA-xxxx-yyyy-zzzz"]:
            with self.subTest(value=value):
                self.assertIsNone(normalize_cve_id(value))


class KevParserTests(unittest.TestCase):
    def test_parses_valid_catalog_with_expected_columns(self):
        payload = kev_document([dict(KEV_ENTRY_STRUCT), second_kev_entry()])
        parsed = parse_kev_json(payload)

        self.assertEqual(parsed.metadata["catalog_version"], "2026.10.08")
        self.assertEqual(parsed.metadata["snapshot_date"], "2026-10-08")
        self.assertEqual(parsed.metadata["declared_count"], 2)
        self.assertEqual(len(parsed.frame), 2)
        row = parsed.frame.set_index("cve_id").loc["CVE-2016-3081"]
        self.assertEqual(row["kev_date_added"], "2026-10-08")
        self.assertEqual(row["kev_due_date"], "2026-10-11")
        self.assertEqual(row["kev_cwes"], "CWE-77")
        self.assertEqual(row["kev_known_ransomware_campaign_use"], "Unknown")
        self.assertEqual(parsed.findings["duplicate_cve_id_rows"], 0)

    def test_rejects_missing_top_level_field(self):
        document = json.loads(kev_document().decode("utf-8"))
        del document["catalogVersion"]
        with self.assertRaisesRegex(SourceSchemaError, "catalogVersion"):
            parse_kev_json(json.dumps(document).encode("utf-8"))

    def test_rejects_entry_missing_a_required_field(self):
        entry = dict(KEV_ENTRY_STRUCT)
        del entry["dateAdded"]
        with self.assertRaisesRegex(SourceSchemaError, "required fields"):
            parse_kev_json(kev_document([entry]))

    def test_rejects_declared_count_mismatch(self):
        with self.assertRaisesRegex(SourceValidationError, "declared count"):
            parse_kev_json(kev_document([dict(KEV_ENTRY_STRUCT)], count=5))

    def test_rejects_malformed_and_duplicate_cve_identifiers(self):
        bad = dict(KEV_ENTRY_STRUCT, cveID="CVE-2016-308")
        with self.assertRaisesRegex(SourceValidationError, "malformed cveID"):
            parse_kev_json(kev_document([bad]))

        duplicate = [dict(KEV_ENTRY_STRUCT), dict(KEV_ENTRY_STRUCT)]
        with self.assertRaisesRegex(SourceValidationError, "sharing 1 CVE IDs"):
            parse_kev_json(kev_document(duplicate))

    def test_rejects_unparseable_dates(self):
        bad = dict(KEV_ENTRY_STRUCT, dateAdded="08/10/2026")
        with self.assertRaisesRegex(SourceValidationError, "unparseable dates"):
            parse_kev_json(kev_document([bad]))

    def test_keeps_unexpected_ransomware_values_and_reports_them(self):
        odd = dict(KEV_ENTRY_STRUCT, knownRansomwareCampaignUse="Probable")
        parsed = parse_kev_json(kev_document([odd]))
        self.assertEqual(parsed.frame.loc[0, "kev_known_ransomware_campaign_use"], "Probable")
        self.assertEqual(parsed.findings["unexpected_ransomware_values"], {"Probable": 1})

    def test_accepts_gzip_wrapped_payloads_and_reports_it(self):
        parsed = parse_kev_json(gzip.compress(kev_document()))
        self.assertTrue(parsed.metadata["gzip_wrapped"])
        self.assertEqual(len(parsed.frame), 1)

    def test_rejects_invalid_json_and_non_object_documents(self):
        with self.assertRaisesRegex(SourceSchemaError, "not valid UTF-8 JSON"):
            parse_kev_json(b"<html>maintenance</html>")
        with self.assertRaisesRegex(SourceSchemaError, "JSON object"):
            parse_kev_json(b"[]")


class EpssParserTests(unittest.TestCase):
    def test_parses_real_excerpt_with_model_and_score_date(self):
        parsed = parse_epss_csv(EPSS_REAL_EXCERPT)

        self.assertEqual(parsed.metadata["model_version"], "v2026.06.15")
        self.assertEqual(parsed.metadata["snapshot_date"], "2026-10-11")
        self.assertEqual(len(parsed.frame), 4)
        row = parsed.frame.set_index("cve_id").loc["CVE-1999-0016"]
        self.assertAlmostEqual(row["epss_score"], 0.95667)
        self.assertAlmostEqual(row["epss_percentile"], 0.99871)

    def test_accepts_gzip_compressed_bulk_file(self):
        parsed = parse_epss_csv(gzip.compress(EPSS_REAL_EXCERPT))
        self.assertTrue(parsed.metadata["gzip_wrapped"])
        self.assertEqual(len(parsed.frame), 4)

    def test_scores_and_percentiles_must_lie_in_zero_to_one(self):
        high = EPSS_REAL_EXCERPT.replace(b"0.95667", b"1.00001")
        with self.assertRaisesRegex(SourceValidationError, "outside \\[0, 1\\]"):
            parse_epss_csv(high)
        negative = EPSS_REAL_EXCERPT.replace(b"0.98059", b"-0.01")
        with self.assertRaisesRegex(SourceValidationError, "outside \\[0, 1\\]"):
            parse_epss_csv(negative)
        bad_percentile = EPSS_REAL_EXCERPT.replace(b"0.99871", b"2")
        with self.assertRaisesRegex(SourceValidationError, "percentile"):
            parse_epss_csv(bad_percentile)

    def test_rejects_non_numeric_scores(self):
        payload = EPSS_REAL_EXCERPT.replace(b"0.27858", b"high")
        with self.assertRaisesRegex(SourceValidationError, "non-numeric"):
            parse_epss_csv(payload)

    def test_empty_numeric_cells_are_kept_as_counted_missing_values(self):
        payload = EPSS_REAL_EXCERPT.replace(b"CVE-1999-0002,0.27858,0.98059", b"CVE-1999-0002,,0.98059")
        parsed = parse_epss_csv(payload)
        self.assertEqual(parsed.findings["missing_value_counts"]["epss"], 1)
        score = parsed.frame.set_index("cve_id").loc["CVE-1999-0002", "epss_score"]
        self.assertTrue(math.isnan(score))
        self.assertEqual(len(parsed.frame), 4)

    def test_rejects_missing_comment_metadata(self):
        payload = EPSS_REAL_EXCERPT.replace(b"#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z\n", b"")
        with self.assertRaisesRegex(SourceSchemaError, "lacks 'model_version'"):
            parse_epss_csv(payload)

    def test_rejects_changed_header(self):
        payload = EPSS_REAL_EXCERPT.replace(b"cve,epss,percentile", b"cve_id,epss_probability,percentile")
        with self.assertRaisesRegex(SourceSchemaError, "header must be"):
            parse_epss_csv(payload)

    def test_rejects_malformed_and_duplicate_identifiers(self):
        malformed = EPSS_REAL_EXCERPT.replace(b"CVE-1999-0003", b"CVE-99-3")
        with self.assertRaisesRegex(SourceValidationError, "malformed CVE IDs"):
            parse_epss_csv(malformed)
        duplicate = EPSS_REAL_EXCERPT.replace(b"CVE-1999-0003", b"CVE-1999-0001")
        with self.assertRaisesRegex(SourceValidationError, "sharing 1 CVE IDs"):
            parse_epss_csv(duplicate)

    def test_header_without_records_is_rejected(self):
        payload = b"#model_version:v1,score_date:2026-10-11T12:00:25Z\ncve,epss,percentile\n"
        with self.assertRaises(SourceValidationError):
            parse_epss_csv(payload)


if __name__ == "__main__":
    unittest.main()
