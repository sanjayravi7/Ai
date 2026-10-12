"""Synthetic tests for CVE status parsing and marker detection (no network)."""

import json
import unittest

from src.cve_status_sources import (
    REJECT_MARKER,
    STATUS_REJECTED,
    STATUS_REINSTATED,
    STATUS_UNMARKED,
    STATUS_UNVERIFIED,
    CveStatusSchemaError,
    CveStatusValidationError,
    classify_status,
    cvelistv5_api_url,
    cvelistv5_blob_url,
    cvelistv5_record_path,
    has_disputed_marker,
    is_reject_placeholder,
    marker_audit,
    marker_summary,
    parse_consult_ids,
    parse_cve_record,
    parse_rejection_reason,
    verify_supported_identifier,
)

from tests.cve_status_fixtures import (
    DISPUTED_SUMMARY,
    published_record,
    record_bytes,
    rejected_record,
    rejected_summary,
    reserved_record,
)


class MarkerTests(unittest.TestCase):
    def test_exact_prefix_is_a_rejected_placeholder(self):
        self.assertTrue(is_reject_placeholder(rejected_summary("CVE-2019-0002")))
        self.assertTrue(marker_summary(rejected_summary())["reject_exact_prefix"])

    def test_leading_whitespace_is_tolerated_and_reported(self):
        summary = "  " + rejected_summary()
        self.assertTrue(is_reject_placeholder(summary))
        findings = marker_summary(summary)
        self.assertFalse(findings["reject_exact_prefix"])
        self.assertTrue(findings["reject_prefix_after_leading_whitespace"])

    def test_marker_inside_the_text_is_not_a_placeholder(self):
        summary = f"See also {REJECT_MARKER} entries elsewhere in this dataset."
        self.assertFalse(is_reject_placeholder(summary))
        findings = marker_summary(summary)
        self.assertTrue(findings["reject_marker_not_at_start"])
        self.assertFalse(findings["reject_exact_prefix"])

    def test_case_variant_is_not_a_placeholder_but_is_disclosed(self):
        summary = "** reject ** DO NOT USE THIS CANDIDATE NUMBER."
        self.assertFalse(is_reject_placeholder(summary))
        self.assertTrue(marker_summary(summary)["reject_case_variant_prefix"])

    def test_lowercase_prose_mention_is_not_a_placeholder(self):
        self.assertFalse(is_reject_placeholder("The server does not reject malformed input."))

    def test_blank_and_missing_summaries_are_not_placeholders(self):
        for value in (None, "", float("nan")):
            self.assertFalse(is_reject_placeholder(value))
            self.assertEqual(marker_summary(value)["disputed_marker_present"], False)

    def test_disputed_marker_is_detected_anywhere_in_the_summary(self):
        self.assertTrue(has_disputed_marker(DISPUTED_SUMMARY))
        self.assertTrue(has_disputed_marker("Text. " + DISPUTED_SUMMARY))
        findings = marker_summary("Text. " + DISPUTED_SUMMARY)
        self.assertTrue(findings["disputed_marker_present"])
        self.assertFalse(findings["disputed_marker_at_start"])
        self.assertFalse(has_disputed_marker("No marker here."))

    def test_marker_audit_counts_every_form(self):
        summaries = [
            rejected_summary(),
            " " + rejected_summary(),
            "** reject ** withdrawn",
            f"mentions {REJECT_MARKER} inline",
            DISPUTED_SUMMARY,
            "ordinary summary",
        ]
        counts = marker_audit(summaries)
        self.assertEqual(counts["rows"], 6)
        self.assertEqual(counts["reject_exact_prefix"], 1)
        self.assertEqual(counts["reject_prefix_after_leading_whitespace"], 1)
        self.assertEqual(counts["reject_case_variant_prefix"], 1)
        self.assertEqual(counts["reject_marker_not_at_start"], 1)
        self.assertEqual(counts["reject_placeholder_rows"], 2)
        self.assertEqual(counts["disputed_marker_present"], 1)


class RecordPathTests(unittest.TestCase):
    def test_paths_follow_the_official_bucket_layout(self):
        self.assertEqual(
            cvelistv5_record_path("CVE-2007-3004"), "cves/2007/3xxx/CVE-2007-3004.json"
        )
        self.assertEqual(
            cvelistv5_record_path("CVE-1999-0001"), "cves/1999/0xxx/CVE-1999-0001.json"
        )
        self.assertEqual(
            cvelistv5_record_path("cve-2017-9410"), "cves/2017/9xxx/CVE-2017-9410.json"
        )
        self.assertEqual(
            cvelistv5_record_path("CVE-2024-12345"), "cves/2024/12xxx/CVE-2024-12345.json"
        )

    def test_malformed_identifiers_are_rejected(self):
        for value in ("", None, "CVE-99-1", "not-a-cve", "CVE-X-0001"):
            with self.assertRaises(CveStatusValidationError):
                cvelistv5_record_path(value)
            with self.assertRaises(CveStatusValidationError):
                verify_supported_identifier(value)

    def test_api_url_pins_the_reference(self):
        url = cvelistv5_api_url("CVE-2007-3004", ref="abc123")
        self.assertEqual(
            url,
            "https://api.github.com/repos/CVEProject/cvelistV5/contents/"
            "cves/2007/3xxx/CVE-2007-3004.json?ref=abc123",
        )
        self.assertNotIn("?", cvelistv5_api_url("CVE-2007-3004"))

    def test_blob_url_is_human_readable_and_pinned(self):
        url = cvelistv5_blob_url("CVE-2007-3004", ref="deadbeef")
        self.assertEqual(
            url,
            "https://github.com/CVEProject/cvelistV5/blob/deadbeef/cves/2007/3xxx/CVE-2007-3004.json",
        )


class ParsedRecordTests(unittest.TestCase):
    def test_rejected_record_fields_reasons_and_consult_ids(self):
        payload = record_bytes(rejected_record("CVE-2020-0003", consult="CVE-2019-0003"))
        record = parse_cve_record(payload, expected_cve_id="CVE-2020-0003")

        self.assertEqual(record.cve_id, "CVE-2020-0003")
        self.assertEqual(record.state, "REJECTED")
        self.assertEqual(record.date_rejected, "2022-10-03T00:00:00Z")
        self.assertEqual(record.date_updated, "2021-02-03T04:05:06Z")
        self.assertEqual(record.assigner_short_name, "mitre")
        self.assertEqual(record.consult_ids, ("CVE-2019-0003",))
        self.assertIn("duplicate of CVE-2019-0003", record.rejected_reason)
        self.assertEqual(
            parse_rejection_reason(record.rejected_reason),
            "This candidate is a duplicate of CVE-2019-0003.",
        )

    def test_published_record_keeps_metrics_for_disclosure(self):
        payload = record_bytes(published_record("CVE-2020-0004", cvss_base_score=8.4))
        record = parse_cve_record(payload)
        self.assertEqual(record.state, "PUBLISHED")
        self.assertEqual(record.cvss_version, "cvssV3_1")
        self.assertAlmostEqual(record.cvss_base_score, 8.4)
        self.assertEqual(record.consult_ids, ())

    def test_multiple_consult_ids_and_missing_reason_are_parsed(self):
        text = (
            "DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2019-0001, "
            "CVE-2019-0002. Reason: This candidate is a duplicate."
        )
        self.assertEqual(parse_consult_ids(text), ("CVE-2019-0001", "CVE-2019-0002"))
        self.assertEqual(parse_consult_ids(""), ())
        self.assertEqual(parse_rejection_reason("no reason here"), "")
        self.assertEqual(parse_consult_ids("ConsultIDs: not-a-cve."), ())

    def test_identifier_mismatch_is_rejected(self):
        payload = record_bytes(rejected_record("CVE-2020-0003"))
        with self.assertRaisesRegex(CveStatusValidationError, "identifier mismatch"):
            parse_cve_record(payload, expected_cve_id="CVE-2020-0004")

    def test_schema_failures(self):
        with self.assertRaisesRegex(CveStatusSchemaError, "UTF-8 JSON"):
            parse_cve_record(b"{not json")
        with self.assertRaisesRegex(CveStatusSchemaError, "top level"):
            parse_cve_record(json.dumps([1, 2]).encode("utf-8"))
        with self.assertRaisesRegex(CveStatusSchemaError, "cveMetadata"):
            parse_cve_record(json.dumps({"containers": {}}).encode("utf-8"))

        missing_state = json.loads(record_bytes(rejected_record("CVE-2020-0003")))
        del missing_state["cveMetadata"]["state"]
        with self.assertRaisesRegex(CveStatusSchemaError, "state"):
            parse_cve_record(missing_state)

        bad_id = json.loads(record_bytes(rejected_record("CVE-2020-0003")))
        bad_id["cveMetadata"]["cveId"] = "CVE-20-3"
        with self.assertRaisesRegex(CveStatusSchemaError, "cveId"):
            parse_cve_record(bad_id)

    def test_unparseable_dates_are_rejected_not_silently_kept(self):
        payload = json.loads(record_bytes(rejected_record("CVE-2020-0003")))
        payload["cveMetadata"]["dateRejected"] = "not-a-date"
        with self.assertRaisesRegex(CveStatusValidationError, "dateRejected"):
            parse_cve_record(payload)

    def test_reserved_records_are_read_but_not_final(self):
        record = parse_cve_record(record_bytes(reserved_record("CVE-2020-0009")))
        self.assertEqual(record.state, "RESERVED")
        status, reason = classify_status(record, True)
        self.assertEqual(status, STATUS_UNVERIFIED)
        self.assertIn("RESERVED", reason)


class ClassificationTests(unittest.TestCase):
    def test_status_vocabulary(self):
        rejected = parse_cve_record(record_bytes(rejected_record("CVE-2020-0003")))
        published = parse_cve_record(record_bytes(published_record("CVE-2020-0004")))

        self.assertEqual(classify_status(rejected, True)[0], STATUS_REJECTED)
        self.assertEqual(classify_status(published, True)[0], STATUS_REINSTATED)
        self.assertEqual(classify_status(None, True)[0], STATUS_UNVERIFIED)
        self.assertEqual(classify_status(None, False)[0], STATUS_UNMARKED)
        self.assertEqual(classify_status(rejected, False)[0], STATUS_UNMARKED)

    def test_reasons_are_explicit(self):
        rejected = parse_cve_record(record_bytes(rejected_record("CVE-2020-0003")))
        self.assertEqual(classify_status(rejected, True)[1], "authoritative_state_rejected")
        self.assertEqual(classify_status(None, True)[1], "no_authoritative_record_available")
        self.assertEqual(
            classify_status(None, False)[1], "summary_does_not_start_with_reject_marker"
        )


if __name__ == "__main__":
    unittest.main()
