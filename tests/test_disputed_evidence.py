"""Synthetic tests for the disputed-record evidence parsers and classifiers.

Every input is a local fixture or literal string: the tests never contact the
network and never read the bundled dataset.
"""

import json
import unittest

from src.cve_status_sources import CveStatusSchemaError, CveStatusValidationError
from src.disputed_evidence import (
    BUCKET_NOT_VERIFIABLE,
    BUCKET_RESOLVED,
    BUCKET_UNRESOLVED,
    CLASS_CONTRADICTED,
    CLASS_DISPUTE_TAG,
    CLASS_DISPUTE_TEXT,
    CLASS_NONE,
    CLASS_NON_FINAL,
    CLASS_SILENT,
    CLASS_WITHDRAWN,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_NONE,
    EXCLUSION_NOT_EVALUABLE,
    EXCLUSION_NOT_SUPPORTED,
    EXCLUSION_SUPPORTED,
    POSITION_CONTRADICTS,
    POSITION_DOES_NOT_RESOLVE,
    POSITION_NO_RECORD,
    POSITION_SUPPORTS,
    RESOLUTION_CONTRADICTED,
    RESOLUTION_NON_FINAL,
    RESOLUTION_NOT_VERIFIABLE,
    RESOLUTION_OPEN,
    RESOLUTION_UNRESOLVED,
    RESOLUTION_WITHDRAWN,
    RETRIEVAL_FAILED,
    RETRIEVAL_NOT_ATTEMPTED,
    RETRIEVAL_NOT_FOUND,
    RETRIEVAL_RETRIEVED,
    STATUS_CONTRADICTORY,
    STATUS_INSUFFICIENT,
    STATUS_NOT_VERIFIABLE,
    STATUS_SUFFICIENT,
    classify_dispute_evidence,
    classify_dataset_rows,
    dataset_dispute_text,
    parse_dispute_record,
    sentence_containing,
)

from tests.disputed_fixtures import (
    REJECTION_REASON,
    disputed_consult_record,
    disputed_contradiction_record,
    disputed_reserved_record,
    disputed_silent_record,
    disputed_tag_only_record,
    disputed_text_record,
    disputed_withdrawn_record,
    record_bytes,
)


class DisputeRecordParsingTests(unittest.TestCase):
    def test_parses_state_tags_text_paths_and_references(self):
        view = parse_dispute_record(record_bytes(disputed_text_record()), expected_cve_id="CVE-2020-1001")
        self.assertEqual(view.cve_id, "CVE-2020-1001")
        self.assertEqual(view.state, "PUBLISHED")
        self.assertEqual(view.all_tags, ("disputed",))
        self.assertTrue(view.dispute_tag_present)
        self.assertTrue(view.is_final_state)
        self.assertEqual(view.assigner_short_name, "mitre")
        self.assertEqual(view.data_version, "5.0")
        self.assertEqual(view.date_published, "2019-11-18T05:24:15.000Z")
        self.assertEqual(
            [field.path for field in view.text_fields],
            ["containers/cna/descriptions/0/value"],
        )
        self.assertEqual(len(view.references), 2)
        self.assertEqual(view.references[0].tags, ("vendor-advisory",))
        self.assertEqual(view.cvss_version, "cvssV3_1")
        self.assertEqual(view.cvss_base_score, 7.5)

    def test_accepts_predecoded_mapping_and_json_text(self):
        payload = disputed_tag_only_record()
        as_text = json.dumps(payload)
        self.assertEqual(parse_dispute_record(as_text).cve_id, payload["cveMetadata"]["cveId"])
        self.assertEqual(parse_dispute_record(payload).state, "PUBLISHED")

    def test_identifier_mismatch_is_a_validation_error(self):
        with self.assertRaises(CveStatusValidationError):
            parse_dispute_record(record_bytes(disputed_text_record()), expected_cve_id="CVE-2020-9999")

    def test_malformed_documents_raise_schema_errors(self):
        with self.assertRaises(CveStatusSchemaError):
            parse_dispute_record(b"{not json")
        with self.assertRaises(CveStatusSchemaError):
            parse_dispute_record(json.dumps({"containers": {}}).encode("utf-8"))
        with self.assertRaises(CveStatusSchemaError):
            parse_dispute_record(json.dumps({"cveMetadata": {"cveId": "NOT-A-CVE"}}).encode("utf-8"))
        with self.assertRaises(CveStatusSchemaError):
            parse_dispute_record(json.dumps({"cveMetadata": {"cveId": "CVE-2020-1001"}, "containers": []}).encode("utf-8"))

    def test_adp_and_metadata_tags_are_read(self):
        payload = disputed_tag_only_record()
        payload["containers"]["adp"] = [
            {"providerMetadata": {"shortName": "CVE"}, "tags": ["disputed"]}
        ]
        payload["cveMetadata"]["cveTags"] = ["disputed"]
        view = parse_dispute_record(payload)
        self.assertEqual(set(view.all_tags), {"disputed"})
        self.assertEqual(view.provider_short_names, ("mitre", "CVE"))

    def test_timeline_and_legacy_description_are_scanned(self):
        payload = disputed_text_record()
        payload["containers"]["cna"]["timeline"] = [
            {"time": "2020-01-01T00:00:00Z", "lang": "en", "value": "The vendor disputes this issue."}
        ]
        payload["containers"]["cna"]["x_legacyV4Record"] = {
            "description": {"description_data": [{"lang": "en", "value": "Legacy text about the issue."}]}
        }
        view = parse_dispute_record(payload)
        paths = [field.path for field in view.text_fields]
        self.assertIn("containers/cna/timeline/0/value", paths)
        self.assertIn("containers/cna/x_legacyV4Record/description/description_data/0/value", paths)

    def test_withdrawn_record_exposes_reasons_and_consult_ids(self):
        view = parse_dispute_record(record_bytes(disputed_withdrawn_record()))
        self.assertEqual(view.state, "REJECTED")
        self.assertEqual(view.replacement_ids, ("CVE-2019-9000",))
        self.assertIn("DO NOT USE THIS CANDIDATE NUMBER", view.rejected_reasons[0].value)
        self.assertEqual(view.rejected_reasons[0].path, "containers/cna/rejectedReasons/0/value")

    def test_replacement_documented_in_description_text(self):
        view = parse_dispute_record(record_bytes(disputed_consult_record()))
        self.assertEqual(view.replacement_ids, ("CVE-2019-9000",))
        self.assertEqual(view.replacement_evidence[0][0], "duplicate_of")
        self.assertEqual(
            view.replacement_evidence[0][2], "containers/cna/descriptions/0/value"
        )


class DatasetMarkerTests(unittest.TestCase):
    def test_marker_at_start_is_recorded_with_offset_and_claim(self):
        claim = dataset_dispute_text("** DISPUTED ** A claim about the issue.")
        self.assertTrue(claim["disputed_marker_present"])
        self.assertTrue(claim["disputed_marker_at_start"])
        self.assertEqual(claim["disputed_marker_offset"], 0)
        self.assertEqual(claim["disputed_claim_text"], "A claim about the issue.")
        self.assertEqual(claim["dataset_text_before_marker"], "")
        self.assertEqual(claim["dataset_summary_original"], "** DISPUTED ** A claim about the issue.")

    def test_marker_in_the_middle_is_not_treated_as_a_prefix(self):
        claim = dataset_dispute_text("Text first. ** DISPUTED ** Rest.")
        self.assertTrue(claim["disputed_marker_present"])
        self.assertFalse(claim["disputed_marker_at_start"])
        self.assertEqual(claim["dataset_text_before_marker"], "Text first.")
        self.assertEqual(claim["disputed_claim_text"], "Rest.")

    def test_absent_marker_reports_no_claim_text(self):
        claim = dataset_dispute_text("An ordinary summary.")
        self.assertFalse(claim["disputed_marker_present"])
        self.assertEqual(claim["disputed_marker_offset"], -1)
        self.assertEqual(claim["disputed_claim_text"], "An ordinary summary.")

    def test_sentence_excerpt_is_the_sentence_around_the_match(self):
        text = "First sentence. The vendor disputes this issue. Third sentence."
        index = text.index("disputes")
        excerpt = sentence_containing(text, index, index + len("disputes"))
        self.assertEqual(excerpt, "The vendor disputes this issue.")

    def test_long_sentences_are_truncated_with_an_ellipsis(self):
        text = "Start. " + " ".join(["word"] * 400) + " end."
        index = text.index("word")
        excerpt = sentence_containing(text, index, index + 4, max_chars=80)
        self.assertLessEqual(len(excerpt), 85)
        self.assertTrue(excerpt.rstrip().endswith("..."))
        self.assertNotEqual(excerpt, text)


class EvidenceClassificationTests(unittest.TestCase):
    def _classify(self, record, status=RETRIEVAL_RETRIEVED, claim=""):
        view = None if record is None else parse_dispute_record(record_bytes(record))
        return classify_dispute_evidence(view, retrieval_status=status, dataset_claim_text=claim)

    def test_withdrawn_identifier_supports_exclusion(self):
        result = self._classify(disputed_withdrawn_record())
        self.assertEqual(result["official_record_position"], POSITION_SUPPORTS)
        self.assertEqual(result["dispute_resolution"], RESOLUTION_WITHDRAWN)
        self.assertEqual(result["resolution_bucket"], BUCKET_RESOLVED)
        self.assertEqual(result["evidence_classification"], CLASS_WITHDRAWN)
        self.assertEqual(result["exclusion_evidence"], EXCLUSION_SUPPORTED)
        self.assertEqual(result["evidence_confidence"], CONFIDENCE_HIGH)
        self.assertEqual(result["authoritative_rationale"], REJECTION_REASON)
        self.assertEqual(result["authoritative_rationale_field"], "containers/cna/rejectedReasons/0/value")
        self.assertEqual(result["authoritative_rationale_status"], "RECORDED")

    def test_open_dispute_documented_in_text_is_high_confidence(self):
        result = self._classify(
            disputed_text_record(), claim="Example widget firmware does not validate updates."
        )
        self.assertEqual(result["official_record_position"], POSITION_SUPPORTS)
        self.assertEqual(result["dispute_resolution"], RESOLUTION_OPEN)
        self.assertEqual(result["resolution_bucket"], BUCKET_UNRESOLVED)
        self.assertEqual(result["evidence_classification"], CLASS_DISPUTE_TEXT)
        self.assertEqual(result["evidence_status"], STATUS_SUFFICIENT)
        self.assertEqual(result["evidence_confidence"], CONFIDENCE_HIGH)
        self.assertEqual(result["exclusion_evidence"], EXCLUSION_NOT_SUPPORTED)
        self.assertEqual(result["dispute_language_rule"], "disputed_word")
        self.assertEqual(result["dispute_actor"], "THIRD_PARTY")
        self.assertEqual(result["dispute_subject"], "RELEVANCE_OR_SEVERITY")
        self.assertIn("dispute the relevance", result["authoritative_rationale"])

    def test_tag_only_dispute_is_medium_confidence_and_not_an_exclusion(self):
        result = self._classify(disputed_tag_only_record())
        self.assertEqual(result["evidence_classification"], CLASS_DISPUTE_TAG)
        self.assertEqual(result["evidence_confidence"], CONFIDENCE_MEDIUM)
        self.assertEqual(result["exclusion_evidence"], EXCLUSION_NOT_SUPPORTED)
        self.assertEqual(result["review_reason"], "dispute_recorded_only_as_a_tag")
        self.assertEqual(result["dispute_resolution"], RESOLUTION_OPEN)

    def test_record_silent_on_dispute_is_insufficient(self):
        result = self._classify(disputed_silent_record())
        self.assertEqual(result["evidence_classification"], CLASS_SILENT)
        self.assertEqual(result["official_record_position"], POSITION_DOES_NOT_RESOLVE)
        self.assertEqual(result["dispute_resolution"], RESOLUTION_UNRESOLVED)
        self.assertEqual(result["evidence_status"], STATUS_INSUFFICIENT)
        self.assertEqual(result["evidence_confidence"], CONFIDENCE_LOW)
        self.assertEqual(result["authoritative_rationale"], "")

    def test_explicit_contradiction_is_recorded_verbatim(self):
        result = self._classify(disputed_contradiction_record())
        self.assertEqual(result["evidence_classification"], CLASS_CONTRADICTED)
        self.assertEqual(result["official_record_position"], POSITION_CONTRADICTS)
        self.assertEqual(result["dispute_resolution"], RESOLUTION_CONTRADICTED)
        self.assertEqual(result["evidence_status"], STATUS_CONTRADICTORY)
        self.assertEqual(result["contradiction_rule"], "dispute_resolved")
        self.assertEqual(result["exclusion_evidence"], EXCLUSION_NOT_SUPPORTED)
        self.assertIn("no longer disputed", result["contradiction_quote"])

    def test_non_final_state_is_not_treated_as_evidence(self):
        result = self._classify(disputed_reserved_record())
        self.assertEqual(result["evidence_classification"], CLASS_NON_FINAL)
        self.assertEqual(result["dispute_resolution"], RESOLUTION_NON_FINAL)
        self.assertEqual(result["evidence_status"], STATUS_INSUFFICIENT)
        self.assertIn("authoritative_state_not_final", result["review_reason"])

    def test_missing_record_is_not_verifiable_in_every_failure_mode(self):
        for status in (RETRIEVAL_NOT_FOUND, RETRIEVAL_FAILED, RETRIEVAL_NOT_ATTEMPTED):
            result = classify_dispute_evidence(None, retrieval_status=status, dataset_claim_text="")
            self.assertEqual(result["official_record_position"], POSITION_NO_RECORD)
            self.assertEqual(result["dispute_resolution"], RESOLUTION_NOT_VERIFIABLE)
            self.assertEqual(result["resolution_bucket"], BUCKET_NOT_VERIFIABLE)
            self.assertEqual(result["evidence_classification"], CLASS_NONE)
            self.assertEqual(result["evidence_confidence"], CONFIDENCE_NONE)
            self.assertEqual(result["exclusion_evidence"], EXCLUSION_NOT_EVALUABLE)
            self.assertEqual(result["evidence_status"], STATUS_NOT_VERIFIABLE)

    def test_unknown_retrieval_status_is_rejected(self):
        with self.assertRaises(CveStatusValidationError):
            classify_dispute_evidence(None, retrieval_status="PROBABLY_FINE")

    def test_word_boundary_keeps_undisputed_out_of_dispute_language(self):
        record = disputed_silent_record()
        record["containers"]["cna"]["descriptions"] = [
            {"lang": "en", "value": "This issue is undisputed and well documented."}
        ]
        result = self._classify(record)
        self.assertEqual(result["evidence_classification"], CLASS_SILENT)

    def test_actor_and_subject_rules_cover_documented_phrasings(self):
        cases = [
            ("The vendor has disputed this issue.", "VENDOR_OR_UPSTREAM"),
            ("The software maintainer disputes that this is a vulnerability.", "VENDOR_OR_UPSTREAM"),
            ("disputed by some third parties", "THIRD_PARTY"),
            ("this issue is disputed by CVE because the include is unused", "CNA_OR_ASSIGNER"),
        ]
        for text, expected_actor in cases:
            record = disputed_silent_record()
            record["containers"]["cna"]["descriptions"] = [{"lang": "en", "value": text}]
            result = self._classify(record)
            self.assertEqual(result["dispute_actor"], expected_actor, msg=text)

        record = disputed_silent_record()
        record["containers"]["cna"]["descriptions"] = [
            {"lang": "en", "value": "The vendor reports they have not been able to reproduce the issue."}
        ]
        self.assertEqual(self._classify(record)["dispute_subject"], "BEHAVIOR_OR_REPRODUCIBILITY")

    def test_dataset_claim_text_supplies_actor_when_record_is_tag_only(self):
        result = self._classify(
            disputed_tag_only_record(),
            claim="Example portal allows command execution. NOTE: third parties claim/state this is not an issue.",
        )
        self.assertEqual(result["dispute_actor"], "THIRD_PARTY")
        self.assertEqual(result["dispute_actor_field"], "dataset:summary")

    def test_classify_dataset_rows_keeps_caller_fields(self):
        rows = [
            {
                "cve_id": "CVE-2020-1001",
                "summary": "** DISPUTED ** A claim.",
                "retrieval_status": RETRIEVAL_RETRIEVED,
                "extra": "kept",
            }
        ]
        records = {"CVE-2020-1001": parse_dispute_record(record_bytes(disputed_text_record()))}
        result = classify_dataset_rows(rows, records)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["extra"], "kept")
        self.assertEqual(result[0]["disputed_claim_text"], "A claim.")
        self.assertEqual(result[0]["evidence_classification"], CLASS_DISPUTE_TEXT)


if __name__ == "__main__":
    unittest.main()
