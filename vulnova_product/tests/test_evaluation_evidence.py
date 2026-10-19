"""The mandatory three-state KEV evidence classification."""

from __future__ import annotations

import datetime as dt

from vulnova.evaluation.evidence import (
    ABSENCE_INTERPRETATION,
    KevEvidence,
    absence_is_proof_of_non_exploitation,
    classification_vocabulary,
    classify_kev_evidence,
)

DAY = dt.date(2025, 2, 1)
REVISION = "b3b7d34318e4f6d1de4e082d03ea21984ff2f176"


def test_confirmed_inclusion_requires_observed_membership():
    result = classify_kev_evidence(
        "CVE-2024-0001",
        observed_at=DAY,
        catalogue_revision=REVISION,
        revision_available=True,
        revision_readable=True,
        membership_ids={"CVE-2024-0001", "CVE-2024-0002"},
    )
    assert result.status is KevEvidence.CONFIRMED_KEV_INCLUSION
    assert result.supports_positive_label is True
    assert result.supports_negative_label is False
    assert result.reason == "LISTED_IN_OBSERVED_CATALOG_REVISION"


def test_absence_from_kev_is_not_non_exploitation():
    result = classify_kev_evidence(
        "CVE-2024-0003",
        observed_at=DAY,
        catalogue_revision=REVISION,
        revision_available=True,
        revision_readable=True,
        membership_ids={"CVE-2024-0001"},
    )
    assert result.status is KevEvidence.ABSENT_FROM_KEV
    assert result.supports_positive_label is False
    assert result.supports_negative_label is False
    assert absence_is_proof_of_non_exploitation() is False
    assert "not evidence" in result.detail
    assert "not proof of non-exploitation" in ABSENCE_INTERPRETATION


def test_missing_revision_is_missing_evidence_not_absence():
    result = classify_kev_evidence(
        "CVE-2024-0003",
        observed_at=DAY,
        catalogue_revision=None,
        revision_available=False,
        revision_readable=False,
        membership_ids=None,
    )
    assert result.status is KevEvidence.MISSING_HISTORICAL_EVIDENCE
    assert result.reason == "NO_CATALOG_REVISION_AVAILABLE"
    assert result.supports_positive_label is False
    assert result.supports_negative_label is False


def test_unreadable_or_truncated_revision_is_missing_evidence():
    result = classify_kev_evidence(
        "CVE-2024-0003",
        observed_at=DAY,
        catalogue_revision="a7fa9428cc131b160e2edddc42693a45f6ce44ed",
        revision_available=True,
        revision_readable=False,
        membership_ids={"CVE-2024-0001"},
    )
    assert result.status is KevEvidence.MISSING_HISTORICAL_EVIDENCE
    assert result.reason == "CATALOG_REVISION_UNREADABLE"


def test_unknown_membership_is_missing_even_if_revision_claims_readable():
    result = classify_kev_evidence(
        "CVE-2024-0003",
        observed_at=DAY,
        catalogue_revision=REVISION,
        revision_available=True,
        revision_readable=True,
        membership_ids=None,
    )
    assert result.status is KevEvidence.MISSING_HISTORICAL_EVIDENCE


def test_classification_vocabulary_spells_out_both_prohibitions():
    vocabulary = classification_vocabulary()
    assert set(vocabulary) == {
        "CONFIRMED_KEV_INCLUSION",
        "ABSENT_FROM_KEV",
        "MISSING_HISTORICAL_EVIDENCE",
        "absence_is_proof_of_non_exploitation",
    }
    assert vocabulary["ABSENT_FROM_KEV"]["can_support_negative_label"] is False
    assert vocabulary["MISSING_HISTORICAL_EVIDENCE"][
        "can_support_negative_label"
    ] is False
    assert vocabulary["absence_is_proof_of_non_exploitation"] is False


def test_assessment_serializes_without_creating_a_negative_label():
    result = classify_kev_evidence(
        "CVE-2024-0004",
        observed_at=DAY,
        catalogue_revision=REVISION,
        revision_available=True,
        revision_readable=True,
        membership_ids=set(),
    )
    payload = result.as_dict()
    assert payload["status"] == "ABSENT_FROM_KEV"
    assert payload["supports_negative_label"] is False
    assert payload["supports_positive_label"] is False
