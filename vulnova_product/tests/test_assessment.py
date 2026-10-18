"""Evidence adequacy: the six required cases plus wording guards."""

from __future__ import annotations

import pytest

from vulnova import assessment


def _assess(**kwargs):
    defaults = dict(has_cvss=False, has_epss=False, kev_listed=False,
                    score=10, band="P4_LOW")
    defaults.update(kwargs)
    return assessment.assess(**defaults)


def test_neither_cvss_nor_epss_is_insufficient_and_review_required():
    result = _assess(has_cvss=False, has_epss=False)
    assert result["status"] == assessment.INSUFFICIENT
    assert result["review_required"] is True
    assert result["missing"] == ["cvss_severity", "epss_probability"]
    assert "INSUFFICIENT EVIDENCE" in result["display_band"]


def test_cvss_only_is_partial_and_does_not_require_review():
    result = _assess(has_cvss=True, has_epss=False)
    assert result["status"] == assessment.PARTIAL
    assert result["review_required"] is False
    assert result["missing"] == ["epss_probability"]
    assert "likelihood is unknown" in result["statement"]


def test_epss_only_is_partial_and_does_not_require_review():
    result = _assess(has_cvss=False, has_epss=True)
    assert result["status"] == assessment.PARTIAL
    assert result["review_required"] is False
    assert result["missing"] == ["cvss_severity"]
    assert "severity and impact are unknown" in result["statement"]


def test_both_signals_are_sufficient():
    result = _assess(has_cvss=True, has_epss=True, score=85, band="P1_CRITICAL")
    assert result["status"] == assessment.SUFFICIENT
    assert result["review_required"] is False
    assert result["missing"] == []
    assert result["display_band"] == "P1_CRITICAL"


def test_kev_membership_with_no_signals_still_insufficient():
    result = _assess(kev_listed=True, score=50, band="P2_HIGH")
    assert result["status"] == assessment.INSUFFICIENT
    assert result["review_required"] is True
    assert "KEV membership (40 points)" in result["statement"]
    assert "not a judgement that this vulnerability is low risk" in result["statement"]


def test_insufficient_statement_never_asserts_low_risk():
    result = _assess()
    lowered = result["statement"].lower()
    assert "not an assessment that this vulnerability is low risk" in lowered
    # the unqualified claim must not appear
    assert "vulnerability is low risk" in lowered  # only as part of the negation
    assert lowered.count("low risk") == 1


def test_denominator_is_never_rescaled():
    for kwargs in (
        dict(has_cvss=False, has_epss=False),
        dict(has_cvss=True, has_epss=False),
        dict(has_cvss=False, has_epss=True),
        dict(has_cvss=True, has_epss=True),
    ):
        assert _assess(**kwargs)["denominator_rescaled"] is False


def test_numeric_band_is_preserved_verbatim():
    result = _assess(has_cvss=False, has_epss=False, score=10, band="P4_LOW")
    assert result["numeric_band"] == "P4_LOW"
    assert result["display_band"] == "P4_LOW (INSUFFICIENT EVIDENCE)"


@pytest.mark.parametrize("kev", [True, False])
def test_status_label_is_human_readable(kev):
    result = _assess(kev_listed=kev)
    assert result["label"].startswith("Insufficient evidence")
