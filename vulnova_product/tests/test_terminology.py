"""Guard the ``recency`` → ``publication_recency`` rename.

These tests exist to prove two things at once:

1. the component is *named* ``publication_recency`` wherever it is presented;
2. the rename changed no arithmetic — the golden scores below were produced by
   the pre-rename (Validation 1.1) implementation and must keep passing.
"""

from __future__ import annotations

import pytest

from vulnova import explain, rank

# Score, band and per-component points captured from the Validation 1.1
# implementation before the rename.  Any drift here is an unauthorised scoring
# change, not a terminology change.
GOLDEN = [
    # (kwargs, score, band, points)
    (dict(published="2026-10-15", kev_listed=True, epss_probability=1.0,
          cvss_value=10.0, cvss_version="3.1", cvss_source="cvelistv5"),
     100, "P1_CRITICAL", [40, 30, 20, 10]),
    (dict(published="2026-07-18", kev_listed=True, epss_probability=0.5,
          cvss_value=9.8, cvss_version="3.1", cvss_source="cvelistv5"),
     85, "P1_CRITICAL", [40, 15, 20, 10]),
    (dict(published="2021-01-22", kev_listed=True, epss_probability=0.4,
          cvss_value=7.5, cvss_version="3.1", cvss_source="cvelistv5"),
     67, "P2_HIGH", [40, 12, 15, 0]),
    (dict(published="2015-05-18", kev_listed=True, epss_probability=0.99,
          cvss_value=10.0, cvss_version="3.0", cvss_source="cvelistv5"),
     90, "P1_CRITICAL", [40, 30, 20, 0]),
    (dict(published="2026-10-15", kev_listed=False, epss_probability=None,
          cvss_value=None),
     10, "P4_LOW", [0, 0, 0, 10]),
    (dict(published="2024-01-10", kev_listed=False, epss_probability=None,
          cvss_value=7.5, cvss_version="3.1", cvss_source="cvelistv5"),
     19, "P4_LOW", [0, 0, 15, 4]),
    (dict(published="2025-02-01", kev_listed=False, epss_probability=0.9,
          cvss_value=None),
     33, "P3_MODERATE", [0, 27, 0, 6]),
    (dict(published=None, kev_listed=False, epss_probability=None, cvss_value=None),
     0, "P5_NONE", [0, 0, 0, 0]),
]


@pytest.mark.parametrize("kwargs,score,band,points", GOLDEN)
def test_golden_scores_unchanged_by_rename(kwargs, score, band, points):
    result = rank.score_cve("CVE-GOLDEN", reference_date="2026-10-16", **kwargs)
    assert result.score == score
    assert result.band == band
    assert [s.points for s in result.signals] == points


def test_weights_use_the_presented_name():
    assert rank.WEIGHTS["publication_recency"] == 10
    assert "recency" not in rank.WEIGHTS          # exact key, not a substring
    assert rank.denominator_check() == 100


def test_signal_is_named_publication_recency():
    result = rank.score_cve(
        "CVE-T", reference_date="2026-10-16", published="2026-01-01"
    )
    names = [s.name for s in result.signals]
    assert names == [
        "kev_known_exploited", "epss_probability", "cvss_severity",
        "publication_recency",
    ]
    assert "recency" not in names


def test_signal_detail_states_the_three_exclusions():
    result = rank.score_cve(
        "CVE-T", reference_date="2026-10-16", published="2026-01-01"
    )
    detail = next(s.detail for s in result.signals if s.name == "publication_recency")
    assert "CVE published 2026-01-01" in detail
    assert "does not represent recent exploitation activity" in detail
    assert "recent KEV inclusion" in detail
    assert "independently verified increase in threat activity" in detail


def test_missing_signals_uses_the_new_name():
    result = rank.score_cve("CVE-T", reference_date="2026-10-16", published=None)
    assert "publication_recency" in result.missing_signals
    assert "recency" not in result.missing_signals


def test_method_text_says_publication_recency():
    assert "publication recency" in rank.METHOD
    assert "Not a validated predictive model" in rank.METHOD


def test_explanation_names_the_component_and_its_limits(conn):
    payload = explain.explain_one(conn, "CVE-2019-0005")
    names = [s["name"] for s in payload["priority"]["signals"]]
    assert "publication_recency" in names
    assert "recency" not in names

    context = payload["publication_recency_context"]
    assert context["component"] == "publication_recency"
    assert context["component_basis"] == "publication_date"
    assert len(context["does_not_represent"]) == 3
    assert "recency_context" not in payload


def test_no_bare_recency_component_name_leaks(conn):
    """No presentation surface may call the component plain ``recency``."""
    payload = explain.explain_one(conn, "CVE-2019-0005")
    for signal in payload["priority"]["signals"]:
        assert signal["name"] != "recency"
    assert "recency" not in payload["priority"]["missing_signals"]
    assert "recency" not in [w["signal"] for w in rank.describe_weights()]
