"""Scoring arithmetic, bands and recency boundaries."""

from __future__ import annotations

import pytest

from vulnova import rank


def test_weights_sum_to_fixed_denominator():
    assert rank.denominator_check() == 100
    assert rank.MAX_SCORE == 100
    assert rank.WEIGHTS == {
        "kev_known_exploited": 40,
        "epss_probability": 30,
        "cvss_severity": 20,
        "publication_recency": 10,
    }


def test_bands_are_threshold_name_pairs():
    # regression: mis-unpacking these tuples silently empties every band
    for entry in rank.BANDS:
        assert len(entry) == 2
        assert isinstance(entry[0], int)
        assert isinstance(entry[1], str)
        assert entry[1].startswith("P")


@pytest.mark.parametrize(
    "score,expected",
    [
        (100, "P1_CRITICAL"), (70, "P1_CRITICAL"), (69, "P2_HIGH"),
        (40, "P2_HIGH"), (39, "P3_MODERATE"), (20, "P3_MODERATE"),
        (19, "P4_LOW"), (1, "P4_LOW"), (0, "P5_NONE"),
    ],
)
def test_band_boundaries(score, expected):
    assert rank.band_for(score) == expected


def test_kev_points():
    assert rank.kev_points(True) == 40
    assert rank.kev_points(False) == 0


@pytest.mark.parametrize(
    "probability,points",
    [( None, None), (0.0, 0), (0.01666, 0), (0.01667, 1), (0.5, 15), (1.0, 30)],
)
def test_epss_points_and_low_end_rounding(probability, points):
    assert rank.epss_points(probability) == points


@pytest.mark.parametrize(
    "value,points",
    [(None, None), (0.0, 0), (5.0, 10), (9.74, 19), (9.75, 20), (10.0, 20)],
)
def test_cvss_points_and_rounding_edge(value, points):
    assert rank.cvss_points(value) == points


def test_publication_recency_boundaries():
    assert rank.publication_recency_points("2026-07-18", "2026-10-16") == 10   # 90 days
    assert rank.publication_recency_points("2026-07-17", "2026-10-16") == 9    # 91 days
    assert rank.publication_recency_points("2021-10-17", "2026-10-16") == 0    # 1825 days
    assert rank.publication_recency_points("2021-10-18", "2026-10-16") == 0    # 1824 days
    assert rank.publication_recency_points(None, "2026-10-16") is None


def test_publication_recency_is_monotonically_non_increasing():
    days = ["2026-10-16", "2026-07-18", "2026-01-01", "2024-01-01",
            "2022-01-01", "2021-10-17"]
    points = [rank.publication_recency_points(day, "2026-10-16") for day in days]
    assert points == sorted(points, reverse=True)


def test_publication_recency_never_negative_for_future_publication():
    assert rank.publication_recency_points("2027-01-01", "2026-10-16") == 10


def test_score_is_sum_of_components():
    score = rank.score_cve(
        "CVE-2023-0001",
        reference_date="2026-10-16",
        published="2026-08-01",
        kev_listed=True,
        epss_probability=0.5,
        cvss_value=9.8,
        cvss_version="3.1",
        cvss_source="cvelistv5",
    )
    assert [s.points for s in score.signals] == [40, 15, 20, 10]
    assert score.score == 85
    assert score.band == "P1_CRITICAL"
    assert score.missing_signals == ()
    assert score.kev_listed is True


def test_missing_inputs_score_zero_and_are_named():
    score = rank.score_cve(
        "CVE-2023-0002",
        reference_date="2026-10-16",
        published="2026-10-15",
        kev_listed=False,
        epss_probability=None,
        cvss_value=None,
    )
    assert score.score == 10
    # KEV absence is an observed absence, not a missing input
    assert score.missing_signals == ("epss_probability", "cvss_severity")


def test_score_is_capped_at_denominator():
    score = rank.score_cve(
        "CVE-X",
        reference_date="2026-10-16",
        published="2026-10-15",
        kev_listed=True,
        epss_probability=1.0,
        cvss_value=10.0,
    )
    assert score.score == 100


def test_scoring_is_deterministic():
    kwargs = dict(
        reference_date="2026-10-16", published="2023-01-01", kev_listed=True,
        epss_probability=0.33, cvss_value=8.1, cvss_version="3.1",
        cvss_source="cvelistv5",
    )
    first = rank.score_cve("CVE-A", **kwargs).as_dict()
    second = rank.score_cve("CVE-A", **kwargs).as_dict()
    assert first == second


def test_describe_weights_uses_signal_key():
    weights = rank.describe_weights()
    assert {w["signal"] for w in weights} == set(rank.WEIGHTS)
    assert all("name" not in w for w in weights)
    assert sum(w["max_points"] for w in weights) == 100


def test_method_states_not_a_predictive_model():
    assert "Not a validated predictive model" in rank.METHOD
    assert "provisional" in rank.METHOD.lower()
