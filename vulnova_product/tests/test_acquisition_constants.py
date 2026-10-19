"""The acquisition vocabulary must not drift from the evaluation contract."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from vulnova.acquisition import constants as A
from vulnova.evaluation import constants as E

PRODUCT_ROOT = Path(__file__).resolve().parents[1]


def test_only_three_statuses_exist():
    assert A.STATUSES == ("VERIFIED", "UNAVAILABLE", "BLOCKED")


def test_worst_is_blocked_biased():
    assert A.worst([A.VERIFIED, A.VERIFIED]) == A.VERIFIED
    assert A.worst([A.VERIFIED, A.UNAVAILABLE]) == A.UNAVAILABLE
    assert A.worst([A.UNAVAILABLE, A.BLOCKED]) == A.BLOCKED
    assert A.worst([]) == A.BLOCKED


def test_temporal_rules_are_imported_not_redefined():
    assert A.HORIZON_DAYS == E.HORIZON_DAYS == 180
    assert A.MATURITY_LAG_DAYS == E.MATURITY_LAG_DAYS == 30
    assert A.MATURITY_SPAN_DAYS == E.MATURITY_SPAN_DAYS == 210
    assert A.REQUIRED_DISTINCT_TEST_EVENTS == E.REQUIRED_DISTINCT_TEST_EVENTS == 30
    assert A.REQUIRED_SEQUENTIAL_BLOCKS == E.REQUIRED_SEQUENTIAL_BLOCKS == 3


def test_candidate_cutoffs_are_the_frozen_three():
    assert A.CANDIDATE_CUTOFFS == (
        dt.date(2025, 2, 1),
        dt.date(2025, 9, 1),
        dt.date(2026, 4, 1),
    )
    assert A.FINAL_CANDIDATE_CUTOFF == dt.date(2026, 4, 1)


def test_final_candidate_matures_on_2026_10_28():
    assert A.final_candidate_maturity() == dt.date(2026, 10, 28)
    assert A.cutoff_maturity(dt.date(2025, 2, 1)) == dt.date(2025, 8, 30)
    assert A.cutoff_maturity(dt.date(2025, 9, 1)) == dt.date(2026, 3, 30)


def test_every_reason_code_has_a_description():
    codes = {
        value
        for name, value in vars(A).items()
        if name.isupper()
        and isinstance(value, str)
        and value not in A.ACCESS_PROVENANCE_VALUES
        and value not in A.STATUSES
        and value not in A.TRUSTED_CHANNELS
        and not value.startswith("vulnova")
        and not value.startswith("Historical")
    }
    missing = sorted(code for code in codes if code not in A.REASON_DESCRIPTIONS)
    # Descriptive constants (schema version, phase title, OK/HTTP words) are not
    # reason codes; only dotted-underscore identifiers are.
    missing = [code for code in missing if code.startswith(("RETRIEVAL", "ARTIFACT", "EPSS", "KEV"))]
    assert missing == []


def test_schema_version_names_the_phase():
    assert A.SCHEMA_VERSION == "vulnova.acquisition/1.7"


def test_third_party_mirror_is_not_trusted():
    assert A.CHANNEL_THIRD_PARTY_MIRROR not in A.TRUSTED_CHANNELS
    assert A.CHANNEL_OFFICIAL in A.TRUSTED_CHANNELS
    assert A.CHANNEL_OFFICIAL_GITHUB in A.TRUSTED_CHANNELS


def test_package_is_importable_from_the_product_root():
    assert (PRODUCT_ROOT / "vulnova" / "acquisition" / "__init__.py").is_file()
