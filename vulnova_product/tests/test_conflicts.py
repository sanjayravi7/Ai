"""Source-conflict selection, comparability and preservation."""

from __future__ import annotations

from vulnova.explain import select_cvss


def candidate(obs_id, source="cvelistv5", container="cna", version="3.1",
              value=9.8, org="ACME", status="OBSERVED"):
    return {
        "obs_id": obs_id,
        "cve_id": "CVE-2019-0005",
        "source": source,
        "container": container,
        "version": version,
        "value": value,
        "severity": "CRITICAL",
        "scoring_organization": org,
        "status": status,
        "retrieved_at": "2026-10-17T00:00:00Z",
        "vector": "CVSS:3.1/AV:N",
    }


def test_all_candidates_are_preserved():
    candidates = [
        candidate(1, value=9.8),
        candidate(2, container="adp", org="NVD", value=7.5),
        candidate(3, source="legacy_cve_csv", container="legacy", version="2.0", value=6.8),
    ]
    result = select_cvss(candidates)
    assert len(result["candidates"]) == 3
    assert {c["value"] for c in result["candidates"]} == {9.8, 7.5, 6.8}


def test_cvelistv5_is_selected_over_legacy_even_when_lower():
    result = select_cvss([
        candidate(1, value=5.0),
        candidate(2, source="legacy_cve_csv", container="legacy", version="2.0", value=9.5),
    ])
    assert result["selected"]["source"] == "cvelistv5"
    assert result["selected"]["value"] == 5.0


def test_highest_version_wins_within_a_source():
    result = select_cvss([
        candidate(1, version="3.0", value=6.0),
        candidate(2, version="4.0", value=7.0),
        candidate(3, version="3.1", value=8.0),
    ])
    assert result["selected"]["version"] == "4.0"


def test_cna_precedes_adp_at_the_same_version():
    result = select_cvss([
        candidate(1, container="adp", org="NVD", value=7.5),
        candidate(2, container="cna", org="ACME", value=9.8),
    ])
    assert result["selected"]["container"] == "cna"


def test_conflict_flag_delta_and_comparability():
    result = select_cvss([
        candidate(1, value=9.8),
        candidate(2, container="adp", org="NVD", value=7.5),
    ])
    conflict = result["conflict"]
    assert conflict["has_conflict"] is True
    assert conflict["distinct_values"] == [7.5, 9.8]
    assert conflict["delta"] == 2.3
    assert conflict["comparable"] is True   # both v3.1


def test_mixed_major_versions_are_not_comparable():
    result = select_cvss([
        candidate(1, version="3.1", value=9.8),
        candidate(2, source="legacy_cve_csv", container="legacy", version="2.0", value=6.8),
    ])
    assert result["conflict"]["comparable"] is False
    assert "NOT directly comparable" in result["conflict"]["comparability_note"]


def test_agreement_is_reported_as_no_conflict():
    result = select_cvss([
        candidate(1, value=9.8),
        candidate(2, container="adp", org="NVD", value=9.8),
    ])
    assert result["conflict"]["has_conflict"] is False
    assert result["conflict"]["delta"] == 0.0


def test_no_observed_value():
    result = select_cvss([
        candidate(1, value=None, status="MISSING_FROM_SOURCE"),
    ])
    assert result["selected"] is None
    assert result["conflict"]["has_conflict"] is False


def test_selection_reason_names_the_rule():
    result = select_cvss([candidate(1), candidate(2, container="adp", value=7.5)])
    assert "cvelistv5 before the legacy extract" in result["conflict"]["selection_rule"]
    assert "Selected" in result["conflict"]["selected_reason"]
