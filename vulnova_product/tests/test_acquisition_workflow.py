"""End-to-end workflow behaviour with a fully canned environment."""

from __future__ import annotations

import datetime as dt

from vulnova.acquisition import constants as C
from vulnova.acquisition.manifest import validate_schema
from vulnova.acquisition.verify import check_coverage, verify_manifest
from vulnova.acquisition.workflow import (
    AcquisitionOptions,
    POLICIES,
    load_reference_pins,
    run_acquisition,
)

from tests.acquisition_fixtures import (
    CUTOFFS,
    CVE_PINS,
    GRID,
    KEV_HISTORY,
    RUN_AT,
    build_scenario,
    commit_payload,
    cve_url,
    epss_url,
    kev_catalog_bytes,
)


def _run(scenario, *, reference=None, cutoffs=CUTOFFS, grid=GRID, clock=RUN_AT):
    options = AcquisitionOptions(
        store=scenario.store,
        transport=scenario.transport,
        api=scenario.api,
        cutoffs=cutoffs,
        grid=grid,
        clock=lambda: clock,
        reference=reference,
    )
    return run_acquisition(options)


def test_full_run_produces_a_valid_manifest(tmp_path):
    scenario = build_scenario(tmp_path)
    manifest = _run(scenario)
    assert validate_schema(manifest) == []
    assert manifest["schema_version"] == C.SCHEMA_VERSION
    assert manifest["as_of"] == "2026-10-20"
    assert manifest["cutoffs"] == sorted(day.isoformat() for day in CUTOFFS)


def test_manifest_digest_is_deterministic_for_the_same_inputs(tmp_path):
    first = _run(build_scenario(tmp_path / "a"))
    second = _run(build_scenario(tmp_path / "b"))
    assert first["manifest_digest"] == second["manifest_digest"]


def test_manifest_digest_changes_when_a_retrieval_time_changes(tmp_path):
    first = _run(build_scenario(tmp_path / "a"))
    scenario = build_scenario(tmp_path / "b")
    day = CUTOFFS[0]
    sha, committed, tree = CVE_PINS[day.isoformat()]
    scenario.transport.add_json(
        cve_url(day),
        [commit_payload(sha, committed, tree)],
        retrieved_at="2026-10-21T10:00:00Z",
    )
    second = _run(scenario)
    assert first["manifest_digest"] != second["manifest_digest"]


def test_epss_outage_is_unavailable_and_never_green(tmp_path):
    manifest = _run(build_scenario(tmp_path, epss_available=False))
    epss_requirements = [
        item for item in manifest["requirements"] if item["id"].startswith("EPSS-")
    ]
    assert epss_requirements
    assert all(item["status"] == C.UNAVAILABLE for item in epss_requirements)
    assert all(
        item["reason_code"] == C.OFFICIAL_SOURCE_UNREACHABLE for item in epss_requirements
    )


def test_direct_cisa_feed_failure_is_reported_separately(tmp_path):
    manifest = _run(build_scenario(tmp_path, cisa_feed_available=False))
    direct = next(
        item for item in manifest["requirements"] if item["id"] == "KEV-01_DIRECT_CISA_FEED"
    )
    assert direct["status"] == C.UNAVAILABLE
    current = next(
        item for item in manifest["requirements"] if item["id"] == "KEV-02_CURRENT_CATALOG"
    )
    assert current["status"] == C.VERIFIED
    assert C.CHANNEL_OFFICIAL_GITHUB in current["detail"]


def test_historical_retrieval_requirements_are_blocked_not_verified(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    for requirement_id in (
        "CVE-03_HISTORICAL_RETRIEVAL_PROVENANCE",
        "KEV-05_HISTORICAL_RETRIEVAL_PROVENANCE",
    ):
        requirement = next(
            item for item in manifest["requirements"] if item["id"] == requirement_id
        )
        assert requirement["status"] == C.BLOCKED
        assert requirement["reason_code"] == C.RETRIEVAL_NOT_CONTEMPORANEOUS


def test_content_requirements_can_be_verified_independently(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    content_ids = (
        "CVE-01_REVISION_PIN_RESOLVED",
        "KEV-03_HISTORICAL_REVISION_AT_CUTOFF",
    )
    for requirement_id in content_ids:
        requirement = next(
            item for item in manifest["requirements"] if item["id"] == requirement_id
        )
        assert requirement["status"] == C.VERIFIED, requirement


def test_final_block_labels_are_not_observable_before_2026_10_28(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    observations = manifest["label_observations"]
    final = observations[C.FINAL_CANDIDATE_CUTOFF.isoformat()]
    assert final["maturity_date"] == "2026-10-28"
    assert final["matured_at_as_of"] is False
    assert final["catalog_covers_maturity"] is False
    assert final["status"] == C.BLOCKED
    assert final["reason_code"] == C.CATALOG_PREDATES_MATURITY


def test_earlier_blocks_cover_maturity_but_still_record_the_access_lag(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    first = manifest["label_observations"]["2025-02-01"]
    assert first["maturity_date"] == "2025-08-30"
    assert first["catalog_covers_maturity"] is True
    assert first["status"] == C.VERIFIED
    assert first["filter_basis"] == "dateAdded <= maturity_date"


def test_no_requirement_claims_protocol_approval(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    assert manifest["policies"]["protocol_approval"].endswith("NOT_APPROVED and unamended.")
    for requirement in manifest["requirements"]:
        assert "APPROVED" not in requirement["status"]
        assert "approval" not in requirement["detail"].lower()


def test_provenance_requirement_records_the_maturity_date_and_the_remaining_days(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    requirement = next(
        item
        for item in manifest["requirements"]
        if item["id"] == "PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED"
    )
    evidence = requirement["evidence"]
    assert evidence["final_candidate_maturity"] == "2026-10-28"
    assert evidence["maturity_claimed"] is False
    assert evidence["fresh_evidence_required_after_maturity"] is True
    assert "8 days remaining" in requirement["detail"]


def test_after_maturity_the_requirement_still_requires_fresh_evidence(tmp_path):
    manifest = _run(build_scenario(tmp_path), clock="2026-10-29T00:00:00Z")
    requirement = next(
        item
        for item in manifest["requirements"]
        if item["id"] == "PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED"
    )
    assert requirement["status"] == C.VERIFIED
    assert requirement["evidence"]["maturity_claimed"] is False
    assert requirement["evidence"]["fresh_evidence_required_after_maturity"] is True
    # The catalog still predates the maturity date, so block 3 stays blocked.
    final = manifest["label_observations"][C.FINAL_CANDIDATE_CUTOFF.isoformat()]
    assert final["status"] == C.BLOCKED
    assert final["reason_code"] == C.CATALOG_PREDATES_MATURITY


def test_policies_state_the_non_negotiable_rules():
    assert "never" in POLICIES["kev_absence"].lower()
    assert "never" in POLICIES["epss_substitution"].lower()
    assert "never" in POLICIES["mirrors"].lower()
    assert "2026-10-28" in POLICIES["maturity"]
    assert "No model" in POLICIES["model_training"]


def test_summary_counts_every_record_once(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    summary = manifest["summary"]
    assert summary["records"] == len(manifest["records"])
    assert sum(summary["by_content_status"].values()) == summary["records"]
    assert sum(summary["by_access_provenance"].values()) == summary["records"]


def test_manifest_verifies_offline(tmp_path):
    scenario = build_scenario(tmp_path)
    manifest = _run(scenario)
    verification = verify_manifest(manifest, scenario.store)
    assert verification["status"] == C.VERIFIED
    assert verification["summary"]["network_used"] is False
    assert verification["summary"]["artifacts_hashed"] >= 4


def test_coverage_matrix_names_every_source_and_cutoff(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    coverage = check_coverage(manifest)
    assert len(coverage["rows"]) == 3 * 3
    assert coverage["missing"] == []
    assert coverage["unverified"]


def test_missing_epss_makes_coverage_unverified_but_not_missing(tmp_path):
    manifest = _run(build_scenario(tmp_path, epss_available=False))
    coverage = check_coverage(manifest)
    assert coverage["status"] == C.UNAVAILABLE
    assert {row["source"] for row in coverage["unverified"]} == {"epss"}


def test_cutoff_outside_the_grid_is_reported(tmp_path):
    scenario = build_scenario(tmp_path)
    manifest = _run(scenario, cutoffs=CUTOFFS, grid=(CUTOFFS[0],))
    verification = verify_manifest(manifest, scenario.store)
    check = next(item for item in verification["checks"] if item["id"] == "CUTOFFS_IN_GRID")
    assert check["status"] == C.BLOCKED


def _write_reference(tmp_path, *, cve_override=None):
    import csv
    import hashlib

    root = tmp_path / "reference"
    (root / "raw").mkdir(parents=True)
    with open(root / "cvelistv5_inventory_manifest.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["cutoff_T", "resolution", "revision_sha", "revision_committer_iso"]
        )
        writer.writeheader()
        for day, (sha, committed, _tree) in CVE_PINS.items():
            writer.writerow(
                {
                    "cutoff_T": day,
                    "resolution": "RESOLVED",
                    "revision_sha": sha if cve_override is None else cve_override,
                    "revision_committer_iso": committed,
                }
            )
    with open(root / "raw" / "kev_revisions.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["commit_sha", "commit_date", "content_sha256", "catalog_version", "date_released"],
        )
        writer.writeheader()
        for day, (sha, committed, version, released, count) in KEV_HISTORY.items():
            body = kev_catalog_bytes(version, released, count=min(count, 5))
            writer.writerow(
                {
                    "commit_sha": sha,
                    "commit_date": committed,
                    "content_sha256": hashlib.sha256(body).hexdigest(),
                    "catalog_version": version,
                    "date_released": released,
                }
            )
    (root / "cutoffs.txt").write_text(
        "\n".join(day.isoformat() for day in CUTOFFS) + "\n", encoding="utf-8"
    )
    return root


def test_reference_pins_cross_check_verifies_when_they_match(tmp_path):
    pins = load_reference_pins(_write_reference(tmp_path))
    assert pins.grid == CUTOFFS
    manifest = _run(build_scenario(tmp_path / "scenario"), reference=pins)
    requirement = next(
        item for item in manifest["requirements"] if item["id"] == "CVE-02_PIN_CROSSCHECK"
    )
    assert requirement["status"] == C.VERIFIED
    kev_requirement = next(
        item for item in manifest["requirements"] if item["id"] == "KEV-03_HISTORICAL_REVISION_AT_CUTOFF"
    )
    assert kev_requirement["status"] == C.VERIFIED


def test_reference_pin_disagreement_is_blocked_not_silently_preferred(tmp_path):
    pins = load_reference_pins(_write_reference(tmp_path, cve_override="0" * 40))
    manifest = _run(build_scenario(tmp_path / "scenario"), reference=pins)
    requirement = next(
        item for item in manifest["requirements"] if item["id"] == "CVE-02_PIN_CROSSCHECK"
    )
    assert requirement["status"] == C.BLOCKED
    assert requirement["reason_code"] == C.PIN_CONFLICT


def test_reference_content_hash_mismatch_is_blocked(tmp_path):
    root = _write_reference(tmp_path)
    # Corrupt one recorded content hash.
    import csv

    path = root / "raw" / "kev_revisions.csv"
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    rows[0]["content_sha256"] = "f" * 64
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    pins = load_reference_pins(root)
    manifest = _run(build_scenario(tmp_path / "scenario"), reference=pins)
    blocked = [
        record
        for record in manifest["records"]
        if record["source"] == "kev" and record["reason_code"] == C.SHA256_MISMATCH
    ]
    assert blocked


def test_manifest_holds_timestamps_for_every_retrieved_artifact(tmp_path):
    manifest = _run(build_scenario(tmp_path))
    for record in manifest["records"]:
        if record["access_provenance"] == C.NOT_RETRIEVED:
            assert record["retrieved_at"] is None
        else:
            assert record["retrieved_at"]
            stamp = record["retrieved_at"]
            dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def test_a_mirror_never_drags_a_satisfied_epss_requirement_down(tmp_path):
    manifest = _run(build_scenario(tmp_path, epss_available=True))
    epss = next(
        item for item in manifest["requirements"] if item["id"] == "EPSS-01_EXACT_DAILY_FILE"
    )
    assert epss["status"] == C.VERIFIED
    assert epss["evidence"]["mirrors_satisfy_requirement"] is False
    assert len(epss["evidence"]["third_party_mirrors"]) == len(CUTOFFS)


def test_failed_attempts_are_not_reported_as_late_retrievals(tmp_path):
    manifest = _run(build_scenario(tmp_path, epss_available=False))
    for record in manifest["records"]:
        if record["source"] == "epss" and record["channel"] == C.CHANNEL_OFFICIAL:
            assert record["sha256"] is None
            assert record["access_provenance"] == C.NOT_RETRIEVED


def test_a_refused_redirect_blocks_the_requirement_without_claiming_an_outage(tmp_path):
    """A policy refusal must not look like a publisher that failed to answer."""
    scenario = build_scenario(tmp_path, epss_available=False)
    for day in CUTOFFS:
        scenario.transport.add_error(
            epss_url(day), reason="DISALLOWED_REDIRECT_HOST", status=302
        )
    manifest = _run(scenario)
    requirement = next(
        item for item in manifest["requirements"] if item["id"] == "EPSS-01_EXACT_DAILY_FILE"
    )
    assert requirement["status"] == C.BLOCKED
    assert requirement["reason_code"] == C.REDIRECT_BLOCKED
    assert requirement["reason_code"] != C.OFFICIAL_SOURCE_UNREACHABLE
    for record in manifest["records"]:
        if record["source"] == "epss" and record["channel"] == C.CHANNEL_OFFICIAL:
            assert record["reason_code"] == C.REDIRECT_BLOCKED
