"""The committed 1.7 acquisition archive must verify from the repository alone.

Like ``test_evaluation_repository_report.py`` for the readiness report, this test
guards the committed deliverable rather than a synthetic fixture. It performs no
network I/O: it re-hashes the committed bytes and re-derives access provenance
from the committed manifest.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.acquisition import constants as C
from vulnova.acquisition.manifest import manifest_digest
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.verify import check_coverage, verify_manifest

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PRODUCT_ROOT / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
STORE_PATH = PRODUCT_ROOT / "data" / "acquisition_store"
REPORT_PATH = PRODUCT_ROOT / "reports" / "acquisition_1_7" / "DATA_ACQUISITION_1_7_REPORT.md"

pytestmark = pytest.mark.skipif(
    not MANIFEST_PATH.is_file() or not STORE_PATH.is_dir(),
    reason="committed acquisition manifest or store is absent",
)


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_committed_manifest_is_digest_consistent():
    manifest = _manifest()
    assert manifest["schema_version"] == C.SCHEMA_VERSION
    assert manifest_digest(manifest) == manifest["manifest_digest"]


def test_committed_artifacts_reverify_offline():
    result = verify_manifest(_manifest(), ArtifactStore(STORE_PATH))
    assert result["status"] == C.VERIFIED, [
        check for check in result["checks"] if check["status"] != C.VERIFIED
    ]
    assert result["summary"]["network_used"] is False
    assert result["summary"]["artifacts_hashed"] >= 7


def test_committed_run_covers_every_required_source_and_cutoff():
    coverage = check_coverage(_manifest())
    assert coverage["missing"] == []
    assert coverage["cutoffs_outside_grid"] == []


def test_committed_run_never_claims_contemporaneous_historical_access():
    manifest = _manifest()
    for record in manifest["records"]:
        if record["access_provenance"] == C.CONTEMPORANEOUS and record["cutoff"]:
            # Only a cutoff reached on or before its own cutoff could qualify,
            # and no 2025-2026 cutoff can be reached from a later acquisition.
            assert record["retrieved_at"] <= record["cutoff"] + "T00:00:00Z"


def test_committed_run_does_not_claim_final_block_maturity():
    manifest = _manifest()
    final = manifest["label_observations"][C.FINAL_CANDIDATE_CUTOFF.isoformat()]
    assert final["maturity_date"] == "2026-10-28"
    if not final["matured_at_as_of"]:
        assert final["status"] != C.VERIFIED
    requirement = next(
        item
        for item in manifest["requirements"]
        if item["id"] == "PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED"
    )
    assert requirement["evidence"]["maturity_claimed"] is False
    assert requirement["evidence"]["fresh_evidence_required_after_maturity"] is True


def test_committed_manifest_records_the_unavailable_sources_honestly():
    manifest = _manifest()
    by_id = {item["id"]: item for item in manifest["requirements"]}
    assert by_id["EPSS-01_EXACT_DAILY_FILE"]["status"] == C.UNAVAILABLE
    if by_id["KEV-01_DIRECT_CISA_FEED"]["status"] != C.VERIFIED:
        assert by_id["KEV-01_DIRECT_CISA_FEED"]["reason_code"] in (
            C.OFFICIAL_SOURCE_UNREACHABLE,
            C.HTTP_ERROR,
        )
    assert by_id["CVE-03_HISTORICAL_RETRIEVAL_PROVENANCE"]["status"] == C.BLOCKED


def test_tampering_with_the_committed_store_would_be_caught(tmp_path):
    """A restored copy that has been altered must fail exactly like a live one."""
    import shutil

    manifest = _manifest()
    target = tmp_path / "store"
    shutil.copytree(STORE_PATH, target)
    record = next(item for item in manifest["records"] if item["artifact_path"])
    path = target.joinpath(*record["artifact_path"].split("/"))
    path.write_bytes(path.read_bytes() + b"\n")
    result = verify_manifest(manifest, ArtifactStore(target))
    assert result["status"] == C.BLOCKED


def test_committed_report_exists_and_states_the_same_digest():
    if not REPORT_PATH.is_file():
        pytest.skip("committed Markdown report is absent")
    text = REPORT_PATH.read_text(encoding="utf-8")
    assert _manifest()["manifest_digest"] in text
    assert "Missing or blocked evidence" in text
