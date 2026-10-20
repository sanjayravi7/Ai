"""Prospective capture must leave every sealed historical artifact untouched.

The 1.9 subsystem hashes the sealed 1.7 archive as part of verification, and the
write-safety guard treats it as read-only.  These tests measure that, rather than
trusting it: the archive fingerprint is taken before and after a capture, a
verify and a report, and compared.  A synthetic archive exercises the failure
paths without ever touching the real one.
"""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from vulnova.acquisition import constants as A
from vulnova.prospective import constants as C
from vulnova.prospective.capture import run_capture
from vulnova.prospective.report import build_report, write_json
from vulnova.prospective.verify import verify_failure_reasons, verify_store
from vulnova.refresh.workflow import archive_fingerprint

from tests.prospective_fixtures import build_scenario

PRODUCT = Path(__file__).resolve().parents[1]
MANIFEST = PRODUCT / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
ARCHIVE_STORE = PRODUCT / "data" / "acquisition_store"
REFRESH_REPORT = PRODUCT / "reports" / "refresh_1_8" / "refresh_report.json"


def _fingerprint() -> dict:
    return archive_fingerprint(MANIFEST, ARCHIVE_STORE)


def _file_hashes() -> dict[str, str]:
    return {
        str(path.relative_to(PRODUCT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((PRODUCT / "reports").rglob("*"))
        if path.is_file()
    }


def test_the_offline_guard_is_active():
    with pytest.raises(AssertionError):
        socket.create_connection(("cisa.gov", 443), timeout=0.01)
    with pytest.raises(AssertionError):
        socket.socket().connect(("epss.empiricalsecurity.com", 443))


def test_a_capture_does_not_change_the_sealed_archive(tmp_path):
    before = _fingerprint()
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    verify_store(scenario.store_root)
    build_report(scenario.store_root)
    assert _fingerprint() == before


def test_a_capture_does_not_touch_any_committed_report(tmp_path):
    before = _file_hashes()
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    verify_store(scenario.store_root)
    build_report(scenario.store_root)
    assert _file_hashes() == before


def test_the_sealed_1_7_archive_still_verifies_in_this_checkout(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    result = verify_store(scenario.store_root)
    check = next(item for item in result["checks"] if item["id"] == "HISTORICAL_ARCHIVE")
    assert check["status"] == A.VERIFIED
    assert "7 sealed 1.7 artifact(s)" in check["detail"]


def test_the_1_8_report_is_byte_identical_after_a_capture(tmp_path):
    before = hashlib.sha256(REFRESH_REPORT.read_bytes()).hexdigest()
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    after = hashlib.sha256(REFRESH_REPORT.read_bytes()).hexdigest()
    assert before == after


# ------------------------------------------------ synthetic archive outcomes
def _fake_product(tmp_path: Path) -> tuple[Path, Path]:
    product = tmp_path / "product"
    repository = tmp_path / "repository"
    store = product / "data" / "acquisition_store"
    artifact = store / "artifacts" / "kev" / "current.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b'{"catalogVersion": "2026.10.16"}\n')
    manifest = product / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "source": "kev",
                        "key": "current",
                        "artifact_path": "artifacts/kev/current.json",
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    }
                ]
            }
        )
    )
    repository.mkdir()
    return product, repository


def _verify_with_fake_roots(tmp_path, monkeypatch) -> dict:
    # The scenario owns ``tmp_path``, so build it first and give the synthetic
    # product its own directory.
    scenario = build_scenario(tmp_path)
    product, repository = _fake_product(tmp_path / "sealed")
    monkeypatch.setattr(
        "vulnova.prospective.verify.package_roots", lambda: (product, repository)
    )
    run_capture(scenario.options())
    return verify_store(scenario.store_root)


def test_a_synthetic_sealed_archive_that_matches_is_verified(tmp_path, monkeypatch):
    result = _verify_with_fake_roots(tmp_path, monkeypatch)
    check = next(item for item in result["checks"] if item["id"] == "HISTORICAL_ARCHIVE")
    assert check["status"] == A.VERIFIED


def test_a_changed_sealed_artifact_fails_verification(tmp_path, monkeypatch):
    scenario = build_scenario(tmp_path)
    product, _repository = _fake_product(tmp_path / "sealed")
    monkeypatch.setattr(
        "vulnova.prospective.verify.package_roots", lambda: (product, _repository)
    )
    run_capture(scenario.options())
    artifact = product / "data" / "acquisition_store" / "artifacts" / "kev" / "current.json"
    artifact.write_bytes(b"changed")

    result = verify_store(scenario.store_root)
    assert result["status"] == A.BLOCKED
    assert "HISTORICAL_ARCHIVE" in verify_failure_reasons(result)


def test_no_committed_archive_is_not_applicable_not_a_pass(tmp_path, monkeypatch):
    scenario = build_scenario(tmp_path)
    empty_product = tmp_path / "empty-product"
    empty_product.mkdir()
    monkeypatch.setattr(
        "vulnova.prospective.verify.package_roots",
        lambda: (empty_product, tmp_path),
    )
    run_capture(scenario.options())
    result = verify_store(scenario.store_root)

    check = next(item for item in result["checks"] if item["id"] == "HISTORICAL_ARCHIVE")
    assert check["status"] == "NOT_APPLICABLE"
    # Not applicable never means failed: verification of *this* store still holds.
    assert result["status"] == A.VERIFIED


def test_a_report_written_by_the_cli_does_not_land_in_the_archive(tmp_path):
    scenario = build_scenario(tmp_path)
    run_capture(scenario.options())
    report = build_report(scenario.store_root)
    out = tmp_path / "report.json"
    write_json(report, out)
    assert json.loads(out.read_text())["captures"] == 1
    assert not any((ARCHIVE_STORE).rglob("report.json"))
    assert C.SCHEMA_VERSION.startswith("vulnova.prospective/")
