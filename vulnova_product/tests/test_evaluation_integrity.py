"""Artifact integrity: sidecars, manifests, safe extraction and partitions."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from vulnova.evaluation.integrity import (
    IntegrityError,
    extract_archive,
    extract_if_needed,
    sha256_file,
    verify_archive_sidecar,
    verify_manifest,
)
from vulnova.evaluation.readiness import build_report

from tests.evaluation_fixtures import build_fixture


def _archive_with(path: Path, member_name: str, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    info = tarfile.TarInfo(member_name)
    info.size = len(payload)
    with tarfile.open(path, "w:gz") as tar:
        tar.addfile(info, io.BytesIO(payload))
    return path


def _manifest_for(root: Path) -> dict:
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append(
                {
                    "path": str(path.relative_to(root)),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return {"file_count": len(entries), "files": entries}


def test_archive_sidecar_pass_fail_and_missing(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    archive.write_bytes(b"payload")
    sidecar = tmp_path / "bundle.tar.gz.sha256"
    sidecar.write_text(f"{sha256_file(archive)}  {archive.name}\n", encoding="utf-8")

    result = verify_archive_sidecar(archive, sidecar)
    assert result["status"] == "PASS"
    assert result["matches"] is True
    assert result["declared_name_matches"] is True

    archive.write_bytes(b"payload-changed")
    result = verify_archive_sidecar(archive, sidecar)
    assert result["status"] == "FAIL"
    assert result["matches"] is False

    missing = verify_archive_sidecar(tmp_path / "absent.tar.gz", sidecar)
    assert missing["status"] == "MISSING"


def test_manifest_detects_missing_and_mismatched_files(tmp_path):
    root = tmp_path / "dataset"
    root.mkdir()
    (root / "a.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (root / "b.json").write_text('{"x": 1}\n', encoding="utf-8")
    manifest = _manifest_for(root)

    clean = verify_manifest(root, manifest)
    assert clean["present_count"] == 2
    assert clean["missing_count"] == 0
    assert clean["mismatched_count"] == 0

    (root / "a.csv").write_text("a,b\n1,3\n", encoding="utf-8")
    dirty = verify_manifest(root, manifest)
    assert dirty["mismatched_count"] == 1
    assert dirty["mismatched"][0]["path"] == "a.csv"

    (root / "b.json").unlink()
    missing = verify_manifest(root, manifest)
    assert missing["missing_count"] == 1
    assert missing["missing"][0]["path"] == "b.json"


def test_manifest_expected_absences_are_reported_not_hidden(tmp_path):
    root = tmp_path / "core"
    root.mkdir()
    (root / "present.txt").write_text("x", encoding="utf-8")
    manifest = {
        "file_count": 2,
        "files": [
            {"path": "present.txt", "bytes": 1, "sha256": sha256_file(root / "present.txt")},
            {"path": "omitted.bin", "bytes": 1, "sha256": "0" * 64},
        ],
    }
    result = verify_manifest(root, manifest, expected_absent=1)
    assert result["missing_count"] == 1
    assert result["absent_as_expected"] is True


def test_safe_extraction_rejects_path_traversal(tmp_path):
    archive = _archive_with(tmp_path / "evil.tar.gz", "../escape.txt", b"owned")
    with pytest.raises(IntegrityError, match="escapes|absolute"):
        extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_safe_extraction_returns_the_single_top_level_directory(tmp_path):
    archive = _archive_with(
        tmp_path / "ok.tar.gz", "bundle/data.txt", b"hello"
    )
    root = extract_archive(archive, tmp_path / "out")
    assert root.name == "bundle"
    assert (root / "data.txt").read_text(encoding="utf-8") == "hello"


def test_extraction_cache_is_reused_only_for_the_same_digest(tmp_path):
    archive = _archive_with(tmp_path / "ok.tar.gz", "bundle/data.txt", b"hello")
    first = extract_if_needed(
        archive, tmp_path / "cache", required_paths=("data.txt",)
    )
    assert first["extracted"] is True
    second = extract_if_needed(
        archive, tmp_path / "cache", required_paths=("data.txt",)
    )
    assert second["reused_cache"] is True
    assert second["root"] == first["root"]


def test_corrupted_membership_partition_fails_the_checksum_check(tmp_path):
    fixture = build_fixture(
        tmp_path / "fixture",
        corrupt_partition_at=__import__("datetime").date(2025, 9, 1),
    )
    report = build_report(fixture.options)
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["INT-05_membership_partition_checksums"]["status"] == "FAIL"
    assert "2025-09-01" in " ".join(
        checks["INT-05_membership_partition_checksums"]["reasons"]
    )


def test_missing_membership_partition_blocks_the_checksum_check(tmp_path):
    fixture = build_fixture(
        tmp_path / "fixture",
        missing_partition_at=__import__("datetime").date(2025, 9, 1),
    )
    report = build_report(fixture.options)
    checks = {check["id"]: check for check in report["checks"]}
    assert checks["INT-05_membership_partition_checksums"]["status"] == "BLOCKED"
    assert checks["INT-06_membership_row_accounting"]["status"] == "BLOCKED"


def test_fixture_manifest_verifies_cleanly(tmp_path):
    fixture = build_fixture(tmp_path / "fixture")
    manifest = json.loads(
        (fixture.dataset / "phase2_3k_integrity_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    result = verify_manifest(fixture.dataset, manifest)
    assert result["present_count"] == result["entries"]
    assert result["mismatched_count"] == 0
    assert result["missing_count"] == 0
