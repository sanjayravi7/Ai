"""Digest, archive and manifest verification helpers.

Everything here is read-only with respect to the research artifacts.  Extraction
goes to a caller-supplied cache directory (normally ``build/``), never into the
artifact tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable, Optional


class IntegrityError(RuntimeError):
    """Raised when an archive or manifest is structurally unsafe/unreadable."""


def sha256_file(path: Path | str, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path | str, *, relative_to: Optional[Path] = None) -> dict:
    path = Path(path)
    record = {
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if relative_to is not None:
        try:
            record["path"] = str(path.resolve().relative_to(Path(relative_to).resolve()))
        except ValueError:
            record["path"] = str(path)
    else:
        record["path"] = str(path)
    return record


def read_sha256_sidecar(path: Path | str) -> dict:
    """Read the conventional ``<digest>  <filename>`` sidecar format."""
    path = Path(path)
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise IntegrityError(f"empty checksum sidecar: {path}")
    parts = text.split()
    digest = parts[0].lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise IntegrityError(f"not a sha256 digest in {path}: {digest!r}")
    declared_name = parts[-1] if len(parts) > 1 else None
    return {"sha256": digest, "declared_name": declared_name}


def verify_archive_sidecar(archive: Path | str, sidecar: Path | str) -> dict:
    archive = Path(archive)
    sidecar = Path(sidecar)
    record = {
        "archive": str(archive),
        "sidecar": str(sidecar),
        "archive_present": archive.is_file(),
        "sidecar_present": sidecar.is_file(),
    }
    if not archive.is_file():
        return {**record, "status": "MISSING", "reason": "archive not found"}
    if not sidecar.is_file():
        return {**record, "status": "MISSING", "reason": "checksum sidecar not found"}
    record["bytes"] = archive.stat().st_size
    record["actual_sha256"] = sha256_file(archive)
    try:
        declared = read_sha256_sidecar(sidecar)
    except IntegrityError as exc:
        return {**record, "status": "FAIL", "reason": str(exc)}
    record.update(declared)
    record["matches"] = record["actual_sha256"] == declared["sha256"]
    record["status"] = "PASS" if record["matches"] else "FAIL"
    if not record["matches"]:
        record["reason"] = "archive digest does not match its sidecar"
    if declared.get("declared_name"):
        record["declared_name_matches"] = declared["declared_name"] == archive.name
    return record


def _safe_member_path(member: tarfile.TarInfo) -> str:
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        raise IntegrityError(f"archive member has an absolute path: {name!r}")
    normalized = os.path.normpath(name)
    if normalized.startswith("..") or "/../" in normalized or "\\..\\" in normalized:
        raise IntegrityError(f"archive member escapes the destination: {name!r}")
    if member.issym() or member.islnk():
        raise IntegrityError(f"archive member is a link: {name!r}")
    if not (member.isfile() or member.isdir()):
        raise IntegrityError(f"archive member is not a regular file/directory: {name!r}")
    return normalized


def extract_archive(archive: Path | str, destination: Path | str) -> Path:
    """Safely extract ``archive`` and return the single top-level directory."""
    archive = Path(archive)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            _safe_member_path(member)
        # Members are validated above (no absolute paths, no traversal, no
        # links, regular files/directories only), so extraction is safe on
        # Python versions that predate tarfile's extraction filters.
        tar.extractall(destination, members=members)

    children = [child for child in destination.iterdir() if child.is_dir()]
    if len(children) != 1:
        raise IntegrityError(
            f"expected one top-level directory in {archive}, found "
            f"{[child.name for child in children]}"
        )
    return children[0]


def extract_if_needed(
    archive: Path | str,
    destination: Path | str,
    *,
    expected_sha256: Optional[str] = None,
    required_paths: Iterable[str] = (),
) -> dict:
    """Extract once, reusing a cache keyed by the archive digest.

    Returns a record describing whether extraction happened.  A cache is only
    reused when the recorded digest matches the archive's current digest and all
    ``required_paths`` exist.
    """
    archive = Path(archive)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    marker = destination / ".extraction.json"
    actual = sha256_file(archive)
    record = {
        "archive": str(archive),
        "destination": str(destination),
        "archive_sha256": actual,
        "expected_sha256": expected_sha256,
        "digest_matches_expected": (
            True if expected_sha256 is None else actual == expected_sha256
        ),
        "reused_cache": False,
        "extracted": False,
    }
    if marker.is_file():
        try:
            cached = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            cached = {}
        root = destination / str(cached.get("root", ""))
        if (
            cached.get("archive_sha256") == actual
            and cached.get("root")
            and root.is_dir()
            and all((root / item).exists() for item in required_paths)
        ):
            record.update({"reused_cache": True, "root": str(root)})
            return record

    with tempfile.TemporaryDirectory(dir=destination, prefix=".extract-") as staging:
        root = extract_archive(archive, staging)
        target = destination / root.name
        if target.exists():
            raise IntegrityError(f"refusing to overwrite existing directory: {target}")
        root.rename(target)
    marker.write_text(
        json.dumps(
            {"archive_sha256": actual, "root": target.name, "archive": str(archive)},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    record.update({"extracted": True, "root": str(target)})
    return record


def verify_manifest(
    root: Path | str,
    manifest: dict,
    *,
    expected_absent: Optional[int] = None,
) -> dict:
    """Verify a manifest's ``files`` entries against files under ``root``.

    Missing files are reported, not treated as corruption by themselves: the
    core bundle deliberately omits the bulk membership data.  The caller decides
    whether the observed set of absences is expected.
    """
    root = Path(root)
    entries = manifest.get("files", [])
    present: list[dict] = []
    missing: list[dict] = []
    mismatched: list[dict] = []
    for entry in entries:
        relative = entry.get("path")
        if not relative:
            mismatched.append({"path": "", "reason": "manifest entry lacks path"})
            continue
        target = root / relative
        if not target.is_file():
            missing.append({"path": relative})
            continue
        actual_bytes = target.stat().st_size
        actual_sha = sha256_file(target)
        problems = []
        if "bytes" in entry and int(entry["bytes"]) != actual_bytes:
            problems.append(
                {"field": "bytes", "expected": entry["bytes"], "actual": actual_bytes}
            )
        expected_sha = entry.get("sha256")
        if expected_sha and expected_sha != actual_sha:
            problems.append(
                {"field": "sha256", "expected": expected_sha, "actual": actual_sha}
            )
        if problems:
            mismatched.append({"path": relative, "problems": problems})
        else:
            present.append({"path": relative, "bytes": actual_bytes, "sha256": actual_sha})

    result = {
        "root": str(root),
        "manifest_file_count": int(manifest.get("file_count", len(entries))),
        "entries": len(entries),
        "present_count": len(present),
        "missing_count": len(missing),
        "mismatched_count": len(mismatched),
        "present": present,
        "missing": missing,
        "mismatched": mismatched,
        "total_bytes_present": sum(item["bytes"] for item in present),
    }
    if expected_absent is not None:
        result["expected_absent"] = expected_absent
        result["absent_as_expected"] = len(missing) == expected_absent
    return result
