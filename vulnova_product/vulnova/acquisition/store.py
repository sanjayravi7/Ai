"""On-disk artifact store.

Artifacts are addressed by portable, forward-slash relative paths so a manifest
written on one machine verifies on another.  Writes are byte-exact: the digest
recorded in the manifest is the digest of the file that was stored, never a
re-encoded or normalised variant.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional


class StoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredArtifact:
    relative_path: str
    bytes: int
    sha256: str

    def as_dict(self) -> dict:
        return {
            "artifact_path": self.relative_path,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


def _safe_relative(relative: str) -> PurePosixPath:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        raise StoreError(f"artifact path escapes the store: {relative!r}")
    return path


class ArtifactStore:
    """A directory of acquired bytes, addressed by relative path."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def path(self, relative: str) -> Path:
        return self.root.joinpath(*_safe_relative(relative).parts)

    def exists(self, relative: str) -> bool:
        return self.path(relative).is_file()

    def write(self, relative: str, data: bytes) -> StoredArtifact:
        target = self.path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return StoredArtifact(
            relative_path=str(_safe_relative(relative)),
            bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def read(self, relative: str) -> bytes:
        target = self.path(relative)
        if not target.is_file():
            raise StoreError(f"artifact not found: {relative}")
        return target.read_bytes()

    def digest(self, relative: str) -> Optional[dict]:
        """Return ``{"bytes", "sha256"}`` for a stored artifact, or ``None``."""
        target = self.path(relative)
        if not target.is_file():
            return None
        data = target.read_bytes()
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


__all__ = ["ArtifactStore", "StoreError", "StoredArtifact"]
