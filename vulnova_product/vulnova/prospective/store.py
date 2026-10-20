"""Append-only evidence store for prospective capture.

Layout::

    <store>/artifacts/<kind>/<sha256><suffix>   immutable, content-addressed
    <store>/runs/<run_id>.json                  immutable capture record

Two properties matter and are enforced structurally rather than documented:

**Nothing is overwritten.**  Every write is create-once.  Bytes are addressed by
their own SHA-256, so identical bytes captured twice occupy one file, and a
second, *different* capture of the same source is stored beside the first under
a different digest.  Writing a file that already exists is either a no-op (the
bytes match) or a :class:`StoreConflict` (they do not — which means the file was
tampered with, and is never "repaired" by overwriting it).

**Writes are atomic.**  Bytes are written to a temporary file in the destination
directory, flushed and fsynced, then linked into place.  A reader never observes
a half-written artifact, and a crash leaves the previous state intact.

Paths are store-relative and validated twice: syntactically (no absolute paths,
no ``..``) and physically (the resolved target must stay inside the store, even
if an intermediate component is a symlink).
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path, PurePosixPath
from typing import Optional

from ..acquisition.store import StoreError, StoredArtifact
from . import constants as C

CREATED = "created"
IDENTICAL = "identical"


class StoreConflict(StoreError):
    """A create-once path already exists with different bytes.

    Raised for a tampered artifact or a run-id collision.  Callers must never
    resolve it by overwriting: the existing bytes are the earlier evidence.
    """


def _safe_relative(relative: str) -> PurePosixPath:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        raise StoreError(f"path escapes the store: {relative!r}")
    if not path.parts:
        raise StoreError("empty store-relative path")
    return path


def _inside(root: Path, target: Path) -> bool:
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def _fsync_directory(directory: Path) -> None:
    """Best-effort durability for the directory entry itself."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover - platforms without directory fds
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - some filesystems refuse
        pass
    finally:
        os.close(fd)


def atomic_create(path: Path, data: bytes) -> str:
    """Create ``path`` atomically, never replacing an existing file.

    Returns :data:`CREATED` or :data:`IDENTICAL`.  Raises
    :class:`StoreConflict` when the path exists with different bytes, and
    :class:`StoreError` when the existing path is not a regular file.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    except OSError as exc:
        raise StoreError(f"cannot create a temporary file beside {path}: {exc}") from exc
    temporary_path = Path(temporary)
    try:
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise StoreError(f"cannot write {path}: {exc}") from exc

        created = False
        try:
            os.link(temporary_path, path)
            created = True
        except FileExistsError:
            created = False
        except OSError:  # pragma: no cover - filesystems without hard links
            try:
                with open(path, "xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                created = True
            except FileExistsError:
                created = False
    finally:
        try:
            temporary_path.unlink()
        except OSError:  # pragma: no cover - already gone
            pass

    if created:
        _fsync_directory(path.parent)
        return CREATED

    if path.is_symlink() or not path.is_file():
        raise StoreConflict(
            f"refusing to treat {path} as an existing artifact: it is not a regular file"
        )
    existing = path.read_bytes()
    if existing == data:
        return IDENTICAL
    raise StoreConflict(
        f"{path} already exists with different bytes "
        f"({hashlib.sha256(existing).hexdigest()} != {hashlib.sha256(data).hexdigest()}); "
        "existing evidence is never overwritten"
    )


def atomic_replace(path: Path, data: bytes) -> None:
    """Atomically replace ``path``.

    Used only for *regenerable* outputs (reports), never for evidence.  Evidence
    goes through :func:`atomic_create`.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    except OSError as exc:
        raise StoreError(f"cannot create a temporary file beside {path}: {exc}") from exc
    temporary_path = Path(temporary)
    try:
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise StoreError(f"cannot write {path}: {exc}") from exc
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except OSError:  # pragma: no cover - already moved
            pass
    _fsync_directory(path.parent)


class ProspectiveStore:
    """Content-addressed, append-only prospective evidence store."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    # ----------------------------------------------------------- resolution
    def artifact_path(self, relative: str) -> Path:
        """Resolve a store-relative path, refusing escapes and symlinks."""
        target = self.root.joinpath(*_safe_relative(relative).parts)
        root = self.root.resolve()
        resolved = target.resolve()
        if not _inside(root, resolved):
            raise StoreError(
                f"{relative!r} resolves outside the store ({resolved}); refusing to use it"
            )
        if target.is_symlink():
            raise StoreError(f"{relative!r} is a symlink inside the evidence store")
        return target

    def run_path(self, run_id: str) -> Path:
        if "/" in run_id or "\\" in run_id or run_id.startswith("."):
            raise StoreError(f"invalid run id: {run_id!r}")
        return self.artifact_path(f"{C.RUNS_DIR}/{run_id}.json")

    # ------------------------------------------------------------ artifacts
    @staticmethod
    def artifact_relative(kind: str, sha256: str) -> str:
        if kind not in C.CAPTURE_KINDS:
            raise StoreError(f"unknown capture kind: {kind!r}")
        suffix = C.ARTIFACT_SUFFIX[kind]
        return f"{C.ARTIFACTS_DIR}/{kind}/{sha256}{suffix}"

    def store_artifact(self, kind: str, body: bytes) -> StoredArtifact:
        """Store bytes once, by digest.  Identical bytes are a no-op."""
        digest = hashlib.sha256(body).hexdigest()
        relative = self.artifact_relative(kind, digest)
        atomic_create(self.artifact_path(relative), body)
        return StoredArtifact(relative_path=relative, bytes=len(body), sha256=digest)

    # ---------------------------------------------------------------- runs
    def store_run(self, run_id: str, payload: bytes) -> str:
        return atomic_create(self.run_path(run_id), payload)

    def read_run(self, run_id: str) -> bytes:
        return self.run_path(run_id).read_bytes()

    def run_ids(self) -> list[str]:
        directory = self.root / C.RUNS_DIR
        if not directory.is_dir():
            return []
        return sorted(path.stem for path in directory.glob("*.json") if path.is_file())

    # -------------------------------------------------------------- reading
    def read_artifact(self, relative: str) -> bytes:
        return self.artifact_path(relative).read_bytes()

    def artifact_digest(self, relative: str) -> Optional[dict]:
        try:
            path = self.artifact_path(relative)
        except StoreError:
            return None
        if not path.is_file():
            return None
        data = path.read_bytes()
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


__all__ = [
    "CREATED",
    "IDENTICAL",
    "ProspectiveStore",
    "StoreConflict",
    "StoreError",
    "atomic_create",
    "atomic_replace",
]
