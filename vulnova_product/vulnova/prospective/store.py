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
directory, flushed and fsynced, then ``os.link``-ed into place.  A reader never
observes a half-written artifact, and a crash leaves the previous state intact.
There is deliberately **no weaker fallback**: the filesystem must support a
hard link (``link(2)``) for the store to be usable.  A filesystem that refuses
hard links gets a :class:`StoreCapabilityError`, not a direct write into the
final evidence path — a partial file at the final path would be worse than a
clear refusal.

Paths are store-relative and validated twice: syntactically (no absolute paths,
no ``..``, no non-string values) and physically (the resolved target must stay
inside the store, even if an intermediate component is a symlink).
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

from ..acquisition.store import StoreError, StoredArtifact
from . import constants as C

CREATED = "created"
IDENTICAL = "identical"

#: A content-addressed filename must be exactly a lower-case SHA-256.
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

#: Errors that mean "this filesystem cannot provide an atomic create-once link".
#: They are reported as a capability failure, never worked around by writing
#: directly into the final path.
LINK_CAPABILITY_ERRNOS = frozenset(
    {
        errno.EPERM,
        errno.EACCES,
        errno.EOPNOTSUPP,
        errno.ENOSYS,
        errno.EXDEV,
        errno.EMLINK,
        errno.EINVAL,
    }
)


class StoreConflict(StoreError):
    """A create-once path already exists with different bytes.

    Raised for a tampered artifact or a run-id collision.  Callers must never
    resolve it by overwriting: the existing bytes are the earlier evidence.
    """


class StoreCapabilityError(StoreError):
    """The filesystem cannot perform an atomic create-once write.

    The store refuses to degrade to a direct write into the final path: that
    would leave a partial artifact behind on a crash, so a clean refusal is the
    only safe answer.
    """


def _safe_relative(relative: str) -> PurePosixPath:
    """Validate a store-relative path.

    Non-string values are refused rather than passed to ``PurePosixPath``,
    which would raise ``TypeError`` out of callers that only handle
    :class:`StoreError`.
    """
    if not isinstance(relative, str):
        raise StoreError(
            "store-relative path must be a string, got "
            f"{type(relative).__name__}"
        )
    if not relative:
        raise StoreError("empty store-relative path")
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


def _existing_outcome(path: Path, data: bytes) -> str:
    """Compare ``data`` with an existing destination without writing anything."""
    if path.is_symlink() or not path.is_file():
        raise StoreConflict(
            f"refusing to replace {path}: it is not a regular file"
        )
    try:
        existing = path.read_bytes()
    except OSError as exc:
        raise StoreError(
            f"cannot compare with the existing file at {path}: {exc}"
        ) from exc
    if existing == data:
        return IDENTICAL
    raise StoreConflict(
        f"{path} already exists with different bytes "
        f"({hashlib.sha256(existing).hexdigest()} != {hashlib.sha256(data).hexdigest()}); "
        "existing evidence is never overwritten"
    )


def atomic_create(path: Path, data: bytes) -> str:
    """Create ``path`` atomically, never replacing an existing file.

    Returns :data:`CREATED` or :data:`IDENTICAL`.  Raises
    :class:`StoreConflict` when the path exists with different bytes, and
    :class:`StoreCapabilityError` when the filesystem cannot hard-link the
    temporary file into place.

    The bytes are never written to ``path`` directly.  If the link cannot be
    made, the temporary file is removed and the call fails; an existing file is
    left exactly as it was.  An existing destination is compared *before* any
    write is attempted, so a filesystem without hard links still reports
    identical bytes and conflicts correctly -- it can simply never accept new
    evidence.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StoreError(f"cannot create the directory for {path}: {exc}") from exc

    # Read-only fast path.  It never creates a temporary file, and it is what
    # tells an existing destination apart from a filesystem that cannot link.
    if path.is_symlink() or path.exists():
        return _existing_outcome(path, data)

    try:
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
            raise StoreError(f"cannot write the temporary file for {path}: {exc}") from exc

        created = False
        try:
            os.link(temporary_path, path)
            created = True
        except FileExistsError:
            # Another writer won the race.  Not a capability failure: compare the
            # bytes below and report identical or conflict.
            created = False
        except OSError as exc:
            if exc.errno in LINK_CAPABILITY_ERRNOS:
                raise StoreCapabilityError(
                    f"{C.ATOMIC_CREATE_UNAVAILABLE}: hard links are unavailable in "
                    f"{path.parent} ({errno.errorcode.get(exc.errno, exc.errno)}); "
                    "refusing to write evidence directly into its final path"
                ) from exc
            # A real I/O error.  It is never a licence to write the final path
            # directly; the temporary file is removed and the error is reported.
            raise StoreError(
                f"cannot link the temporary file into place for {path}: {exc}"
            ) from exc
    finally:
        try:
            temporary_path.unlink()
        except OSError:  # pragma: no cover - already gone
            pass

    if created:
        _fsync_directory(path.parent)
        return CREATED
    return _existing_outcome(path, data)


def atomic_replace(path: Path, data: bytes) -> None:
    """Atomically replace ``path``.

    Used only for *regenerable* outputs (reports), never for evidence.  Evidence
    goes through :func:`atomic_create`, which never replaces.
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


@dataclass(frozen=True)
class StoreEntry:
    """One filesystem entry discovered beneath a store subdirectory.

    ``problem`` is ``None`` for a recognized, content-addressed artifact whose
    filename digest matches its bytes.  Every other value is a reason code from
    :mod:`vulnova.prospective.constants`.
    """

    relative: str
    entry_type: str
    name: str
    kind: Optional[str] = None
    problem: Optional[str] = None
    bytes: Optional[int] = None
    sha256: Optional[str] = None
    filename_sha256: Optional[str] = None


def _digest_file(path: Path) -> tuple[Optional[int], Optional[str], Optional[str]]:
    """Return ``(bytes, sha256, problem)`` for one regular file."""
    try:
        total = 0
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                total += len(chunk)
                digest.update(chunk)
    except OSError:
        return None, None, C.ARTIFACT_UNREADABLE
    return total, digest.hexdigest(), None


def _scan_directory(path: Path) -> list[os.DirEntry]:
    try:
        with os.scandir(path) as iterator:
            return sorted(iterator, key=lambda entry: entry.name)
    except OSError as exc:
        raise StoreError(f"cannot read the directory {path}: {exc}") from exc


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
                f"{relative!r} resolves outside the store; refusing to use it"
            )
        if target.is_symlink():
            raise StoreError(f"{relative!r} is a symlink inside the evidence store")
        return target

    def run_path(self, run_id: str) -> Path:
        if not isinstance(run_id, str):
            raise StoreError(f"invalid run id: {type(run_id).__name__}")
        if "/" in run_id or "\\" in run_id or run_id.startswith("."):
            raise StoreError(f"invalid run id: {run_id!r}")
        return self.artifact_path(f"{C.RUNS_DIR}/{run_id}.json")

    # ------------------------------------------------------------ artifacts
    @staticmethod
    def artifact_relative(kind: str, sha256: str) -> str:
        if kind not in C.CAPTURE_KINDS:
            raise StoreError(f"unknown capture kind: {kind!r}")
        if not isinstance(sha256, str) or not SHA256_HEX.match(sha256):
            raise StoreError("artifact digest must be a lower-case SHA-256 hex string")
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
        try:
            entry = os.lstat(directory)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise StoreError(f"cannot inspect the run directory: {exc}") from exc
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
            # Not a directory: the caller is told by ``run_directory_entries``,
            # and an empty list here must not be mistaken for "no evidence".
            return []
        try:
            names = [
                name
                for name in os.listdir(directory)
                if name.endswith(".json")
                and (directory / name).is_file()
                and not (directory / name).is_symlink()
            ]
        except OSError as exc:
            raise StoreError(f"cannot read the run directory: {exc}") from exc
        return sorted(name[: -len(".json")] for name in names)

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
        try:
            data = path.read_bytes()
        except OSError:
            return None
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    # ------------------------------------------------------------ inventory
    def artifact_entries(self) -> list[StoreEntry]:
        """Every entry beneath ``artifacts/``, deterministically ordered.

        Symlinks are never followed: a symlink is reported as
        ``UNSAFE_ARTIFACT_PATH``.  A regular file is read once and classified by
        its content-addressed name and digest.  The inventory is the physical
        truth; run records are compared against it by the verifier.
        """
        base = self.root / C.ARTIFACTS_DIR
        try:
            base_stat = os.lstat(base)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise StoreError(f"cannot inspect the artifact directory: {exc}") from exc

        if stat.S_ISLNK(base_stat.st_mode):
            return [
                StoreEntry(
                    relative=C.ARTIFACTS_DIR,
                    entry_type="symlink",
                    name=C.ARTIFACTS_DIR,
                    problem=C.UNSAFE_ARTIFACT_PATH,
                )
            ]
        if not stat.S_ISDIR(base_stat.st_mode):
            return [
                StoreEntry(
                    relative=C.ARTIFACTS_DIR,
                    entry_type="other",
                    name=C.ARTIFACTS_DIR,
                    problem=C.UNEXPECTED_ARTIFACT,
                )
            ]

        entries: list[StoreEntry] = []
        for kind_entry in _scan_directory(base):
            kind_relative = f"{C.ARTIFACTS_DIR}/{kind_entry.name}"
            if kind_entry.is_symlink():
                entries.append(
                    StoreEntry(
                        relative=kind_relative,
                        entry_type="symlink",
                        name=kind_entry.name,
                        problem=C.UNSAFE_ARTIFACT_PATH,
                    )
                )
                continue
            if not kind_entry.is_dir(follow_symlinks=False):
                entries.append(
                    StoreEntry(
                        relative=kind_relative,
                        entry_type="other",
                        name=kind_entry.name,
                        problem=C.UNEXPECTED_ARTIFACT,
                    )
                )
                continue
            kind = kind_entry.name
            if kind not in C.CAPTURE_KINDS:
                entries.append(
                    StoreEntry(
                        relative=kind_relative,
                        entry_type="directory",
                        name=kind_entry.name,
                        problem=C.UNEXPECTED_ARTIFACT,
                    )
                )
                continue
            for file_entry in _scan_directory(Path(kind_entry.path)):
                relative = f"{kind_relative}/{file_entry.name}"
                if file_entry.is_symlink():
                    entries.append(
                        StoreEntry(
                            relative=relative,
                            entry_type="symlink",
                            name=file_entry.name,
                            kind=kind,
                            problem=C.UNSAFE_ARTIFACT_PATH,
                        )
                    )
                    continue
                if file_entry.is_dir(follow_symlinks=False):
                    entries.append(
                        StoreEntry(
                            relative=relative,
                            entry_type="directory",
                            name=file_entry.name,
                            kind=kind,
                            problem=C.UNEXPECTED_ARTIFACT,
                        )
                    )
                    continue
                if not file_entry.is_file(follow_symlinks=False):
                    entries.append(
                        StoreEntry(
                            relative=relative,
                            entry_type="other",
                            name=file_entry.name,
                            kind=kind,
                            problem=C.UNEXPECTED_ARTIFACT,
                        )
                    )
                    continue
                entries.append(
                    self._classify_artifact_file(
                        Path(file_entry.path), relative, kind, file_entry.name
                    )
                )
        return entries

    @staticmethod
    def _classify_artifact_file(
        path: Path, relative: str, kind: str, name: str
    ) -> StoreEntry:
        suffix = C.ARTIFACT_SUFFIX[kind]
        filename_sha: Optional[str] = None
        problem: Optional[str] = None

        if name.startswith(".tmp-"):
            problem = C.ABANDONED_TEMPORARY_FILE
        elif not name.endswith(suffix):
            problem = C.UNEXPECTED_ARTIFACT
        else:
            stem = name[: -len(suffix)]
            if not SHA256_HEX.match(stem):
                problem = C.UNEXPECTED_ARTIFACT
            else:
                filename_sha = stem

        size, digest, file_problem = _digest_file(path)
        if file_problem is not None:
            problem = file_problem
        elif problem is None and digest != filename_sha:
            # The filename is the content address.  If the bytes no longer hash
            # to it, the file is corrupt or was never written by this store.
            problem = C.ARTIFACT_TAMPERED

        return StoreEntry(
            relative=relative,
            entry_type="file",
            name=name,
            kind=kind,
            problem=problem,
            bytes=size,
            sha256=digest,
            filename_sha256=filename_sha,
        )

    def run_directory_entries(self) -> list[StoreEntry]:
        """Entries in ``runs/`` that are not readable run records.

        Temporary files and unexpected names are reported rather than hidden by
        a ``*.json`` glob.  A symlinked run file is reported as unsafe.
        """
        directory = self.root / C.RUNS_DIR
        try:
            directory_stat = os.lstat(directory)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise StoreError(f"cannot inspect the run directory: {exc}") from exc

        if stat.S_ISLNK(directory_stat.st_mode):
            return [
                StoreEntry(
                    relative=C.RUNS_DIR,
                    entry_type="symlink",
                    name=C.RUNS_DIR,
                    problem=C.UNSAFE_ARTIFACT_PATH,
                )
            ]
        if not stat.S_ISDIR(directory_stat.st_mode):
            return [
                StoreEntry(
                    relative=C.RUNS_DIR,
                    entry_type="other",
                    name=C.RUNS_DIR,
                    problem=C.UNEXPECTED_ARTIFACT,
                )
            ]

        entries: list[StoreEntry] = []
        for entry in _scan_directory(directory):
            relative = f"{C.RUNS_DIR}/{entry.name}"
            if entry.is_symlink():
                entries.append(
                    StoreEntry(
                        relative=relative,
                        entry_type="symlink",
                        name=entry.name,
                        problem=C.UNSAFE_ARTIFACT_PATH,
                    )
                )
            elif entry.is_dir(follow_symlinks=False):
                entries.append(
                    StoreEntry(
                        relative=relative,
                        entry_type="directory",
                        name=entry.name,
                        problem=C.UNEXPECTED_ARTIFACT,
                    )
                )
            elif entry.name.startswith(".tmp-"):
                entries.append(
                    StoreEntry(
                        relative=relative,
                        entry_type="file",
                        name=entry.name,
                        problem=C.ABANDONED_TEMPORARY_FILE,
                    )
                )
            elif not entry.name.endswith(".json"):
                entries.append(
                    StoreEntry(
                        relative=relative,
                        entry_type="file",
                        name=entry.name,
                        problem=C.UNEXPECTED_ARTIFACT,
                    )
                )
        return entries


__all__ = [
    "CREATED",
    "IDENTICAL",
    "StoreEntry",
    "ProspectiveStore",
    "StoreCapabilityError",
    "StoreConflict",
    "StoreError",
    "atomic_create",
    "atomic_replace",
]
