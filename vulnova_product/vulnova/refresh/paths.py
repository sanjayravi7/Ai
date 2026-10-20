"""Centralised write-safety checks for the 1.8 refresh.

The refresh writes in exactly three places: the artifact store, the JSON report
and the Markdown summary.  All three are validated here, **before** the first
network request and before any directory is created.

The rule is deliberately conservative.  Overlap in *either* direction is
refused: a destination that contains a sealed directory is as unacceptable as
one that sits inside it.  A user who passes ``--report reports/`` is one ``mkdir``
away from writing into ``reports/evaluation_readiness_1_6``, so that path is
rejected even though the leaf does not exist yet.

Paths are resolved with :meth:`pathlib.Path.resolve`, which follows existing
symlinks and collapses ``..`` segments.  A tail that does not exist yet is
resolved as far as it does exist, so ``reports/link/new.json`` is judged by where
``reports/link`` really points rather than by its spelling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import constants as C
from .errors import PathSafetyError


def resolve_path(path: Path | str) -> Path:
    """Resolve a path the same way for every comparison.

    Existing symlinks are followed and ``..`` is normalised.  ``strict=False``
    (the default) means a destination that does not exist yet still resolves
    against its nearest existing ancestor.

    ``~`` is deliberately *not* expanded here: :func:`write_json` and
    :func:`write_markdown` write the literal path they are given, so the check
    must judge that same literal path rather than a different one.
    """
    target = Path(path)
    try:
        return target.resolve()
    except OSError:  # pragma: no cover - defensive; resolve(strict=False) is safe
        return target.absolute()


def _overlaps(target: Path, guarded: Path) -> bool:
    return target == guarded or guarded in target.parents or target in guarded.parents


def paths_overlap(left: Path | str, right: Path | str) -> bool:
    """True when either path contains the other (equality included)."""
    return _overlaps(resolve_path(left), resolve_path(right))


def assert_safe_write_targets(
    store_root: Optional[Path | str],
    outputs: Sequence[Path | str] = (),
    protected: Iterable[Path | str] = (),
) -> tuple[Path, ...]:
    """Validate every refresh destination before anything is written.

    ``store_root`` is the refresh artifact store; ``outputs`` are the report and
    Markdown destinations; ``protected`` are the sealed inputs and configured
    read-only artifacts the refresh must never modify.

    Returns the resolved output paths, in the order given, so a caller can print
    exactly where it will write.  Raises :class:`PathSafetyError` on the first
    unsafe destination:

    * a store that overlaps a protected path (``REFRESH_STORE_OVERLAPS_ARCHIVE``);
    * an output that overlaps a protected path (``OUTPUT_OVERLAPS_PROTECTED``);
    * an output that overlaps the store, or another output
      (``OUTPUT_PATHS_COLLIDE``).
    """
    guarded = tuple(resolve_path(item) for item in protected)
    resolved_store: Optional[Path] = None

    if store_root is not None:
        resolved_store = resolve_path(store_root)
        for item in guarded:
            if _overlaps(resolved_store, item):
                raise PathSafetyError(
                    f"{C.REFRESH_STORE_OVERLAPS_ARCHIVE}: refresh store "
                    f"{store_root} overlaps the sealed path {item}; refusing to write"
                )

    resolved_outputs: list[Path] = []
    for output in outputs:
        target = resolve_path(output)
        for item in guarded:
            if _overlaps(target, item):
                raise PathSafetyError(
                    f"{C.OUTPUT_OVERLAPS_PROTECTED}: write target {output} resolves "
                    f"to {target}, which overlaps the protected path {item}; "
                    "refusing to write"
                )
        if resolved_store is not None and _overlaps(target, resolved_store):
            raise PathSafetyError(
                f"{C.OUTPUT_PATHS_COLLIDE}: write target {output} resolves to "
                f"{target}, which overlaps the refresh store {resolved_store}; "
                "the report and the store must be separate"
            )
        for previous in resolved_outputs:
            if _overlaps(target, previous):
                raise PathSafetyError(
                    f"{C.OUTPUT_PATHS_COLLIDE}: write targets {previous} and "
                    f"{target} resolve to the same or overlapping paths; each output "
                    "needs its own path"
                )
        resolved_outputs.append(target)
    return tuple(resolved_outputs)


__all__ = [
    "assert_safe_write_targets",
    "paths_overlap",
    "resolve_path",
]
