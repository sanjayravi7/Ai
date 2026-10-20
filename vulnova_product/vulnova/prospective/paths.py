"""Write-safety for prospective capture.

The 1.8 guard already refuses any destination that overlaps the 1.6 readiness
report, the 1.7 archive, the original snapshots or the Phase 2.3K export, and it
derives those paths from the package layout rather than from the caller.  1.9
adds the 1.8 refresh store and its reports to that set, and keeps the same rule:
the fixed historical paths are always protected, whatever a caller passes.

A prospective capture writes in one place — its own store — plus optional report
outputs.  All of them are checked here, before the first network request.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Sequence

from ..refresh.paths import (
    assert_safe_write_targets,
    default_protected_paths,
    merge_protected_paths,
    package_roots,
)
from . import constants as C


def historical_protected_paths(
    product_root: Optional[Path | str] = None,
    repository_root: Optional[Path | str] = None,
) -> tuple[Path, ...]:
    """Every sealed historical artifact, including the 1.8 evidence.

    ``default_protected_paths`` supplies the 1.6 report, the 1.7 archive and
    manifest, ``data/snapshots`` and the Phase 2.3K export.  On top of that we
    protect the 1.8 refresh store and reports and the protocol directory, so a
    capture or a report can never overwrite the evidence and rules it depends
    on.
    """
    product, repository = package_roots()
    product = product if product_root is None else Path(product_root)
    repository = repository if repository_root is None else Path(repository_root)
    extra = [product / relative for relative in C.PROTECTED_RELATIVE_PATHS]
    return merge_protected_paths(
        default_protected_paths(product, repository),
        extra,
    )


def capture_protected_paths(
    protected: Iterable[Path | str] = (),
    *,
    product_root: Optional[Path | str] = None,
    repository_root: Optional[Path | str] = None,
) -> tuple[Path, ...]:
    """The fixed historical paths plus anything the caller added.

    Caller paths are additive.  An empty tuple means "nothing extra", never
    "nothing protected", so a programmatic caller cannot switch the safeguard
    off by omitting optional arguments.
    """
    return merge_protected_paths(
        historical_protected_paths(product_root, repository_root),
        protected,
    )


def assert_capture_safety(
    store_root: Path | str,
    outputs: Sequence[Path | str] = (),
    protected: Iterable[Path | str] = (),
) -> tuple[Path, ...]:
    """Validate the capture store and every report output.

    Raises :class:`vulnova.refresh.errors.PathSafetyError` before any network
    request or filesystem mutation.
    """
    return assert_safe_write_targets(
        store_root,
        outputs,
        capture_protected_paths(protected),
        store_reason=C.STORE_OVERLAPS_PROTECTED,
    )


__all__ = [
    "assert_capture_safety",
    "capture_protected_paths",
    "historical_protected_paths",
]
