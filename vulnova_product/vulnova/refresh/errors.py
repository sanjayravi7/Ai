"""Exceptions shared by the 1.8 refresh modules.

``RefreshError`` lives here rather than in :mod:`vulnova.refresh.workflow` so
that the path-safety module can raise it without importing the workflow (which
imports the path-safety module in turn).  ``vulnova.refresh.workflow`` re-exports
it, so ``from vulnova.refresh.workflow import RefreshError`` keeps working.
"""

from __future__ import annotations


class RefreshError(RuntimeError):
    """The refresh cannot proceed without violating a safety invariant."""


class PathSafetyError(RefreshError):
    """A write destination overlaps a sealed input, the store, or another output.

    Raised before the first network request and before any directory is created,
    so a rejected run leaves the filesystem untouched.
    """


__all__ = ["PathSafetyError", "RefreshError"]
