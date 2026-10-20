"""The runtime version and the distribution version must not drift apart.

1.9.2 exists because they did: ``pyproject.toml`` said ``1.9.1`` while
``vulnova.__version__`` still said ``1.1.0``, so an installed distribution and a
running interpreter could report different versions of the same code.  The
literal is deliberately written twice -- reading it from installed metadata would
break when the package is used from a source checkout -- so these tests are what
keep the two copies honest.
"""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import pytest

import vulnova

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PRODUCT_ROOT / "pyproject.toml"

# A release triplet.  Suffixes such as ``.dev0`` or ``rc1`` are rejected so a
# pre-release cannot be published under a name that sorts above the real release.
RELEASE_VERSION = re.compile(r"\d+\.\d+\.\d+\Z")


def declared_version() -> str:
    """The version a build of this tree would stamp on the distribution."""
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def test_runtime_version_matches_pyproject():
    assert vulnova.__version__ == declared_version()


def test_both_versions_are_release_triplets():
    for label, value in (
        ("pyproject.toml [project].version", declared_version()),
        ("vulnova.__version__", vulnova.__version__),
    ):
        assert RELEASE_VERSION.match(value), f"{label} is not X.Y.Z: {value!r}"


def test_installed_distribution_matches_runtime_version():
    """Only checkable when the distribution is installed.

    CI runs the suite from a source checkout and installs no ``vulnova``
    distribution, so this skips there.  A clean-room ``pip install .`` is what
    exercises it.
    """
    try:
        installed = importlib.metadata.version("vulnova")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("vulnova is not installed in this environment")
    assert installed == vulnova.__version__
