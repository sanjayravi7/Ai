"""Per-source acquisition adapters.

Each adapter owns one publisher and one artifact shape:

* :mod:`~vulnova.acquisition.sources.cvelistv5` — CVE Program revision pins.
* :mod:`~vulnova.acquisition.sources.epss` — FIRST EPSS daily score files.
* :mod:`~vulnova.acquisition.sources.kev` — CISA KEV catalog revisions.

Adapters never substitute one channel for another.  A third-party mirror is
recorded as a mirror and contributes ``UNAVAILABLE``, never ``VERIFIED``.
"""

from __future__ import annotations

__all__ = ["cvelistv5", "epss", "kev"]
