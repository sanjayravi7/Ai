"""VULNOVA 1.7 evidence acquisition.

The package acquires historical evidence from official publishers, stores the
exact bytes, records *when* each byte was actually retrieved, and can re-verify
every hash offline.  It trains nothing, scores nothing, and approves nothing.
"""

from __future__ import annotations

from . import constants
from .records import ArtifactRecord, Requirement
from .store import ArtifactStore, StoreError
from .transport import (
    DisallowedHost,
    FakeTransport,
    HttpResponse,
    Transport,
    TransportError,
    UrllibTransport,
)

__all__ = [
    "ArtifactRecord",
    "ArtifactStore",
    "DisallowedHost",
    "FakeTransport",
    "HttpResponse",
    "Requirement",
    "StoreError",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "constants",
]
