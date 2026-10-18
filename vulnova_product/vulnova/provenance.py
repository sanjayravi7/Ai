"""Provenance helpers.

Every value that reaches the console must be traceable to (source, revision,
retrieval timestamp, content checksum).  These helpers are deliberately tiny
and dependency-free so the ingest and receipt paths cannot drift apart.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

CHUNK = 1 << 20


def utc_now() -> str:
    """Current UTC time as an ISO-8601 string with a trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path) -> str:
    """Stream a file through SHA-256 without loading it into memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(entries) -> str:
    """Deterministic digest over ``(relative_path, sha256)`` pairs.

    Used for directory-shaped sources (cvelistV5) where storing every blob in
    the workspace is not practical: the digest plus the upstream revision lets
    a third party re-fetch and re-verify the exact same content.
    """
    digest = hashlib.sha256()
    for rel, sha in sorted(entries):
        digest.update(f"{rel}\x00{sha}\n".encode("utf-8"))
    return digest.hexdigest()


def write_json(path, payload) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_json(path):
    return json.loads(Path(path).read_text())
