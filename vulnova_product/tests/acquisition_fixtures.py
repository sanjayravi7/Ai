"""Deterministic fixtures for acquisition tests.

Everything here is canned bytes served by :class:`FakeTransport`.  No test in
this suite touches the network, and every timestamp is explicit so a test that
depends on "now" cannot drift.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import gzip
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from vulnova.acquisition.github import API_ROOT, GitHubApi
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import FakeTransport

CUTOFFS = (dt.date(2025, 2, 1), dt.date(2025, 9, 1), dt.date(2026, 4, 1))
GRID = CUTOFFS

RUN_AT = "2026-10-20T10:05:00Z"
RETRIEVED_CVE = "2026-10-20T10:00:00Z"
RETRIEVED_KEV = "2026-10-20T10:01:00Z"
RETRIEVED_EPSS = "2026-10-20T10:02:00Z"

CVE_PINS = {
    "2025-02-01": (
        "b3b7d34318e4f6d1de4e082d03ea21984ff2f176",
        "2025-01-31T23:08:06Z",
        "934556ae44b42c14cd46d76287c9dac4ad12ce76",
    ),
    "2025-09-01": (
        "2549c0e76d2857fa6ed14b146fa377d5164914d7",
        "2025-08-31T23:33:54Z",
        "5503272d22387f8ffe3942439702de5f9bc22e48",
    ),
    "2026-04-01": (
        "bc781f6b07948ceacd7c5e1c1ede9119b2ac0778",
        "2026-03-31T23:51:08Z",
        "700902d04456533139516e19b43b274b8011a353",
    ),
}

KEV_HISTORY = {
    "2025-02-01": (
        "49c9495366c4e9b9abc9db85f91657d8bb9a0be2",
        "2025-01-29T17:59:10Z",
        "2025.01.29",
        "2025-01-29T17:02:51Z",
        1253,
    ),
    "2025-09-01": (
        "9d28701f99f7" + "0" * 28,
        "2025-08-29T17:00:00Z",
        "2025.08.29",
        "2025-08-29T16:00:00Z",
        1406,
    ),
    "2026-04-01": (
        "72998801139e" + "0" * 28,
        "2026-03-31T17:00:00Z",
        "2026.04.01",
        "2026-03-31T16:00:00Z",
        1556,
    ),
}


def sha40(seed: str) -> str:
    """Deterministic 40-hex identifier for a canned object."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:40]


KEV_CURRENT_COMMIT = "6a392940" + "0" * 32
KEV_CURRENT_COMMITTED = "2026-10-16T19:22:35Z"
KEV_CURRENT_VERSION = "2026.10.16"
KEV_CURRENT_RELEASED = "2026-10-16T17:15:48Z"


# ------------------------------------------------------------------- helpers
def cve_url(day: dt.date) -> str:
    return (
        f"{API_ROOT}/repos/CVEProject/cvelistV5/commits"
        f"?until={day.isoformat()}T00:00:00Z&per_page=1"
    )


def kev_until_url(day: dt.date) -> str:
    return (
        f"{API_ROOT}/repos/cisagov/kev-data/commits"
        f"?until={day.isoformat()}T00:00:00Z&per_page=1"
    )


def kev_latest_url() -> str:
    return f"{API_ROOT}/repos/cisagov/kev-data/commits?sha=HEAD&per_page=1"


def kev_tree_url(tree_sha: str) -> str:
    return f"{API_ROOT}/repos/cisagov/kev-data/git/trees/{tree_sha}"


def kev_blob_url(blob_sha: str) -> str:
    return f"{API_ROOT}/repos/cisagov/kev-data/git/blobs/{blob_sha}"


def epss_url(day: dt.date) -> str:
    return f"https://epss.cyentia.com/epss_scores-{day.isoformat()}.csv.gz"


def kev_catalog_bytes(
    version: str,
    released: str,
    *,
    count: int = 3,
    declared: Optional[int] = None,
    first_date_added: str = "2024-01-01",
) -> bytes:
    entries = [
        {
            "cveID": f"CVE-2024-{1000 + index}",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": f"Test {index}",
            "dateAdded": first_date_added,
            "knownRansomwareCampaignUse": "Unknown",
        }
        for index in range(count)
    ]
    payload = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": released,
        "count": declared if declared is not None else count,
        "vulnerabilities": entries,
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def epss_bytes(
    day: dt.date,
    *,
    model: str = "v2026.06.15",
    score_date: Optional[str] = None,
    rows: int = 3,
    raw_header: Optional[str] = None,
) -> bytes:
    stamp = score_date or f"{day.isoformat()}T12:02:51Z"
    header = raw_header or f"#model_version:{model},score_date:{stamp}"
    lines = [header, "cve,epss,percentile"]
    for index in range(rows):
        lines.append(f"CVE-2024-{2000 + index},0.5{index},0.9{index}")
    # mtime=0 removes the gzip header timestamp.  Without it every call produces
    # different bytes, which made captured artifacts (and therefore run and
    # report digests) depend on the wall clock and could flake the
    # reproducibility tests across a second boundary.
    return gzip.compress(("\n".join(lines) + "\n").encode("utf-8"), mtime=0)


def blob_payload(body: bytes, blob_sha: str) -> dict:
    return {
        "sha": blob_sha,
        "size": len(body),
        "encoding": "base64",
        "content": base64.b64encode(body).decode("ascii"),
    }


def commit_payload(sha: str, committed: str, tree_sha: str) -> dict:
    return {
        "sha": sha,
        "commit": {
            "committer": {"date": committed},
            "tree": {"sha": tree_sha},
        },
    }


def tree_payload(blob_sha: str, size: int, path: str = "known_exploited_vulnerabilities.json"):
    return {"sha": "tree", "tree": [{"path": path, "mode": "100644", "type": "blob", "sha": blob_sha, "size": size}]}


@dataclass
class Scenario:
    transport: FakeTransport
    api: GitHubApi
    store: ArtifactStore
    cutoffs: tuple[dt.date, ...]
    grid: tuple[dt.date, ...]

    def kev_blob_add(self, tree_sha: str, blob_sha: str, body: bytes, retrieved_at: str):
        self.transport.add_json(kev_tree_url(tree_sha), tree_payload(blob_sha, len(body)), retrieved_at=retrieved_at)
        self.transport.add_json(
            kev_blob_url(blob_sha), blob_payload(body, blob_sha), retrieved_at=retrieved_at
        )


def build_scenario(
    tmp_path: Path,
    *,
    cutoffs: tuple[dt.date, ...] = CUTOFFS,
    kev_available: bool = True,
    epss_available: bool = False,
    cisa_feed_available: bool = False,
) -> Scenario:
    """A complete, internally consistent canned acquisition environment."""
    transport = FakeTransport()
    api = GitHubApi(transport)
    store = ArtifactStore(tmp_path / "store")

    for day in cutoffs:
        key = day.isoformat()
        if key in CVE_PINS:
            sha, committed, tree_sha = CVE_PINS[key]
            transport.add_json(
                cve_url(day),
                [commit_payload(sha, committed, tree_sha)],
                retrieved_at=RETRIEVED_CVE,
            )

        if kev_available:
            hist_sha, committed, version, released, count = KEV_HISTORY[key]
            tree_sha = sha40(f"tree-{key}")
            blob_sha = sha40(f"blob-{key}")
            body = kev_catalog_bytes(version, released, count=min(count, 5))
            transport.add_json(
                kev_until_url(day),
                [commit_payload(hist_sha, committed, tree_sha)],
                retrieved_at=RETRIEVED_KEV,
            )
            transport.add_json(
                kev_tree_url(tree_sha),
                tree_payload(blob_sha, len(body)),
                retrieved_at=RETRIEVED_KEV,
            )
            transport.add_json(
                kev_blob_url(blob_sha),
                blob_payload(body, blob_sha),
                retrieved_at=RETRIEVED_KEV,
            )

        if epss_available:
            transport.add_bytes(
                epss_url(day),
                epss_bytes(day),
                content_type="application/gzip",
                retrieved_at=RETRIEVED_EPSS,
            )
        else:
            transport.add_error(epss_url(day), reason="UNREACHABLE")

    if cisa_feed_available:
        transport.add_bytes(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            kev_catalog_bytes(KEV_CURRENT_VERSION, KEV_CURRENT_RELEASED, count=5),
            content_type="application/json",
            retrieved_at=RETRIEVED_KEV,
        )
    else:
        transport.add_error(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            reason="UNREACHABLE",
        )

    if kev_available:
        current_tree = sha40("tree-current")
        current_blob = sha40("blob-current")
        current_body = kev_catalog_bytes(KEV_CURRENT_VERSION, KEV_CURRENT_RELEASED, count=5)
        transport.add_json(
            kev_latest_url(),
            [commit_payload(KEV_CURRENT_COMMIT, KEV_CURRENT_COMMITTED, current_tree)],
            retrieved_at=RETRIEVED_KEV,
        )
        transport.add_json(
            kev_tree_url(current_tree),
            tree_payload(current_blob, len(current_body)),
            retrieved_at=RETRIEVED_KEV,
        )
        transport.add_json(
            kev_blob_url(current_blob),
            blob_payload(current_body, current_blob),
            retrieved_at=RETRIEVED_KEV,
        )

    return Scenario(
        transport=transport,
        api=api,
        store=store,
        cutoffs=cutoffs,
        grid=cutoffs,
    )
