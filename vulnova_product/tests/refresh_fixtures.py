"""Deterministic fixtures for the VULNOVA 1.8 refresh tests.

Every timestamp is explicit and every response is canned, so a refresh test can
place the run on any date it likes without touching the system clock or the
network.  Production code always uses the real UTC clock; only the tests inject
one, and only through :class:`vulnova.refresh.workflow.RefreshOptions`.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from vulnova.acquisition.github import GitHubApi
from vulnova.acquisition.manifest import build_manifest
from vulnova.acquisition.records import ArtifactRecord, Requirement
from vulnova.acquisition.store import ArtifactStore
from vulnova.acquisition.transport import FakeTransport
from vulnova.refresh.workflow import RefreshOptions

from tests.acquisition_fixtures import (
    KEV_CURRENT_COMMIT,
    KEV_CURRENT_COMMITTED,
    blob_payload,
    commit_payload,
    epss_bytes,
    epss_url,
    kev_blob_url,
    kev_latest_url,
    kev_tree_url,
    sha40,
    tree_payload,
)

CISA_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

CUTOFFS = (dt.date(2025, 2, 1), dt.date(2025, 9, 1), dt.date(2026, 4, 1))
FINAL_MATURITY = dt.date(2026, 10, 28)

#: A catalog that clearly predates the final maturity.
PRE_MATURITY_CATALOG = "2026-10-16T17:15:48Z"
#: A catalog released on the maturity date itself.
ON_MATURITY_CATALOG = "2026-10-28T06:00:00Z"
#: A catalog released after maturity.
POST_MATURITY_CATALOG = "2026-10-29T09:30:00Z"

DEFAULT_AS_OF = "2026-10-20T09:00:00Z"
DEFAULT_RETRIEVED = "2026-10-20T09:00:10Z"


def catalog_bytes(
    *,
    version: str = "2026.10.16",
    released: str = PRE_MATURITY_CATALOG,
    entries: Sequence[tuple[str, str]] = (
        ("CVE-2024-1000", "2024-01-01"),
        ("CVE-2024-1001", "2024-06-01"),
        ("CVE-2025-2000", "2025-03-01"),
    ),
    declared: Optional[int] = None,
    raw_entries: Optional[list[dict]] = None,
) -> bytes:
    """Build a schema-valid KEV catalog with explicit ``dateAdded`` values."""
    if raw_entries is None:
        raw_entries = [
            {
                "cveID": cve,
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": f"Test {cve}",
                "dateAdded": added,
                "knownRansomwareCampaignUse": "Unknown",
            }
            for cve, added in entries
        ]
    payload = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": released,
        "count": declared if declared is not None else len(raw_entries),
        "vulnerabilities": raw_entries,
    }
    return json.dumps(payload, indent=2).encode("utf-8")


@dataclass
class RefreshScenario:
    root: Path
    store: ArtifactStore
    transport: FakeTransport
    api: GitHubApi
    clock_value: str = DEFAULT_AS_OF
    protected: tuple[Path, ...] = ()
    baseline_report_path: Optional[Path] = None
    baseline_manifest_path: Optional[Path] = None
    baseline_store_path: Optional[Path] = None
    extras: dict = field(default_factory=dict)

    def options(self, **overrides) -> RefreshOptions:
        payload = dict(
            store=self.store,
            transport=self.transport,
            api=self.api,
            clock=lambda: self.clock_value,
            cutoffs=CUTOFFS,
            protocol_path=self.extras.get("protocol_path"),
            baseline_report_path=self.baseline_report_path,
            baseline_manifest_path=self.baseline_manifest_path,
            baseline_store_path=self.baseline_store_path,
            protected_paths=self.protected,
            readiness_factory=self.extras.get("readiness_factory"),
            repository_root=self.root,
        )
        payload.update(overrides)
        return RefreshOptions(**payload)


def build_scenario(
    tmp_path: Path,
    *,
    as_of: str = DEFAULT_AS_OF,
    catalog_released: str = PRE_MATURITY_CATALOG,
    catalog_version: str = "2026.10.16",
    entries: Optional[Sequence[tuple[str, str]]] = None,
    raw_entries: Optional[list[dict]] = None,
    declared: Optional[int] = None,
    direct_feed: bool = False,
    direct_feed_redirect: Optional[str] = None,
    epss: str = "unavailable",  # "unavailable" | "available" | "mismatch"
    archive: bool = False,
    retrieved_at: str = DEFAULT_RETRIEVED,
) -> RefreshScenario:
    """A complete canned refresh environment.

    ``archive=True`` writes a small but real 1.7-shaped archive (manifest plus
    stored bytes) so the seal guard has something to measure.
    """
    root = Path(tmp_path)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    transport = FakeTransport()
    api = GitHubApi(transport)
    store = ArtifactStore(root / "refresh_store")

    body = catalog_bytes(
        version=catalog_version,
        released=catalog_released,
        entries=entries
        if entries is not None
        else (
            ("CVE-2024-1000", "2024-01-01"),
            ("CVE-2024-1001", "2024-06-01"),
            ("CVE-2025-2000", "2025-03-01"),
        ),
        declared=declared,
        raw_entries=raw_entries,
    )

    # ---- direct CISA feed
    if direct_feed:
        transport.add_bytes(
            CISA_FEED_URL,
            body,
            content_type="application/json",
            retrieved_at=retrieved_at,
            final_url=direct_feed_redirect,
        )
    else:
        transport.add_error(CISA_FEED_URL, reason="UNREACHABLE")

    # ---- CISA's own GitHub repository
    tree_sha = sha40("refresh-tree")
    blob_sha = sha40("refresh-blob")
    transport.add_json(
        kev_latest_url(),
        [commit_payload(KEV_CURRENT_COMMIT, KEV_CURRENT_COMMITTED, tree_sha)],
        retrieved_at=retrieved_at,
    )
    transport.add_json(
        kev_tree_url(tree_sha),
        tree_payload(blob_sha, len(body)),
        retrieved_at=retrieved_at,
    )
    transport.add_json(
        kev_blob_url(blob_sha),
        blob_payload(body, blob_sha),
        retrieved_at=retrieved_at,
    )

    # ---- EPSS
    for cutoff in CUTOFFS:
        if epss == "unavailable":
            transport.add_error(epss_url(cutoff), reason="UNREACHABLE")
        elif epss == "mismatch":
            transport.add_bytes(
                epss_url(cutoff),
                epss_bytes(cutoff, score_date="2026-10-01T00:00:00Z"),
                content_type="application/gzip",
                retrieved_at=retrieved_at,
            )
        else:
            transport.add_bytes(
                epss_url(cutoff),
                epss_bytes(cutoff),
                content_type="application/gzip",
                retrieved_at=retrieved_at,
            )

    scenario = RefreshScenario(
        root=root,
        store=store,
        transport=transport,
        api=api,
        clock_value=as_of,
    )

    if archive:
        scenario.baseline_manifest_path, scenario.baseline_store_path = build_archive(root)
        scenario.protected = (
            scenario.baseline_manifest_path,
            scenario.baseline_store_path,
        )
    return scenario


def build_archive(root: Path) -> tuple[Path, Path]:
    """A tiny, internally consistent 1.7-shaped archive used by the seal guard."""
    store_root = root / "sealed_1_7_store"
    store = ArtifactStore(store_root)
    records = []
    rows = [
        ("kev", "current", "kev/current/known_exploited_vulnerabilities.json", b'{"count": 0}'),
        ("epss", "2025-02-01", "epss/epss_scores-2025-02-01.csv.gz", b"sealed-epss"),
    ]
    for source, key, relative, body in rows:
        stored = store.write(relative, body)
        records.append(
            {
                "source": source,
                "key": key,
                "channel": "OFFICIAL_GITHUB",
                "source_url": "https://api.github.com/repos/cisagov/kev-data",
                "request_url": "https://api.github.com/repos/cisagov/kev-data/git/blobs/x",
                "content_status": "VERIFIED",
                "reason_code": "OK_VERIFIED",
                "access_provenance": "CONTEMPORANEOUS",
                "historical_retrieval_verified": False,
                "artifact_path": stored.relative_path,
                "bytes": stored.bytes,
                "sha256": stored.sha256,
                "retrieved_at": "2026-10-19T18:56:54Z",
                "source_timestamp": "2026-10-16T17:15:48Z",
            }
        )
    manifest = build_manifest(
        records=[_as_record(row) for row in records],
        requirements=[
            Requirement(
                id="PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED",
                title="fixture",
                status="VERIFIED",
                reason_code="OK_VERIFIED",
                detail="fixture",
            )
        ],
        generated_at="2026-10-19T18:57:00Z",
        cutoffs=["2025-02-01", "2025-09-01", "2026-04-01"],
        grid_cutoffs=["2025-02-01", "2025-09-01", "2026-04-01"],
        as_of="2026-10-19",
    )
    path = root / "sealed_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, store_root


def _as_record(payload: dict) -> ArtifactRecord:
    record = ArtifactRecord(
        source=payload["source"],
        key=payload["key"],
        channel=payload["channel"],
        source_url=payload["source_url"],
        request_url=payload["request_url"],
        content_status=payload["content_status"],
        reason_code=payload["reason_code"],
    )
    record.access_provenance = payload["access_provenance"]
    record.historical_retrieval_verified = payload["historical_retrieval_verified"]
    record.artifact_path = payload["artifact_path"]
    record.bytes = payload["bytes"]
    record.sha256 = payload["sha256"]
    record.retrieved_at = payload["retrieved_at"]
    record.source_timestamp = payload["source_timestamp"]
    return record


def tamper_archive(scenario: RefreshScenario) -> None:
    """Flip one byte of a sealed artifact, to prove the guard notices."""
    store = ArtifactStore(scenario.baseline_store_path)
    target = store.path("kev/current/known_exploited_vulnerabilities.json")
    target.write_bytes(b'{"count": 1}')


__all__ = [
    "CISA_FEED_URL",
    "CUTOFFS",
    "DEFAULT_AS_OF",
    "DEFAULT_RETRIEVED",
    "FINAL_MATURITY",
    "ON_MATURITY_CATALOG",
    "POST_MATURITY_CATALOG",
    "PRE_MATURITY_CATALOG",
    "RefreshScenario",
    "build_archive",
    "build_scenario",
    "catalog_bytes",
    "tamper_archive",
]
