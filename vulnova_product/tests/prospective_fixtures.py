"""Deterministic fixtures for VULNOVA 1.9 prospective-capture tests.

Every response is canned and every clock value is explicit, so a capture test
can place the run on any date without touching the system clock or the network.
Production capture never accepts a date from its caller; only tests inject one,
and only through :class:`vulnova.prospective.capture.CaptureOptions`.
"""

from __future__ import annotations

import datetime as dt
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vulnova.acquisition.github import API_ROOT, GitHubApi
from vulnova.acquisition.transport import (
    DEFAULT_ALLOWED_HOSTS,
    FakeTransport,
    HostPolicy,
    HttpResponse,
    TransportError,
    require_https,
)
from vulnova.prospective.capture import CaptureOptions
from vulnova.prospective.paths import historical_protected_paths

from tests.acquisition_fixtures import (
    blob_payload,
    commit_payload,
    epss_bytes,
    epss_url,
    kev_blob_url,
    kev_catalog_bytes,
    kev_latest_url,
    kev_tree_url,
    sha40,
    tree_payload,
)

CISA_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CVE_LATEST_URL = f"{API_ROOT}/repos/CVEProject/cvelistV5/commits?sha=HEAD&per_page=1"

DEFAULT_AS_OF = "2026-10-20T14:00:00Z"
DEFAULT_RETRIEVED = "2026-10-20T14:00:05Z"
DEFAULT_COMPLETED = "2026-10-20T14:00:09Z"

KEV_VERSION = "2026.10.16"
KEV_RELEASED = "2026-10-16T17:15:48Z"
KEV_COMMIT = "6a392940" + "0" * 32
KEV_COMMITTED = "2026-10-16T19:22:35Z"

CVE_REVISION = sha40("cvelist-head-2026-10-20")
CVE_COMMITTED = "2026-10-20T08:41:00Z"
CVE_TREE = sha40("cvelist-tree-2026-10-20")


class PolicyTransport(FakeTransport):
    """``FakeTransport`` plus the policy checks ``UrllibTransport`` performs.

    ``FakeTransport`` deliberately does not validate the URL it is asked for;
    the real transport does, on the request *and* on the URL that finally
    answered.  This wrapper reproduces those two checks without a socket, so a
    test can prove that a refused redirect is reported as ``BLOCKED`` and never
    disguised as a publisher outage.
    """

    def __init__(self, *, allowed_hosts=DEFAULT_ALLOWED_HOSTS) -> None:
        super().__init__()
        self.policy = HostPolicy(allowed_hosts)

    def get(self, url: str, *, accept: Optional[str] = None) -> HttpResponse:
        self.policy.check(url)
        require_https(url, context="requested URL")
        response = super().get(url, accept=accept)
        try:
            self.policy.check(response.final_url)
        except TransportError as exc:
            raise TransportError(
                f"response came from a host outside the acquisition policy: {response.final_url}",
                url=url,
                reason="DISALLOWED_REDIRECT_HOST",
                detail=str(exc),
            ) from exc
        try:
            require_https(response.final_url, context="final response URL")
        except TransportError as exc:
            raise TransportError(
                f"refusing insecure redirect to {response.final_url}",
                url=url,
                reason="HTTPS_DOWNGRADE_BLOCKED",
                detail=str(exc),
            ) from exc
        return response


@dataclass
class ProspectiveScenario:
    root: Path
    store_root: Path
    transport: PolicyTransport
    api: GitHubApi
    clock_value: str = DEFAULT_AS_OF
    completed_value: str = DEFAULT_COMPLETED
    protected: tuple[Path, ...] = field(default_factory=tuple)

    def options(self, **overrides) -> CaptureOptions:
        ticks = iter([self.clock_value, self.completed_value])

        def clock() -> str:
            return next(ticks, self.completed_value)

        payload = dict(
            store_root=self.store_root,
            transport=self.transport,
            api=self.api,
            clock=clock,
            protected_paths=self.protected,
            output_paths=(),
        )
        payload.update(overrides)
        return CaptureOptions(**payload)


def build_scenario(
    tmp_path: Path,
    *,
    as_of: str = DEFAULT_AS_OF,
    retrieved_at: str = DEFAULT_RETRIEVED,
    direct_feed: bool = True,
    github: bool = True,
    kev_body: Optional[bytes] = None,
    kev_version: str = KEV_VERSION,
    kev_released: str = KEV_RELEASED,
    kev_transport_error: Optional[str] = None,
    epss: str = "available",  # available | unavailable | mismatch | empty | malformed
    epss_redirect: Optional[str] = None,
    cve: str = "available",  # available | unavailable | malformed | empty
    store_name: str = "prospective_store",
) -> ProspectiveScenario:
    """A complete canned capture environment.

    ``epss``/``cve`` select the *shape of the source response*, never the
    outcome: a test that asks for ``unavailable`` is asserting that the capture
    records an outage, not that the other sources are ignored.
    """
    root = Path(tmp_path)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    transport = PolicyTransport()
    api = GitHubApi(transport)
    body = kev_body if kev_body is not None else kev_catalog_bytes(
        kev_version, kev_released
    )
    observation = dt.date.fromisoformat(as_of[:10])

    # ---- direct CISA feed
    if kev_transport_error:
        transport.add_error(CISA_FEED_URL, reason=kev_transport_error)
    elif direct_feed:
        transport.add_bytes(
            CISA_FEED_URL,
            body,
            content_type="application/json",
            retrieved_at=retrieved_at,
        )
    else:
        transport.add_error(CISA_FEED_URL, reason="UNREACHABLE")

    # ---- CISA's own GitHub repository
    if github:
        tree_sha = sha40("prospective-kev-tree")
        blob_sha = sha40("prospective-kev-blob")
        transport.add_json(
            kev_latest_url(),
            [commit_payload(KEV_COMMIT, KEV_COMMITTED, tree_sha)],
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
    else:
        transport.add_error(kev_latest_url(), reason="UNREACHABLE")

    # ---- EPSS, exact observation date
    url = epss_url(observation)
    if epss == "unavailable":
        transport.add_error(url, reason="UNREACHABLE")
    elif epss == "missing":
        transport.add_error(url, reason="HTTP_ERROR", status=404)
    elif epss == "mismatch":
        transport.add_bytes(
            url,
            epss_bytes(observation, score_date="2026-10-01T00:00:00Z"),
            content_type="application/gzip",
            retrieved_at=retrieved_at,
        )
    elif epss == "empty":
        transport.add_bytes(
            url, b"", content_type="application/gzip", retrieved_at=retrieved_at
        )
    elif epss == "malformed":
        transport.add_bytes(
            url, b"not a csv", content_type="application/gzip", retrieved_at=retrieved_at
        )
    else:
        transport.add_bytes(
            url,
            epss_bytes(observation),
            content_type="application/gzip",
            retrieved_at=retrieved_at,
            final_url=epss_redirect,
        )

    # ---- cvelistV5 head
    if cve == "unavailable":
        transport.add_error(CVE_LATEST_URL, reason="UNREACHABLE")
    elif cve == "empty":
        transport.add_json(CVE_LATEST_URL, [], retrieved_at=retrieved_at)
    elif cve == "malformed":
        transport.add_json(
            CVE_LATEST_URL,
            [{"sha": "not-a-sha", "commit": {"committer": {"date": CVE_COMMITTED}}}],
            retrieved_at=retrieved_at,
        )
    else:
        transport.add_json(
            CVE_LATEST_URL,
            [commit_payload(CVE_REVISION, CVE_COMMITTED, CVE_TREE)],
            retrieved_at=retrieved_at,
        )

    return ProspectiveScenario(
        root=root,
        store_root=root / store_name,
        transport=transport,
        api=api,
        clock_value=as_of,
        protected=(),
    )


def protected_defaults() -> tuple[Path, ...]:
    """The fixed historical paths, for assertions."""
    return historical_protected_paths()


__all__ = [
    "CISA_FEED_URL",
    "CVE_COMMITTED",
    "CVE_LATEST_URL",
    "CVE_REVISION",
    "CVE_TREE",
    "DEFAULT_AS_OF",
    "DEFAULT_COMPLETED",
    "DEFAULT_RETRIEVED",
    "KEV_COMMITTED",
    "KEV_COMMIT",
    "KEV_RELEASED",
    "KEV_VERSION",
    "PolicyTransport",
    "ProspectiveScenario",
    "build_scenario",
    "protected_defaults",
]
