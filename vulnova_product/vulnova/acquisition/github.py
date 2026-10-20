"""A minimal, policy-respecting GitHub API client.

Only the three endpoints acquisition needs are implemented: list commits up to a
timestamp, read a tree, and read a blob.  Every call returns the response URL and
the actual receipt time so the manifest can record exactly what was fetched and
when.

GitHub is used because the CVE Program's cvelistV5 and CISA's kev-data are both
published there by their owners; it is not a mirror substitution for either.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Optional

from .transport import HttpResponse, Transport, TransportError, parse_json_body

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
API_ROOT = "https://api.github.com"


class BlobNotInline(Exception):
    """The blob API refused to inline the content (files larger than 1 MB).

    GitHub documents this: ``encoding`` is ``"none"`` and no ``content`` field
    is returned.  Callers must fall back to a raw-media-type request rather than
    treating the file as corrupt.
    """

    def __init__(self, url: str, size: Optional[int]) -> None:
        super().__init__(f"{url} is not inlined (size={size})")
        self.url = url
        self.size = size


class MalformedGitHubResponse(TransportError):
    def __init__(self, url: str, detail: str, *, retrieved_at: Optional[str] = None):
        super().__init__(
            f"unexpected GitHub payload from {url}: {detail}",
            url=url,
            reason="MALFORMED_RESPONSE",
            detail=detail,
            retrieved_at=retrieved_at,
        )


@dataclass(frozen=True)
class ApiResult:
    url: str
    retrieved_at: str
    payload: object
    body: bytes
    final_url: str = ""


def commits_url(repo: str, until_iso: str) -> str:
    return f"{API_ROOT}/repos/{repo}/commits?until={until_iso}&per_page=1"


def tree_url(repo: str, sha: str) -> str:
    return f"{API_ROOT}/repos/{repo}/git/trees/{sha}"


def blob_url(repo: str, sha: str) -> str:
    return f"{API_ROOT}/repos/{repo}/git/blobs/{sha}"


class GitHubApi:
    def __init__(self, transport: Transport, *, api_root: str = API_ROOT) -> None:
        self.transport = transport
        self.api_root = api_root

    # ------------------------------------------------------------ endpoints
    def latest_commit(self, repo: str, *, ref: str = "HEAD") -> ApiResult:
        """Most recent commit reachable from ``ref`` (no timestamp filter)."""
        url = f"{self.api_root}/repos/{repo}/commits?sha={ref}&per_page=1"
        response = self.transport.get(url, accept="application/vnd.github+json")
        payload = parse_json_body(response)
        if not isinstance(payload, list):
            raise MalformedGitHubResponse(
                url, "expected a JSON list of commits", retrieved_at=response.retrieved_at
            )
        return ApiResult(
            url=url,
            retrieved_at=response.retrieved_at,
            payload=payload,
            final_url=response.final_url,
            body=response.body,
        )

    def commits_until(self, repo: str, until_iso: str) -> ApiResult:
        url = f"{self.api_root}/repos/{repo}/commits?until={until_iso}&per_page=1"
        response = self.transport.get(url, accept="application/vnd.github+json")
        payload = parse_json_body(response)
        if not isinstance(payload, list):
            raise MalformedGitHubResponse(
                url, "expected a JSON list of commits", retrieved_at=response.retrieved_at
            )
        return ApiResult(
            url=url,
            retrieved_at=response.retrieved_at,
            payload=payload,
            final_url=response.final_url,
            body=response.body,
        )

    def tree(self, repo: str, sha: str) -> ApiResult:
        if not SHA_RE.match(sha):
            raise ValueError(f"not a 40-hex tree sha: {sha!r}")
        url = f"{self.api_root}/repos/{repo}/git/trees/{sha}"
        response = self.transport.get(url, accept="application/vnd.github+json")
        payload = parse_json_body(response)
        if not isinstance(payload, dict) or not isinstance(payload.get("tree"), list):
            raise MalformedGitHubResponse(
                url, "expected an object with a 'tree' list", retrieved_at=response.retrieved_at
            )
        return ApiResult(
            url=url,
            retrieved_at=response.retrieved_at,
            payload=payload,
            final_url=response.final_url,
            body=response.body,
        )

    def blob(self, repo: str, sha: str) -> tuple[bytes, ApiResult]:
        if not SHA_RE.match(sha):
            raise ValueError(f"not a 40-hex blob sha: {sha!r}")
        url = f"{self.api_root}/repos/{repo}/git/blobs/{sha}"
        response = self.transport.get(url, accept="application/vnd.github+json")
        payload = parse_json_body(response)
        if not isinstance(payload, dict):
            raise MalformedGitHubResponse(
                url, "expected an object with base64 'content'", retrieved_at=response.retrieved_at
            )
        encoding = payload.get("encoding", "base64")
        if encoding == "none":
            raise BlobNotInline(url, payload.get("size"))
        if "content" not in payload:
            raise MalformedGitHubResponse(
                url, "expected an object with base64 'content'", retrieved_at=response.retrieved_at
            )
        if encoding != "base64":
            raise MalformedGitHubResponse(
                url, f"unsupported encoding {encoding!r}", retrieved_at=response.retrieved_at
            )
        try:
            # The API wraps base64 content at 60 characters; whitespace is not
            # part of the payload and must be removed before strict decoding.
            encoded = re.sub(r"\s+", "", str(payload["content"]))
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise MalformedGitHubResponse(
                url, f"invalid base64 content: {exc}", retrieved_at=response.retrieved_at
            ) from exc
        declared = payload.get("size")
        if isinstance(declared, int) and declared != len(body):
            raise MalformedGitHubResponse(
                url,
                f"declared size {declared} != decoded {len(body)}",
                retrieved_at=response.retrieved_at,
            )
        return body, ApiResult(
            url=url,
            retrieved_at=response.retrieved_at,
            payload=payload,
            final_url=response.final_url,
            body=response.body,
        )

    def blob_raw(self, repo: str, sha: str) -> ApiResult:
        """Fetch a blob as raw bytes (for files the JSON API will not inline)."""
        if not SHA_RE.match(sha):
            raise ValueError(f"not a 40-hex blob sha: {sha!r}")
        url = f"{self.api_root}/repos/{repo}/git/blobs/{sha}"
        response = self.transport.get(url, accept="application/vnd.github.raw")
        if not response.body:
            raise MalformedGitHubResponse(
                url, "raw blob response is empty", retrieved_at=response.retrieved_at
            )
        return ApiResult(
            url=url,
            retrieved_at=response.retrieved_at,
            payload={"bytes": len(response.body)},
            body=response.body,
            final_url=response.final_url,
        )

    # -------------------------------------------------------------- helpers
    @staticmethod
    def commit_date(commit: dict) -> Optional[str]:
        node = (commit or {}).get("commit") or {}
        committer = (node.get("committer") or {}).get("date")
        if committer:
            return committer
        return (node.get("author") or {}).get("date")

    @staticmethod
    def tree_sha(commit: dict) -> Optional[str]:
        return ((commit or {}).get("commit") or {}).get("tree", {}).get("sha")


def unchanged(response: HttpResponse) -> dict:
    """Small helper used by tests and callers that only need the metadata."""
    return {
        "url": response.url,
        "status": response.status,
        "retrieved_at": response.retrieved_at,
        "bytes": len(response.body),
    }


__all__ = [
    "API_ROOT",
    "ApiResult",
    "BlobNotInline",
    "GitHubApi",
    "MalformedGitHubResponse",
    "SHA_RE",
    "blob_url",
    "commits_url",
    "tree_url",
    "unchanged",
]
