"""Network access with an injectable transport.

Every byte the acquisition tool ever reads passes through a :class:`Transport`.
Tests supply :class:`FakeTransport`; production uses :class:`UrllibTransport`.
Nothing here fetches at import time, so importing this module is offline-safe
and deterministic.

The transport is also where the *actual* retrieval timestamp is captured: it is
taken after the body has been read, so it can never precede the request and can
never be backdated to match the artifact it fetched.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Optional, Protocol

from ..provenance import utc_now

USER_AGENT = "VULNOVA-acquisition/1.7 (+https://github.com/sanjayravi7/Ai)"


class TransportError(RuntimeError):
    """A request could not be completed.

    ``reason`` is a stable machine code (``UNREACHABLE``, ``HTTP_ERROR``,
    ``RATE_LIMITED``, ``DISALLOWED_HOST``) that the manifest records verbatim.
    """

    def __init__(
        self,
        message: str,
        *,
        url: str,
        reason: str,
        status: Optional[int] = None,
        detail: str = "",
        retrieved_at: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.url = url
        self.reason = reason
        self.status = status
        self.detail = detail
        self.retrieved_at = retrieved_at


class DisallowedHost(TransportError):
    """Raised when a URL points outside the declared source policy."""


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    retrieved_at: str

    @property
    def content_type(self) -> str:
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                return value
        return ""


class Transport(Protocol):
    def get(self, url: str, *, accept: Optional[str] = None) -> HttpResponse:
        ...


class HostPolicy:
    """An explicit allowlist of hosts acquisition may talk to."""

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        self.allowed = tuple(sorted({host.lower() for host in allowed_hosts}))

    def check(self, url: str) -> str:
        host = urllib.parse.urlsplit(url).hostname or ""
        if host.lower() not in self.allowed:
            raise DisallowedHost(
                f"host {host!r} is not an approved acquisition host",
                url=url,
                reason="DISALLOWED_HOST",
                detail=f"allowed hosts: {', '.join(self.allowed)}",
            )
        return host


#: Hosts the tooling is allowed to contact.  All are first-party: GitHub for the
#: CVE Program and CISA repositories, and the two official data publishers.
DEFAULT_ALLOWED_HOSTS = (
    "api.github.com",
    "codeload.github.com",
    "github.com",
    "epss.cyentia.com",
    "www.cisa.gov",
    "www.first.org",
)


class UrllibTransport:
    """Standard-library HTTP transport with an explicit host policy."""

    def __init__(
        self,
        *,
        policy: Optional[HostPolicy] = None,
        clock: Callable[[], str] = utc_now,
        timeout: float = 30.0,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.policy = policy or HostPolicy(DEFAULT_ALLOWED_HOSTS)
        self.clock = clock
        self.timeout = timeout
        self.user_agent = user_agent
        #: Count of HTTP requests actually attempted, for the run manifest.
        self.request_count = 0

    def get(self, url: str, *, accept: Optional[str] = None) -> HttpResponse:
        self.policy.check(url)
        self.request_count += 1
        headers = {"User-Agent": self.user_agent}
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
                status = response.status
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read() or b""
            except Exception:  # pragma: no cover - defensive against fp=None
                body = b""
            if isinstance(body, str):
                body = body.encode("utf-8", "replace")
            retrieved_at = self.clock()
            reason = "RATE_LIMITED" if exc.code in (403, 429) else "HTTP_ERROR"
            raise TransportError(
                f"{exc.code} from {url}",
                url=url,
                reason=reason,
                status=exc.code,
                detail=body[:400].decode("utf-8", "replace"),
                retrieved_at=retrieved_at,
            ) from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            raise TransportError(
                f"cannot reach {url}: {exc}",
                url=url,
                reason="UNREACHABLE",
                detail=str(exc),
                retrieved_at=self.clock(),
            ) from exc
        retrieved_at = self.clock()
        return HttpResponse(
            url=url,
            status=status,
            headers=response_headers,
            body=body,
            retrieved_at=retrieved_at,
        )


@dataclass
class FakeTransport:
    """Deterministic transport for tests.

    ``responses`` maps a URL to either an :class:`HttpResponse` or an exception
    instance to raise.  Unknown URLs raise ``TransportError(UNREACHABLE)`` so a
    test that forgets a URL fails loudly rather than silently.
    """

    responses: dict[str, object] = field(default_factory=dict)
    default_reason: str = "UNREACHABLE"
    calls: list[str] = field(default_factory=list)
    policy: Optional[HostPolicy] = None

    def add_json(self, url: str, payload, *, status: int = 200, retrieved_at: str):
        body = json.dumps(payload).encode("utf-8")
        self.responses[url] = HttpResponse(
            url=url,
            status=status,
            headers={"content-type": "application/json"},
            body=body,
            retrieved_at=retrieved_at,
        )
        return self

    def add_bytes(
        self,
        url: str,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/octet-stream",
        retrieved_at: str,
    ):
        self.responses[url] = HttpResponse(
            url=url,
            status=status,
            headers={"content-type": content_type},
            body=body,
            retrieved_at=retrieved_at,
        )
        return self

    def add_error(self, url: str, *, reason: str = "UNREACHABLE", status=None, detail=""):
        self.responses[url] = TransportError(
            f"injected {reason} for {url}",
            url=url,
            reason=reason,
            status=status,
            detail=detail,
            retrieved_at=None,
        )
        return self

    def get(self, url: str, *, accept: Optional[str] = None) -> HttpResponse:
        self.calls.append(url)
        if self.policy is not None:
            self.policy.check(url)
        result = self.responses.get(url)
        if result is None:
            raise TransportError(
                f"no canned response for {url}",
                url=url,
                reason=self.default_reason,
            )
        if isinstance(result, TransportError):
            raise result
        assert isinstance(result, HttpResponse)
        return result


def parse_json_body(response: HttpResponse):
    """Parse a JSON body, raising ``TransportError(MALFORMED_RESPONSE)``."""
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransportError(
            f"malformed JSON from {response.url}: {exc}",
            url=response.url,
            reason="MALFORMED_RESPONSE",
            detail=response.body[:200].decode("utf-8", "replace"),
            retrieved_at=response.retrieved_at,
        ) from exc


__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "DisallowedHost",
    "FakeTransport",
    "HostPolicy",
    "HttpResponse",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "parse_json_body",
]
