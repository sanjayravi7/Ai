"""Network access with an injectable transport.

Every byte the acquisition tool ever reads passes through a :class:`Transport`.
Tests supply :class:`FakeTransport`; production uses :class:`UrllibTransport`.
Nothing here fetches at import time, so importing this module is offline-safe
and deterministic.

The transport is also where the *actual* retrieval timestamp is captured: it is
taken after the body has been read, so it can never precede the request and can
never be backdated to match the artifact it fetched.

Redirects are a security boundary, not a detail.  ``urllib``'s default handler
follows a ``Location`` header wherever it points, which would let an approved
host bounce a request to an unapproved one — or downgrade HTTPS to plaintext —
*after* the host policy had approved the original URL.  :class:`SafeRedirectHandler`
re-validates every hop against the same policy and refuses any non-HTTPS target.
The URL that actually served the bytes is reported as
:attr:`HttpResponse.final_url`, separately from the URL that was requested.
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

#: Maximum number of redirect hops a single request may take.  This bounds a
#: redirect loop; exceeding it surfaces as urllib's own redirect ``HTTPError``
#: and is reported as ``HTTP_ERROR``, not as a policy refusal, because no policy
#: decision was involved.
MAX_REDIRECTS = 5

#: Transport reasons that mean *our own policy* refused the request, as opposed
#: to the publisher failing to answer.  Sources map these to ``REDIRECT_BLOCKED``
#: instead of ``HTTP_ERROR`` so a refusal is never disguised as a server fault.
REDIRECT_REASONS = frozenset(
    {
        "INSECURE_TRANSPORT",
        "HTTPS_DOWNGRADE_BLOCKED",
        "DISALLOWED_REDIRECT_HOST",
    }
)
INITIAL_URL_REASONS = frozenset({"INSECURE_TRANSPORT"})


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
    """A completed response.

    ``url`` is the URL that was requested; ``final_url`` is the URL that actually
    served the bytes after any redirects.  They are equal when nothing redirected,
    and the distinction is kept rather than collapsed because a redirect is
    exactly the moment a host policy could otherwise be bypassed.
    """

    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    retrieved_at: str
    final_url: str = ""

    def __post_init__(self) -> None:
        if not self.final_url:
            object.__setattr__(self, "final_url", self.url)

    @property
    def redirected(self) -> bool:
        return self.final_url != self.url

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
#:
#: The EPSS entry is the host FIRST's current documentation names for the daily
#: CSV.  ``epss.cyentia.com`` was removed rather than left alongside it: it is no
#: longer documented as the daily-CSV host, it redirects to the current one, and
#: an allowlisted host that exists only to bounce a request elsewhere is policy
#: surface without a purpose.  Removing it narrows the allowlist; it does not
#: relax any redirect or downgrade check.
DEFAULT_ALLOWED_HOSTS = (
    "api.github.com",
    "codeload.github.com",
    "github.com",
    "epss.empiricalsecurity.com",
    "www.cisa.gov",
    "www.first.org",
)


def require_https(url: str, *, context: str = "request") -> str:
    """Reject anything that is not HTTPS.

    Applied to the requested URL and again to the URL that finally answered, so
    a plaintext destination is impossible even if a redirect handler misbehaves.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme != "https":
        raise TransportError(
            f"{context} is not HTTPS: {url}",
            url=url,
            reason="INSECURE_TRANSPORT",
            detail=f"scheme {scheme!r}; acquisition requires HTTPS",
        )
    return url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when they stay inside the declared policy.

    Every hop is re-checked: the destination must be HTTPS (so an approved host
    cannot downgrade the connection to plaintext), and its host must be in the
    :class:`HostPolicy` allowlist.  A rejected hop raises :class:`TransportError`
    *before* the redirected request is issued, so the request never reaches the
    unapproved host.
    """

    def __init__(self, policy: HostPolicy, *, max_redirections: int = MAX_REDIRECTS) -> None:
        super().__init__()
        self.policy = policy
        self.max_redirections = max_redirections

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        origin = req.full_url
        # Resolve relative Location headers against the URL they came from.
        target = urllib.parse.urljoin(origin, newurl)
        origin_scheme = urllib.parse.urlsplit(origin).scheme.lower()
        target_scheme = urllib.parse.urlsplit(target).scheme.lower()

        if target_scheme != "https":
            downgrade = origin_scheme == "https"
            raise TransportError(
                f"refusing {'downgrade' if downgrade else 'insecure'} redirect to {target}",
                url=origin,
                reason="HTTPS_DOWNGRADE_BLOCKED" if downgrade else "INSECURE_TRANSPORT",
                status=code,
                detail=f"{origin_scheme} -> {target_scheme} ({target})",
            )

        try:
            self.policy.check(target)
        except DisallowedHost as exc:
            raise TransportError(
                f"refusing redirect to a host outside the acquisition policy: {target}",
                url=origin,
                reason="DISALLOWED_REDIRECT_HOST",
                status=code,
                detail=str(exc),
            ) from exc

        return super().redirect_request(req, fp, code, msg, headers, target)


class UrllibTransport:
    """Standard-library HTTPS transport with an explicit host policy.

    The opener is built with :class:`SafeRedirectHandler` replacing urllib's
    default redirect handler, so the policy is enforced on every hop rather than
    only on the first request.
    """

    def __init__(
        self,
        *,
        policy: Optional[HostPolicy] = None,
        clock: Callable[[], str] = utc_now,
        timeout: float = 30.0,
        user_agent: str = USER_AGENT,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        self.policy = policy or HostPolicy(DEFAULT_ALLOWED_HOSTS)
        self.clock = clock
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        #: Count of HTTP requests actually attempted, for the run manifest.
        self.request_count = 0
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """An opener whose redirect handler enforces :class:`HostPolicy`."""
        return urllib.request.build_opener(
            SafeRedirectHandler(self.policy, max_redirections=self.max_redirects)
        )

    def get(self, url: str, *, accept: Optional[str] = None) -> HttpResponse:
        self.policy.check(url)
        require_https(url, context="requested URL")
        self.request_count += 1
        headers = {"User-Agent": self.user_agent}
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(url, headers=headers)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read()
                status = response.status
                response_headers = dict(response.headers.items())
                final_url = response.geturl() or url
        except TransportError:
            # A policy refusal raised by SafeRedirectHandler.  Never rewrite it
            # as an HTTP error: the publisher did not answer, we declined to ask.
            raise
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
        # Defence in depth: the handler already refused these, but a response
        # must never be handed back with a final URL the policy would reject.
        try:
            self.policy.check(final_url)
        except DisallowedHost as exc:
            raise TransportError(
                f"response came from a host outside the acquisition policy: {final_url}",
                url=url,
                reason="DISALLOWED_REDIRECT_HOST",
                detail=str(exc),
            ) from exc
        require_https(final_url, context="final response URL")
        retrieved_at = self.clock()
        return HttpResponse(
            url=url,
            status=status,
            headers=response_headers,
            body=body,
            retrieved_at=retrieved_at,
            final_url=final_url,
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

    def add_json(
        self,
        url: str,
        payload,
        *,
        status: int = 200,
        retrieved_at: str,
        final_url: Optional[str] = None,
    ):
        body = json.dumps(payload).encode("utf-8")
        self.responses[url] = HttpResponse(
            url=url,
            status=status,
            headers={"content-type": "application/json"},
            body=body,
            retrieved_at=retrieved_at,
            final_url=final_url or url,
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
        final_url: Optional[str] = None,
    ):
        self.responses[url] = HttpResponse(
            url=url,
            status=status,
            headers={"content-type": content_type},
            body=body,
            retrieved_at=retrieved_at,
            final_url=final_url or url,
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
    "INITIAL_URL_REASONS",
    "MAX_REDIRECTS",
    "REDIRECT_REASONS",
    "SafeRedirectHandler",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "parse_json_body",
    "require_https",
]
