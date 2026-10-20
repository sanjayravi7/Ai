"""Transport behaviour: host policy, error taxonomy and retrieval clocks."""

from __future__ import annotations

import email.message
import json
import urllib.error
import urllib.request
from urllib.request import BaseHandler

import pytest

from vulnova.acquisition.transport import (
    DisallowedHost,
    FakeTransport,
    HostPolicy,
    HttpResponse,
    SafeRedirectHandler,
    TransportError,
    UrllibTransport,
    parse_json_body,
    require_https,
)


class _StubResponse:
    """Stand-in for the object ``OpenerDirector.open`` returns."""

    def __init__(self, body: bytes, status: int, final_url: str):
        self._body = body
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self._final_url = final_url

    def read(self):
        return self._body

    def geturl(self):
        return self._final_url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _StubOpener:
    """An opener with scripted final-URL behaviour, used instead of a socket."""

    def __init__(self, *, body=b'{"ok": true}', status=200, final_url=None, error=None):
        self.body = body
        self.status = status
        self.final_url = final_url
        self.error = error
        self.requested: list[str] = []

    def open(self, request, timeout=None):
        self.requested.append(request.full_url)
        if self.error is not None:
            raise self.error
        return _StubResponse(self.body, self.status, self.final_url or request.full_url)


def test_host_policy_allows_known_hosts_only():
    policy = HostPolicy(["api.github.com"])
    assert policy.check("https://api.github.com/repos/x") == "api.github.com"
    with pytest.raises(DisallowedHost) as excinfo:
        policy.check("https://evil.example.com/x")
    assert excinfo.value.reason == "DISALLOWED_HOST"


def test_transport_error_carries_machine_readable_fields():
    error = TransportError(
        "boom", url="https://api.github.com/x", reason="HTTP_ERROR", status=500, detail="bad"
    )
    assert error.reason == "HTTP_ERROR"
    assert error.status == 500
    assert error.url.endswith("/x")


def test_default_policy_covers_only_first_party_hosts():
    transport = UrllibTransport()
    for url in (
        "https://api.github.com/x",
        "https://epss.cyentia.com/x",
        "https://www.cisa.gov/x",
    ):
        transport.policy.check(url)
    with pytest.raises(DisallowedHost):
        transport.policy.check("https://raw.githubusercontent.com/x")


def test_urllib_transport_timestamps_after_body_read():
    """The retrieval clock is read after the body, never before the request."""
    events: list[str] = []

    def clock():
        events.append("clock")
        return "2026-10-20T00:00:09Z"

    class RecordingResponse(_StubResponse):
        def read(self):
            events.append("body-read")
            return super().read()

    class RecordingOpener(_StubOpener):
        def open(self, request, timeout=None):
            return RecordingResponse(b"{}", 200, request.full_url)

    transport = UrllibTransport(clock=clock)
    transport._opener = RecordingOpener()
    response = transport.get("https://api.github.com/anything")
    assert events == ["body-read", "clock"]
    assert response.retrieved_at == "2026-10-20T00:00:09Z"


def test_http_error_becomes_a_typed_transport_error():
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    transport._opener = _StubOpener(
        error=urllib.error.HTTPError(
            "https://api.github.com/missing", 404, "Not Found", {}, None
        )
    )
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/missing")
    assert excinfo.value.reason == "HTTP_ERROR"
    assert excinfo.value.status == 404
    assert excinfo.value.retrieved_at == "2026-10-20T00:00:00Z"


def test_rate_limited_http_error_keeps_its_own_reason():
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    transport._opener = _StubOpener(
        error=urllib.error.HTTPError(
            "https://api.github.com/x", 403, "Forbidden", {}, None
        )
    )
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/x")
    assert excinfo.value.reason == "RATE_LIMITED"


def test_rate_limit_status_is_classified():
    transport = FakeTransport().add_error(
        "https://api.github.com/x", reason="RATE_LIMITED", status=403
    )
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/x")
    assert excinfo.value.reason == "RATE_LIMITED"


def test_fake_transport_fails_loudly_on_an_unregistered_url():
    transport = FakeTransport()
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/unexpected")
    assert excinfo.value.reason == "UNREACHABLE"


def test_parse_json_body_reports_malformed_payloads():
    response = HttpResponse(
        url="https://api.github.com/x",
        status=200,
        headers={"content-type": "application/json"},
        body=b"{not json",
        retrieved_at="2026-10-20T00:00:00Z",
    )
    with pytest.raises(TransportError) as excinfo:
        parse_json_body(response)
    assert excinfo.value.reason == "MALFORMED_RESPONSE"
    assert excinfo.value.retrieved_at == "2026-10-20T00:00:00Z"


def test_fake_transport_records_every_call():
    transport = FakeTransport().add_json(
        "https://api.github.com/x", {"ok": True}, retrieved_at="2026-10-20T00:00:00Z"
    )
    transport.get("https://api.github.com/x")
    assert transport.calls == ["https://api.github.com/x"]
    assert json.loads(transport.responses["https://api.github.com/x"].body) == {"ok": True}


# ---------------------------------------------------------------------------
# Redirect policy.  A redirect is the one moment the host allowlist could be
# bypassed: the original URL is approved, then a header points elsewhere.
# ---------------------------------------------------------------------------
def _policy() -> HostPolicy:
    return HostPolicy(["api.github.com", "www.cisa.gov"])


def _request(url: str = "https://api.github.com/repos/x") -> urllib.request.Request:
    return urllib.request.Request(url)


def _redirect(handler, newurl, *, origin="https://api.github.com/repos/x", code=302):
    return handler.redirect_request(
        _request(origin), None, code, "Found", {}, newurl
    )


def test_redirect_to_an_allowed_https_host_is_followed():
    handler = SafeRedirectHandler(_policy())
    new = _redirect(handler, "https://api.github.com/repos/y")
    assert new.full_url == "https://api.github.com/repos/y"


def test_redirect_to_another_allowed_host_is_followed():
    handler = SafeRedirectHandler(_policy())
    new = _redirect(handler, "https://www.cisa.gov/feeds/kev.json")
    assert new.full_url == "https://www.cisa.gov/feeds/kev.json"


def test_relative_redirect_is_resolved_against_the_original_url():
    handler = SafeRedirectHandler(_policy())
    new = _redirect(handler, "/repos/y?page=2")
    assert new.full_url == "https://api.github.com/repos/y?page=2"


def test_redirect_to_a_disallowed_host_is_refused_before_it_is_issued():
    handler = SafeRedirectHandler(_policy())
    with pytest.raises(TransportError) as excinfo:
        _redirect(handler, "https://evil.example.com/steal")
    error = excinfo.value
    assert error.reason == "DISALLOWED_REDIRECT_HOST"
    # The error names the URL we asked for, not the one we refused to visit.
    assert error.url == "https://api.github.com/repos/x"
    assert "evil.example.com" in error.detail


def test_redirect_to_a_disallowed_host_on_a_relative_lookalike_is_refused():
    handler = SafeRedirectHandler(_policy())
    with pytest.raises(TransportError) as excinfo:
        _redirect(handler, "//evil.example.com/steal")
    assert excinfo.value.reason == "DISALLOWED_REDIRECT_HOST"


def test_https_to_http_downgrade_is_refused_even_for_an_allowed_host():
    handler = SafeRedirectHandler(_policy())
    with pytest.raises(TransportError) as excinfo:
        _redirect(handler, "http://api.github.com/repos/y")
    assert excinfo.value.reason == "HTTPS_DOWNGRADE_BLOCKED"
    assert excinfo.value.status == 302


def test_downgrade_is_refused_for_307_and_308_too():
    handler = SafeRedirectHandler(_policy())
    for code in (301, 303, 307, 308):
        with pytest.raises(TransportError) as excinfo:
            _redirect(handler, "http://api.github.com/repos/y", code=code)
        assert excinfo.value.reason == "HTTPS_DOWNGRADE_BLOCKED"


def test_non_http_scheme_redirect_is_refused():
    handler = SafeRedirectHandler(_policy())
    with pytest.raises(TransportError) as excinfo:
        _redirect(handler, "ftp://api.github.com/repos/y")
    assert excinfo.value.reason == "HTTPS_DOWNGRADE_BLOCKED"


def test_require_https_rejects_plaintext_urls():
    with pytest.raises(TransportError) as excinfo:
        require_https("http://api.github.com/x")
    assert excinfo.value.reason == "INSECURE_TRANSPORT"
    assert require_https("https://api.github.com/x") == "https://api.github.com/x"


def test_transport_installs_the_policy_aware_redirect_handler():
    """urllib's permissive default must actually be replaced, not shadowed."""
    transport = UrllibTransport()
    handlers = transport._opener.handlers
    assert any(isinstance(handler, SafeRedirectHandler) for handler in handlers)
    assert not any(type(handler) is urllib.request.HTTPRedirectHandler for handler in handlers)
    installed = next(h for h in handlers if isinstance(h, SafeRedirectHandler))
    assert installed.policy is transport.policy


def test_transport_refuses_a_plaintext_initial_url():
    transport = UrllibTransport()
    transport._opener = _StubOpener()
    with pytest.raises(TransportError) as excinfo:
        transport.get("http://api.github.com/x")
    assert excinfo.value.reason == "INSECURE_TRANSPORT"
    assert transport._opener.requested == []


def test_transport_refuses_an_initial_url_on_a_disallowed_host():
    transport = UrllibTransport()
    transport._opener = _StubOpener()
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://evil.example.com/x")
    assert excinfo.value.reason == "DISALLOWED_HOST"
    assert transport._opener.requested == []


def test_final_url_is_recorded_separately_after_a_redirect():
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    transport._opener = _StubOpener(
        final_url="https://api.github.com/repositories/42"
    )
    response = transport.get("https://api.github.com/repos/x")
    assert response.url == "https://api.github.com/repos/x"
    assert response.final_url == "https://api.github.com/repositories/42"
    assert response.redirected is True


def test_unredirected_response_records_the_same_url_twice():
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    transport._opener = _StubOpener()
    response = transport.get("https://api.github.com/repos/x")
    assert response.final_url == response.url
    assert response.redirected is False


def test_a_final_url_outside_the_policy_is_rejected_as_defence_in_depth():
    """Even if a handler misbehaved, the response itself is re-checked."""
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    transport._opener = _StubOpener(final_url="https://evil.example.com/x")
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/repos/x")
    assert excinfo.value.reason == "DISALLOWED_REDIRECT_HOST"


def test_a_final_url_on_plaintext_is_rejected_as_defence_in_depth():
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    transport._opener = _StubOpener(final_url="http://api.github.com/repos/x")
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/repos/x")
    assert excinfo.value.reason == "INSECURE_TRANSPORT"


def test_policy_refusal_is_never_reported_as_a_generic_http_error():
    """A refusal is our decision, so it must keep its own machine code."""
    handler = SafeRedirectHandler(_policy())
    with pytest.raises(TransportError) as excinfo:
        _redirect(handler, "https://evil.example.com/x")
    assert excinfo.value.reason in {
        "INSECURE_TRANSPORT",
        "HTTPS_DOWNGRADE_BLOCKED",
        "DISALLOWED_REDIRECT_HOST",
    }
    assert excinfo.value.reason != "HTTP_ERROR"


class _FakeFP:
    """Minimal file-like body for the error path (urllib wraps it in addinfourl)."""

    msg = None

    def read(self, *args):
        return b""

    def close(self):
        pass


class _FakeSuccess:
    """Enough of ``http.client.HTTPResponse`` for urllib's response processor."""

    code = 200
    status = 200
    msg = "OK"

    def __init__(self, body: bytes, url: str):
        self._body = body
        self._url = url
        self.headers = email.message.Message()

    def info(self):
        return self.headers

    def read(self, *args):
        return self._body

    def geturl(self):
        return self._url

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeHTTP(BaseHandler):
    """One canned 302 through the *real* urllib redirect chain, no socket.

    ``https_open`` routes the response through ``OpenerDirector.error`` exactly
    as ``AbstractHTTPHandler.do_open`` does, so ``http_error_302`` — and therefore
    ``SafeRedirectHandler.redirect_request`` — really runs. A handler that merely
    raised ``HTTPError`` would bypass the redirect machinery entirely and prove
    nothing.

    The first request answers 302 with ``location``; the follow-up answers 200 so
    an allowed hop can complete and report its final URL.
    """

    handler_order = 100

    def __init__(self, location: str):
        self.location = location
        self.requests: list[str] = []

    def https_open(self, request):
        self.requests.append(request.full_url)
        if len(self.requests) == 1:
            headers = email.message.Message()
            headers["Location"] = self.location
            return self.parent.error(
                "http", request, _FakeFP(), 302, "Found", headers
            )
        return _FakeSuccess(b'{"ok": true}', self.location)


def _real_opener_transport(location: str):
    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    handler = _FakeHTTP(location)
    transport._opener.add_handler(handler)
    return transport, handler


def test_real_opener_follows_an_allowed_redirect_and_records_the_final_url():
    """End to end through urllib's own redirect machinery: hop allowed, URL kept."""
    transport, handler = _real_opener_transport("https://api.github.com/repos/y")
    response = transport.get("https://api.github.com/repos/x")
    assert handler.requests == [
        "https://api.github.com/repos/x",
        "https://api.github.com/repos/y",
    ]
    assert response.url == "https://api.github.com/repos/x"
    assert response.final_url == "https://api.github.com/repos/y"
    assert response.redirected is True
    assert response.body == b'{"ok": true}'


def test_real_opener_refuses_a_disallowed_redirect_end_to_end():
    transport, handler = _real_opener_transport("https://evil.example.com/steal")
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/repos/x")
    assert excinfo.value.reason == "DISALLOWED_REDIRECT_HOST"
    # The refusal happened before the hop: evil.example.com was never requested.
    assert handler.requests == ["https://api.github.com/repos/x"]


def test_real_opener_refuses_a_downgrade_end_to_end():
    transport, handler = _real_opener_transport("http://api.github.com/repos/y")
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/repos/x")
    assert excinfo.value.reason == "HTTPS_DOWNGRADE_BLOCKED"
    assert handler.requests == ["https://api.github.com/repos/x"]


def test_real_opener_refusal_is_not_rewritten_as_an_http_error():
    """The refusal must survive urllib's error machinery intact."""
    transport, _ = _real_opener_transport("https://evil.example.com/steal")
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/repos/x")
    assert not isinstance(excinfo.value, urllib.error.HTTPError)
    assert excinfo.value.reason != "HTTP_ERROR"
