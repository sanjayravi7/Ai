"""Transport behaviour: host policy, error taxonomy and retrieval clocks."""

from __future__ import annotations

import json

import pytest

from vulnova.acquisition.transport import (
    DisallowedHost,
    FakeTransport,
    HostPolicy,
    HttpResponse,
    TransportError,
    UrllibTransport,
    parse_json_body,
)


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


def test_urllib_transport_timestamps_after_body_read(monkeypatch):
    """The retrieval clock is read after the body, never before the request."""
    events: list[str] = []

    def clock():
        events.append("clock")
        return "2026-10-20T00:00:09Z"

    transport = UrllibTransport(clock=clock)

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self):
            events.append("body-read")
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: FakeResponse())
    response = transport.get("https://api.github.com/anything")
    assert events == ["body-read", "clock"]
    assert response.retrieved_at == "2026-10-20T00:00:09Z"


def test_http_error_becomes_a_typed_transport_error(monkeypatch):
    import urllib.error

    def raise_http(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 404, "Not Found", {}, None
        )

    transport = UrllibTransport(clock=lambda: "2026-10-20T00:00:00Z")
    monkeypatch.setattr("urllib.request.urlopen", raise_http)
    with pytest.raises(TransportError) as excinfo:
        transport.get("https://api.github.com/missing")
    assert excinfo.value.status == 404
    assert excinfo.value.retrieved_at == "2026-10-20T00:00:00Z"


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
