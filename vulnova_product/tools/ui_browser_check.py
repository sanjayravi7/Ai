#!/usr/bin/env python3
"""Real Chromium smoke tests for VULNOVA's loading/error/retry UI.

This check serves the committed static UI and mocks only the HTTP API. It does
not need the production SQLite database, source snapshots, or internet access.
Install requirements-browser.txt and the Playwright Chromium build first.
"""
from __future__ import annotations

import json
import mimetypes
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = PRODUCT_ROOT / "vulnova" / "static"
TIMEOUT_MS = 8_000


class ResponsePlan:
    """One deterministic mock response; `hold` lets a newer request win first."""

    def __init__(self, kind: str, body: dict | None = None, status: int = 200):
        self.kind = kind
        self.body = body or {}
        self.status = status
        self.started = threading.Event()
        self.release = threading.Event()
        self.request_url = ""


class MockServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        super().__init__(address, UIHandler)
        self.plans: queue.Queue[ResponsePlan] = queue.Queue()


class UIHandler(BaseHTTPRequestHandler):
    server: MockServer

    def log_message(self, _format, *_args):
        # Keep CI output concise; assertion failures are reported by the runner.
        return

    def _send(self, status: int, content_type: str, data: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload: dict):
        self._send(status, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            target = STATIC_ROOT / "index.html"
            self._send(200, "text/html; charset=utf-8", target.read_bytes())
            return

        if parsed.path.startswith("/static/"):
            name = parsed.path.removeprefix("/static/")
            if name not in {"app.js", "style.css"}:
                self._json(404, {"message": "Not found"})
                return
            target = STATIC_ROOT / name
            mime, _ = mimetypes.guess_type(str(target))
            self._send(200, (mime or "application/octet-stream") + "; charset=utf-8", target.read_bytes())
            return

        if parsed.path == "/api/status":
            # Status failure must not block the independent ranking request.
            self._json(503, {"message": "private mocked status failure"})
            return

        if parsed.path == "/api/ranking":
            try:
                plan = self.server.plans.get(timeout=15)
            except queue.Empty:
                self._json(500, {"message": "No queued browser-test response"})
                return

            plan.request_url = self.path
            plan.started.set()
            if plan.kind == "hold" and not plan.release.wait(timeout=15):
                self._json(504, {"message": "Mock response timed out"})
                return
            if plan.kind == "http_error":
                self._json(plan.status, plan.body)
            elif plan.kind == "invalid_json":
                self._send(plan.status, "application/json; charset=utf-8", b"{not-json")
            else:
                self._json(plan.status, plan.body)
            return

        self._json(404, {"message": "Not found"})


def row(cve_id: str, score: int = 84) -> dict:
    return {
        "cve_id": cve_id,
        "band": "P1_CRITICAL",
        "score": score,
        "kev_listed": True,
        "cvss_value": 9.8,
        "epss_probability": 0.92,
        "cvss_conflict": False,
        "cvss_candidates": 1,
        "review_required": False,
        "evidence_status": "SUFFICIENT_EVIDENCE",
        "published": "2026-01-15",
    }


def ranking(*rows: dict, total: int | None = None, limit: int = 25, offset: int = 0) -> dict:
    actual_total = len(rows) if total is None else total
    return {"rows": list(rows), "total": actual_total, "limit": limit, "offset": offset}


def require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)
    print(f"  PASS  {message}")


def wait_started(plan: ResponsePlan, label: str):
    if not plan.started.wait(timeout=TIMEOUT_MS / 1000):
        raise AssertionError(f"Timed out waiting for request: {label}")


def main() -> int:
    server = MockServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    initial = ResponsePlan("hold", ranking(row("CVE-2026-0001")))
    server.plans.put(initial)

    checks = 0
    try:
        with sync_playwright() as playwright:
            launch_options = {"headless": True}
            system_chromium = os.environ.get("VULNOVA_CHROMIUM_PATH")
            if system_chromium:
                launch_options["executable_path"] = system_chromium
            browser = playwright.chromium.launch(**launch_options)
            page = browser.new_page(viewport={"width": 1365, "height": 768})
            page.set_default_timeout(TIMEOUT_MS)
            page.goto(base_url, wait_until="domcontentloaded")
            wait_started(initial, "initial ranking")

            require(page.locator("#ranking-loading").is_visible(), "initial ranking shows loading state")
            checks += 1
            require(page.locator("#ranking-loading").get_attribute("role") == "status", "loading has status role")
            checks += 1
            require(page.locator("#ranking-loading").get_attribute("aria-live") == "polite", "loading status is polite")
            checks += 1
            require(page.locator("#ranking").get_attribute("aria-busy") == "true", "table is marked busy while request is pending")
            checks += 1

            initial.release.set()
            page.locator('tr[data-cve="CVE-2026-0001"]').wait_for(state="visible")
            page.locator("#ranking-loading").wait_for(state="hidden")
            require(page.locator("#ranking").get_attribute("aria-busy") == "false", "successful response clears busy state")
            checks += 1

            # Exercise the error/Retry path on a narrow viewport as well.
            page.set_viewport_size({"width": 390, "height": 844})
            search_error = ResponsePlan("http_error", {"message": "private server detail"}, status=503)
            server.plans.put(search_error)
            page.locator("#q").fill("CVE-2026-0001")
            wait_started(search_error, "search failure")
            page.locator("#ranking-error").wait_for(state="visible")
            require(page.get_by_role("alert").is_visible(), "failed search exposes an alert")
            checks += 1
            require("private server detail" not in page.locator("#ranking-error").inner_text(), "server internals are not shown")
            checks += 1
            require(page.locator("#list-meta").inner_text() == "Results unavailable", "failed request is not presented as an empty success")
            checks += 1
            require(page.locator("tbody tr[data-cve]").count() == 0, "failed refresh clears stale rows")
            checks += 1

            filter_error = ResponsePlan("http_error", {"message": "private filter error"}, status=503)
            server.plans.put(filter_error)
            page.locator("#band").select_option("P1_CRITICAL")
            wait_started(filter_error, "filter failure")
            page.locator("#ranking-error").wait_for(state="visible")

            retry_success = ResponsePlan("json", ranking(row("CVE-2026-0001")))
            server.plans.put(retry_success)
            page.get_by_role("button", name="Retry").click()
            wait_started(retry_success, "Retry")
            retry_query = parse_qs(urlsplit(retry_success.request_url).query)
            require(retry_query.get("q") == ["CVE-2026-0001"] and
                    retry_query.get("band") == ["P1_CRITICAL"],
                    "Retry preserves the active query and priority filter")
            checks += 1
            retry_success.release.set()
            page.locator('tr[data-cve="CVE-2026-0001"]').wait_for(state="visible")
            page.locator("#ranking-error").wait_for(state="hidden")
            require(page.locator("#ranking").get_attribute("aria-busy") == "false", "successful Retry restores the results view")
            checks += 1

            # Resolve Reset's newer request before an older filter response.
            stale = ResponsePlan("hold", ranking(row("CVE-2026-0003", score=20)))
            server.plans.put(stale)
            page.locator("#band").select_option("P2_HIGH")
            wait_started(stale, "older pending filter request")
            reset_success = ResponsePlan("hold", ranking(row("CVE-2026-0002", score=35)))
            server.plans.put(reset_success)
            page.get_by_role("button", name="Reset").click()
            wait_started(reset_success, "Reset request")
            reset_query = parse_qs(urlsplit(reset_success.request_url).query)
            require("q" not in reset_query and "band" not in reset_query and "kev" not in reset_query and "review" not in reset_query,
                    "Reset clears query and filters in the request")
            checks += 1
            reset_success.release.set()
            page.locator('tr[data-cve="CVE-2026-0002"]').wait_for(state="visible")
            with page.expect_response(lambda response: "/api/ranking?" in response.url and "band=P2_HIGH" in response.url) as stale_response:
                stale.release.set()
            stale_response.value.finished()
            page.wait_for_load_state("networkidle")
            page.wait_for_function("document.querySelector('tbody tr[data-cve]')?.getAttribute('data-cve') === 'CVE-2026-0002'")
            require(page.locator('tbody tr[data-cve]').first.get_attribute("data-cve") == "CVE-2026-0002",
                    "late stale response cannot overwrite Reset results")
            checks += 1
            require(page.locator("#q").input_value() == "" and page.locator("#band").input_value() == "",
                    "Reset clears the visible controls")
            checks += 1

            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print(f"\n{checks} browser checks passed (Chromium; desktop + narrow viewport).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
