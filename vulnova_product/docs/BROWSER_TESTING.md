# Real-browser UI checks

The normal `./verify_all.sh` suite includes a DOM-shim rendering check and a
mocked request-order regression suite. The separate Chromium smoke test exercises
the real browser runtime without requiring the built SQLite store or external
feeds.

From `vulnova_product/`:

```bash
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python tools/ui_browser_check.py
```

The check verifies the initial loading state and live-status semantics, successful
rendering, safe HTTP failure presentation, clearing stale rows, Retry preserving
filters, Reset clearing controls, and stale-response protection. It runs the main
flow at a desktop viewport and the failure/Retry path at a narrow viewport.

GitHub Actions runs it on pull requests and pushes that touch `vulnova_product/`.
A passing run prints `14 browser checks passed (Chromium; desktop + narrow
viewport).` The script mocks `/api/status` and `/api/ranking`; it is a frontend
integration smoke test, not a test of the production database, source ingestion,
non-Chromium engines, or assistive-technology announcements.

See `CI.md` for the workflow definition, path scoping and the unit-test commands.
