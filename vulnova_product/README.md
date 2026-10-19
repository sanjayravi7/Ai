# VULNOVA — prototype triage console

A read-only console that ranks CVE records by a **provisional, rule-based** priority
score and explains exactly which evidence produced each score.

> This workspace is rebuilt from source each time the sandbox is re-initialised; see
> `REBUILD.md` for the one-command restore. The derived store (`build/vulnova.db`) and
> the virtualenv (`.venv/`) are intentionally excluded from snapshots.

## What it does

* Ingests four sources with pinned revisions and content checksums: cvelistV5
  (2020–2026, plus KEV members from 1999–2019), the legacy CVE extract (1999–2019),
  the CISA KEV catalog, and a daily EPSS snapshot.
* Scores each CVE on a fixed denominator of 100:
  KEV 40 · EPSS 30 · CVSS 20 · **`publication_recency` 10**.
* `publication_recency` is based on the **CVE publication date only**. It does *not*
  represent recent exploitation activity, recent KEV inclusion, or an independently
  verified increase in threat activity.
* Refuses to let missing evidence look like low risk: records with no CVSS **and** no
  EPSS get an `INSUFFICIENT_EVIDENCE` status, a `review_required` flag and a display
  band that says so.
* Shows every conflicting CVSS value from every source, which one was selected, why,
  and whether the values are comparable.
* Serves a searchable ranking and a per-CVE explanation, with provenance and
  retrieval timestamps.

## Quick start

From a **clean checkout**, follow `RUNBOOK.md` — it covers the virtualenv, the pinned
source fetch, the database build and the expected row counts.

Once `build/vulnova.db` exists:

```bash
.venv/bin/python -m vulnova.web --db build/vulnova.db --host 127.0.0.1 --port 8000 --warm
# → http://127.0.0.1:8000
```

## Verify

```bash
./verify_all.sh
```

Runs `pytest`, `tools/verify_product.py` and `tools/ui_render_check.js`
(30 checks — a DOM shim, **not** a screenshot). This full check needs the built
store and is not run in lightweight CI.

## CI

GitHub Actions runs the unit tests and the Chromium smoke test on changes under
`vulnova_product/`, both on Python 3.11. Neither job needs `build/vulnova.db`.
See `docs/CI.md` for commands, path scoping and expected results.

## Layout

```
RUNBOOK.md        clean-checkout instructions
REBUILD.md        restoring a lost sandbox workspace
PRESERVATION.md   provenance of this preserved snapshot
requirements.txt  runtime + test dependencies
pyproject.toml    package metadata and pytest config
vulnova/
  sources/{cvelistv5,legacy_csv,kev,epss}.py   source adapters
  store.py        SQLite schema and status
  ingest.py       ingest CLI with reconciliation receipts
  rank.py         scoring arithmetic only
  assessment.py   evidence-adequacy interpretation only
  explain.py      per-CVE payload, conflicts, coverage
  web.py          HTTP API + static UI
  static/         index.html, style.css, app.js
docs/
  ARCHITECTURE.md
  BROWSER_TESTING.md
  CI.md
  RANKING_SEMANTICS.md
tests/            test suite
tools/            verifiers, digest, manifest, pre-2020 fetch
reports/
  validation1_1/  previous phase (historical, unchanged)
  improvement1_2/ this phase's report, diffs and evidence
data/snapshots/   KEV, EPSS, cvelistV5 manifest
build/vulnova.db  derived store (not snapshotted)
```

## Scope and limits

* Coverage: cvelistV5 2020–2026 ingested (identifiers without a publication date are not
  admitted); 1999–2019 only via the legacy extract (~62% of pre-2020 identifiers) plus
  KEV members.
* No historical evaluation data is produced or modified here.
* Not a validated predictive model. Not a probability of exploitation.
