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

## Evaluation readiness (1.6)

VULNOVA 1.6 adds a reproducible readiness command for a future temporal
evaluation. It verifies the Phase 2.3K artifacts, source revisions and retrieval
provenance, cutoff/maturity dates, the 30-distinct-event gate, point-in-time
feature availability and future-information leakage, then writes a
machine-readable report:

```bash
cd vulnova_product
python -m vulnova.evaluation readiness --check-reproducible \
  --markdown reports/evaluation_readiness_1_6/readiness_report.md
```

The command **trains nothing and scores nothing**. It cannot approve the protocol,
adopt a design or relax the event gate. The protocol in
`protocol/EVALUATION_PROTOCOL_1.6.md` remains `NOT_APPROVED`, and the committed
report is `BLOCKED_PROTOCOL_NOT_APPROVED`: 42 PASS, 0 FAIL, 1 BLOCKED (retrieval
timestamps) and 1 NOT_APPLICABLE (no previous report). The earliest three-block
design matures 2026-10-28, after the reference date, and the supplied KEV timeline
ends 2026-10-15. See `docs/EVALUATION_READINESS.md` for the check catalog, report
schema and status semantics.

## Historical data acquisition (1.7)

VULNOVA 1.7 adds offline-verifiable acquisition of the historical evidence a
temporal evaluation would need. For each frozen cutoff it resolves the exact
cvelistV5 revision, preserves the CISA KEV catalog as published, and records the
**actual** UTC retrieval time, response URL, byte size and SHA-256 of every
artifact it stores:

```bash
cd vulnova_product
python -m vulnova.acquisition acquire    # the only command that uses a network
python -m vulnova.acquisition verify     # offline: re-hash the archive
python -m vulnova.acquisition check      # offline: required sources and cutoffs
python -m vulnova.acquisition report     # readable missing-evidence report
```

The committed run reproduces all three cvelistV5 and all three KEV revision pins
from Phase 2.3K, and re-downloads the current KEV catalog byte-for-byte. It also
records what it could **not** get: `epss.cyentia.com` and the direct
`www.cisa.gov` feed were unreachable from the acquisition environment, and no
acquisition run today can be contemporaneous with a 2025 cutoff. Those
requirements are `UNAVAILABLE`/`BLOCKED`, never quietly satisfied. The 2026-04-01
block matures 2026-10-28 and maturity is not claimed. Overall evidence status:
`BLOCKED`. See `docs/DATA_ACQUISITION_1_7.md`.

## CI

GitHub Actions runs the unit tests and the Chromium smoke test on changes under
`vulnova_product/`, both on Python 3.11. Neither job needs `build/vulnova.db`.
The unit suite includes the readiness tests and one archive-backed reproduction
of the committed report. See `docs/CI.md` for commands, path scoping and expected
results.

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
  evaluation/     readiness checks, temporal validation, report writer
  acquisition/    historical acquisition, provenance manifest, offline verify
  static/         index.html, style.css, app.js
protocol/
  EVALUATION_PROTOCOL_1.6.md      draft protocol (NOT_APPROVED)
  evaluation_protocol.json        machine-readable protocol and approval state
docs/
  ARCHITECTURE.md
  BROWSER_TESTING.md
  CI.md
  EVALUATION_READINESS.md
  RANKING_SEMANTICS.md
tests/            test suite (386 tests, including synthetic readiness and acquisition fixtures)
tools/            verifiers, digest, manifest, pre-2020 fetch
reports/
  validation1_1/  previous phase (historical, unchanged)
  improvement1_2/ earlier product report, diffs and evidence
  improvement1_5/ CI hardening report
  evaluation_readiness_1_6/ committed readiness report (JSON + Markdown)
  acquisition_1_7/ committed acquisition manifest and missing-evidence report
data/snapshots/   KEV, EPSS, cvelistV5 manifest
data/acquisition_store/ historical artifacts acquired in 1.7, with hashes
build/vulnova.db  derived store (not snapshotted)
```

## Scope and limits

* Coverage: cvelistV5 2020–2026 ingested (identifiers without a publication date are not
  admitted); 1999–2019 only via the legacy extract (~62% of pre-2020 identifiers) plus
  KEV members.
* No historical evaluation data is produced or modified here.
* Not a validated predictive model. Not a probability of exploitation.
