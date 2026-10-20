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
ends 2026-10-15. See `docs/EVALUATION_READINESS_1_6.md` for the check catalog, report
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

## Maturity gate and evidence refresh (1.8)

VULNOVA 1.8 answers one question the earlier phases could only defer: after the
final candidate block matures on **2026-10-28**, can its labels actually be
observed? Calendar maturity and observability are kept apart, because a KEV
catalog released before the maturity date cannot contain labels that settled
after it.

```bash
cd vulnova_product
python -m vulnova.refresh gate     # offline: is the block mature, and observable?
python -m vulnova.refresh run      # the only network-using command
python -m vulnova.refresh verify   # offline: re-hash the refresh + the sealed archive
```

The committed run (as of 2026-10-20) reports `BLOCKED_MATURITY_NOT_REACHED`: the
final labels mature 2026-10-28, 8 days later, and the catalog in hand
(`2026.10.16`) predates them, so the observation is right-censored and **no**
`dateAdded`-filtered label view is produced. `run` has no date override — it
always uses the real UTC clock and records each artifact's actual retrieval
time. The refresh writes to its own store and report directory. All three of its
destinations — store, JSON report, Markdown summary — are validated before the
first network request against every sealed input (the 1.7 archive and manifest,
the committed 1.6 report, `data/snapshots`, the Phase 2.3K export and whatever
`--protocol`/`--baseline`/`--artifacts` name), and it re-hashes all seven sealed
1.7 artifacts before and after each run. A refused path writes nothing.

The readiness comparison against the committed 1.6 report shows **0 check status
changes** and **no admissible design**; the protocol remains `NOT_APPROVED`.
A digest difference between the two reports is expected and is explained in the
report itself: a readiness report embeds its own as-of date. See
`docs/MATURITY_REFRESH_1_8.md`.

## Prospective evidence capture (1.9)

VULNOVA 1.9 starts recording evidence while the period is live, so a future
assessment does not depend on artifacts downloaded years after the fact. One
capture preserves, with its real UTC retrieval time and SHA-256, the CISA KEV
catalog (from the publisher's feed and from CISA's own repository), the exact
daily EPSS file for the observation date from FIRST's documented daily-CSV host
`epss.empiricalsecurity.com` (1.9.1; the legacy `epss.cyentia.com` is no longer
requested), and the observable cvelistV5 commit SHA — without cloning the
multi-gigabyte repository.

```bash
cd vulnova_product
python -m vulnova.prospective capture   # the only network-using command
python -m vulnova.prospective verify    # offline: re-hash every capture
python -m vulnova.prospective report    # offline: deterministic summary
```

The store is append-only and content-addressed (`~/.vulnova/prospective` by
default, `--store` or `VULNOVA_PROSPECTIVE_STORE` to relocate). Nothing is
overwritten; two captures of the same day that disagree are both kept and
reported as a conflict. Every write target is validated before the first network
request against the sealed 1.6 report, the 1.7 archive, `data/snapshots`, the
Phase 2.3K export, the 1.8 refresh store and reports, and `protocol/`. An
unreachable source is `UNAVAILABLE`, a policy refusal is `BLOCKED`, and a partial
capture is never rounded up. `capture` has no date override: scheduling, backup
and the reasons there is no GitHub Actions capture job are in
`docs/PROSPECTIVE_CAPTURE_1_9.md`.

This milestone adds the capability and its tests, not captured evidence: no
prospective store is committed. It does not mature labels, admit a design or
approve the protocol — `protocol/evaluation_protocol.json` remains
`NOT_APPROVED`.

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
  refresh/        maturity gate, evidence refresh, feasibility comparison (1.8)
  prospective/    append-only prospective evidence capture and verification (1.9)
  static/         index.html, style.css, app.js
protocol/
  EVALUATION_PROTOCOL_1.6.md      draft protocol (NOT_APPROVED)
  evaluation_protocol.json        machine-readable protocol and approval state
docs/
  ARCHITECTURE.md
  BROWSER_TESTING.md
  CI.md
  DATA_ACQUISITION_1_7.md
  EVALUATION_READINESS_1_6.md
  MATURITY_REFRESH_1_8.md
  PROSPECTIVE_CAPTURE_1_9.md
  RANKING_SEMANTICS.md
tests/            test suite (744 tests, including synthetic readiness, acquisition, refresh and prospective fixtures)
tools/            verifiers, digest, manifest, pre-2020 fetch
reports/
  validation1_1/  previous phase (historical, unchanged)
  improvement1_2/ earlier product report, diffs and evidence
  improvement1_5/ CI hardening report
  evaluation_readiness_1_6/ committed readiness report (JSON + Markdown)
  acquisition_1_7/ committed acquisition manifest and missing-evidence report
  refresh_1_8/    committed maturity gate, refresh report and comparison
data/snapshots/   KEV, EPSS, cvelistV5 manifest
data/acquisition_store/ historical artifacts acquired in 1.7, with hashes
data/refresh_store_1_8/  refreshed artifacts from 1.8, kept separate from 1.7
build/vulnova.db  derived store (not snapshotted)
```

## Scope and limits

* Coverage: cvelistV5 2020–2026 ingested (identifiers without a publication date are not
  admitted); 1999–2019 only via the legacy extract (~62% of pre-2020 identifiers) plus
  KEV members.
* No historical evaluation data is produced or modified here.
* Not a validated predictive model. Not a probability of exploitation.
