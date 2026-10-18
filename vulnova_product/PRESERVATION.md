# PRESERVATION RECORD — VULNOVA prototype 1.2

This file travels with the code. It states, without embellishment, what this
snapshot is, where it came from, and what is missing.

## What this is

The working VULNOVA prototype as it stood on **2026-10-17 05:25 UTC**, after the
approved Improvement 1.2 change (rename of the recency component to
`publication_recency`, plus its explanatory text).

* Source: `vulnova/` — 12 modules, standard library only.
* Tests: `tests/` — 8 files, 109 assertions-worth of cases, all passing.
* Static interface: `vulnova/static/{index.html,style.css,app.js}`.
* Tools: `tools/` — verifiers, digest, manifests, pre-2020 fetch, distribution builder.
* Documentation: `README.md`, `RUNBOOK.md`, `REBUILD.md`, `docs/`.
* Data-source definitions and provenance: `data/snapshots/` and
  `reports/improvement1_2/MANIFEST.json`.
* Verification evidence: `reports/improvement1_2/01…05`.

## Provenance — read this before citing anything as original

The sandbox that hosts this work is re-initialised between sessions and does not
preserve large parts of the workspace. It was reset **twice** during this project:

1. At the start of the Validation 1.1 session, the entire earlier product
   workspace was lost.
2. At the start of the Improvement 1.2 session, the entire Validation 1.1
   workspace was lost again.

Consequences that are recorded here rather than papered over:

| Item | Status |
| --- | --- |
| `vulnova/` application source as it exists now | **Current, working, test-verified.** It was re-derived from the documented architecture after loss #1, then modified by the approved 1.2 rename. It is not a byte-for-byte copy of any earlier build, and it is not described as one. |
| Validation 1.1 reports (`PROTOTYPE_VALIDATION_1_1_REPORT.md`, `COVERAGE_2020_2023_REPORT.md`, `RANKING_SEMANTICS_PROPOSAL.md`) | **UNAVAILABLE.** Written, then lost with the workspace. Not recreated. |
| Validation 1.1 test run (91 passed / 60 product / 27 render) | **RECONSTRUCTED** as a figure — it was reported at the time, but the artefacts no longer exist in this workspace. |
| `docs/` and `README.md` before Improvement 1.2 | **UNAVAILABLE.** No before-image exists, so no diff of the documentation is possible. |
| Baseline copy of the pre-rename code (`/tmp/baseline_1_1`) | **UNAVAILABLE** in the repository. It lived on `/tmp` and was used to produce `reports/improvement1_2/SOURCE_DIFF.txt`. |
| `cve.csv.zip` | **Original**, in the repository root, 7,326,681 bytes. |
| KEV and EPSS snapshots | **Original downloads**, sha256 recorded in `data/snapshots/SOURCES.md`. |
| cvelistV5 tree | **Not stored**, reproducible from commit `c2a4235e…` and the tree digests in `data/snapshots/cvelistv5/MANIFEST.json`. |
| Derived database `build/vulnova.db` | **Deliberately not stored** (425 MB, excluded by `.gitignore`). Rebuild it with `RUNBOOK.md` §5. |

Nothing in this snapshot is labelled "recovered". Nothing was reconstructed from a
filename, a hash or a summary.

## What this snapshot does NOT contain

* Any virtual environment, cache, or derived database.
* The 2.6 GB cvelistV5 working tree (manifest only).
* Any historical research phase output (`phase2.3k-export/` lives on the
  `arena/ee812e17-ai` branch of the repository, outside this directory).
* Any credential, token or private endpoint.

## Invariants that must not change without a separately documented amendment

| Invariant | Value |
| --- | --- |
| Weights | KEV 40 · EPSS 30 · CVSS 20 · `publication_recency` 10 |
| Denominator | 100, never rescaled |
| Bands | P1 ≥ 70 · P2 ≥ 40 · P3 ≥ 20 · P4 ≥ 1 · P5 = 0 |
| Recency window | full credit ≤ 90 days, zero at ≥ 1,825 days |
| Reference date | 2026-10-16 (EPSS score date) |
| Ranking rows at this snapshot | 345,249 |
| `numeric_digest` | `7c6d3832ec174a1932a955978b0b28049eefb977c7220f942396d9019296ffbf` |

`tests/test_terminology.py` pins the scoring behaviour with a golden table.

## Reproduction

* **From a clean checkout:** `RUNBOOK.md`.
* **After a sandbox reset:** `REBUILD.md`.
* **Verification:** `./verify_all.sh`.
