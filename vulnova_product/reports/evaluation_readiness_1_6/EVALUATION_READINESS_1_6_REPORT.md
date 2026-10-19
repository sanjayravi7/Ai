# VULNOVA 1.6 — Evaluation Readiness and Temporal Data Validation

**Release:** 1.6.0 · **Reference date:** 2026-10-15 · **Prepared:** 2026-10-19
**Readiness status:** `BLOCKED_PROTOCOL_NOT_APPROVED`
**Report digest:** `1d51544af41a8421522e566ffb051e2835b27d7cccc0bbd1cc42a25497322010`

This phase adds a reproducible admission check for a future temporal evaluation.
It does not train, tune, score or evaluate a model. It does not claim predictive
performance, change a ranking weight or modify a source datum. It does not
approve the protocol or adopt a design.

## 1. Delivered

| Area | Artifact |
|---|---|
| Readiness engine | `vulnova/evaluation/` (`constants`, `temporal`, `evidence`, `protocol`, `integrity`, `datasets`, `checks_*`, `readiness`, `report`, `cli`) |
| Protocol, machine-readable | `protocol/evaluation_protocol.json` — `NOT_APPROVED`, `adopted_design: null` |
| Protocol, human-readable | `protocol/EVALUATION_PROTOCOL_1.6.md` — draft, explicitly does not adopt a design |
| Command | `python -m vulnova.evaluation readiness` / `vulnova-readiness` |
| Machine report | `reports/evaluation_readiness_1_6/readiness_report.json` (44 checks, 260 KB) |
| Human report | `reports/evaluation_readiness_1_6/readiness_report.md` |
| Documentation | `docs/EVALUATION_READINESS.md` (statuses, check catalog, schema, limitations) |
| Tests | 6 new test modules plus a synthetic Phase 2.3K-shaped fixture builder |

The engine reads the committed `phase2.3k-export/` archives, verifies both
SHA-256 sidecars, extracts to `build/evaluation_artifacts/` (not committed), and
fingerprints every consumed input. The 21 monthly membership partitions are
scanned in full (6,852,808 rows).

## 2. Result

```text
checks: PASS 42 · FAIL 0 · BLOCKED 1 · NOT_APPLICABLE 1 (total 44)
READINESS: BLOCKED_PROTOCOL_NOT_APPROVED
primary blocker: PROTOCOL_NOT_APPROVED
```

Blockers, in report order:

| Code | Primary | Meaning |
|---|---:|---|
| `PROTOCOL_NOT_APPROVED` | yes | The protocol is a draft. Only the project owner can approve it. |
| `NO_ADOPTED_DESIGN` | no | No candidate is adopted. |
| `LABEL_MATURITY_NOT_REACHED` | no | The earliest three-block design matures 2026-10-28, 13 days after the reference date. |
| `LABEL_STABILITY_NOT_OBSERVABLE_IN_PROVIDED_SOURCE` | no | The served KEV timeline ends 2026-10-15, before that maturity date. |
| `NON_BLOCKING_EVIDENCE_GAP` | no | `PRV-06`: per-revision cvelistV5 fetch times are not recorded. |

The single BLOCKED check is `PRV-06_retrieval_timestamp_provenance`. It is
non-blocking because the revision pin itself is valid: committer times, tree
hashes and the artifact sealing time exist. What is missing is the fetch time of
each pinned revision. The single NOT_APPLICABLE check is `REP-02` because no
previous report was supplied.

## 3. Candidate designs

No design is admitted. The verdicts below are technical findings, not approvals.

| Design | Blocks | Cutoffs | Distinct events | Verdict | Reason codes | Admissible |
|---|---:|---|---|---|---|---:|
| `A_180D_SPACED_3SEG` | 3 | 2025-02-01 / 2025-08-01 / 2026-02-01 | 55 / 46 / 60 | `INFEASIBLE` | labels not matured before next block | no |
| `A2_EARLIEST_3BLOCK` | 3 | 2025-02-01 / 2025-09-01 / 2026-04-01 | 55 / 52 / 47 (floor) | `INFEASIBLE` | block labels not matured; source does not cover maturity | no |
| `B_CONTIGUOUS_THIRDS` | 3 | contiguous thirds | 92 / 85 / 123 | `INFEASIBLE` | shared events (42/15/44) and immature labels | no |
| `E_LABEL_MATURED_2BLOCK` | 2 | 2025-02-01 / 2025-09-01 | 55 / 52 | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | insufficient blocks | no |
| `C_SINGLE_FINAL_CUTOFF` | 1 | 2026-03-01 | 60 | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | insufficient blocks | no |
| `D_ROLLING_ORIGIN` | 14 | 2025-02-01 … 2026-03-01 | 37–61 | `INFEASIBLE` | rolling origin is not sequential | no |

The two-block and single-cutoff designs are constructible but do not satisfy the
three-block protocol. They are reported, never substituted. The 180-day-spaced
design misses the next decision point by 29 and 26 days; 210 days is the minimum.

## 4. What the checks found

| Area | Finding |
|---|---|
| Archives | Both sidecars PASS: export `26a2a144…3bb7d`, core `850e68a5…420db`. All 45 export files and 75 members match their manifests. |
| Membership | 21/21 partitions match `INDEX.csv`; 6,852,808 rows reconcile exactly; 18,150,017 partition bytes. |
| Denominators | 21/21 exclusion identities hold; risk sets grow 274,815 → 392,114; risk-pair sum 6,723,857. |
| cvelistV5 provenance | 21/21 cutoffs pinned; every committer timestamp precedes its cutoff; clone head `ffd2179…`; coverage from 2025-01-20. |
| KEV provenance | 325 readable revisions, 498 additions, 4 removals, 1,749 distinct CVEs ever listed, 1 unparseable revision (`a7fa9428cc13`, 2025-02-25), max pin staleness 10 days. |
| EPSS provenance | 13 cutoffs are backfills and are not treated as historical; 8 have demonstrable availability; 1 matured cutoff (2026-03-01) has usable historical EPSS. |
| Maturity | 21/21 dates recompute from `T + 180 + 30`; 14 matured at the reference date, 7 censored. |
| Event gate | 14/14 matured cutoffs clear 30 distinct events; minimum is 37; censored counts are floors. |
| Event rows | 952 rows across all cutoffs, 739 matured rows, 214 distinct matured events (3.45 rows/event); 0 duplicate `(cutoff, CVE)` pairs. |
| Windows | 952/952 event rows fall in `(T, T+180]`; none precedes its cutoff. |
| Membership at T | Every event is present in its cutoff partition with `ELIGIBLE_AT_RISK`; none was already in KEV at T. |
| Leakage | No publication-date, CVSS or KEV value from after `T` enters a historical row. |
| Evidence states | 263 confirmed inclusion events; 6,723,857 catalog-absence observations; 0 negative exploitation labels. KEV absence is not non-exploitation. |
| Prohibitions | No training, tuning, scoring, performance claim, gate relaxation, weight change or source-data change. |

## 5. Tests and actual results

Environment: Python 3.11.2, pytest 9.1.1. The root suite additionally needs
pandas; it was run in a separate temporary venv with pandas 3.0.6.

| Suite | Command | Result | Log |
|---|---|---|---|
| VULNOVA product | `cd vulnova_product && python -m pytest -q` | **204 passed in 21.41 s** | `01_vulnova_pytest.txt` |
| Repository root | `python -m pytest tests -q` | **192 passed, 6 subtests passed in 6.95 s** | `02_root_pytest.txt` |
| Readiness, double run | `python -m vulnova.evaluation readiness --check-reproducible` | **PASS 42 · FAIL 0 · BLOCKED 1 · N/A 1**, `double_run_match: yes`, digest `1d51544a…` | `03_readiness_reproducibility.txt` |
| Lint (new files) | `flake8 … --select=E9,F63,F7,F82` and 127-column warnings | **0 errors, 0 warnings** | `04_flake8.txt` |

The product baseline was 122 tests; this phase adds 82 tests (66 readiness tests plus 16 protocol-validation regressions and integration assertions). The root
suite is unchanged at 192 tests plus 6 subtests. The Chromium smoke test was not
run because no UI file changed; its workflow is unchanged.

New tests cover:

* maturity at `T+209`, `T+210` and `T+211`, inclusive horizon end and the 30/29
  event-gate boundary;
* 180-day versus 210-day block spacing and the 29/26-day shortfalls;
* calendar maturity without source coverage;
* confirmed inclusion, catalog absence and missing/unreadable revisions;
* archive sidecar mismatch, missing/mismatched manifest files, path traversal and
  fresh-cache reproducibility;
* corrupted and missing membership partitions returning BLOCKED rather than a
  fabricated absence failure;
* duplicate event rows and event-level future-information leakage;
* adoption without approval, approval without evidence and event-gate relaxation;
* protocol validation of the adopted design itself: an unknown design kind, a
  design with no blocks, an unregistered adopted design, and `approved_on`
  values that are not exact `YYYY-MM-DD` calendar dates;
* digest canonicalization, CLI exit codes and reproduction of the committed
  report from the committed archives.

### Protocol-validation follow-up

Review found three gaps in `vulnova/evaluation/protocol.py`; all three are fixed
and covered by regression tests:

1. the design loop skipped the design named by `adopted_design`, so a selected
   design escaped kind and structural validation;
2. an approved protocol could name an `adopted_design` that was not a registered
   candidate;
3. `approved_on` was checked for presence but not for being a real date in
   `YYYY-MM-DD` form (`date.fromisoformat` alone also accepts `20261015` and
   `2026-W42-1`).

The 180-day horizon, 30-day maturation lag, 210-day spacing and 30-distinct-event
gate are unchanged. The readiness report is unchanged: the committed digest
`1d51544a…` recomputes identically, because the validator's problem list for the
current protocol is still empty.

## 6. Reproducing

```bash
cd vulnova_product
python -m vulnova.evaluation readiness --check-reproducible \
  --markdown reports/evaluation_readiness_1_6/readiness_report.md
```

The command is path-stable: repository paths are relative in the report and
runtime extraction bookkeeping is excluded from the digest. A cold extraction and
a warm cache produce the same digest. `pytest -q` includes
`tests/test_evaluation_repository_report.py`, which fails if the committed report
digest no longer matches a fresh run.

## 7. Limitations

* **Protocol not approved.** No evaluation may execute. That is a human decision,
  not a technical one.
* **Final block not mature at the reference date.** 2026-10-28 is after
  2026-10-15. At the time of writing (2026-10-19), it is 9 days away.
* **Source coverage ends 2026-10-15.** Waiting for 2026-10-28 without a fresh KEV
  retrieval does not make the final labels observable. A fresh retrieval that
  reaches 2026-10-28 is required, and it must be recorded as new evidence.
* **Per-revision retrieval timestamps are not recorded.** Revision committer
  times and the sealing time exist; fetch times do not. `PRV-06` stays BLOCKED
  until the pipeline records them.
* **Phase 2.3F and 2.3G remain unavailable.** Their digests are historical claims,
  not verified access.
* **Census payloads are not shipped.** Recorded sizes and hashes are verified;
  the per-record bytes cannot be re-hashed from this repository.
* **EPSS is usable at only one matured cutoff.** Backfilled files are not
  historical evidence.
* **Event reuse is material.** 739 matured rows cover 214 distinct events. Reused
  events are not independent evidence.
* **Only one or two blocks meet every rule.** Even after maturity, a three-block
  design needs disjoint events and complete label windows.
* **No model was trained or evaluated.** No predictive performance is claimed.

## 8. Constraints observed

* No model training, tuning or predictive evaluation.
* No predictive-performance or probability-of-exploitation claim.
* No ranking-weight or source-data change.
* No protocol approval, amendment or silent design adoption.
* No event-gate, horizon or maturation-lag relaxation.
* No claim that omitted or unavailable research artifacts are available.
* Phase 2.3K evidence classifications are preserved, including the four KEV
  removals and the unparseable revision.

The confirmatory NO-GO is retained.
