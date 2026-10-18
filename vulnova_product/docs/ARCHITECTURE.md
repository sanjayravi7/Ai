# Architecture

```
             ┌──────────────┐   ┌───────────────┐   ┌────────────┐   ┌────────────┐
 sources ──► │  cvelistV5   │   │ legacy_cve_csv│   │    kev     │   │    epss    │
             └──────┬───────┘   └───────┬───────┘   └─────┬──────┘   └─────┬──────┘
                    │                   │                 │                │
                    └───────────┬───────┴─────────────────┴────────────────┘
                                ▼
                        vulnova/ingest.py
                     (reconciliation receipts)
                                ▼
                        build/vulnova.db
             cve_record · cvss_observation · kev · epss
                                │
                                ▼
                      rank.py (arithmetic)
                                │
                    ┌───────────┴────────────┐
                    ▼                        ▼
          assessment.py (wording)      explain.py (payload)
                    └───────────┬────────────┘
                                ▼
                          web.py  +  static/
```

## Design decisions

**One row per `(cve_id, source)`.** cvelistV5 and the legacy extract never overwrite
each other, so a conflict is representable rather than resolved at ingest.

**Every CVSS candidate is kept.** `cvss_observation` holds each CNA and ADP metric with
its own version, scoring organisation and retrieval timestamp. Selection happens at
read time in `explain.select_cvss`, and the rule is returned with the answer.

**Missingness is a row, not an absence.** A record that states no CVSS produces an
observation with `status='MISSING_FROM_SOURCE'`. KEV and EPSS only hold what they
contain; their absence is computed as `NOT_LISTED_IN_CATALOG` / `MISSING_FROM_SOURCE`.

**Arithmetic and interpretation are separate modules.** `rank.py` cannot produce a
sentence; `assessment.py` cannot change a number.

**Provenance travels with the data.** Every `cve_record` row stores its source revision
and retrieval timestamp; every CVSS observation stores the same. `/api/status` and every
detail payload expose them.

**The ranking is materialised.** `ranking` is rebuilt when the store fingerprint
changes; list queries are indexed scans, and the payload for one CVE is four primary-key
lookups.

## Tables

| Table | Purpose |
| --- | --- |
| `ingest_run` | per-stage counters: in / new / existing / duplicate / rejected / skipped |
| `cve_record` | one row per (CVE, source); state, state_basis, publication date, description, revision, retrieved_at |
| `cvss_observation` | one row per metric; value, version, organisation, status, retrieved_at |
| `kev` | catalog membership + `date_added` |
| `epss` | probability, percentile, model version, score date |
| `ranking` | materialised score, band, adequacy status, conflict flags |
| `ranking_meta` | fingerprint, build time, reference date |

### State and `state_basis`

`state` is the value the source itself supplied, copied verbatim (for cvelistV5,
`cveMetadata.state`). `state_basis` records only where that value came from:

| `state_basis` | Meaning |
| --- | --- |
| `stated` | the source supplied a non-empty state (`PUBLISHED`, `REJECTED`, or any other value) |
| `not_stated` | the source supplied no state field or an empty/null value |

`state_basis` is never inferred from `reject_marker`, and `reject_marker` is never
inferred from the basis. The legacy extract has no state column, so its rows are
always `not_stated`. When a CVE has rows from more than one source, each row keeps
its own state and basis; `/api/cve/<id>` exposes the primary record under
`record` and the others under `record.alternate_source_records`, with their own
retrieval timestamps. No disagreement is resolved by merging the values.

## Naming

| Layer | Name for the fourth component |
| --- | --- |
| Presentation (API, UI, docs) | `publication_recency` |
| Detail payload block | `publication_recency_context` |
| Status payload block | `publication_recency_definition` |
| List API field | `publication_recency_points` |
| Database column | `recency_points` (internal storage name, unchanged) |

The storage column keeps the short name deliberately: renaming it would require a
schema migration for no user-visible benefit. `store.py` documents the mapping.

## Scoring

See `docs/RANKING_SEMANTICS.md`. Fixed denominator 100; weights 40/30/20/10; missing
inputs score zero and are named; bands P1 ≥ 70, P2 ≥ 40, P3 ≥ 20, P4 ≥ 1, P5 = 0.

## Known divergences / limitations

1. Pre-2020 cvelistV5 is present only for KEV members (bounded fetch).
2. `legacy_cve_csv` has no stated revision; recorded as `null`.
3. Text search is a `LIKE` scan; there is no FTS index.
4. `/api/status` pre-computes coverage at startup because the store is read-only while
   serving.
5. No browser-based UI test exists; see the render-check disclaimer.
