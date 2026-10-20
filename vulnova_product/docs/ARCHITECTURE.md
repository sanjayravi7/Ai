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

## Evaluation-readiness subsystem (1.6)

The readiness command is a separate, read-only pipeline. It never writes to the
store, the source snapshots or the ranking:

```
phase2.3k-export/*.tar.gz ─► integrity.py (sidecars, manifests, safe extraction)
                              │
                              ▼
                        datasets.py (Phase 2.3K readers + 21-partition scan)
                              │
       protocol/evaluation_protocol.json ─► protocol.py
                              │
                              ▼
        temporal.py + evidence.py (maturity, designs, three-state KEV rule)
                              │
                              ▼
                    checks_*.py (44 checks, PASS/FAIL/BLOCKED/N/A)
                              │
                              ▼
             report.py (canonical digest) ─► JSON + Markdown
```

`checks.py` fixes the report order and rejects duplicate check IDs. Each check
receives an immutable-by-convention `CheckContext` and returns a status with
explicit reasons. Unavailable evidence produces `BLOCKED`, never a pass and never
a fabricated failure. The only human decision in the pipeline — protocol approval
and design adoption — is read from `protocol/evaluation_protocol.json`; the tool
cannot write it. See `docs/EVALUATION_READINESS_1_6.md`.

## Historical-acquisition subsystem (1.7)

Acquisition is a separate, write-only-to-its-own-store pipeline. It reads the
Phase 2.3K pins for cross-checking and never writes to `data/snapshots/`, the
database or the protocol:

```
Phase 2.3K revisions ─────► workflow.ReferencePins (cross-check only)
                                  │
cvelistV5 ──┐                     ▼
KEV ────────┼──► transport.py ─► sources/*.py ─► records.py (two axes)
EPSS ───────┘     (host policy,      │              │
                   retrieval clock)  │              ▼
                                     ▼        manifest.py (canonical digest)
                             store.py (exact bytes)   │
                                     │                ▼
                                     └──────► verify.py (offline) ─► report.py
```

`transport.py` is the only module that can reach the network, and it stamps the
retrieval time *after* the body is read. It is also the only place the host
allowlist is enforced, and it enforces it on **every redirect hop**: urllib's
default redirect handler follows a `Location` header anywhere, so the transport
installs a `SafeRedirectHandler` that rejects any destination outside the
`HostPolicy`, refuses HTTPS-to-HTTP downgrades, and reports the URL that actually
served the bytes as `HttpResponse.final_url` — kept separate from the requested
URL, because a redirect is exactly where an allowlist can otherwise be bypassed. `records.py` derives
`CONTEMPORANEOUS` / `LATE_RETRIEVAL` / `NOT_RETRIEVED` from those timestamps, so
no caller can declare historical access that the data does not support.
`verify.py` re-derives the same classification from the manifest alone and
rejects disagreement, which is what makes the archive auditable by a third party
with no network access.

## Maturity-refresh subsystem (1.8)

`vulnova/refresh/` sits on top of acquisition and reuses it verbatim: the same
`ArtifactStore`, the same KEV parser, the same transport, the same
`VERIFIED`/`UNAVAILABLE`/`BLOCKED` vocabulary and the same `Requirement` type.
It adds no source adapter and no second definition of a status.

* `gate.py` answers the maturity question in two steps — has the calendar date
  arrived, and was the catalog published on or after it — and returns
  `NOT_MATURED`, `MATURED_SOURCE_MISSING`, `MATURED_SOURCE_PREDATES` or
  `MATURED_AND_OBSERVED`. Only the last sets `filter_applied`, which is what
  permits `filter_entries_by_date_added` to produce a derived view. Every other
  outcome is reported `RIGHT_CENSORED_NOT_FILTERED` and the requirement is
  `BLOCKED`.
* `workflow.py` runs the acquisition, gates each block, writes the report, and
  enforces two structural guarantees: the refresh store may not overlap the
  sealed 1.7 paths (checked before any write, either direction), and the sealed
  1.7 manifest plus its seven artifacts are fingerprinted before and after the
  run. A maturity claim is re-checked against the run's own as-of date after the
  status is computed; a run that would claim maturity early raises.
* `comparison.py` compares a fresh readiness report against the committed 1.6
  one by **check status and design verdict**, not by report digest. A readiness
  report embeds its `as_of` date, so digests legitimately differ when nothing
  changed; the report says so rather than letting a reader conflate the two.
* `paths.py` is the single write-safety gate. Every destination — store, JSON
  report, Markdown summary — is resolved (following symlinks and `..`) and
  checked against the sealed directories and the configured read-only inputs
  before the first network request. Overlap in either direction is refused.
  `default_protected_paths()` derives the five sealed locations from the
  package layout, and `protected_inputs()` merges them with the options and any
  caller paths, so `run_refresh` enforces the rule even when invoked without
  the CLI and with ``protected_paths=()``.

`run_refresh` takes its clock as a parameter. The CLI never exposes a date for
`run`: production acquisition always uses the real UTC clock, and every
`retrieved_at` is the transport's actual receipt time.

## Prospective-capture subsystem (1.9)

`vulnova/prospective/` captures the same three first-party sources while the
period is live. It reuses the 1.7 adapters, transport, host policy, status
vocabulary and `Requirement` type, and it reuses the 1.8 write-safety gate
instead of reimplementing it.

* `capture.py` runs the KEV direct feed and CISA's GitHub repository (both
  attempts are kept), the exact EPSS daily file for the run's UTC observation
  date via `acquire_daily(..., historical=False)`, and `capture_current`, which
  records cvelistV5's default-branch commit SHA from one API response without a
  clone. It rejects any record carrying a historical cutoff and re-hashes every
  `VERIFIED` artifact before writing the run.
* `store.py` is content-addressed and create-once: `<sha256>` names the bytes, a
  temporary file is fsynced and `os.link`ed into place, identical bytes are a
  no-op and different bytes raise `StoreConflict` rather than overwrite. There
  is no weaker writer: a filesystem that cannot link gets
  `StoreCapabilityError` (`ATOMIC_CREATE_UNAVAILABLE`) and stores nothing, so a
  crash can never leave a partial artifact at the evidence path. Paths are
  checked syntactically and against the resolved store root; symlinks are
  refused, and the inventory exposes every entry the write path could not have
  produced.
* `verify.py` is offline. It recomputes every run digest, re-derives every run
  id, re-hashes every artifact, re-derives every summary status, rejects a
  cutoff in a prospective record, and re-hashes the sealed 1.7 archive. It also
  inventories `artifacts/` directly — content-addressing every file, refusing
  symlinks and escapes, distinguishing tampering from an incomplete capture
  (`UNREFERENCED_ARTIFACT`) and from an abandoned temporary write. An empty
  store is `BLOCKED` (`CAPTURES_PRESENT`), and two captures of one date that
  disagree are a reported conflict, not a failure.
* `report.py` is derived only from stored runs — no clock, no absolute paths — so
  the same store yields a byte-identical report and digest on any machine. Per
  source it reports the run's own requirement status, not the worst failed
  attempt beside a successful fallback. A run whose record does not validate is
  counted as `BLOCKED` and excluded from the source grid; it is named in
  `malformed_runs` with the exact problems, and an invented or wrong-typed
  status is never used as a dictionary key or counted as a status.
* `paths.py` extends the 1.8 fixed protected set with `data/refresh_store_1_8`,
  `reports/refresh_1_8` and `protocol/`. `capture_protected_paths()` treats
  caller paths as additive, so `protected_paths=()` still protects the seals.

The CLI exposes `capture`, `verify` and `report`. `capture` has no date override;
tests inject a clock only through `CaptureOptions`.

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
5. `tools/ui_render_check.js` is a DOM shim, not a real browser. The separate
   `tools/ui_browser_check.py` Chromium smoke test covers loading/error/retry and
   stale-response behaviour; it does not replace cross-browser or screen-reader tests.
