# Historical data acquisition and provenance (1.7)

VULNOVA 1.7 answers one question: **can the evidence behind a historical
evaluation be produced again, and does the archive say honestly what it has and
what it lacks?**

It resolves the exact source revision behind each frozen cutoff, stores the
bytes, records when those bytes were *actually* retrieved, and can re-verify the
whole archive offline. It trains no model, computes no score, changes no weight,
and leaves the evaluation protocol `NOT_APPROVED`.

- Manifest: `reports/acquisition_1_7/acquisition_manifest.json`
- Report: `reports/acquisition_1_7/DATA_ACQUISITION_1_7_REPORT.md`
- Artifact store: `data/acquisition_store/`
- Code: `vulnova/acquisition/`

## The two axes

Every artifact carries two independent verdicts. Collapsing them is how a phase
like this lies by accident.

| Axis | Values | Question |
| --- | --- | --- |
| `content_status` | `VERIFIED` / `UNAVAILABLE` / `BLOCKED` | Are these bytes what they claim to be? |
| `access_provenance` | `CONTEMPORANEOUS` / `LATE_RETRIEVAL` / `NOT_RETRIEVED` | Did we observe this at the time it describes? |

An old revision downloaded today is `VERIFIED` content with `LATE_RETRIEVAL`
access. It satisfies a revision-pin requirement. It does **not** satisfy a
historical-retrieval-provenance requirement, and the code cannot mark it as if it
did: `historical_retrieval_verified` requires `content_status == VERIFIED`,
`access_provenance == CONTEMPORANEOUS`, a cutoff, a digest and a retrieval
timestamp.

A failed request still records *when* it was attempted, but nothing was
retrieved, so its access provenance is `NOT_RETRIEVED`, never `LATE_RETRIEVAL`.

## Sources and channels

| Source | Publisher | Channel used | Why |
| --- | --- | --- | --- |
| cvelistV5 | CVE Program | `api.github.com` (`CVEProject/cvelistV5`) | The CVE Program's own repository. |
| KEV | CISA | `www.cisa.gov` feed, then `cisagov/kev-data` | Direct feed is canonical; `cisagov/kev-data` is the same agency's repository, not a third-party mirror. |
| EPSS | FIRST / Cyentia | `epss.cyentia.com` only | The published daily feed. |

Third-party mirrors are **recorded but never used**. `github.com/empiricalsec/epss_scores`
mirrors per-day EPSS files and is reachable; it is stored as a
`THIRD_PARTY_MIRROR` record with reason `THIRD_PARTY_MIRROR_ONLY` and can never
satisfy a requirement. A mirror record is also excluded from requirement
aggregation, so an available mirror cannot drag down a requirement the official
channel already satisfies.

## Network policy

Every byte passes through one `Transport`, and that transport is the only place
the host allowlist is enforced.

- **HTTPS only.** A plaintext URL is refused before any socket is opened
  (`INSECURE_TRANSPORT`).
- **Redirects are re-checked, not trusted.** urllib's default handler follows a
  `Location` header to any host, so the transport installs a `SafeRedirectHandler`
  that re-validates every hop against the same `HostPolicy`. A redirect to an
  unapproved host is refused before it is issued (`DISALLOWED_REDIRECT_HOST`),
  and an HTTPS-to-HTTP downgrade is refused even when the host is approved
  (`HTTPS_DOWNGRADE_BLOCKED`). Relative `Location` headers are resolved against
  the URL they came from, so `//evil.example.com/x` is caught too.
- **Defence in depth.** After the body is read, the final URL is checked again;
  a response can never be handed back from a host or scheme the policy rejects.
- **Refusals are not outages.** These reasons map to `REDIRECT_BLOCKED` and a
  `BLOCKED` status, never to `HTTP_ERROR`/`OFFICIAL_SOURCE_UNREACHABLE`. The
  publisher never answered, so it would be wrong to report that it failed.
- **The final URL is recorded separately.** `HttpResponse.final_url` carries the
  URL that actually served the bytes; `HttpResponse.url` stays the URL that was
  requested. In a record, `final_url` is serialised **only when a redirect moved
  the request**, so an unchanged URL is not duplicated.
- **`request_url` names the request for the artifact itself.** For a KEV catalog
  that is the blob endpoint that served the JSON
  (`…/git/blobs/<sha>`), not the commit listing that merely located it; the
  listing is recorded separately in `details.commit_url` /
  `details.commit_query_url`. Recording the lookup instead of the fetch would
  describe a request that never produced the stored bytes.

The committed manifest contains no `final_url` field: every request resolved on
its original URL, so separating the two adds nothing. That is a fact about this
run, not a default.

## What this run acquired

Acquisition time is recorded in the manifest (`generated_at`, and a
per-artifact `retrieved_at`). The pinned grid is the Phase 2.3K one: 21 monthly
cutoffs from 2025-02-01 to 2026-10-01; the three candidate blocks are
**2025-02-01 / 2025-09-01 / 2026-04-01**.

| Artifact | Revision | Bytes | SHA-256 |
| --- | --- | --- | --- |
| cvelistV5 commit at 2025-02-01 | `b3b7d34318e4f6d1de4e082d03ea21984ff2f176` | 1,509 | `bc59fc810c0f…` |
| cvelistV5 commit at 2025-09-01 | `2549c0e76d2857fa6ed14b146fa377d5164914d7` | 1,508 | `eec42dd7c31a…` |
| cvelistV5 commit at 2026-04-01 | `bc781f6b07948ceacd7c5e1c1ede9119b2ac0778` | 1,523 | `a7dc381c70a6…` |
| KEV catalog at 2025-02-01 | commit `49c9495366c4…` · catalog `2025.01.29` | 1,089,781 | `e040ac917f18…` |
| KEV catalog at 2025-09-01 | commit `9d28701f99f7…` · catalog `2025.08.29` | 1,259,609 | `d4e88aa93681…` |
| KEV catalog at 2026-04-01 | commit `6fe63a2e8d9b…` · catalog `2026.03.30` | 1,431,397 | `a925400c147a…` |
| KEV catalog, current | commit `6a392940c663…` · catalog `2026.10.16` | 1,792,713 | `b6e27975f663…` |

Two independent cross-checks passed:

1. **Revision pins.** All three live cvelistV5 resolutions equal the pins in
   `cvelistv5_inventory_manifest.csv`, and all three KEV resolutions equal the
   `commit_sha` values selected from `raw/kev_revisions.csv` by the same rule
   (latest commit at or before `T 00:00:00Z`).
2. **Content hashes.** Each downloaded KEV catalog hashes to the
   `content_sha256` recorded by Phase 2.3K for that revision, so the live
   repository reproduces the research bytes exactly.

The current KEV catalog also reproduces `data/snapshots/kev/known_exploited_vulnerabilities.json`
byte-for-byte (`b6e27975f663…`, catalog `2026.10.16`, 1748 entries) — the
committed 1.6 snapshot is authentic.

## What is missing, and why

Reported as `BLOCKED`/`UNAVAILABLE`, never silently filled:

| Requirement | Status | Reason |
| --- | --- | --- |
| `CVE-01_REVISION_PIN_RESOLVED` | VERIFIED | 3 pins resolved and hashed |
| `CVE-02_PIN_CROSSCHECK` | VERIFIED | live pins match Phase 2.3K |
| `CVE-03_HISTORICAL_RETRIEVAL_PROVENANCE` | **BLOCKED** | everything was retrieved in 2026 for cutoffs in 2025–2026 |
| `KEV-01_DIRECT_CISA_FEED` | **UNAVAILABLE** | `www.cisa.gov` is unreachable from the acquisition environment |
| `KEV-02_CURRENT_CATALOG` | VERIFIED | CISA's own `cisagov/kev-data` repository |
| `KEV-03_HISTORICAL_REVISION_AT_CUTOFF` | VERIFIED | 3 revisions preserved and hash-matched |
| `KEV-04_LABEL_MATURITY_COVERAGE` | **BLOCKED** | the latest catalog (2026-10-16) predates the 2026-10-28 maturity |
| `KEV-05_HISTORICAL_RETRIEVAL_PROVENANCE` | **BLOCKED** | late retrieval |
| `EPSS-01_EXACT_DAILY_FILE` | **UNAVAILABLE** | `epss.cyentia.com` is unreachable; no substitute accepted |
| `EPSS-02_HISTORICAL_RETRIEVAL_PROVENANCE` | **UNAVAILABLE** | nothing was retrieved |
| `PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED` | VERIFIED | 2026-10-28 is not claimed |

Overall evidence status: **BLOCKED**. That is the correct answer: two of the
three required sources cannot be acquired from this environment, and no
acquisition performed today can be contemporaneous with a 2025 cutoff.

`KEV-01` stays `UNAVAILABLE` even though `KEV-02` verifies. The direct feed is a
distinct source record; falling back to a first-party repository is recorded, not
hidden.

### EPSS is not substituted

`epss.cyentia.com` did not answer. A newer daily file, a different model version,
or a reachable third-party mirror would all have produced a plausible-looking
number, and all three are refused:

- a file whose header `score_date` differs from the cutoff yields
  `SCORE_DATE_MISMATCH` and is not stored as satisfying the cutoff;
- a mirror yields `THIRD_PARTY_MIRROR_ONLY`;
- a missing file yields `EPSS_FILE_MISSING` (404) or
  `OFFICIAL_SOURCE_UNREACHABLE`.

### Maturity is not claimed early

Filtering a catalog to `dateAdded <= maturity_date` is only valid when the
catalog was released at or after that maturity date. Otherwise the observation is
right-censored and `filter_basis` says `RIGHT_CENSORED_NOT_FILTERED`.

| Cutoff | Maturity | Catalog released | Covers maturity | Filter basis |
| --- | --- | --- | --- | --- |
| 2025-02-01 | 2025-08-30 | 2026-10-16 | yes | `dateAdded <= maturity_date` |
| 2025-09-01 | 2026-03-30 | 2026-10-16 | yes | `dateAdded <= maturity_date` |
| 2026-04-01 | 2026-10-28 | 2026-10-16 | **no** | `RIGHT_CENSORED_NOT_FILTERED` |

The final block matures on **2026-10-28**. `PROV-01` records
`maturity_claimed: false` and `fresh_evidence_required_after_maturity: true`, and
the verifier rejects a manifest that claims otherwise.

## Commands

```bash
cd vulnova_product

# fetch, store bytes, write the manifest (the only command that uses a network)
python -m vulnova.acquisition acquire \
  --store data/acquisition_store \
  --manifest reports/acquisition_1_7/acquisition_manifest.json

# re-attest the manifest digest
python -m vulnova.acquisition manifest

# offline: re-hash stored bytes and re-derive access provenance
python -m vulnova.acquisition verify --markdown report.md

# offline: every required source/cutoff pair present, cutoffs inside the grid
python -m vulnova.acquisition check
python -m vulnova.acquisition check --require-verified   # stricter exit code

# readable missing-evidence report
python -m vulnova.acquisition report
```

Exit codes: `acquire` returns 2 for a cutoff outside the grid or a transport
failure; `verify`/`manifest` return 1 when integrity fails; `check` returns 1 when
a source/cutoff pair is missing or a cutoff is outside the grid, and with
`--require-verified` also when a pair exists but is not `VERIFIED`. No command
returns 0 on the basis of a status it did not observe.

`acquire` flags: `--cutoffs` (default: the three candidate blocks), `--grid`
(default: the 21 dates read from the Phase 2.3K bundle), `--reference` /
`--no-reference`, `--no-cve`, `--no-kev`, `--no-epss`.

## Manifest

`vulnova.acquisition/1.7`. One record per artifact, with
`source`, `key`, `channel`, `cutoff`, `content_status`, `reason_code`,
`access_provenance`, `historical_retrieval_verified`, `retrieved_at`,
`source_timestamp`, `revision`, `http_status`, `artifact_path`, `bytes`,
`sha256` and per-source `details`.

`manifest_digest` is SHA-256 over the canonical JSON with `manifest_digest`,
`generated_at` and `runtime` removed. `generated_at` is the wall clock and
`runtime` describes the local checkout; neither is evidence. Everything that
identifies an artifact, its source time or its retrieval time is inside the
digest, so the digest attests *what was acquired and when*, not where it was
written.

Re-running `acquire` produces a **different digest** by design: the retrieval
timestamps are new, because the retrieval really is new. What stays identical is
every `sha256`, `revision` and `source_timestamp` for unchanged upstream content.

## Offline verification

`verify` performs no network I/O and runs twelve checks:

`SCHEMA`, `MANIFEST_DIGEST`, `ARTIFACT_PRESENT`, `ARTIFACT_SIZE`,
`ARTIFACT_SHA256`, `RETRIEVAL_TIMESTAMP_PRESENT`, `RETRIEVAL_AFTER_SOURCE`,
`RETRIEVAL_BEFORE_MANIFEST`, `ACCESS_PROVENANCE_RECONSISTENT`,
`HISTORICAL_RETRIEVAL_NOT_OVERSTATED`, `CUTOFFS_IN_GRID`,
`FINAL_BLOCK_MATURITY_NOT_CLAIMED`.

The interesting ones are the honesty checks: `ACCESS_PROVENANCE_RECONSISTENT`
re-derives `CONTEMPORANEOUS`/`LATE_RETRIEVAL`/`NOT_RETRIEVED` from the recorded
timestamps and rejects a manifest that disagrees with its own data;
`HISTORICAL_RETRIEVAL_NOT_OVERSTATED` rejects a late retrieval marked as
verified historical provenance; `RETRIEVAL_BEFORE_MANIFEST` rejects an artifact
stamped after the manifest was written (a backdating tell); and
`FINAL_BLOCK_MATURITY_NOT_CLAIMED` rejects a maturity claim before 2026-10-28.

`integrity_status` and `evidence_status` are reported separately. A manifest can
be perfectly intact and still carry `BLOCKED` evidence — that is the normal,
honest outcome here.

## Scope

- No model is trained, no score computed, no predictive metric produced.
- No ranking weight, source datum, event threshold or temporal rule is changed;
  180 / 30 / 210 / 30 and the three cutoffs are imported from
  `vulnova.evaluation.constants`, not redefined.
- The protocol stays `NOT_APPROVED`; nothing here can adopt a design.
- Unavailable evidence never counts as success, and absence from KEV is never
  described as proof of non-exploitation.
