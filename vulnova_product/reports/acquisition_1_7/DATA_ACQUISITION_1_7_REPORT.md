# VULNOVA 1.7 — Historical Data Acquisition and Provenance

This report is generated from the acquisition manifest. It records what was actually retrieved, when, and from which publisher. It trains no model, scores nothing, and does not approve the evaluation protocol.

- manifest schema: `vulnova.acquisition/1.7`
- generated at (UTC): `2026-10-20T02:59:38Z`
- as of: `2026-10-20`
- final candidate maturity: `2026-10-28`
- evidence status: **BLOCKED**
- manifest digest: `5993ce8ce98a0051bd2accec5e5f6259a799d6f05e8cbc9784c2f3b65a40b8c8`
- artifact store: `data/acquisition_store`

## Artifact status

14 record(s). Content: VERIFIED 7, UNAVAILABLE 7, BLOCKED 0. Including access provenance: VERIFIED 1, UNAVAILABLE 7, BLOCKED 6.

Access provenance: CONTEMPORANEOUS 1, LATE_RETRIEVAL 6, NOT_RETRIEVED 7.

## Requirement verdicts

| Requirement | Status | Reason | Detail |
|---|---|---|---|
| `CVE-01_REVISION_PIN_RESOLVED` | VERIFIED | `OK_VERIFIED` | 3 cutoff(s) resolved to an exact commit, with response bytes stored and SHA-256 recorded. |
| `CVE-02_PIN_CROSSCHECK` | VERIFIED | `OK_VERIFIED` | All 3 live revision(s) match the pins recorded in the Phase 2.3K export. |
| `CVE-03_HISTORICAL_RETRIEVAL_PROVENANCE` | BLOCKED | `RETRIEVAL_NOT_CONTEMPORANEOUS` | 2025-02-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2025-09-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2026-04-01: RETRIEVAL_NOT_CONTEMPORANEOUS |
| `KEV-01_DIRECT_CISA_FEED` | UNAVAILABLE | `OFFICIAL_SOURCE_UNREACHABLE` | current: OFFICIAL_SOURCE_UNREACHABLE |
| `KEV-02_CURRENT_CATALOG` | VERIFIED | `OK_VERIFIED` | 1 trusted channel(s) verified: OFFICIAL_GITHUB:current#github; unavailable: OFFICIAL:current (OFFICIAL_SOURCE_UNREACHABLE) |
| `KEV-03_HISTORICAL_REVISION_AT_CUTOFF` | VERIFIED | `OK_VERIFIED` | All 3 record(s) verified. |
| `KEV-04_LABEL_MATURITY_COVERAGE` | BLOCKED | `CATALOG_PREDATES_MATURITY` | 2026-04-01: CATALOG_PREDATES_MATURITY |
| `KEV-05_HISTORICAL_RETRIEVAL_PROVENANCE` | BLOCKED | `RETRIEVAL_NOT_CONTEMPORANEOUS` | 2025-02-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2025-09-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2026-04-01: RETRIEVAL_NOT_CONTEMPORANEOUS |
| `EPSS-01_EXACT_DAILY_FILE` | UNAVAILABLE | `OFFICIAL_SOURCE_UNREACHABLE` | 2025-02-01: OFFICIAL_SOURCE_UNREACHABLE; 2025-09-01: OFFICIAL_SOURCE_UNREACHABLE; 2026-04-01: OFFICIAL_SOURCE_UNREACHABLE |
| `EPSS-02_HISTORICAL_RETRIEVAL_PROVENANCE` | UNAVAILABLE | `OFFICIAL_SOURCE_UNREACHABLE` | 2025-02-01: OFFICIAL_SOURCE_UNREACHABLE; 2025-09-01: OFFICIAL_SOURCE_UNREACHABLE; 2026-04-01: OFFICIAL_SOURCE_UNREACHABLE |
| `PROV-01_FINAL_BLOCK_MATURITY_NOT_CLAIMED` | VERIFIED | `OK_VERIFIED` | Final candidate cutoff 2026-04-01 matures 2026-10-28; this run is as of 2026-10-20 (8 days remaining). Maturity is not claimed and fresh evidence is still required afterwards. |

## Missing or blocked evidence

### CVE-03_HISTORICAL_RETRIEVAL_PROVENANCE — BLOCKED

- reason: `RETRIEVAL_NOT_CONTEMPORANEOUS`
- meaning: The artifact was retrieved after the cutoff. The content may be authentic, but historical access was not observed at the time.
- detail: 2025-02-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2025-09-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2026-04-01: RETRIEVAL_NOT_CONTEMPORANEOUS
- records: `cvelistv5:2025-02-01`, `cvelistv5:2025-09-01`, `cvelistv5:2026-04-01`

### KEV-01_DIRECT_CISA_FEED — UNAVAILABLE

- reason: `OFFICIAL_SOURCE_UNREACHABLE`
- meaning: The official source could not be reached from the acquisition environment.
- detail: current: OFFICIAL_SOURCE_UNREACHABLE
- records: `kev:current`

### KEV-04_LABEL_MATURITY_COVERAGE — BLOCKED

- reason: `CATALOG_PREDATES_MATURITY`
- meaning: The catalog was released before the maturity date, so it cannot observe labels that matured later.
- detail: 2026-04-01: CATALOG_PREDATES_MATURITY
- records: `kev:current#github`

### KEV-05_HISTORICAL_RETRIEVAL_PROVENANCE — BLOCKED

- reason: `RETRIEVAL_NOT_CONTEMPORANEOUS`
- meaning: The artifact was retrieved after the cutoff. The content may be authentic, but historical access was not observed at the time.
- detail: 2025-02-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2025-09-01: RETRIEVAL_NOT_CONTEMPORANEOUS; 2026-04-01: RETRIEVAL_NOT_CONTEMPORANEOUS
- records: `kev:2025-02-01`, `kev:2025-09-01`, `kev:2026-04-01`

### EPSS-01_EXACT_DAILY_FILE — UNAVAILABLE

- reason: `OFFICIAL_SOURCE_UNREACHABLE`
- meaning: The official source could not be reached from the acquisition environment.
- detail: 2025-02-01: OFFICIAL_SOURCE_UNREACHABLE; 2025-09-01: OFFICIAL_SOURCE_UNREACHABLE; 2026-04-01: OFFICIAL_SOURCE_UNREACHABLE
- records: `epss:2025-02-01`, `epss:2025-09-01`, `epss:2026-04-01`

### EPSS-02_HISTORICAL_RETRIEVAL_PROVENANCE — UNAVAILABLE

- reason: `OFFICIAL_SOURCE_UNREACHABLE`
- meaning: The official source could not be reached from the acquisition environment.
- detail: 2025-02-01: OFFICIAL_SOURCE_UNREACHABLE; 2025-09-01: OFFICIAL_SOURCE_UNREACHABLE; 2026-04-01: OFFICIAL_SOURCE_UNREACHABLE
- records: `epss:2025-02-01`, `epss:2025-09-01`, `epss:2026-04-01`

## Source records

| Source | Key | Channel | Content | Access | Retrieved (UTC) | Source time | SHA-256 |
|---|---|---|---|---|---|---|---|
| cvelistv5 | 2025-02-01 | OFFICIAL_GITHUB | VERIFIED | LATE_RETRIEVAL | 2026-10-20T02:59:32Z | 2025-01-31T23:08:06Z | bc59fc810c0f |
| cvelistv5 | 2025-09-01 | OFFICIAL_GITHUB | VERIFIED | LATE_RETRIEVAL | 2026-10-20T02:59:33Z | 2025-08-31T23:33:54Z | eec42dd7c31a |
| cvelistv5 | 2026-04-01 | OFFICIAL_GITHUB | VERIFIED | LATE_RETRIEVAL | 2026-10-20T02:59:33Z | 2026-03-31T23:51:08Z | a7dc381c70a6 |
| epss | 2025-02-01 | OFFICIAL | UNAVAILABLE | NOT_RETRIEVED | 2026-10-20T02:59:38Z | — | — |
| epss | 2025-02-01#mirror | THIRD_PARTY_MIRROR | UNAVAILABLE | NOT_RETRIEVED | — | — | — |
| epss | 2025-09-01 | OFFICIAL | UNAVAILABLE | NOT_RETRIEVED | 2026-10-20T02:59:38Z | — | — |
| epss | 2025-09-01#mirror | THIRD_PARTY_MIRROR | UNAVAILABLE | NOT_RETRIEVED | — | — | — |
| epss | 2026-04-01 | OFFICIAL | UNAVAILABLE | NOT_RETRIEVED | 2026-10-20T02:59:38Z | — | — |
| epss | 2026-04-01#mirror | THIRD_PARTY_MIRROR | UNAVAILABLE | NOT_RETRIEVED | — | — | — |
| kev | 2025-02-01 | OFFICIAL_GITHUB | VERIFIED | LATE_RETRIEVAL | 2026-10-20T02:59:35Z | 2025-01-29T17:02:51.9769Z | e040ac917f18 |
| kev | 2025-09-01 | OFFICIAL_GITHUB | VERIFIED | LATE_RETRIEVAL | 2026-10-20T02:59:36Z | 2025-08-29T17:00:23.7015Z | d4e88aa93681 |
| kev | 2026-04-01 | OFFICIAL_GITHUB | VERIFIED | LATE_RETRIEVAL | 2026-10-20T02:59:38Z | 2026-03-30T18:55:21.8585Z | a925400c147a |
| kev | current | OFFICIAL | UNAVAILABLE | NOT_RETRIEVED | 2026-10-20T02:59:33Z | — | — |
| kev | current#github | OFFICIAL_GITHUB | VERIFIED | CONTEMPORANEOUS | 2026-10-20T02:59:34Z | 2026-10-16T17:15:48.8752Z | b6e27975f663 |

## Label-maturity window per block

| Cutoff | Maturity | Matured at as-of | Catalog released | Covers maturity | Filter basis | Status |
|---|---|---|---|---|---|---|
| `2025-02-01` | 2025-08-30 | True | 2026-10-16T17:15:48.875200+00:00 | True | dateAdded <= maturity_date | VERIFIED |
| `2025-09-01` | 2026-03-30 | True | 2026-10-16T17:15:48.875200+00:00 | True | dateAdded <= maturity_date | VERIFIED |
| `2026-04-01` | 2026-10-28 | False | 2026-10-16T17:15:48.875200+00:00 | False | RIGHT_CENSORED_NOT_FILTERED | BLOCKED |

A catalog released before a block's maturity date is right-censored for that block: filtering it to `dateAdded <= maturity_date` would silently report incomplete labels as complete, so it is not done.

## Offline verification

- integrity status: **VERIFIED** (12 of 12 checks verified)
- artifacts hashed: 7 · network used: no

| Check | Status | Detail |
|---|---|---|
| `SCHEMA` | VERIFIED | structure and digest are valid |
| `MANIFEST_DIGEST` | VERIFIED | recorded 5993ce8ce98a0051bd2accec5e5f6259a799d6f05e8cbc9784c2f3b65a40b8c8, recomputed 5993ce8ce98a0051bd2accec5e5f6259a799d6f05e8cbc9784c2f3b65a40b8c8 |
| `ARTIFACT_PRESENT` | VERIFIED | 7 artifact(s) present |
| `ARTIFACT_SIZE` | VERIFIED | all sizes match |
| `ARTIFACT_SHA256` | VERIFIED | all 7 artifact digest(s) match |
| `RETRIEVAL_TIMESTAMP_PRESENT` | VERIFIED | every retrieved record carries an actual retrieval timestamp |
| `RETRIEVAL_AFTER_SOURCE` | VERIFIED | no retrieval timestamp precedes its source timestamp |
| `RETRIEVAL_BEFORE_MANIFEST` | VERIFIED | no record was retrieved after the manifest was generated |
| `ACCESS_PROVENANCE_RECONSISTENT` | VERIFIED | access provenance matches the recorded timestamps |
| `HISTORICAL_RETRIEVAL_NOT_OVERSTATED` | VERIFIED | no late retrieval is reported as contemporaneous |
| `CUTOFFS_IN_GRID` | VERIFIED | all cutoffs belong to the 21-date grid |
| `FINAL_BLOCK_MATURITY_NOT_CLAIMED` | VERIFIED | maturity 2026-10-28 is not claimed as of 2026-10-20 |

## Standing policies

- **epss_substitution**: A daily EPSS file is used only when its own score_date equals the cutoff. Newer files, later model versions and backfilled values are never substituted.
- **historical_access**: Authentic historical content retrieved now is LATE_RETRIEVAL, not contemporaneous provenance, and is reported BLOCKED for that requirement.
- **kev_absence**: Absence from the KEV catalog is recorded as NOT_LISTED_IN_CATALOG. It is never treated as proof that a vulnerability was not exploited.
- **maturity**: The final candidate block matures 2026-10-28. Maturity is never claimed before that date, and fresh evidence is required after it.
- **mirrors**: Third-party mirrors are recorded as mirrors and never satisfy a requirement.
- **model_training**: No model is trained, scored or approved by this workflow.
- **protocol_approval**: The evaluation protocol remains NOT_APPROVED and unamended.
- **retrieval_timestamps**: Retrieval timestamps are captured after the response body is read. They are never derived from the artifact, never backdated, and never edited.

## Reproducing this acquisition

```bash
python -m vulnova.acquisition acquire --store <dir> --manifest <file>
python -m vulnova.acquisition verify --manifest <file> --store <dir>
python -m vulnova.acquisition check --manifest <file>
python -m vulnova.acquisition report --manifest <file> --out report.md
```

`verify` performs no network I/O: it re-hashes the stored bytes and checks the recorded timestamps for internal consistency.
