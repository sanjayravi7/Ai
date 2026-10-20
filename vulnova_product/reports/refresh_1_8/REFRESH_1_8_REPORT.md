# VULNOVA 1.8 — Maturity Gate and Evidence Refresh

**Refresh status:** `BLOCKED_MATURITY_NOT_REACHED` · **Evidence status:** `BLOCKED` · **As of:** `2026-10-20`
**Protocol approval:** `NOT_APPROVED` · **Adopted design:** `none` · **Protocol execution authorised:** no · **Model trained:** no

This report measures whether the final candidate block has matured and what fresh evidence could be obtained. It **does not** approve the protocol, adopt a design, relax the event gate or authorise training. A green integrity result is not proof that the historical evaluation is viable.

## The maturity boundary

| Question | Answer |
|---|---|
| Final candidate cutoff | `2026-04-01` |
| Label maturity date | `2026-10-28` (210 days = 180 horizon + 30 lag) |
| Calendar mature at this as-of date | **no** |
| Days remaining | 8 |
| Maturity claimed | **no** |

Calendar maturity is necessary but not sufficient. A block is only observable when the catalog was published **on or after** its maturity date; a catalog released earlier cannot contain labels that settled later.

## Gate, block by block

| Cutoff | Maturity | Calendar matured | Days remaining | Catalog released | Observes maturity | Status |
|---|---|---|---:|---|---|---|
| 2025-02-01 | 2025-08-30 | yes | -416 | 2026-10-16T17:15:48.8752Z | yes | `MATURED_AND_OBSERVED` |
| 2025-09-01 | 2026-03-30 | yes | -204 | 2026-10-16T17:15:48.8752Z | yes | `MATURED_AND_OBSERVED` |
| 2026-04-01 | 2026-10-28 | no | 8 | 2026-10-16T17:15:48.8752Z | no | `NOT_MATURED` |

## Catalog in hand

- **Selection:** `OFFICIAL_GITHUB:current#github` (catalog `2026.10.16`, released `2026-10-16T17:15:48.8752Z`)
- **Entries:** 1748 parsed / 1748 declared
- **Revision:** `6a392940c663b52271fa4e6aa7b39995b18c9a71`
- **SHA-256:** `b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d`
- **Request URL:** `https://api.github.com/repos/cisagov/kev-data/git/blobs/fd8de296db5877570e6d30a85e003665fc802cf2`
- **Retrieved (UTC):** `2026-10-20T03:31:20Z`

## dateAdded filter

| Block | Applied | Basis | Entries | Observable | After maturity | Trusted |
|---|---|---|---:|---:|---:|---|
| 2025-02-01 | yes | `FILTERED_BY_DATE_ADDED` | 1748 | 1406 | 342 | yes |
| 2025-09-01 | yes | `FILTERED_BY_DATE_ADDED` | 1748 | 1555 | 193 | yes |
| 2026-04-01 | no | `RIGHT_CENSORED_NOT_FILTERED` | — | — | — | yes |

A filtered view is a derived lower bound over one catalog, **not** an observed point-in-time membership set. The 1.6 event rules remain the only basis for a real label.

## EPSS retry

| Cutoff | Content | Access | Reason | Retrieved | SHA-256 |
|---|---|---|---|---|---|
| 2025-02-01 | `UNAVAILABLE` | `NOT_RETRIEVED` | `OFFICIAL_SOURCE_UNREACHABLE` | 2026-10-20T03:31:20Z | — |
| 2025-09-01 | `UNAVAILABLE` | `NOT_RETRIEVED` | `OFFICIAL_SOURCE_UNREACHABLE` | 2026-10-20T03:31:20Z | — |
| 2026-04-01 | `UNAVAILABLE` | `NOT_RETRIEVED` | `OFFICIAL_SOURCE_UNREACHABLE` | 2026-10-20T03:31:21Z | — |

A historical EPSS file retrieved today is `LATE_RETRIEVAL`, not contemporaneous provenance. A newer file, a backfilled value or a third-party mirror is never substituted.

## Requirements

| Requirement | Status | Reason | Detail |
|---|---|---|---|
| `KEV-R1_DIRECT_CISA_FEED`<br>The direct CISA feed is reachable and preserved | `UNAVAILABLE` | `OFFICIAL_SOURCE_UNREACHABLE` | direct feed: UNAVAILABLE (OFFICIAL_SOURCE_UNREACHABLE) |
| `KEV-R2_CURRENT_CATALOG`<br>A current KEV catalog is preserved from a first-party channel | `VERIFIED` | `OK_VERIFIED` | selected OFFICIAL_GITHUB:current#github (catalog 2026.10.16, released 2026-10-16T17:15:48.8752Z, 1748 entries, sha256 b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d) |
| `KEV-R3_MATURITY_OBSERVABLE`<br>Every block's labels can be observed at its maturity date | `BLOCKED` | `MATURITY_NOT_REACHED` | 2025-02-01: MATURED_AND_OBSERVED (OK_VERIFIED); 2025-09-01: MATURED_AND_OBSERVED (OK_VERIFIED); 2026-04-01: NOT_MATURED (MATURITY_NOT_REACHED) |
| `EPSS-R1_EXACT_DAILY_FILE`<br>The exact daily EPSS file exists for every cutoff | `UNAVAILABLE` | `OFFICIAL_SOURCE_UNREACHABLE` | 2025-02-01: UNAVAILABLE (OFFICIAL_SOURCE_UNREACHABLE); 2025-09-01: UNAVAILABLE (OFFICIAL_SOURCE_UNREACHABLE); 2026-04-01: UNAVAILABLE (OFFICIAL_SOURCE_UNREACHABLE) |
| `EPSS-R2_HISTORICAL_PROVENANCE`<br>EPSS scores were observed at their cutoffs, not downloaded later | `UNAVAILABLE` | `OFFICIAL_SOURCE_UNREACHABLE` | 2025-02-01: NOT_RETRIEVED; 2025-09-01: NOT_RETRIEVED; 2026-04-01: NOT_RETRIEVED |
| `PROV-R1_NO_PREMATURE_MATURITY`<br>Premature maturity of the final candidate block is impossible | `VERIFIED` | `OK_VERIFIED` | final candidate cutoff 2026-04-01 matures 2026-10-28; this run is as of 2026-10-20 (8 days remaining). Maturity is not claimed and fresh evidence is required after that date. |
| `PROV-R2_SEALED_ARCHIVE_UNCHANGED`<br>The sealed 1.7 archive was not rewritten by the refresh | `VERIFIED` | `OK_VERIFIED` | 7 artifact(s) still hash to their recorded digests; the manifest is byte-identical |

## Comparison with the committed 1.6 readiness report

| | 1.6 baseline | this refresh |
|---|---|---|
| As of | `2026-10-15` | `2026-10-20` |
| Readiness status | `BLOCKED_PROTOCOL_NOT_APPROVED` | `BLOCKED_PROTOCOL_NOT_APPROVED` |
| Checks PASS / FAIL / BLOCKED / N/A | 42 / 0 / 1 / 1 | 42 / 0 / 1 / 1 |
| Report digest | `1d51544af41a…` | `f38d0393e343…` |

**No check changed status.** Every one of the 44 checks reports the same status as the committed 1.6 report.

## Feasibility questions

| Question | Answer |
|---|---|
| `final_kev_maturity_requirement_satisfied` | no |
| `exact_historical_epss_available` | no |
| `required_provenance_complete` | no |
| `any_candidate_design_admissible` | no |
| `protocol_remains_not_approved` | **yes** |
| `protocol_execution_authorized` | no |
| `model_training_authorized` | no |
| `report_digest_matches_baseline` | no |
| `semantic_check_statuses_match_baseline` | **yes** |

Maturity is necessary, not sufficient: the gate says whether a block's labels could be observed, while the readiness checks say whether the evidence and the protocol actually support an evaluation.

## Designs

| Design | Baseline verdict | Current verdict | Protocol-admissible |
|---|---|---|---|
| `A2_EARLIEST_3BLOCK` | `INFEASIBLE` | `INFEASIBLE` | no |
| `A_180D_SPACED_3SEG` | `INFEASIBLE` | `INFEASIBLE` | no |
| `B_CONTIGUOUS_THIRDS` | `INFEASIBLE` | `INFEASIBLE` | no |
| `C_SINGLE_FINAL_CUTOFF` | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | no |
| `D_ROLLING_ORIGIN` | `INFEASIBLE` | `INFEASIBLE` | no |
| `E_LABEL_MATURED_2BLOCK` | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | no |

## Limitations

- The final candidate block matures 2026-10-28; this run is 8 day(s) earlier, so no final-block label set is produced and maturity is not claimed.
- The catalog (2026.10.16, released 2026-10-16T17:15:48.8752Z) predates 2026-10-28; those observations are right-censored and are not filtered.
- Exact historical EPSS files were not obtained for 2025-02-01, 2025-09-01, 2026-04-01; those requirements stay UNAVAILABLE and no newer file or mirror is substituted.
- Readiness checks were re-run at this as-of date. Their statuses (unchanged) are technical evidence, not an approval.
- A green integrity result proves the bytes are intact. It does not prove the historical evaluation is viable.
- The final KEV maturity requirement is not satisfied; the maturity gate remains the primary blocker and no label set is reported.
- The two report digests differ. A readiness report embeds its as-of date and derived maturity rows, so a digest difference is expected even when every check status is identical; compare statuses, not digests.
- Exact historical EPSS files are not available; the EPSS requirement stays UNAVAILABLE and is never satisfied by a newer file or a mirror.

## Reproduce

```bash
cd vulnova_product
python -m vulnova.refresh run          # the only network-using command
python -m vulnova.refresh gate         # offline: is the block mature yet?
python -m vulnova.refresh verify       # offline: re-hash and re-check
```

Refresh digest: `36803f26f02331e705c26e31a437fae04f0dc5705b837a11a849c3cd6ea174f4`
