# Addendum — VULNOVA 1.7 acquisition against the Phase 2.3K pins

**Status:** addendum to [`VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md`](VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md).
**The sealed report has not been edited.** Its SHA-256 remains
`d4f346909b6c3d1af4bf9adb58e59fbb789ae3c0ae0e1acd3a4c32614c9be141`.

**Decision unchanged: `NOT_VIABLE_HISTORICAL`.** Protocol approval remains
`NOT_APPROVED`. No model was trained, no event gate was relaxed, no temporal rule
was changed.

## What 1.7 did with this export

VULNOVA 1.7 re-derived, from the live official sources, the revision pin behind
each frozen cutoff and compared it against the pins recorded here. It then stored
the exact bytes and recorded when it actually retrieved them.

Artifacts: `vulnova_product/reports/acquisition_1_7/` ·
`vulnova_product/data/acquisition_store/` · code in `vulnova_product/vulnova/acquisition/`.

## Cross-check results

**cvelistV5 — all three candidate cutoffs reproduce exactly.**
`cvelistv5_inventory_manifest.csv` records a `revision_sha` per cutoff; the live
CVE Program repository resolves the same commit under the same rule (latest
commit at or before `T 00:00:00Z`):

| Cutoff | `revision_sha` in this export | Live re-resolution | Result |
|---|---|---|---|
| 2025-02-01 | `b3b7d34318e4f6d1de4e082d03ea21984ff2f176` | identical | MATCH |
| 2025-09-01 | `2549c0e76d2857fa6ed14b146fa377d5164914d7` | identical | MATCH |
| 2026-04-01 | `bc781f6b07948ceacd7c5e1c1ede9119b2ac0778` | identical | MATCH |

**KEV — all three candidate cutoffs reproduce exactly.** For each cutoff the live
`cisagov/kev-data` commit matches the `commit_sha` selected from
`raw/kev_revisions.csv` by the same rule, and the downloaded catalog's SHA-256
equals the recorded `content_sha256`:

| Cutoff | Selected commit | Catalog | Entries | `content_sha256` |
|---|---|---|---|---|
| 2025-02-01 | `49c9495366c4…` | `2025.01.29` | 1,253 | `e040ac917f18…` MATCH |
| 2025-09-01 | `9d28701f99f7…` | `2025.08.29` | 1,406 | `d4e88aa93681…` MATCH |
| 2026-04-01 | `6fe63a2e8d9b…` | `2026.03.30` | 1,555 | `a925400c147a…` MATCH |

The current catalog (`2026.10.16`, 1,748 entries) additionally reproduces the
committed 1.6 snapshot `vulnova_product/data/snapshots/kev/known_exploited_vulnerabilities.json`
byte-for-byte (`b6e27975f663…`).

Note the 2026-04-01 row: `raw/kev_revisions.csv` also contains a later,
2026-04-01-dated revision (`72998801139e…`, 1,556 entries). It falls *after*
`2026-04-01T00:00:00Z`, so the acquisition rule — and this export's own pin —
select the 2026-03-30 revision. Both agree; no choice was re-made here.

## What 1.7 could not obtain

| Requirement | Status | Why |
|---|---|---|
| EPSS exact daily files at the three cutoffs | `UNAVAILABLE` | `epss.cyentia.com` did not answer |
| Direct CISA KEV feed | `UNAVAILABLE` | `www.cisa.gov` did not answer |
| Historical retrieval provenance (CVE, KEV) | `BLOCKED` | acquired in 2026 for 2025–2026 cutoffs |
| Block-3 label maturity | `BLOCKED` | catalog 2026-10-16 predates maturity 2026-10-28 |

No substitute was used. A reachable third-party EPSS mirror
(`github.com/empiricalsec/epss_scores`) was recorded and explicitly refused. The
overall evidence status of the acquisition run is **`BLOCKED`**, which does not
change this export's decision or its reasons — it only makes explicit which
inputs a future evaluation could and could not re-derive.

## Why this matters for the recorded decision

The 2.3K verdict rests on calendar length, not on missing files: all 14 matured
cutoffs clear the 30-event gate individually. Nothing acquired in 1.7 shortens
that calendar. The final candidate block still matures **2026-10-28**, and 1.7
records `maturity_claimed: false` with `fresh_evidence_required_after_maturity:
true`. Maturity is not evidence; a fresh acquisition will be required after that
date.
