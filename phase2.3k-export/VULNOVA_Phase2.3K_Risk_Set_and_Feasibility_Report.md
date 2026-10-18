# VULNOVA — Phase 2.3K

## Point-in-Time Risk-Set Materialization and Temporal Feasibility

**Reference date:** 2026-10-15 · **Cutoffs:** 21 monthly, 2025-02-01 → 2026-10-01 · **Horizon:**
180 days · **Maturation lag:** 30 days · **Distinct-test-event gate:** 30 (unchanged)

---

## 1. Scope

This phase materialised the exact, outcome-blind risk set the protocol needs, at 21 historical
cutoffs, from sources whose revision history can be independently verified — and then tested
whether the resulting history can carry the protocol's temporal split.

**No model was trained, tuned, or evaluated. No predictive claim is made.** The protocol
amendment discussed in §9 is **not** approved here; approving it is the project owner's decision,
and technical feasibility is reported separately from that approval. The 443-CVE panel was used
for reconciliation only and never as the risk set. The standing NO-GO for confirmatory predictive
evaluation is retained.

Status vocabulary used throughout: `VERIFIED`, `RECONSTRUCTED`, `PROPOSED`, `UNVERIFIED`,
`UNAVAILABLE`, `BLOCKED`.

---

## 2. Persistence and provenance gate

Executed first, before any new work.

| Item | Result |
|---|---|
| Archives vs. their checksum manifests | `VERIFIED` — 2.3H, 2.3I, 2.3J all `sha256sum -c` OK |
| Internal members verified | **590 / 590** — 0 missing, 0 mismatched |
| 2.3J digest | `c78dc191498e6fa47600d2924cdaa35c9f8e13c9c735a5b6767b01a3d16a6a3b` (supersedes `b1299f43…`) |

The three manifests are not schema-uniform — 2.3H/2.3I use `member`/`size_bytes` and 2.3J uses
`path`/`bytes` — so they were normalised before comparison. Archive membership is excluded from
its own manifest, so each manifest lists 28 / 51 / 511 of the 29 / 52 / 513 members.

**`UNAVAILABLE` in this environment:** the Phase 2.3F and Phase 2.3G source directories. Their
recorded digests are carried forward as **historical claims** — they were not re-verified and must
not be cited as verified access. Nothing about them was reconstructed from a filename or a
reported hash.

---

## 3. Historical inventories — `VERIFIED`

For each cutoff `T`, the source revision is the **greatest commit on `main` whose committer
timestamp is ≤ `T` 00:00:00Z** — the rule was frozen before any revision was selected. All 21
pins resolved; every pin lands between 20:56 and 23:54 UTC on `T−1`, so no cutoff sits near a
boundary where the rule would be fragile. Per cutoff the manifest records the commit SHA, the
`cves` tree SHA, the commit timestamp, the exact rule, a per-year subtree hash, per-year counts,
non-conforming paths, and the record count.

| Cutoff | Records | Cutoff | Records | Cutoff | Records |
|---|---:|---|---:|---|---:|
| 2025-02-01 | 279,720 | 2025-10-01 | 312,129 | 2026-06-01 | 354,406 |
| 2025-03-01 | 283,551 | 2025-11-01 | 316,519 | 2026-07-01 | 362,411 |
| 2025-04-01 | 287,718 | 2025-12-01 | 319,635 | 2026-08-01 | 372,322 |
| 2025-05-01 | 291,859 | 2026-01-01 | 325,278 | 2026-09-01 | 385,041 |
| 2025-06-01 | 296,123 | 2026-02-01 | 330,421 | 2026-10-01 | 400,116 |
| 2025-07-01 | 299,923 | 2026-03-01 | 335,229 | | |
| 2025-08-01 | 303,855 | 2026-04-01 | 341,535 | | |
| 2025-09-01 | 307,593 | 2026-05-01 | 347,424 | | |

**Enumeration completeness** was established twice by independent routes: a walk of the local
object database, and a separate walk of all 27 year subtrees through the GitHub trees API at
`b3b7d343…` (every subtree reported `truncated=false`). Both returned **279,720** records for
2025-02-01.

**Content completeness.** All 21 revisions were read in full and reduced to per-record facts
(CVSS, state, dates, rejection, byte size, content hash) — **279,720 → 400,116 records, 21/21
`completeness_match: true`, 0 duplicate identifiers, 0 parse errors.** Each full revision streams
in ~47 s as a single codeload tarball; the reductions are staged outside the workspace (406 MB).

**`PROPOSED`** for the split-vs-outcome geometry, and for the protocol amendment in §9.

### 3.1 Source-history limitations, recorded not hidden

* The working clone carries revisions from **2025-01-20** onward (`984a0f571ae8…`). All 21 cutoffs
  are covered, but this is why no earlier cutoff is offered.
* `datePublished` is a field value in the record. Tree presence at the pinned revision is what
  establishes retrievability at `T`; publication date is used only for the eligibility rule in §4.
* The classification of *when a record's content entered a revision* is `RECONSTRUCTED` from
  commit history, not observed directly.

---

## 4. The outcome-blind risk set — `VERIFIED`

The definition was versioned **before** any label was generated. A record is **eligible at risk**
at `T` when it is present in the verified inventory at `T`, carries a well-formed identifier, is
not a rejected record, satisfies `datePublished ≤ T`, and **is not in the KEV catalog as observed
at `T`**. No component of the rule references any later KEV entry.

`EXCLUDED_ALREADY_IN_KEV_AT_T` uses genuine contemporaneous membership (§6.1), never a
`dateAdded ≤ T` reconstruction.

| Cutoff | Inventory | KEV @ T | **Risk set** | Published after T (excluded) |
|---|---:|---:|---:|---:|
| 2025-02-01 | 279,720 | 1,253 | **274,815** | 3,652 |
| 2025-04-01 | 287,718 | 1,312 | **283,055** | 3,351 |
| 2025-06-01 | 296,123 | 1,352 | **291,075** | 3,696 |
| 2025-08-01 | 303,855 | 1,391 | **298,533** | 3,931 |
| 2025-10-01 | 312,129 | 1,422 | **306,483** | 4,224 |
| 2025-12-01 | 319,635 | 1,464 | **313,778** | 4,393 |
| 2026-01-01 | 325,278 | 1,484 | **319,280** | 4,514 |
| 2026-03-01 | 335,229 | 1,529 | **328,202** | 5,498 |
| 2026-06-01 | 354,406 | 1,607 | **347,191** | 5,608 |
| 2026-10-01 | 400,116 | 1,730 | **392,114** | 6,272 |

Risk set: **274,815 → 392,114**; **6,723,857** unique `(CVE, cutoff)` pairs. Full per-cutoff
reasons are in `risk_set_denominator_summary.csv`; the membership itself is shipped as 21
deterministic partitions plus a hashed index (`risk_set_membership/`), never as counts alone.

Every reason-coded exclusion is preserved per record. Nothing was estimated from KEV additions,
from the 89,660-row archive, or from eventual-KEV counts. `UNRESOLVED_RECORD_UNREADABLE` is 0 at
every cutoff — every record in every revision reduced to facts.

**A negative check that matters:** across all 5.9 M `(CVE, cutoff)` pairs, **zero** records in a
risk set carry a `datePublished` later than their cutoff. Tree presence at `R(T)` implies
`datePublished ≤ T` in practice, so the publication rule holds empirically rather than only by
construction.

---

## 5. Feature availability, independent of membership — `VERIFIED`

Missingness is reported, never filled: no substitutes, no interpolated scores, no current data
presented as historical.

### 5.1 CVSS

CVSS availability is read from the **exact census of the pinned revision**, so it is a genuine
point-in-time value; a score that first appears after `T` cannot enter the table at `T`.

| Cutoff | Coverage | Cutoff | Coverage | Cutoff | Coverage |
|---|---:|---|---:|---|---:|
| 2025-02-01 | 31.08 % | 2025-10-01 | 40.31 % | 2026-06-01 | 46.93 % |
| 2025-03-01 | 32.18 % | 2025-11-01 | 41.29 % | 2026-07-01 | 47.95 % |
| 2025-04-01 | 33.93 % | 2025-12-01 | 41.82 % | 2026-08-01 | 49.58 % |
| 2025-05-01 | 35.84 % | 2026-01-01 | 42.53 % | 2026-09-01 | 51.47 % |
| 2025-06-01 | 37.39 % | 2026-02-01 | 43.35 % | 2026-10-01 | 52.98 % |
| 2025-07-01 | 38.36 % | 2026-03-01 | 44.08 % | | |
| 2025-08-01 | 39.01 % | 2026-04-01 | 45.07 % | | |
| 2025-09-01 | 39.69 % | 2026-05-01 | 46.00 % | | |

Missingness is structural, not random: the risk set is dominated by older records that never
received a CVSS score, and coverage rises monotonically with the cutoff because newer records are
more often scored. **Roughly half the risk set has no usable CVSS at any cutoff** — a property of
the population, not of the retrieval.

### 5.2 EPSS — the decisive negative result

The emission archive's **first commit is 2026-02-02**, so no public commit history existed before
then. Of its 2,003 daily files (2021-04-14 → 2026-10-16), only **256 have same-day commits**, the
earliest dated 2026-02-03; **1,747 are backfills**. The 2021-04-14 file, for instance, was added on
2026-02-03.

A file whose *score date* precedes `T` is therefore **not** evidence that the score was available
at `T`. Applying that rule:

| Verdict | Cutoffs |
|---|---|
| `BACKFILLED_AFTER_CUTOFF` | **13** — 2025-02-01 … 2026-02-01 |
| `HISTORICALLY_AVAILABLE` | **8** — 2026-03-01 … 2026-10-01, all at lag 0 |

Where genuinely available, EPSS coverage of the risk set is high and exact:

| Cutoff | Model | Coverage |
|---|---|---:|
| 2026-03-01 | v2025.03.14 | 96.38 % |
| 2026-04-01 | v2025.03.14 | 96.44 % |
| 2026-05-01 | v2025.03.14 | 96.49 % |
| 2026-06-01 | v2025.03.14 | 96.56 % |
| 2026-07-01 | v2026.06.15 | 96.62 % |
| 2026-08-01 | v2026.06.15 | 96.70 % |
| 2026-09-01 | v2026.06.15 | 96.79 % |
| 2026-10-01 | v2026.06.15 | 96.90 % |

Two consequences that constrain any design: the model version **changes inside the window**
(v2025.03.14 → v2026.06.15 at 2026-07-01), so EPSS is not one feature across the span; and of the
eight available cutoffs, **only 2026-03-01 is matured** — so EPSS cannot contribute to a matured
multi-block historical design at all.

---

## 6. Outcome reconciliation — `VERIFIED`

### 6.1 The KEV timeline corrects the previous phase

Replaying all **325** readable catalog revisions (2025-01-27 → 2026-10-15) gives **1,749**
distinct CVEs ever listed, **498** additions and **4** removals.

This **refutes the record carried by 2.3J and 2.3H of "493 additions, 0 removed."** Those figures
came from differencing two snapshots, which is structurally blind to anything added *and removed*
between them. The four removals are:

| CVE | First observed | Removed | Resolution |
|---|---|---|---|
| CVE-2025-4664 | 2025-05-15 | 2025-06-09 | permanent |
| CVE-2025-6264 | 2025-10-14 | 2025-10-22 | permanent |
| CVE-2026-1281 | 2026-01-29 | 2026-01-29 | **transient** — withdrawn for exactly one revision, present at the final revision |
| CVE-2026-69836 | 2026-08-21 | 2026-08-21 | permanent |

Consequently KEV membership at `T` is computed by **replaying revisions**, which is removal-aware.
A `dateAdded ≤ T` reconstruction would report CVE-2025-4664 and CVE-2025-6264 as in-KEV at cutoffs
where they were in fact absent.

One upstream defect is recorded rather than repaired: blob `a7fa9428cc13…` (2025-02-25,
`catalogVersion 2025.02.25`, `count: 1280`) is truncated mid-record. It is recorded as
`unparseable_revisions` and never allowed to reset the baseline.

### 6.2 Events, and a reconciliation that explains itself

An **event** is a distinct CVE that was in the risk set at `T` and first entered the KEV catalog
within the forward window `(T, T+180d]`. `dateAdded` is *not* used as the observation time: the
first-observed catalog inclusion is.

| Cutoff | Matured | Catalogue additions in window | In risk set | **Eligible events** |
|---|---|---|---:|---:|---:|
| 2025-02-01 | yes | 139 | 55 | **55** |
| 2025-03-01 | yes | 126 | 48 | **48** |
| … 14 matured cutoffs … | | 104–157 | 33–61 | **33–61 each** |
| 2026-03-01 | yes | 157 | 60 | **60** |
| 2026-04-01 | no | 173 | 47 | 47 (floor) |
| 2026-10-01 | no | 15 | 7 | 7 (floor) |

**14 matured cutoffs** yield **739 event rows** covering **214 distinct events** (3.45 rows per
event). Censored cutoffs' counts are floors and are never treated as gate results — on this
evidence the 30-event gate is met by **14 / 14** matured cutoffs.

**Reconciliation with 2.3J.** 2.3J reported 213 distinct events; 2.3K finds 214. The delta is
exactly **+1**, and it is fully explained by a concrete identifier:

* **CVE-2025-6264** — first observed in KEV 2025-10-14, eligible at risk at 2025-07-01 …
  2025-10-01, and **removed from the catalog on 2025-10-22**. 2.3J's snapshot-diff could not see
  it because it is present in neither of 2.3J's two snapshots.

The other three removals contribute no matured-window event, for a documented structural reason:
**the record does not exist in the historical inventory** at any cutoff whose window covers its
inclusion — CVE-2025-4664 is absent at 2025-02-01 … 2025-05-01, CVE-2026-69836 at 2026-03-01, and
CVE-2026-1281 at 2025-09-01 … 2026-01-01. Newly published CVEs become eligible at a *later*
cutoff under the same rule; they were never retroactively inserted into earlier inventories.

2.3J's 493 additions also exclude CVE-2026-21589 (added after its reference snapshot). The counts
were reconciled with identifiers rather than forced to match: **2.3K does not adopt 493.**

---

## 7. Temporal split feasibility — `PROPOSED`

Preserving the 180-day horizon, the 30-day maturation lag and the ≥30-event gate unchanged.

### 7.1 The binding constraint is label maturity, not disjointness

A train/validation/test design requires each block's labels to be matured **before the next
block's decision point**. With a 180-day horizon and a 30-day lag, consecutive blocks must
therefore be **210 days** apart — not 180.

This is the finding that decides the phase. The candidate design carried out of 2.3J — three
segments at 180-day spacing (`2025-02-01 / 2025-08-01 / 2026-02-01`), yielding 55 / 46 / 60 events
with **fully disjoint** outcome windows — is `INFEASIBLE`:

| Block | Cutoff | Events | Gate | Disjoint | Labels matured before next block? | Slack |
|---|---|---:|---|---|---|---:|
| SEG1 | 2025-02-01 | 55 | yes | yes | **no** | **−29 d** |
| SEG2 | 2025-08-01 | 46 | yes | yes | **no** | **−26 d** |
| SEG3 | 2026-02-01 | 60 | yes | yes | n/a | |

Segment 1's labels mature **2025-08-30**, but segment 2 decides on **2025-08-01**. Disjointness
was achieved; sequential label availability was not. The gap is exactly the 30-day maturation lag.

**A three-block design is impossible, provably.** For the earliest possible first cutoff
(2025-02-01), the earliest successor blocks are `+210 d` and `+420 d` → `2025-09-01` and
`2026-04-01`, whose labels mature `2026-10-28`. But a test cutoff must satisfy `T + 210 ≤
2026-10-15`, i.e. `T ≤ 2026-03-18`. So the third block cannot be matured: the grid is **13 days
short** (equivalently, the cutoff window would have to begin 39 days earlier). This is arithmetic,
not a data defect.

### 7.2 What *is* constructible

| Design | Blocks | Events per block | Verdict |
|---|---|---|---|
| A — 180-day spaced | 3 | 55 / 46 / 60 | `INFEASIBLE_LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK` |
| A2 — earliest 3-block on the grid | 3 | 55 / 52 / 47 | `INFEASIBLE_BLOCK_NOT_MATURED` (final block matures 2026-10-28) |
| B — contiguous thirds | 3 | 92 / 85 / 123 | `INFEASIBLE_SHARED_EVENTS_AND_LABELS_NOT_MATURED` |
| **E — label-matured sequential** | **2** | **55 / 52** | **`FEASIBLE`** |
| C — single final cutoff | 1 | 60 | `FEASIBLE` |
| D — rolling origin | 1 each × 14 | 33–61 | `FEASIBLE` per cutoff |

**Design E is the ceiling:** `2025-02-01` (55 events, labels mature 2025-08-30) and `2025-09-01`
(52 events, labels mature 2026-03-30) — disjoint event sets, both above the gate, both matured,
labels genuinely available in sequence. It provides **training and test blocks but no separate
validation block**.

Design B is the naive chronological split and fails twice over: adjacent monthly cutoffs share
**151 of 180 days** of window, and the blocks reuse each other's events — TRAIN∩VALIDATION = 42,
VALIDATION∩TEST = 44, TRAIN∩TEST = 15. Chronological ordering alone creates no independence, and
the label-maturity slacks are −179 and −180 days.

No boundary was moved to improve a score or inflate a count. No purge interval was used as an
extra evaluation block, and no split is called independent merely because its cutoffs are ordered
or non-adjacent. Event reuse is reported separately from window overlap. The 214-event total is
**not** 214 independent observations, and is not presented as such.

---

## 8. Decision

> ## `NOT_VIABLE_HISTORICAL`

The protocol requires a chronological training/validation/test design whose labels mature in
sequence. Under the frozen 180-day horizon and 30-day maturation lag, that requires three blocks
210 days apart plus a matured final block. The available matured history supports **two**. No
split satisfies the protocol, so the historical evaluation is not viable — and the gate is **not**
relaxed to change that answer.

**This is not an event-scarcity failure, and it is not a data-quality failure.** Every one of the
14 matured cutoffs clears the 30-event gate on its own, with 33–61 eligible events against
274,815–392,114 at-risk candidates. A two-block train/test design is constructible today. The
blocker is the **length of the matured calendar**.

The three alternatives are all outside this phase's authority:

1. **Collect prospectively** — the sound default, and the recommendation here.
2. **Let the calendar supply the missing block.** The earliest three-block design on the monthly
   grid (`2025-02-01 / 2025-09-01 / 2026-04-01`) becomes matured on **2026-10-28**. Adopting it is
   a protocol amendment requiring the project owner's documented approval, which this phase does
   **not** give.
3. Adopt a two-block design — likewise an amendment, and one that would still need to say where
   validation comes from.

EPSS independently reinforces the conclusion for a different reason: only one matured cutoff has
demonstrably historical EPSS, and the model version changes inside the window.

`BLOCKED_INSUFFICIENT_EVIDENCE` is **not** the right verdict here: the evidence is complete enough
to *prove* the infeasibility rather than to be missing from it.

---

## 9. Limitations

1. **2.3F / 2.3G are `UNAVAILABLE`** in this environment; their digests are historical claims.
2. **EPSS has no demonstrable point-in-time availability before 2026-02-03**, capping historical
   EPSS at 8 cutoffs, of which 1 is matured.
3. **The working clone covers revisions from 2025-01-20 only**; no cutoff before 2025-02-01 is
   offered from it.
4. **~50 % of the risk set has no usable CVSS**, rising with the cutoff (31 % → 53 %).
5. One KEV revision is **truncated upstream** and is recorded as unparseable.
6. The risk set is very large relative to the event count (~0.02 % base rate at most cutoffs) —
   a property of the honest population, and the reason 2.3J's cohort-based ~7.9 % figure would be
   wrong by roughly two orders of magnitude.
7. KEV is **not exhaustive**; catalog absence is never treated as proof a vulnerability was not
   exploited.

---

## 10. Artifacts

| File | Role |
|---|---|
| `cvelistv5_inventory_manifest.csv` | revision pin, rule, tree hashes, counts per cutoff |
| `risk_set_membership/` | 21 membership partitions + `INDEX.csv` with per-partition sha256 |
| `risk_set_denominator_summary.csv` | exact denominators and every exclusion reason |
| `point_in_time_feature_eligibility.csv` | CVSS and EPSS availability, kept apart from membership |
| `outcome_and_event_reconciliation.csv` | outcomes against the verified timeline, per cutoff |
| `temporal_split_feasibility.csv` | per-block events, independence and label-maturity verdicts |
| `phase2_3k_quality_summary.json` | machine-readable result |
| `phase2_3k_integrity_manifest.json` | file digests (self-excluded) |
| `evidence/census_index.csv` | the 21 exact censuses, with hashes |

Reproduce the critical counts with `python3 tools/verify_phase2_3k.py . <cvelistv5_clone>`; the
censuses regenerate in ~47 s per cutoff via `tools/census_from_tarball.py`.

**`/home/user/Ai` was not modified in any way** — no file, Git history, branch, remote, commit or
push. The repository was verified unchanged before and after this phase.
