# VULNOVA Evaluation Protocol 1.6

**Protocol ID:** `vulnova-evaluation-protocol-1.6` · **Status:** `DRAFT_AWAITING_APPROVAL`
**Approval state:** `NOT_APPROVED` · **Approved by:** — · **Approval reference:** —
**Adopted design:** **none** · **Reference date:** 2026-10-15

> This document is a draft protocol, not an approval and not an evaluation. It does
> not adopt a two-block or three-block design. Adopting any design, and lifting the
> standing NO-GO for confirmatory predictive evaluation, are separate decisions that
> only the project owner can make in writing.

---

## 1. Purpose and scope

This protocol defines how a VULNOVA temporal evaluation may be admitted once the
project owner approves a design. It freezes the temporal boundaries and the
evidence rules already used by Phase 2.3K so that readiness can be checked
mechanically and reproducibly.

In scope:

* point-in-time construction of the risk set and its features;
* label maturity and leakage controls;
* the distinct-event gate;
* evidence classification for KEV;
* an explicit, auditable approval state;
* a reproducible readiness report.

Out of scope and prohibited in this phase:

* training, tuning, scoring or evaluating any model;
* any predictive-performance claim or probability-of-exploitation claim;
* changing ranking weights, scores or source data;
* relaxing the event gate, horizon or maturation lag;
* approving this protocol by tooling, by inference, or by silence.

## 2. Frozen constants

| Constant | Value | Meaning |
|---|---:|---|
| Forward horizon | **180 days** | An event is a KEV inclusion in `(T, T+180d]`. |
| Label maturation lag | **30 days** | Labels are allowed to settle for 30 days after the horizon. |
| Maturity span | **210 days** | `T + 180 + 30`; the minimum spacing between sequential single-cutoff blocks. |
| Distinct-event gate | **30** | Minimum distinct test events in every evaluated block. Never relaxed. |
| Sequential blocks | **3** | Training, validation and test. A two-block design is insufficient. |
| Cutoff definition | 00:00:00Z | Only information observable at or before `T` may be used. |

These values are duplicated in `protocol/evaluation_protocol.json`, in the code
(`vulnova/evaluation/constants.py`) and in the Phase 2.3K quality summary. The
readiness command cross-checks all three; a disagreement is a failing check.

## 3. Definitions

**Risk set at `T`.** Records present in the verified cvelistV5 inventory at the
revision pinned for `T`, with a well-formed identifier, not rejected, with
`datePublished <= T`, and not in the CISA KEV catalog **as observed at `T`**. The
exclusion uses genuine contemporaneous membership, never a `dateAdded <= T`
reconstruction.

**Event.** A distinct CVE that was in the risk set at `T` and first entered the KEV
catalog within `(T, T+180d]`. The observation time is the first catalog inclusion,
not the record's `dateAdded`.

**Label maturity.** `T + 210 days`. A block's labels are usable only when:

1. the calendar date has reached the maturity date; **and**
2. the served source timeline actually covers the maturity date.

Condition 2 matters. Waiting for 2026-10-28 without a new retrieval does not make
labels observable when the supplied KEV timeline ends 2026-10-15.

**Censored cutoff.** A cutoff whose maturity date is after the reference date. Its
event count is a **floor**, never a gate result.

## 4. Evidence classification (mandatory three-state rule)

| State | Meaning | Positive label? | Negative label? |
|---|---|---:|---:|
| `CONFIRMED_KEV_INCLUSION` | The CVE was observed in a readable catalog revision at the observation point. | yes | no |
| `ABSENT_FROM_KEV` | A readable catalog revision did not list the CVE. | no | **no** |
| `MISSING_HISTORICAL_EVIDENCE` | No readable catalog revision at the observation point. | no | **no** |

* **Absence is not proof of non-exploitation.** KEV is not exhaustive. A CVE missing
  from a catalog revision means only that this catalog did not list it then.
* **Missing is not absence.** An unavailable source or an unparseable revision leaves
  the question unanswered and must not be imputed.
* No negative exploitation label is constructed anywhere in this phase.
* The KEV timeline is replayed across all readable revisions, so membership is
  removal-aware. Four removals are observed; `CVE-2025-6264` is a genuine event at
  the cutoffs before its removal.

## 5. Admission rules

A design may be executed only when **all** of the following hold:

1. The protocol approval state is `APPROVED`, with a named approver, approval date,
   approval reference and `adopted_design`.
2. The adopted design has exactly three sequential blocks: training, validation, test.
3. Each block's labels matured before the next block's decision point.
4. Each block's label maturity is covered by the served source timeline.
5. Each block has at least 30 distinct events.
6. Blocks used as evidence do not share events. Reuse is reported separately from
   outcome-window overlap and is never counted as independent evidence.
7. No censored cutoff is used as a gate result.
8. No feature value, KEV membership fact or label postdates its decision point.
9. The readiness report contains no FAIL on a blocking check.

Technical feasibility does **not** imply admission. A two-block design may satisfy
rules 3–8 and still fail rule 2.

## 6. Candidate designs (none adopted)

| Design | Blocks | Cutoffs | Distinct events | Final maturity | Phase 2.3K verdict | Adopted? |
|---|---:|---|---|---|---|---|
| `A_180D_SPACED_3SEG` | 3 | 2025-02-01 / 2025-08-01 / 2026-02-01 | 55 / 46 / 60 | 2026-08-30 | `INFEASIBLE_LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK` | **no** |
| `A2_EARLIEST_3BLOCK` | 3 | **2025-02-01 / 2025-09-01 / 2026-04-01** | 55 / 52 / 47 (47 is a floor) | **2026-10-28** | `INFEASIBLE_BLOCK_NOT_MATURED` | **no** |
| `B_CONTIGUOUS_THIRDS` | 3 | contiguous thirds | 92 / 85 / 123 | 2026-09-27 | `INFEASIBLE_SHARED_EVENTS_AND_LABELS_NOT_MATURED_BEFORE_NEXT_BLOCK` | **no** |
| `E_LABEL_MATURED_2BLOCK` | 2 | 2025-02-01 / 2025-09-01 | 55 / 52 | 2026-03-30 | `FEASIBLE` (technical, two blocks) | **no** |
| `C_SINGLE_FINAL_CUTOFF` | 1 | 2026-03-01 | 60 | 2026-09-27 | `FEASIBLE` (single block) | **no** |
| `D_ROLLING_ORIGIN` | 14 × 1 | 2025-02-01 … 2026-03-01 | 33–61 per cutoff | varies | `FEASIBLE` per cutoff | **no** |

### 6.1 The decisive boundary

The 180-day-spaced design is disjoint in outcome windows but **29 and 26 days short**
of sequential label maturity. Disjointness is not the binding constraint; the
30-day maturation lag is.

The earliest three-block design the monthly grid can carry is:

```
2025-02-01  →  labels mature 2025-08-30
2025-09-01  →  labels mature 2026-03-30
2026-04-01  →  labels mature 2026-10-28
```

Its final block matures **13 days after the 2026-10-15 reference date**, and the
served KEV timeline ends 2026-10-15. At the 2026-10-15 reference date that block is
not matured and its labels are not observable from the supplied evidence.

Adopting this design is a **protocol amendment** requiring explicit project-owner
approval. Neither this document nor the readiness command adopts it. Nor does
calendar passage alone make it observable: a fresh retrieval through 2026-10-28 is
required.

### 6.2 The two-block design

`2025-02-01` (55 events, mature 2025-08-30) and `2025-09-01` (52 events, mature
2026-03-30) are label-matured, event-disjoint and above the gate. This is the
largest constructible historical design, but it has **no separate validation
block**. It is reported as `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` in readiness terms and
is **not** silently substituted.

## 7. Required readiness checks

The command `python -m vulnova.evaluation readiness` runs 44 checks in nine groups:

| Area | Check IDs |
|---|---|
| Dataset and artifact integrity | `INT-01` … `INT-08` |
| Source and retrieval provenance | `PRV-01` … `PRV-07` |
| Cutoff and maturity boundaries | `TMP-01` … `TMP-07` |
| Distinct-event gate | `EVT-01` … `EVT-07` |
| Point-in-time features | `LKG-01`, `LKG-02`, `LKG-05` |
| Future-information leakage | `LKG-03`, `LKG-04`, `LKG-06`, `EVT-04` |
| Evidence classification | `LKG-07`, `EVT-02`, `EVT-07` |
| Protocol validity and approval | `PRO-01` … `PRO-05` |
| Reproducibility and prohibitions | `REP-01` … `REP-03` |

A check is `PASS`, `FAIL`, `BLOCKED` (prerequisite evidence unavailable) or
`NOT_APPLICABLE`. Every blocked check carries a reason code in the report. Only
blocking checks influence the readiness status.

## 8. Approval procedure

An approval is valid only when **all** of the following are committed together:

1. `approval.state` becomes `APPROVED` in `protocol/evaluation_protocol.json`;
2. `approval.approved_by`, `approval.approved_on` and
   `approval.approval_reference` are populated;
3. `adopted_design` names exactly one registered candidate;
4. the commit message cites the written owner decision;
5. a readiness report generated against that commit shows the adopted design as
   protocol-admissible at the then-current `--as-of` date.

Until then the readiness status remains `BLOCKED_PROTOCOL_NOT_APPROVED`. The command
never writes to the protocol file.

The standing **NO-GO for confirmatory predictive evaluation is retained**. Approval
of a design would not, by itself, lift it, and this protocol authorises no model
training.

## 9. Evidence and limitations

* 21 monthly cutoffs, 2025-02-01 → 2026-10-01; 14 matured at 2026-10-15.
* Risk set 274,815 → 392,114; 6,723,857 eligible `(CVE, cutoff)` pairs.
* KEV replay: 325 readable revisions, 498 additions, 4 removals, 1 unparseable
  revision, 1,749 distinct CVEs ever listed.
* EPSS: 13 cutoffs are backfills, 8 are historically available, only 1 of those is
  matured. EPSS cannot support a matured multi-block historical design.
* CVSS: 31.08 % → 52.98 % coverage; missingness is reported, never filled.
* Phase 2.3F and 2.3G are `UNAVAILABLE`; their digests are historical claims.
* The cvelistV5 clone covers revisions from 2025-01-20 only.
* The 406 MB per-record census payloads are not shipped; recorded manifests are
  verified, not the payload bytes.
* Per-revision cvelistV5 retrieval timestamps are not recorded.
* Event rows are reused across overlapping cutoffs (3.45 rows per distinct event);
  reuse is not independence.

## 10. Change control

Changes to the horizon, lag, gate, block count or evidence semantics are protocol
amendments. They require the same written owner approval as design adoption, a
version bump, and a readiness run showing the new constants binding across code,
protocol and artifacts. A code change that silently alters a constant is a failure,
not a configuration.

---

**This protocol is `NOT_APPROVED`. No design is adopted. No model is trained. No
predictive claim is made.**
