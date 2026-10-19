# VULNOVA 1.6 — Evaluation Readiness

**Status:** `BLOCKED_PROTOCOL_NOT_APPROVED` · **As of:** `2026-10-15` · **Reference date:** `2026-10-15`
**Protocol approval:** `NOT_APPROVED` · **Adopted design:** `none` · **Model trained:** no · **Predictive claim:** none

This is technical readiness evidence. It does **not** approve the protocol, adopt a design, relax the event gate, or authorise training.

## Check summary

| Status | Count |
|---|---:|
| PASS | 42 |
| FAIL | 0 |
| BLOCKED | 1 |
| NOT_APPLICABLE | 1 |
| **Total** | **44** |

## Blockers

| Code | Primary | Detail |
|---|---|---|
| `PROTOCOL_NOT_APPROVED` | yes | approval_state=NOT_APPROVED; adoption requires the project owner's documented approval, which this command cannot grant. |
| `NO_ADOPTED_DESIGN` | no | No design is adopted. The two-block and three-block candidates remain candidates only. |
| `LABEL_MATURITY_NOT_REACHED` | no | the earliest three-block design's final labels mature 2026-10-28, 13 days after the as-of date 2026-10-15 |
| `LABEL_STABILITY_NOT_OBSERVABLE_IN_PROVIDED_SOURCE` | no | the served KEV timeline ends 2026-10-15, before the final maturity date 2026-10-28; a fresh retrieval is required even after the calendar date passes |
| `NON_BLOCKING_EVIDENCE_GAP` | no | CVELISTV5_RETRIEVAL_TIMESTAMP_NOT_RECORDED: revision committer timestamps and the artifact sealing time exist, but the fetch time of each pinned revision does not. This does not invalidate the revision pin; it limits re… |

## Frozen parameters

| Parameter | Value |
|---|---:|
| `horizon_days` | 180 |
| `maturity_lag_days` | 30 |
| `maturity_span_days` | 210 |
| `required_distinct_test_events` | 30 |
| `required_sequential_blocks` | 3 |

## Candidate designs

| Design | Kind | Blocks | Cutoffs | Events per block | Final maturity | Verdict | Protocol-admissible |
|---|---|---|---|---|---|---|---|
| `A_180D_SPACED_3SEG` | sequential | 3 | 2025-02-01; 2025-08-01; 2026-02-01 | 55 / 46 / 60 | 2026-08-30 | `INFEASIBLE` | no |
| `A2_EARLIEST_3BLOCK` | sequential | 3 | 2025-02-01; 2025-09-01; 2026-04-01 | 55 / 52 / 47 | 2026-10-28 | `INFEASIBLE` | no |
| `B_CONTIGUOUS_THIRDS` | sequential | 3 | 2025-02-01,2025-03-01,2025-04-01,2025-05-01; 2025-06-01,2025-07-01,2025-08-01,2025-09-01; 2025-10-01,2025-11-01,2025-12-01,2026-01-01,2026-02-01,2026-03-01 | 92 / 85 / 123 | 2026-09-27 | `INFEASIBLE` | no |
| `E_LABEL_MATURED_2BLOCK` | sequential | 2 | 2025-02-01; 2025-09-01 | 55 / 52 | 2026-03-30 | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | no |
| `C_SINGLE_FINAL_CUTOFF` | single_cutoff | 1 | 2026-03-01 | 60 | 2026-09-27 | `FEASIBLE_BUT_INSUFFICIENT_BLOCKS` | no |
| `D_ROLLING_ORIGIN` | rolling_origin | 14 | 2025-02-01; 2025-03-01; 2025-04-01; 2025-05-01; 2025-06-01; 2025-07-01; 2025-08-01; 2025-09-01; 2025-10-01; 2025-11-01; 2025-12-01; 2026-01-01; 2026-02-01; 2026-03-01 | 55 / 48 / 37 / 54 / 50 / 48 / 46 / 52 / 60 / 52 / 56 / 61 / 60 / 60 | 2026-09-27 | `INFEASIBLE` | no |

## Maturity calendar

| Cutoff | Horizon end | Label maturity | Matured at as-of | Source covers maturity |
|---|---|---|---|---|
| 2025-02-01 | 2025-07-31 | 2025-08-30 | yes | yes |
| 2025-03-01 | 2025-08-28 | 2025-09-27 | yes | yes |
| 2025-04-01 | 2025-09-28 | 2025-10-28 | yes | yes |
| 2025-05-01 | 2025-10-28 | 2025-11-27 | yes | yes |
| 2025-06-01 | 2025-11-28 | 2025-12-28 | yes | yes |
| 2025-07-01 | 2025-12-28 | 2026-01-27 | yes | yes |
| 2025-08-01 | 2026-01-28 | 2026-02-27 | yes | yes |
| 2025-09-01 | 2026-02-28 | 2026-03-30 | yes | yes |
| 2025-10-01 | 2026-03-30 | 2026-04-29 | yes | yes |
| 2025-11-01 | 2026-04-30 | 2026-05-30 | yes | yes |
| 2025-12-01 | 2026-05-30 | 2026-06-29 | yes | yes |
| 2026-01-01 | 2026-06-30 | 2026-07-30 | yes | yes |
| 2026-02-01 | 2026-07-31 | 2026-08-30 | yes | yes |
| 2026-03-01 | 2026-08-28 | 2026-09-27 | yes | yes |
| 2026-04-01 | 2026-09-28 | 2026-10-28 | no | no |
| 2026-05-01 | 2026-10-28 | 2026-11-27 | no | no |
| 2026-06-01 | 2026-11-28 | 2026-12-28 | no | no |
| 2026-07-01 | 2026-12-28 | 2027-01-27 | no | no |
| 2026-08-01 | 2027-01-28 | 2027-02-27 | no | no |
| 2026-09-01 | 2027-02-28 | 2027-03-30 | no | no |
| 2026-10-01 | 2027-03-30 | 2027-04-29 | no | no |

## Checks

| Check | Status | Blocking | Reason |
|---|---|---|---|
| `INT-01_archive_digests`<br>Research archive bytes match their published SHA-256 sidecars | `PASS` | yes | 2 archive(s) match their published SHA-256 sidecars. |
| `INT-02_core_bundle_manifest`<br>Core bundle matches its internal integrity manifest where present | `PASS` | no | The 22 absences are the bulk membership partitions plus the duplicate inventory_method.json that the core bundle documents as omitted. |
| `INT-03_full_export_integrity_manifest`<br>Full export matches its internal integrity manifest | `PASS` | yes | All 45 manifest entries are present with matching SHA-256 and size. |
| `INT-04_export_member_manifest`<br>Every archive member matches EXPORT_MANIFEST.json | `PASS` | yes |  |
| `INT-05_membership_partition_checksums`<br>Membership partitions match INDEX.csv sizes and SHA-256 | `PASS` | yes | All 21 partitions match INDEX.csv (byte size and SHA-256). |
| `INT-06_membership_row_accounting`<br>Membership partitions reconcile exactly to the denominator summary | `PASS` | yes | 6,852,808 rows across 21 partitions reconcile: every reason count, size and identifier membership agrees with the summary. |
| `INT-07_inventory_census_consistency`<br>Inventory manifest and census index agree with each other and the summaries | `PASS` | yes | 21/21 censuses report complete enumeration, zero duplicates and zero parse errors; counts agree with the inventory manifest and denominators. The staged census payloads themselves are not available for re-hashing. |
| `INT-08_denominator_reconciliation`<br>Risk-set denominators satisfy every recorded exclusion identity | `PASS` | yes | 21 cutoffs reconcile exactly; risk set 274,815 → 392,114, 6,723,857 eligible (CVE, cutoff) pairs. |
| `PRV-01_source_revision_pins`<br>Every cutoff carries a resolved cvelistV5 revision pin and tree hash | `PASS` | yes | 21/21 revisions resolve under the frozen rule; every committer timestamp is before its cutoff, and every pin carries a cves tree hash and partition digest. |
| `PRV-02_cutoff_grid`<br>All artifacts describe one consistent, non-duplicated cutoff grid | `PASS` | yes | 21 monthly cutoffs from 2025-02-01 to 2026-10-01; every artifact agrees and no cutoff is repeated. |
| `PRV-03_kev_revision_pins`<br>KEV membership is pinned to readable, removal-aware catalog revisions | `PASS` | yes | 21/21 cutoffs pin a KEV revision (max staleness 10 days). Replaying 325 revisions reproduces 498 additions and 4 removals with 1 unparseable revision(s) recorded. |
| `PRV-04_epss_retrieval_provenance`<br>EPSS availability is decided by commit history, not by filename date | `PASS` | yes | 13 cutoff(s) are backfills whose file was committed after the cutoff and are excluded; 8 cutoff(s) are historically available. Only 1 available cutoff is also matured. |
| `PRV-05_reference_and_generation_times`<br>Reference, generation and source-observation times are coherent | `PASS` | yes | The artifact sealing time, protocol reference date and KEV observation timeline are consistent. |
| `PRV-06_retrieval_timestamp_provenance`<br>Per-source retrieval timestamps are recorded where the artifacts claim them | `BLOCKED` | no | CVELISTV5_RETRIEVAL_TIMESTAMP_NOT_RECORDED: revision committer timestamps and the artifact sealing time exist, but the fetch time of each pinned revision does not. This does not invalidate the revision pin; it limits re… |
| `PRV-07_unavailable_sources_declared`<br>Unavailable sources remain declared as unavailable, not reconstructed | `PASS` | yes | The unavailable Phase 2.3F/2.3G sources are carried as historical claims only; nothing was reconstructed from a filename or digest. |
| `TMP-01_frozen_constants`<br>Horizon, maturation lag and event gate are the frozen values | `PASS` | yes | 180-day horizon, 30-day lag, 210-day span and 30-event gate agree across code, protocol and Phase 2.3K artifacts. |
| `TMP-02_maturity_dates_recomputed`<br>Every recorded maturation date is recomputed from T + 180 + 30 | `PASS` | yes | 21/21 maturity dates recompute exactly; 14 are matured at the 2026-10-15 reference date and 14 at the 2026-10-15 as-of date. |
| `TMP-03_candidate_design_sequence`<br>Each protocol candidate design recomputes to the Phase 2.3K verdict | `PASS` | yes | All 6 registered candidate designs recompute consistently (A_180D_SPACED_3SEG: INFEASIBLE; A2_EARLIEST_3BLOCK: INFEASIBLE; B_CONTIGUOUS_THIRDS: INFEASIBLE; E_LABEL_MATURED_2BLOCK: FEASIBLE_BUT_INSUFFICIENT_BLOCKS; C_SIN… |
| `TMP-04_earliest_three_block_design`<br>The earliest three-block design matures 2026-10-28 and is not adopted | `PASS` | yes | The earliest three-block design is 2025-02-01 / 2025-09-01 / 2026-04-01. Its final labels mature 2026-10-28, 13 days after the reference date 2026-10-15, and the served KEV timeline ends 2026-10-15. It remains a candida… |
| `TMP-05_two_block_design_not_adopted`<br>The two-block design is reported as insufficient, never adopted silently | `PASS` | yes | The two-block design (2025-02-01 [55 events] / 2025-09-01 [52 events]) is FEASIBLE_BUT_INSUFFICIENT_BLOCKS; two blocks are insufficient for the three-block protocol. No substitution is made. |
| `TMP-06_event_gate_not_relaxed`<br>The 30-distinct-event gate is unchanged everywhere it appears | `PASS` | yes | No artifact, protocol field or computed block lowers the gate below 30. |
| `TMP-07_label_window_observability`<br>Matured blocks are covered by the served KEV timeline | `PASS` | yes | 14/14 matured cutoffs have their full 210-day label window inside the served timeline (ends 2026-10-15). |
| `EVT-01_distinct_event_gate`<br>Every matured cutoff clears 30 distinct events; censored cutoffs are floors | `PASS` | yes | 14/14 matured cutoffs clear the gate (minimum 37); the 7 censored cutoffs are reported as floors, never as gate results. |
| `EVT-02_event_row_uniqueness`<br>Event rows are unique per cutoff; cross-cutoff reuse is measured separately | `PASS` | yes | 952 event rows contain no duplicate (cutoff, CVE) pair. Cross-cutoff reuse is real and reported separately: 739 matured rows cover 214 distinct events (3.45 rows/event). Reuse is not counted as independent evidence. |
| `EVT-03_event_window_boundaries`<br>Every event is first observed strictly after T and within 180 days | `PASS` | yes | All 952 event rows fall in (T, T+180d]; no event precedes its cutoff and none exceeds the horizon. |
| `EVT-04_event_membership_at_cutoff`<br>Every event was eligible at risk at its cutoff, not already in KEV | `PASS` | yes | All 952 event rows are present in their cutoff's partition with reason ELIGIBLE_AT_RISK; none was already in KEV at T. |
| `EVT-05_event_reuse_and_independence`<br>Event reuse is measured, and claimed overlaps recompute exactly | `PASS` | yes | The naive contiguous split shares 42/44/15 events between block pairs, exactly as recorded. The two-block and three-block disjoint candidates share none. Event reuse is never counted as independent evidence. |
| `EVT-06_censored_cutoffs_not_gated`<br>Censored cutoffs are floors and never used as gate results | `PASS` | yes | All 7 censored cutoffs are labelled floors; no design uses one as a gate pass. |
| `EVT-07_kev_removal_awareness`<br>Outcomes preserve removal-aware KEV replay, including CVE-2025-6264 | `PASS` | yes | Replaying 325 revisions yields 498 additions and 4 removals, not 2.3J's 493/0. CVE-2025-6264 is an eligible event at 4 cutoffs despite its removal. |
| `LKG-01_cvss_point_in_time`<br>CVSS availability is an exact census of the pinned revision at T | `PASS` | yes | 21/21 cutoffs read CVSS from the exact census of the pinned revision. Coverage runs from 31.08% to 52.98%; the missing remainder is reported, not filled. |
| `LKG-02_epss_point_in_time`<br>EPSS is used only where historical availability is demonstrable | `PASS` | yes | 13 cutoff(s) are rejected as backfills and 8 are historically available. 1 of those is/are matured, so EPSS cannot support a matured multi-block historical design. |
| `LKG-03_publication_rule`<br>No risk-set record is published after its cutoff | `PASS` | yes | Zero violations: no risk-set member was published after its cutoff. |
| `LKG-04_already_in_kev_exclusion`<br>Contemporaneous KEV membership is excluded at T, never reconstructed | `PASS` | yes | 21/21 cutoffs exclude exactly the contemporaneously observed KEV entries. A dateAdded-based reconstruction would wrongly include CVEs that were later removed. |
| `LKG-05_missingness_preserved`<br>Missing feature values stay missing; no substitute is invented | `PASS` | yes | CVSS-present and CVSS-absent counts partition every risk set; EPSS gaps are left blank. No imputation or interpolation is present. |
| `LKG-06_no_future_information`<br>No check finds a future value entering a historical observation | `PASS` | yes | Zero violations across all five leakage classes. |
| `LKG-07_evidence_classification_preserved`<br>KEV inclusion, absence and missing evidence remain three distinct states | `PASS` | yes | The three states are distinct and immutable in this report. 263 confirmed inclusion events are used; 6,723,857 absence observations are not treated as non-exploitation. |
| `PRO-01_protocol_document`<br>The evaluation protocol is present and structurally valid | `PASS` | yes | The protocol file is complete, self-consistent and internally bound to the frozen constants. |
| `PRO-02_approval_state_explicit`<br>Protocol approval state is explicit and evidence-backed | `PASS` | yes | Approval state is NOT_APPROVED; no signatory or adoption evidence is present, and this command cannot create any. |
| `PRO-03_no_silent_design_adoption`<br>No candidate design is silently adopted | `PASS` | yes | adopted_design is null. All 6 registered designs remain candidates, including the two-block and the three-block designs. |
| `PRO-04_protocol_binding_constants`<br>Protocol constants bind exactly to the frozen evaluation values | `PASS` | yes | All five frozen constants and both top-level gate values bind exactly to the protocol contract. |
| `PRO-05_requirement_traceability`<br>Every requirement area maps to report checks, and prohibitions are complete | `PASS` | yes | All 9 requirement areas map to report checks, and all 8 required prohibitions are declared. |
| `REP-01_input_digests`<br>Every consumed input is identified by a SHA-256 digest | `PASS` | yes | 18 consumed files plus 2 archive(s) are pinned by SHA-256. |
| `REP-02_previous_report_digest`<br>A supplied previous report re-hashes to its recorded digest | `NOT_APPLICABLE` | no | No previous report was supplied. |
| `REP-03_prohibitions_respected`<br>No model was trained, no performance was claimed, no source or weight changed | `PASS` | yes | The Phase 2.3K prohibitions are preserved. This command only reads evidence and writes its own report; it does not train, score or reweight. |

## Evidence classification

| State | Count | Interpretation |
|---|---:|---|
| `CONFIRMED_KEV_INCLUSION` | 952 event rows / 263 distinct | Observed in a readable catalog revision. |
| `ABSENT_FROM_KEV` | 6723857 risk-set observations | Not proof of non-exploitation; never a negative label. |
| `MISSING_HISTORICAL_EVIDENCE` | 13 EPSS cutoffs + unavailable sources | Unknown, never imputed as absence. |

## Limitations

- The evaluation protocol remains NOT_APPROVED. This report is technical readiness evidence, not approval and not an evaluation.
- The earliest three-block design (2025-02-01 / 2025-09-01 / 2026-04-01) has its final labels mature on 2026-10-28. Adopting it is a protocol amendment requiring the project owner's written approval.
- The served KEV timeline ends 2026-10-15, before the earliest design's final maturity date 2026-10-28. Even when the calendar date passes, a fresh retrieval through the maturity date is required before the final block's labels are observable in evidence.
- No model was trained, tuned, scored or evaluated. No predictive performance is claimed, and no ranking weight or source datum was changed.
- Phase 2.3F and Phase 2.3G source directories are UNAVAILABLE in this environment; their digests remain historical claims.
- EPSS has no demonstrable point-in-time availability at 13 cutoff(s) (2025-02-01 to 2026-02-01); those score files are backfills and are not treated as historical. 8 cutoff(s) have demonstrable historical availability.
- The cvelistV5 working clone carries revisions from 2025-01-20 onward only; no cutoff before the first cloned revision is offered.
- CVSS coverage is 31.08% to 52.98% across the cutoff grid; missing values are reported, never imputed.
- 1 KEV catalog revision is truncated upstream and recorded as unparseable rather than repaired.
- KEV is not exhaustive. Absence from the catalog is never proof that a vulnerability was not exploited, and no negative exploitation label is built from it.
- The staged per-record census payloads are not shipped; their recorded hashes and counts are verified, but the payload bytes cannot be re-hashed here.
- Per-revision retrieval timestamps are not recorded where the artifacts only carry source commit times and the artifact sealing time.
- Event rows are reused across overlapping cutoffs (739 matured rows cover 214 distinct events, 3.45 rows/event); reuse is not independent evidence.
- Labels are first-observed KEV catalog inclusions within the forward window, not a complete record of exploitation or of all exploitation activity.
- The two-block design (2025-02-01 / 2025-09-01) is constructible but lacks a separate validation block; it is not a protocol-compliant substitute.
- 4 KEV removals are replayed; membership is removal-aware, so a removed CVE is still a valid event at cutoffs before its removal.
- The as-of date for this run is 2026-10-15; maturity status can change with the calendar, while evidence coverage changes only with a new retrieval.

## Reproduce

```bash
cd vulnova_product
python -m vulnova.evaluation readiness \
  --artifacts ../phase2.3k-export \
  --out reports/evaluation_readiness_1_6/readiness_report.json
```

Report digest: `1d51544af41a8421522e566ffb051e2835b27d7cccc0bbd1cc42a25497322010`
