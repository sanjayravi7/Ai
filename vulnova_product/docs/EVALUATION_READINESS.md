# Evaluation readiness and temporal data validation (VULNOVA 1.6)

This document describes the `readiness` command added in VULNOVA 1.6. It turns the
Phase 2.3K research export into a **machine-readable admission decision** for a
future temporal evaluation, and it refuses to admit one that the evidence cannot
support.

The command trains no model, scores no CVE, changes no source datum or ranking
weight, and cannot approve the evaluation protocol. Those prohibitions are
enforced by code, by the protocol document and by report checks.

## 1. What the command answers

Given eight questions, it returns a status and a reason for each:

1. Are the research artifacts the bytes they claim to be?
2. Which source revision produced each cutoff, and when was it retrieved?
3. Are label-maturity dates consistent with `T + 180 + 30` days?
4. Does every evaluated block contain at least 30 **distinct** events?
5. Was every feature available at the decision point, with no substitution?
6. Did any future information leak into a historical observation?
7. Is KEV inclusion, KEV absence and missing evidence still three distinct states?
8. Has the evaluation protocol been explicitly approved, with a design adopted?

A PASS on 1–7 is necessary but not sufficient. Rule 8 is deliberately human-only.

## 2. Running it

From the repository root:

```bash
cd vulnova_product
python -m vulnova.evaluation readiness --check-reproducible \
  --markdown reports/evaluation_readiness_1_6/readiness_report.md
```

The default inputs are the committed files, so no network access is required:

| Input | Default |
|---|---|
| Research artifacts | `../phase2.3k-export/` |
| Full export archive | `../phase2.3k-export/VULNOVA_Phase2.3K_export.tar.gz` |
| Core bundle archive | `../phase2.3k-export/VULNOVA_Phase2.3K_core_bundle.tar.gz` |
| Protocol | `protocol/evaluation_protocol.json` |
| Extraction cache | `build/evaluation_artifacts/` |
| As-of date | the protocol reference date (`2026-10-15`) |

Useful options:

| Option | Effect |
|---|---|
| `--as-of YYYY-MM-DD` | Evaluate maturity at another date. The Phase 2.3K verdict comparison still uses the protocol reference date, so a later date cannot turn a historical finding into a validation failure. |
| `--no-extract` | Never unpack archives; require an already extracted dataset or `--artifacts`. |
| `--no-deep` | Skip the 6.85 M-row membership scan. The report then contains BLOCKED checks, not silent passes. |
| `--check-reproducible` | Run twice from scratch and compare canonical digests. |
| `--previous-report PATH` | Record whether a prior report re-hashes to the same digest. |
| `--require-ready` | Exit 1 unless the status is `READY_FOR_PROTOCOL_EXECUTION`. |

The command exits 0 when the report was produced, including when readiness is
blocked. `--require-ready` is the admission gate for scripts. A reproducibility
failure exits 1, and an unreadable input exits 2.

## 3. Report statuses

Every one of the 44 checks carries exactly one status:

| Status | Meaning |
|---|---|
| `PASS` | The evidence was present and the check's invariant held. |
| `FAIL` | The evidence was present and the invariant was violated. A blocking FAIL makes the run `NOT_READY_VALIDATION_FAILED`. |
| `BLOCKED` | The evidence needed to decide was unavailable or unreadable. This is never converted into a pass or a failure. |
| `NOT_APPLICABLE` | The check's input was not supplied (for example, no previous report). |

Overall readiness uses one of:

| Status | Meaning |
|---|---|
| `READY_FOR_PROTOCOL_EXECUTION` | All blocking checks pass under an approved protocol with an adopted, admissible design. |
| `BLOCKED_PROTOCOL_NOT_APPROVED` | The protocol is a draft. No design may be executed. |
| `BLOCKED_NO_ADOPTED_DESIGN` | The protocol is approved but adopts no design. |
| `BLOCKED_EVIDENCE_UNAVAILABLE` | A blocking check could not be evaluated. |
| `BLOCKED_ADOPTED_DESIGN_INFEASIBLE` | The adopted design fails an admission rule (for example, only two blocks). |
| `NOT_READY_VALIDATION_FAILED` | At least one blocking check failed. |

`READY_FOR_PROTOCOL_EXECUTION` still does **not** authorise model training. The
report always records `model_training_authorized: false`,
`confirmatory_no_go: RETAINED` and
`approval_granted_by_this_command: false`.

### Protocol validation rules

`validate_protocol` rejects a protocol file, and `PRO-01` then fails, when:

| Code | Condition |
|---|---|
| `PROTOCOL_ID_MISMATCH`, `PROTOCOL_VERSION_MISMATCH` | Wrong protocol ID or version. |
| `APPROVAL_STATE_INVALID` | An approval state outside the documented vocabulary. |
| `PROTOCOL_CONSTANT_MISSING`, `PROTOCOL_CONSTANT_MISMATCH` | A frozen constant is missing or altered. |
| `PROTOCOL_BLOCK_COUNT_MISMATCH`, `EVENT_GATE_RELAXED` | The block requirement or event gate is weakened. |
| `APPROVAL_EVIDENCE_MISSING` | `APPROVED` without `approved_by`, `approved_on` or `approval_reference`. |
| `APPROVAL_DATE_INVALID` | `approved_on` is not a real calendar date written exactly `YYYY-MM-DD`. |
| `APPROVED_WITHOUT_ADOPTED_DESIGN` | `APPROVED` but no `adopted_design`. |
| `ADOPTED_DESIGN_NOT_REGISTERED` | `APPROVED` but `adopted_design` names no registered candidate. |
| `UNAPPROVED_DESIGN_ADOPTED`, `APPROVAL_EVIDENCE_INCONSISTENT` | Adoption or signatory evidence while the state is not `APPROVED`. |
| `DESIGN_KIND_UNKNOWN`, `DESIGN_WITHOUT_BLOCKS`, `DUPLICATE_DESIGN_ID` | A candidate design is malformed. **Every** candidate is checked, including the adopted one; selecting a design never exempts it from validation. |
| `EARLIEST_THREE_BLOCK_NOT_REGISTERED`, `EARLIEST_THREE_BLOCK_CUTOFFS_CHANGED` | The Phase 2.3K three-block reference design is missing or altered. |
| `PROHIBITION_MISSING`, `TRACEABILITY_MISSING`, `TRACEABILITY_EMPTY` | A required prohibition or requirement trace is absent. |

## 4. Frozen temporal contract

| Constant | Value | Consequence |
|---|---:|---|
| Forward horizon | 180 days | An event is a KEV inclusion in `(T, T+180d]`. |
| Label maturation lag | 30 days | Labels settle for 30 days after the horizon. |
| Maturity span | 210 days | Consecutive single-cutoff blocks must be at least 210 days apart. |
| Distinct-event gate | 30 | Minimum distinct test events in every *matured* block. Never relaxed. |
| Sequential blocks | 3 | Training, validation and test. A two-block design is reported but not admitted. |

Cutoffs are at `00:00:00Z`; only information observable at or before `T` may be
used. A censored cutoff's event count is a **floor**, never a gate result. The
earliest three-block grid the monthly cutoffs can carry is
`2025-02-01 / 2025-09-01 / 2026-04-01`; its final labels mature **2026-10-28**.
The supplied KEV timeline ends **2026-10-15**, so waiting for the calendar date
without a fresh retrieval is not enough.

## 5. Evidence classification

| State | Meaning | Positive label | Negative label |
|---|---|---:|---:|
| `CONFIRMED_KEV_INCLUSION` | The CVE was listed in a readable catalog revision at the observation point. | yes | no |
| `ABSENT_FROM_KEV` | A readable catalog revision did not list the CVE. | no | **no** |
| `MISSING_HISTORICAL_EVIDENCE` | No readable revision, or an unparseable/truncated revision, at the observation point. | no | **no** |

* KEV is not exhaustive; absence is not proof of non-exploitation.
* Missing evidence is not absence and is never imputed.
* Membership is replayed across readable revisions, so removals are handled. Four
  removals are observed; `CVE-2025-6264` remains a valid event at cutoffs before
  its removal.
* No negative exploitation label is constructed anywhere.

## 6. Check catalog

`INT-*` integrity, `PRV-*` provenance, `TMP-*` temporal, `EVT-*` event gate,
`LKG-*` point-in-time/leakage, `PRO-*` protocol, `REP-*` report/reproducibility.

| Check | What it verifies | Blocking |
|---|---|---|
| `INT-01_archive_digests` | Both archives match their published SHA-256 sidecars. | yes |
| `INT-02_core_bundle_manifest` | The core bundle matches its internal manifest where present. | no |
| `INT-03_full_export_integrity_manifest` | All 45 full-export files match their recorded sizes and digests. | yes |
| `INT-04_export_member_manifest` | All 75 archive members match `EXPORT_MANIFEST.json`. | yes |
| `INT-05_membership_partition_checksums` | All 21 partitions match `INDEX.csv` bytes and SHA-256. | yes |
| `INT-06_membership_row_accounting` | 6,852,808 partition rows reconcile to the denominator summary. | yes |
| `INT-07_inventory_census_consistency` | Inventory manifest, census index and summaries agree. | yes |
| `INT-08_denominator_reconciliation` | Every exclusion identity sums to the recorded totals. | yes |
| `PRV-01_source_revision_pins` | Every cutoff has a resolved cvelistV5 revision and tree hash. | yes |
| `PRV-02_cutoff_grid` | One consistent, non-duplicated monthly cutoff grid. | yes |
| `PRV-03_kev_revision_pins` | KEV replay uses readable, removal-aware catalog revisions. | yes |
| `PRV-04_epss_retrieval_provenance` | EPSS availability follows commit history, not filename dates. | yes |
| `PRV-05_reference_and_generation_times` | Reference, generation and observation times are coherent. | yes |
| `PRV-06_retrieval_timestamp_provenance` | Per-source fetch times are recorded where claimed. | no |
| `PRV-07_unavailable_sources_declared` | 2.3F/2.3G stay `UNAVAILABLE`, not reconstructed. | yes |
| `TMP-01_frozen_constants` | Horizon, lag and gate match the frozen values in all artifacts. | yes |
| `TMP-02_maturity_dates_recomputed` | Every recorded maturation date equals `T + 210`. | yes |
| `TMP-03_candidate_design_sequence` | Candidate verdicts recompute to the Phase 2.3K record. | yes |
| `TMP-04_earliest_three_block_design` | The earliest grid matures 2026-10-28 and is not adopted. | yes |
| `TMP-05_two_block_design_not_adopted` | The two-block design is insufficient, never silently adopted. | yes |
| `TMP-06_event_gate_not_relaxed` | The 30-event gate is unchanged everywhere it appears. | yes |
| `TMP-07_label_window_observability` | Source coverage reaches each matured block's maturity date. | yes |
| `EVT-01_distinct_event_gate` | Every matured cutoff clears 30 distinct events; censored values are floors. | yes |
| `EVT-02_event_row_uniqueness` | No duplicate event row within a cutoff; reuse is measured separately. | yes |
| `EVT-03_event_window_boundaries` | Every event is first observed in `(T, T+180d]`. | yes |
| `EVT-04_event_membership_at_cutoff` | Every event is eligible at risk at `T`, not already in KEV. | yes |
| `EVT-05_event_reuse_and_independence` | Pairwise block overlap recomputes to the recorded values. | yes |
| `EVT-06_censored_cutoffs_not_gated` | Censored cutoffs never supply a gate result. | yes |
| `EVT-07_kev_removal_awareness` | Removal-aware replay is preserved and observable. | yes |
| `LKG-01_cvss_point_in_time` | CVSS comes from an exact census at the pinned revision. | yes |
| `LKG-02_epss_point_in_time` | EPSS is used only with demonstrable historical availability. | yes |
| `LKG-03_publication_rule` | No risk-set record is published after `T`. | yes |
| `LKG-04_already_in_kev_exclusion` | Contemporaneous KEV membership is excluded at `T`. | yes |
| `LKG-05_missingness_preserved` | Missing values stay missing; no substitute is invented. | yes |
| `LKG-06_no_future_information` | No check observes a future value entering a historical row. | yes |
| `LKG-07_evidence_classification_preserved` | Inclusion, absence and missing evidence remain distinct. | yes |
| `PRO-01_protocol_document` | The protocol exists and is structurally valid. | yes |
| `PRO-02_approval_state_explicit` | Approval state is explicit and evidence-backed. | yes |
| `PRO-03_no_silent_design_adoption` | No candidate is adopted without approval. | yes |
| `PRO-04_protocol_binding_constants` | Protocol constants bind to the frozen values. | yes |
| `PRO-05_requirement_traceability` | Every requirement area maps to checks; prohibitions are complete. | yes |
| `REP-01_input_digests` | Every consumed input is identified by a SHA-256 digest. | yes |
| `REP-02_previous_report_digest` | A supplied previous report re-hashes to its recorded digest. | no |
| `REP-03_prohibitions_respected` | No training, no performance claim, no source/weight change. | yes |

## 7. Report schema

The JSON report (`readiness_report.json`) contains:

| Key | Contents |
|---|---|
| `schema_version`, `phase` | `vulnova.evaluation_readiness/1.6` and the release title. |
| `as_of`, `reference_date` | The evaluated date and the Phase 2.3K reference date. |
| `parameters` | The five frozen constants actually used. |
| `protocol` | Protocol ID, version, status, approval state, adopted design and constants. |
| `inputs` | Artifact mode, archive digests, extraction records, and SHA-256 fingerprints of every consumed input. Paths under the repository are relative. |
| `checks` | 44 objects, each with `id`, `title`, `status`, `blocking`, `reasons` and `evidence`. |
| `summary` | Counts per status plus blocking failures and non-blocking gaps. |
| `designs` | Every registered candidate with block-level maturity, gate, overlaps, verdict and reason codes. |
| `maturity` | Per-cutoff horizon end, maturity date, as-of status and source coverage. |
| `evidence_classification` | The three-state vocabulary, counts and interpretation. |
| `readiness` | Overall status, primary blocker, secondary blockers and prohibition flags. |
| `limitations` | Specific, computed limitations of this run. |
| `report_digest` | Canonical SHA-256 over the report excluding `report_digest` and `reproducibility`. |
| `reproducibility` | Canonicalization rule, second-run digest, optional previous-report digest. |

The digest is computed over JSON with sorted keys and compact separators. Runtime
bookkeeping (`extracted`, `reused_cache`, temporary destinations) is excluded, and
repository paths are relative, so the same committed inputs produce the same
digest from a different checkout location. `--check-reproducible` verifies this by
running the whole suite twice, including a cold extraction on the first run.

## 8. Tests

`vulnova_product/tests/test_evaluation_*.py` cover:

* maturity boundaries at `T+209`, `T+210`, `T+211` and the inclusive gate at 30/29;
* 180-day versus 210-day block spacing and the 13-day shortfall;
* calendar maturity without source coverage;
* confirmed inclusion, absence and missing/unreadable revisions;
* archive sidecar mismatch, manifest missing/mismatched files and path traversal;
* corrupted and missing membership partitions (BLOCKED, not a fabricated FAIL);
* duplicate event rows and event-level future-information leakage;
* protocol adoption without approval, approval without evidence and gate relaxation;
* report digest stability, canonicalization and CLI exit codes.

The suite uses a small synthetic Phase 2.3K-shaped fixture, so it runs without the
21 MB archive. One additional test re-runs the real committed archive and compares
its digest to the committed report; it is skipped only if the archive is absent.

## 9. Current result

The committed report was generated from the committed artifacts at the protocol
reference date. At the time of writing (2026-10-19) the earliest design's final
maturity date is 9 days away, but the more restrictive fact is that the supplied
KEV timeline ends 2026-10-15; the calendar passing 2026-10-28 would not make the
labels observable without a fresh retrieval. The result at the reference date is:

```text
checks: PASS 42 · FAIL 0 · BLOCKED 1 · NOT_APPLICABLE 1 (total 44)
READINESS: BLOCKED_PROTOCOL_NOT_APPROVED
primary blocker: PROTOCOL_NOT_APPROVED
report digest: 1d51544af41a8421522e566ffb051e2835b27d7cccc0bbd1cc42a25497322010
```

`--check-reproducible` recorded `double_run_match: true` for that digest. The
digest is reproduced by `tests/test_evaluation_repository_report.py`; it changes
whenever a check, a reason string, an input digest or the protocol changes.

The single BLOCKED check is `PRV-06_retrieval_timestamp_provenance`: revision
committer times and the artifact sealing time exist, but the fetch time of each
pinned cvelistV5 revision was not recorded. It does not invalidate the revision
pin; it limits retrieval-time provenance. The NOT_APPLICABLE check is `REP-02`
because no previous report was supplied.

This is not a favourable result and it is not presented as one. The protocol is a
draft, no design is adopted, the earliest three-block design matures after the
reference date, and the served KEV timeline does not cover that maturity date. The
standing confirmatory NO-GO is retained.
