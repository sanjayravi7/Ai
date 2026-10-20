# VULNOVA 1.8 — the maturity gate and evidence refresh

1.6 asked whether a temporal evaluation was *possible*. 1.7 acquired the
historical evidence that question needs. 1.8 answers the next one honestly:

> The final candidate block matures on **2026-10-28**. On that day, may we
> actually see its labels?

The answer is **not** "yes, once the date passes". It is "only if a catalog
published on or after that date can be obtained". Those are different questions,
and 1.8 keeps them apart everywhere: in the report, in the checks, and in the
commands.

Nothing here approves the protocol, adopts a design, relaxes a gate or trains a
model. A green integrity result proves the bytes are intact; it never proves the
evaluation is viable.

## Commands

```bash
cd vulnova_product

python -m vulnova.refresh gate     # offline: has the block matured, and is it observable?
python -m vulnova.refresh run      # the only network-using command
python -m vulnova.refresh verify   # offline: re-hash the refresh and the sealed archive
```

`run` has **no** `--as-of` flag. Production acquisition always reads the real UTC
clock, and every `retrieved_at` in the report is the transport's actual receipt
time. Backdating is not a configuration option. Tests inject a fixed clock
through `RefreshOptions`, which is the same code path with a different clock.

Outputs:

| Path | What it is |
|---|---|
| `reports/refresh_1_8/refresh_report.json` | machine-readable refresh report, with `refresh_digest` |
| `reports/refresh_1_8/REFRESH_1_8_REPORT.md` | the readable summary |
| `data/refresh_store_1_8/kev/refresh/…` | the refreshed catalog bytes, kept separate from the 1.7 archive |

## The gate, in one table

| Cutoff | Horizon ends | Labels mature | Catalog must be released on or after |
|---|---|---|---|
| 2025-02-01 | 2025-07-31 | 2025-08-30 | 2025-08-30 |
| 2025-09-01 | 2026-02-28 | 2026-03-30 | 2026-03-30 |
| **2026-04-01** | 2026-09-28 | **2026-10-28** | **2026-10-28** |

The gate has four outcomes, and only the last one permits a filtered view:

| Status | Meaning |
|---|---|
| `NOT_MATURED` | The as-of date is before the maturity date. Nothing about an artifact can change this. |
| `MATURED_SOURCE_MISSING` | The date arrived, but no readable first-party catalog was acquired. |
| `MATURED_SOURCE_PREDATES` | The date arrived, but the catalog was published earlier. The observation is right-censored. |
| `MATURED_AND_OBSERVED` | The date arrived **and** the catalog was published on or after it. |

### Why a stale catalog is not "almost mature"

A KEV catalog released on 2026-10-16 cannot list an entry that CISA adds on
2026-10-27. Filtering it by `dateAdded <= 2026-10-28` would return a number that
*looks* like the matured label set and is in fact a lower bound frozen nine days
early. 1.8 refuses to do that: the filter is applied only under
`MATURED_AND_OBSERVED`, and otherwise the report says
`RIGHT_CENSORED_NOT_FILTERED` and the requirement is `BLOCKED`.

This is visible today. Running the gate on the committed 1.7 catalog at
successive dates gives:

```text
--as-of 2026-10-27  2026-04-01 -> NOT_MATURED              (1 day remaining)
--as-of 2026-10-28  2026-04-01 -> MATURED_SOURCE_PREDATES  (catalog is from 10-16)
--as-of 2026-11-05  2026-04-01 -> MATURED_SOURCE_PREDATES  (still the same catalog)
```

The date passing is necessary. It is not sufficient, and the third row is why:
the store still holds the October 16 catalog, so the answer stays "cannot
observe" until a fresh acquisition runs.

## Maturity is not evidence completeness

These are four independent facts, and 1.8 reports them separately:

| Fact | Where it appears |
|---|---|
| The calendar date has passed | `final_candidate.calendar_matured` |
| The catalog can observe the labels | `maturity_gate[*].catalog_observes_maturity`, `summary.maturity_claimed` |
| The exact historical EPSS files exist | `requirements[EPSS-R1_EXACT_DAILY_FILE]` |
| Those files were observed at the time | `requirements[EPSS-R2_HISTORICAL_PROVENANCE]` |

A run can be mature and observable and still report
`BLOCKED_EVIDENCE_INCOMPLETE`, because authentic bytes downloaded today for a
2025 cutoff are `LATE_RETRIEVAL`, not contemporaneous provenance. There is a
test that constructs exactly that case
(`test_every_byte_present_still_blocks_on_non_contemporaneous_provenance`).

**Consequence, stated plainly:** for the 2025–2026 candidate cutoffs,
contemporaneous provenance is permanently unattainable. A refresh run can
therefore never reach `EVIDENCE_COMPLETE_FOR_REASSESSMENT`; it will report
`BLOCKED_EVIDENCE_INCOMPLETE` and name `EPSS-R2_HISTORICAL_PROVENANCE` as the
unmet requirement. That status exists for completeness of the vocabulary, not as
a state this project can enter. If you see it, something is wrong.

## Reading the statuses

Two vocabularies meet here. Neither may be softened.

### Content axis — `VERIFIED` / `UNAVAILABLE` / `BLOCKED`

| Status | Means | Example in this run |
|---|---|---|
| `VERIFIED` | Inspected bytes support the claim. | The KEV catalog parsed, declared 1,748 entries, and 1,748 were present. |
| `UNAVAILABLE` | The publisher could not supply it. | `epss.cyentia.com` did not answer for any of the three dates. |
| `BLOCKED` | A precondition we control was not met. | The final block has not matured; no filtered label view is allowed. |

`UNAVAILABLE` is a fact about the publisher. `BLOCKED` is a fact about our
position relative to the evidence. They are never interchanged, and a policy
refusal (`REDIRECT_BLOCKED`) is always `BLOCKED`, never an outage.

### Access axis — `CONTEMPORANEOUS` / `LATE_RETRIEVAL` / `NOT_RETRIEVED`

A 2025 file fetched in 2026 is `LATE_RETRIEVAL`. It can satisfy a *content*
requirement and can never satisfy a *historical provenance* requirement.

### Refresh status

| Status | Meaning |
|---|---|
| `BLOCKED_MATURITY_NOT_REACHED` | The calendar gate is closed. |
| `BLOCKED_SOURCE_CANNOT_OBSERVE_MATURITY` | The date passed, but no catalog observes it. |
| `BLOCKED_EVIDENCE_INCOMPLETE` | Labels are observable, but refreshed evidence is not. |
| `EVIDENCE_COMPLETE_FOR_REASSESSMENT` | Every requirement is supported — **still not an approval**. |

## Write safety

Three destinations are written by `run`: the artifact store, the JSON report and
the Markdown summary. All three are checked **before the first network request
and before any directory is created**, by one function
(`vulnova.refresh.paths.assert_safe_write_targets`), so the CLI and any
programmatic caller are judged by the same rules.

Protected, in both directions:

| Protected path | Why |
|---|---|
| `data/acquisition_store/` | the sealed 1.7 artifact store |
| `reports/acquisition_1_7/` | the sealed 1.7 manifest and its report |
| `reports/evaluation_readiness_1_6/` | the committed 1.6 baseline |
| `data/snapshots/` | the original publisher snapshots |
| `phase2.3k-export/` | the sealed Phase 2.3K export |
| `--protocol`, `--baseline`, `--artifacts`, `--archive-manifest`, `--archive-store` | whatever this run actually reads as sealed input |

Consequences:

* `--report` and `--markdown` may not equal, sit inside, or contain any protected
  path. `--report reports/` is refused even though `reports/` is a directory,
  because it contains `reports/evaluation_readiness_1_6/`.
* `--store` may not overlap a protected path (this was the 1.8.0 check, unchanged).
* The report and the Markdown summary may not resolve to the same path, may not
  overlap each other, and may not live inside the refresh store.
* Paths are resolved with `Path.resolve`, so relative paths, `..` segments and
  existing symlinks are all judged by where they really point. A symlink aimed at
  the 1.6 report is the 1.6 report.

A refused run exits with status 2 and prints `error: OUTPUT_OVERLAPS_PROTECTED`
or `error: OUTPUT_PATHS_COLLIDE`. It opens no socket, creates no directory and
leaves every protected byte untouched — the tests assert all three.

The check runs again immediately before the files are written, so a destination
swapped for a symlink while the acquisition was in flight is still caught.

## What the refresh does to existing artifacts

Nothing. The refresh store is checked against the protected paths before a byte
is written, and overlap in either direction is refused
(`REFRESH_STORE_OVERLAPS_ARCHIVE`). The 1.7 manifest and all seven artifacts are
fingerprinted before and after the run; `PROV-R2_SEALED_ARCHIVE_UNCHANGED`
reports the comparison. The sealed Phase 2.3K export is only ever read.

The refresh also never rewrites the 1.6 readiness report. It builds a **new**
readiness report in memory at the run's as-of date and compares it against the
committed baseline. That is why the two digests differ even when nothing
changed: a readiness report embeds its own `as_of` date. Compare statuses, not
digests.

## The committed 1.8 run (2026-10-20)

| | |
|---|---|
| Refresh digest | `36803f26f02331e705c26e31a437fae04f0dc5705b837a11a849c3cd6ea174f4` |
| Refresh status | `BLOCKED_MATURITY_NOT_REACHED` |
| Evidence status | `BLOCKED` |
| Final block | matures 2026-10-28, **8 days remaining**, maturity not claimed |
| KEV catalog | `2026.10.16`, 1,748 entries, `b6e27975…`, via CISA's own repository |
| Direct CISA feed | `UNAVAILABLE` — `www.cisa.gov` did not answer |
| EPSS | all three exact daily files `UNAVAILABLE` — `epss.cyentia.com` did not answer |
| 1.6 comparison | 44 checks, **0 status changes**, same 42 PASS / 0 FAIL / 1 BLOCKED / 1 N/A |
| Designs | none admissible; unchanged from 1.6 |
| Protocol | `NOT_APPROVED`, unamended, execution not authorised |
| Sealed 1.7 archive | 7/7 artifacts and the manifest byte-identical |

The catalog bytes happen to be identical to the 1.7 current snapshot
(`b6e27975…`), because upstream has not published since 2026-10-16. That is a
fact about the source, not a copy: the run fetched and hashed them again.

## What to do on and after 2026-10-28

1. Run `python -m vulnova.refresh run` **on or after** that date.
2. Read `summary.maturity_claimed` first. If it is `false`, the gate did not
   open, and nothing downstream is worth reading yet — usually because the
   catalog that answered still predates 2026-10-28.
3. If it is `true`, read `date_added_filters["2026-04-01"]`. A `trustworthy:
   false` view means some entries carried no usable `dateAdded`; do not use it.
4. Read `readiness_comparison.questions`. In particular
   `any_candidate_design_admissible` — maturity does not make a two-block design
   into a three-block one, and `A2_EARLIEST_3BLOCK` must still clear every
   temporal and event rule.
5. Protocol approval remains a separate, human, written decision. No status in
   this report substitutes for it.

## Remaining gaps (explicit)

1. **EPSS.** The official historical daily files for 2025-02-01, 2025-09-01 and
   2026-04-01 have never been obtained. The publisher did not answer, and no
   mirror, newer file or backfilled value is substituted. This alone keeps the
   EPSS requirements `UNAVAILABLE`.
2. **Provenance.** Even if EPSS files were obtained today they would be
   `LATE_RETRIEVAL`. Historical retrieval provenance for these cutoffs is
   unattainable and stays `BLOCKED`.
3. **The direct CISA feed.** `www.cisa.gov` remains unreachable from this
   environment; KEV is verified through CISA's own GitHub repository instead, and
   the direct-feed requirement honestly stays `UNAVAILABLE`.
4. **Maturity.** The final block matures 2026-10-28. Fresh evidence is required
   after that date, and the stored 2026-10-16 catalog cannot substitute for it.
5. **Protocol.** `NOT_APPROVED`, with no adopted design. This release does not
   change that.

## Why the three-state rule still matters

`ABSENT_FROM_KEV` is not proof of non-exploitation, and
`MISSING_HISTORICAL_EVIDENCE` is never imputed as absence. The dateAdded view
introduced in 1.8 is a **derived lower bound over one catalog**, not an observed
point-in-time membership set, and it is labelled that way in the report
(`date_added_filters[*].note`). Any real label still comes from the 1.6 rule: an
event is a first catalog inclusion *observed* within `(T, T+180d]`.
