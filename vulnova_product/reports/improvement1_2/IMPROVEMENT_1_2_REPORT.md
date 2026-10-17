# IMPROVEMENT 1.2 — Clarify the recency signal

**VULNOVA · narrow terminology change**
Date: 2026-10-17 · Reference date: 2026-10-16 · Store: `build/vulnova.db`
Status: **complete** — approved change only; no scoring change.

---

## 1. What was approved and what was done

Approved: rename the recency component to `publication_recency` wherever it is
presented to the user or documented, and state clearly that it is based on the CVE
publication date and does not represent recent exploitation activity, recent KEV
inclusion, or an independently verified increase in threat activity.

| Requirement | Status |
| --- | --- |
| Rename to `publication_recency` in presentation and docs | **Done** — API, detail view, list API, footer, docs |
| Explain it is based on the CVE publication date | **Done** — in the component detail, a dedicated payload block, and the UI |
| State what it does **not** represent | **Done** — explicit three-item list in API + UI + docs |
| Preserve weights 40 / 30 / 20 / 10 | **Verified identical** |
| Preserve fixed denominator 100 | **Verified identical** |
| Do not alter scores, thresholds, bands, source precedence | **Verified identical** (§4) |
| No retraining / no ML | None performed |
| No pre-2020 backfill | Not started |
| No research artifacts or repository changes | `/home/user/Ai` clean at `34750f6b…` |
| Preserve provenance and missing-data warnings | Untouched — `assessment.py`, `store.py`, `ingest.py`, `sources/*` byte-identical |

---

## 2. Environment note — the workspace was lost again

At the start of this turn the sandbox had been re-initialised (05:12 UTC) and contained
only `/home/user/Ai`. Everything from Validation 1.1 was gone: the application, the
store, the tests, the reports. `/tmp` was empty too.

This is the second occurrence. `build/` and `.venv/` are excluded from snapshots by
name, so the database was never going to persist; the loss was broader than that. See
`REBUILD.md` for the restore procedure.

**Consequence for this report:** to make the "scores unchanged" claim testable, the
Validation 1.1 code was reconstructed first, a byte-for-byte copy was taken at
`/tmp/baseline_1_1`, the ranking was built with it, a full digest was recorded, and only
then was the rename applied. The before/after comparison in §4 is therefore a genuine
measurement on one store with one dataset — not an assertion.

Two things did **not** survive and are stated plainly:

* `docs/` and `README.md` had no before-image; they are written directly in their 1.2
  state. Their 1.1 wording cannot be diffed.
* `reports/validation1_1/*` are absent from this workspace. They were not modified and
  are not reproduced here.

---

## 3. Exact changes

Eight files changed, one test file added, seventeen unchanged. The full unified diff is
`reports/improvement1_2/SOURCE_DIFF.txt`.

### 3.1 `vulnova/rank.py`

| Before | After |
| --- | --- |
| `WEIGHTS["recency"] = 10` | `WEIGHTS["publication_recency"] = 10` |
| `Signal(name="recency", …)` | `Signal(name="publication_recency", …)` |
| `recency_points()` | `publication_recency_points()` |
| `RECENCY_FULL_DAYS` / `RECENCY_ZERO_DAYS` | `PUBLICATION_RECENCY_FULL_DAYS` / `…_ZERO_DAYS` (values still 90 / 1825) |
| detail: `"Published {d}; publication age only (not exploitation recency)."` | detail: `"CVE published {d}; publication age only. This component does not represent recent exploitation activity, recent KEV inclusion, or an independently verified increase in threat activity."` |
| module docstring | adds an explicit three-item "does not represent" list |

**No expression changed.** The decay formula, the floor, the cap, the weights and the
band table are byte-identical in behaviour — see the numeric-literal proof in §4.

### 3.2 `vulnova/explain.py`

* `recency_context()` → `publication_recency_context()`
* payload key `recency_context` → `publication_recency_context`
* the block gains `"component": "publication_recency"` and a `"does_not_represent"`
  array (three items)
* the statement now opens by naming the component and its three exclusions, then reports
  the publication age, the KEV listing age, and — where applicable — the sentence that an
  old CVE with a recent KEV listing must not be described as having no recent activity.

### 3.3 `vulnova/web.py`

* ranking build: the component selector reads `"publication_recency"`
* list API: `recency_points` → `recency_points AS publication_recency_points`
  (presentation alias; **the database column keeps its name**, see §5)
* `/api/status`: `recency_definition` → `publication_recency_definition`, now carrying
  `component`, `basis`, `does_not_represent`, the two day thresholds and a note.

### 3.4 `vulnova/static/app.js`

* detail section heading `"Recency semantics"` → `"Publication recency (not exploitation recency)"`
* renders `publication_recency_context` (statement, publication date and age, KEV
  listing date and age, and the explicit "does NOT represent" line).

### 3.5 `vulnova/static/index.html`

* footer names the component as `<code>publication_recency</code>` and states the three
  exclusions inline.

### 3.6 Tests

| File | Change |
| --- | --- |
| `tests/test_rank.py` | renamed the component references; renamed the three boundary tests |
| `tests/test_explain.py` | payload-key rename; two new assertions (component name, `does_not_represent` contents) |
| `tests/test_web.py` | two new tests: `publication_recency_points` field present / `recency_points` absent; signal names |
| `tests/test_terminology.py` | **new** — 15 tests guarding the rename and the arithmetic |

`tests/test_terminology.py` includes the golden table: eight input cases whose score,
band and per-component points were produced by the *pre-rename* implementation and are
asserted unchanged.

### 3.7 Documentation

`docs/RANKING_SEMANTICS.md` (rewritten around `publication_recency`), `docs/ARCHITECTURE.md`
(naming table across layers), `README.md`.

---

## 4. Verification that numbers did not move

### 4.1 Full-store digest, before vs after

The ranking was rebuilt from scratch with the pre-rename code, digested, then rebuilt
from scratch with the renamed code and digested again.

| Measure | Before (1.1 code) | After (1.2 code) | Result |
| --- | --- | --- | --- |
| Ranking rows | 345,249 | 345,249 | **identical** |
| `numeric_digest` (all score-bearing columns) | `7c6d3832ec174a1932a955978b0b28049eefb977c7220f942396d9019296ffbf` | `7c6d3832ec174a1932a955978b0b28049eefb977c7220f942396d9019296ffbf` | **identical** |
| `labelled_digest` (adds `missing_signals`) | `e63bbe91f3c5a682cf36e6fab36942dd9b609c1d31a9e2149b01efc53ea40bd9` | `e63bbe91f3c5a682cf36e6fab36942dd9b609c1d31a9e2149b01efc53ea40bd9` | **identical** |
| Band counts | P1 1,020 · P2 1,744 · P3 130,541 · P4 194,652 · P5 17,292 | same | **identical** |
| Score histogram | full 0–100 distribution | same | **identical** |
| `missing_signals` values | `cvss_severity` 46,103 · `epss_probability` 327 | same | **identical** |

The `labelled_digest` is identical too because no ranked record currently lacks a
publication date, so no stored `missing_signals` value contained the old name. The path
is still covered by tests: a record with no publication date now reports
`publication_recency` instead of `recency` (golden case G-8), and that is the only
observable difference in that case.

### 4.2 Golden score table (asserted in `tests/test_terminology.py`)

| Case | Inputs | 1.1 score | 1.2 score | Points |
| --- | --- | ---: | ---: | --- |
| G-1 | KEV, EPSS 1.0, CVSS 10.0, published day-before | 100 | **100** | 40/30/20/10 |
| G-2 | KEV, EPSS 0.5, CVSS 9.8, 90 days | 85 | **85** | 40/15/20/10 |
| G-3 | KEV, EPSS 0.4, CVSS 7.5, ~4.7 years | 67 | **67** | 40/12/15/0 |
| G-4 | KEV, EPSS 0.99, CVSS 10.0, 2015 | 90 | **90** | 40/30/20/0 |
| G-5 | no KEV, no CVSS, no EPSS, day-before | 10 | **10** | 0/0/0/10 |
| G-6 | CVSS 7.5 only, ~2.8 years | 19 | **19** | 0/0/15/4 |
| G-7 | EPSS 0.9 only, ~1.7 years | 33 | **33** | 0/27/0/6 |
| G-8 | nothing available | 0 | **0** | 0/0/0/0 |

### 4.3 Static proof that no arithmetic changed

The set of numeric literals in `rank.py` is identical before and after:

```
before: [0, 1, 10, 20, 30, 40, 70, 90, 100, 1825]
after : [0, 1, 10, 20, 30, 40, 70, 90, 100, 1825]
```

Band thresholds are byte-identical:

```
BANDS = ((70, "P1_CRITICAL"), (40, "P2_HIGH"), (20, "P3_MODERATE"),
         (1, "P4_LOW"), (0, "P5_NONE"))
```

---

## 5. Known discrepancies (all deliberate, none silent)

| # | Discrepancy | Why |
| --- | --- | --- |
| 1 | The database column is still `ranking.recency_points` | Renaming a column needs a schema migration for no user-visible gain. The API never exposes the old name; `store.py` and `ARCHITECTURE.md` document the mapping. |
| 2 | `docs/` and `README.md` have no before-image | Lost with the workspace (§2). They are written in their 1.2 state. |
| 3 | Absolute store counts differ from the Validation 1.1 report | cvelistV5 moved from `c6e6286…` to `c2a4235…` between phases (+15 files in 2026). Records 348,655 → **348,670**; ranked 345,234 → **345,249**. This is upstream data drift, not a code change. |
| 4 | `reports/validation1_1/*` is absent | Lost with the workspace; not recreated and not modified. `RANKING_SEMANTICS_PROPOSAL.md` (which proposed this rename) is likewise absent, not rewritten. |
| 5 | Ranked distribution shifted slightly vs 1.1 (P3 130,541 vs 130,528) | Follows from discrepancy 3 — the extra 15 records. |

---

## 6. Test and verification results (actual)

```
.venv/bin/python -m pytest tests -q
109 passed in 9.09s                       (91 before this phase; +15 terminology, +3 other)

.venv/bin/python tools/verify_product.py --db build/vulnova.db
64 PASS, 0 FAIL, 0 SKIP                   (60 before; +5 terminology, −1 renamed)

node tools/ui_render_check.js --base http://127.0.0.1:8000
30 PASS, 0 FAIL                           (27 before; +3 terminology checks)
```

Evidence files: `01_pytest.txt`, `02_product_verification.txt`,
`03_ui_render_check.txt`. Rendered DOM-shim output: `rendered_markup/`
(**not screenshots**).

The UI checks now assert that the detail view:

* shows `publication_recency` in the score breakdown;
* carries the heading *"Publication recency (not exploitation recency)"*;
* states *"measures the CVE publication date only"*;
* prints *"publication_recency does NOT represent: recent exploitation activity; recent
  KEV inclusion; an independently verified increase in threat activity."*

---

## 7. Consistency check across surfaces

| Surface | Name used |
| --- | --- |
| Detail payload `priority.signals[].name` | `publication_recency` |
| Detail payload block | `publication_recency_context` (`component: "publication_recency"`) |
| `/api/status` weights | `publication_recency` |
| `/api/status` definition block | `publication_recency_definition` |
| `/api/ranking` row field | `publication_recency_points` |
| Detail view heading | "Publication recency (not exploitation recency)" |
| Footer | `<code>publication_recency</code>` with the three exclusions |
| `docs/RANKING_SEMANTICS.md`, `docs/ARCHITECTURE.md`, `README.md` | `publication_recency` |
| Database column (internal only) | `recency_points` — documented, never exposed |

Checked live: none of the presentation surfaces exposes a signal named bare `recency`,
and `/api/ranking` rows no longer contain a `recency_points` key.

---

## 8. What was not done

* No weight, threshold, band, denominator or source-precedence change.
* No ML model, training, tuning or predictive evaluation.
* No pre-2020 backfill.
* No research artifact or repository modification: `/home/user/Ai` at
  `34750f6bcb069863680e446ed53d23c33a21ae73`, working tree clean.
* No Git operation of any kind in this workspace.

---

## 9. Deliverables

| File | Contents |
| --- | --- |
| `reports/improvement1_2/IMPROVEMENT_1_2_REPORT.md` | this report |
| `reports/improvement1_2/SOURCE_DIFF.txt` | unified diff against the preserved 1.1 tree |
| `reports/improvement1_2/DIGEST_before.json` | full-store digest from the pre-rename build |
| `reports/improvement1_2/DIGEST_after.json` | full-store digest from the post-rename build |
| `reports/improvement1_2/MANIFEST.json` | sha256 of every product file + store state |
| `reports/improvement1_2/rendered_markup/` | DOM-shim output (**not screenshots**) |
| `tests/test_terminology.py` | rename guards + golden score table |
| `REBUILD.md` | how to restore this workspace after a sandbox reset |

Reproduce:

```bash
cd /home/user/vulnova_product && ./verify_all.sh
```
