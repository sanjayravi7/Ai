# VULNOVA

VULNOVA is a reproducible workspace for inspecting, enriching, and prioritizing
records in a historical CVE snapshot (1999 – 2019-11-21). Its baseline is a
transparent **CVSS-descending ranking only**. Phase 2 adds an auditable
threat-intelligence enrichment layer built from two official sources, CISA's
Known Exploited Vulnerabilities (KEV) catalog and FIRST's EPSS daily scores.
Phase 2.1 audits the 17 records whose summaries begin with `** REJECT **`,
verifies each one against the official CVE Program records, and applies an
explicit status-aware ranking policy: confirmed rejections leave the reviewed
ranking, while the original CVSS baseline is kept unchanged for comparison.
The repository still does **not** implement an exploitation predictor, a
vulnerability scanner, or a live vulnerability feed. The enrichment is a
point-in-time, descriptive join, and the ML-readiness assessment below
concludes that supervised learning is not yet defensible.

## Project layout

```text
.
├── cve.csv.zip                         # Bundled source archive (already in repository)
├── data/
│   ├── raw/vulnerabilities.csv         # Local raw CSV; never rewritten by scripts
│   ├── external/raw/                   # Source snapshots + manifests (ignored by Git)
│   │   ├── kev/                        #   KEV JSON snapshot and manifest
│   │   ├── epss/                       #   EPSS gzip snapshot and manifest
│   │   └── cve_status/                 #   cvelistV5 records + manifest (Phase 2.1)
│   └── processed/                      # Reproducible outputs; generated locally
├── inspect_data.py                     # Full, untruncated descriptive profile
├── notebooks/01_inspect_data.ipynb     # Exploratory notebook
├── src/
│   ├── data.py                         # Shared loading and missingness helpers
│   ├── validate_data.py                # Read-only data-quality report
│   ├── preprocess_data.py              # Validates and creates clean CSV
│   ├── baseline.py                     # CVSS-only ranking and JSON summary
│   ├── threat_intel_sources.py         # Pure KEV/EPSS parsers and schema validators
│   ├── fetch_threat_intelligence.py    # HTTPS download, cache, checksums, manifests
│   ├── enrich_vulnerabilities.py       # Row-preserving join and coverage report
│   ├── cve_status_sources.py           # Reject/dispute markers + CVE 5.x record parser
│   ├── fetch_cve_status.py             # Commit-pinned cvelistV5 status snapshots
│   └── audit_rejected_cves.py          # Rejected-record audit and reviewed ranking
├── tests/                              # Synthetic, mocked-network unit tests
├── requirements.txt
└── README.md
```

## Setup and tests

Python 3.9 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v   # 123 synthetic tests; no network access needed
```

Phase 2 adds no new runtime dependencies. The fetch step uses only the Python
standard library for HTTPS; the rest uses pandas. Phase 2.1 adds no new runtime
dependencies either: the status fetcher uses the standard library, and the audit
uses pandas.

The scripts use `data/raw/vulnerabilities.csv` by default. The extracted CSV
is ignored by Git; if it is absent in a fresh checkout, recreate the local copy
from the bundled archive (this writes only when you run the command):

```bash
python -c "from pathlib import Path; from zipfile import ZipFile; p=Path('data/raw/vulnerabilities.csv'); p.parent.mkdir(parents=True, exist_ok=True); p.exists() or p.write_bytes(ZipFile('cve.csv.zip').read('cve.csv'))"
```

Then run the scripts from the project root:

```bash
python inspect_data.py
python -m src.validate_data
python -m src.preprocess_data
python -m src.baseline
```

Optional input/output paths are available from each script's `--help`. The
validator's `--strict` option returns a non-zero exit status for malformed or
missing CVE IDs, duplicate IDs, date parse failures, non-numeric CVSS values, or
CVSS scores outside 0–10.
Expected missing access/impact attributes are reported but are not, on their
own, treated as a strict failure.

## Dataset schema and verified observations

The raw CSV has **89,660 rows and 13 columns**. Pandas reads its blank first
header as `Unnamed: 0`; that column contains the CVE identifiers. The columns
in source order are:

1. `Unnamed: 0` (renamed to `cve_id` in processed data)
2. `mod_date`
3. `pub_date`
4. `cvss`
5. `cwe_code`
6. `cwe_name`
7. `summary`
8. `access_authentication`
9. `access_complexity`
10. `access_vector`
11. `impact_availability`
12. `impact_confidentiality`
13. `impact_integrity`

The inspected snapshot has no malformed CVE identifier, duplicate CVE ID,
non-parsing date, non-numeric CVSS value, or CVSS value outside 0–10. The six
access/impact fields are blank for the same **884 records**. These values are
unknown, not zero, “none,” or evidence of no impact. The date range in the
snapshot extends from 1999 to November 21, 2019. The file has a `cvss` score,
but does not identify its CVSS version. It has no exploitation label, `severity`
column, or `epss_score` column.

The reusable loader in `src/data.py` renames the source identifier column to
`cve_id`, parses `mod_date` and `pub_date`, and converts `cvss` to numeric in
memory. `inspect_data.py` prints the full schema, dtypes, missingness, and
`describe(include="all")` results for every column without pandas' default
row/column truncation. Neither operation writes to the raw CSV.

## Provenance and licence

The only provenance that can be verified from this checkout is that the tracked
`cve.csv.zip` archive contains a member named `cve.csv`, and the extracted
`data/raw/vulnerabilities.csv` is byte-for-byte identical to that member
(SHA-256: `cad0f1e3c91b61d2eef4289c78045fd520cbea2c2cde0aba3338aa3a5aed5201`).
The archive does not establish an upstream URL, publisher, release/version, or
licence, and no such attribution or licence notice was found in the repository.
The archive member's 2020-03-26 timestamp is archive metadata, not proof of the
underlying data's publication or licence.

Accordingly, the upstream provenance and redistribution/use rights **cannot
be verified here**. This project does not grant a licence to the dataset.
Before redistributing the CSV/archive or using it in a product, identify and
review the upstream source's applicable terms, attribution requirements, and
any separate rights in the data and descriptions. Preserve any source licence
and notices once verified. Do not infer a licence from the CVE identifiers or
from the fact that the records concern public vulnerabilities.

## Validation and cleaning decisions

`python -m src.validate_data` is read-only. It reports:

- CVE ID format checks (`CVE-YYYY-NNNN...`), missing IDs, and duplicate IDs;
- per-column missing counts and percentages;
- non-empty date values that fail parsing;
- missing, non-numeric, and out-of-range CVSS values;
- inferred/source and validation-time dtypes; and
- the observed CWE code/name and CVSS score distributions.

The validator distinguishes blank/whitespace-only cells from parse failures and
does not clean or rewrite the source. Findings are reported rather than silently
corrected.

`python -m src.preprocess_data` reads the raw CSV and writes
`data/processed/vulnerabilities_clean.csv` with these decisions:

- Verify every value in the first source column against the CVE identifier
  pattern before renaming that column to `cve_id`. Invalid or missing IDs stop
  preprocessing with an error; records are not silently discarded.
- Parse `mod_date` and `pub_date` to datetimes and `cvss` to numeric values.
  Malformed non-empty values become missing in the processed copy and their
  counts/examples are reported. Rows are retained even when a date or score
  cannot be parsed.
- Treat empty and whitespace-only cells as missing. Keep the 884 records with
  missing access/impact values; do not impute values, change them to zero, or
  interpret them as “none.” Missing CSV cells are written as blanks.
- Preserve all input rows and other source columns. No duplicate removal,
  severity labels, exploitation labels, or new score fields are introduced.

The raw CSV is read-only to these scripts. It is listed in `.gitignore` so the
extracted local copy is not re-added by ordinary Git adds; the bundled archive
is a separate, already-tracked repository file.

## Baseline methodology and limitations

`python -m src.baseline` reads the clean CSV and ranks **all rows** by `cvss`
in descending order. Ties are broken by `cve_id` ascending and then original
input order. Missing scores, if present, are retained at the bottom; non-numeric
or out-of-range scores stop the ranking rather than being silently accepted.
The outputs are:

- `data/processed/vulnerabilities_ranked.csv` — source fields plus
  `baseline_rank`;
- `data/processed/baseline_summary.json` — machine-readable counts, score
  distribution, ranking rules, and limitations.

This is a prioritization heuristic, not a forecast of exploitation. The
Phase 2 coverage report notes that 17 records whose summaries begin with
`** REJECT **` (withdrawn candidate entries) carry a CVSS value of 5.0 and are
ranked by this baseline as if they were ordinary records. **This baseline is
deliberately left unchanged** so the effect of the correction can be measured;
Phase 2.1 (below) audits those records and excludes the confirmed rejections
from a separate, reviewed ranking that keeps the same ordering rules. The data
(the historical CSV) contains no exploitation outcome label, no `severity` column, and no EPSS score;
therefore no labels, predictions, precision/recall, or other predictive metrics
are fabricated. CVSS version/provenance is unspecified, and the snapshot is
historical. CVSS severity/impact scoring should not be interpreted as observed
exploitation, current risk, or a version-specific severity category.

## Threat-intelligence enrichment (Phase 2)

### Official sources and their roles

| Source | Official endpoint (default) | Role in VULNOVA | Granularity |
| --- | --- | --- | --- |
| CISA Known Exploited Vulnerabilities (KEV) catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Binary, positive-only evidence that a CVE was listed as known exploited on the catalog snapshot date. | One record per listed CVE, with `dateAdded`, `dueDate`, vendor/product, required action, and ransomware-use flag. |
| FIRST Exploit Prediction Scoring System (EPSS) | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (redirects to a dated file) | Model estimate of the probability of exploitation in the wild in the **next 30 days**, with a percentile. | One record per scored CVE: `cve`, `epss`, `percentile`, plus a `#model_version`/`score_date` header. |

Per the FIRST documentation, the daily CSV is the right tool for batch joins,
and the API is for lookups. The pipeline does not call the EPSS API.

### Snapshots and provenance in this checkout

| Source | Snapshot used here | How it was obtained | Verification |
| --- | --- | --- | --- |
| KEV | catalogVersion `2026.10.08`, `dateReleased` 2026-10-08T20:09:18Z, 1,739 entries, SHA-256 `fb1621be…dfee` | The build sandbox could not reach `cisa.gov` directly. The file was imported from CISA's own GitHub organisation mirror, `cisagov/kev-data`, pinned to commit `be330da6…7417` (`--kev-file`, `--kev-origin`). | catalogVersion, dateReleased, and count match the `cisa.gov` catalog metadata observed on 2026-10-12. Record count equals the declared count. |
| EPSS | model `v2026.06.15`, `score_date` 2026-10-11T12:00:25Z, 385,738 records, SHA-256 `34485d61…f344` | The build sandbox could not reach `epss.empiricalsecurity.com`. The file is the 2026-10-11 member of FIRST's documented archive, `github.com/empiricalsec/epss_scores`, pinned to commit `33b3261f…ce195`. Imported with `--epss-file` and `--epss-origin`. | Its header and the rows visible in the official `current` file on the same date (for example CVE-1999-0001 through CVE-1999-0005, CVE-1999-0016, and CVE-1999-0067) match exactly. Parsed with zero malformed IDs, duplicates, or missing values; scores in [0.00049, 0.99999]; percentiles in [0, 1]. |

Manifests record the URLs requested and final, the declared origin, the
retrieval method, the UTC retrieval time, the snapshot date, SHA-256, byte size,
version metadata, and validation counts. For `local_import` snapshots, the
retrieval time is the time the file was imported. It is not the time the file
was downloaded from the origin.

Snapshots live in `data/external/raw/<source>/` (ignored by Git). Each file is
named by source, snapshot date, and checksum prefix, so it is never
overwritten. A payload that fails validation is never written.

### Commands

```bash
# Official endpoints (requires access to cisa.gov and epss.empiricalsecurity.com):
python -m src.fetch_threat_intelligence --source all
python -m src.fetch_threat_intelligence --source kev --refresh       # force re-download

# Offline import of a locally obtained, already-verified copy:
python -m src.fetch_threat_intelligence --source kev  --kev-file  PATH --kev-origin  OFFICIAL_URL
python -m src.fetch_threat_intelligence --source epss --epss-file PATH --epss-origin OFFICIAL_URL

# Join the newest verified snapshots (or pin them with --kev-manifest / --epss-manifest):
python -m src.enrich_vulnerabilities
python -m src.enrich_vulnerabilities --allow-missing-sources   # leave an unavailable source blank
```

Network behaviour: HTTPS only, 60-second timeout, up to three retries with
exponential backoff for timeouts, connection errors, and HTTP 429/5xx. Other
HTTP errors fail immediately. Redirects that leave HTTPS are refused. Payloads
over 100 MB (KEV) or 200 MB (EPSS) are rejected. A fresh cached snapshot from
the same URL (under 24 hours old) is reused.

Validation (`src/threat_intel_sources.py`):

- **KEV:** required top-level and per-entry fields; declared `count` equals the
  number of entries; CVE identifiers match `CVE-YYYY-NNNN+` after normalisation;
  no duplicate identifiers; ISO dates parse; unexpected ransomware-use values are
  kept and reported.
- **EPSS:** the exact header `cve,epss,percentile`; `model_version` and
  `score_date` present in the `#` header; identifiers well-formed; no duplicates;
  `epss` and `percentile` numeric and within [0, 1]. Empty numeric cells are kept
  as counted missing values.

### Enrichment outputs

`python -m src.enrich_vulnerabilities` writes:

- `data/processed/vulnerabilities_enriched_current.csv`: the clean dataset with
  all original columns copied as text, followed by `ti_`-prefixed fields.
- `data/processed/threat_intel_coverage.json`: coverage, validation, source
  provenance, examples, and the descriptive analyses listed below.

| Field | Meaning |
| --- | --- |
| `ti_kev_listed` | `True` if the normalised CVE is in the KEV snapshot; `False` if the snapshot was checked and the CVE is absent; blank only if KEV was not ingested. |
| `ti_kev_date_added`, `ti_kev_due_date` | KEV `dateAdded` and `dueDate` (ISO dates). |
| `ti_kev_vendor_project`, `ti_kev_product`, `ti_kev_vulnerability_name`, `ti_kev_short_description`, `ti_kev_required_action` | Catalog text fields. |
| `ti_kev_known_ransomware_campaign_use` | `Known` or `Unknown`, as published. |
| `ti_kev_cwes` | Semicolon-separated CWE list from the catalog. |
| `ti_kev_snapshot_date` | Catalog snapshot date (`dateReleased`, UTC date). |
| `ti_epss_matched` | `True`/`False` against the EPSS snapshot; blank only if EPSS was not ingested. |
| `ti_epss_score`, `ti_epss_percentile` | EPSS probability and percentile, blank when unmatched. |
| `ti_epss_model_version`, `ti_epss_snapshot_date` | EPSS model version (from the file header) and score date. |

Historical fields are unchanged. The ranking baseline is unchanged and still
uses CVSS only.

Join method: the join key is the trimmed, upper-cased CVE identifier. Source
keys are unique (validated), so each dataset row matches at most one record per
source. The code asserts that the row count is unchanged and that the original
columns are unmodified. Unmatched rows keep blank `ti_` fields. They are **not**
negative labels.

### Verified coverage (snapshot run on 2026-10-12)

| Measure | Result |
| --- | --- |
| Original rows / unique CVE IDs preserved | 89,660 / 89,660 (0 dropped; 0 duplicate IDs) |
| CVEs in KEV (dataset rows) | **443 (0.494%)**, all unique |
| KEV catalog entries not in this dataset | 1,296 of 1,739 (74.5%); 1,181 have a 2020-or-later CVE year, and 115 have earlier years but are absent from this snapshot |
| KEV `ransomware-use` among matched | Known 92, Unknown 351 |
| Lag from CVE publication to KEV `dateAdded` (matched) | min 722 days, median 1,964, p90 4,105, max 6,507; 0 negative |
| CVEs matched to EPSS | **89,627 (99.963%)**; 33 unmatched |
| Unmatched to EPSS | 17 are `** REJECT **` placeholders; 16 are non-placeholder CVEs absent from the EPSS file |
| EPSS score among matched (all) | median 0.0166; p90 0.0916; p99 0.698; max 0.99999 |
| EPSS score, KEV-listed vs not | median 0.687 (n=443) vs 0.0165 (n=89,184) |
| KEV listing rate by CVSS band | 0.0–3.9: 0.06%; 4.0–6.9: 0.21%; 7.0–8.9: 0.81%; 9.0–10.0: 1.55% |
| Blank `ti_` cells | All KEV detail fields blank for 89,217 rows (99.5%); EPSS blank for 33 rows |

Examples (real matches, first five by CVE ID): CVE-2007-3010 (Alcatel OmniPCX
Enterprise, `dateAdded` 2022-04-15, ransomware "Unknown"), CVE-2007-5659 (Adobe
Acrobat and Reader, 2022-06-08), CVE-2008-0015 (Microsoft Windows, 2026-02-17),
CVE-2008-2992 (Adobe Acrobat and Reader, 2022-03-03, ransomware "Known"), and
CVE-2008-3431 (Oracle VirtualBox, 2022-03-03). The coverage JSON lists the
highest-EPSS examples as well.

Data-quality findings reported, not changed: 17 records begin with
`** REJECT **`; all have CVSS 5.0, so the existing baseline ranks them as normal
records (Phase 2.1 audits them and produces the reviewed ranking; this
enrichment still changes nothing). 455 summaries carry a `** DISPUTED **`
marker.

### KEV evidence is not EPSS probability

- **KEV** is a catalog decision by CISA that there is reliable evidence of
  exploitation. A KEV listing is positive evidence about the snapshot date. An
  absent CVE is **not listed in this snapshot**. It does not mean the CVE was
  never exploited, because the catalog is curated and incomplete.
- **`dateAdded`** is the catalog listing date. It is not the date exploitation
  began or was first observed. CISA's 2021-11-03 publication describes the initial catalog as
  retrospective listings (182 CVEs from 2017–2020 and 108 from 2021, per CISA).
  In the current catalog, 287 entries carry that `dateAdded`. In this dataset,
  73 of the 443 positives have it.
- **EPSS** is a statistical estimate of the probability of exploitation in the
  next 30 days, produced by a model at `score_date`. It is not a record of past
  exploitation, and its value changes as the model and data change. Its
  percentile is relative to the scored population on that day.

These are different kinds of evidence and should not be merged into one label
without a documented decision.

### Temporal alignment and leakage risks

1. **Time-window mismatch.** All dataset CVEs were published on or before
   2019-11-21. KEV `dateAdded` values are all on or after 2021-11-03. EPSS
   history begins on 2021-04-14, according to FIRST. The EPSS snapshot used here
   is dated 2026-10-11. Every current EPSS value and every KEV listing date
   postdates the 2019 publication window. They are not historical 2019-era
   values, and they must not be presented as such.
2. **Post-outcome features.** A feature built from a 2026 EPSS score or KEV
   status is post-outcome for any prediction made in 2019 or 2021. Using it
   to predict the same outcome is leakage.
3. **Circularity.** EPSS is itself a model of exploitation in the wild (its
   documented meaning is the probability of exploitation in the next 30 days).
   Its strong association with KEV status (median 0.687 vs 0.0165 here) is
   therefore not an independent check. A model that uses EPSS to predict KEV, or
   that predicts EPSS, is largely re-learning the same signal.
4. **Label censoring.** Labels from a 2026 snapshot are right-censored for any
   as-of date. The `dateAdded` window must be applied carefully. The catalog
   stores only the current listing date, so historical as-of labels also depend
   on the catalog having no removals.
5. **Snapshot and version drift.** EPSS changes model versions periodically;
   FIRST states that each version shifts scores on its start date. A time series
   that crosses a version boundary mixes a methodology change with a real change.
6. **Duplicate identifiers and rejected entries.** There are no duplicate IDs, but
   17 rejected placeholders remain in the source and sit in the CVSS baseline.
   Phase 2.1 excludes the confirmed rejections from the reviewed ranking and
   keeps the original baseline for comparison; it changes no feature or label.

### Selection bias and label uncertainty

- KEV is a **U.S. federal-oriented catalog**. Its scope and timing reflect
  federal remediation priorities, and it may over-represent products and vendors
  that CISA prioritises. The 1,296 catalog CVEs outside this dataset show that
  its coverage is much wider than the 2019 snapshot.
- The dataset itself was sampled by an unknown process. Publication years are
  uneven: the KEV listing rate varies from 0.0% (1999–2006) to 0.9% (2016)
  (`pub_year_listing_rates` in the coverage JSON).
- **Positive-only labels.** The only confirmed positives are 443 KEV listings.
  Everything else is unlabelled, so precision, recall, and AUC computed on it are
  bounds, not measures of true performance.
- **Descriptive diagnostic (not a model).** Ranking the 89,660 CVEs by the fixed
  CVSS baseline gives ROC-AUC 0.743 against the KEV label. The top 100 contain 0
  listed CVEs, the top 1,000 contain 3 (0.7% recall), and the top 10,000 contain
  155 (35.0% recall). The unlabelled rows hold 89,217 potential negatives, so
  these figures are descriptive only.

### ML readiness decision

**The available data does not yet support a defensible supervised exploitation
model.** Recommended next phase: **additional data collection, followed by a
ranking evaluation.** Not supervised ML yet.

Reasons:

1. **Label scarcity.** 443 positives out of 89,660 rows (0.49%).
2. **Time-aligned labels are tiny.** Using KEV `dateAdded` as the label and only
   the 2021-04-14 EPSS start date as the as-of date gives 0 positives for a
   30-day horizon, and 271 for 365 days. The 365-day figure includes the
   retrospective 2021-11-03 batch. The later as-of dates (2022-02-04, 2023-03-07,
   2025-03-17) give 81, 2, and 3 positives for 30 days (`temporal_label_feasibility`
   in the coverage JSON). These counts are too small for a stable model.
3. **Features are sparse.** The historical data has CVSS, a few access and impact
   fields, CWE, and a summary. The CVSS version is unknown. There is no vendor,
   product, patch, exploit, or time-of-disclosure feature.
4. **Negatives are unknown.** The absence of KEV is not a label.
5. **Leakage risk is high** unless every feature and label is restricted to its
   as-of date, which the current data cannot establish.

What the data does support now: the CVSS ranking can be evaluated against KEV
as a descriptive, positive-only benchmark, and ranking variants can be compared
on the same unlabelled background. This is a **ranking improvement study with
clear caveats**, not a predictive model.

### Minimum additional data before supervised ML

1. **Historical KEV as-of snapshots.** Reconstruct listing status at past dates from
   the `cisagov/kev-data` commit history (CISA-mirrored, CC0). This gives true
   as-of labels and handles removals, if any.
2. **Historical EPSS.** Use the FIRST-referenced archive (`empiricalsec/epss_scores`)
   from 2021-04-14 onward, with model version recorded for each date.
3. **Dated CVE and CVSS records.** Publication, modification, and CVSS-version
   metadata from the NVD or CVE program, to align features exactly with as-of dates.
4. **Independent exploitation evidence.** Such as public exploit repositories,
   vendor advisories, or threat reports, with stated collection dates and their
   own licences, so that KEV and EPSS are not the only label sources.
5. **Written label policy.** Define the target (for example, "KEV-listed within
   365 days of an as-of date"), the horizon, eligibility, and handling of
   unlabelled rows before any model is fitted.

### Recommended time-based split (for the later supervised phase)

- Features use only data available at the as-of date `T`.
- Label: KEV `dateAdded` in `(T, T + H]`, with `H` fixed in advance.
- Split by `T`, not randomly: train on earlier as-of dates, validate on a later
  block, and test on the most recent block. Keep a gap of at least `H` between
  blocks to prevent label overlap.
- Never use EPSS or KEV status recorded after `T` as a feature.
- Report results with positive-only caveats and with a random-ranking baseline.

## Withdrawn CVE records: audit and status-aware ranking (Phase 2.1)

The snapshot contains **17 records whose `summary` begins with `** REJECT **`**.
They are withdrawn candidate identifiers, not vulnerabilities: all 17 are
duplicate reservations, and the `cvss` value they carry — **5.0 for every one of
them** — is a placeholder, not a severity. Phase 2.1 verifies each record against
the official CVE Program record and applies an explicit, reversible policy to the
ranking. Nothing in the raw dataset, in `src/baseline.py`, or in the Phase 2
enrichment is modified.

### 1. Status verification

| Item | Value |
| --- | --- |
| Authoritative source | `CVEProject/cvelistV5` — CVE Program CVE Services 5.x records |
| Retrieval | GitHub contents API; every record URL is pinned with `?ref=<commit>` |
| Commit used | `5835abf86b2f3e8fb804a48125da370a92ccfc8b` (branch `main`, resolved 2026-10-12) |
| Verification date (UTC) | `2026-10-12T12:11:04Z` — recorded per row as `verification_date_utc` |
| Records found | 17 of 17 (manifest `missing_count` = 0) |
| Integrity check | Each decoded record's Git blob SHA is recomputed (`sha1("blob <len>\0" + bytes)`) and must equal the SHA the API reports for that path; a per-record SHA-256 is also stored |
| Local snapshot | `data/external/raw/cve_status/cve_status-2026-10-12-5835abf86b2f.manifest.json` (Git-ignored) |
| Per-record URL | `https://github.com/CVEProject/cvelistV5/blob/5835abf86b2f3e8fb804a48125da370a92ccfc8b/cves/<year>/<n>xxx/<CVE>.json` |

**Result: 17 rejected, 0 reinstated, 0 unclear, 0 unverified.** Every record is
`state = REJECTED` in the CVE Program record, and every rejection notice is a
duplicate notice that names a replacement identifier. No record had been
reinstated as of the verification date. If a later check finds
`state = PUBLISHED`, the policy keeps that identifier eligible (§3); anything
that cannot be read is labelled `UNVERIFIED` and disclosed — never guessed.

### 2. Audit table (all 17 records)

Columns: CVE ID, CVSS in the snapshot, publication date, modification date,
official `dateRejected`, duplicate-of identifier, official assigner, and position
in the unchanged CVSS baseline. `KEV` and `EPSS` are the Phase 2 snapshot matches
(`kev-2026-10-08` and EPSS `v2026.06.15` scored 2026-10-11): **none of the 17 is
KEV-listed or EPSS-matched.**

| CVE ID | CVSS | Published | Modified | dateRejected | Duplicate of | Assigner | Baseline rank |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `CVE-2007-3004` | 5.0 | 2007-06-04 17:30:00 | 2008-01-10 05:00:00 | 2007-07-19T09:00:00Z | CVE-2007-2788 | mitre | 48048 |
| `CVE-2007-4721` | 5.0 | 2007-09-05 19:17:00 | 2008-02-11 05:00:00 | 2007-11-28T10:00:00Z | CVE-2007-6113 | mitre | 48085 |
| `CVE-2007-5317` | 5.0 | 2007-10-09 21:17:00 | 2008-04-18 04:00:00 | 2008-04-18T09:00:00Z | CVE-2007-5292 | mitre | 48138 |
| `CVE-2007-6370` | 5.0 | 2007-12-15 01:46:00 | 2008-01-10 05:00:00 | 2007-12-19T10:00:00Z | CVE-2007-5583 | mitre | 48227 |
| `CVE-2007-6442` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6114 | redhat | 48236 |
| `CVE-2007-6443` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6115 | redhat | 48237 |
| `CVE-2007-6444` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6113 | redhat | 48238 |
| `CVE-2007-6446` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6118 | redhat | 48239 |
| `CVE-2007-6447` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6114 | redhat | 48240 |
| `CVE-2007-6448` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6120 | redhat | 48241 |
| `CVE-2007-6449` | 5.0 | 2007-12-19 22:46:00 | 2008-01-10 05:00:00 | 2022-10-03T00:00:00Z | CVE-2007-6121 | redhat | 48242 |
| `CVE-2007-6678` | 5.0 | 2008-01-10 01:46:00 | 2008-01-21 05:00:00 | 2008-01-19T10:00:00Z | CVE-2007-6167 | mitre | 48266 |
| `CVE-2008-1112` | 5.0 | 2008-03-03 18:44:00 | 2008-03-05 05:00:00 | 2022-10-03T00:00:00Z | CVE-2008-0928 | mitre | 48367 |
| `CVE-2008-1271` | 5.0 | 2008-03-10 21:44:00 | 2008-03-12 04:00:00 | 2022-10-03T00:00:00Z | CVE-2008-1218 | mitre | 48379 |
| `CVE-2008-1683` | 5.0 | 2008-04-06 23:44:00 | 2008-04-15 04:00:00 | 2008-04-15T09:00:00Z | CVE-2008-0887 | mitre | 48418 |
| `CVE-2008-2007` | 5.0 | 2008-05-22 13:09:00 | 2008-06-12 04:00:00 | 2008-06-06T09:00:00Z | CVE-2008-1035 | mitre | 48444 |
| `CVE-2017-9410` | 5.0 | 2017-07-27 06:29:00 | 2019-10-03 00:03:00 | 2019-09-04T16:01:54Z | CVE-2015-9101 | mitre | 55609 |

The full official rejection text, the parsed `Reason:` sentence, the replacement
identifiers, the per-record source URL, and the ranking decision for each record
are in `data/processed/rejected_cve_audit.csv` (17 rows × 34 columns).

Two observations from the audit. CVE-2007-6447's archived dataset summary still
ends with a `Patch = …` fragment, showing that the withdrawn text was truncated
rather than fully cleared. And nine of the 17 (the `redhat`-assigned Wireshark
duplicates) were only marked rejected in the CVE Program record on 2022-10-03,
years after this 2019 snapshot was produced — for those rows the dataset's
`** REJECT **` text and the official `dateRejected` disagree by more than a
decade, which is why the policy treats the official record, not the dataset text,
as the authority for the current status.

### 3. Ranking policy

| Status | How it is decided | In the primary ranking? | Score used |
| --- | --- | --- | --- |
| `REJECTED` | Summary begins with `** REJECT **` **and** the official state is `REJECTED` | No — excluded from the ranking, preserved in the audit table | none: a placeholder value is never a severity |
| `REINSTATED` | Marker present but the official state is `PUBLISHED` | Yes | The snapshot score, **unless** it equals a placeholder value derived from the confirmed rejections in this snapshot; then the record is ranked last with a missing score |
| `UNVERIFIED` | Marker present and no authoritative record could be read (missing, unreachable, malformed, or a non-final state such as `RESERVED`) | No — excluded by default and disclosed with identifiers and URLs. `--include-unverified` keeps them, at the bottom with a missing score | none |
| `UNMARKED` | No marker (89,643 records) | Yes | Unchanged: the snapshot score |
| `** DISPUTED **` | Marker anywhere in the summary (455 records) | Yes, unchanged | Unchanged: the snapshot score |

Rationale and guarantees:

- **The raw dataset is never altered.** The audit reads
  `data/processed/vulnerabilities_clean.csv` (itself generated from the raw CSV
  without dropping rows) and only ever writes to new output files; the raw CSV is
  read-only, is refused as an output path, and its SHA-256 is unchanged by a run.
- **A placeholder is not a score.** The excluded records' CVSS value is not
  treated as a genuine severity anywhere: it is flagged `cvss_genuine = False`
  and never enters the ranking arithmetic.
- **Placeholder values are derived, not assumed.** The placeholder set is
  computed from the CVSS values actually observed on confirmed-rejected records
  of the current snapshot (here `5.0`); no constant is hard-coded, and the
  derived set is reported as `placeholder_score_values`.
- **Ordering rules are preserved.** Eligible records keep the existing
  CVSS-descending order with deterministic tie-breaking (`cve_id` ascending, then
  input order) and missing scores last, because the reviewed ranking calls the
  same `rank_by_cvss` function as the baseline.
- **Exclusion is visible, not silent.** Excluded rows are listed in the audit
  table and in `rejected_cve_summary.json`; every output row carries
  `record_status`, `status_source`, `ranking_eligible`,
  `score_used_for_ranking`, `baseline_rank`, `reviewed_rank`, and `rank_shift`.
- **The baseline stays comparable.** `python -m src.baseline` is untouched and
  still ranks all 89,660 rows; `data/processed/vulnerabilities_ranked.csv` and
  `baseline_summary.json` remain. `python -m src.audit_rejected_cves` reports
  whether an existing baseline file matches its own recomputation
  (`baseline_file_matches_recomputed_baseline`).
- **Unverified is conservative by default.** An unverifiable record cannot be
  assigned a trustworthy score, so it does not compete in a prioritization
  ranking; it is preserved and must be resolved by a human. The opt-in
  `--include-unverified` ranks it last instead, and says so in the outputs.
- **Disputed records are untouched.** They stay eligible with their snapshot CVSS
  score and are additionally reported, one row each, in
  `data/processed/disputed_cve_report.csv` with an explicit `policy_note`.

### 4. Outputs (all regenerable and Git-ignored)

| File | Contents |
| --- | --- |
| `data/processed/rejected_cve_audit.csv` | The 17 marker records with status verification, rejection explanation, KEV/EPSS match, and ranking decision |
| `data/processed/vulnerabilities_ranked_reviewed.csv` | The primary active-vulnerability ranking: 89,643 eligible rows, original columns plus the policy columns |
| `data/processed/rejected_cve_summary.json` | Counts, policy text, provenance, per-record verification, marker audit, disputed reporting, and the baseline comparison |
| `data/processed/disputed_cve_report.csv` | The 455 `** DISPUTED **` records, reported separately with the unchanged-treatment note |

### 5. Effect on the ranking

| Measure | Result |
| --- | --- |
| Rows in / out | 89,660 records read; 89,643 ranked + 17 audited = 89,660 accounted for |
| Excluded | 17 confirmed rejections (0 unverified in this run) |
| Top 10 / 100 / 1,000 / 10,000 records | **Identical to the baseline** in all four bands, same order |
| Top-ranked record | `CVE-1999-0226` (CVSS 10.0) in both the baseline and the reviewed ranking |
| Rejected records' baseline positions | ranks 48,048 – 55,609 (inside the 11,765 rows that share the placeholder value 5.0) |
| First affected rank | 48,049 — every record above it is untouched (47,664 rows have CVSS > 5.0) |
| Rows shifted | 41,596, each by 1–17 positions, mean 7.77, always upwards |
| Rows shifted downward | 0 (the correction never demotes a genuine record) |

The honest reading is that this correction changes no prioritization decision in
the part of the ranking anyone acts on: the withdrawn records were never near the
top, because their placeholder 5.0 is below 47,664 genuine scores. What it does
change is that the mid-tier listing no longer contains 17 identifiers the CVE
Program tells users not to reference, and that the exclusion is explicit and
auditable rather than an unexamined side effect.

### 6. Limitations (Phase 2.1)

- The dataset's `cvss` version is unspecified, so an authoritative base score
  found on a `PUBLISHED` status record is **disclosed but never substituted**
  into the ranking; mixing CVSS versions would be an unmeasured change.
- Status verification is a point-in-time check of one commit of
  `CVEProject/cvelistV5` on 2026-10-12. CVE status can change afterwards; re-run
  the check and re-audit rather than assuming today's status.
- Records that appeared to be rejected but that the CVE Program no longer holds
  (or that return an unexpected state) are reported as `UNVERIFIED`; they are
  never silently dropped or silently ranked.
- Only the 17 marker records are status-checked. The other 89,643 rows are
  labelled `UNMARKED` with `status_source = not_checked`, which means "no reject
  marker in this snapshot", **not** "verified active".
- The same placeholder pattern is not searched for elsewhere: a withdrawn record
  whose summary was truncated before the marker (see CVE-2007-6447's trailing
  `Patch = …` fragment) cannot be detected from text alone. Cross-checking the
  full dataset against cvelistV5 states would be a larger, separate audit.
- Empty KEV/EPSS columns mean "not ingested", never "not listed"; `False` means
  the complete snapshot was checked. See the Phase 2 limitations above for the
  snapshot-drift and temporal-alignment caveats that still apply.
- The reviewed ranking is a prioritization ordering, not an exploitation
  prediction, and it inherits every baseline limitation above.

### 7. Reproducing the audit

```bash
# 1. Fetch the authoritative status records (needs access to api.github.com).
python -m src.fetch_cve_status --input data/processed/vulnerabilities_clean.csv

# 2. Audit the marker records and write the reviewed ranking.
python -m src.audit_rejected_cves

# 3. Offline reproduction from local copies of the CVE records (no network):
python -m src.fetch_cve_status --from-directory PATH_TO_CVE_JSON_DIR \
    --origin-url https://github.com/CVEProject/cvelistV5/blob/<commit> --commit-sha <commit>
python -m src.audit_rejected_cves --status-manifest data/external/raw/cve_status/<snapshot>.manifest.json

# 4. Degraded run with no status source at all: every marker record becomes
#    UNVERIFIED, is disclosed, and is excluded from the reviewed ranking.
python -m src.audit_rejected_cves --allow-missing-status-source --allow-missing-sources
```

Notes on the environment: the build sandbox could not reach
`raw.githubusercontent.com`, so the fetcher uses the GitHub contents API
(`api.github.com`, the same repository and commit-pinned paths) and verifies each
payload with the repository's own Git blob SHA as described above. The snapshot
keeps the verbatim record files, so the offline path reproduces the same audit.
Generated outputs are deterministic: byte-identical across re-runs of unchanged
inputs, and `rejected_cve_summary.json` embeds the outputs' SHA-256 values.

## Limitations (Phase 2)

- The reproducible enrichment in this checkout was built from the snapshots above.
  Running the fetch command in a network-connected environment will produce a
  new, current snapshot and therefore new numbers. This is expected.
- The KEV and EPSS files in this checkout came through verified mirrors, not
  direct downloads from the official hosts. The manifests record that. The
  checksums and content checks above are the evidence for their equivalence.
- The coverage analysis is descriptive. It contains no trained model and no
  claim of predictive accuracy.
- `ti_` fields describe 2026 threat intelligence applied to 2019 records. They
  are context, not historical facts.

## Attribution and licensing (threat intelligence)

- **CISA KEV.** The `cisagov/kev-data` repository describes its data as
  distributed under CC0 1.0 (`LICENSE` and README), and states that it matches
  CISA's own licence text. CISA's own page is the authority; check it before
  relying on this. Attribution is not a licence condition under CC0, but it is
  good practice to cite CISA as the source, to note the catalog version and
  snapshot date, and to state that third-party links within KEV carry their own
  terms.
- **FIRST EPSS.** The FIRST data page says EPSS scores are "published daily, free
  of charge, with no registration required," that they are maintained by the
  EPSS SIG at FIRST, and that they are generated by Empirical Security. No explicit
  redistribution licence was found on that page. The archive repository reports
  no licence through the GitHub API. Before redistributing EPSS data, confirm the
  terms with FIRST. Cite FIRST and Empirical Security, and record the model
  version and score date.
- **Dataset.** The licence status of the historical CVE CSV is unchanged from the
  section above and remains unverified.

## Reproduction

Run these commands from the repository root after setup. Steps 1–4 are the
original pipeline; steps 5–6 are the Phase 2 threat-intelligence enrichment.

```bash
# 1. Review the full schema and descriptive statistics.
python inspect_data.py

# 2. Generate read-only quality findings before cleaning.
python -m src.validate_data --strict

# 3. Create the clean dataset, then rank it by CVSS.
python -m src.preprocess_data
python -m src.baseline

# 4. Run the synthetic tests.
python -m unittest discover -s tests -v

# 5. Download and snapshot KEV and EPSS from their official URLs (needs internet access).
python -m src.fetch_threat_intelligence --source all

# 6. Join the newest verified snapshots to the clean dataset.
python -m src.enrich_vulnerabilities

# 7. Fetch the authoritative CVE status records for the '** REJECT **' entries
#    (needs access to api.github.com; --from-directory reproduces it offline).
python -m src.fetch_cve_status

# 8. Audit those records and write the reviewed status-aware ranking.
python -m src.audit_rejected_cves
```

Note that step 5 uses the official endpoints by default. Cached snapshots
retrieved within 24 hours are reused; add `--refresh` to force a download.

The clean CSV, ranked CSV, and JSON summaries are reproducible local outputs in
`data/processed/`. The enriched CSV and coverage JSON, and the Phase 2.1 audit
table, reviewed ranking, disputed report, and audit summary, are written there
too. All of these are ignored by Git. Tests use small synthetic fixtures and do
not require copying or modifying the full raw file, and the suite never needs
network access.
