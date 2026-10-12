# VULNOVA

VULNOVA is a reproducible workspace for inspecting, enriching, and prioritizing
records in a historical CVE snapshot (1999 – 2019-11-21). Its baseline is a
transparent **CVSS-descending ranking only**. Phase 2 adds an auditable
threat-intelligence enrichment layer built from two official sources, CISA's
Known Exploited Vulnerabilities (KEV) catalog and FIRST's EPSS daily scores.
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
│   ├── external/raw/                   # Threat-intel snapshots + manifests (ignored by Git)
│   │   ├── kev/                        #   KEV JSON snapshot and manifest
│   │   └── epss/                       #   EPSS gzip snapshot and manifest
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
│   └── enrich_vulnerabilities.py       # Row-preserving join and coverage report
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
python -m unittest discover -s tests -v   # 64 synthetic tests; no network access needed
```

Phase 2 adds no new runtime dependencies. The fetch step uses only the Python
standard library for HTTPS; the rest uses pandas.

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
`** REJECT **` (withdrawn candidate entries) carry a CVSS value of 5.0 and remain
in the ranking as ordinary records. They are reported, not removed, because
changing the baseline requires separate approval. The data
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
records. 455 summaries carry a `** DISPUTED **` marker.

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
   17 rejected placeholders remain in the source and affect the CVSS baseline.

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
```

Note that step 5 uses the official endpoints by default. Cached snapshots
retrieved within 24 hours are reused; add `--refresh` to force a download.

The clean CSV, ranked CSV, and JSON summary are reproducible local outputs in
`data/processed/`. The enriched CSV and coverage JSON are written there too.
All of these are ignored by Git. Tests use small synthetic fixtures and do not
require copying or modifying the full raw file.
