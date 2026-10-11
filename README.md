# VULNOVA

VULNOVA is a reproducible workspace for inspecting and prioritizing records in
a historical CVE snapshot. Its baseline is a transparent **CVSS-descending
ranking only**. This repository does not implement an exploitation predictor,
a vulnerability scanner, or a live vulnerability feed.

## Project layout

```text
.
├── cve.csv.zip                         # Bundled source archive (already in repository)
├── data/
│   ├── raw/vulnerabilities.csv         # Local raw CSV; never rewritten by scripts
│   └── processed/                      # Reproducible outputs; generated locally
├── inspect_data.py                     # Full, untruncated descriptive profile
├── notebooks/01_inspect_data.ipynb     # Exploratory notebook
├── src/
│   ├── data.py                         # Shared loading and missingness helpers
│   ├── validate_data.py                # Read-only data-quality report
│   ├── preprocess_data.py              # Validates and creates clean CSV
│   └── baseline.py                     # CVSS-only ranking and JSON summary
├── tests/                              # Synthetic unit tests
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
python -m unittest discover -s tests -v
```

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

This is a prioritization heuristic, not a forecast of exploitation. The data
contains no exploitation outcome label, no `severity` column, and no EPSS score;
therefore no labels, predictions, precision/recall, or other predictive metrics
are fabricated. CVSS version/provenance is unspecified, and the snapshot is
historical. CVSS severity/impact scoring should not be interpreted as observed
exploitation, current risk, or a version-specific severity category.

## Reproduction

Run these commands from the repository root after setup:

```bash
# Review the full schema and descriptive statistics.
python inspect_data.py

# Generate read-only quality findings before cleaning.
python -m src.validate_data

# Create the clean dataset, then rank it by CVSS.
python -m src.preprocess_data
python -m src.baseline

# Run the synthetic validation, preprocessing, and ranking tests.
python -m unittest discover -s tests -v
```

The clean CSV, ranked CSV, and JSON summary are reproducible local outputs in
`data/processed/`; they are ignored by Git and the scripts create that directory
as needed. Tests use small synthetic fixtures and do not require copying or
modifying the full raw file.
