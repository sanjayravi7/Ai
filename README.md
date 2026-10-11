# VULNOVA

VULNOVA is a small, reproducible workspace for exploring a historical CVE
vulnerability dataset. The first milestone is a transparent inspection of the
bundled data—not a vulnerability scanner, live feed, or severity predictor.

## Project layout

```text
data/
├── raw/
│   └── vulnerabilities.csv  # Extracted source data; preserved as supplied
└── processed/               # Reserved for reproducible analysis outputs
notebooks/
└── 01_inspect_data.ipynb    # Initial data quality and distribution review
src/
├── __init__.py
└── data.py                  # Reusable loading and missingness helpers
README.md
requirements.txt
```

The repository also contains the original `cve.csv.zip` archive. The raw CSV
is extracted from that archive so it can be loaded directly by the notebook and
Python helpers.

## Quick start

Python 3.9 or newer is recommended.

```bash
python -m venv .venv
# Activate the environment, then install the dependencies:
python -m pip install -r requirements.txt
jupyter notebook notebooks/01_inspect_data.ipynb
```

The loader can also be used from Python:

```python
from src import load_vulnerabilities, summarize_missingness

vulnerabilities = load_vulnerabilities()
print(vulnerabilities.shape)
print(summarize_missingness(vulnerabilities))
```

`load_vulnerabilities()` reads `data/raw/vulnerabilities.csv` by default. It
normalizes the source's blank first-column header to `cve_id`, parses `mod_date`
and `pub_date` as dates, and converts `cvss` to a numeric column. These changes
are made in memory; the raw CSV is not modified.

## Dataset at a glance

The bundled snapshot contains **89,660 records** and **13 fields**. Publication
dates run from 1999 through November 21, 2019. The original CSV's first column
contains the CVE identifier but has no header; the loader names it `cve_id`.

| Field | Description |
| --- | --- |
| `cve_id` | CVE identifier (blank header in the source file) |
| `mod_date`, `pub_date` | Modification and publication timestamps |
| `cvss` | Numeric CVSS score as provided by the source; the score version is not specified in this file |
| `cwe_code`, `cwe_name` | CWE classification code and name |
| `summary` | Text description of the vulnerability |
| `access_authentication`, `access_complexity`, `access_vector` | Access characteristics from the source record |
| `impact_availability`, `impact_confidentiality`, `impact_integrity` | Impact characteristics from the source record |

The six access/impact fields are blank in 884 records. Treat missing values as
unknown rather than as evidence that a vulnerability has no such property.
The data is a historical snapshot, and its schema does not identify a CVSS
version; analyses should avoid applying version-specific severity thresholds
without further provenance.

## Next steps

Use `notebooks/01_inspect_data.ipynb` to review schema, missingness, score
coverage, publication-year counts, and common CWE labels before deciding on any
cleaning or modeling. Save intentionally generated tables or datasets under
`data/processed/` and document their inputs and transformations.
