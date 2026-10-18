# Data sources

Every ingest reads from a pinned snapshot. Nothing is fetched at query time and
nothing drifts silently: the ingest records the revision, retrieval timestamp and
content checksum of each source, and `/api/status` serves them back.

| Source | File / location | Revision | Content sha256 | Retrieved (UTC) |
| --- | --- | --- | --- | --- |
| CISA KEV catalog | `snapshots/kev/known_exploited_vulnerabilities.json` | commit `6a392940c663b52271fa4e6aa7b39995b18c9a71` · catalog `2026.10.16` · 1,748 entries | `b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d` | 2026-10-17T05:13Z |
| EPSS daily scores | `snapshots/epss/epss_scores-2026-10-16.csv.gz` | model `v2026.06.15` · score date `2026-10-16` · 390,400 rows | `0647405e86c84cc6dc9f0b7b3270589a52e9599d63c15ff53defa34b6f41894f` | 2026-10-17T05:13Z |
| cvelistV5 2020–2026 | **not committed** — fetched at rebuild time | commit `c2a4235ef9fbfbe31bad0b8400366b04b461772f` | per-year tree digests in `snapshots/cvelistv5/MANIFEST.json` | 2026-10-17T05:14Z |
| cvelistV5 pre-2020 KEV subset | **not committed** — fetched at rebuild time (558 files) | same commit as above | digest in `snapshots/cvelistv5/MANIFEST.json` | 2026-10-17T05:18Z |
| Legacy CVE extract | `/cve.csv.zip` in the repository root (7,326,681 B) | **no revision stated by the source** | see `reports/ingest_receipts/2026-10-17_full.json` | n/a |

## Why the 2.6 GB cvelistV5 tree is not committed

`cves/2020`–`cves/2026` is 263,543 JSON files. It is reproducible from a pinned
commit, so the repository stores only the manifest: source revision, per-directory
file counts and a SHA-256 tree digest over `(path, sha256)` pairs. A rebuild
fetches the same commit and re-verifies against that digest.

## Upstreams

| Source | URL |
| --- | --- |
| cvelistV5 | https://github.com/CVEProject/cvelistV5 |
| KEV | https://github.com/cisagov/kev-data (mirror of https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| EPSS | https://github.com/empiricalsec/epss_scores (FIRST EPSS) |

## Known limitations

* The legacy extract carries no state column and no stated revision; it is recorded
  with `revision: null` rather than an invented value.
* cvelistV5 is a live repository. A rebuild performed later will pick up a newer
  commit and produce slightly different counts. Record the commit actually used.
* KEV membership is not exhaustive; absence from the catalog is recorded as
  `NOT_LISTED_IN_CATALOG`, never as evidence of no exploitation.
