# Restoring this workspace after a sandbox reset

The sandbox is re-initialised between some turns. Only `/home/user/Ai` (the Git
repository) reliably survives; `build/` and `.venv/` are excluded from snapshots by
name, and in practice the whole product directory has been lost twice.

Everything below is reproducible from public sources plus `cve.csv.zip`, which ships in
the repository. Total restore time: roughly 10 minutes, including two network fetches.

## 0. Prerequisites

`git`, `python3` (3.11), `node` (22), `curl`, `gh`. Egress to `github.com`,
`codeload.github.com` and `api.github.com` is required; nothing else is contacted.

## 1. Sources

```bash
cd /home/user
mkdir -p vulnova_product/data/snapshots/{kev,epss,cvelistv5}

# KEV — pinned revision 6a392940c663b52271fa4e6aa7b39995b18c9a71 (2026-10-16)
gh api "repos/cisagov/kev-data/git/blobs/fd8de296db5877570e6d30a85e003665fc802cf2" \
  --jq .content | base64 -d \
  > vulnova_product/data/snapshots/kev/known_exploited_vulnerabilities.json

# EPSS — pinned blob 1053f99ea37029dcd8e9229a988ebe17772f4519 (score date 2026-10-16)
gh api "repos/empiricalsec/epss_scores/git/blobs/1053f99ea37029dcd8e9229a988ebe17772f4519" \
  --jq .content | base64 -d \
  > vulnova_product/data/snapshots/epss/epss_scores-2026-10-16.csv.gz

# cvelistV5 — bounded sparse checkout, NOT the full archive
git clone --filter=blob:none --no-checkout --depth 1 \
  https://github.com/CVEProject/cvelistV5 /tmp/cvel2020_2023
cd /tmp/cvel2020_2023
git sparse-checkout init --no-cone
git sparse-checkout set '/cves/2020/' '/cves/2021/' '/cves/2022/' '/cves/2023/' \
                      '/cves/2024/' '/cves/2025/' '/cves/2026/'
git checkout
git rev-parse HEAD    # pin whatever this prints for the ingest step
```

## 2. Code

The application source is in this directory (`vulnova/`, `tests/`, `tools/`, `docs/`).
If the directory itself is gone, it must be restored from the phase report or a copy;
the manifests in `reports/*/MANIFEST.json` record the sha256 of every file so a restore
can be verified.

```bash
cd /home/user/vulnova_product
python3 -m venv .venv
.venv/bin/pip -q install pytest
```

## 3. Pre-2020 KEV subset (558 identifiers, not the historical archive)

```bash
.venv/bin/python tools/fetch_pre2020_kev.py \
  --repo /tmp/cvel2020_2023 \
  --kev data/snapshots/kev/known_exploited_vulnerabilities.json \
  --out /tmp/cvel_pre2020
```

## 4. Ingest and rank

```bash
.venv/bin/python tools/make_source_manifest.py

.venv/bin/python -m vulnova.ingest --store build/vulnova.db \
  --legacy /home/user/Ai/cve.csv.zip \
  --cvelistv5-root /tmp/cvel2020_2023 \
  --cvelistv5-revision "$(git -C /tmp/cvel2020_2023 rev-parse HEAD)" \
  --cve-from 2020-01-01 --pre2020-root /tmp/cvel_pre2020 \
  --kev data/snapshots/kev/known_exploited_vulnerabilities.json \
  --kev-revision 6a392940c663b52271fa4e6aa7b39995b18c9a71 \
  --epss data/snapshots/epss/epss_scores-2026-10-16.csv.gz \
  --receipt reports/ingest_receipts/restore.json

.venv/bin/python -c "from vulnova import store, web; \
  c = store.connect('build/vulnova.db'); print(web.build_ranking(c, force=True, verbose=True))"
```

## 5. Verify

```bash
./verify_all.sh
```

Expected on the 2026-10-17 data: **109 pytest**, **64 product checks**,
**30 render checks**, all passing.

## 6. Serve

```bash
.venv/bin/python -m vulnova.web --db build/vulnova.db --host 0.0.0.0 --port 8000 --warm
```

## Notes on drift

`cvelistV5` is a live repository, so a later restore will pick up a newer revision and
produce slightly larger counts. Record the revision printed by `git rev-parse HEAD`
alongside any comparison. The 2026-10-17 build used
`c2a4235ef9fbfbe31bad0b8400366b04b461772f` (348,670 CVE rows, 345,249 ranked).
