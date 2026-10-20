# RUNBOOK — clean checkout to running console

Every step below is exercised in `reports/improvement1_2/05_cleanroom_rebuild.txt`.
Total time: ~6 minutes, of which ~4 are the cvelistV5 ingest.

## 0. Requirements

| Tool | Version used | Notes |
| --- | --- | --- |
| Python | 3.11.2 | 3.11+ required (`zipfile`, `tomllib` usage and type syntax) |
| Node.js | 22.22.3 | only for `tools/ui_render_check.js` |
| git, curl, gh | current | `gh` only for the pinned KEV/EPSS blob download |
| Disk | ~5 GB | 2.6 GB cvelistV5 checkout + 0.4 GB database |

Network egress needed: `github.com`, `codeload.github.com`, `api.github.com`.

## 1. Get the code

```bash
git clone https://github.com/sanjayravi7/Ai.git
cd Ai/vulnova_product
```

## 2. Create the virtualenv

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2b. Maturity gate (optional, offline)

The 1.8 maturity gate needs no data and no network — it reads the committed 1.7
manifest and the real UTC clock:

```bash
cd vulnova_product
.venv/bin/python -m vulnova.refresh gate
```

On or after 2026-10-28 the refresh command fetches fresh evidence into its own
store (`data/refresh_store_1_8/`) and never touches the 1.7 archive:

```bash
.venv/bin/python -m vulnova.refresh run
.venv/bin/python -m vulnova.refresh verify   # offline re-hash
```

## 2c. Prospective evidence capture (optional, network)

1.9 records evidence while the period is live. A capture uses the network and
always the real UTC clock; the store defaults to `~/.vulnova/prospective` and
should live outside the repository:

```bash
export VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence
.venv/bin/python -m vulnova.prospective capture
.venv/bin/python -m vulnova.prospective verify    # offline re-hash
.venv/bin/python -m vulnova.prospective report    # offline summary
```

Schedule it once per UTC day after ~13:00 UTC. Do not backfill a missed day, do
not edit or delete a run, and do not commit the store. `verify` inventories every
file under `artifacts/`, not only the files the run records mention; a green
`verify` means the store is fully accounted for, and an orphaned artifact is
reported rather than ignored. See `docs/PROSPECTIVE_CAPTURE_1_9.md`.

## 3. Fetch the pinned sources

```bash
mkdir -p data/snapshots/{kev,epss,cvelistv5}

# KEV — pinned blob for catalog 2026.10.16
gh api "repos/cisagov/kev-data/git/blobs/fd8de296db5877570e6d30a85e003665fc802cf2" \
  --jq .content | base64 -d \
  > data/snapshots/kev/known_exploited_vulnerabilities.json

# EPSS — pinned blob, score date 2026-10-16
gh api "repos/empiricalsec/epss_scores/git/blobs/1053f99ea37029dcd8e9229a988ebe17772f4519" \
  --jq .content | base64 -d \
  > data/snapshots/epss/epss_scores-2026-10-16.csv.gz
```

> The KEV and EPSS snapshots are also committed, so this step is only needed to
> re-verify the checksums in `data/snapshots/SOURCES.md`.

cvelistV5 is 2.6 GB and is **not** committed. Fetch the pinned window:

```bash
git clone --filter=blob:none --no-checkout --depth 1 \
  https://github.com/CVEProject/cvelistV5 /tmp/cvel2020_2023
cd /tmp/cvel2020_2023
git sparse-checkout init --no-cone
git sparse-checkout set '/cves/2020/' '/cves/2021/' '/cves/2022/' \
                      '/cves/2023/' '/cves/2024/' '/cves/2025/' '/cves/2026/'
git checkout
git rev-parse HEAD          # pin this for the next step
```

For the 2026-10-17 build this printed `c2a4235ef9fbfbe31bad0b8400366b04b461772f`.
A different commit is fine — it will yield slightly different counts; record it.

## 4. Pre-2020 KEV subset (558 identifiers)

```bash
cd /path/to/Ai/vulnova_product
.venv/bin/python tools/fetch_pre2020_kev.py \
  --repo /tmp/cvel2020_2023 \
  --kev data/snapshots/kev/known_exploited_vulnerabilities.json \
  --out /tmp/cvel_pre2020
```

## 5. Build the database

```bash
REV=$(git -C /tmp/cvel2020_2023 rev-parse HEAD)

.venv/bin/python -m vulnova.ingest --store build/vulnova.db \
  --legacy /path/to/Ai/cve.csv.zip \
  --cvelistv5-root /tmp/cvel2020_2023 \
  --cvelistv5-revision "$REV" \
  --cve-from 2020-01-01 \
  --pre2020-root /tmp/cvel_pre2020 \
  --kev data/snapshots/kev/known_exploited_vulnerabilities.json \
  --kev-revision 6a392940c663b52271fa4e6aa7b39995b18c9a71 \
  --epss data/snapshots/epss/epss_scores-2026-10-16.csv.gz \
  --receipt reports/ingest_receipts/rebuild.json

.venv/bin/python -c "from vulnova import store, web; \
  c = store.connect('build/vulnova.db'); print(web.build_ranking(c, force=True, verbose=True))"
```

Expected counts for the pinned sources (assert these, not just the exit code):

```
cve_record  348,670      cvss_observation 409,736     kev        1,748
epss        390,400      distinct CVEs    348,227     rejected   2,961
ranking     345,249      reference date   2026-10-16
```

## 6. Verify

```bash
./verify_all.sh
```

Expected: `719 passed` (pytest), `64 PASS / 0 FAIL` (product), `30 PASS / 0 FAIL`
(DOM-shim render check). Exit code 0.

## 7. Run the console

```bash
.venv/bin/python -m vulnova.web --db build/vulnova.db --host 127.0.0.1 --port 8000 --warm
```

Open <http://127.0.0.1:8000>. Bind to `0.0.0.0` only when a sandbox preview needs it.

## 8. Confirm the build matches what was published

```bash
.venv/bin/python tools/score_digest.py --db build/vulnova.db --json /tmp/after.json
diff <(jq -S . /tmp/after.json) \
     <(jq -S . reports/improvement1_2/DIGEST_after.json) && echo "MATCH"
```

`numeric_digest` must equal
`7c6d3832ec174a1932a955978b0b28049eefb977c7220f942396d9019296ffbf`.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `RuntimeError: CatalogTruncated` | A truncated KEV revision. Use the pinned blob, not a later commit. |
| `cve_record` count is zero | Wrong `--cvelistv5-root`; the path must contain `cves/<year>/`. |
| Server serves stale code | Python modules load at start; restart after edits. |
| `pytest: command not found` | The venv is not activated — use `.venv/bin/python -m pytest`. |
| Render check hangs | Server not listening yet; the script waits 20 s, then fails. |
| `STORE_OVERLAPS_PROTECTED` | The prospective store points at a sealed historical path. Choose a directory outside the repository. |
| `ATOMIC_CREATE_UNAVAILABLE` | The store's filesystem cannot create hard links (a network share, or a link-restricted mount). Capture refuses rather than write partial evidence. Move the store to a local filesystem; do not patch the code to write the final path directly. |
| `STORE_INVENTORY` / `UNREFERENCED_ARTIFACT` | An artifact exists with no readable run record — an interrupted capture, not corruption. Do not delete it. Restore the missing run record from a verified backup, or record an owner decision to quarantine the bytes outside the store. The store stays `BLOCKED` until then. |
| `ARTIFACT_TAMPERED` | A file's bytes no longer hash to its name. Preserve them for investigation and restore from a verified backup; never "repair" the file in place. |
| `Malformed runs` in `prospective report` | Run JSON that does not validate. It is counted as `BLOCKED` and excluded from the day grid. Inspect the named fields; do not hand-edit a run to make the report look better. |
| `EPSS_FILE_MISSING` | The daily EPSS file for that UTC date was not published (or not yet). A gap in observation, never a zero. |
| `CAPTURES_PRESENT` on `prospective verify` | The store has no captures yet; an empty store is `BLOCKED`, not verified. |
