# Preservation handoff — VULNOVA prototype 1.2

Date: 2026-10-17 · Proves what was preserved, what is missing, and how to rebuild.

## 1. What was preserved

| Asset | Where | Count / size |
| --- | --- | --- |
| Application source | `vulnova/` | 12 modules, ~133 KB |
| Source adapters | `vulnova/sources/` | 4 adapters + `__init__` |
| Static interface | `vulnova/static/` | `index.html`, `style.css`, `app.js` |
| Tests | `tests/` | 8 files, 109 test cases |
| Verification tools | `tools/` | 6 tools incl. `ui_render_check.js` |
| Documentation | `README.md`, `RUNBOOK.md`, `REBUILD.md`, `PRESERVATION.md`, `docs/` | 6 files |
| Dependency declaration | `requirements.txt`, `pyproject.toml` | pytest 9.1.1; stdlib-only runtime |
| Data-source definitions | `data/snapshots/SOURCES.md` | revisions, URLs, sha256 |
| Source snapshots | `data/snapshots/{kev,epss}/` | 4.4 MB |
| cvelistV5 provenance | `data/snapshots/cvelistv5/MANIFEST.json` | revision + per-year tree digests, 558-file pre-2020 subset digest |
| Ingest receipt | `reports/ingest_receipts/2026-10-17_full.json` | per-stage reconciliation |
| 1.2 change record | `reports/improvement1_2/SOURCE_DIFF.txt` | unified diff vs the pre-rename tree |
| Verification evidence | `reports/improvement1_2/01…05`, `DIGEST_*.json` | pytest / product / render / verify_all / clean-room |
| Manifest | `reports/improvement1_2/MANIFEST.json` | sha256 of every file + store state |

**Deliberately excluded** by `.gitignore` and by the distribution allow-list:
`.venv/` (39 MB), `build/vulnova.db` (425 MB), `__pycache__/`, `.pytest_cache/`, the
2.6 GB cvelistV5 working tree.

## 2. What remains unavailable

| Item | Status | Why |
| --- | --- | --- |
| Validation 1.1 reports | **UNAVAILABLE** | Written, then lost with the sandbox workspace. Not recreated, not paraphrased as if original. |
| `RANKING_SEMANTICS_PROPOSAL.md` | **UNAVAILABLE** | Same loss. |
| Pre-rename source tree (`/tmp/baseline_1_1`) | **UNAVAILABLE** | Lived on `/tmp`; its diff survives in `SOURCE_DIFF.txt`, the tree itself does not. |
| `docs/` and `README.md` before 1.2 | **UNAVAILABLE** | No before-image, so no documentation diff can be produced. |
| Validation 1.1 test artefacts | **RECONSTRUCTED** | Figures were reported (91/60/27) but the log files are gone. |
| Earlier research phases (2.3F–2.3K.1) | **UNAVAILABLE in this workspace** | Their surviving artefact is `phase2.3k-export/` on the `arena/ee812e17-ai` branch, outside this directory. |
| Real browser screenshots | **BLOCKED** | No browser binary in the sandbox and no route to install one. `rendered_markup/` is DOM-shim output and is labelled as such. |

Nothing in this snapshot is described as "recovered". The application source is the
current working prototype — reconstructed once after the first workspace loss, then
modified only by the approved 1.2 rename.

## 3. How to reproduce

From a clean checkout: **`RUNBOOK.md`** (8 steps, ~6 minutes).
After a sandbox reset: **`REBUILD.md`**.
Verify: **`./verify_all.sh`**.

## 4. Evidence that the committed tree reproduces the published build

A clean room was created from the exact distribution tree — no virtualenv, no
`build/`, no database — and the database was rebuilt from the committed snapshots.

| Measure | Clean room | Published | |
| --- | --- | --- | --- |
| `pytest` | 109 passed | 109 passed | match |
| Ranking rows | 345,249 | 345,249 | match |
| `numeric_digest` | `7c6d3832ec174a1932a955978b0b28049eefb977c7220f942396d9019296ffbf` | same | **match** |
| `labelled_digest` | `e63bbe91f3c5a682cf36e6fab36942dd9b609c1d31a9e2149b01efc53ea40bd9` | same | **match** |
| Band counts | P1 1,020 · P2 1,744 · P3 130,541 · P4 194,652 · P5 17,292 | same | match |
| Score histogram | identical | identical | match |
| `verify_product.py` | 64 PASS / 0 FAIL | 64 PASS / 0 FAIL | match |
| `ui_render_check.js` | 30 PASS / 0 FAIL | 30 PASS / 0 FAIL | match |

Full transcript: `05_cleanroom_rebuild.txt`. Digest: `DIGEST_cleanroom.json`.

### Note on scope of the clean-room test

The clean room reused the already-fetched pinned cvelistV5 tree at
`/tmp/cvel2020_2023` (`c2a4235e…`). The **fetch** step was executed once earlier in
this session and is pinned by `data/snapshots/cvelistv5/MANIFEST.json`; the
**rebuild** step — ingest, ranking, verification — is what the clean room exercised
end to end.

Two files (`vulnova/ingest.py`, `tools/freeze_manifest.py`) were edited *after* the
clean-room database build to remove hard-coded `/home/user/Ai` defaults. The rebuild
passed explicit `--legacy`/`--research-repo` arguments, so the data result is
unaffected; the post-edit tree was re-verified in the clean room (109 / 64 / 30, all
passing) against that same database.

## 5. Ranking invariants — unchanged

```
weights    : KEV 40 · EPSS 30 · CVSS 20 · publication_recency 10 = 100
denominator: 100 (never rescaled)
bands      : P1 ≥ 70 · P2 ≥ 40 · P3 ≥ 20 · P4 ≥ 1 · P5 = 0
recency    : full credit ≤ 90 days, linear to 0 at ≥ 1,825 days
```

`tests/test_terminology.py` pins these with a golden score table; `tools/score_digest.py`
pins the full-store output.
