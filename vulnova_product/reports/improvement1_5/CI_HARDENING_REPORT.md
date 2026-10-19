# IMPROVEMENT 1.5 — CI hardening

**VULNOVA · CI ownership, scoping and failure investigation**
Date: 2026-10-19 · Python 3.11.2 · pytest 9.1.1
Status: **complete** — CI and documentation only; no scoring, ranking or source change.

---

## 1. Scope

| Requirement | Result |
| --- | --- |
| Inspect existing workflows and separate VULNOVA from root-project tests | Done — see §2 |
| Reliable VULNOVA CI on Python 3.11 | Added `vulnova-unit-tests.yml`; retained the 3.11 browser workflow |
| Run VULNOVA unit tests | **122 passed** (§3) |
| Run the Chromium smoke test | **14 checks passed** with a local Chromium 153 binary (§3.2) |
| Scope triggers | VULNOVA workflows watch `vulnova_product/**`; root workflow ignores it (§4) |
| Investigate existing failures | Root cause found and fixed; invalid Django workflow removed (§5) |
| Do not require `build/vulnova.db` | No CI job builds or reads the database (§6) |
| Document commands and expected checks | `docs/CI.md`, README and BROWSER_TESTING updated |
| Do not alter weights, scoring logic or source data | None touched — changes are workflow/docs/report files only |

## 2. Workflow inventory

| Workflow (before) | Owner | What it actually ran | State before |
| --- | --- | --- | --- |
| `python-package.yml` | Root data pipeline | `pytest` from repo root, which collected both root and VULNOVA tests | Failing (exit 2) on 3.9/3.10/3.11 |
| `django.yml` | None | `python manage.py test` | Failing at Python 3.7 setup |
| `vulnova-browser.yml` | VULNOVA | `tools/ui_browser_check.py` | Passing on `main` (run 39285900265) |

The root `tests/` suite (192 tests + 6 subtests) exercises `src/` (Phase 2 CVE
data pipeline). It is not a VULNOVA test. `vulnova_product/tests` (122 tests)
exercises `vulnova/` and must run only on Python 3.11, which is the project's
declared minimum.

## 3. Tests run in this workspace

### 3.1 VULNOVA unit tests

```bash
cd vulnova_product
python -m pip install -r requirements.txt
python -m pytest -q
```

Result: `122 passed in 11.19s`, exit 0. Raw output: `01_vulnova_pytest.txt`.
No `build/vulnova.db` or source snapshot was present or used.

### 3.2 Chromium browser smoke test

```bash
python -m pip install -r requirements-browser.txt
# in CI: python -m playwright install --with-deps chromium
python tools/ui_browser_check.py
```

The sandbox cannot reach the Playwright browser CDN (`cdn.playwright.dev`), so
the exact pinned browser could not be downloaded here. The script was run with a
locally available Chromium 153 executable via its supported
`VULNOVA_CHROMIUM_PATH` override:

```bash
VULNOVA_CHROMIUM_PATH=/tmp/chromium python tools/ui_browser_check.py
```

Result: `14 browser checks passed (Chromium; desktop + narrow viewport).`,
exit 0. Raw output: `03_ui_browser_check.txt`. The first lines of that file are a
non-fatal Playwright cleanup message (`Target closed`) emitted while the browser
closes with a mocked response still settling; it does not affect the exit code or
the checks. The CI job installs Playwright 1.64's bundled Chromium and does not
use the override.

### 3.3 Root project regression check

The root workflow's fixed command was run to confirm the failure is an import-path
problem, not a test defect:

```bash
python -m pip install -r requirements.txt
python -m pytest tests -q
```

Result on Python 3.11: `192 passed, 6 subtests passed`, exit 0. Raw output:
`02_root_pytest.txt`. The pre-fix command (bare `pytest`) still reproduces the
12 collection errors: `04_root_ci_failure_reproduction.txt`. Python 3.9 and 3.10
were not available in this sandbox, so they were not run locally; the GitHub
Actions matrix did run both and both jobs passed (§8).

### 3.4 Lint

```bash
flake8 src tests inspect_data.py --count --select=E9,F63,F7,F82 --show-source --statistics
```

Result: `0`, exit 0. Raw output: `05_flake8.txt`.

## 4. Trigger scoping

* **VULNOVA unit tests** — pull requests and pushes to `main` only when
  `vulnova_product/**` or `vulnova-unit-tests.yml` changes; manual dispatch.
* **VULNOVA browser** — unchanged: pull requests and pushes to `main` only when
  `vulnova_product/**` or `vulnova-browser.yml` changes; manual dispatch.
* **Root `python-package.yml`** — pull requests and pushes to `main`, ignoring
  `vulnova_product/**` and the two VULNOVA workflow files.

A documentation-only change inside `vulnova_product/` runs VULNOVA checks, which
is intentional because the browser test serves committed static assets. A root
pipeline change no longer runs VULNOVA tests, and a VULNOVA change no longer runs
the root tests.

## 5. Failure investigation

### 5.1 Root `Python package` workflow (exit code 2)

The annotation reported `Process completed with exit code 2` in the
`Test with pytest` step, for every Python version. Exit code 2 is an interrupted
collection. Local reproduction with the original command:

```text
ModuleNotFoundError: No module named 'src'
ModuleNotFoundError: No module named 'tests'
!!!!!!!!!!!!!!!!!!! Interrupted: 12 errors during collection !!!!!!!!!!!!!!!!!!!
```

Cause: the workflow ran bare `pytest`. The console script does not put the
repository root on `sys.path`, so `from src...` and `from tests...` fail.
`python -m pytest` does add the working directory. Fix:

```diff
-      run: |
-        pytest
+      run: |
+        python -m pytest tests -q
```

The lint stage is also scoped to `src tests inspect_data.py`, and the root job no
longer collects `vulnova_product/tests`. No test was deleted or skipped.

### 5.2 `Django CI`

Failed at `Set up Python 3.7` ("Version 3.7 with arch x64 not found") and would
then have run `python manage.py test`. There is no `manage.py`, no Django
dependency and no Django app in the repository. The workflow was removed; no
legitimate test coverage was lost.

### 5.3 VULNOVA browser workflow

Passing on `main` (run 39285900265). Retained as-is, including Python 3.11, the
pinned Playwright version and the no-database design.

## 6. Database policy

Lightweight CI does not require `build/vulnova.db`:

* Unit tests build throwaway stores in `tmp_path` via `tests/conftest.py`.
* The browser test mocks the API and serves only committed static files.
* `tools/verify_product.py` still requires a built store and remains part of
  `verify_all.sh`, **not** CI.

No workflow was added that builds the database. If a future CI job needs the
store, it must build it reproducibly from committed inputs in the same job.

## 7. Files changed

| File | Change |
| --- | --- |
| `.github/workflows/vulnova-unit-tests.yml` | New Python 3.11 unit-test workflow |
| `.github/workflows/python-package.yml` | Fixed pytest invocation, scoped lint/tests, excluded VULNOVA paths |
| `.github/workflows/django.yml` | Removed (invalid workflow) |
| `vulnova_product/docs/CI.md` | New CI reference |
| `vulnova_product/docs/BROWSER_TESTING.md` | Expected browser count and CI link |
| `vulnova_product/README.md` | CI section and docs index |
| `vulnova_product/reports/improvement1_5/*` | This report and raw evidence |

## 8. GitHub Actions verification (PR #9)

All workflows were run on the pull request from `arena/5d8fad69-ai`:

| Workflow | Run | Result | Notes |
| --- | --- | --- | --- |
| VULNOVA unit tests | 39288436970 | **success** | `Unit tests (Python 3.11)` passed in 26 s |
| VULNOVA browser smoke test | 39288436845 | **success** | Playwright 1.64 Chromium installed in CI; all checks passed |
| Python package | 39288436929 | **success** | `build (3.9)`, `build (3.10)` and `build (3.11)` all passed lint and pytest |

The two VULNOVA workflows were triggered by the product changes; the root
workflow was triggered because this PR also edits `python-package.yml` and
removes `django.yml`. GitHub evaluates pull-request path filters against the
**complete PR diff**, not the latest commit, so a follow-up commit confined to
`vulnova_product/` still ran all three workflows while the PR remained open.
For a PR whose diff touches only `vulnova_product/**`, the root workflow's
`paths-ignore` skips it; for a PR touching only root files, the two VULNOVA
workflows' `paths` filters skip them.

The only annotations on the runs were GitHub's own Node.js 20 deprecation notice
for `actions/checkout@v4` / `actions/setup-python@v5` and the `ubuntu-latest`
migration notice. Neither affects job results.

A second set of runs after the first documentation follow-up also passed:
VULNOVA unit tests 39288674479, VULNOVA browser 39288674746 and Python package
39288674662. All subsequent pushes to the PR produced the same results.
