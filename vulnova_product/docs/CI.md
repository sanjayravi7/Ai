# CI — workflows, commands and expected checks

VULNOVA lives in `vulnova_product/` and is a separate project from the
repository-root vulnerability-data pipeline. The workflows are split so that a
change under `vulnova_product/` does not run the root project's tests, and a
change to `src/` or `tests/` does not run VULNOVA's tests.

## Workflow ownership

| Workflow | Project | What it runs | Python |
| --- | --- | --- | --- |
| `.github/workflows/vulnova-unit-tests.yml` | VULNOVA | `vulnova_product/tests` (635 tests) | 3.11 |
| `.github/workflows/vulnova-browser.yml` | VULNOVA | `vulnova_product/tools/ui_browser_check.py` (14 Chromium checks) | 3.11 |
| `.github/workflows/python-package.yml` | Root data pipeline | `tests/` (192 tests + 6 subtests) and flake8 | 3.9, 3.10, 3.11 |

`django.yml` was removed in VULNOVA 1.5. It ran `python manage.py test` against a
repository that has no `manage.py`, no Django dependency and no Django
application. Its setup step also failed before reaching any test because Python
3.7 is not available on `ubuntu-latest`. It did not represent a legitimate test
of either project; see "Failure investigation" below.

## VULNOVA unit tests

Triggered by a pull request or a push to `main` that changes any path under
`vulnova_product/` or `phase2.3k-export/`, or the workflow file itself. It can
also be run manually (`workflow_dispatch`).

From a checkout:

```bash
cd vulnova_product
python -m pip install -r requirements.txt
python -m pytest -q
```

Expected on Python 3.11 with `pytest==9.1.1`:

```text
635 passed
```

The suite creates its own temporary SQLite stores through
`tests/conftest.py`. It does **not** read `build/vulnova.db` or use the network,
and the workflow does not build a database. The evaluation-readiness tests use a
synthetic Phase 2.3K-shaped fixture; one additional test re-runs the committed
`phase2.3k-export/` archive and compares the report digest, skipping itself if the
archive is absent. That test unpacks into `vulnova_product/build/` (not committed)
and takes roughly 12 seconds on a cold cache, so the suite takes about 25 seconds
instead of 12.

The acquisition tests (1.7) use an injected `FakeTransport` with canned bytes and
fixed clocks. They never open a socket and never read `data/acquisition_store/`:
tampering, missing timestamps, hash mismatches, cutoff mismatches and
historical-versus-actual retrieval times are all exercised against the fixture.

The refresh tests (1.8) follow the same rule. `tests/refresh_fixtures.py` builds a
canned catalog with explicit `dateAdded` values, an optional direct CISA feed
(including a redirect), optional EPSS files (present, absent, or carrying the
wrong `score_date`) and an optional sealed 1.7-shaped archive. `RefreshOptions`
takes the clock as a parameter, so a test can stand on 2026-10-27, on the
maturity date, or after it without touching the system time. Seven tests in
`test_refresh_repository_report.py` re-derive the committed report from the
committed inputs, including a full readiness re-run at the committed as-of date.

The redirect tests are deterministic too. `SafeRedirectHandler.redirect_request`
is called directly with synthetic `Location` values; a second group drives the
*real* `OpenerDirector` and redirect chain with a canned handler that never opens
a socket. No DNS, no live redirect. They cover
an allowed same-host redirect, an allowed cross-host redirect, a relative
`Location`, a lookalike `//host/path`, a disallowed host, a 301/303/307/308
HTTPS-to-HTTP downgrade, a non-HTTP scheme, a plaintext initial URL, and the
final URL being recorded separately. They also assert that urllib's permissive
default handler is genuinely *replaced* in the installed opener.

The prospective-capture tests (1.9) are fully offline as well.
`tests/prospective_fixtures.py` serves canned KEV catalogs, EPSS daily files,
cvelistV5 commit responses and policy-checked redirects; the clock is injected
through `CaptureOptions`. `tests/conftest.py` installs an autouse guard that fails
any connection to a non-loopback address, so a test that reached CISA, FIRST or
GitHub would fail rather than pass slowly and differently on each machine. The
six `test_prospective_*.py` modules (137 tests) cover capture, verification,
path safety, the store primitive, the report and the sealed-archive invariant.

CI also runs two 1.9 smoke steps after the 1.8 verifier: the prospective CLI must
describe itself, and an empty store must report itself as empty and verify as
`BLOCKED` with zero captures. There is deliberately **no scheduled capture job**:
a GitHub Actions cron that committed a daily EPSS file would make an expiring
artifact look like a durable archive, and the store is meant to grow outside the
repository. See `docs/PROSPECTIVE_CAPTURE_1_9.md`.

## Optional: verify the committed acquisition archive

This is not part of CI, because it needs neither the network nor a database and
therefore proves nothing that the unit suite does not already cover. It is the
command a reviewer runs to check the committed evidence:

```bash
cd vulnova_product
python -m vulnova.acquisition verify    # offline; exit 1 on tampering
python -m vulnova.acquisition check     # offline; exit 1 on a missing source row
```

`verify` re-hashes the seven stored artifacts and re-derives access provenance
from the recorded timestamps. It reports `integrity: VERIFIED` and
`evidence: BLOCKED` for the committed archive: the bytes are intact, and three
requirements are still honestly unmet.

The 1.8 refresh has the same offline command, and CI runs it after the 1.7 one:

```bash
cd vulnova_product
python -m vulnova.refresh verify    # offline; exit 1 on tampering
python -m vulnova.refresh gate      # offline; prints the maturity boundary
```

The prospective store has the same offline command, but the repository commits
no store: a fresh checkout has nothing to verify. On an operator's store:

```bash
cd vulnova_product
python -m vulnova.prospective verify --store /srv/vulnova/evidence   # offline
python -m vulnova.prospective report --store /srv/vulnova/evidence   # offline
```

`prospective verify` exits `1` for an empty store (`CAPTURES_PRESENT`), because
"nothing to verify" is not "verified". `prospective report` exits `0` and says the
store is empty.

`refresh verify` recomputes `refresh_digest`, re-hashes the refreshed catalog,
re-checks that no block claims maturity before its maturity date, and re-hashes
all seven sealed 1.7 artifacts. It reports `integrity: VERIFIED`,
`evidence: BLOCKED` and `BLOCKED_MATURITY_NOT_REACHED`. It must **not** be gated
on evidence completeness: the committed run's honest findings are that the final
block has not matured and that EPSS is unavailable.

## VULNOVA Chromium smoke test

Triggered by the same VULNOVA paths, plus changes to its own workflow file. It
can also be run manually.

```bash
python -m pip install -r vulnova_product/requirements-browser.txt
python -m playwright install --with-deps chromium
python vulnova_product/tools/ui_browser_check.py
```

Expected when all checks pass:

```text
14 browser checks passed (Chromium; desktop + narrow viewport).
```

The script serves the committed static UI and mocks `/api/status` and
`/api/ranking`. It does not need `build/vulnova.db`, source snapshots or network
access (other than installing Playwright and Chromium before the run). It is a
frontend integration smoke test, not a test of the production API, ingestion,
non-Chromium engines or assistive-technology announcements.

> Local note (2026-10-19): the sandbox could not reach the Playwright browser
> CDN, so the smoke test was executed against a locally downloaded Chromium 153
> binary (`VULNOVA_CHROMIUM_PATH`) rather than Playwright 1.64's bundled
> Chromium 156. It exited 0 and printed all 14 passes. The CI job installs the
> pinned Playwright browser and does not use this override.

## Evaluation-readiness reproduction

The readiness command itself is not a CI gate: its current result is
intentionally `BLOCKED_PROTOCOL_NOT_APPROVED`, and treating a blocked report as a
failing job would obscure the reason. Reproducibility is tested instead:

```bash
cd vulnova_product
python -m pytest -q tests/test_evaluation_repository_report.py
```

That test rebuilds the report from the committed archives and asserts that the
canonical digest equals the digest in
`reports/evaluation_readiness_1_6/readiness_report.json`. A separate fixture-based
test (`test_report_digest_is_canonical_and_reproducible`) verifies that two
independent runs agree. Any change to a check, a reason string or an input digest
therefore requires regenerating the committed report; the test fails until it is
regenerated, which is the intended review signal.

To regenerate:

```bash
cd vulnova_product
python -m vulnova.evaluation readiness --check-reproducible \
  --markdown reports/evaluation_readiness_1_6/readiness_report.md
```

## Root project tests

Triggered by pull requests and pushes to `main` that do not consist solely of
VULNOVA files. The matrix is retained from the original workflow.

```bash
python -m pip install flake8 pytest
python -m pip install -r requirements.txt
python -m pytest tests -q
```

Expected on Python 3.11:

```text
192 passed, 6 subtests passed
```

Use `python -m pytest`, not bare `pytest`. The root `tests/` files import the
repository-local `src` and `tests` packages; `python -m pytest` puts the
repository root on `sys.path`, while the bare console script does not.

## Path scoping

| Change | VULNOVA unit tests | VULNOVA browser | Root project |
| --- | --- | --- | --- |
| `vulnova_product/**` | runs | runs | skipped |
| `.github/workflows/vulnova-*.yml` | runs (own file only) | runs (own file only) | skipped |
| `src/**`, `tests/**`, `requirements.txt`, `inspect_data.py` | skipped | skipped | runs |
| `.github/workflows/python-package.yml` | skipped | skipped | runs |

Both VULNOVA workflows also run on pushes to `main` and via manual dispatch.

For `pull_request` events, GitHub evaluates these filters against the complete
diff between the pull request and its base branch, not just the latest commit.
A pull request that changes both VULNOVA and root-project files therefore runs
both sets of workflows; that is expected.

## Failure investigation (2026-10-19)

Recorded from the GitHub Actions API; the log archive endpoint is not reachable
from the development sandbox, so the findings below use job/step statuses, check
annotations and a local reproduction.

### `Python package` — failed on every run (all Python versions)

Observed: `Test with pytest` failed with exit code 2 in runs `39274219913`,
`39274258105` and `39285871594` (Python 3.9, 3.10 and 3.11). Exit code 2 is a
collection interruption, not a normal assertion failure.

Reproduced locally on the same commit with a clean virtualenv and the workflow's
exact commands:

```text
ERROR tests/test_audit_disputed_cves.py
...
ModuleNotFoundError: No module named 'src'
ModuleNotFoundError: No module named 'tests'
!!!!!!!!!!!!!!!!!!! Interrupted: 12 errors during collection !!!!!!!!!!!!!!!!!!!
```

Root cause: the workflow ran bare `pytest` from the repository root. The console
script does not add the current directory to `sys.path`, so the root test
modules could not import `src.*` or `tests.*`. The same suite passes with
`python -m pytest`, which adds the working directory.

Fix: run `python -m pytest tests -q`. Selecting `tests` explicitly also stops
the root workflow from collecting `vulnova_product/tests`; VULNOVA tests now run
only in the VULNOVA workflows on Python 3.11. The lint commands are similarly
scoped to `src tests inspect_data.py`.

### `Django CI` — failed before running anything

Observed: `Set up Python 3.7` failed with "Version 3.7 with arch x64 not found"
in run `39274257936`; the remaining matrix entries were cancelled. Even with a
working interpreter, `python manage.py test` cannot run because no `manage.py`
exists anywhere in the repository.

Decision: remove the workflow. Nothing it claimed to test exists, so no
legitimate coverage was removed.

### `VULNOVA browser smoke test` — passing

Run `39285900265` on `main` completed successfully. The workflow already used
Python 3.11, path-scoped triggers, a pinned Playwright version and needed no
database. It is retained unchanged.

### `VULNOVA unit tests` — new

The VULNOVA tests were previously collected indirectly by the root
`Python package` workflow (as part of `pytest` from the repository root) and
failed at collection for the root import reason above. They now have a
dedicated Python 3.11 workflow with only `vulnova_product/requirements.txt`
installed.
