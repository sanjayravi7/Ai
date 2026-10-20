# VULNOVA 1.9 — prospective evidence capture

1.6 asked whether a historical evaluation was possible. 1.7 acquired the
historical evidence that question needed and found that every artifact had to be
downloaded long after the period it described. 1.8 showed that the final block's
labels cannot be observed from a catalog published before they mature. 1.9 starts
building evidence **from now on**, so that a future assessment does not inherit
the same weakness: evidence observed while the period is live, with a retrieval
time that is the time of observation rather than the time of a later cleanup.

This subsystem captures evidence. It does **not** evaluate, mature labels, admit
a design or approve the protocol.

```
python -m vulnova.prospective capture   # network: record one observation
python -m vulnova.prospective verify    # offline: re-hash every capture
python -m vulnova.prospective report    # offline: deterministic summary
```

`capture` is the only command that touches the network, and it has no date
override: it always reads the real UTC clock. A prospective capture that its
caller could date would be worth no more than the backdated historical evidence
this subsystem exists to avoid repeating. Tests inject a clock through
`vulnova.prospective.capture.CaptureOptions`; the CLI never does.

## What one capture records

| Source | First-party endpoint | What is preserved |
| --- | --- | --- |
| CISA KEV | `www.cisa.gov/.../known_exploited_vulnerabilities.json`, then `api.github.com/repos/cisagov/kev-data` | The catalog bytes, catalog version, `dateReleased`, entry count, and the commit SHA that served them on the GitHub channel |
| FIRST EPSS | `epss.cyentia.com/epss_scores-<UTC observation date>.csv.gz` | The exact daily file for the observation date, its declared model version and `score_date`, and a parsed-row count |
| cvelistV5 | `api.github.com/repos/CVEProject/cvelistV5/commits?sha=HEAD&per_page=1` | The observable default-branch commit SHA and the API response bytes — never a clone |

All three endpoints are first-party. There is no mirror fallback: an unreachable
publisher is recorded as `UNAVAILABLE`, never replaced with a third-party copy
labelled official.

The cvelistV5 repository is far too large to clone on a daily schedule, and
cloning would add nothing to the identifier: a commit SHA fully names the
revision. `capture_current` therefore makes one API request, stores its bytes,
and records `clone_required=false`. A test pins that exactly one URL is fetched.

## Provenance recorded per artifact

Every record carries, independently:

| Field | Meaning |
| --- | --- |
| `source`, `key`, `channel` | Which source, which observation (`current`, a date, `HEAD`), and which first-party channel served it |
| `source_url` | The publisher's canonical location |
| `request_url` | The URL actually requested |
| `final_url` | The URL that answered after any permitted redirect |
| `retrieved_at` | The **actual UTC receipt time** from the transport |
| `source_timestamp` | The publisher's own timestamp (`dateReleased`, EPSS `score_date`, commit time) |
| `revision` | A publisher revision identifier where one exists (commit SHA) |
| `http_status`, `bytes`, `sha256` | Size and digest of the stored bytes; status of the response |
| `artifact_path` | Where the bytes live in the store, or `null` if nothing was stored |
| `content_status`, `status`, `reason_code` | The three-state outcome and a stable reason code |
| `access_provenance` | `CONTEMPORANEOUS` for a prospective record; `historical_retrieval_verified` is always `false` |
| `details` | Source-specific validation facts (counts, declared dates, model version, `observation_date`, `prospective`) |

Retrieval time is never derived from the publisher's timestamp. If a source
timestamp is later than the retrieval time, `finalize()` marks the record
`BLOCKED` with `RETRIEVAL_BEFORE_SOURCE_TIME`: that ordering is impossible and
means the artifact or the clock is wrong. A fixed defect in the direct-feed path
(1.9) previously finalized the KEV record before attaching `dateReleased`, so a
future-dated catalog could pass as `VERIFIED` on the direct channel while the
GitHub channel correctly refused it; both channels now share the check, and a
regression test pins it.

A prospective record must never carry a historical cutoff. `acquire_daily` gains
a `historical=False` mode that records the observation date instead of a block
boundary, and the capture layer refuses any record whose `cutoff` is not `None`
with `HISTORICAL_CUTOFF_IN_PROSPECTIVE_CAPTURE`. The default remains
`historical=True`, so 1.7 behaviour is unchanged.

## The three states

The 1.7 vocabulary is reused rather than redefined, so the two subsystems cannot
drift apart:

* **`VERIFIED`** — the expected artifact was obtained from a first-party channel
  and passed the source's own validation.
* **`UNAVAILABLE`** — the publisher did not supply usable evidence: unreachable,
  timed out, rate-limited, no daily file, an empty or malformed body.
* **`BLOCKED`** — an unmet precondition or a policy refusal: a redirect outside
  the approved HTTPS hosts, an HTTPS downgrade, a truncated or empty catalog, a
  retrieval time before the source time.

A run with two of three sources verified is a **partial capture**, reported as
`UNAVAILABLE` at run level, never rounded up to success. A run where nothing
verified still writes a run record: a failed attempt is evidence that an attempt
happened, and it is never evidence of absence.

`ALREADY_CAPTURED` is an outcome of one invocation, not a status written into the
record. It means the derived run id already existed with byte-identical content,
which happens when the same responses are captured at the same instant (as a
test does deliberately). In production a new run normally gets a new instant and
therefore a new run id; identical artifacts are deduplicated by content address,
not re-stored.

## Store layout and immutability

```
<store>/artifacts/kev/<sha256>.json
<store>/artifacts/epss/<sha256>.csv.gz
<store>/artifacts/cvelistv5/<sha256>.json
<store>/runs/<YYYYmmddTHHMMSSZ>-<digest[:12]>.json
```

* The default store is `~/.vulnova/prospective`; `VULNOVA_PROSPECTIVE_STORE` or
  `--store` relocates it. It lives outside the repository on purpose — a year of
  daily EPSS files is hundreds of megabytes and must not become repository
  history.
* Artifacts are **content-addressed**. Unchanged daily catalogs therefore occupy
  one file, not one per day.
* Every write is **create-once**: bytes go to a temporary file in the destination
  directory, are flushed and fsynced, then `os.link`ed into place. A write that
  finds an existing file either proves the bytes identical (no-op) or raises
  `StoreConflict` — existing evidence is never overwritten. A tampered artifact
  is reported, not "repaired" by replacing it.
* The run id is derived from the capture instant and the run digest, so two
  machines computing the same run agree on its name. The digest covers the whole
  record except `run_digest` and `run_id`.
* Paths are validated twice: syntactically (no absolute path, no `..`) and
  physically (the resolved target must stay inside the store, and a symlink is
  refused).

Two captures of the same observation date that disagree about a source's bytes
are both preserved. `verify` and `report` list them as conflicts with both run
ids and both digests. Neither is preferred, and verification does not fail
because of a conflict: choosing between them is a later assessment's job, and it
must say which one it used and why.

## Write safety

Path safety runs before the clock is read, before the first socket is opened and
before any directory is created. A refused run writes nothing.

The guard is the 1.8 implementation (`vulnova.refresh.paths.assert_safe_write_targets`),
not a copy. Overlap in either direction is refused: a store inside a sealed path
is as unacceptable as a store that contains one. The fixed protected set is the
1.8 one (the 1.6 readiness report, the 1.7 archive and manifest,
`data/snapshots`, the Phase 2.3K export) **plus** `data/refresh_store_1_8`,
`reports/refresh_1_8` and `protocol/`.

Caller-supplied paths are additive. Passing `protected_paths=()` means "nothing
extra", never "nothing protected": a programmatic caller cannot switch the
safeguard off by omitting an optional argument. `..` segments are resolved before
comparison, and an existing symlink is followed to its target, so neither can
launder a sealed path.

## Offline verification

`verify` answers one question: **are these the bytes that were captured, and does
the record that describes them hold together?** It never touches the network;
re-downloading would verify the publisher, not the archive.

| Check | What it proves |
| --- | --- |
| `SCHEMA` | Every run parses and carries the 1.9 schema |
| `RUN_DIGEST` | Every run digest recomputes over its own payload |
| `RUN_IDENTITY` | Every run id is exactly the one derived from its instant and digest |
| `RECORD_INVARIANTS` | No prospective record carries a cutoff; every `VERIFIED` record names a stored artifact, digest and retrieval time |
| `ARTIFACTS` | Every stored artifact re-hashes to the recorded SHA-256 and size |
| `CAPTURE_STATUS` | Every summary status equals the worst recomputed requirement status |
| `HISTORICAL_ARCHIVE` | The sealed 1.7 manifest still names artifacts that hash to their recorded values (`NOT_APPLICABLE` when the checkout has none) |
| `CAPTURES_PRESENT` | An empty store is `BLOCKED`, not `VERIFIED` |

`verify` exits `0` only when the store verifies and `1` when it does not.
`capture` and `report` exit `2` when a write-safety rule refuses the command.

A matching SHA-256 proves the stored bytes are the bytes that were captured. It
does not prove historical correctness or completeness, and it does not prove
authorship: someone who can rewrite a run can recompute its digest. Defending
against that needs an external trust anchor (a signed log, WORM storage, an
off-site copy), which this milestone does not add.

## The report

`report` is derived only from stored runs: no wall clock, no absolute path, no
environment detail. Two machines with the same store produce byte-identical
output and the same `report_digest`; the tests assert both. It lists:

* captures per observation date and the status of each source for that day, taken
  from the run's own requirements — a verified GitHub fallback is a verified KEV
  day even though the direct-feed attempt failed beside it;
* status counts per run and per source;
* conflicts, with both run ids and both digests;
* unreadable run files, named and never discarded;
* an explicit statement that an empty store is not evidence of absence.

The Markdown summary ends with **What this does not prove**: a capture is not an
evaluation; a hash is not historical correctness; a missing source is not a
negative label; collecting daily evidence does not by itself satisfy the
three-block protocol.

## Operating it

### Manual run

```bash
cd /srv/vulnova/vulnova_product
VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence .venv/bin/python -m vulnova.prospective capture
VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence .venv/bin/python -m vulnova.prospective verify
VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence .venv/bin/python -m vulnova.prospective report --out /srv/vulnova/reports/prospective.md
```

`capture` exits `0` when the attempt was recorded, whatever the sources did; the
status is in the record and on stdout. `verify` exits non-zero if anything is
wrong. Neither command retries silently.

### Scheduling

Capture on a real schedule, once per UTC day, after the EPSS daily file normally
appears (about 12:00 UTC). A cron entry:

```cron
# 13:10 UTC every day; capture, then verify what is on disk.
10 13 * * * cd /srv/vulnova/vulnova_product && \
  VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence \
  .venv/bin/python -m vulnova.prospective capture --quiet \
  >> /var/log/vulnova-capture.log 2>&1 && \
  VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence \
  .venv/bin/python -m vulnova.prospective verify \
  >> /var/log/vulnova-capture.log 2>&1
```

A systemd timer works the same way (`OnCalendar=*-*-* 13:10:00 UTC`,
`Type=oneshot`, `Persistent=true`); Windows Task Scheduler needs the same command
line with an absolute `--store`.

Rules for the schedule:

* **Missed days are left missing.** There is no backfill: running later cannot
  create a contemporaneous observation, and the CLI has no date override.
* **Re-runs are new captures.** A second capture on the same day appends a new
  run; it does not overwrite the first. Repeated unsuccessful attempts stay
  visible.
* **A 404 on the EPSS daily file is `UNAVAILABLE`** with `EPSS_FILE_MISSING`.
  That is a gap in observation, never a score of zero and never an absence of
  exploitation.
* **No substitution.** Do not drop a mirror file into the store or edit a record
  by hand. Both would break `verify`, which is the point.

### Backup and restore

The store is append-only, so a backup is a copy:

```bash
rsync -a /srv/vulnova/evidence/ /srv/backup/evidence/
cd /srv/vulnova/vulnova_product
.venv/bin/python -m vulnova.prospective verify --store /srv/backup/evidence
```

Never back up with a deleting mode that could remove older evidence, and verify
the copy rather than trusting the copy command. `report` prints a digest; compare
it before and after a restore.

### Unavailable sources

When a source is down, the capture records the failure and finishes. There is
nothing to repair in the store: the run says what happened, with the URL, the
status, the reason code and the time. Investigate the publisher, then let the
next scheduled capture try again. Do not rewrite history to look complete.

### Growth

EPSS dominates: roughly 1–2 MB per daily file compressed. A year is on the order
of half a gigabyte. Unchanged KEV catalogs deduplicate; the cvelistV5 API
response is a few kilobytes per day. Budget disk and backup accordingly.

## CI and what is deliberately absent

`.github/workflows/vulnova-unit-tests.yml` runs the full suite and the offline
1.7 and 1.8 verifiers, plus two 1.9 smoke steps: the CLI must describe itself,
and an empty store must report itself as empty and verify as `BLOCKED`, not
`VERIFIED`.

There is **no scheduled GitHub Actions capture job**, and there must not be one.
A cron that committed a daily EPSS file would turn a transient, expiring artifact
into repository history, grow without bound, and make the workflow look like a
durable archive it is not. Capture is an operator-run task against a store
outside the repository. No cloud credentials are needed for local capture,
verification or the tests.

## Evidence status of this milestone

Kept separate, because conflating them is how a project convinces itself it has
evidence it does not have:

**Confirmed historical facts.** The sealed 1.7 archive (7 artifacts) and the
committed 1.8 report still hash to their recorded values; `verify` re-checks the
archive on every run. The 1.8 status remains `BLOCKED_MATURITY_NOT_REACHED`; the
final block matures 2026-10-28; the protocol remains `NOT_APPROVED`; no design is
admissible.

**New prospective evidence.** This milestone adds the capability and its tests,
not captured observations. The repository commits no prospective store, and no
real daily capture has been performed from this environment. The first real
observation is whatever an operator captures first.

**Unavailable evidence.** From this sandbox the direct `www.cisa.gov` feed and
`epss.cyentia.com` are unreachable (connection refused/timeout), so a live
capture here would honestly record `OFFICIAL_SOURCE_UNREACHABLE`; CISA's GitHub
repository is reachable and can satisfy the KEV requirement. Those are properties
of the environment, not of the code, and they are exactly what the status
vocabulary is for.

**Unexercised capabilities.** A multi-week scheduled run, restore-from-backup at
scale, and conflict adjudication by a later assessment have not been exercised.
The tests prove the mechanics on synthetic stores, not the operational routine.

**Open research questions.** Whether daily prospective capture makes a future
three-block evaluation feasible; whether post-2026-10-28 KEV catalogs can observe
the final block's labels; whether EPSS daily files remain retrievable from this
environment; and whether a prospective store can be trusted enough to substitute
for the historical evidence that 1.7 could not obtain contemporaneously. None of
these is answered here.

## Tests

`tests/test_prospective_*.py` (137 tests) drive the real capture, verify and
report paths against canned responses. No test opens a socket: `tests/conftest.py`
installs an autouse guard that fails any connection to a non-loopback address, and
one test asserts the guard is live. The checklist covered:

* KEV success on both channels, GitHub fallback, partial failure, all-fail;
* EPSS success, 404, empty, malformed, `score_date` mismatch, unreachable;
* cvelistV5 success without a clone, empty commit list, malformed SHA, unreachable;
* permitted redirects recording request and final URL; refused host and HTTPS
  downgrade recorded as `BLOCKED`/`REDIRECT_BLOCKED`;
* retrieval time recorded separately from source time, and the impossible
  ordering refused; a future-dated catalog on the direct feed;
* offline verification of a healthy store; tampered artifact, missing artifact,
  tampered record, wrong run id, injected cutoff, unbacked `VERIFIED` record,
  summary/requirement disagreement, checksum mismatch;
* repeat capture without overwrite, same-date conflicting captures preserved,
  deterministic report and report digest;
* atomic writes, concurrent create-once, temporary-file cleanup, fallback writer;
* unsafe store, report and symlink targets, traversal, and refusals that leave
  no directory and read no clock;
* programmatic calls with empty defaults still protected; the sealed 1.7 archive
  and every committed report byte-identical after capture, verify and report;
* missing EPSS and KEV absence never turned into a negative label.

## Known limitations

* Verification detects corruption relative to the stored record, not a fully
  re-signed forgery. An external trust anchor would be a separate milestone.
* The store is a filesystem directory; it assumes a local filesystem with hard
  links and ordinary POSIX semantics. A network filesystem with weak `link`
  guarantees would weaken the create-once property (the code falls back to
  `open(..., "xb")`, which is still create-once but less atomic under some
  network filesystems).
* The KEV daily catalog is content-addressed, so an operator cannot reconstruct
  "which day first saw this catalog" from the store alone without reading the run
  records — the run records do carry the observation date and the selected
  digest.
* EPSS files are large and are stored in full; there is no pruning, by design.
