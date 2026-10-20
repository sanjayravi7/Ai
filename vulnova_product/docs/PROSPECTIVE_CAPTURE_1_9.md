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
python -m vulnova.prospective cycle     # network: one capture + verify + report
python -m vulnova.prospective verify    # offline: re-hash every capture
python -m vulnova.prospective report    # offline: deterministic summary
```

`capture` and `cycle` are the only commands that touch the network, and neither
has a date override: both always read the real UTC clock. A prospective capture
that its caller could date would be worth no more than the backdated historical
evidence this subsystem exists to avoid repeating. Tests inject a clock through
`vulnova.prospective.capture.CaptureOptions` or
`vulnova.prospective.cycle.CycleOptions`; the CLI never does. `cycle` is the same
capture, followed by the same offline verification and the same deterministic
report — not a second evidence format.

## What one capture records

| Source | First-party endpoint | What is preserved |
| --- | --- | --- |
| CISA KEV | `www.cisa.gov/.../known_exploited_vulnerabilities.json`, then `api.github.com/repos/cisagov/kev-data` | The catalog bytes, catalog version, `dateReleased`, entry count, and the commit SHA that served them on the GitHub channel |
| FIRST EPSS | `epss.empiricalsecurity.com/epss_scores-<UTC observation date>.csv.gz` | The exact daily file for the observation date, its declared model version and `score_date`, and a parsed-row count |
| cvelistV5 | `api.github.com/repos/CVEProject/cvelistV5/commits?sha=HEAD&per_page=1` | The observable default-branch commit SHA and the API response bytes — never a clone |

All three endpoints are first-party. There is no mirror fallback: an unreachable
publisher is recorded as `UNAVAILABLE`, never replaced with a third-party copy
labelled official.

The cvelistV5 repository is far too large to clone on a daily schedule, and
cloning would add nothing to the identifier: a commit SHA fully names the
revision. `capture_current` therefore makes one API request, stores its bytes,
and records `clone_required=false`. A test pins that exactly one URL is fetched.

## EPSS endpoint (1.9.1 hotfix)

The first real capture (`20261020T062217Z-3ba1c441132c`) recorded EPSS as
`BLOCKED` / `REDIRECT_BLOCKED` while KEV and cvelistV5 verified. The cause was the
host: VULNOVA requested `epss.cyentia.com`, FIRST's legacy EPSS host. That record
is preserved unchanged — it is an accurate record of what was requested and
refused on that date, and this hotfix does not rewrite it.

Documented, indexed, observed and unobserved evidence are kept apart here,
because collapsing them is how a plausible URL becomes a claimed fact:

| Claim | Status |
| --- | --- |
| `epss.empiricalsecurity.com` is the daily CSV host | **Published now.** FIRST's *Get the Data* page names it and gives `epss_scores-current.csv.gz`. |
| The *current-file* URL redirects | **Published now.** The same page says so and tells users to pass `curl -L`. |
| The date-specific filename pattern `epss_scores-YYYY-MM-DD.csv.gz` appears in FIRST-hosted documentation | **Historically documented, not retrievable now.** FIRST's EPSS statistics page at `www.first.org/epss/data_stats` listed the pattern explicitly. It is still present in search indexes and in third-party issue reports that cite that page as their source, but a direct request to it now returns 404. The pattern is therefore documented history, not a live page that can be re-checked today. |
| A date-specific file is served from that path on that host | **Observed.** A 2026-10-19 file fetched from the path declares its own `score_date` in its header. |
| The date-specific URL redirects, and to where | **Unobserved.** No HTTP status code and no `Location` header has been seen. |

The historical row is deliberate. It would be wrong to say the date-specific
pattern *never* appeared in FIRST-hosted documentation: it did, on the
statistics page named above. What cannot be done today is re-fetch that page,
so the pattern rests on indexed/historical documentation plus one observed file
rather than on a currently live FIRST page.

Since 1.9.1 the source constructs the date-specific URL directly, for the
observation date and no other.

| Rule | Behaviour |
| --- | --- |
| Requested URL | `https://epss.empiricalsecurity.com/epss_scores-<UTC date>.csv.gz` — always the exact date, never `-current` and never a different day |
| Allowlist | `DEFAULT_ALLOWED_HOSTS` names only hosts a source fetches: the three GitHub hosts, `www.cisa.gov` and `epss.empiricalsecurity.com`. `epss.cyentia.com` and `www.first.org` were removed — neither is requested by any source, and the latter is FIRST's documentation site, not a data endpoint |
| Redirects | `SafeRedirectHandler` and `require_https` are unchanged. Every hop must stay HTTPS and inside the allowlist |
| Response check | the source re-checks the URL that actually answered against `APPROVED_RESPONSE_HOSTS`, which holds **exactly** `epss.empiricalsecurity.com`, before the body is parsed, hashed or stored |
| Recorded URLs | `request_url` is always kept; `final_url` is recorded only when a response actually answered. A redirect is therefore visible rather than assumed, and a refusal issued before the hop leaves no `final_url` at all |
| Refusals | an unapproved destination or a plaintext response is `BLOCKED` / `REDIRECT_BLOCKED`, with no digest and no artifact path |
| Everything else | `score_date` comparison, storage and requirement status are unchanged |

**What is published, indexed, observed and unobserved.** These are four
different kinds of evidence and they are not interchangeable:

* *Published now* — FIRST's *Get the Data* page names
  `epss.empiricalsecurity.com` and the current-file URL, and states that the
  current-file URL redirects. It does not show the date-specific pattern.
* *Historically documented, not retrievable* — FIRST's EPSS statistics page
  (`www.first.org/epss/data_stats`) listed the date-specific pattern. That page
  now returns 404 to a direct request; it survives in search indexes and in
  third-party reports that cite it.
* *Observed* — a date-specific file fetched from that path for 2026-10-19
  declares `score_date:2026-10-19T12:00:27Z` in its own header. The retrieval
  path used returns the file body only, so it says nothing about the HTTP
  exchange.
* *Unobserved* — the HTTP status, the `Location` header and the redirect
  destination of a date-specific request. Direct TLS to the host is blocked
  before the handshake completes from this environment, so none of the three
  could be captured.

The observation establishes that the exact-date path serves a file whose own
header declares that date. It establishes **nothing** about redirects, and it is
not a substitute for a real capture; no live capture is claimed to succeed.

Because the response allowlist is now exactly the EPSS host, an undocumented
redirect to an infrastructure host will fail closed: the record becomes
`BLOCKED` / `REDIRECT_BLOCKED` and names the refused destination. That is the
deliberate trade — an unverified redirect is not silently trusted — and it is
recoverable by adding an evidence-backed allowance if one is later observed.

**What a refusal guarantees.** A refused response is not parsed, not hashed and
not written to the store; `request_url` and `final_url` are both kept. It does
**not** mean the bytes were never received: the transport reads a response body
before the source sees the URL that produced it, so the guarantee is about what
is done with those bytes, not about whether they arrived. In production the
transport refuses an unapproved redirect before the follow-up request is issued,
so the destination is never contacted at all.

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
| `details` | Source-specific validation facts (counts, declared dates, model version, `observation_date`, `prospective`) and, on a failed EPSS request, a bounded `error_detail` |

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

### Failed requests keep bounded diagnostics

A capture that fails still records *why*, and from this patch it also records
what the publisher said. For an EPSS request that ends in a transport error, the
record keeps:

| Field | Content |
| --- | --- |
| `http_status` | The response status, when there was a response (`403`, `429`, `404`, …), otherwise `null` |
| `reason_code` | The stable classification (`RATE_LIMITED`, `HTTP_ERROR`, `OFFICIAL_SOURCE_UNREACHABLE`, `REDIRECT_BLOCKED`, …) |
| `details.error` | The transport's own reason string |
| `details.error_detail` | A bounded, single-line excerpt of the response body, when the transport captured one. **Omitted entirely when there is nothing to record** |

`error_detail` is at most 400 characters, ellipsis included, and every run of
whitespace is collapsed to a single space, so an HTML error page cannot make a
stored record depend on the publisher's formatting. A non-string detail is not
response text and is not recorded.

**A 403 status does not establish rate limiting as the cause.** `RATE_LIMITED` is
the transport's classification of *both* `403` and `429`
(`transport.py`: `reason = "RATE_LIMITED" if exc.code in (403, 429)`). A 403 can
equally be a bot block, a WAF challenge, a geographic restriction or a rejected
request signature. The stored status and reason are unchanged by this patch — the
excerpt is what a later reader uses to tell those cases apart, and treating the
label as a finding would be exactly the kind of "plausible URL becomes a claimed
fact" collapse this subsystem exists to avoid.

Nothing else about a failed request changes: `sha256`, `artifact_path` and the
stored bytes are still absent, the classification vocabulary is untouched, and a
refused redirect is still `BLOCKED` / `REDIRECT_BLOCKED`. Records written before
this field existed are unaffected — the field is additive and the verifier does
not require it, so old and new run records verify on the same store.

Diagnostics are not a licence to retry: one cycle still makes one request per
source, and a 403 recorded once is not a signal to hammer the publisher.

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
* The store therefore **requires a filesystem that supports hard links** (ext4,
  XFS, APFS, NTFS and most local filesystems do). Where `link(2)` is
  unavailable, capture fails with `ATOMIC_CREATE_UNAVAILABLE`; it does **not**
  fall back to opening the final path. A direct write would leave a truncated
  artifact at the evidence path if the process died mid-write — the exact
  corruption an append-only store exists to prevent. A read-only comparison of
  an existing destination still works, so a link-less filesystem can report
  identical bytes and conflicts; it simply cannot accept new evidence. Choose a
  local filesystem, not a network share with weak link semantics.
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

`verify` answers one question: **are these the bytes that were captured, does the
record that describes them hold together, and is the physical store fully
accounted for?** It never touches the network; re-downloading would verify the
publisher, not the archive.

| Check | What it proves |
| --- | --- |
| `SCHEMA` | Every run parses, carries exactly the 1.9 fields, has an ISO observation date and capture instants, and does not finish before it starts |
| `RUN_DIGEST` | Every run digest recomputes over its own payload |
| `RUN_IDENTITY` | Every run id is exactly the one derived from its instant and digest |
| `RECORD_INVARIANTS` | Every record is well typed; no prospective record carries a cutoff; every `VERIFIED` record names a usable store path, digest, size and retrieval time |
| `ARTIFACTS` | Every artifact a run references exists and re-hashes to the recorded SHA-256 and size |
| `STORE_INVENTORY` | **Every file under `artifacts/`** is enumerated, re-hashed, checked against its content address, and matched to a readable run; symlinks and escapes are refused |
| `CAPTURE_STATUS` | Exactly one entry exists for every requirement ID (duplicates and missing IDs are refused), every status is in the vocabulary, and the summary counters equal the recomputed requirement statuses |
| `HISTORICAL_ARCHIVE` | The sealed 1.7 manifest still names artifacts that hash to their recorded values (`NOT_APPLICABLE` when the checkout has none) |
| `CAPTURES_PRESENT` | An empty store is `BLOCKED`, not `VERIFIED` |

### What the inventory adds

Run records alone cannot prove the store is complete. A capture writes an
artifact first and its run record second; a crash in between leaves a valid
artifact that no run mentions, and a verification that only walked the records
would never see it. The inventory therefore treats the filesystem as the source
of truth and derives findings from it:

| Finding | Meaning |
| --- | --- |
| `ARTIFACT_TAMPERED` | The file's bytes do not hash to the digest in its own name. Corruption, not an incomplete capture. |
| `UNSAFE_ARTIFACT_PATH` | A symlink (or `artifacts/` itself) is not a regular store file. It is never followed, so bytes outside the store are never hashed as evidence. |
| `ARTIFACT_MISSING` | A run references an artifact the store does not hold. Evidence was lost or the record was edited. |
| `UNEXPECTED_ARTIFACT` | A file or directory does not follow `artifacts/<kind>/<sha256><suffix>`. |
| `ARTIFACT_UNREADABLE` | The file exists but its bytes could not be read. This is never treated as "no file". |
| `ABANDONED_TEMPORARY_FILE` | A `.tmp-` file from a write that never completed. It is not a captured artifact and is never counted as one. |
| `UNREFERENCED_ARTIFACT` | The bytes are intact and content-addressed, but no readable run mentions them. This is an **incomplete capture**, not corruption. |

The last distinction is deliberate. A file whose name is its SHA-256 and whose
bytes match is not damaged; it is evidence whose run record is missing. Deleting
it to make `verify` green would destroy the only record that the capture
happened. The store stays `BLOCKED` and the operator investigates.

The inventory is deterministic: entries are sorted, counts are exact, and only
the first 20 paths of each category are printed (the JSON result carries the
counts and the capped lists). Symlinked directories are reported, never
descended. A file that vanishes between the scan and the read is reported as
unreadable rather than silently skipped.

`verify` exits `0` only when the store verifies and `1` when it does not.
`capture` and `report` exit `2` when a write-safety rule refuses the command.
`cycle` combines capture, verification and reporting and uses `0` / `2` / `3` /
`4` to say whether a scheduler must act; the mapping is below.

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
* malformed run files, with every problem found: a status outside the
  vocabulary, a requirement block that is not a list, a record that is not an
  object, a bad digest/size/timestamp, a missing or unexpected field;
* an explicit statement that an empty store is not evidence of absence.

A malformed run is **counted as `BLOCKED`, never under the status it claims**,
and its per-source claims are excluded from the day grid. `captures_well_formed`
and `malformed_captures` make the difference explicit, so the counts cannot be
read as "everything that was read succeeded". The report never raises on bad
values: a list, an object or an invented label is rejected before it can become a
dictionary key, and only values in the three-state vocabulary are counted. Two
reports of the same store — however damaged — are byte-identical and carry the
same `report_digest`, and no absolute path from the machine that produced them
appears in the output.

The Markdown summary ends with **What this does not prove**: a capture is not an
evaluation; a hash is not historical correctness; a missing source is not a
negative label; collecting daily evidence does not by itself satisfy the
three-block protocol.

## Operating it

### Manual run

One command does the whole round trip:

```bash
cd /srv/vulnova/vulnova_product
.venv/bin/python -m vulnova.prospective cycle --store /srv/vulnova/evidence
```

`cycle` is `capture`, then `verify`, then `report`, in that order, against the
same store. It is the same capture code and the same verification code — not a
second evidence format and not a second copy of the logic. The three commands
remain available separately when an operator wants one step at a time:

```bash
cd /srv/vulnova/vulnova_product
VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence .venv/bin/python -m vulnova.prospective capture
VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence .venv/bin/python -m vulnova.prospective verify
VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence .venv/bin/python -m vulnova.prospective report --out /srv/vulnova/reports/prospective.md
```

`capture` exits `0` when the attempt was recorded, whatever the sources did; the
status is in the record and on stdout. `verify` exits non-zero if anything is
wrong. Neither command retries silently, and neither does `cycle`.

The store is any directory outside the repository. `--store` accepts an absolute
path; `VULNOVA_PROSPECTIVE_STORE` sets the default when the flag is omitted:

```bash
export VULNOVA_PROSPECTIVE_STORE=/srv/vulnova/evidence
.venv/bin/python -m vulnova.prospective cycle
```

### Scheduling

Run one cycle per UTC day, after the EPSS daily file normally appears (about
12:00 UTC). Because `cycle` already verifies and reports, a scheduler invokes it
once and alerts on the exit status.

| Exit | Meaning | What a human should do |
| --- | --- | --- |
| `0` | Every source verified **and** the store verified. | Nothing. |
| `2` | Nothing was recorded: an unsafe destination, or a capture that failed before its run record was written. | Read the error; fix the path or the environment. No evidence was lost. |
| `3` | **The run was recorded, but at least one source did not verify.** | Nothing to repair in the store — the gap is in the observation. Investigate the publisher; the next cycle tries again. |
| `4` | The store did not verify: tampered bytes, a missing artifact, an orphan, an unreadable or malformed run. | Stop and investigate the disk. Do not delete anything to make the check green. |

A non-zero exit **never** removes a capture that was written. A run with two of
three sources verified is still evidence that an attempt happened, and it stays
in the store; `3` means "look at the publisher", not "discard the day".

`--json` emits the same result for a monitoring script. It carries `exit_code`
and `reason` (`OK`, `UNSAFE_CONFIGURATION`, `CAPTURE_NOT_RECORDED`,
`CAPTURE_INCOMPLETE`, `INTEGRITY_FAILED`, `REPORT_NOT_WRITTEN`), the `run_id`,
`observation_date`, `capture_status`, a `sources` list with one `status` /
`reason_code` pair per requirement, an `integrity` block naming the failed
checks, and `report_digest`. The process exit status is the same number, so a
scheduler can use either. `--out PATH` writes the deterministic report as well;
that path is validated before the capture starts and may not sit inside the
store or inside a sealed path.

#### Check a schedule before trusting it

A scheduler is configured once and then runs unattended for months, so the
mistakes worth catching are configuration mistakes. The preflight checks them
without capturing anything and without opening a socket:

```bash
cd /srv/vulnova/vulnova_product
.venv/bin/python tools/check_schedule.py \
  --store /srv/vulnova/evidence \
  --out /srv/vulnova/reports/prospective.md \
  --trigger-utc 13:10
```

It checks that the interpreter is 3.11+ and can import `vulnova`, that both paths
are absolute, that neither is inside the repository, that neither touches the
sealed 1.6/1.7/1.8 paths or `protocol/`, that the destination filesystem really
supports hard links (the store refuses to write without them), that the report is
not inside the store, and that the existing store still verifies. It also prints
the machine's UTC offset and what `13:10` UTC is in local time — the single most
common source of a schedule that runs, and looks fine, at the wrong hour.

Exit status is `0` when every check passes and `1` when any fails; warnings do not
fail the run. An empty store is a **warning**: there is nothing to verify yet, and
an empty store is never reported as verified. `--json` emits the whole result.

The preflight reads the store; it never writes evidence, never deletes evidence
and never contacts a publisher. Its only filesystem mutation is a temporary
directory used to prove hard-link support, removed immediately afterwards.

#### Which clock does the scheduler use?

The same text means different instants on different systems:

| Scheduler | How the configured time is interpreted |
| --- | --- |
| cron | the **host's local timezone**, unless the implementation supports `CRON_TZ` and it is set |
| systemd timer | the **host's local timezone**, unless the calendar spec names a zone (`… UTC`) |
| Windows Task Scheduler | the **machine's local timezone**; the command line has no UTC option |

For a machine in `Asia/Kolkata` (UTC+05:30, no daylight saving), **13:10 UTC is
18:40 IST**. For `Pacific/Auckland` in October (UTC+13) it is **02:10 the next
day**. A schedule labelled "13:10" without a timezone is therefore a statement
about the host, not about UTC.

Only the systemd example below is configured in UTC. The cron and Windows
examples that use a literal clock time are labelled **local**, because that is
what those schedulers do with it.

#### cron

On a Vixie-derived cron — cronie (RHEL, Fedora, Arch), Debian's `cron`, FreeBSD —
`CRON_TZ` sets the timezone used to *interpret the schedule*, so the entry fires
at 13:10 UTC regardless of the host's zone:

```cron
# User crontab (crontab -e).
# CRON_TZ applies to the entries below it in this file.
CRON_TZ=UTC
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=""

10 13 * * * /usr/local/bin/vulnova-cycle
```

Two compatibility caveats, both of which fail **quietly** rather than loudly:

* `CRON_TZ` is a Vixie-cron extension. Check the host's own manual —
  `man 5 crontab | grep CRON_TZ` — before relying on it. BusyBox `crond` and
  several minimal container images do not implement it and **silently ignore**
  it; the job then runs at 13:10 *local*. In a container, run the scheduler
  outside the container or use a UTC host.
* `TZ=` is **not** `CRON_TZ=`. `TZ` sets the environment of the job; it does not
  move the firing time.

If the implementation has no `CRON_TZ`, convert the instant and label it as local
time:

```cron
# 18:40 Asia/Kolkata (UTC+05:30, no DST) == 13:10 UTC. THIS IS LOCAL TIME.
40 18 * * * /usr/local/bin/vulnova-cycle
```

Derive the offset from `timedatectl` or `date +%z`, add it to 13:10 UTC, and write
the local result. Where the zone observes daylight saving, the local time of a
fixed UTC instant moves by an hour twice a year; either recompute after every
transition or use a scheduler that can be told UTC. `tools/check_schedule.py`
prints the current conversion for the machine it runs on, which is the value to
compare against.

Keep shell logic out of the crontab: an unescaped `%` in a crontab means "newline"
and will corrupt anything using `printf` or `date +%F`. Put it in a wrapper the
operator owns, outside the repository:

```sh
#!/bin/sh
# /usr/local/bin/vulnova-cycle  (chmod 0755; owned by the operator, not the repo)
set -u
PY=/srv/vulnova/vulnova_product/.venv/bin/python
STORE=/srv/vulnova/evidence
REPORT=/srv/vulnova/reports/prospective.md
LOG=/var/log/vulnova-cycle.log
LOCK=/run/lock/vulnova-cycle.lock

# One instance at a time. An overlapping cycle would double the requests to each
# publisher and confuse the log; it could never corrupt the store.
command -v flock >/dev/null || { echo "flock (util-linux) is required" >>"$LOG"; exit 2; }
exec 9>"$LOCK" || exit 2
if ! flock -n 9; then
    echo "$(date -u +%FT%TZ) skipped: previous cycle still running" >>"$LOG"
    exit 75          # EX_TEMPFAIL: logged, not paged
fi

"$PY" -m vulnova.prospective cycle --store "$STORE" --out "$REPORT" >>"$LOG" 2>&1
status=$?
echo "$(date -u +%FT%TZ) cycle exit=$status" >>"$LOG"

case "$status" in
    0) ;;
    2) vulnova-alert alert    "cycle recorded nothing; configuration or path" ;;
    3) vulnova-alert notice   "cycle recorded, at least one source incomplete" ;;
    4) vulnova-alert critical "store integrity failure; do not delete anything" ;;
    *) vulnova-alert critical "cycle exited $status" ;;
esac
exit "$status"
```

`vulnova-alert` is a stand-in for whatever paging or mail hook the operator
already runs; VULNOVA ships no alerting binary and does not assume one. What
matters is the mapping: a non-zero `cycle` exit is classified and forwarded, and
the exit status is still propagated so the scheduler's own reporting agrees.

The wrapper never deletes the previous report: `--out` replaces that file
atomically, and the report is regenerable — the evidence store is not touched.

#### systemd

The timer states its timezone explicitly, so no local-time conversion is needed:

```ini
# /etc/systemd/system/vulnova-cycle.service
[Unit]
Description=VULNOVA prospective evidence cycle
Wants=network-online.target
After=network-online.target
OnFailure=vulnova-alert@%n.service

[Service]
Type=oneshot
User=vulnova
Group=vulnova
WorkingDirectory=/srv/vulnova/vulnova_product
ExecStart=/srv/vulnova/vulnova_product/.venv/bin/python -m vulnova.prospective cycle --store /srv/vulnova/evidence --out /srv/vulnova/reports/prospective.md
# Distinguish 3 from 4 in the alert; EXIT_STATUS is set for ExecStopPost.
ExecStopPost=/usr/local/bin/vulnova-alert --status "$EXIT_STATUS"
RuntimeMaxSec=1800
TimeoutStartSec=1900
Nice=10
```

```ini
# /etc/systemd/system/vulnova-cycle.timer
[Unit]
Description=Daily VULNOVA prospective cycle

[Timer]
OnCalendar=*-*-* 13:10:00 UTC
AccuracySec=1min
RandomizedDelaySec=0
Persistent=false
Unit=vulnova-cycle.service

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now vulnova-cycle.timer`, then confirm the
computed instant instead of assuming it:

```bash
systemd-analyze calendar '*-*-* 13:10:00 UTC'   # prints Next elapse … UTC
systemctl list-timers vulnova-cycle.timer       # NEXT column is the real answer
```

* **`Persistent=false` on purpose.** `Persistent=true` replays a missed timer at
  the next boot. For a capture that is wrong twice over: the run happens hours
  late, and on a machine that boots before ~12:00 UTC it happens *before* the new
  day's EPSS file exists, so it records a partial capture on a date nobody chose.
  A missed day must stay missing — see the rules below.
* **No overlap is possible.** systemd does not start a second instance of a
  `Type=oneshot` unit while it is running, so no lock file is needed here;
  `RuntimeMaxSec` bounds a hung capture instead of letting it block tomorrow's.
* Use an absolute `ExecStart` pointing at the deployment's own virtualenv, an
  absolute `--store` **outside** the repository, and an absolute `--out` outside
  both. `WorkingDirectory` is set so a relative path cannot be resolved against
  `/`.
* `OnFailure=` fires for any non-zero exit (2, 3 or 4); `ExecStopPost` receives
  `$EXIT_STATUS` so the alert can say which one. Both point at an alert unit the
  operator supplies — VULNOVA does not ship one.

#### Windows Task Scheduler

Task Scheduler interprets the trigger in the **machine's local time**, and
`schtasks` has no UTC switch. On a machine set to `Asia/Kolkata`, 13:10 UTC is
**18:40 IST**, so that is the value to configure:

```
schtasks /Create /TN "VULNOVA prospective cycle" /SC DAILY /ST 18:40 ^
  /TR "C:\vulnova\vulnova-cycle.cmd" ^
  /RU SYSTEM
```

To derive it for another machine, ask the machine rather than doing the
arithmetic by hand:

```powershell
Get-TimeZone | Select-Object Id, BaseUtcOffset
$utc = [datetime]::UtcNow.Date.AddHours(13).AddMinutes(10)
[TimeZoneInfo]::ConvertTimeFromUtc($utc, [TimeZoneInfo]::Local).ToString("yyyy-MM-dd HH:mm")
```

The second line prints the local time of 13:10 UTC **today**; use its `HH:mm` in
`/ST`, and its date to notice a day boundary (a zone at UTC+13 puts 13:10 UTC at
02:10 the next local day). Where the zone observes daylight saving, the result
moves by an hour twice a year: rerun it after each transition, or schedule with a
UTC-aware tool. Do not label that value UTC — it is not.

In the GUI the same task is *Create Task* → *Triggers* → daily at **18:40** →
*Actions* → start `C:\vulnova\vulnova-cycle.cmd` → *Settings* → **If the task is
already running: Do not start a new instance**, and untick *Run task as soon as
possible after a scheduled start is missed* (the Windows analogue of
`Persistent=false`). PowerShell:

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\vulnova\vulnova-cycle.cmd"
$trigger = New-ScheduledTaskTrigger -Daily -At "18:40"
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable:$false
Register-ScheduledTask -TaskName "VULNOVA prospective cycle" `
  -Action $action -Trigger $trigger -Settings $settings `
  -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
```

`-MultipleInstances IgnoreNew` is the overlap guard; without it a slow run and
the next day's run can overlap. `18:40` is local time.

`vulnova-cycle.cmd` (operator-owned, outside the repository) logs the exit code
and raises an event so the run is visible in Event Viewer and to any monitoring
that reads it:

```bat
@echo off
setlocal
set PY=C:\vulnova\vulnova_product\.venv\Scripts\python.exe
set LOG=C:\vulnova\logs\cycle.log
if not exist C:\vulnova\logs mkdir C:\vulnova\logs

"%PY%" -m vulnova.prospective cycle --store C:\vulnova\evidence ^
  --out C:\vulnova\reports\prospective.md >> "%LOG%" 2>&1
set RC=%ERRORLEVEL%
echo %DATE% %TIME% exit=%RC% >> "%LOG%"

if "%RC%"=="2" eventcreate /T ERROR   /ID 100 /L APPLICATION /D "VULNOVA cycle recorded nothing (exit 2)"
if "%RC%"=="3" eventcreate /T WARNING /ID 101 /L APPLICATION /D "VULNOVA cycle incomplete (exit 3)"
if "%RC%"=="4" eventcreate /T ERROR   /ID 102 /L APPLICATION /D "VULNOVA store integrity failure (exit 4)"

exit /b %RC%
```

`eventcreate` may need elevation depending on the machine's audit policy. If it
is not permitted, forward `C:\vulnova\logs\cycle.log` to the existing monitoring
instead — the exit code and the JSON summary are both in that file, and Task
Scheduler's *Last Run Result* carries the same number.

#### Testing a schedule without capturing

Three checks, in increasing cost, none of which records evidence:

1. `tools/check_schedule.py` — validates the configuration (above). Run it as the
   scheduled user, with the same absolute paths the job uses.
2. **Fire the schedule with the preflight instead of the cycle.** Point the
   cron/Task entry or `ExecStart` at `check_schedule.py` for one day, confirm from
   the log and the timer's next-elapse that it fires at the intended instant, then
   switch it to `cycle`. This tests the *scheduler* — timezone, user, paths,
   permissions — without a single network request.
3. `python -m vulnova.prospective verify --store …` — offline re-hash of what is
   already stored.

Never test a schedule by lowering the trigger time and letting it capture for
real: that records a run at an hour nobody chose, on a day that is now part of the
archive.

#### Rules for the schedule

* **Missed days are left missing.** There is no backfill and no date override:
  running later cannot create a contemporaneous observation, and a file
  downloaded today can never be stored as evidence of what was observable last
  week. Do not hand-edit, re-date or replay a captured run to fill a gap.
* **Re-runs are new captures.** A second capture on the same day appends a new
  run; it does not overwrite the first. Repeated unsuccessful attempts stay
  visible.
* **A 404 on the EPSS daily file is `UNAVAILABLE`** with `EPSS_FILE_MISSING`.
  That is a gap in observation, never a score of zero and never an absence of
  exploitation.
* **No substitution.** Do not drop a mirror file into the store or edit a record
  by hand. Both would break `verify`, which is the point.
* **No retry loop.** One cycle per schedule slot. If a source is down, the cycle
  records the outage and exits; the next *scheduled* run is the retry.
* **Nothing is deleted automatically.** No pruning, no rotation that removes old
  runs, no cleanup of "failed" captures. Exit 3 and exit 4 both leave the store
  exactly as the run left it.
* **Evidence and reports stay outside the repository.** The store, the report and
  the log all live outside the checkout; `check_schedule.py` fails a store or
  report path inside it.

### Backup and restore

The store is append-only, so a backup is a copy:

```bash
rsync -a /srv/vulnova/evidence/ /srv/backup/evidence/
cd /srv/vulnova/vulnova_product
.venv/bin/python -m vulnova.prospective verify --store /srv/backup/evidence
```

Never back up with a deleting mode that could remove older evidence, and verify
the copy rather than trusting the copy command:

* `verify --store <copy>` must report `integrity: VERIFIED`;
* `report --json --store <copy>` must print the same `report_digest` as the live
  store. A copy with a different digest is not the archive, however successful
  the copy command looked.

A restore is the same operation in reverse. After restoring, run `verify` (not
`cycle`) against the restored store before treating it as evidence: a restore
that does not verify is a second incident, not a recovery. Keep at least one
copy off the machine that runs the cycle, and remember that `verify` detects
corruption relative to the stored record — it cannot detect a forgery that was
re-signed, so an append-only or WORM backup target is stronger than a mutable
one.

### Unavailable sources

When a source is down, the capture records the failure and finishes. There is
nothing to repair in the store: the run says what happened, with the URL, the
status, the reason code, the time and — when the publisher sent one — a bounded
excerpt of the error body in `details.error_detail`. Start an investigation from
that excerpt rather than from the status alone: `403` is classified
`RATE_LIMITED` alongside `429`, and the body is what distinguishes a real rate
limit from a WAF block. Then let the next scheduled capture try again. Do not
rewrite history to look complete, and do not retry the same request in a loop.

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
outside the repository. No workflow runs `cycle` either: it is a networked
capture, and CI exercises only the offline surface. No cloud credentials are
needed for local capture, verification or the tests.

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

**Unavailable evidence.** From this sandbox the direct `www.cisa.gov` feed is
unreachable, and TLS to `epss.empiricalsecurity.com` is closed before the
handshake completes (`SSLZeroReturnError`, TCP connects), so a live capture here
would honestly record `OFFICIAL_SOURCE_UNREACHABLE` for EPSS; CISA's GitHub
repository is reachable and can satisfy the KEV requirement. Those are properties
of the environment, not of the code, and they are exactly what the status
vocabulary is for.

**Unexercised capabilities.** A multi-week scheduled run, restore-from-backup at
scale, an actual link-less filesystem (the failure is simulated by monkeypatching
`os.link`), and conflict adjudication by a later assessment have not been
exercised. The tests prove the mechanics on synthetic stores, not the operational
routine.

**Open research questions.** Whether daily prospective capture makes a future
three-block evaluation feasible; whether post-2026-10-28 KEV catalogs can observe
the final block's labels; whether EPSS daily files remain retrievable from this
environment; and whether a prospective store can be trusted enough to substitute
for the historical evidence that 1.7 could not obtain contemporaneously. None of
these is answered here.

## Tests

`tests/test_prospective_*.py` (227 tests) and `test_schedule_preflight.py` (24)
drive the real capture, cycle, verify and report paths against canned responses,
and exercise the schedule preflight against temporary directories. No test opens a
socket: `tests/conftest.py` installs an autouse guard that fails any connection to
a non-loopback address, and one test asserts the guard is live. The nine modules
are:

| Module | Tests | Focus |
| --- | --- | --- |
| `test_prospective_capture.py` | 42 | KEV/EPSS/cvelistV5 capture, fallback, redirects, provenance, clock |
| `test_prospective_cycle.py` | 28 | one-shot cycle: exit status, JSON, refusals before any request, no retries, idempotency |
| `test_prospective_verify.py` | 19 | tampered/deleted artifacts and records, run identity, conflicts |
| `test_prospective_paths.py` | 23 | protected-path guard, traversal, symlinks, refusals before I/O |
| `test_prospective_store.py` | 26 | create-once, atomicity, concurrency, capability refusal, path safety |
| `test_prospective_report.py` | 26 | determinism, gaps, conflicts, unreadable runs, sealed targets |
| `test_prospective_archive.py` | 9 | sealed 1.7 archive and committed report invariants |
| `test_prospective_adversarial.py` | 54 | the 1.9 findings: link-less filesystems, malformed values, orphaned artifacts, structural requirement validation |
| `test_schedule_preflight.py` | 24 | UTC→local trigger arithmetic (including a next-day zone), store/report path refusals, hard-link capability, store integrity, and the preflight CLI's exit codes |

The checklist covered:

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
* an unreferenced but intact artifact, two orphans and exact counts; a filename
  that lies about its bytes; a vanished run record; an unexpected file, an
  abandoned temporary file, a symlinked artifact or artifact directory, and a
  directory where an artifact belongs;
* repeat capture without overwrite, same-date conflicting captures preserved,
  deterministic report and report digest;
* atomic writes, concurrent create-once (threads and processes), temporary-file
  cleanup, and a link-less filesystem failing closed with no partial file and no
  change to existing bytes;
* malformed report input: `capture_status` as a list, an invented status, a
  requirement status as an object, `records` as a dict/null/string/number, an
  unhashable requirement id or record source, bad hashes/sizes/timestamps, and
  missing or unexpected fields — through both the API and the CLI, with multiple
  malformed records in one store;
* structural requirement validation after re-signing: a duplicate requirement ID
  and a missing required ID are refused even when the summary counters are made
  consistent, and `capture_completed_at` earlier than `capture_started_at` is
  rejected by both verification and the report (equal instants are accepted);
* verify/report agreement: for every structural defect the suite damages, the
  verifier is `BLOCKED` exactly when the report calls the run malformed and
  excludes it from the day grid — a permissive report can never contradict a
  failed verification;
* a scheduled configuration: the preflight passes a usable store, refuses one
  inside the repository, one overlapping a sealed path, a relative path, a report
  inside the store and a filesystem without hard links; it warns on an empty store
  and fails a tampered one; it writes nothing into the store and leaves no probe
  directory behind; the UTC→local conversion is pinned for +05:30, +00:00, −08:00
  and a +13 zone that lands on the next local date;
* unsafe store, report and symlink targets, traversal, and refusals that leave
  no directory and read no clock;
* programmatic calls with empty defaults still protected; the sealed 1.7 archive
  and every committed report byte-identical after capture, verify and report;
* the cycle: a healthy run exits `0`; a partial or blocked source exits `3` while
  keeping the run; a tampered, malformed or orphaned store exits `4` without
  deleting the new capture; a capture that cannot be recorded exits `2` with no
  run written; unsafe store and report paths, and a report path that collides
  with the store, are refused with the transport never asked for a URL; a
  crashed verifier is reported as `INTEGRITY_FAILED` rather than a traceback; an
  unwritable report exits `2` and still keeps the recorded capture; one cycle
  issues one request per source and never retries; repeating the same instant is
  `ALREADY_CAPTURED` with one run and one digest;
* missing EPSS and KEV absence never turned into a negative label.

## Known limitations

* Verification detects corruption relative to the stored record, not a fully
  re-signed forgery. An external trust anchor would be a separate milestone.
* The store is a filesystem directory; it **requires** a local filesystem with
  working hard links and ordinary POSIX semantics. There is no weaker writer:
  a filesystem that cannot link gets `ATOMIC_CREATE_UNAVAILABLE` and stores
  nothing. Supporting a network filesystem without atomic link would require a
  different design (and a project-owner decision), not a fallback.
* Verification cannot tell an orphaned artifact from one deliberately planted.
  Both are `UNREFERENCED_ARTIFACT`; the distinction requires the missing run
  record, which is exactly what is not there.
* The inventory caps printed paths at 20 per category. Counts are exact, so a
  truncated list is never mistaken for a complete one.
* The KEV daily catalog is content-addressed, so an operator cannot reconstruct
  "which day first saw this catalog" from the store alone without reading the run
  records — the run records do carry the observation date and the selected
  digest.
* EPSS files are large and are stored in full; there is no pruning, by design.
