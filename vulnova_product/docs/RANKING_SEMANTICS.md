# Ranking semantics

Reference definition of every number the console displays. Nothing in this file is a
proposal; proposed changes live in `reports/validation1_1/RANKING_SEMANTICS_PROPOSAL.md`
(historical, unchanged).

## The score

```
priority_score = KEV membership            (0 or 40)
               + round(EPSS probability * 30)          (0..30)
               + round(CVSS base score / 10 * 20)      (0..20)
               + publication_recency points            (0..10)
```

Fixed denominator: **100**. Weights: **40 / 30 / 20 / 10**. The denominator is never
rescaled when evidence is missing; a missing input contributes **zero points** and is
named in `missing_signals`. Zero points is arithmetic, not a risk judgement.

The fourth component is named **`publication_recency`** in every presentation surface
(API, detail view, footer, these docs). The database column that stores it is
`ranking.recency_points`, an internal storage name; the ranking API exposes it as
`publication_recency_points`.

## publication_recency

**Basis: the CVE publication date, and nothing else.**

| Property | Value |
| --- | --- |
| Component name | `publication_recency` |
| Input | CVE `datePublished` (cvelistV5) or `pub_date` (legacy extract) |
| Reference date | EPSS `score_date` of the loaded snapshot (2026-10-16), so the arithmetic is reproducible rather than wall-clock dependent |
| Full credit | publication age ≤ 90 days → 10 points |
| Decay | linear from 90 to 1,825 days, floored |
| Zero | publication age ≥ 1,825 days → 0 points |
| Maximum | 10 points (10% of the fixed denominator) |

```
publication_recency_points = 10                                   if age <= 90
                           = floor(10 * (1825 - age) / 1735)      if 90 < age < 1825
                           = 0                                    if age >= 1825
```

It answers: *"was this vulnerability disclosed recently?"*

### What it does not represent

`publication_recency` does **not** represent:

* **recent exploitation activity** — no exploitation event, EPSS movement or observation
  time enters this component;
* **recent KEV inclusion** — the catalog `dateAdded` is displayed separately
  (`kev_listing_date`, `days_since_kev_listing`) and contributes nothing to this
  component; KEV contributes the fixed 40-point membership component instead;
* **an independently verified increase in threat activity** — no such measurement is
  performed anywhere in this system.

A 2015 CVE added to KEV last week therefore scores **0** on `publication_recency`. Its
position comes from KEV membership, EPSS and CVSS. The console states this explicitly
for such records rather than describing them as having no recent activity.

The API returns this in `publication_recency_context`:

```json
{
  "component": "publication_recency",
  "component_basis": "publication_date",
  "does_not_represent": [
    "recent exploitation activity",
    "recent KEV inclusion",
    "an independently verified increase in threat activity"
  ],
  "publication_date": "2015-05-18",
  "publication_age_days": 4169,
  "kev_listing_date": "2026-10-08",
  "days_since_kev_listing": 8,
  "statement": "publication_recency measures the CVE publication date only: it does not represent …"
}
```

## Bands

| Band | Minimum score | Operational meaning |
| --- | ---: | --- |
| `P1_CRITICAL` | 70 | immediate triage |
| `P2_HIGH` | 40 | scheduled triage |
| `P3_MODERATE` | 20 | backlog |
| `P4_LOW` | 1 | lowest priority |
| `P5_NONE` | 0 | no positive evidence |

## What the score is not

* Not a probability.
* Not a validated predictive model.
* Not a claim that a low-scoring CVE is safe.
* Not evidence about exploitation when KEV is silent: absence from the catalog is
  `NOT_LISTED_IN_CATALOG`, not "not exploited".

## Evidence adequacy

Independent of the score:

| Status | Condition | `review_required` |
| --- | --- | --- |
| `INSUFFICIENT_EVIDENCE` | no CVSS **and** no EPSS | **yes** |
| `PARTIAL_EVIDENCE` | exactly one of CVSS / EPSS | no |
| `SUFFICIENT_EVIDENCE` | both present | no |

For `INSUFFICIENT_EVIDENCE` the numeric band is preserved but the display band gains
`(INSUFFICIENT EVIDENCE)` and the detail view states that the band is **not** an
assessment that the vulnerability is low risk.

## CVSS selection

When sources disagree, the value used for scoring is chosen by:

1. source: `cvelistv5` before `legacy_cve_csv`;
2. CVSS version within the source: v4.0 > v3.1 > v3.0 > v2.0;
3. container within the version: CNA before ADP.

All candidates are returned by the API and displayed, with organisation, version,
retrieval timestamp and a `comparable` flag (different major versions are **not**
directly comparable).

## KEV

Membership contributes 40 points and is shown as a distinct `KEV` chip and filter.
The catalog's `dateAdded` is displayed but does **not** contribute to the score.

## Change history of this component

| Version | Change |
| --- | --- |
| Validation 1.1 | Component presented as `recency`; basis documented as publication date |
| Improvement 1.2 | Renamed to `publication_recency` in every presentation surface; explicitly documented as *not* exploitation activity, KEV inclusion, or a verified threat increase. **Arithmetic, weight and denominator unchanged** |
