# VULNOVA Phase 2.3K — export artifacts

**Decision: `NOT_VIABLE_HISTORICAL`** — point-in-time risk-set materialization and temporal
feasibility, reference date 2026-10-15.

Read [`VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md`](VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md)
directly in the browser, or take the bundle.

## Files

| File | Bytes | SHA-256 |
|---|---:|---|
| `VULNOVA_Phase2.3K_core_bundle.tar.gz` | 138,434 | `850e68a5009e23ab84461e900c395a200fbcae57c175aba704731f66352420db` |
| `VULNOVA_Phase2.3K_core_bundle.tar.gz.sha256` | 103 | — |
| `VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md` | 19,851 | `d4f346909b6c3d1af4bf9adb58e59fbb789ae3c0ae0e1acd3a4c32614c9be141` |

## The bundle contains

report · all five CSV deliverables · quality summary · integrity manifest · inventory method and
manifest · the 21-cutoff list · evidence (census index, EPSS availability) · KEV timeline
(revisions, membership-by-revision, first-seen) · every builder and verifier tool ·
`risk_set_membership/INDEX.csv` + the partition scheme description.

## The bundle deliberately omits

| Absent | Size | Why |
|---|---:|---|
| `risk_set_membership/cutoff_*.csv.gz` (21 partitions) | 18 MB | per-cutoff sizes and SHA-256 are in `INDEX.csv` |
| `inventory/inventory_ids/` | ~16 MB | per-cutoff identifier lists |
| staged per-record census fact files | 406 MB | regenerate in ~47 s each from the revisions pinned in `cvelistv5_inventory_manifest.csv` |

**Consequence:** `phase2_3k_integrity_manifest.json` covers 45 files *including* the membership
partitions and identifier lists. Verifying it against this bundle will report those missing. That
is expected, not corruption. Expect `23 present, 0 mismatched, 22 absent`.

## Verify

```
tar -xzf VULNOVA_Phase2.3K_core_bundle.tar.gz
cd VULNOVA_Phase2.3K_core
python3 -c "
import json, hashlib, os
man = json.load(open('phase2_3k_integrity_manifest.json'))
present = [e for e in man['files'] if os.path.isfile(e['path'])]
absent  = [e['path'] for e in man['files'] if not os.path.isfile(e['path'])]
bad = [e['path'] for e in present
       if hashlib.sha256(open(e['path'],'rb').read()).hexdigest() != e['sha256']]
print(f'{len(present)} present, {len(bad)} mismatched, {len(absent)} absent')
print('mismatched:', bad)"
```

The full 21 MB archive, containing the membership partitions, is held outside this repository and
can be pushed on request.

## The decision in one paragraph

The frozen protocol needs a chronological train/validation/test design whose labels mature in
sequence. With the 180-day horizon and 30-day maturation lag, blocks must be **210 days** apart —
not 180. The candidate design carried out of 2.3J (three segments 180 days apart, 55/46/60 events,
disjoint windows) fails on label maturity by 29 days. No three-block design is possible: the
earliest the monthly grid carries is `2025-02-01 / 2025-09-01 / 2026-04-01`, maturing 2026-10-28,
13 days past the reference date. All 14 matured cutoffs clear the 30-event gate individually
(33–61 events), so **this is not event scarcity** — the blocker is the length of the matured
calendar. The largest constructible design is two blocks: 2025-02-01 (55 events) and 2025-09-01
(52 events).

## Scope

Data engineering and research validation only. **No model was trained, tuned or evaluated.** The
30-distinct-test-event gate was not relaxed. Protocol approval is separate from this technical
feasibility decision and is **not** granted here; the standing NO-GO for confirmatory predictive
evaluation is retained.
