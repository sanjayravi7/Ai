"""Synthetic Phase 2.3K-shaped fixtures for readiness tests.

The fixture is deliberately small (three monthly cutoffs, 35 events each) but
keeps every structural relationship the readiness engine checks: pinned
inventory, reason-coded membership partitions, KEV replay evidence, event
windows, maturity flags and a protocol file.
"""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from vulnova.evaluation.readiness import ReadinessOptions

CUTOFFS = [dt.date(2025, 2, 1), dt.date(2025, 9, 1), dt.date(2026, 4, 1)]
EVENTS_PER_CUTOFF = 35
FILLER_PER_CUTOFF = 2
EXCLUDED_KEV_PER_CUTOFF = 2
EXCLUDED_UNPUBLISHED_PER_CUTOFF = 3
RISK_SET_SIZE = EVENTS_PER_CUTOFF + FILLER_PER_CUTOFF
RECORDS_TOTAL = RISK_SET_SIZE + EXCLUDED_KEV_PER_CUTOFF + EXCLUDED_UNPUBLISHED_PER_CUTOFF
SELECTION_RULE = "greatest committer timestamp <= T 00:00:00Z on main"
REMOVED_CVES = [
    "CVE-2025-4664",
    "CVE-2025-6264",
    "CVE-2026-1281",
    "CVE-2026-69836",
]
EXTRA_REMOVED = ["CVE-2025-4664", "CVE-2026-1281", "CVE-2026-69836"]
DEFAULT_REFERENCE = dt.date(2026, 11, 1)


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fake_sha(seed: str, length: int = 40) -> str:
    return _sha_text(seed)[:length]


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_gzip_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def event_ids(cutoff_index: int, count: int = EVENTS_PER_CUTOFF) -> list[str]:
    ids = [f"CVE-2020-{1000 + cutoff_index * 100 + index}" for index in range(count)]
    if cutoff_index == 1:
        ids[0] = "CVE-2025-6264"
    return ids


def first_seen_day(cutoff: dt.date, index: int) -> dt.date:
    return cutoff + dt.timedelta(days=5 + (index % 60))


@dataclass
class Fixture:
    root: Path
    dataset: Path
    protocol: Path
    reference_date: dt.date
    source_end: dt.date
    events_by_cutoff: dict[dt.date, list[str]]
    options: ReadinessOptions


def build_fixture(
    root: Path,
    *,
    reference_date: dt.date = DEFAULT_REFERENCE,
    source_end: Optional[dt.date] = None,
    approved: bool = False,
    adopted_design: Optional[str] = None,
    event_already_in_kev_at: Optional[dt.date] = None,
    duplicate_event_at: Optional[dt.date] = None,
    corrupt_partition_at: Optional[dt.date] = None,
    missing_partition_at: Optional[dt.date] = None,
    missing_membership_index: bool = False,
) -> Fixture:
    root = Path(root)
    if root.exists():
        shutil.rmtree(root)
    dataset = root / "phase2_3k"
    dataset.mkdir(parents=True)
    source_end = source_end or reference_date
    events = {cutoff: event_ids(index) for index, cutoff in enumerate(CUTOFFS)}
    first_seen: dict[str, dt.date] = {}
    for index, cutoff in enumerate(CUTOFFS):
        for offset, cve_id in enumerate(events[cutoff]):
            first_seen[cve_id] = first_seen_day(cutoff, offset)
    for offset, cve_id in enumerate(EXTRA_REMOVED):
        first_seen[cve_id] = dt.date(2025, 5, 15) + dt.timedelta(days=offset * 120)
    first_seen = {key: value for key, value in first_seen.items() if value <= source_end}

    matured_flags = {
        cutoff: cutoff + dt.timedelta(days=210) <= reference_date for cutoff in CUTOFFS
    }
    matured_cutoffs = [cutoff for cutoff in CUTOFFS if matured_flags[cutoff]]
    matured_events = {
        cve_id for cutoff in matured_cutoffs for cve_id in events[cutoff]
    }
    matured_rows = sum(len(events[cutoff]) for cutoff in matured_cutoffs)
    distinct_events = {cve_id for ids in events.values() for cve_id in ids}

    # Independent identifiers per cutoff: filler, already-in-KEV, unpublished.
    inventory: dict[dt.date, list[str]] = {}
    reasons: dict[dt.date, dict[str, list[str]]] = {}
    for index, cutoff in enumerate(CUTOFFS):
        filler = [f"CVE-2019-{9000 + index * 10 + k}" for k in range(FILLER_PER_CUTOFF)]
        in_kev = [
            f"CVE-2018-{7000 + index * 10 + k}"
            for k in range(EXCLUDED_KEV_PER_CUTOFF)
        ]
        unpublished = [
            f"CVE-2018-{8000 + index * 10 + k}"
            for k in range(EXCLUDED_UNPUBLISHED_PER_CUTOFF)
        ]
        reasons[cutoff] = {
            "ELIGIBLE_AT_RISK": list(events[cutoff]) + filler,
            "EXCLUDED_ALREADY_IN_KEV_AT_T": in_kev,
            "EXCLUDED_UNPUBLISHED_AT_T": unpublished,
        }
        if event_already_in_kev_at == cutoff:
            moved = reasons[cutoff]["ELIGIBLE_AT_RISK"].pop(0)
            reasons[cutoff]["EXCLUDED_ALREADY_IN_KEV_AT_T"].append(moved)
        inventory[cutoff] = [
            cve_id
            for group in reasons[cutoff].values()
            for cve_id in group
        ]

    # cutoffs.txt
    (dataset / "cutoffs.txt").write_text(
        "".join(cutoff.isoformat() + "\n" for cutoff in CUTOFFS), encoding="utf-8"
    )

    # Inventory manifest
    inventory_rows = []
    for index, cutoff in enumerate(CUTOFFS):
        inventory_rows.append(
            {
                "cutoff_T": cutoff.isoformat(),
                "resolution": "RESOLVED",
                "revision_sha": _fake_sha(f"revision-{cutoff}"),
                "revision_committer_iso": (
                    dt.datetime.combine(
                        cutoff - dt.timedelta(days=1),
                        dt.time(23, 0),
                        tzinfo=dt.timezone.utc,
                    ).isoformat()
                ),
                "selection_rule": SELECTION_RULE,
                "cves_tree_sha": _fake_sha(f"tree-{cutoff}"),
                "year_subtree_count": 27,
                "year_subtrees_sha256": _sha_text(f"subtrees-{cutoff}"),
                "record_count": len(inventory[cutoff]),
                "distinct_record_count": len(inventory[cutoff]),
                "first_year": 1999,
                "last_year": cutoff.year,
                "year_dir_count": 27,
                "nonconforming_paths": 2,
                "nonconforming_examples": "cves/delta.json;cves/deltaLog.json",
                "partition_file": f"inventory_ids/cutoff_{cutoff.isoformat()}.txt.gz",
                "partition_sha256": _sha_text(f"inventory-{cutoff}"),
            }
        )
    _write_csv(dataset / "cvelistv5_inventory_manifest.csv", list(inventory_rows[0]), inventory_rows)

    # Denominator summary
    denominator_rows = []
    for cutoff in CUTOFFS:
        reasons_here = reasons[cutoff]
        risk_size = len(reasons_here["ELIGIBLE_AT_RISK"])
        excluded_kev = len(reasons_here["EXCLUDED_ALREADY_IN_KEV_AT_T"])
        excluded_unpublished = len(reasons_here["EXCLUDED_UNPUBLISHED_AT_T"])
        denominator_rows.append(
            {
                "cutoff_T": cutoff.isoformat(),
                "revision_sha": _fake_sha(f"revision-{cutoff}"),
                "revision_committer_iso": (
                    dt.datetime.combine(
                        cutoff - dt.timedelta(days=1),
                        dt.time(23, 0),
                        tzinfo=dt.timezone.utc,
                    ).isoformat()
                ),
                "matured": "YES" if matured_flags[cutoff] else "NO",
                "maturity_date": (cutoff + dt.timedelta(days=210)).isoformat(),
                "inventory_records": len(inventory[cutoff]),
                "kev_revision_sha": _fake_sha(f"kev-revision-{cutoff}"),
                "kev_revision_iso": (
                    dt.datetime.combine(
                        cutoff - dt.timedelta(days=2),
                        dt.time(12, 0),
                        tzinfo=dt.timezone.utc,
                    ).isoformat()
                ),
                "kev_staleness_days": 2,
                "kev_entries_at_T": excluded_kev,
                "cve_in_kev_at_T": excluded_kev,
                "excluded_already_in_kev": excluded_kev,
                "excluded_rejected_record": 0,
                "excluded_unpublished_at_T": excluded_unpublished,
                "excluded_malformed_identifier": 0,
                "unresolved_record_unreadable": 0,
                "risk_set_size": risk_size,
                "census_loaded": "YES",
                "risk_with_cvss": 20,
                "risk_with_cvss_cna": 18,
                "risk_without_any_cvss": risk_size - 20,
                "risk_published_after_T": 0,
                "cvss_coverage_pct": f"{100.0 * 20 / risk_size:.2f}",
            }
        )
    _write_csv(
        dataset / "risk_set_denominator_summary.csv",
        list(denominator_rows[0]),
        denominator_rows,
    )

    # Events
    event_rows = []
    for cutoff in CUTOFFS:
        ids = list(events[cutoff])
        if duplicate_event_at == cutoff and ids:
            ids = ids + [ids[0]]
        additions = len(events[cutoff]) + 1
        event_rows.append(
            {
                "cutoff_T": cutoff.isoformat(),
                "matured": "YES" if matured_flags[cutoff] else "NO",
                "catalogue_additions_in_window": additions,
                "in_risk_set_at_T": len(events[cutoff]),
                "outside_risk_set_already_in_kev": 1,
                "publication_rule_satisfied": len(ids),
                "eligible_events": len(ids),
                "event_ids": ";".join(ids),
                "gate_required": 30,
                "gate_met": (
                    "YES"
                    if matured_flags[cutoff] and len(set(ids)) >= 30
                    else "NO"
                ),
                "all_matured_distinct_events": len(matured_events),
                "all_matured_rows": matured_rows,
            }
        )
    _write_csv(
        dataset / "outcome_and_event_reconciliation.csv",
        list(event_rows[0]),
        event_rows,
    )

    # Feature eligibility
    feature_rows = []
    for index, cutoff in enumerate(CUTOFFS):
        available = index == 2
        risk_size = len(reasons[cutoff]["ELIGIBLE_AT_RISK"])
        feature_rows.append(
            {
                "cutoff_T": cutoff.isoformat(),
                "revision_sha": _fake_sha(f"revision-{cutoff}"),
                "risk_set_size": risk_size,
                "cvss_available_exact": 20,
                "cvss_available_cna_only": 18,
                "cvss_unavailable": risk_size - 20,
                "cvss_coverage_pct": f"{100.0 * 20 / risk_size:.2f}",
                "cvss_evidence": "EXACT_CENSUS_AT_PINNED_REVISION",
                "epss_availability_verdict": (
                    "HISTORICALLY_AVAILABLE" if available else "BACKFILLED_AFTER_CUTOFF"
                ),
                "epss_risk_rows_with_score": 35 if available else "",
                "epss_evidence": "EXACT_FILE_AT_T" if available else "NOT_HISTORICALLY_AVAILABLE_AT_T",
                "state_published": 30,
                "state_non_published": risk_size - 30,
                "state_missing": 0,
                "date_published_after_T": 0,
            }
        )
    _write_csv(
        dataset / "point_in_time_feature_eligibility.csv",
        list(feature_rows[0]),
        feature_rows,
    )

    # Census index
    census_rows = []
    for cutoff in CUTOFFS:
        count = len(inventory[cutoff])
        census_rows.append(
            {
                "cutoff_T": cutoff.isoformat(),
                "revision_expected_records": count,
                "census_record_members": count,
                "distinct_cve_ids": count,
                "completeness_match": "True",
                "duplicate_ids": 0,
                "parse_errors": 0,
                "non_record_members": 2,
                "census_bytes": 1000 + count,
                "census_sha256": _sha_text(f"census-{cutoff}"),
                "staged_path": f"/tmp/fixture/census_{cutoff}.jsonl.gz",
            }
        )
    _write_csv(dataset / "evidence" / "census_index.csv", list(census_rows[0]), census_rows)

    # EPSS availability
    epss_rows = []
    for index, cutoff in enumerate(CUTOFFS):
        available = index == 2
        added = cutoff if available else dt.date(2026, 2, 3)
        epss_rows.append(
            {
                "availability_verdict": (
                    "HISTORICALLY_AVAILABLE" if available else "BACKFILLED_AFTER_CUTOFF"
                ),
                "backfill_lag_days": (added - cutoff).days,
                "cutoff_T": cutoff.isoformat(),
                "eligible_at_T": "YES" if available else "NO",
                "epss_coverage_pct": "94.59" if available else "",
                "epss_file": f"epss_scores-{cutoff}.csv.gz",
                "epss_header_score_date": (
                    f"{cutoff.isoformat()}T12:00:00Z" if available else ""
                ),
                "epss_model_version": "v2025.03.14" if available else "",
                "epss_score_date": cutoff.isoformat(),
                "file_add_commit_iso": (
                    dt.datetime.combine(
                        added, dt.time(12, 0), tzinfo=dt.timezone.utc
                    ).isoformat()
                ),
                "file_add_commit_sha": _fake_sha(f"epss-{cutoff}"),
                "repository_path": f"{cutoff.year}/epss_scores-{cutoff}.csv.gz",
                "risk_set_size": len(reasons[cutoff]["ELIGIBLE_AT_RISK"]) if available else "",
                "risk_with_epss_score": 35 if available else "",
                "source": "github.com/empiricalsec/epss_scores",
            }
        )
    _write_csv(
        dataset / "evidence" / "epss_availability_evidence.csv",
        list(epss_rows[0]),
        epss_rows,
    )
    _write_json(
        dataset / "evidence" / "epss_evidence_summary.json",
        {
            "backfilled_files": 2,
            "cutoffs_backfilled_only": 2,
            "cutoffs_historically_available": 1,
            "cutoffs_total": 3,
            "daily_files": 3,
            "file_range": ["2025-02-01", "2026-04-01"],
            "first_same_day_evidence": "2026-04-01",
            "same_day_committed_files": 1,
        },
    )

    # KEV revisions and first-seen
    revisions = []
    added = [4, 52, 52]
    removed = [0, 4, 0]
    commit_dates = [
        dt.datetime(2025, 1, 30, 12, 0, tzinfo=dt.timezone.utc),
        dt.datetime(2025, 8, 30, 12, 0, tzinfo=dt.timezone.utc),
        dt.datetime.combine(source_end, dt.time(18, 0), tzinfo=dt.timezone.utc),
    ]
    for index, commit in enumerate(commit_dates):
        revisions.append(
            {
                "commit_sha": _fake_sha(f"kev-commit-{index}"),
                "commit_date": commit.isoformat(),
                "blob_sha": _fake_sha(f"kev-blob-{index}"),
                "content_sha256": _sha_text(f"kev-content-{index}"),
                "entry_count": 100 + index,
                "parsed_entry_count": 100 + index,
                "catalog_version": f"2025.0{index + 1}.01",
                "date_released": commit.date().isoformat(),
                "max_date_added": commit.date().isoformat(),
                "added_since_previous": added[index],
                "removed_since_previous": removed[index],
            }
        )
    _write_csv(dataset / "raw" / "kev_revisions.csv", list(revisions[0]), revisions)
    _write_gzip_lines(
        dataset / "raw" / "kev_first_seen.jsonl.gz",
        [
            json.dumps(
                {
                    "cve_id": cve_id,
                    "first_observed": dt.datetime.combine(
                        observed, dt.time(12, 0), tzinfo=dt.timezone.utc
                    ).isoformat(),
                },
                sort_keys=True,
            )
            for cve_id, observed in sorted(first_seen.items())
        ],
    )
    _write_json(
        dataset / "raw" / "kev_timeline_summary.json",
        {
            "catalog_path": "known_exploited_vulnerabilities.json",
            "commit_days_span": None,
            "distinct_cves_ever_listed": len(first_seen),
            "first_entry_count": 100,
            "first_revision": commit_dates[0].isoformat(),
            "last_entry_count": 104,
            "last_revision": commit_dates[-1].isoformat(),
            "readable_revisions": len(revisions),
            "removal_verdict": "REMOVALS_OBSERVED",
            "removals": [
                {
                    "cve_id": cve_id,
                    "commit_date": "2025-10-22T18:09:14+00:00",
                    "commit": _fake_sha(f"removal-{cve_id}"),
                    "previous_revision_date": "2025-10-21T19:05:29+00:00",
                }
                for cve_id in REMOVED_CVES
            ],
            "revisions": len(revisions),
            "total_additions": sum(added),
            "total_removals": sum(removed),
            "unique_catalog_blobs": len(revisions),
            "unparseable_revision_count": 0,
            "unparseable_revisions": [],
        },
    )

    # Membership partitions and inventory identifier lists
    membership_dir = dataset / "risk_set_membership"
    membership_dir.mkdir(parents=True, exist_ok=True)
    index_rows = []
    for cutoff in CUTOFFS:
        partition = membership_dir / f"cutoff_{cutoff.isoformat()}.csv.gz"
        _write_gzip_lines(
            partition,
            ["cve_id,cutoff_T,eligibility_reason_code"]
            + [
                f"{cve_id},{cutoff.isoformat()},{reason}"
                for reason, ids in reasons[cutoff].items()
                for cve_id in ids
            ],
        )
        if corrupt_partition_at == cutoff:
            raw = bytearray(partition.read_bytes())
            raw[-1] ^= 0xFF
            partition.write_bytes(bytes(raw))
        if missing_partition_at == cutoff:
            partition.unlink()
        partition_bytes = (
            partition.stat().st_size if partition.is_file() else 0
        )
        if missing_partition_at == cutoff:
            partition_sha = _sha_text(f"missing-{cutoff}")
        elif corrupt_partition_at == cutoff:
            partition_sha = _sha_text(f"corrupt-{cutoff}")
        else:
            partition_sha = hashlib.sha256(partition.read_bytes()).hexdigest()
        index_rows.append(
            {
                "cutoff_T": cutoff.isoformat(),
                "risk_set_size": len(reasons[cutoff]["ELIGIBLE_AT_RISK"]),
                "records_total": len(inventory[cutoff]),
                "partition": f"risk_set_membership/cutoff_{cutoff.isoformat()}.csv.gz",
                "partition_bytes": partition_bytes,
                "partition_sha256": partition_sha,
                "reason_counts": ";".join(
                    f"{reason}={len(ids)}" for reason, ids in reasons[cutoff].items()
                ),
            }
        )
        _write_gzip_lines(
            dataset / "inventory" / "inventory_ids" / f"cutoff_{cutoff.isoformat()}.txt.gz",
            inventory[cutoff],
        )
    if not missing_membership_index:
        _write_csv(membership_dir / "INDEX.csv", list(index_rows[0]), index_rows)

    # Split feasibility table (only what the checks consume)
    split_rows = []
    for design_id, roles in (
        (
            "A2_EARLIEST_3BLOCK",
            [("BLOCK1", CUTOFFS[0]), ("BLOCK2", CUTOFFS[1]), ("BLOCK3", CUTOFFS[2])],
        ),
        (
            "E_LABEL_MATURED_2BLOCK",
            [("BLOCK1", CUTOFFS[0]), ("BLOCK2", CUTOFFS[1])],
        ),
    ):
        for role, cutoff in roles:
            split_rows.append(
                {
                    "split_id": design_id,
                    "design_family": "fixture",
                    "block": role,
                    "cutoffs": cutoff.isoformat(),
                    "n_cutoffs": 1,
                    "distinct_events": len(events[cutoff]),
                    "gate_required": 30,
                    "block_meets_gate": "YES",
                    "all_cutoffs_matured": "YES" if matured_flags[cutoff] else "NO",
                    "label_maturity_date": (cutoff + dt.timedelta(days=210)).isoformat(),
                    "next_block_decision_point": "",
                    "labels_matured_before_next_block": "NOT_APPLICABLE",
                    "maturity_slack_days": "",
                    "purge_days": 0,
                    "shares_events_with": "",
                    "independence_verdict": "INDEPENDENT_DISJOINT_EVENT_SETS",
                    "note": "fixture",
                    "split_verdict": "FIXTURE",
                    "usable_as_historical_split": "YES",
                }
            )
    _write_csv(
        dataset / "temporal_split_feasibility.csv",
        list(split_rows[0]),
        split_rows,
    )

    # Facts and quality summary
    facts = {
        "cutoffs": len(CUTOFFS),
        "distinct_events_all_cutoffs": len(distinct_events),
        "distinct_events_all_matured": len(matured_events),
        "kev_additions_total": sum(added),
        "kev_distinct_ever_listed": len(first_seen),
        "kev_removals_total": sum(removed),
        "kev_unparseable_revisions": 0,
        "matured_cutoffs": len(matured_cutoffs),
        "risk_set_max": max(len(reasons[c]["ELIGIBLE_AT_RISK"]) for c in CUTOFFS),
        "risk_set_min": min(len(reasons[c]["ELIGIBLE_AT_RISK"]) for c in CUTOFFS),
        "risk_set_sum_unique_pairs": sum(
            len(reasons[c]["ELIGIBLE_AT_RISK"]) for c in CUTOFFS
        ),
        "split_candidates": 2,
    }
    _write_json(dataset / "_facts_3k.json", facts)
    _write_json(
        dataset / "phase2_3k_quality_summary.json",
        {
            "phase": "fixture",
            "reference_date": reference_date.isoformat(),
            "decision": "FIXTURE_ONLY",
            "constants_preserved": {
                "changed_from_prior_phases": False,
                "cutoff_count": len(CUTOFFS),
                "cutoff_end": CUTOFFS[-1].isoformat(),
                "cutoff_start": CUTOFFS[0].isoformat(),
                "horizon_days": 180,
                "maturity_lag_days": 30,
                "maturity_offset_days": 210,
                "test_event_gate": 30,
            },
            "features": {
                "missing_stays_missing": True,
                "substitutes_invented": False,
                "membership_kept_separate_from_feature_availability": True,
            },
            "kev_timeline": {
                "additions": sum(added),
                "removals": sum(removed),
                "distinct_cves_ever_listed": len(first_seen),
                "refutes_prior_phase": "fixture preserves 498/4 semantics for tests",
                "removal_verdict": "REMOVALS_OBSERVED",
                "unparseable_revisions": 0,
            },
            "outcome_reconciliation": {
                "distinct_events_all_cutoffs": len(distinct_events),
                "matured_distinct_events": len(matured_events),
                "matured_event_rows": matured_rows,
                "reuse_factor": 1.0,
                "kev_absence_not_treated_as_non_exploitation": True,
            },
            "prohibitions_observed": {
                "artifacts_uploaded_or_pushed": False,
                "confirmatory_no_go_lifted": False,
                "estimates_substituted_for_counts": False,
                "gates_relaxed": False,
                "missing_inputs_fabricated": False,
                "model_trained": False,
                "model_tuned": False,
                "predictive_evaluation_run": False,
                "protocol_amendment_approved": False,
            },
            "limitations": [
                "The Phase 2.3F source directory is UNAVAILABLE in this fixture.",
                "The Phase 2.3G source directory is UNAVAILABLE in this fixture.",
            ],
        },
    )
    _write_json(
        dataset / "inventory_method.json",
        {
            "clone_command": "fixture",
            "clone_head": _fake_sha("clone-head"),
            "clone_repo": "https://github.com/CVEProject/cvelistV5.git",
            "commit_count": 3,
            "covers_all_cutoffs": True,
            "cutoffs": len(CUTOFFS),
            "enumeration_method": "git ls-tree -r",
            "oldest_commit_in_clone": "2025-01-20T01:16:09+00:00",
            "resolved": len(CUTOFFS),
            "shallow_file_present": True,
            "truncation_risk": "none in fixture",
        },
    )
    (dataset / "VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md").write_text(
        "# Fixture report\n\nKEV is not exhaustive; catalog absence is never treated as "
        "proof that a vulnerability was not exploited.\n\nPhase 2.3F and Phase 2.3G are "
        "UNAVAILABLE in this fixture.\n",
        encoding="utf-8",
    )

    # Protocol file
    protocol_dir = root / "protocol"
    protocol_dir.mkdir(parents=True, exist_ok=True)
    protocol = _protocol_payload(reference_date, approved, adopted_design)
    protocol_path = protocol_dir / "evaluation_protocol.json"
    _write_json(protocol_path, protocol)

    # Integrity manifest last, self-excluded
    entries = []
    for path in sorted(dataset.rglob("*")):
        if not path.is_file() or path.name == "phase2_3k_integrity_manifest.json":
            continue
        entries.append(
            {
                "path": str(path.relative_to(dataset)),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "group": "fixture",
            }
        )
    _write_json(
        dataset / "phase2_3k_integrity_manifest.json",
        {
            "file_count": len(entries),
            "files": entries,
            "generated_utc": (
                dt.datetime.combine(
                    reference_date + dt.timedelta(days=1),
                    dt.time(0, 0),
                    tzinfo=dt.timezone.utc,
                ).isoformat()
            ),
            "phase": "fixture",
            "reference_date": reference_date.isoformat(),
            "self_excluded": "phase2_3k_integrity_manifest.json",
            "total_bytes": sum(item["bytes"] for item in entries),
        },
    )

    options = ReadinessOptions(
        artifact_dir=root,
        protocol_path=protocol_path,
        as_of=None,
        deep=True,
        export_archive=root / "no-export.tar.gz",
        core_bundle=root / "no-core.tar.gz",
        extract_dir=root / "build",
        previous_report_path=None,
        repository_root=root,
        extract=False,
    )
    return Fixture(
        root=root,
        dataset=dataset,
        protocol=protocol_path,
        reference_date=reference_date,
        source_end=source_end,
        events_by_cutoff=events,
        options=options,
    )


def _protocol_payload(
    reference_date: dt.date, approved: bool, adopted_design: Optional[str]
) -> dict:
    real = Path(__file__).resolve().parents[1] / "protocol" / "evaluation_protocol.json"
    payload = json.loads(real.read_text(encoding="utf-8"))
    payload["reference_date"] = reference_date.isoformat()
    payload["approval"] = {
        "state": "APPROVED" if approved else "NOT_APPROVED",
        "required_from": "project_owner",
        "approved_by": "Fixture Owner" if approved else None,
        "approved_on": (reference_date - dt.timedelta(days=1)).isoformat() if approved else None,
        "approval_reference": "FIXTURE-APPROVAL-1" if approved else None,
        "note": "fixture protocol",
    }
    payload["adopted_design"] = adopted_design if approved else None
    payload["candidate_designs"] = [
        {
            "id": "A2_EARLIEST_3BLOCK",
            "title": "fixture three-block",
            "kind": "sequential",
            "adoption_status": "CANDIDATE_NOT_ADOPTED",
            "blocks": [
                {"role": "BLOCK1", "cutoffs": [CUTOFFS[0].isoformat()]},
                {"role": "BLOCK2", "cutoffs": [CUTOFFS[1].isoformat()]},
                {"role": "BLOCK3", "cutoffs": [CUTOFFS[2].isoformat()]},
            ],
        },
        {
            "id": "E_LABEL_MATURED_2BLOCK",
            "title": "fixture two-block",
            "kind": "sequential",
            "adoption_status": "CANDIDATE_NOT_ADOPTED",
            "blocks": [
                {"role": "BLOCK1", "cutoffs": [CUTOFFS[0].isoformat()]},
                {"role": "BLOCK2", "cutoffs": [CUTOFFS[1].isoformat()]},
            ],
        },
    ]
    return payload
