"""Readers for the Phase 2.3K research export.

The export is treated as read-only evidence.  Every loader is defensive: a
missing or malformed file is recorded in ``errors`` and the dependent checks
report BLOCKED/FAIL rather than crashing the whole command.
"""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


class DatasetError(RuntimeError):
    pass


def _read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _read_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise DatasetError(f"expected a JSON object: {path}")
    return payload


def _read_jsonl_gz(path: Path) -> list[dict]:
    rows = []
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integers(row: dict, key: str, default: Optional[int] = None) -> Optional[int]:
    value = row.get(key)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def floats(row: dict, key: str) -> Optional[float]:
    value = row.get(key)
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass
class Dataset:
    root: Path
    export_root: Optional[Path] = None
    errors: dict[str, str] = field(default_factory=dict)
    cutoffs: list[dt.date] = field(default_factory=list)
    inventory_manifest: list[dict] = field(default_factory=list)
    denominators: list[dict] = field(default_factory=list)
    outcomes: list[dict] = field(default_factory=list)
    splits: list[dict] = field(default_factory=list)
    features: list[dict] = field(default_factory=list)
    census: list[dict] = field(default_factory=list)
    epss_availability: list[dict] = field(default_factory=list)
    epss_summary: dict = field(default_factory=dict)
    kev_revisions: list[dict] = field(default_factory=list)
    kev_first_seen_rows: list[dict] = field(default_factory=list)
    kev_timeline_summary: dict = field(default_factory=dict)
    quality_summary: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    index: list[dict] = field(default_factory=list)
    integrity_manifest: dict = field(default_factory=dict)
    inventory_method: dict = field(default_factory=dict)
    report_text: str = ""

    # ------------------------------------------------------------------ paths
    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def has(self, *parts: str) -> bool:
        return self.path(*parts).is_file()

    @property
    def has_membership(self) -> bool:
        return self.has("risk_set_membership", "INDEX.csv")

    @property
    def has_inventory_ids(self) -> bool:
        return self.path("inventory", "inventory_ids").is_dir()

    # --------------------------------------------------------------- lookups
    @property
    def denominator_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.denominators}

    @property
    def outcome_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.outcomes}

    @property
    def feature_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.features}

    @property
    def inventory_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.inventory_manifest}

    @property
    def index_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.index}

    @property
    def census_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.census}

    @property
    def epss_by_cutoff(self) -> dict[str, dict]:
        return {row.get("cutoff_T", ""): row for row in self.epss_availability}

    @property
    def first_seen_day(self) -> dict[str, dt.date]:
        result = {}
        for row in self.kev_first_seen_rows:
            cve_id = row.get("cve_id")
            observed = row.get("first_observed")
            if not cve_id or not observed:
                continue
            try:
                result[cve_id] = dt.date.fromisoformat(observed[:10])
            except ValueError:
                continue
        return result

    @property
    def first_seen_instant(self) -> dict[str, dt.datetime]:
        result = {}
        for row in self.kev_first_seen_rows:
            cve_id = row.get("cve_id")
            observed = row.get("first_observed")
            if not cve_id or not observed:
                continue
            text = observed[:-1] + "+00:00" if observed.endswith("Z") else observed
            try:
                result[cve_id] = dt.datetime.fromisoformat(text)
            except ValueError:
                continue
        return result

    @property
    def events_by_cutoff(self) -> tuple[dict[dt.date, set[str]], list[dict]]:
        """Return ``{cutoff: set(event ids)}`` and a list of parse problems."""
        events: dict[dt.date, set[str]] = {}
        problems: list[dict] = []
        for row in self.outcomes:
            cutoff_text = row.get("cutoff_T", "")
            try:
                cutoff = dt.date.fromisoformat(cutoff_text)
            except ValueError:
                problems.append({"cutoff": cutoff_text, "problem": "BAD_CUTOFF"})
                continue
            ids = [item.strip() for item in row.get("event_ids", "").split(";") if item.strip()]
            expected = integers(row, "eligible_events")
            if expected is not None and expected != len(ids):
                problems.append(
                    {
                        "cutoff": cutoff_text,
                        "problem": "EVENT_COUNT_MISMATCH",
                        "declared": expected,
                        "parsed": len(ids),
                    }
                )
            if len(ids) != len(set(ids)):
                problems.append(
                    {
                        "cutoff": cutoff_text,
                        "problem": "DUPLICATE_EVENT_ID_IN_CELL",
                        "duplicates": len(ids) - len(set(ids)),
                    }
                )
            events[cutoff] = set(ids)
        return events, problems

    @property
    def source_coverage_end(self) -> Optional[dt.date]:
        """Latest KEV catalog revision day available in the served timeline."""
        days = []
        for row in self.kev_revisions:
            value = row.get("commit_date")
            if not value:
                continue
            try:
                days.append(dt.date.fromisoformat(value[:10]))
            except ValueError:
                continue
        for row in self.kev_first_seen_rows:
            value = row.get("first_observed")
            if value:
                try:
                    days.append(dt.date.fromisoformat(value[:10]))
                except ValueError:
                    pass
        last = self.kev_timeline_summary.get("last_revision")
        if last:
            try:
                days.append(dt.date.fromisoformat(str(last)[:10]))
            except ValueError:
                pass
        return max(days) if days else None

    # ---------------------------------------------------------------- inputs
    def key_files(self) -> list[Path]:
        names = [
            "cvelistv5_inventory_manifest.csv",
            "risk_set_denominator_summary.csv",
            "outcome_and_event_reconciliation.csv",
            "temporal_split_feasibility.csv",
            "point_in_time_feature_eligibility.csv",
            "phase2_3k_quality_summary.json",
            "phase2_3k_integrity_manifest.json",
            "_facts_3k.json",
            "cutoffs.txt",
            "inventory_method.json",
            "evidence/census_index.csv",
            "evidence/epss_availability_evidence.csv",
            "evidence/epss_evidence_summary.json",
            "raw/kev_revisions.csv",
            "raw/kev_first_seen.jsonl.gz",
            "raw/kev_timeline_summary.json",
            "risk_set_membership/INDEX.csv",
        ]
        return [self.path(name) for name in names if self.path(name).is_file()]


def locate_dataset_root(root: Path | str) -> tuple[Path, Optional[Path]]:
    """Return ``(dataset_dir, export_root)`` for a core bundle or full export."""
    root = Path(root)
    if (root / "phase2_3k").is_dir():
        return root / "phase2_3k", root
    if (root / "cvelistv5_inventory_manifest.csv").is_file():
        return root, None
    matches = sorted(root.glob("*/phase2_3k"))
    if len(matches) == 1:
        return matches[0], matches[0].parent
    raise DatasetError(
        "no Phase 2.3K dataset found at "
        f"{root}; expected phase2_3k/ or cvelistv5_inventory_manifest.csv"
    )


def load_dataset(root: Path | str) -> Dataset:
    dataset_root, export_root = locate_dataset_root(root)
    dataset = Dataset(root=dataset_root, export_root=export_root)

    def load_csv(relative: str, attribute: str) -> None:
        path = dataset.path(relative)
        if not path.is_file():
            dataset.errors[relative] = "missing"
            return
        try:
            setattr(dataset, attribute, _read_csv(path))
        except (OSError, csv.Error, UnicodeDecodeError) as exc:
            dataset.errors[relative] = f"{type(exc).__name__}: {exc}"

    def load_json(relative: str, attribute: str) -> None:
        path = dataset.path(relative)
        if not path.is_file():
            dataset.errors[relative] = "missing"
            return
        try:
            setattr(dataset, attribute, _read_json(path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            dataset.errors[relative] = f"{type(exc).__name__}: {exc}"

    load_csv("cvelistv5_inventory_manifest.csv", "inventory_manifest")
    load_csv("risk_set_denominator_summary.csv", "denominators")
    load_csv("outcome_and_event_reconciliation.csv", "outcomes")
    load_csv("temporal_split_feasibility.csv", "splits")
    load_csv("point_in_time_feature_eligibility.csv", "features")
    load_csv("evidence/census_index.csv", "census")
    load_csv("evidence/epss_availability_evidence.csv", "epss_availability")
    load_csv("raw/kev_revisions.csv", "kev_revisions")
    load_csv("risk_set_membership/INDEX.csv", "index")
    load_json("phase2_3k_quality_summary.json", "quality_summary")
    load_json("_facts_3k.json", "facts")
    load_json("phase2_3k_integrity_manifest.json", "integrity_manifest")
    load_json("raw/kev_timeline_summary.json", "kev_timeline_summary")
    load_json("evidence/epss_evidence_summary.json", "epss_summary")
    load_json("inventory_method.json", "inventory_method")

    first_seen_path = dataset.path("raw", "kev_first_seen.jsonl.gz")
    if first_seen_path.is_file():
        try:
            dataset.kev_first_seen_rows = _read_jsonl_gz(first_seen_path)
        except (OSError, EOFError, ValueError, gzip.BadGzipFile) as exc:
            dataset.errors["raw/kev_first_seen.jsonl.gz"] = f"{type(exc).__name__}: {exc}"
    else:
        dataset.errors["raw/kev_first_seen.jsonl.gz"] = "missing"

    cutoffs_path = dataset.path("cutoffs.txt")
    if cutoffs_path.is_file():
        try:
            values = [
                line.strip()
                for line in cutoffs_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            dataset.cutoffs = [dt.date.fromisoformat(value) for value in values]
        except (OSError, ValueError) as exc:
            dataset.errors["cutoffs.txt"] = f"{type(exc).__name__}: {exc}"
    else:
        dataset.errors["cutoffs.txt"] = "missing"
        dataset.cutoffs = sorted(
            dt.date.fromisoformat(row["cutoff_T"])
            for row in dataset.denominators
            if row.get("cutoff_T")
        )

    report_path = dataset.path("VULNOVA_Phase2.3K_Risk_Set_and_Feasibility_Report.md")
    if report_path.is_file():
        try:
            dataset.report_text = report_path.read_text(encoding="utf-8")
        except OSError as exc:
            dataset.errors[report_path.name] = f"{type(exc).__name__}: {exc}"

    return dataset


@dataclass
class PartitionScan:
    cutoff: str
    partition: str
    partition_sha256: Optional[str] = None
    partition_bytes: Optional[int] = None
    indexed_sha256: Optional[str] = None
    indexed_bytes: Optional[int] = None
    checksum_matches: Optional[bool] = None
    bytes_match: Optional[bool] = None
    rows: int = 0
    unique_ids: int = 0
    duplicate_ids: int = 0
    reason_counts: dict[str, int] = field(default_factory=dict)
    cutoff_column_mismatches: int = 0
    inventory_rows: int = 0
    inventory_unique_ids: int = 0
    inventory_duplicates: int = 0
    membership_not_in_inventory: int = 0
    event_reasons: dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "cutoff": self.cutoff,
            "partition": self.partition,
            "partition_sha256": self.partition_sha256,
            "partition_bytes": self.partition_bytes,
            "indexed_sha256": self.indexed_sha256,
            "indexed_bytes": self.indexed_bytes,
            "checksum_matches": self.checksum_matches,
            "bytes_match": self.bytes_match,
            "rows": self.rows,
            "unique_ids": self.unique_ids,
            "duplicate_ids": self.duplicate_ids,
            "reason_counts": dict(sorted(self.reason_counts.items())),
            "cutoff_column_mismatches": self.cutoff_column_mismatches,
            "inventory_rows": self.inventory_rows,
            "inventory_unique_ids": self.inventory_unique_ids,
            "inventory_duplicates": self.inventory_duplicates,
            "membership_not_in_inventory": self.membership_not_in_inventory,
            "event_reasons": dict(sorted(self.event_reasons.items())),
            "error": self.error,
        }


def _read_inventory_ids(path: Path) -> tuple[set[str], int, int]:
    ids: set[str] = set()
    rows = 0
    duplicates = 0
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value:
                continue
            rows += 1
            if value in ids:
                duplicates += 1
            else:
                ids.add(value)
    return ids, rows, duplicates


def scan_memberships(
    dataset: Dataset,
    events_by_cutoff: dict[dt.date, Iterable[str]],
) -> tuple[dict[str, PartitionScan], list[dict]]:
    """Scan every membership partition once, checking it against its index.

    This is the expensive part of a readiness run (~10 s for 6.85 M rows).  It
    validates the archive's own claims rather than trusting the summary CSV.
    """
    scans: dict[str, PartitionScan] = {}
    problems: list[dict] = []
    if not dataset.has_membership:
        return scans, [{"problem": "MEMBERSHIP_UNAVAILABLE"}]
    if not dataset.has_inventory_ids:
        return scans, [{"problem": "INVENTORY_IDS_UNAVAILABLE"}]

    for index_row in dataset.index:
        cutoff_text = index_row.get("cutoff_T", "")
        scan = PartitionScan(cutoff=cutoff_text, partition=index_row.get("partition", ""))
        scans[cutoff_text] = scan
        partition = dataset.path(index_row.get("partition", ""))
        scan.indexed_sha256 = index_row.get("partition_sha256")
        scan.indexed_bytes = integers(index_row, "partition_bytes")
        if not partition.is_file():
            scan.error = "partition missing"
            problems.append({"cutoff": cutoff_text, "problem": "PARTITION_MISSING"})
            continue
        try:
            scan.partition_bytes = partition.stat().st_size
            scan.partition_sha256 = sha256_file(partition)
        except OSError as exc:
            scan.error = f"{type(exc).__name__}: {exc}"
            problems.append({"cutoff": cutoff_text, "problem": "PARTITION_UNREADABLE"})
            continue
        scan.checksum_matches = scan.partition_sha256 == scan.indexed_sha256
        scan.bytes_match = scan.partition_bytes == scan.indexed_bytes
        if not scan.checksum_matches:
            problems.append({"cutoff": cutoff_text, "problem": "PARTITION_CHECKSUM_MISMATCH"})

        inventory_path = dataset.path(
            "inventory", "inventory_ids", f"cutoff_{cutoff_text}.txt.gz"
        )
        if not inventory_path.is_file():
            scan.error = "inventory id list missing"
            problems.append({"cutoff": cutoff_text, "problem": "INVENTORY_IDS_MISSING"})
            continue
        try:
            inventory_ids, inventory_rows, inventory_duplicates = _read_inventory_ids(
                inventory_path
            )
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            scan.error = f"inventory: {type(exc).__name__}: {exc}"
            problems.append({"cutoff": cutoff_text, "problem": "INVENTORY_IDS_UNREADABLE"})
            continue
        scan.inventory_rows = inventory_rows
        scan.inventory_unique_ids = len(inventory_ids)
        scan.inventory_duplicates = inventory_duplicates

        wanted_events = {str(item) for item in events_by_cutoff.get(
            _safe_date(cutoff_text), set()
        )}
        seen: set[str] = set()
        reason_counts: dict[str, int] = {}
        cutoff_mismatches = 0
        not_in_inventory = 0
        try:
            with gzip.open(partition, "rt", encoding="utf-8", newline="") as handle:
                reader = csv.reader(handle)
                header = next(reader, None)
                if header != ["cve_id", "cutoff_T", "eligibility_reason_code"]:
                    scan.error = f"unexpected header: {header!r}"
                    problems.append(
                        {"cutoff": cutoff_text, "problem": "PARTITION_HEADER_UNEXPECTED"}
                    )
                    continue
                for row in reader:
                    if len(row) != 3:
                        problems.append(
                            {"cutoff": cutoff_text, "problem": "PARTITION_ROW_MALFORMED"}
                        )
                        continue
                    cve_id, row_cutoff, reason = row
                    scan.rows += 1
                    if row_cutoff != cutoff_text:
                        cutoff_mismatches += 1
                    if cve_id in seen:
                        scan.duplicate_ids += 1
                    else:
                        seen.add(cve_id)
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
                    if cve_id not in inventory_ids:
                        not_in_inventory += 1
                    if cve_id in wanted_events:
                        scan.event_reasons[cve_id] = reason
        except (OSError, EOFError, gzip.BadGzipFile, csv.Error) as exc:
            scan.error = f"membership: {type(exc).__name__}: {exc}"
            problems.append({"cutoff": cutoff_text, "problem": "PARTITION_UNREADABLE"})
            continue

        scan.unique_ids = len(seen)
        scan.reason_counts = reason_counts
        scan.cutoff_column_mismatches = cutoff_mismatches
        scan.membership_not_in_inventory = not_in_inventory
    return scans, problems


def _safe_date(value: str) -> Optional[dt.date]:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _display_path(path: Path, relative_to: Optional[Path]) -> str:
    resolved = path.resolve()
    if relative_to is not None:
        try:
            return str(resolved.relative_to(Path(relative_to).resolve()))
        except ValueError:
            # Inputs outside the repository (for example a fixture in a temporary
            # directory) are still fingerprinted, just not made relative.
            return str(resolved)
    return str(path)


def input_fingerprints(paths: Iterable[Path], relative_to: Optional[Path] = None) -> list[dict]:
    records = []
    for path in sorted({Path(item) for item in paths}):
        if not path.is_file():
            continue
        record = {
            "path": _display_path(path, relative_to),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        records.append(record)
    return records
