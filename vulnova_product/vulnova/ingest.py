"""Ingest CLI.

Every stage writes an ``ingest_run`` row so the reconciliation numbers are
queryable after the fact.  The same numbers are printed as JSON on stdout for
the receipt under ``reports/ingest_receipts/``.

    python -m vulnova.ingest --store build/vulnova.db \
        --legacy ../cve.csv.zip \
        --cvelistv5-root /tmp/cvel2020_2023 --cve-from 2020-01-01 \
        --pre2020-root /tmp/cvel_pre2020 \
        --kev data/snapshots/kev/known_exploited_vulnerabilities.json \
        --kev-revision 6a392940c663b52271fa4e6aa7b39995b18c9a71 \
        --epss data/snapshots/epss/epss_scores-2026-10-16.csv.gz
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import store
from .provenance import utc_now
from .sources import cvelistv5, epss, kev, legacy_csv

BATCH = 5000


def _start_run(conn, *, source, stage, revision, retrieved_at, sha,
               window_from=None, window_to=None, note=None) -> int:
    cur = conn.execute(
        "INSERT INTO ingest_run (source, stage, source_revision, retrieved_at,"
        " content_sha256, window_from, window_to, note)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (source, stage, revision, retrieved_at, sha, window_from, window_to, note),
    )
    return cur.lastrowid


def _finish_run(conn, run_id, counters):
    conn.execute(
        "UPDATE ingest_run SET records_in=?, records_new=?, records_existing=?,"
        " records_duplicate=?, records_rejected=?, records_skipped=? WHERE run_id=?",
        (
            counters["records_in"],
            counters["records_new"],
            counters["records_existing"],
            counters["records_duplicate"],
            counters["records_rejected"],
            counters["records_skipped"],
            run_id,
        ),
    )


def _blank():
    return {
        "records_in": 0,
        "records_new": 0,
        "records_existing": 0,
        "records_duplicate": 0,
        "records_rejected": 0,
        "records_skipped": 0,
    }


def load_kev(conn, path, *, revision, retrieved_at=None):
    retrieved_at = retrieved_at or utc_now()
    payload = kev.load(path, revision=revision, retrieved_at=retrieved_at)
    meta = payload["meta"]
    counters = _blank()
    run_id = _start_run(
        conn, source="kev", stage="catalog", revision=meta["revision"],
        retrieved_at=retrieved_at, sha=meta["content_sha256"],
    )
    rows = []
    for cve_id, entry in payload["entries"].items():
        counters["records_in"] += 1
        rows.append(
            (
                cve_id, entry["date_added"], entry["vendor"], entry["product"],
                entry["name"], int(entry["ransom_known"]), meta["revision"],
                retrieved_at,
            )
        )
    conn.executemany(
        "INSERT INTO kev (cve_id, date_added, vendor, product, name, ransom_known,"
        " source_revision, retrieved_at) VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(cve_id) DO UPDATE SET date_added=excluded.date_added,"
        " vendor=excluded.vendor, product=excluded.product, name=excluded.name,"
        " ransom_known=excluded.ransom_known, source_revision=excluded.source_revision,"
        " retrieved_at=excluded.retrieved_at",
        rows,
    )
    counters["records_new"] = len(rows)
    _finish_run(conn, run_id, counters)
    conn.commit()
    return {"stage": "kev_catalog", "meta": meta, "counters": counters}


def load_epss(conn, path, *, retrieved_at=None):
    retrieved_at = retrieved_at or utc_now()
    payload = epss.load(path, retrieved_at=retrieved_at)
    meta = payload["meta"]
    counters = _blank()
    run_id = _start_run(
        conn, source="epss", stage="daily_scores", revision=meta["revision"],
        retrieved_at=retrieved_at, sha=meta["content_sha256"],
        window_from=meta["score_date"], window_to=meta["score_date"],
    )
    batch = []
    for cve_id, probability, percentile in epss.iter_rows(path):
        counters["records_in"] += 1
        batch.append((cve_id, probability, percentile, meta["score_date"],
                      meta["revision"], retrieved_at))
        if len(batch) >= BATCH:
            conn.executemany(
                "INSERT INTO epss (cve_id, probability, percentile, score_date,"
                " model_version, retrieved_at) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(cve_id) DO UPDATE SET probability=excluded.probability,"
                " percentile=excluded.percentile, score_date=excluded.score_date,"
                " model_version=excluded.model_version, retrieved_at=excluded.retrieved_at",
                batch,
            )
            batch.clear()
    if batch:
        conn.executemany(
            "INSERT INTO epss (cve_id, probability, percentile, score_date,"
            " model_version, retrieved_at) VALUES (?,?,?,?,?,?)"
            " ON CONFLICT(cve_id) DO UPDATE SET probability=excluded.probability,"
            " percentile=excluded.percentile, score_date=excluded.score_date,"
            " model_version=excluded.model_version, retrieved_at=excluded.retrieved_at",
            batch,
        )
    counters["records_new"] = counters["records_in"]
    _finish_run(conn, run_id, counters)
    conn.commit()
    return {"stage": "epss_daily", "meta": meta, "counters": counters}


def _insert_record(conn, record, *, source, revision, retrieved_at, existing_ids):
    cve_id = record["cve_id"]
    conn.execute(
        "INSERT INTO cve_record (cve_id, source, source_revision, retrieved_at,"
        " published, updated, state, state_basis, reject_marker, assigner, title,"
        " description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(cve_id, source) DO UPDATE SET"
        " source_revision=excluded.source_revision, retrieved_at=excluded.retrieved_at,"
        " published=excluded.published, updated=excluded.updated, state=excluded.state,"
        " state_basis=excluded.state_basis, reject_marker=excluded.reject_marker,"
        " assigner=excluded.assigner, title=excluded.title, description=excluded.description",
        (
            cve_id, source, revision, retrieved_at, record.get("published"),
            record.get("updated"), record.get("state"),
            record.get("state_basis", "not_stated"), int(bool(record.get("reject_marker"))),
            record.get("assigner"), record.get("title"), record.get("description"),
        ),
    )
    if cve_id in existing_ids:
        conn.execute(
            "DELETE FROM cvss_observation WHERE cve_id=? AND source=?",
            (cve_id, source),
        )

    candidates = record.get("candidates")
    if candidates is None and record.get("cvss") is not None:
        candidates = [{
            "container": "legacy",
            "scoring_organization": None,
            "version": "2.0",
            "value": record["cvss"],
            "severity": None,
            "vector": None,
        }]
    candidates = candidates or []
    if candidates:
        conn.executemany(
            "INSERT INTO cvss_observation (cve_id, source, source_record_id, container,"
            " scoring_organization, version, value, severity, vector, status, retrieved_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    cve_id, source, cve_id, cand["container"], cand["scoring_organization"],
                    cand["version"], cand["value"], cand["severity"], cand["vector"],
                    "OBSERVED" if cand["value"] is not None else "NOT_STATED_BY_SOURCE",
                    retrieved_at,
                )
                for cand in candidates
            ],
        )
    else:
        conn.execute(
            "INSERT INTO cvss_observation (cve_id, source, source_record_id, container,"
            " scoring_organization, version, value, severity, vector, status, retrieved_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (cve_id, source, cve_id, "cna", None, None, None, None, None,
             "MISSING_FROM_SOURCE", retrieved_at),
        )


def _existing_ids(conn, source):
    return {
        row[0]
        for row in conn.execute(
            "SELECT cve_id FROM cve_record WHERE source=?", (source,)
        )
    }


def load_legacy(conn, path, *, retrieved_at=None):
    retrieved_at = retrieved_at or utc_now()
    meta = legacy_csv.meta(path, retrieved_at=retrieved_at)
    counters = _blank()
    run_id = _start_run(
        conn, source="legacy_cve_csv", stage="full_extract", revision=None,
        retrieved_at=retrieved_at, sha=meta["content_sha256"],
        note=meta["note"],
    )
    existing = _existing_ids(conn, "legacy_cve_csv")
    seen = set()
    for row in legacy_csv.iter_rows(path):
        counters["records_in"] += 1
        cve_id = row["cve_id"]
        if cve_id in seen:
            counters["records_duplicate"] += 1
            continue
        seen.add(cve_id)
        if cve_id in existing:
            counters["records_existing"] += 1
        else:
            counters["records_new"] += 1
        record = {
            **row,
            "state": None,
            "state_basis": "not_stated",
            "title": None,
            "assigner": None,
        }
        if row["reject_marker"]:
            counters["records_rejected"] += 1
        _insert_record(
            conn, record, source="legacy_cve_csv", revision=None,
            retrieved_at=retrieved_at, existing_ids=existing,
        )
        if counters["records_in"] % BATCH == 0:
            conn.commit()
    _finish_run(conn, run_id, counters)
    conn.commit()
    meta["duplicate_identifiers"] = counters["records_duplicate"]
    return {"stage": "legacy_extract", "meta": meta, "counters": counters}


def load_cvelistv5(
    conn,
    root,
    *,
    years,
    revision,
    retrieved_at=None,
    published_from=None,
    admit_ids=None,
    stage="window",
    window_from=None,
    window_to=None,
):
    retrieved_at = retrieved_at or utc_now()
    counters = _blank()
    run_id = _start_run(
        conn, source="cvelistv5", stage=stage, revision=revision,
        retrieved_at=retrieved_at, sha=None,
        window_from=window_from, window_to=window_to,
        note=("KEV-admitted pre-window records" if admit_ids is not None else None),
    )
    existing = _existing_ids(conn, "cvelistv5")
    seen = set()
    skipped_undated = 0
    skipped_out_of_window = 0
    admitted = set()

    for year in years:
        for record in cvelistv5.iter_year(root, year):
            counters["records_in"] += 1
            cve_id = record["cve_id"]

            if admit_ids is not None:
                if cve_id not in admit_ids or cve_id in seen:
                    continue
            else:
                published = record.get("published")
                if published_from and (published is None or published < published_from):
                    skipped_out_of_window += 1
                    continue
                if published is None:
                    skipped_undated += 1
                    continue
            if window_to and record.get("published") and record["published"] > window_to:
                skipped_out_of_window += 1
                continue

            if cve_id in seen:
                counters["records_duplicate"] += 1
                continue
            seen.add(cve_id)
            admitted.add(cve_id)
            if cve_id in existing:
                counters["records_existing"] += 1
            else:
                counters["records_new"] += 1
            if record.get("state") == "REJECTED" or record.get("reject_marker"):
                counters["records_rejected"] += 1
            _insert_record(
                conn, record, source="cvelistv5", revision=revision,
                retrieved_at=retrieved_at, existing_ids=existing,
            )
            if len(admitted) % BATCH == 0:
                conn.commit()

    counters["records_skipped"] = skipped_out_of_window + skipped_undated
    _finish_run(conn, run_id, counters)
    conn.commit()
    return {
        "stage": f"cvelistv5_{stage}",
        "meta": {
            "source": "cvelistv5",
            "revision": revision,
            "retrieved_at": retrieved_at,
            "window_from": window_from,
            "window_to": window_to,
            "undated_skipped": skipped_undated,
        },
        "counters": counters,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Ingest VULNOVA sources")
    parser.add_argument("--store", default="build/vulnova.db")
    parser.add_argument(
        "--legacy",
        default=str(Path(__file__).resolve().parents[2] / "cve.csv.zip"),
        help="legacy extract; defaults to cve.csv.zip at the repository root",
    )
    parser.add_argument("--cvelistv5-root", default=None)
    parser.add_argument("--cvelistv5-revision", default=None)
    parser.add_argument("--cve-from", default="2020-01-01")
    parser.add_argument("--cve-to", default=None)
    parser.add_argument("--years", default="2020,2021,2022,2023,2024,2025,2026")
    parser.add_argument("--pre2020-root", default=None)
    parser.add_argument("--pre2020-years", default=None)
    parser.add_argument("--kev", default=None)
    parser.add_argument("--kev-revision", default=None)
    parser.add_argument("--epss", default=None)
    parser.add_argument("--stages", default="kev,epss,legacy,cvelistv5,pre2020")
    parser.add_argument("--receipt", default=None)
    args = parser.parse_args(argv)

    conn = store.initialise(args.store)
    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    receipts = []

    if "kev" in stages:
        if not args.kev:
            raise SystemExit("--kev is required for the kev stage")
        receipts.append(load_kev(conn, args.kev, revision=args.kev_revision))

    if "epss" in stages:
        if not args.epss:
            raise SystemExit("--epss is required for the epss stage")
        receipts.append(load_epss(conn, args.epss))

    if "legacy" in stages:
        receipts.append(load_legacy(conn, args.legacy))

    years = [int(y) for y in args.years.split(",") if y.strip()]

    if "cvelistv5" in stages:
        if not args.cvelistv5_root:
            raise SystemExit("--cvelistv5-root is required for the cvelistv5 stage")
        if not args.cvelistv5_revision:
            raise SystemExit("--cvelistv5-revision is required (pin the source revision)")
        receipts.append(
            load_cvelistv5(
                conn, args.cvelistv5_root, years=years,
                revision=args.cvelistv5_revision,
                published_from=args.cve_from, window_from=args.cve_from,
                window_to=args.cve_to,
            )
        )

    if "pre2020" in stages and args.pre2020_root:
        kev_ids = {row[0] for row in conn.execute("SELECT cve_id FROM kev")}
        pre_years = (
            [int(y) for y in args.pre2020_years.split(",") if y.strip()]
            if args.pre2020_years
            else list(range(1999, 2020))
        )
        receipts.append(
            load_cvelistv5(
                conn, args.pre2020_root, years=pre_years,
                revision=args.cvelistv5_revision,
                admit_ids=kev_ids, stage="kev_members_pre2020",
            )
        )

    payload = {
        "generated_at": utc_now(),
        "store": str(Path(args.store).resolve()),
        "receipts": receipts,
        "counts": store.counts(conn),
        "reference_date": store.reference_date(conn),
    }
    conn.close()

    text = json.dumps(payload, indent=2)
    print(text)
    if args.receipt:
        Path(args.receipt).parent.mkdir(parents=True, exist_ok=True)
        Path(args.receipt).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
