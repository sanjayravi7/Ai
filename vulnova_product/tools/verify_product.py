"""End-to-end verification against the store and a live console.

    python tools/verify_product.py --db build/vulnova.db

Starts an in-process server on an ephemeral port, exercises the API, and
prints one PASS/FAIL line per check.  Exit code 0 only if every check passes.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vulnova import assessment, explain, rank, store, web  # noqa: E402

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((bool(condition), name, detail))
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not condition else ""))


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=30) as response:
        return response.status, json.loads(response.read().decode())


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="build/vulnova.db")
    parser.add_argument("--base", default=None,
                        help="use an already-running server instead of starting one")
    args = parser.parse_args(argv)

    db = Path(args.db)
    if not db.exists():
        print(f"FAIL: store {db} does not exist")
        return 2

    conn = store.connect(db, readonly=True)
    counts = store.counts(conn)
    reference = store.reference_date(conn)
    coverage = explain.coverage_report(conn)

    print("== store ==")
    check("store has CVE records", counts["cve_record"] >= 300_000, counts["cve_record"])
    check("distinct CVE identifiers", counts["distinct_cves"] >= 300_000, counts["distinct_cves"])
    check("KEV catalog loaded", counts["kev"] >= 1_700, counts["kev"])
    check("EPSS loaded", counts["epss"] >= 390_000, counts["epss"])
    check("ranking materialised", counts["ranking"] >= 300_000, counts["ranking"])
    check("reference date from EPSS", reference == "2026-10-16", reference)
    check("ingest runs recorded", counts["ingest_run"] >= 5, counts["ingest_run"])
    check("rejected records present but not ranked", counts["rejected"] > 0, counts["rejected"])

    runs = store.ingest_runs(conn)
    v5_runs = [r for r in runs if r["source"] == "cvelistv5"]
    check("cvelistV5 revision pinned", all(r["source_revision"] for r in v5_runs))
    legacy = [r for r in runs if r["source"] == "legacy_cve_csv"]
    check("legacy extract ingested", legacy and legacy[-1]["records_in"] >= 89_000,
          legacy[-1]["records_in"] if legacy else 0)

    totals = {row["year"]: row for row in coverage["published_year_totals"]}
    print("== 2020-2023 coverage ==")
    for year, floor in (("2020", 12_000), ("2021", 18_000), ("2022", 22_000), ("2023", 25_000)):
        row = totals.get(year, {})
        non_kev = row.get("records", 0) - row.get("kev_listed", 0)
        check(f"{year} has non-KEV records", non_kev >= floor, non_kev)
    check("no coverage gaps remain", coverage["gaps"] == [], coverage["gaps"])
    check("no KEV-only identifiers", not coverage["kev_only_by_id_year"],
          coverage["kev_only_by_id_year"])
    check("EPSS unmatched fell below 60k",
          coverage["epss"]["unmatched_records"] < 60_000,
          coverage["epss"]["unmatched_records"])
    check("EPSS covers >99% of stored CVEs",
          coverage["epss"]["coverage_of_store"] > 99.0,
          coverage["epss"]["coverage_of_store"])

    print("== evidence ==")
    cvss_obs = conn.execute(
        "SELECT COUNT(*) FROM cvss_observation WHERE status='OBSERVED'"
    ).fetchone()[0]
    check("observed CVSS values", cvss_obs >= 350_000, cvss_obs)
    legacy_obs = conn.execute(
        "SELECT COUNT(*) FROM cvss_observation WHERE source='legacy_cve_csv' AND status='OBSERVED'"
    ).fetchone()[0]
    check("legacy CVSS stored as observations", legacy_obs >= 89_000, legacy_obs)
    no_evidence = conn.execute(
        "SELECT COUNT(*) FROM cvss_observation WHERE status='MISSING_FROM_SOURCE'"
    ).fetchone()[0]
    check("missing CVSS is represented as rows", no_evidence > 0, no_evidence)
    conflicts = conn.execute(
        "SELECT COUNT(*) FROM ranking WHERE cvss_conflict=1"
    ).fetchone()[0]
    check("conflicting CVSS rows retained", conflicts > 10_000, conflicts)
    insufficient = conn.execute(
        "SELECT COUNT(*) FROM ranking WHERE review_required=1"
    ).fetchone()[0]
    check("insufficient-evidence rows flagged", insufficient > 0, insufficient)
    check("weights sum to fixed denominator", rank.denominator_check() == 100)
    check("five priority bands", len(rank.BANDS) == 5)
    check("bands are (threshold, name) pairs",
          all(isinstance(b[0], int) and isinstance(b[1], str) for b in rank.BANDS))

    print("== API ==")
    httpd = None
    if args.base:
        base = args.base.rstrip("/")
    else:
        httpd = web.build_server(db, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

    try:
        status_code, status = get(base, "/api/status")
        check("GET /api/status", status_code == 200)
        check("status counts match store", status["counts"]["ranking"] == counts["ranking"])
        check("status exposes coverage", bool(status["coverage"]["published_year_totals"]))
        check("status weights sum to 100",
              sum(w["max_points"] for w in status["weights"]) == 100)
        check("status exposes 5 bands", len(status["bands"]) == 5)
        check("status states method limits",
              "Not a validated predictive model" in status["method"])

        _, listing = get(base, "/api/ranking?limit=25")
        check("ranking total matches", listing["total"] == counts["ranking"],
              f"{listing['total']} vs {counts['ranking']}")
        scores = [row["score"] for row in listing["rows"]]
        check("ranking sorted by score desc", scores == sorted(scores, reverse=True))
        check("ranking page size respected", len(listing["rows"]) == 25)

        _, kev_listing = get(base, "/api/ranking?kev=1&limit=50")
        check("KEV filter returns only KEV",
              all(row["kev_listed"] for row in kev_listing["rows"]))
        check("KEV members are distinguishable",
              any(row["kev_listed"] for row in listing["rows"])
              or kev_listing["total"] > 0)

        _, review_listing = get(base, "/api/ranking?review=1&limit=50")
        check("review filter returns insufficient rows",
              review_listing["total"] > 0
              and all(row["review_required"] for row in review_listing["rows"]))

        _, band_listing = get(base, "/api/ranking?band=P1_CRITICAL&limit=10")
        check("band filter works",
              all(row["band"] == "P1_CRITICAL" for row in band_listing["rows"]))

        _, search = get(base, "/api/ranking?q=CVE-2021-44228")
        check("search by identifier", any(r["cve_id"] == "CVE-2021-44228" for r in search["rows"]))

        # a conflict record from the store
        conflict_id = conn.execute(
            "SELECT cve_id FROM ranking WHERE cvss_conflict=1 ORDER BY score DESC LIMIT 1"
        ).fetchone()[0]
        _, detail = get(base, f"/api/cve/{conflict_id}")
        candidates = detail["observed"]["cvss"]["candidates"]
        check("detail exposes >=2 CVSS candidates", len(candidates) >= 2, len(candidates))
        check("detail marks one candidate selected",
              detail["observed"]["cvss"]["selected"] is not None)
        check("detail reports comparability",
              "comparable" in detail["observed"]["cvss"]["conflict"])
        check("detail keeps every value",
              len({c["value"] for c in candidates}) == len(
                  detail["observed"]["cvss"]["conflict"]["distinct_values"]))
        check("detail carries retrieval timestamps",
              all(c["retrieved_at"] for c in candidates))

        list_row = next(
            row for row in get(base, f"/api/ranking?q={conflict_id}")[1]["rows"]
            if row["cve_id"] == conflict_id
        )
        check("detail score matches list score",
              list_row["score"] == detail["priority"]["score"])
        check("detail band matches list band",
              list_row["band"] == detail["priority"]["band"])

        insufficient_id = conn.execute(
            "SELECT cve_id FROM ranking WHERE review_required=1 ORDER BY score DESC LIMIT 1"
        ).fetchone()[0]
        _, weak = get(base, f"/api/cve/{insufficient_id}")
        check("insufficient detail flagged review_required",
              weak["assessment"]["review_required"] is True)
        check("insufficient detail keeps numeric band",
              weak["assessment"]["numeric_band"] == weak["priority"]["band"])
        check("insufficient detail says it is not low risk",
              "NOT an assessment that this vulnerability is low risk"
              in weak["assessment"]["statement"])
        check("insufficient detail does not rescale denominator",
              weak["assessment"]["denominator_rescaled"] is False)
        check("provenance lists retrieved sources",
              bool(weak["provenance"]["retrieved"]))

        _, kev_detail = get(base, f"/api/cve/{kev_listing['rows'][0]['cve_id']}")
        check("KEV detail shows date added",
              kev_detail["observed"]["kev"]["date_added"] is not None)
        check("publication recency context names its basis",
              kev_detail["publication_recency_context"]["component_basis"]
              == "publication_date")
        check("publication recency states what it does not represent",
              kev_detail["publication_recency_context"]["does_not_represent"] == [
                  "recent exploitation activity",
                  "recent KEV inclusion",
                  "an independently verified increase in threat activity",
              ])
        check("component is named publication_recency",
              [s["name"] for s in kev_detail["priority"]["signals"]][-1]
              == "publication_recency")
        check("status exposes publication_recency_definition",
              status.get("publication_recency_definition", {}).get("component")
              == "publication_recency"
              and "recency_definition" not in status)
        check("list API names the points publication_recency_points",
              "publication_recency_points" in listing["rows"][0]
              and "recency_points" not in listing["rows"][0])

        try:
            get(base, "/api/cve/CVE-1999-9999")
            check("unknown CVE returns 404", False)
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode())
            check("unknown CVE returns 404", exc.code == 404)
            check("404 message explains coverage", "not in the store" in body["message"])

        try:
            get(base, "/api/cve/NOT-A-CVE")
            check("malformed identifier returns 404", False)
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode())
            check("malformed identifier returns 404", exc.code == 404)
            check("malformed message is explicit",
                  "not a CVE identifier" in body["message"])

        with urllib.request.urlopen(base + "/static/app.js", timeout=10) as response:
            app_js = response.read().decode()
        check("static app.js served", "INSUFFICIENT EVIDENCE" in app_js)
        with urllib.request.urlopen(base + "/", timeout=10) as response:
            index = response.read().decode()
        check("index carries method caveat",
              "<em>not</em> a validated predictive model" in index.lower())
    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        conn.close()

    failed = [row for row in RESULTS if not row[0]]
    print(f"\n{len(RESULTS) - len(failed)} PASS, {len(failed)} FAIL, 0 SKIP")
    if failed:
        for _, name, detail in failed:
            print(f"  FAILED: {name} {detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
