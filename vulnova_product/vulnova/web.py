"""Read-only HTTP console.

    python -m vulnova.web --db build/vulnova.db --host 0.0.0.0 --port 8000 --warm

Endpoints
---------
GET /                     console
GET /static/<file>        assets
GET /api/status           counts, coverage, weights, provenance
GET /api/ranking          search + filters + paging
GET /api/cve/<CVE-ID>     full explanation payload
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import assessment, explain, rank, store
from .provenance import utc_now

STATIC_DIR = Path(__file__).with_name("static")

FACTS_SQL = """
WITH rec AS (
    SELECT cve_id,
           MIN(published) AS published,
           MAX(CASE WHEN state='REJECTED' OR reject_marker=1 THEN 1 ELSE 0 END) AS rejected
    FROM cve_record
    GROUP BY cve_id
),
cv AS (
    SELECT cve_id, value, version, source, container FROM (
        SELECT cve_id, value, version, source, container,
               ROW_NUMBER() OVER (
                   PARTITION BY cve_id
                   ORDER BY
                     CASE source WHEN 'cvelistv5' THEN 0 WHEN 'legacy_cve_csv' THEN 1 ELSE 2 END,
                     CASE version WHEN '4.0' THEN 4 WHEN '3.1' THEN 3
                                  WHEN '3.0' THEN 2 WHEN '2.0' THEN 1 ELSE 0 END DESC,
                     obs_id ASC
               ) AS rn
        FROM cvss_observation
        WHERE status='OBSERVED' AND value IS NOT NULL
    ) WHERE rn = 1
)
SELECT rec.cve_id, rec.published, rec.rejected,
       cv.value AS cvss_value, cv.version AS cvss_version,
       cv.source AS cvss_source, cv.container AS cvss_container,
       COALESCE(cvn.n, 0) AS cvss_candidates,
       CASE WHEN COALESCE(cvn.distinct_values, 0) > 1 THEN 1 ELSE 0 END AS cvss_conflict,
       ep.probability AS epss_probability,
       (k.cve_id IS NOT NULL) AS kev_listed
FROM rec
LEFT JOIN cv ON cv.cve_id = rec.cve_id
LEFT JOIN (
    SELECT cve_id, COUNT(*) AS n, COUNT(DISTINCT ROUND(value, 1)) AS distinct_values
    FROM cvss_observation
    WHERE status='OBSERVED' AND value IS NOT NULL
    GROUP BY cve_id
) cvn ON cvn.cve_id = rec.cve_id
LEFT JOIN epss ep ON ep.cve_id = rec.cve_id
LEFT JOIN kev k ON k.cve_id = rec.cve_id
"""

ORPHAN_KEV_SQL = """
SELECT k.cve_id FROM kev k
LEFT JOIN (SELECT DISTINCT cve_id FROM cve_record) r ON r.cve_id = k.cve_id
WHERE r.cve_id IS NULL
"""


def _fingerprint(conn) -> str:
    counts = store.counts(conn)
    return ":".join(
        str(counts.get(key)) for key in ("cve_record", "cvss_observation", "kev", "epss")
    ) + ":" + store.reference_date(conn)


def build_ranking(conn, *, force: bool = False, verbose: bool = False) -> dict:
    """Materialise the ranked table.  Pure function of the store contents."""
    fingerprint = _fingerprint(conn)
    stored = conn.execute(
        "SELECT value FROM ranking_meta WHERE key='fingerprint'"
    ).fetchone()
    existing = conn.execute("SELECT COUNT(*) FROM ranking").fetchone()[0]
    if not force and stored and stored[0] == fingerprint and existing:
        return {"rebuilt": False, "rows": existing, "fingerprint": fingerprint}

    reference_day = store.reference_date(conn)
    started = utc_now()
    if verbose:
        print(f"[rank] building for reference date {reference_day}", flush=True)

    conn.execute("DELETE FROM ranking")
    conn.commit()

    batch = []
    total = 0
    tried = 0

    def flush():
        if not batch:
            return
        conn.executemany(
            "INSERT INTO ranking (cve_id, score, band, kev_listed, cvss_value,"
            " cvss_version, cvss_source, cvss_container, cvss_candidates, cvss_conflict,"
            " epss_probability, published, recency_points, missing_signals,"
            " evidence_status, review_required, built_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            batch,
        )
        batch.clear()

    for row in conn.execute(FACTS_SQL):
        tried += 1
        if row["rejected"]:
            continue
        score = rank.score_cve(
            row["cve_id"],
            reference_date=reference_day,
            published=row["published"],
            kev_listed=bool(row["kev_listed"]),
            epss_probability=row["epss_probability"],
            cvss_value=row["cvss_value"],
            cvss_version=row["cvss_version"],
            cvss_source=row["cvss_source"],
        )
        adequacy = assessment.assess(
            has_cvss=row["cvss_value"] is not None,
            has_epss=row["epss_probability"] is not None,
            kev_listed=bool(row["kev_listed"]),
            score=score.score,
            band=score.band,
        )
        batch.append(
            (
                score.cve_id, score.score, score.band, int(bool(row["kev_listed"])),
                row["cvss_value"], row["cvss_version"], row["cvss_source"],
                row["cvss_container"], row["cvss_candidates"], row["cvss_conflict"],
                row["epss_probability"], row["published"],
                next(
                    s.points for s in score.signals
                    if s.name == "publication_recency"
                ),
                ",".join(score.missing_signals), adequacy["status"],
                int(adequacy["review_required"]), started,
            )
        )
        total += 1
        if len(batch) >= 5000:
            flush()
    flush()

    for orphan in conn.execute(ORPHAN_KEV_SQL):
        cve_id = orphan[0]
        score = rank.score_cve(cve_id, reference_date=reference_day, kev_listed=True)
        adequacy = assessment.assess(
            has_cvss=False, has_epss=False, kev_listed=True,
            score=score.score, band=score.band,
        )
        conn.execute(
            "INSERT OR REPLACE INTO ranking (cve_id, score, band, kev_listed,"
            " cvss_value, cvss_version, cvss_source, cvss_container, cvss_candidates,"
            " cvss_conflict, epss_probability, published, recency_points,"
            " missing_signals, evidence_status, review_required, built_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cve_id, score.score, score.band, 1, None, None, None, None, 0, 0, None,
             None, 0, ",".join(score.missing_signals), adequacy["status"],
             int(adequacy["review_required"]), started),
        )
        total += 1

    conn.execute(
        "INSERT OR REPLACE INTO ranking_meta (key, value) VALUES ('fingerprint', ?)",
        (fingerprint,),
    )
    conn.execute(
        "INSERT OR REPLACE INTO ranking_meta (key, value) VALUES ('built_at', ?)",
        (started,),
    )
    conn.execute(
        "INSERT OR REPLACE INTO ranking_meta (key, value) VALUES ('reference_date', ?)",
        (reference_day,),
    )
    conn.commit()
    if verbose:
        print(f"[rank] {total} rows from {tried} candidate CVEs", flush=True)
    return {"rebuilt": True, "rows": total, "fingerprint": fingerprint,
            "reference_date": reference_day, "built_at": started}


def _list_ranking(conn, args) -> dict:
    where = []
    params: list = []
    q = (args.get("q") or [""])[0].strip()
    band = (args.get("band") or [""])[0].strip()
    kev_filter = (args.get("kev") or [""])[0].strip()
    review = (args.get("review") or [""])[0].strip()
    try:
        limit = min(max(int((args.get("limit") or ["50"])[0]), 1), 500)
    except ValueError:
        limit = 50
    try:
        offset = max(int((args.get("offset") or ["0"])[0]), 0)
    except ValueError:
        offset = 0

    if q:
        where.append(
            "(cve_id LIKE ? OR cve_id IN ("
            "SELECT cve_id FROM cve_record WHERE title LIKE ? OR description LIKE ?"
            " LIMIT 5000))"
        )
        like = f"%{q}%"
        params.extend([like, like, like])
    if band:
        where.append("band = ?")
        params.append(band)
    if kev_filter in ("1", "true", "yes"):
        where.append("kev_listed = 1")
    elif kev_filter in ("0", "false", "no"):
        where.append("kev_listed = 0")
    if review in ("1", "true", "yes"):
        where.append("review_required = 1")

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM ranking{clause}", params).fetchone()[0]
    rows = conn.execute(
        "SELECT cve_id, score, band, kev_listed, cvss_value, cvss_version,"
        " cvss_source, cvss_candidates, cvss_conflict, epss_probability, published,"
        " recency_points AS publication_recency_points, missing_signals,"
        " evidence_status, review_required FROM ranking" + clause +
        " ORDER BY score DESC, cve_id ASC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()

    out = []
    for row in rows:
        item = dict(row)
        item["missing_signals"] = [s for s in item["missing_signals"].split(",") if s]
        item["review_required"] = bool(item["review_required"])
        item["kev_listed"] = bool(item["kev_listed"])
        item["cvss_conflict"] = bool(item["cvss_conflict"])
        out.append(item)
    return {"total": total, "limit": limit, "offset": offset, "rows": out}


class Handler(BaseHTTPRequestHandler):
    server_version = "VULNOVA/1.1"

    @property
    def db_path(self):
        return self.server.db_path

    def log_message(self, fmt, *args):
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _send(self, status, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path

        if route in ("/", "/index.html"):
            return self._static("index.html", "text/html; charset=utf-8")
        if route.startswith("/static/"):
            name = route[len("/static/"):]
            if "/" in name or name.startswith("."):
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            guessed = mimetypes.guess_type(name)[0] or "application/octet-stream"
            return self._static(name, guessed + ("; charset=utf-8" if guessed.startswith("text") or guessed.endswith("javascript") else ""))

        conn = store.connect(self.db_path, readonly=True)
        try:
            if route == "/api/status":
                return self._json(self._status(conn))
            if route == "/api/ranking":
                return self._json(_list_ranking(conn, parse_qs(parsed.query)))
            if route.startswith("/api/cve/"):
                cve_id = route[len("/api/cve/"):].strip()
                payload = explain.explain_one(conn, cve_id)
                if payload is None:
                    return self._json(
                        {"cve_id": cve_id, "error": "not_in_store",
                         "message": explain.absent_message(conn, cve_id)},
                        HTTPStatus.NOT_FOUND,
                    )
                return self._json(payload)
            if route == "/api/health":
                return self._json({"ok": True, "at": utc_now()})
        finally:
            conn.close()
        return self._json({"error": "not found", "path": route}, HTTPStatus.NOT_FOUND)

    def _status(self, conn):
        # Coverage is a full-store aggregate and the DB is read-only while
        # serving; compute it once at startup instead of on every poll.
        status = json.loads(json.dumps(self.server.status_base))
        status["weights"] = rank.describe_weights()
        status["denominator"] = rank.denominator_check()
        status["bands"] = [
            {"band": name, "min_score": threshold, "consequence": rank.BAND_CONSEQUENCE[name]}
            for threshold, name in rank.BANDS
        ]
        status["method"] = rank.METHOD
        status["publication_recency_definition"] = {
            "component": "publication_recency",
            "basis": "publication_date",
            "full_credit_days": rank.PUBLICATION_RECENCY_FULL_DAYS,
            "zero_credit_days": rank.PUBLICATION_RECENCY_ZERO_DAYS,
            "does_not_represent": [
                "recent exploitation activity",
                "recent KEV inclusion",
                "an independently verified increase in threat activity",
            ],
            "note": "Derived from the CVE publication date only. KEV listing "
                    "dates are displayed separately and do not contribute to "
                    "this component.",
        }
        status["ranking"] = {
            key: conn.execute(
                "SELECT value FROM ranking_meta WHERE key=?", (key,)
            ).fetchone()
            for key in ("built_at", "reference_date")
        }
        status["ranking"] = {k: (v[0] if v else None) for k, v in status["ranking"].items()}
        status["server_time"] = utc_now()
        return status

    def _static(self, name, content_type):
        path = STATIC_DIR / name
        if not path.is_file():
            return self._json({"error": "not found", "asset": name}, HTTPStatus.NOT_FOUND)
        self._send(HTTPStatus.OK, path.read_bytes(), content_type)


def build_server(db_path, host="127.0.0.1", port=8000, *, warm=False, verbose=False):
    conn = store.initialise(db_path)
    info = build_ranking(conn, force=False, verbose=verbose)
    conn.close()
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.db_path = str(db_path)
    httpd.status_base = store.store_status(db_path)
    httpd.verbose = verbose
    httpd.ranking_info = info
    return httpd


def main(argv=None):
    parser = argparse.ArgumentParser(description="VULNOVA read-only console")
    parser.add_argument("--db", default="build/vulnova.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--warm", action="store_true", help="build the ranking at startup")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    httpd = build_server(
        args.db, args.host, args.port, warm=args.warm, verbose=args.verbose
    )
    print(
        f"VULNOVA console on http://{args.host}:{args.port}  db={args.db}  "
        f"ranking_rows={httpd.ranking_info['rows']}  "
        f"rebuilt={httpd.ranking_info['rebuilt']}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
