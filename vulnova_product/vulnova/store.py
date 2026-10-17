"""SQLite store: schema, connection helpers and status reporting.

Ground rules encoded here
-------------------------
* one row per ``(cve_id, source)`` in ``cve_record`` so conflicting sources
  coexist instead of overwriting each other;
* a CVSS observation exists for every ingested record: ``OBSERVED`` when the
  source states a score, ``MISSING_FROM_SOURCE`` when it does not.  Missing
  data is therefore *representable*, not absent;
* KEV and EPSS produce rows only for what they actually contain.  Absence is
  computed at query time and reported as ``NOT_LISTED_IN_CATALOG`` /
  ``MISSING_FROM_SOURCE``, never merged into an observed value.

Column naming note: ``ranking.recency_points`` is the storage column for the
publication-recency component.  It is an internal name; the API presents it as
``publication_recency_points``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS ingest_run (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,
    stage           TEXT NOT NULL,
    source_revision TEXT,
    retrieved_at    TEXT NOT NULL,
    content_sha256  TEXT,
    window_from     TEXT,
    window_to       TEXT,
    records_in      INTEGER NOT NULL DEFAULT 0,
    records_new     INTEGER NOT NULL DEFAULT 0,
    records_existing INTEGER NOT NULL DEFAULT 0,
    records_duplicate INTEGER NOT NULL DEFAULT 0,
    records_rejected INTEGER NOT NULL DEFAULT 0,
    records_skipped INTEGER NOT NULL DEFAULT 0,
    note            TEXT
);

CREATE TABLE IF NOT EXISTS cve_record (
    cve_id          TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_revision TEXT,
    retrieved_at    TEXT NOT NULL,
    published       TEXT,
    updated         TEXT,
    state           TEXT,
    state_basis     TEXT NOT NULL DEFAULT 'not_stated',
    reject_marker   INTEGER NOT NULL DEFAULT 0,
    assigner        TEXT,
    title           TEXT,
    description     TEXT,
    PRIMARY KEY (cve_id, source)
);
CREATE INDEX IF NOT EXISTS cve_record_pub ON cve_record(published);

CREATE TABLE IF NOT EXISTS cvss_observation (
    obs_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id              TEXT NOT NULL,
    source              TEXT NOT NULL,
    source_record_id    TEXT,
    container           TEXT NOT NULL,
    scoring_organization TEXT,
    version             TEXT,
    value               REAL,
    severity            TEXT,
    vector              TEXT,
    status              TEXT NOT NULL,
    retrieved_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cvss_cve ON cvss_observation(cve_id);
CREATE INDEX IF NOT EXISTS cvss_cve_status ON cvss_observation(cve_id, status);

CREATE TABLE IF NOT EXISTS kev (
    cve_id          TEXT PRIMARY KEY,
    date_added      TEXT,
    vendor          TEXT,
    product         TEXT,
    name            TEXT,
    ransom_known    INTEGER NOT NULL DEFAULT 0,
    source_revision TEXT,
    retrieved_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id        TEXT PRIMARY KEY,
    probability   REAL NOT NULL,
    percentile    REAL,
    score_date    TEXT NOT NULL,
    model_version TEXT,
    retrieved_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ranking (
    cve_id           TEXT PRIMARY KEY,
    score            INTEGER NOT NULL,
    band             TEXT NOT NULL,
    kev_listed       INTEGER NOT NULL,
    cvss_value       REAL,
    cvss_version     TEXT,
    cvss_source      TEXT,
    cvss_container   TEXT,
    cvss_candidates  INTEGER NOT NULL DEFAULT 0,
    cvss_conflict    INTEGER NOT NULL DEFAULT 0,
    epss_probability REAL,
    published        TEXT,
    recency_points   INTEGER NOT NULL,
    missing_signals  TEXT NOT NULL,
    evidence_status  TEXT NOT NULL,
    review_required  INTEGER NOT NULL,
    built_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ranking_score ON ranking(score DESC, cve_id);
CREATE INDEX IF NOT EXISTS ranking_band ON ranking(band, score DESC);

CREATE TABLE IF NOT EXISTS ranking_meta (key TEXT PRIMARY KEY, value TEXT);
"""

COUNTED_TABLES = (
    "cve_record",
    "cvss_observation",
    "kev",
    "epss",
    "ingest_run",
    "ranking",
)


def connect(path, *, readonly: bool = False) -> sqlite3.Connection:
    path = Path(path)
    if readonly:
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=30)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def initialise(path) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def counts(conn) -> dict:
    out = {}
    for table in COUNTED_TABLES:
        try:
            out[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            out[table] = None
    out["distinct_cves"] = conn.execute(
        "SELECT COUNT(DISTINCT cve_id) FROM cve_record"
    ).fetchone()[0]
    out["rejected"] = conn.execute(
        "SELECT COUNT(DISTINCT cve_id) FROM cve_record WHERE state='REJECTED'"
    ).fetchone()[0]
    return out


def ingest_runs(conn) -> list:
    rows = conn.execute(
        "SELECT * FROM ingest_run ORDER BY run_id"
    ).fetchall()
    return [dict(row) for row in rows]


def reference_date(conn) -> str:
    """Latest date for which the store holds *evidence of observation*.

    The EPSS score date is used when available because it is an explicit
    statement by the source about when it looked; recency arithmetic against
    it is therefore reproducible, unlike ``today``.
    """
    row = conn.execute("SELECT MAX(score_date) FROM epss").fetchone()
    if row and row[0]:
        return row[0]
    row = conn.execute("SELECT MAX(published) FROM cve_record").fetchone()
    return row[0] if row and row[0] else "1970-01-01"


def store_status(path) -> dict:
    from . import explain

    conn = connect(path, readonly=True)
    try:
        payload = {
            "db_path": str(Path(path).resolve()),
            "counts": counts(conn),
            "reference_date": reference_date(conn),
            "ingest_runs": ingest_runs(conn),
            "coverage": explain.coverage_report(conn),
        }
    finally:
        conn.close()
    return payload
