"""Explainability layer.

Two jobs:

1. Build the payload for one CVE: every source-specific CVSS value, which one
   was selected for ranking and why, EPSS/KEV provenance, missing signals, the
   evidence-adequacy assessment and a coverage note.
2. Report coverage for the whole store.

The selected CVSS value drives the score; the other values are *never*
discarded.  ``cvss.candidates`` always carries the full set.
"""

from __future__ import annotations

import sqlite3
from datetime import date

from . import assessment, rank
from .store import reference_date as store_reference_date

SOURCE_PRIORITY = {"cvelistv5": 0, "legacy_cve_csv": 1}
CONTAINER_PRIORITY = {"cna": 0, "adp": 1, "legacy": 2}
VERSION_RANK = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}

SELECTION_RULE = (
    "cvelistv5 before the legacy extract; within a source the highest CVSS "
    "version wins (v4.0 > v3.1 > v3.0 > v2.0); within a version the CNA "
    "container precedes ADP containers. The legacy extract carries CVSS v2.0 "
    "scores of unstated revision and is therefore the last resort."
)


def _parse_day(value):
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _major(version):
    return str(version or "").split(".")[0]


def _selection_key(candidate):
    return (
        SOURCE_PRIORITY.get(candidate["source"], 9),
        -VERSION_RANK.get(str(candidate["version"]), 0),
        CONTAINER_PRIORITY.get(candidate["container"], 9),
        candidate["obs_id"],
    )


def _describe(candidate):
    return (
        f"{candidate['source']} {candidate['container']} "
        f"v{candidate['version']} ({candidate['value']:.1f})"
    )


def select_cvss(candidates: list) -> dict:
    """Return ``{selected, candidates, conflict}`` for one CVE."""
    observed = [
        cand for cand in candidates
        if cand["status"] == "OBSERVED" and cand["value"] is not None
    ]
    if not observed:
        return {
            "selected": None,
            "candidates": candidates,
            "conflict": {
                "has_conflict": False,
                "distinct_values": [],
                "delta": None,
                "comparable": None,
                "comparability_note": "No observed CVSS value; nothing to compare.",
                "selection_rule": SELECTION_RULE,
                "selected_reason": "No source states a CVSS base score.",
            },
        }

    ranked = sorted(observed, key=_selection_key)
    selected = ranked[0]
    values = sorted({round(cand["value"], 1) for cand in observed})
    has_conflict = len(values) > 1

    majors = {_major(cand["version"]) for cand in observed}
    comparable = len(majors) == 1
    if comparable:
        note = (
            "All observed values use the same CVSS major version "
            f"(v{next(iter(majors))}), so the numbers share a scale; they may still "
            "differ because they were scored at different times or by different "
            "organisations."
        )
    else:
        note = (
            "Values span different CVSS major versions "
            f"({', '.join('v' + m for m in sorted(majors))}); the numbers are NOT "
            "directly comparable — v2, v3 and v4 use different formulas and produce "
            "different scales for the same underlying severity."
        )

    if has_conflict:
        reason = (
            f"Selected {_describe(selected)} over "
            + ", ".join(_describe(cand) for cand in ranked[1:])
            + ". Rule: " + SELECTION_RULE
        )
    else:
        reason = (
            f"All {len(observed)} observed values agree ({values[0]:.1f}); "
            f"{_describe(selected)} is used."
        )

    return {
        "selected": selected,
        "candidates": candidates,
        "conflict": {
            "has_conflict": has_conflict,
            "distinct_values": values,
            "delta": round(values[-1] - values[0], 1) if has_conflict else 0.0,
            "comparable": comparable,
            "comparability_note": note,
            "selection_rule": SELECTION_RULE,
            "selected_reason": reason,
        },
    }


def _candidate_rows(conn, cve_id) -> list:
    rows = conn.execute(
        "SELECT obs_id, cve_id, source, source_record_id, container,"
        " scoring_organization, version, value, severity, vector, status, retrieved_at"
        " FROM cvss_observation WHERE cve_id=? ORDER BY obs_id",
        (cve_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def facts(conn, cve_id, reference_day=None) -> dict | None:
    """Gather everything known about one CVE using indexed lookups only."""
    records = [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM cve_record WHERE cve_id=?", (cve_id,)
        )
    ]
    if not records:
        return None

    by_source = {record["source"]: record for record in records}
    primary = by_source.get("cvelistv5") or by_source.get("legacy_cve_csv") or records[0]
    published = primary.get("published")
    if not published:
        for record in records:
            if record.get("published"):
                published = record["published"]
                break

    kev_row = conn.execute("SELECT * FROM kev WHERE cve_id=?", (cve_id,)).fetchone()
    epss_row = conn.execute("SELECT * FROM epss WHERE cve_id=?", (cve_id,)).fetchone()

    candidates = _candidate_rows(conn, cve_id)
    cvss = select_cvss(candidates)

    return {
        "cve_id": cve_id,
        "records": records,
        "primary": primary,
        "published": published,
        "candidates": candidates,
        "cvss": cvss,
        "kev": dict(kev_row) if kev_row else None,
        "epss": dict(epss_row) if epss_row else None,
    }


def publication_recency_context(fact: dict, reference_day: str) -> dict:
    """Make the meaning of the publication-recency component explicit.

    The component is named ``publication_recency`` in every presentation layer.
    It is derived from the CVE publication date and nothing else.
    """
    published = _parse_day(fact.get("published"))
    ref = _parse_day(reference_day)
    kev = fact.get("kev")
    kev_day = _parse_day(kev["date_added"]) if kev else None

    pub_age = (ref - published).days if published and ref else None
    kev_age = (ref - kev_day).days if kev_day and ref else None

    parts = [
        "publication_recency measures the CVE publication date only: it does not "
        "represent recent exploitation activity, recent KEV inclusion, or an "
        "independently verified increase in threat activity."
    ]
    if pub_age is None:
        parts.append(
            "No CVE publication date is available, so publication_recency scores zero."
        )
    else:
        parts.append(
            f"This CVE was published {pub_age} days before the reference date."
        )
    if kev and kev_age is not None:
        parts.append(
            f"KEV listing evidence: added to the catalog {kev_age} days before the "
            f"reference date. KEV listing recency does not contribute to the score; "
            f"KEV contributes the fixed 40-point membership component instead."
        )
        if pub_age is not None and kev_age is not None and kev_age <= 90 < pub_age:
            parts.append(
                "This record has recent exploitation evidence even though its "
                "publication is old; it must not be described as having no recent "
                "activity."
            )
    else:
        parts.append(
            "No KEV listing date is available for this CVE; absence from the "
            "catalog is not evidence of no exploitation."
        )

    return {
        "component": "publication_recency",
        "component_basis": "publication_date",
        "does_not_represent": [
            "recent exploitation activity",
            "recent KEV inclusion",
            "an independently verified increase in threat activity",
        ],
        "publication_date": fact.get("published"),
        "publication_age_days": pub_age,
        "kev_listing_date": kev["date_added"] if kev else None,
        "days_since_kev_listing": kev_age,
        "statement": " ".join(parts),
    }


def _coverage_note(fact: dict) -> dict:
    year = (fact.get("published") or "")[:4] or (fact["cve_id"][4:8])
    sources = [record["source"] for record in fact["records"]]
    if "cvelistv5" in sources:
        status = "COVERED_BY_CVELISTV5"
        note = (
            "This publication year is inside the cvelistV5 window "
            "(published 2020-01-01 or later)."
        )
    elif year and year.isdigit() and int(year) <= 2019:
        status = "COVERED_BY_LEGACY_EXTRACT"
        note = (
            "This publication year is covered by the legacy extract "
            "(1999-2019). The extract has no state column and carries CVSS v2 only."
        )
    else:
        status = "OUTSIDE_LOADED_WINDOWS"
        note = "This identifier is outside every loaded source window."
    return {"status": status, "note": note, "publication_year": year}


def explain_one(conn, cve_id, reference_day=None) -> dict | None:
    reference_day = reference_day or store_reference_date(conn)
    fact = facts(conn, cve_id, reference_day)
    if fact is None:
        return None

    selected = fact["cvss"]["selected"]
    kev_listed = fact["kev"] is not None
    epss = fact["epss"]

    score = rank.score_cve(
        cve_id,
        reference_date=reference_day,
        published=fact["published"],
        kev_listed=kev_listed,
        epss_probability=epss["probability"] if epss else None,
        cvss_value=selected["value"] if selected else None,
        cvss_version=selected["version"] if selected else None,
        cvss_source=selected["source"] if selected else None,
    )

    adequacy = assessment.assess(
        has_cvss=selected is not None,
        has_epss=epss is not None,
        kev_listed=kev_listed,
        score=score.score,
        band=score.band,
    )

    record = {
        key: fact["primary"].get(key)
        for key in ("cve_id", "published", "updated", "state", "state_basis",
                    "reject_marker", "assigner", "title", "description")
    }
    record["source"] = fact["primary"]["source"]
    record["sources"] = [r["source"] for r in fact["records"]]
    conflicts = [
        {
            "source": r["source"],
            "published": r["published"],
            "state": r["state"],
            "state_basis": r["state_basis"],
            "reject_marker": r["reject_marker"],
            "retrieved_at": r["retrieved_at"],
        }
        for r in fact["records"]
        if r["source"] != fact["primary"]["source"]
    ]
    record["alternate_source_records"] = conflicts

    observed = {
        "cvss": {
            "selected": selected,
            "candidates": fact["candidates"],
            "conflict": fact["cvss"]["conflict"],
            "status": "OBSERVED" if selected else "MISSING_FROM_SOURCE",
        },
        "epss": (
            {
                "status": "OBSERVED",
                "probability": epss["probability"],
                "percentile": epss["percentile"],
                "score_date": epss["score_date"],
                "model_version": epss["model_version"],
                "retrieved_at": epss["retrieved_at"],
            }
            if epss
            else {"status": "MISSING_FROM_SOURCE", "probability": None}
        ),
        "kev": (
            {
                "status": "LISTED",
                "date_added": fact["kev"]["date_added"],
                "vendor": fact["kev"]["vendor"],
                "product": fact["kev"]["product"],
                "ransom_known": bool(fact["kev"]["ransom_known"]),
                "retrieved_at": fact["kev"]["retrieved_at"],
            }
            if kev_listed
            else {
                "status": "NOT_LISTED_IN_CATALOG",
                "note": "Absence from the catalog is not evidence of no exploitation.",
            }
        ),
    }

    provenance = _provenance(conn, fact)

    return {
        "as_of": reference_day,
        "cve_id": cve_id,
        "record": record,
        "observed": observed,
        "priority": {**score.as_dict(), "method": rank.METHOD},
        "assessment": adequacy,
        "publication_recency_context": publication_recency_context(fact, reference_day),
        "coverage": _coverage_note(fact),
        "provenance": provenance,
    }


def _provenance(conn, fact) -> dict:
    rows = {}
    for record in fact["records"]:
        rows[record["source"]] = {
            "revision": record["source_revision"],
            "retrieved_at": record["retrieved_at"],
        }
    if fact["kev"]:
        rows["kev"] = {
            "revision": fact["kev"]["source_revision"],
            "retrieved_at": fact["kev"]["retrieved_at"],
        }
    if fact["epss"]:
        rows["epss"] = {
            "revision": fact["epss"]["model_version"],
            "retrieved_at": fact["epss"]["retrieved_at"],
            "score_date": fact["epss"]["score_date"],
        }
    return {
        "sources_present": sorted(rows),
        "retrieved": rows,
        "note": "Only sources that hold a row for this CVE are listed.",
    }


def coverage_report(conn) -> dict:
    """Per-year coverage, remaining gaps and unmatched EPSS rows."""
    per_year = {}
    for row in conn.execute(
        "SELECT substr(cve_id, 5, 4) AS year, source, COUNT(*) AS n"
        " FROM cve_record GROUP BY year, source ORDER BY year"
    ):
        bucket = per_year.setdefault(
            row["year"], {"year": row["year"], "legacy_cve_csv": 0, "cvelistv5": 0}
        )
        bucket[row["source"]] = row["n"]

    published_year = {}
    for row in conn.execute(
        "SELECT substr(published, 1, 4) AS year, source, COUNT(*) AS n"
        " FROM cve_record WHERE published IS NOT NULL"
        " GROUP BY year, source ORDER BY year"
    ):
        bucket = published_year.setdefault(
            row["year"], {"year": row["year"], "legacy_cve_csv": 0, "cvelistv5": 0}
        )
        bucket[row["source"]] = row["n"]

    published_totals = [
        {"year": row[0], "records": row[1], "kev_listed": row[2]}
        for row in conn.execute(
            "SELECT substr(c.published, 1, 4) AS year,"
            " COUNT(DISTINCT c.cve_id) AS records,"
            " COUNT(DISTINCT CASE WHEN k.cve_id IS NOT NULL THEN c.cve_id END) AS kev"
            " FROM cve_record c LEFT JOIN kev k ON k.cve_id = c.cve_id"
            " WHERE c.published IS NOT NULL GROUP BY year ORDER BY year"
        )
    ]

    kev_only = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT substr(cve_id, 5, 4) AS year, COUNT(*) FROM kev"
            " WHERE cve_id NOT IN (SELECT cve_id FROM cve_record) GROUP BY year"
        )
    }

    gaps = []
    for year, bucket in sorted(per_year.items()):
        total = bucket["legacy_cve_csv"] + bucket["cvelistv5"]
        if total == 0:
            continue
        if year.isdigit() and 2020 <= int(year) <= 2023 and bucket["cvelistv5"] == 0:
            gaps.append({"year": year, "kind": "NO_NON_KEV_COVERAGE"})
    for year, count in sorted(kev_only.items()):
        gaps.append({"year": year, "kind": "KEV_ONLY_NO_RECORD", "records": count})

    epss_total = conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0]
    epss_unmatched = conn.execute(
        "SELECT COUNT(*) FROM epss WHERE cve_id NOT IN (SELECT cve_id FROM cve_record)"
    ).fetchone()[0]
    epss_unmatched_cves = conn.execute(
        "SELECT COUNT(*) FROM epss WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM cve_record)"
    ).fetchone()[0]
    unmatched_by_year = [
        {"year": row[0], "records": row[1]}
        for row in conn.execute(
            "SELECT substr(cve_id, 5, 4) AS year, COUNT(*) FROM epss"
            " WHERE cve_id NOT IN (SELECT cve_id FROM cve_record)"
            " GROUP BY year ORDER BY year"
        )
    ]

    kev_unranked = [
        {"cve_id": row[0], "date_added": row[1], "reason": row[2]}
        for row in conn.execute(
            "SELECT k.cve_id, k.date_added,"
            " COALESCE((SELECT 'CVE_RECORD_REJECTED' FROM cve_record c"
            "           WHERE c.cve_id = k.cve_id AND c.state='REJECTED' LIMIT 1),"
            "          'NO_RECORD') AS reason"
            " FROM kev k LEFT JOIN ranking r ON r.cve_id = k.cve_id"
            " WHERE r.cve_id IS NULL ORDER BY k.cve_id"
        )
    ]

    return {
        "per_id_year": [per_year[year] for year in sorted(per_year)],
        "per_published_year": [published_year[year] for year in sorted(published_year)],
        "published_year_totals": published_totals,
        "kev_only_by_id_year": kev_only,
        "kev_unranked": kev_unranked,
        "gaps": gaps,
        "windows": [
            {"source": "legacy_cve_csv", "from": "1999-01-01", "to": "2019-12-31"},
            {"source": "cvelistv5", "from": "2020-01-01", "to": None},
        ],
        "epss": {
            "total": epss_total,
            "unmatched_records": epss_unmatched,
            "unmatched_cves": epss_unmatched_cves,
            "unmatched_by_id_year": unmatched_by_year,
            "coverage_of_store": (
                round(
                    100.0
                    * (conn.execute("SELECT COUNT(*) FROM cve_record").fetchone()[0]
                       - conn.execute(
                           "SELECT COUNT(*) FROM cve_record WHERE cve_id NOT IN"
                           " (SELECT cve_id FROM epss)"
                       ).fetchone()[0])
                    / max(conn.execute("SELECT COUNT(*) FROM cve_record").fetchone()[0], 1),
                    2,
                )
            ),
        },
    }


def absent_message(conn, cve_id, reference_day=None) -> str:
    """Human message for a 404 — never pretends the CVE does not exist."""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return f"{cve_id!r} is not a CVE identifier."
    year = cve_id[4:8]
    loaded = {
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT substr(published, 1, 4) FROM cve_record"
            " WHERE published IS NOT NULL"
        )
    }
    if year.isdigit() and year not in loaded:
        return (
            f"{cve_id} is not in the store. No loaded source covers publication year "
            f"{year}. The store holds records for publication years "
            f"{min(loaded) if loaded else 'n/a'}-{max(loaded) if loaded else 'n/a'}, "
            f"so absence here means 'no record loaded', not 'no such CVE'."
        )
    return (
        f"{cve_id} is not in the store even though publication year {year} is "
        f"covered. It may be a reserved or rejected identifier, or absent from the "
        f"loaded source revision."
    )
