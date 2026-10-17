"""Compute digests over the materialised ranking.

Two digests are produced:

``numeric``   sum of every score-bearing column *except* the textual
              ``missing_signals`` list.  This is the digest that must not move
              when only terminology changes.
``labelled``  the same rows plus ``missing_signals``, so a pure rename of a
              signal is visible as a change in exactly this digest.

    python tools/score_digest.py --db build/vulnova.db --json out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnova import store  # noqa: E402

NUMERIC_COLUMNS = (
    "cve_id", "score", "band", "kev_listed", "cvss_value", "cvss_version",
    "cvss_source", "cvss_container", "epss_probability", "published",
    "recency_points", "evidence_status", "review_required",
)


def _feed(digest, row):
    digest.update(
        "|".join("" if value is None else str(value) for value in row).encode()
        + b"\n"
    )


def compute(db_path) -> dict:
    conn = store.connect(db_path, readonly=True)
    try:
        numeric = hashlib.sha256()
        labelled = hashlib.sha256()
        rows = 0
        scores = {}
        bands = {}
        missing_values = {}
        for row in conn.execute(
            "SELECT " + ", ".join(NUMERIC_COLUMNS) + ", missing_signals"
            " FROM ranking ORDER BY cve_id"
        ):
            rows += 1
            values = tuple(row[: len(NUMERIC_COLUMNS)])
            _feed(numeric, values)
            _feed(labelled, values + (row["missing_signals"],))
            scores[row["score"]] = scores.get(row["score"], 0) + 1
            bands[row["band"]] = bands.get(row["band"], 0) + 1
            for token in (row["missing_signals"] or "").split(","):
                if token:
                    missing_values[token] = missing_values.get(token, 0) + 1
        return {
            "rows": rows,
            "numeric_digest": numeric.hexdigest(),
            "labelled_digest": labelled.hexdigest(),
            "score_histogram": dict(sorted(scores.items())),
            "band_counts": dict(sorted(bands.items())),
            "missing_signal_values": dict(sorted(missing_values.items())),
            "reference_date": store.reference_date(conn),
        }
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="build/vulnova.db")
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    payload = compute(args.db)
    text = json.dumps(payload, indent=2)
    print(text)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
