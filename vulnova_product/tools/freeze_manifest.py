"""Freeze a data-integrity manifest for the build.

    python tools/freeze_manifest.py --out reports/improvement1_2/MANIFEST.json

Records a sha256 for every product file (excluding the venv, the derived store and
caches), the store counts and reference date, the ranking fingerprint, and the state
of the research repository.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vulnova import store  # noqa: E402
from vulnova.provenance import sha256_file, tree_digest, utc_now, write_json  # noqa: E402

EXCLUDE_DIRS = {".venv", "build", "__pycache__", ".pytest_cache", ".git"}
EXCLUDE_FILES = {"reports/improvement1_2/MANIFEST.json"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="build/vulnova.db")
    parser.add_argument("--out", default="reports/improvement1_2/MANIFEST.json")
    parser.add_argument(
        "--research-repo",
        default=str(ROOT.parent),
        help="repository this package is checked out in (defaults to the parent dir)",
    )
    args = parser.parse_args(argv)

    entries = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if str(rel) in EXCLUDE_FILES:
            continue
        if path.suffix in (".pyc",):
            continue
        entries.append((str(rel), sha256_file(path)))

    payload = {
        "label": "improvement1_2_final",
        "generated_at": utc_now(),
        "product_root": str(ROOT),
        "file_count": len(entries),
        "combined_digest": tree_digest(entries),
        "files": [{"path": rel, "sha256": sha} for rel, sha in entries],
    }

    db = Path(args.db)
    if db.exists():
        conn = store.connect(db, readonly=True)
        try:
            meta = {
                key: (row[0] if row else None)
                for key in ("built_at", "reference_date", "fingerprint")
                for row in [conn.execute(
                    "SELECT value FROM ranking_meta WHERE key=?", (key,)
                ).fetchone()]
            }
            payload["store"] = {
                "path": str(db.resolve()),
                "size_bytes": db.stat().st_size,
                "counts": store.counts(conn),
                "reference_date": store.reference_date(conn),
                "ranking_meta": meta,
                "ingest_runs": store.ingest_runs(conn),
            }
        finally:
            conn.close()

    repo = Path(args.research_repo)
    if repo.exists():
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            capture_output=True, text=True,
        ).stdout
        payload["research_repo"] = {
            "path": str(repo),
            "head": head,
            "working_tree_clean": status.strip() == "",
        }

    write_json(args.out, payload)
    print(json.dumps({
        "out": args.out,
        "files": len(entries),
        "combined_digest": payload["combined_digest"],
        "store_counts": payload.get("store", {}).get("counts"),
        "research_repo": payload.get("research_repo"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
