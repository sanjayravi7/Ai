"""Materialise the exact tree that is committed to Git.

    python tools/build_dist.py --dest /tmp/vulnova_dist

Only whitelisted paths are copied. The virtualenv, the derived database,
caches and the 2.6 GB cvelistV5 checkout can never enter the commit, because
they are not on the allow-list.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

INCLUDE_DIRS = [
    "vulnova",
    "tests",
    "tools",
    "docs",
    "reports/improvement1_2",
    "reports/ingest_receipts",
    "data/snapshots/kev",
    "data/snapshots/epss",
    "data/snapshots/cvelistv5",
]

INCLUDE_FILES = [
    "README.md",
    "RUNBOOK.md",
    "REBUILD.md",
    "PRESERVATION.md",
    "requirements.txt",
    "pyproject.toml",
    ".gitignore",
    "verify_all.sh",
    "data/snapshots/SOURCES.md",
]

EXCLUDE_NAMES = {"__pycache__", ".pytest_cache", ".venv", "build"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".db", ".db-wal", ".db-shm"}


def wanted(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if any(part in EXCLUDE_NAMES for part in rel.parts):
        return False
    if path.suffix in EXCLUDE_SUFFIXES:
        return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", required=True)
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    dest = Path(args.dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    copied = []
    for rel_dir in INCLUDE_DIRS:
        source = ROOT / rel_dir
        if not source.is_dir():
            print(f"missing directory: {rel_dir}", file=sys.stderr)
            continue
        for path in sorted(source.rglob("*")):
            if not path.is_file() or not wanted(path):
                continue
            rel = path.relative_to(ROOT)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied.append((str(rel), target.stat().st_size))

    for rel in INCLUDE_FILES:
        source = ROOT / rel
        if not source.is_file():
            print(f"missing file: {rel}", file=sys.stderr)
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append((rel, target.stat().st_size))

    copied.sort()
    total = sum(size for _, size in copied)
    payload = {
        "files": len(copied),
        "total_bytes": total,
        "entries": [{"path": path, "bytes": size} for path, size in copied],
    }
    print(json.dumps({k: v for k, v in payload.items() if k != "entries"}, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
