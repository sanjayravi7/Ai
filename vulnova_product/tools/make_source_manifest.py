"""Record the exact cvelistV5 content used by the build.

The upstream tree is 2.6 GB.  It is not copied into the workspace; instead the
manifest records the source revision, retrieval timestamp, per-directory file
counts and a SHA-256 tree digest over ``(path, sha256)`` so the content can be
re-fetched and re-verified byte for byte.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnova.provenance import sha256_file, tree_digest, utc_now, write_json


def digest_dir(root: Path) -> dict:
    entries = []
    files = sorted(root.rglob("CVE-*.json"))
    for path in files:
        entries.append((str(path.relative_to(root)), sha256_file(path)))
    return {"files": len(files), "tree_digest": tree_digest(entries)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="/tmp/cvel2020_2023")
    parser.add_argument("--out", default="data/snapshots/cvelistv5/MANIFEST.json")
    parser.add_argument("--years", default="2020,2021,2022,2023,2024,2025,2026")
    parser.add_argument("--pre2020-root", default="/tmp/cvel_pre2020")
    parser.add_argument("--kev-subset", default=None,
                        help="optional path list for the pre-2020 KEV subset")
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    committed = subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--format=%cI"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    years = {}
    for year in [y.strip() for y in args.years.split(",") if y.strip()]:
        base = repo / "cves" / year
        years[year] = digest_dir(base) if base.is_dir() else {"files": 0, "tree_digest": None}

    pre2020 = None
    pre_root = Path(args.pre2020_root)
    if pre_root.is_dir():
        pre2020 = digest_dir(pre_root)
        pre2020["note"] = (
            "Only KEV members published before 2020 were materialised; this is "
            "not the full 1999-2019 archive."
        )

    payload = {
        "source": "cvelistv5",
        "revision": revision,
        "committed_at": committed,
        "retrieved_at": utc_now(),
        "repository": "https://github.com/CVEProject/cvelistV5",
        "retrieval_method": (
            "git clone --filter=blob:none --no-checkout --depth 1 + "
            "git sparse-checkout set /cves/<year>/ (2020-2026); pre-2020 KEV "
            "members fetched individually with git cat-file --batch"
        ),
        "years": years,
        "pre2020_kev_subset": pre2020,
        "scope_note": (
            "The full historical archive was deliberately not downloaded. "
            "Identifiers published before 2020 are ingested from the legacy "
            "extract, except KEV members, whose cvelistV5 records are fetched "
            "individually so dual-source conflicts remain visible."
        ),
    }
    write_json(args.out, payload)
    print(json.dumps(payload, indent=2)[:4000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
