"""Materialise the cvelistV5 files for pre-2020 KEV members only.

The 2020-2023 extension is a sparse checkout.  The console also needs the
cvelistV5 record for KEV members published before 2020 so that dual-source
(legacy + cvelistV5) conflicts are visible.  Fetching the whole 1999-2019
archive is out of scope, so this tool resolves only the identifiers that are
in the KEV catalog and asks the partial clone for exactly those blobs.

    python tools/fetch_pre2020_kev.py \
        --repo /tmp/cvel2020_2023 \
        --kev data/snapshots/kev/known_exploited_vulnerabilities.json \
        --out /tmp/cvel_pre2020
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="/tmp/cvel2020_2023")
    parser.add_argument("--kev", default="data/snapshots/kev/known_exploited_vulnerabilities.json")
    parser.add_argument("--out", default="/tmp/cvel_pre2020")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.kev).read_text())
    wanted = {
        entry["cveID"]
        for entry in payload["vulnerabilities"]
        if int(entry["cveID"][4:8]) < 2020
    }

    listing = subprocess.run(
        ["git", "-C", args.repo, "ls-tree", "-r", "--name-only", "HEAD", "--", "cves"],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    by_id = {Path(path).stem: path for path in listing}

    targets = sorted((cve, by_id[cve]) for cve in wanted if cve in by_id)
    missing = sorted(cve for cve in wanted if cve not in by_id)

    process = subprocess.Popen(
        ["git", "-C", args.repo, "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    written = 0
    for cve_id, path in targets:
        process.stdin.write(f"HEAD:{path}\n".encode())
        process.stdin.flush()
        header = process.stdout.readline().decode().strip()
        parts = header.split()
        if len(parts) != 3 or parts[1] != "blob":
            print(f"missing: {cve_id} ({header})", file=sys.stderr)
            missing.append(cve_id)
            continue
        size = int(parts[2])
        blob = process.stdout.read(size)
        process.stdout.read(1)  # trailing newline
        target = Path(args.out) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        written += 1
    process.stdin.close()
    process.wait()

    print(json.dumps({
        "kev_pre2020_ids": len(wanted),
        "written": written,
        "missing": len(missing),
        "missing_ids": missing[:20],
        "out": args.out,
    }, indent=2))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
