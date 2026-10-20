#!/usr/bin/env python
"""Check a VULNOVA prospective-capture schedule without making a live capture.

    python tools/check_schedule.py --store /srv/vulnova/evidence \
        --out /srv/vulnova/reports/prospective.md

Run this after editing a crontab, a systemd timer or a Task Scheduler entry, and
again after moving a machine between timezones.  It validates the interpreter,
the store and report paths, the sealed-path guard, hard-link support on the
destination filesystem and the integrity of the existing store.  It never opens a
socket, never captures and never writes evidence.

Exit status: ``0`` when every check passes, ``1`` when any check fails.  Warnings
do not fail the run — an empty store is a warning, not a misconfiguration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnova.prospective import constants as C  # noqa: E402
from vulnova.prospective.preflight import (  # noqa: E402
    EXIT_FAILED,
    EXIT_OK,
    FAIL,
    TRIGGER_UTC,
    run_preflight,
)


def _parse_trigger(value: str) -> dt.time:
    try:
        hour, minute = value.split(":")
        return dt.time(int(hour), int(minute))
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            f"expected HH:MM in 24-hour UTC, got {value!r}"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_schedule.py",
        description=(
            "Offline preflight for a scheduled prospective cycle. Validates "
            "paths, the sealed-path guard, hard-link support and store integrity "
            "without capturing anything."
        ),
    )
    parser.add_argument(
        "--store", type=Path, default=C.default_store_root(),
        help="evidence store (default: %(default)s)",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="report path the schedule will write (optional)",
    )
    parser.add_argument(
        "--trigger-utc", type=_parse_trigger, default=TRIGGER_UTC, metavar="HH:MM",
        help="intended UTC trigger time (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    result = run_preflight(args.store, args.out, trigger=args.trigger_utc)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_OK if result["status"] != FAIL else EXIT_FAILED

    print("VULNOVA 1.9 — schedule preflight (offline, no capture)")
    print(f"store: {result['store']}")
    if result["report_path"]:
        print(f"report: {result['report_path']}")
    for check in result["checks"]:
        print(f"  {check['status']:<4} {check['id']:<24} {check['detail']}")
    print(f"preflight: {result['status']}")
    if result["failed"]:
        print("failed checks: " + ", ".join(result["failed"]))
    print("network used: no")
    return EXIT_OK if result["status"] != FAIL else EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
