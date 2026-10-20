"""Human-readable rendering of an acquisition manifest.

The Markdown report leads with what is *missing*, because the purpose of the
phase is to make gaps impossible to overlook.  It never upgrades a status: the
text is generated from the manifest, not written by hand.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import constants as C

STATUS_ICON = {
    C.VERIFIED: "VERIFIED",
    C.UNAVAILABLE: "UNAVAILABLE",
    C.BLOCKED: "BLOCKED",
}


def _reason(code: str) -> str:
    return C.REASON_DESCRIPTIONS.get(code, "No description recorded.")


def _table(rows: list[list[str]], header: list[str]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |"]
    lines.append("|" + "|".join("---" for _ in header) + "|")
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def render_markdown(
    manifest: dict, verification: Optional[dict] = None, *, store_dir: Optional[str] = None
) -> str:
    summary = manifest.get("summary", {})
    by_status = summary.get("by_status", {})
    by_content = summary.get("by_content_status", {})
    lines: list[str] = []
    lines.append("# VULNOVA 1.7 — Historical Data Acquisition and Provenance")
    lines.append("")
    lines.append(
        "This report is generated from the acquisition manifest. It records what "
        "was actually retrieved, when, and from which publisher. It trains no "
        "model, scores nothing, and does not approve the evaluation protocol."
    )
    lines.append("")
    lines.append(f"- manifest schema: `{manifest.get('schema_version')}`")
    lines.append(f"- generated at (UTC): `{manifest.get('generated_at')}`")
    lines.append(f"- as of: `{manifest.get('as_of')}`")
    lines.append(f"- final candidate maturity: `{manifest.get('final_candidate_maturity')}`")
    lines.append(f"- evidence status: **{summary.get('evidence_status')}**")
    lines.append(f"- manifest digest: `{manifest.get('manifest_digest')}`")
    if store_dir:
        lines.append(f"- artifact store: `{store_dir}`")
    lines.append("")

    lines.append("## Artifact status")
    lines.append("")
    lines.append(
        f"{summary.get('records', 0)} record(s). Content: "
        f"VERIFIED {by_content.get(C.VERIFIED, 0)}, "
        f"UNAVAILABLE {by_content.get(C.UNAVAILABLE, 0)}, "
        f"BLOCKED {by_content.get(C.BLOCKED, 0)}. "
        "Including access provenance: "
        f"VERIFIED {by_status.get(C.VERIFIED, 0)}, "
        f"UNAVAILABLE {by_status.get(C.UNAVAILABLE, 0)}, "
        f"BLOCKED {by_status.get(C.BLOCKED, 0)}."
    )
    lines.append("")
    access = summary.get("by_access_provenance", {})
    if access:
        lines.append(
            "Access provenance: "
            + ", ".join(f"{key} {value}" for key, value in access.items())
            + "."
        )
        lines.append("")

    lines.append("## Requirement verdicts")
    lines.append("")
    rows = []
    for requirement in manifest.get("requirements", []):
        rows.append(
            [
                f"`{requirement['id']}`",
                requirement["status"],
                f"`{requirement['reason_code']}`",
                requirement["detail"].replace("|", "\\|"),
            ]
        )
    lines.extend(_table(rows, ["Requirement", "Status", "Reason", "Detail"]))
    lines.append("")

    blocking = [
        requirement
        for requirement in manifest.get("requirements", [])
        if requirement["status"] != C.VERIFIED
    ]
    lines.append("## Missing or blocked evidence")
    lines.append("")
    if not blocking:
        lines.append("No requirement is missing or blocked.")
    for requirement in blocking:
        lines.append(f"### {requirement['id']} — {requirement['status']}")
        lines.append("")
        lines.append(f"- reason: `{requirement['reason_code']}`")
        lines.append(f"- meaning: {_reason(requirement['reason_code'])}")
        lines.append(f"- detail: {requirement['detail']}")
        if requirement.get("records"):
            lines.append(
                "- records: " + ", ".join(f"`{item}`" for item in requirement["records"])
            )
        lines.append("")

    lines.append("## Source records")
    lines.append("")
    rows = []
    for record in sorted(
        manifest.get("records", []),
        key=lambda item: (item.get("source", ""), str(item.get("cutoff")), item.get("key", "")),
    ):
        rows.append(
            [
                record.get("source", ""),
                str(record.get("key", "")),
                record.get("channel", ""),
                record.get("content_status", ""),
                record.get("access_provenance", ""),
                str(record.get("retrieved_at") or "—"),
                str(record.get("source_timestamp") or "—"),
                str(record.get("sha256") or "—")[:12],
            ]
        )
    lines.extend(
        _table(
            rows,
            [
                "Source",
                "Key",
                "Channel",
                "Content",
                "Access",
                "Retrieved (UTC)",
                "Source time",
                "SHA-256",
            ],
        )
    )
    lines.append("")

    observations = manifest.get("label_observations") or {}
    if observations:
        lines.append("## Label-maturity window per block")
        lines.append("")
        rows = []
        for key, item in sorted(observations.items()):
            rows.append(
                [
                    f"`{key}`",
                    item["maturity_date"],
                    str(item["matured_at_as_of"]),
                    str(item["catalog_released"]),
                    str(item["catalog_covers_maturity"]),
                    item["filter_basis"],
                    item["status"],
                ]
            )
        lines.extend(
            _table(
                rows,
                [
                    "Cutoff",
                    "Maturity",
                    "Matured at as-of",
                    "Catalog released",
                    "Covers maturity",
                    "Filter basis",
                    "Status",
                ],
            )
        )
        lines.append("")
        lines.append(
            "A catalog released before a block's maturity date is right-censored for "
            "that block: filtering it to `dateAdded <= maturity_date` would silently "
            "report incomplete labels as complete, so it is not done."
        )
        lines.append("")

    if verification is not None:
        lines.append("## Offline verification")
        lines.append("")
        lines.append(
            f"- integrity status: **{verification.get('status')}** "
            f"({verification['summary']['verified']} of "
            f"{verification['summary']['checks']} checks verified)"
        )
        lines.append(
            f"- artifacts hashed: {verification['summary']['artifacts_hashed']} · "
            "network used: "
            + ("yes" if verification["summary"]["network_used"] else "no")
        )
        lines.append("")
        rows = [
            [
                f"`{check['id']}`",
                check["status"],
                check["detail"].replace("|", "\\|"),
            ]
            for check in verification.get("checks", [])
        ]
        lines.extend(_table(rows, ["Check", "Status", "Detail"]))
        lines.append("")

    policies = manifest.get("policies") or {}
    if policies:
        lines.append("## Standing policies")
        lines.append("")
        for key, value in sorted(policies.items()):
            lines.append(f"- **{key}**: {value}")
        lines.append("")

    lines.append("## Reproducing this acquisition")
    lines.append("")
    lines.append("```bash")
    lines.append("python -m vulnova.acquisition acquire --store <dir> --manifest <file>")
    lines.append("python -m vulnova.acquisition verify --manifest <file> --store <dir>")
    lines.append("python -m vulnova.acquisition check --manifest <file>")
    lines.append("python -m vulnova.acquisition report --manifest <file> --out report.md")
    lines.append("```")
    lines.append("")
    lines.append(
        "`verify` performs no network I/O: it re-hashes the stored bytes and checks "
        "the recorded timestamps for internal consistency."
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown(text: str, path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


__all__ = ["STATUS_ICON", "render_markdown", "write_markdown"]
