"""Evidence adequacy — the interpretation layer.

Kept deliberately separate from :mod:`vulnova.rank`.  ``rank`` owns arithmetic
and produces a number; this module owns the sentence a human reads.  Nothing
here changes the score, the weights or the fixed denominator.

The rule that motivates the module: a record for which *both* CVSS and EPSS
are missing must never be presented as low risk.  Its numerical band is
retained (for ranking continuity) but is labelled as unassessed and surfaced
as ``review_required``.
"""

from __future__ import annotations

INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
PARTIAL = "PARTIAL_EVIDENCE"
SUFFICIENT = "SUFFICIENT_EVIDENCE"

STATUS_LABEL = {
    INSUFFICIENT: "Insufficient evidence — review required",
    PARTIAL: "Partial evidence",
    SUFFICIENT: "Evidence sufficient",
}


def assess(*, has_cvss: bool, has_epss: bool, kev_listed: bool,
           score: int, band: str) -> dict:
    missing = []
    if not has_cvss:
        missing.append("cvss_severity")
    if not has_epss:
        missing.append("epss_probability")

    if not has_cvss and not has_epss:
        status = INSUFFICIENT
    elif has_cvss and has_epss:
        status = SUFFICIENT
    else:
        status = PARTIAL

    review_required = status == INSUFFICIENT

    if status == INSUFFICIENT and kev_listed:
        statement = (
            f"No CVSS base score and no EPSS estimate are available for this CVE. "
            f"The score of {score} comes from KEV membership (40 points) and the "
            f"publication-recency component alone. KEV membership is itself evidence "
            f"of exploitation, but the {band} band reflects missing severity and "
            f"likelihood data, not a judgement that this vulnerability is low risk."
        )
    elif status == INSUFFICIENT:
        statement = (
            f"No CVSS base score and no EPSS estimate are available for this CVE. "
            f"The score of {score} comes only from the publication-recency component. "
            f"The {band} band is the mechanical output of the fixed scoring rules and "
            f"is NOT an assessment that this vulnerability is low risk: it is "
            f"unassessed until severity or likelihood evidence is obtained."
        )
    elif status == PARTIAL and not has_epss:
        statement = (
            f"CVSS is available but EPSS is not: severity is measured, exploitation "
            f"likelihood is unknown. The score of {score} is a floor built from the "
            f"available signals and treats the missing component as zero points."
        )
    elif status == PARTIAL and not has_cvss:
        statement = (
            f"EPSS is available but CVSS is not: exploitation likelihood is measured, "
            f"severity and impact are unknown. The score of {score} is a floor built "
            f"from the available signals and treats the missing component as zero points."
        )
    else:
        statement = (
            f"CVSS and EPSS are both available; the score of {score} reflects all "
            f"four components."
        )

    return {
        "status": status,
        "label": STATUS_LABEL[status],
        "review_required": review_required,
        "missing": missing,
        "numeric_band": band,
        "display_band": f"{band} (INSUFFICIENT EVIDENCE)" if review_required else band,
        "statement": statement,
        "denominator_rescaled": False,
    }
