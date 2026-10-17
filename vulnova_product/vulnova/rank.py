"""Priority scoring.

The score is a fixed-denominator, rule-based sum of four components::

    KEV membership ......... 40
    EPSS probability ....... 30   (round(probability * 30))
    CVSS base score ........ 20   (round(value / 10 * 20))
    publication recency .... 10   (90 days full credit, linear decay to 0 at 1825)
    ----------------------------
    maximum ................ 100

Missing inputs contribute **zero points** and are named in ``missing_signals``.
Zero points is an arithmetic necessity, not a statement about risk; the
interpretation layer (``vulnova.assessment``) is what tells the reader that a
score built on missing evidence is unassessed.  The denominator is fixed at
100 and must not be rescaled when evidence is missing.

``publication_recency`` is measured from the CVE *publication date* alone.

It does **not** represent:
  * recent exploitation activity;
  * recent KEV inclusion (the catalog ``dateAdded`` is shown separately and
    never contributes to this component);
  * an independently verified increase in threat activity.

It answers "was this vulnerability disclosed recently?", not "is it being
exploited now?".  See ``docs/RANKING_SEMANTICS.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

MAX_SCORE = 100

WEIGHTS = {
    "kev_known_exploited": 40,
    "epss_probability": 30,
    "cvss_severity": 20,
    "publication_recency": 10,
}

BANDS = (
    (70, "P1_CRITICAL"),
    (40, "P2_HIGH"),
    (20, "P3_MODERATE"),
    (1, "P4_LOW"),
    (0, "P5_NONE"),
)

BAND_CONSEQUENCE = {
    "P1_CRITICAL": "immediate triage",
    "P2_HIGH": "scheduled triage",
    "P3_MODERATE": "backlog",
    "P4_LOW": "lowest priority",
    "P5_NONE": "no positive evidence",
}

PUBLICATION_RECENCY_FULL_DAYS = 90
PUBLICATION_RECENCY_ZERO_DAYS = 1825

# The component is named ``publication_recency`` everywhere it is presented.
# Older code and the storage column use the short name ``recency_points``.


METHOD = (
    "Provisional, rule-based prioritisation: fixed-denominator sum of KEV "
    "membership, EPSS probability, CVSS base score and publication recency. "
    "Not a validated predictive model."
)


@dataclass(frozen=True)
class Signal:
    name: str
    points: int
    max_points: int
    status: str          # OBSERVED | MISSING_FROM_SOURCE | NOT_LISTED_IN_CATALOG | UNAVAILABLE
    detail: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "points": self.points,
            "max_points": self.max_points,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Score:
    cve_id: str
    score: int
    band: str
    signals: tuple
    missing_signals: tuple

    @property
    def kev_listed(self) -> bool:
        for signal in self.signals:
            if signal.name == "kev_known_exploited":
                return signal.status == "OBSERVED"
        return False

    def as_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "score": self.score,
            "max_score": MAX_SCORE,
            "band": self.band,
            "band_consequence": BAND_CONSEQUENCE[self.band],
            "signals": [signal.as_dict() for signal in self.signals],
            "missing_signals": list(self.missing_signals),
        }


def _parse_day(value):
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return BANDS[-1][1]


def kev_points(listed: bool) -> int:
    return WEIGHTS["kev_known_exploited"] if listed else 0


def epss_points(probability) -> int | None:
    if probability is None:
        return None
    probability = min(max(float(probability), 0.0), 1.0)
    return round(probability * WEIGHTS["epss_probability"])


def cvss_points(value) -> int | None:
    if value is None:
        return None
    value = min(max(float(value), 0.0), 10.0)
    return round(value / 10.0 * WEIGHTS["cvss_severity"])


def publication_recency_points(published, reference) -> int | None:
    """Headline publication-age score: full credit inside 90 days, zero at 1,825.

    The arithmetic is unchanged from the component previously presented under the
    short name ``recency``; only the presented name and its explanation changed.
    """
    published_day = _parse_day(published)
    reference_day = _parse_day(reference)
    if published_day is None or reference_day is None:
        return None
    age = (reference_day - published_day).days
    if age <= PUBLICATION_RECENCY_FULL_DAYS:
        return WEIGHTS["publication_recency"]
    if age >= PUBLICATION_RECENCY_ZERO_DAYS:
        return 0
    span = PUBLICATION_RECENCY_ZERO_DAYS - PUBLICATION_RECENCY_FULL_DAYS
    # floor, not round: the documented rule is *full* credit inside 90 days,
    # and rounding would silently extend full credit to ~107 days.
    return int(
        WEIGHTS["publication_recency"]
        * (PUBLICATION_RECENCY_ZERO_DAYS - age) / span
    )


def score_cve(
    cve_id: str,
    *,
    reference_date,
    published=None,
    kev_listed: bool = False,
    epss_probability=None,
    cvss_value=None,
    cvss_version=None,
    cvss_source=None,
) -> Score:
    signals = []

    signals.append(
        Signal(
            "kev_known_exploited",
            kev_points(kev_listed),
            WEIGHTS["kev_known_exploited"],
            "OBSERVED" if kev_listed else "NOT_LISTED_IN_CATALOG",
            "Listed in the CISA KEV catalog."
            if kev_listed
            else "Not listed in the KEV catalog at the reference date; "
            "this is absence of catalog evidence, not evidence of no exploitation.",
        )
    )

    epss_pts = epss_points(epss_probability)
    signals.append(
        Signal(
            "epss_probability",
            0 if epss_pts is None else epss_pts,
            WEIGHTS["epss_probability"],
            "MISSING_FROM_SOURCE" if epss_pts is None else "OBSERVED",
            "No EPSS score for this identifier."
            if epss_pts is None
            else f"EPSS probability {epss_probability:.5f}.",
        )
    )

    cvss_pts = cvss_points(cvss_value)
    signals.append(
        Signal(
            "cvss_severity",
            0 if cvss_pts is None else cvss_pts,
            WEIGHTS["cvss_severity"],
            "MISSING_FROM_SOURCE" if cvss_pts is None else "OBSERVED",
            "No CVSS base score in any loaded source."
            if cvss_pts is None
            else f"CVSS v{cvss_version} base score {cvss_value:.1f} from {cvss_source}.",
        )
    )

    recency_pts = publication_recency_points(published, reference_date)
    signals.append(
        Signal(
            "publication_recency",
            0 if recency_pts is None else recency_pts,
            WEIGHTS["publication_recency"],
            "MISSING_FROM_SOURCE" if recency_pts is None else "OBSERVED",
            "No CVE publication date is available."
            if recency_pts is None
            else (
                f"CVE published {published}; publication age only. This component "
                "does not represent recent exploitation activity, recent KEV "
                "inclusion, or an independently verified increase in threat activity."
            ),
        )
    )

    total = sum(signal.points for signal in signals)
    total = min(total, MAX_SCORE)
    missing = tuple(
        signal.name for signal in signals
        if signal.status in ("MISSING_FROM_SOURCE", "UNAVAILABLE")
    )
    return Score(
        cve_id=cve_id,
        score=total,
        band=band_for(total),
        signals=tuple(signals),
        missing_signals=missing,
    )


def describe_weights() -> list:
    return [
        {"signal": name, "max_points": points, "share_of_denominator": points / MAX_SCORE}
        for name, points in WEIGHTS.items()
    ]


def denominator_check() -> int:
    return sum(WEIGHTS.values())
