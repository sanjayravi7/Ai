"""Frozen evaluation constants.

These values are a protocol contract, not tuning parameters.  They are duplicated
in ``protocol/evaluation_protocol.json`` and in the Phase 2.3K artifacts; the
readiness command cross-checks all three.  Changing a value here without an
approved protocol amendment is a failure, not a configuration option.
"""

from __future__ import annotations

import datetime as dt

#: Forward outcome window used to define an event.
HORIZON_DAYS = 180

#: Time allowed after the horizon for labels to settle before a block is used.
MATURITY_LAG_DAYS = 30

#: Horizon plus maturation lag.  Consecutive sequential blocks must be at least
#: this far apart; 180 days is not enough.
MATURITY_SPAN_DAYS = HORIZON_DAYS + MATURITY_LAG_DAYS

#: Minimum number of *distinct* test events in every evaluated block.
REQUIRED_DISTINCT_TEST_EVENTS = 30

#: Number of sequential blocks (train / validation / test) the protocol requires.
REQUIRED_SEQUENTIAL_BLOCKS = 3

#: Reference date of the Phase 2.3K research.  The readiness command defaults to
#: this date so that a run is reproducible from committed inputs.  Pass
#: ``--as-of`` to evaluate a different calendar date.
DEFAULT_REFERENCE_DATE = dt.date(2026, 10, 15)

#: The earliest three-block design the monthly cutoff grid can carry, as
#: concluded by Phase 2.3K.  It is registered as a *candidate*, never adopted.
EARLIEST_THREE_BLOCK_DESIGN_ID = "A2_EARLIEST_3BLOCK"
EARLIEST_THREE_BLOCK_CUTOFFS = (
    dt.date(2025, 2, 1),
    dt.date(2025, 9, 1),
    dt.date(2026, 4, 1),
)

#: The largest design Phase 2.3K found constructible.  Two blocks are not a
#: protocol-compliant train/validation/test design.
LARGEST_TWO_BLOCK_DESIGN_ID = "E_LABEL_MATURED_2BLOCK"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_BLOCKED = "BLOCKED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

CHECK_STATUSES = (STATUS_PASS, STATUS_FAIL, STATUS_BLOCKED, STATUS_NOT_APPLICABLE)

SCHEMA_VERSION = "vulnova.evaluation_readiness/1.6"
PROTOCOL_ID = "vulnova-evaluation-protocol-1.6"


def assert_internal_consistency() -> None:
    """Fail fast if the constants contradict each other."""
    if MATURITY_SPAN_DAYS != HORIZON_DAYS + MATURITY_LAG_DAYS:
        raise AssertionError("maturity span must equal horizon + lag")
    if REQUIRED_SEQUENTIAL_BLOCKS < 2:
        raise AssertionError("a sequential design needs at least two blocks")
    if len(EARLIEST_THREE_BLOCK_CUTOFFS) != REQUIRED_SEQUENTIAL_BLOCKS:
        raise AssertionError("earliest three-block design must have three cutoffs")
    previous = EARLIEST_THREE_BLOCK_CUTOFFS[0]
    for cutoff in EARLIEST_THREE_BLOCK_CUTOFFS[1:]:
        if (cutoff - previous).days < MATURITY_SPAN_DAYS:
            raise AssertionError("earliest design cutoffs violate the maturity span")
        previous = cutoff


assert_internal_consistency()
