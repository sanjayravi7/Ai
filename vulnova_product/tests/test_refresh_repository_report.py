"""Re-derive the committed 1.8 refresh report from the committed inputs.

Two separate claims are checked here:

1. **The committed report verifies offline.**  Its digest recomputes, every
   refreshed artifact re-hashes, and all seven sealed 1.7 artifacts still match.
2. **Its readiness comparison is reproducible.**  Rebuilding the readiness report
   at the committed as-of date and re-running the comparison reproduces the same
   check statuses, design verdicts and feasibility answers.

The second claim is the one that would catch a silently edited comparison.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from vulnova.acquisition import constants as A
from vulnova.evaluation.readiness import ReadinessOptions, build_report
from vulnova.refresh import constants as C
from vulnova.refresh.comparison import build_comparison
from vulnova.refresh.report import verify_digest
from vulnova.refresh.verify import verify_report_file

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PRODUCT_ROOT.parent
REPORT_PATH = PRODUCT_ROOT / "reports" / "refresh_1_8" / "refresh_report.json"
MARKDOWN_PATH = PRODUCT_ROOT / "reports" / "refresh_1_8" / "REFRESH_1_8_REPORT.md"
BASELINE_PATH = (
    PRODUCT_ROOT / "reports" / "evaluation_readiness_1_6" / "readiness_report.json"
)
PROTOCOL_PATH = PRODUCT_ROOT / "protocol" / "evaluation_protocol.json"
ARCHIVE_MANIFEST = (
    PRODUCT_ROOT / "reports" / "acquisition_1_7" / "acquisition_manifest.json"
)
ARCHIVE_STORE = PRODUCT_ROOT / "data" / "acquisition_store"
REFRESH_STORE = PRODUCT_ROOT / "data" / "refresh_store_1_8"
ARTIFACT_DIR = REPOSITORY_ROOT / "phase2.3k-export"

pytestmark = pytest.mark.skipif(
    not REPORT_PATH.is_file() or not ARCHIVE_MANIFEST.is_file(),
    reason="committed 1.8 refresh report or the sealed 1.7 manifest is absent",
)


def _report() -> dict:
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def test_the_committed_report_digest_recomputes():
    ok, recomputed = verify_digest(_report())
    assert ok, f"recorded digest does not match {recomputed}"


def test_the_committed_report_verifies_offline():
    result = verify_report_file(
        REPORT_PATH,
        store_root=REFRESH_STORE,
        archive_manifest_path=ARCHIVE_MANIFEST,
        archive_store_root=ARCHIVE_STORE,
    )
    assert result["status"] == A.VERIFIED
    assert result["evidence_status"] == A.BLOCKED
    checks = {check["id"]: check for check in result["checks"]}
    assert checks["SEALED_ARCHIVE"]["status"] == A.VERIFIED
    assert checks["MATURITY_INVARIANT"]["status"] == A.VERIFIED
    assert checks["PROTOCOL_NOT_APPROVED"]["status"] == A.VERIFIED
    assert "7 sealed 1.7 artifact(s)" in checks["SEALED_ARCHIVE"]["detail"]


def test_the_committed_report_does_not_claim_maturity_early():
    report = _report()
    final = report["final_candidate"]
    assert final["cutoff"] == "2026-04-01"
    assert final["maturity_date"] == C.final_maturity().isoformat() == "2026-10-28"
    as_of = dt.date.fromisoformat(report["as_of"])
    if as_of < C.final_maturity():
        assert final["calendar_matured"] is False
        assert final["maturity_claimed"] is False
        assert report["summary"]["refresh_status"] == C.REFRESH_BLOCKED_MATURITY
        assert report["maturity_gate"][-1]["status"] == C.GATE_NOT_MATURED
    # Whatever the date, claiming maturity requires an observing catalog.
    assert final["maturity_claimed"] is False or report["maturity_gate"][-1][
        "catalog_observes_maturity"
    ]


def test_the_committed_report_keeps_the_frozen_rules():
    report = _report()
    assert report["parameters"] == {
        "horizon_days": 180,
        "maturity_lag_days": 30,
        "maturity_span_days": 210,
        "required_distinct_test_events": 30,
        "required_sequential_blocks": 3,
    }
    assert report["protocol"]["approval_state"] == "NOT_APPROVED"
    assert report["protocol"]["adopted_design"] is None
    assert report["protocol"]["protocol_execution_authorized"] is False
    assert report["summary"]["reassessment"]["eligible_for_protocol_reassessment"] is False


def test_all_seven_sealed_artifacts_still_match():
    report = _report()
    archived = report["archive_guard"]["after"]
    assert archived["artifact_count"] == 7
    assert archived["all_artifacts_unchanged"] is True
    for row in archived["artifacts"]:
        assert row["recorded_sha256"] == row["actual_sha256"], row["artifact_path"]

    manifest = json.loads(ARCHIVE_MANIFEST.read_text(encoding="utf-8"))
    recorded = {
        record["artifact_path"]: record["sha256"]
        for record in manifest["records"]
        if record.get("artifact_path")
    }
    assert len(recorded) == 7
    for path, digest in recorded.items():
        assert any(
            row["artifact_path"] == path and row["recorded_sha256"] == digest
            for row in archived["artifacts"]
        ), path


def test_the_committed_markdown_names_the_same_digest():
    if not MARKDOWN_PATH.is_file():  # pragma: no cover - partial checkout
        pytest.skip("committed Markdown report is absent")
    text = MARKDOWN_PATH.read_text(encoding="utf-8")
    assert _report()["refresh_digest"] in text
    assert "Maturity claimed | **no**" in text.replace("| Maturity claimed |", "Maturity claimed |")


@pytest.mark.skipif(
    not (ARTIFACT_DIR / "VULNOVA_Phase2.3K_export.tar.gz").is_file()
    or not BASELINE_PATH.is_file(),
    reason="committed Phase 2.3K archive or 1.6 readiness report is absent",
)
def test_the_readiness_comparison_is_reproducible():
    committed = _report()
    as_of = committed["as_of"]
    current = build_report(
        ReadinessOptions(
            artifact_dir=ARTIFACT_DIR,
            protocol_path=PROTOCOL_PATH,
            as_of=as_of,
            deep=True,
            repository_root=REPOSITORY_ROOT,
            extract=True,
        )
    )
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    comparison = build_comparison(
        baseline=baseline,
        current=current,
        gates=committed["maturity_gate"],
        epss_records=committed["epss_records"],
        baseline_path="vulnova_product/reports/evaluation_readiness_1_6/readiness_report.json",
    )
    recorded = committed["readiness_comparison"]
    assert comparison["checks"] == recorded["checks"]
    assert comparison["designs"] == recorded["designs"]
    assert comparison["questions"] == recorded["questions"]
    assert current["report_digest"] == recorded["current"]["report_digest"]
    assert baseline["report_digest"] == recorded["baseline"]["report_digest"]
    assert comparison["checks"]["changed"] == []
    assert comparison["questions"]["semantic_check_statuses_match_baseline"] is True
