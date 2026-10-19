"""Reproduce the committed readiness report from the committed artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnova.evaluation.readiness import ReadinessOptions, build_report

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PRODUCT_ROOT.parent
ARTIFACT_DIR = REPOSITORY_ROOT / "phase2.3k-export"
REPORT_PATH = (
    PRODUCT_ROOT / "reports" / "evaluation_readiness_1_6" / "readiness_report.json"
)
PROTOCOL_PATH = PRODUCT_ROOT / "protocol" / "evaluation_protocol.json"

pytestmark = pytest.mark.skipif(
    not (ARTIFACT_DIR / "VULNOVA_Phase2.3K_export.tar.gz").is_file()
    or not REPORT_PATH.is_file(),
    reason="committed Phase 2.3K archive or readiness report is absent",
)


def test_committed_report_reproduces_from_committed_artifacts():
    options = ReadinessOptions(
        artifact_dir=ARTIFACT_DIR,
        protocol_path=PROTOCOL_PATH,
        as_of=None,
        deep=True,
        export_archive=None,
        core_bundle=None,
        extract_dir=None,
        previous_report_path=None,
        repository_root=REPOSITORY_ROOT,
        extract=True,
    )
    report = build_report(options)
    committed = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    assert report["schema_version"] == "vulnova.evaluation_readiness/1.6"
    assert report["report_digest"] == committed["report_digest"]
    assert report["summary"] == committed["summary"]
    assert report["readiness"]["status"] == committed["readiness"]["status"]
    assert report["readiness"]["primary_blocker"] == committed["readiness"][
        "primary_blocker"
    ]
    assert report["protocol"]["approval_state"] == "NOT_APPROVED"
    assert report["readiness"]["model_training_authorized"] is False
    assert report["readiness"]["protocol_execution_authorized"] is False
