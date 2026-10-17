"""HTTP surface: filters, detail payload parity and error messages."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from vulnova import web


@pytest.fixture()
def server(db):
    httpd = web.build_server(db, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base
    httpd.shutdown()
    httpd.server_close()


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as response:
        return response.status, json.loads(response.read().decode())


def test_status_exposes_weights_bands_and_coverage(server):
    _, payload = get(server, "/api/status")
    assert payload["denominator"] == 100
    assert sum(b["max_points"] for b in payload["weights"]) == 100
    assert len(payload["bands"]) == 5
    assert payload["coverage"]["epss"]["total"] == 4
    assert payload["reference_date"] == "2026-10-16"
    assert payload["method"].endswith("Not a validated predictive model.")
    definition = payload["publication_recency_definition"]
    assert definition["component"] == "publication_recency"
    assert definition["basis"] == "publication_date"
    assert "recency_definition" not in payload


def test_ranking_exposes_publication_recency_points(server):
    _, payload = get(server, "/api/ranking?limit=5")
    row = payload["rows"][0]
    assert "publication_recency_points" in row
    assert "recency_points" not in row


def test_detail_names_the_component_publication_recency(server):
    _, detail = get(server, "/api/cve/CVE-2023-0001")
    names = [s["name"] for s in detail["priority"]["signals"]]
    assert names == [
        "kev_known_exploited", "epss_probability", "cvss_severity",
        "publication_recency",
    ]


def test_ranking_excludes_rejected(server):
    _, payload = get(server, "/api/ranking?limit=50")
    ids = [row["cve_id"] for row in payload["rows"]]
    assert "CVE-2023-0007" not in ids
    assert len(ids) == 6
    assert payload["total"] == 6


def test_ranking_is_sorted_by_score_desc(server):
    _, payload = get(server, "/api/ranking?limit=50")
    scores = [row["score"] for row in payload["rows"]]
    assert scores == sorted(scores, reverse=True)


def test_band_filter(server):
    _, payload = get(server, "/api/ranking?band=P1_CRITICAL&limit=50")
    assert all(row["band"] == "P1_CRITICAL" for row in payload["rows"])


def test_kev_filter(server):
    _, payload = get(server, "/api/ranking?kev=1&limit=50")
    assert {row["cve_id"] for row in payload["rows"]} == {
        "CVE-2019-0005", "CVE-2023-0006"
    }


def test_review_filter_returns_insufficient_evidence_rows(server):
    _, payload = get(server, "/api/ranking?review=1&limit=50")
    assert {row["cve_id"] for row in payload["rows"]} == {
        "CVE-2023-0002", "CVE-2023-0006"
    }
    assert all(row["review_required"] for row in payload["rows"])


def test_search_matches_identifier(server):
    _, payload = get(server, "/api/ranking?q=CVE-2023-0001")
    assert [row["cve_id"] for row in payload["rows"]] == ["CVE-2023-0001"]


def test_detail_matches_list_score(server):
    _, listing = get(server, "/api/ranking?q=CVE-2019-0005")
    _, detail = get(server, "/api/cve/CVE-2019-0005")
    assert listing["rows"][0]["score"] == detail["priority"]["score"]
    assert listing["rows"][0]["band"] == detail["priority"]["band"]


def test_detail_exposes_conflict_and_comparability(server):
    _, detail = get(server, "/api/cve/CVE-2019-0005")
    conflict = detail["observed"]["cvss"]["conflict"]
    assert conflict["has_conflict"] is True
    assert conflict["comparable"] is False
    assert len(detail["observed"]["cvss"]["candidates"]) == 3


def test_detail_exposes_insufficient_evidence(server):
    _, detail = get(server, "/api/cve/CVE-2023-0002")
    assert detail["assessment"]["review_required"] is True
    assert "INSUFFICIENT EVIDENCE" in detail["assessment"]["display_band"]


def test_unknown_cve_returns_404_with_explanation(server):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        get(server, "/api/cve/CVE-1999-9999")
    assert excinfo.value.code == 404
    body = json.loads(excinfo.value.read().decode())
    assert "No loaded source covers publication year 1999" in body["message"]


def test_malformed_identifier_returns_404(server):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        get(server, "/api/cve/NOT-A-CVE")
    body = json.loads(excinfo.value.read().decode())
    assert "not a CVE identifier" in body["message"]


def test_static_assets_are_served(server):
    with urllib.request.urlopen(server + "/static/app.js", timeout=10) as response:
        body = response.read().decode()
    assert "INSUFFICIENT EVIDENCE" in body
    assert response.status == 200


def test_index_is_served(server):
    with urllib.request.urlopen(server + "/", timeout=10) as response:
        body = response.read().decode()
    assert "VULNOVA" in body
    lowered = body.lower()
    assert "validated predictive model" in lowered
    assert "<em>not</em> a validated predictive model" in body.lower()


def test_unknown_route_is_json_404(server):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        get(server, "/api/nope")
    assert excinfo.value.code == 404
