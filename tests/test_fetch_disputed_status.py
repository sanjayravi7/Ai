"""Synthetic tests for the disputed-record fetcher; every call is mocked (no network).

The fake opener mimics the GitHub contents API exactly as far as this pipeline
reads it: a base64 payload plus the Git blob SHA of the decoded content, or a
404 for identifiers that do not exist at the pinned commit.
"""

import base64
import contextlib
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd

from src.cve_status_sources import CveStatusValidationError
from src.fetch_cve_status import git_blob_sha, list_status_manifests
from src.fetch_disputed_status import (
    DEFAULT_DISPUTED_ROOT,
    disputed_cve_ids,
    fetch_disputed_snapshot,
    main,
    make_authorized_opener,
    token_from_environment,
)
from src.fetch_threat_intelligence import SourceUnavailableError

from tests.disputed_fixtures import (
    PIPELINE_COMMIT,
    record_bytes,
    disputed_tag_only_record,
    disputed_text_record,
    synthetic_dataset,
    write_dataset,
)


class FakeResponse:
    """Minimal stand-in for an ``http.client.HTTPResponse``."""

    def __init__(self, payload, url, status=200):
        self._payload = payload
        self._url = url
        self.status = status
        self._offset = 0

    def read(self, size=-1):
        if size is None or size < 0:
            chunk, self._offset = self._payload[self._offset :], len(self._payload)
            return chunk
        chunk = self._payload[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def geturl(self):
        return self._url

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeContentsOpener:
    """Serve synthetic contents-API responses and record the requests."""

    def __init__(self, records, *, missing=(), status_overrides=None, blob_sha_overrides=None):
        self.records = records
        self.missing = set(missing)
        self.status_overrides = dict(status_overrides or {})
        self.blob_sha_overrides = dict(blob_sha_overrides or {})
        self.requests = []
        self.authorization_headers = []

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.requests.append(url)
        self.authorization_headers.append(
            request.get_header("Authorization") if hasattr(request, "get_header") else None
        )
        cve_id = next((part.split(".json")[0] for part in url.split("/") if part.startswith("CVE-")), "")
        override = self.status_overrides.get(cve_id)
        if override is not None:
            raise urllib.error.HTTPError(url, override, "forced", {}, io.BytesIO(b""))
        if cve_id in self.missing or cve_id not in self.records:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))
        payload = self.records[cve_id]
        document = {
            "name": f"{cve_id}.json",
            "path": "/".join(url.split("/contents/")[1].split("?")[0].split("/")),
            "sha": self.blob_sha_overrides.get(cve_id, git_blob_sha(payload)),
            "size": len(payload),
            "encoding": "base64",
            "content": base64.b64encode(payload).decode("ascii"),
            "html_url": "https://github.com/CVEProject/cvelistV5/blob/pinned/" + cve_id + ".json",
        }
        return FakeResponse(json.dumps(document).encode("utf-8"), url)


def commit_opener(records, **kwargs):
    """A fake opener that resolves any ``/commits/`` request to a fixed SHA."""
    inner = FakeContentsOpener(records, **kwargs)

    def opener(request, timeout=None):
        url = request.full_url
        if "/commits/" in url:
            inner.requests.append(url)
            return FakeResponse(json.dumps({"sha": PIPELINE_COMMIT}).encode("utf-8"), url)
        return inner(request, timeout=timeout)

    opener.inner = inner
    return opener


class DisputedIdSelectionTests(unittest.TestCase):
    def test_only_marker_rows_are_selected_and_deduplicated(self):
        frame = synthetic_dataset()
        frame = pd.concat([frame, frame[frame["cve_id"] == "CVE-2020-1001"]], ignore_index=True)
        identifiers = disputed_cve_ids(frame)
        self.assertEqual(len(identifiers), 8)
        self.assertEqual(identifiers, sorted(identifiers))
        self.assertIn("CVE-2020-1003", identifiers)
        self.assertNotIn("CVE-2020-1009", identifiers)

    def test_missing_columns_raise(self):
        with self.assertRaises(ValueError):
            disputed_cve_ids(pd.DataFrame({"cve_id": ["CVE-2020-1001"]}))
        with self.assertRaises(ValueError):
            disputed_cve_ids(pd.DataFrame({"summary": ["** DISPUTED ** x"]}))


class TokenHandlingTests(unittest.TestCase):
    def test_token_is_read_from_the_first_populated_variable_only(self):
        token, name = token_from_environment(("GH_TOKEN", "GITHUB_TOKEN"), environ={"GITHUB_TOKEN": "abc"})
        self.assertEqual((token, name), ("abc", "GITHUB_TOKEN"))
        self.assertEqual(token_from_environment(("GH_TOKEN",), environ={}), (None, ""))

    def test_authorized_opener_adds_a_header_without_leaking_the_token(self):
        seen = {}

        def base(request, timeout=None):
            seen["header"] = request.get_header("Authorization")
            return "response"

        opener = make_authorized_opener("secret-token", base=base)
        request = urllib.request.Request("https://api.github.com/repos/x/y/contents/z")
        self.assertEqual(opener(request, timeout=5), "response")
        self.assertEqual(seen["header"], "token secret-token")


class FetchSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.records = {
            "CVE-2020-1001": record_bytes(disputed_text_record()),
            "CVE-2020-1002": record_bytes(disputed_tag_only_record()),
        }
        self.addCleanup(self.temp.cleanup)

    def _fetch(self, opener, **overrides):
        parameters = {
            "repository": "CVEProject/cvelistV5",
            "requested_ref": "main",
            "root": self.root / "disputed",
            "opener": opener,
            "workers": 1,
            "sleep": lambda seconds: None,
        }
        parameters.update(overrides)
        return fetch_disputed_snapshot(
            ["CVE-2020-1001", "CVE-2020-1002", "CVE-2020-1005"], **parameters
        )

    def test_snapshot_records_state_checksums_and_missing_identifiers(self):
        opener = commit_opener(self.records)
        manifest = self._fetch(opener)
        self.assertEqual(manifest["commit_sha"], PIPELINE_COMMIT)
        self.assertEqual(manifest["record_count"], 2)
        self.assertEqual(manifest["missing_count"], 1)
        self.assertEqual(manifest["requested_record_count"], 3)
        self.assertEqual(manifest["records"]["CVE-2020-1001"]["state"], "PUBLISHED")
        self.assertEqual(manifest["records"]["CVE-2020-1005"]["reason"], "http_404_not_found")
        self.assertFalse(manifest["records"]["CVE-2020-1005"]["present"])
        self.assertEqual(
            manifest["failed_records"], {"CVE-2020-1005": "http_404_not_found"}
        )
        # Every request is pinned to the resolved commit, never to a branch name.
        for url in opener.inner.requests:
            if "/contents/" in url:
                self.assertIn(PIPELINE_COMMIT, url)
        written = sorted(path.name for path in (self.root / "disputed" / "cve_status").glob("record-*.json"))
        self.assertEqual(len(written), 2)
        self.assertEqual(len(list_status_manifests(self.root / "disputed")), 1)

    def test_unreachable_record_is_recorded_and_does_not_abort_the_run(self):
        opener = commit_opener(self.records, status_overrides={"CVE-2020-1002": 503})
        manifest = self._fetch(opener)
        self.assertEqual(manifest["record_count"], 1)
        self.assertIn("source_unavailable", manifest["failed_records"]["CVE-2020-1002"])
        self.assertTrue(manifest["records"]["CVE-2020-1001"]["present"])

    def test_blob_sha_mismatch_is_refused_and_recorded(self):
        opener = commit_opener(self.records, blob_sha_overrides={"CVE-2020-1001": "0" * 40})
        manifest = self._fetch(opener)
        self.assertFalse(manifest["records"]["CVE-2020-1001"]["present"])
        self.assertIn("validation_error", manifest["failed_records"]["CVE-2020-1001"])

    def test_pinned_commit_skips_commit_resolution(self):
        opener = commit_opener(self.records)
        manifest = self._fetch(opener, commit_sha=PIPELINE_COMMIT)
        self.assertEqual(manifest["commit_sha"], PIPELINE_COMMIT)
        self.assertFalse(any("/commits/" in url for url in opener.inner.requests))

    def test_parallel_and_sequential_runs_agree(self):
        sequential = self._fetch(commit_opener(self.records), root=self.root / "seq")
        parallel = self._fetch(commit_opener(self.records), root=self.root / "par", workers=3)
        for key in ("commit_sha", "record_count", "missing_count", "failed_records"):
            self.assertEqual(sequential[key], parallel[key])
        self.assertEqual(
            sequential["records"]["CVE-2020-1001"]["sha256"],
            parallel["records"]["CVE-2020-1001"]["sha256"],
        )

    def test_verified_snapshot_is_reused_unless_refresh_is_requested(self):
        first = self._fetch(commit_opener(self.records), reuse=True)
        self.assertNotIn("_reused_cached_snapshot", first)
        second_opener = commit_opener(self.records)
        second = self._fetch(second_opener, reuse=True)
        self.assertTrue(second.get("_reused_cached_snapshot"))
        # No record download happened the second time (only commit resolution).
        self.assertEqual([url for url in second_opener.inner.requests if "/contents/" in url], [])
        refreshed = self._fetch(commit_opener(self.records), reuse=False)
        self.assertNotIn("_reused_cached_snapshot", refreshed)

    def test_invalid_worker_count_is_rejected(self):
        with self.assertRaises(CveStatusValidationError):
            self._fetch(commit_opener(self.records), workers=0)
        with self.assertRaises(CveStatusValidationError):
            self._fetch(commit_opener(self.records), workers=99)

    def test_no_identifiers_is_rejected(self):
        with self.assertRaises(CveStatusValidationError):
            fetch_disputed_snapshot([], root=self.root, opener=commit_opener(self.records))


class FetchCommandLineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dataset_path = write_dataset(self.root / "clean.csv")
        self.addCleanup(self.temp.cleanup)

    def test_missing_token_fails_closed_without_the_override(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(
                [
                    "--input",
                    str(self.dataset_path),
                    "--snapshot-root",
                    str(self.root / "disputed"),
                    "--token-env",
                    "VULNOVA_TEST_MISSING_TOKEN",
                ]
            )
        self.assertEqual(code, 2)

    def test_offline_directory_import_needs_origin_and_commit(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(["--from-directory", str(self.root), "--snapshot-root", str(self.root / "disputed")])

    def test_offline_directory_import_writes_a_pinned_manifest(self):
        records_dir = self.root / "records"
        records_dir.mkdir()
        for cve_id, payload in (
            ("CVE-2020-1001", record_bytes(disputed_text_record())),
            ("CVE-2020-1002", record_bytes(disputed_tag_only_record())),
        ):
            (records_dir / f"{cve_id}.json").write_bytes(payload)
        code = main(
            [
                "--from-directory",
                str(records_dir),
                "--origin-url",
                "https://example.test/cvelistV5",
                "--commit-sha",
                PIPELINE_COMMIT,
                "--snapshot-root",
                str(self.root / "disputed"),
            ]
        )
        self.assertEqual(code, 0)
        manifests = list_status_manifests(self.root / "disputed")
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["commit_sha"], PIPELINE_COMMIT)
        self.assertEqual(manifests[0]["retrieval_method"], "local_import")
        self.assertEqual(manifests[0]["record_count"], 2)

    def test_default_root_is_outside_the_phase_21_snapshot(self):
        self.assertTrue(str(DEFAULT_DISPUTED_ROOT).endswith("raw/disputed"))


if __name__ == "__main__":
    unittest.main()
