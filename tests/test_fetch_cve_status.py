"""Synthetic tests for the CVE status fetcher; every call is mocked (no network)."""

import base64
import contextlib
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

import pandas as pd

from src.cve_status_sources import CveStatusValidationError
from src.fetch_cve_status import (
    MissingStatusSnapshotError,
    fetch_status_snapshot,
    git_blob_sha,
    import_status_snapshot,
    list_status_manifests,
    load_status_snapshot,
    main,
    placeholder_cve_ids,
    select_status_manifest,
    write_status_snapshot,
)
from src.fetch_threat_intelligence import SourceUnavailableError

from tests.cve_status_fixtures import (
    published_record,
    record_bytes,
    rejected_record,
    synthetic_dataset,
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


class FakeOpener:
    """Route fake responses by URL fragment and record every request."""

    def __init__(self, routes, commit_sha="a" * 40):
        self.routes = routes
        self.requests = []
        self.commit_sha = commit_sha

    def __call__(self, request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        self.requests.append(url)
        if "/commits/" in url:
            return FakeResponse(json.dumps({"sha": self.commit_sha}).encode("utf-8"), url)
        for fragment, handler in self.routes.items():
            if fragment in url:
                if isinstance(handler, Exception):
                    raise handler
                return FakeResponse(handler, url)
        raise AssertionError(f"Unexpected URL requested: {url}")


def contents_payload(record, path=None):
    payload = record_bytes(record)
    return json.dumps(
        {
            "name": Path(path or "record.json").name,
            "path": path or "cves/2020/0xxx/CVE-2020-0003.json",
            "sha": git_blob_sha(payload),
            "size": len(payload),
            "encoding": "base64",
            "content": base64.b64encode(payload).decode("ascii"),
        }
    ).encode("utf-8")


class FetchRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_write_and_load_snapshot_roundtrip(self):
        records = {
            "CVE-2020-0003": record_bytes(rejected_record("CVE-2020-0003")),
            "CVE-2020-0004": record_bytes(published_record("CVE-2020-0004")),
        }
        manifest = write_status_snapshot(
            records,
            commit_sha="b" * 40,
            retrieval_method="https_download",
            root=self.root,
        )
        self.assertEqual(manifest["record_count"], 2)
        self.assertEqual(manifest["missing_count"], 0)
        manifest_path = Path(manifest["_manifest_path"])
        self.assertTrue(manifest_path.is_file())
        for entry in manifest["records"].values():
            self.assertTrue((manifest_path.parent / entry["file"]).is_file())
            self.assertIsNotNone(entry["sha256"])

        loaded = load_status_snapshot(manifest)
        self.assertEqual(sorted(loaded), ["CVE-2020-0003", "CVE-2020-0004"])
        self.assertEqual(loaded["CVE-2020-0003"][0].state, "REJECTED")
        self.assertEqual(loaded["CVE-2020-0004"][0].state, "PUBLISHED")

    def test_missing_records_are_recorded_as_absent(self):
        manifest = write_status_snapshot(
            {"CVE-2020-0003": record_bytes(rejected_record("CVE-2020-0003"))},
            commit_sha="c" * 40,
            retrieval_method="https_download",
            root=self.root,
            missing=["CVE-2020-0009"],
        )
        self.assertEqual(manifest["record_count"], 1)
        self.assertEqual(manifest["missing_count"], 1)
        self.assertFalse(manifest["records"]["CVE-2020-0009"]["present"])
        loaded = load_status_snapshot(manifest)
        self.assertNotIn("CVE-2020-0009", loaded)

    def test_malformed_record_is_never_written(self):
        from src.cve_status_sources import CveStatusSchemaError

        with self.assertRaises(CveStatusSchemaError):
            write_status_snapshot(
                {"CVE-2020-0003": b"{not json"},
                commit_sha="d" * 40,
                retrieval_method="https_download",
                root=self.root,
            )
        self.assertEqual(list_manifest_files(self.root), [])

    def test_tampered_snapshot_is_detected(self):
        manifest = write_status_snapshot(
            {"CVE-2020-0003": record_bytes(rejected_record("CVE-2020-0003"))},
            commit_sha="e" * 40,
            retrieval_method="https_download",
            root=self.root,
        )
        manifest_path = Path(manifest["_manifest_path"])
        data_path = manifest_path.parent / manifest["records"]["CVE-2020-0003"]["file"]
        data_path.write_bytes(record_bytes(published_record("CVE-2020-0003")))
        with self.assertRaisesRegex(CveStatusValidationError, "checksum mismatch"):
            load_status_snapshot(manifest)

    def test_select_manifest_prefers_the_newest_and_honours_explicit_paths(self):
        older = write_status_snapshot(
            {"CVE-2020-0003": record_bytes(rejected_record("CVE-2020-0003"))},
            commit_sha="1" * 40,
            retrieval_method="https_download",
            root=self.root,
            retrieved_utc=_stamp("2026-01-01T00:00:00Z"),
        )
        newer = write_status_snapshot(
            {"CVE-2020-0003": record_bytes(rejected_record("CVE-2020-0003"))},
            commit_sha="2" * 40,
            retrieval_method="https_download",
            root=self.root,
            retrieved_utc=_stamp("2026-02-02T00:00:00Z"),
        )
        selected = select_status_manifest(root=self.root)
        self.assertEqual(selected["commit_sha"], newer["commit_sha"])
        explicit = select_status_manifest(root=self.root, explicit=Path(older["_manifest_path"]))
        self.assertEqual(explicit["commit_sha"], older["commit_sha"])
        with self.assertRaises(MissingStatusSnapshotError):
            select_status_manifest(root=self.root, explicit=self.root / "absent.manifest.json")


class FetchNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_fetch_pins_the_commit_and_verifies_blob_sha(self):
        opener = FakeOpener(
            {
                "CVE-2020-0003": contents_payload(rejected_record("CVE-2020-0003")),
                "CVE-2020-0004": contents_payload(published_record("CVE-2020-0004")),
            },
            commit_sha="f" * 40,
        )
        manifest = fetch_status_snapshot(
            ["CVE-2020-0003", "CVE-2020-0004"],
            ref="main",
            root=self.root,
            opener=opener,
            sleep=lambda _: None,
        )
        self.assertEqual(manifest["commit_sha"], "f" * 40)
        self.assertEqual(manifest["requested_ref"], "main")
        self.assertEqual(manifest["record_count"], 2)
        for url in opener.requests:
            if "/contents/" in url:
                self.assertIn("ref=" + "f" * 40, url)
        for entry in manifest["records"].values():
            self.assertEqual(len(entry["git_blob_sha"]), 40)

        before = len([url for url in opener.requests if "/contents/" in url])
        reused = fetch_status_snapshot(
            ["CVE-2020-0003", "CVE-2020-0004"],
            ref="main",
            root=self.root,
            opener=opener,
            sleep=lambda _: None,
        )
        self.assertTrue(reused.get("_reused_cached_snapshot"))
        after = len([url for url in opener.requests if "/contents/" in url])
        self.assertEqual(after, before, "cached snapshot must not re-download any record")

    def test_a_wrong_blob_sha_is_rejected(self):
        tampered = json.loads(contents_payload(rejected_record("CVE-2020-0003")))
        tampered["sha"] = "0" * 40
        opener = FakeOpener({"CVE-2020-0003": json.dumps(tampered).encode("utf-8")})
        with self.assertRaisesRegex(CveStatusValidationError, "blob SHA"):
            fetch_status_snapshot(
                ["CVE-2020-0003"], root=self.root, opener=opener, sleep=lambda _: None
            )

    def test_missing_record_is_recorded_not_guessed(self):
        opener = FakeOpener(
            {
                "CVE-2020-0004": contents_payload(published_record("CVE-2020-0004")),
                "CVE-2020-0009": urllib.error.HTTPError(
                    "https://api.github.com/x", 404, "Not Found", None, None
                ),
            }
        )
        manifest = fetch_status_snapshot(
            ["CVE-2020-0004", "CVE-2020-0009"],
            root=self.root,
            opener=opener,
            sleep=lambda _: None,
        )
        self.assertEqual(manifest["missing_count"], 1)
        self.assertFalse(manifest["records"]["CVE-2020-0009"]["present"])
        self.assertEqual(manifest["records"]["CVE-2020-0009"]["reason"], "http_404_not_found")

    def test_network_failure_writes_nothing(self):
        opener = FakeOpener(
            {"CVE-2020-0004": urllib.error.URLError("no route to host")}
        )
        with self.assertRaises(SourceUnavailableError):
            fetch_status_snapshot(
                ["CVE-2020-0004"], root=self.root, opener=opener, sleep=lambda _: None
            )
        self.assertEqual(list_manifest_files(self.root), [])

    def test_local_import_records_its_declared_origin(self):
        source_dir = self.root / "records"
        source_dir.mkdir()
        for record in (
            rejected_record("CVE-2020-0003"),
            published_record("CVE-2020-0004"),
        ):
            (source_dir / f"{record['cveMetadata']['cveId']}.json").write_bytes(
                record_bytes(record)
            )
        manifest = import_status_snapshot(
            sorted(source_dir.glob("CVE-*.json")),
            commit_sha="9" * 40,
            origin_url="https://github.com/CVEProject/cvelistV5/blob/" + "9" * 40,
            ref="9" * 40,
            root=self.root,
        )
        self.assertEqual(manifest["retrieval_method"], "local_import")
        self.assertEqual(manifest["record_count"], 2)
        loaded = load_status_snapshot(manifest)
        self.assertEqual(loaded["CVE-2020-0004"][0].state, "PUBLISHED")


class PlaceholderDiscoveryTests(unittest.TestCase):
    def test_placeholder_ids_come_from_the_dataset(self):
        frame = synthetic_dataset()
        identifiers = placeholder_cve_ids(frame)
        self.assertEqual(
            identifiers,
            ["CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005", "CVE-2020-0009"],
        )

    def test_dataset_without_markers_yields_nothing(self):
        frame = pd.DataFrame(
            {"cve_id": ["CVE-2020-0001"], "summary": ["Ordinary description."]}
        )
        self.assertEqual(placeholder_cve_ids(frame), [])

    def test_cli_import_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            (records / "CVE-2020-0003.json").write_bytes(
                record_bytes(rejected_record("CVE-2020-0003"))
            )
            snapshot_root = root / "snapshots"
            exit_code = _silent_main(
                [
                    "--from-directory",
                    str(records),
                    "--origin-url",
                    "https://github.com/CVEProject/cvelistV5/blob/" + "7" * 40,
                    "--commit-sha",
                    "7" * 40,
                    "--snapshot-root",
                    str(snapshot_root),
                ]
            )
            self.assertEqual(exit_code, 0)
            manifests = list_status_manifests(snapshot_root)
            self.assertEqual(len(manifests), 1)
            self.assertEqual(manifests[0]["record_count"], 1)

    def test_cli_requires_an_identifier_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(SystemExit):
                _silent_main(
                    [
                        "--input",
                        str(root / "missing.csv"),
                        "--snapshot-root",
                        str(root),
                    ]
                )


def _silent_main(argv):
    """Run the CLI without polluting the test output."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


def list_manifest_files(root):
    directory = Path(root) / "cve_status"
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.manifest.json"))


def _stamp(value):
    from datetime import datetime

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    unittest.main()
