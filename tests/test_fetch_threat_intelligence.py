"""Mocked-network tests for HTTPS download, retries, caching, and snapshots.

No test contacts a live server: an injected opener returns in-memory responses.
"""

import io
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.fetch_threat_intelligence import (
    EPSS_SOURCE,
    KEV_SOURCE,
    OFFICIAL_URLS,
    SourceUnavailableError,
    SourceValidationError,
    download_bytes,
    fetch_source,
    find_reusable_snapshot,
    import_local_snapshot,
    list_manifests,
    sha256_bytes,
    verify_snapshot,
)
from tests.threat_intel_fixtures import EPSS_REAL_EXCERPT, kev_document


class FakeResponse:
    def __init__(self, body, url, status=200):
        self._buffer = io.BytesIO(body)
        self._url = url
        self.status = status

    def read(self, size=-1):
        return self._buffer.read(size)

    def geturl(self):
        return self._url

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def scripted_opener(*outcomes):
    """Return outcomes in order; exceptions are raised, bytes become responses."""
    calls = []

    def opener(request, timeout=None):
        calls.append((request.full_url, timeout))
        outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, tuple):
            body, final_url = outcome
            return FakeResponse(body, final_url)
        return FakeResponse(outcome, request.full_url)

    opener.calls = calls
    return opener


def no_sleep(_seconds):
    return None


NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


class DownloadTests(unittest.TestCase):
    def test_retries_transient_failures_then_succeeds(self):
        opener = scripted_opener(
            urllib.error.HTTPError(OFFICIAL_URLS[KEV_SOURCE], 503, "Unavailable", {}, None),
            urllib.error.URLError("temporary failure"),
            b"payload",
        )
        sleeps = []
        result = download_bytes(
            OFFICIAL_URLS[KEV_SOURCE],
            max_bytes=1024,
            opener=opener,
            sleep=sleeps.append,
            backoff_seconds=1.0,
        )
        self.assertEqual(result.content, b"payload")
        self.assertEqual(result.attempts, 3)
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_gives_clear_error_after_exhausting_retries(self):
        opener = scripted_opener(urllib.error.URLError("no route to host"))
        with self.assertRaisesRegex(SourceUnavailableError, "after 4 attempt"):
            download_bytes(
                OFFICIAL_URLS[EPSS_SOURCE],
                max_bytes=1024,
                opener=opener,
                sleep=no_sleep,
            )
        self.assertEqual(len(opener.calls), 4)

    def test_client_errors_are_not_retried(self):
        opener = scripted_opener(urllib.error.HTTPError(OFFICIAL_URLS[KEV_SOURCE], 404, "Not Found", {}, None))
        with self.assertRaisesRegex(SourceUnavailableError, "HTTP 404"):
            download_bytes(OFFICIAL_URLS[KEV_SOURCE], max_bytes=1024, opener=opener, sleep=no_sleep)
        self.assertEqual(len(opener.calls), 1)

    def test_refuses_non_https_urls_before_any_request(self):
        opener = scripted_opener(b"never")
        with self.assertRaisesRegex(ValueError, "non-HTTPS"):
            download_bytes("http://epss.example.org/epss.csv.gz", max_bytes=10, opener=opener, sleep=no_sleep)
        self.assertEqual(opener.calls, [])

    def test_refuses_redirect_that_leaves_https(self):
        opener = scripted_opener((b"data", "http://insecure.example.org/file"))
        with self.assertRaisesRegex(SourceUnavailableError, "non-HTTPS"):
            download_bytes(OFFICIAL_URLS[EPSS_SOURCE], max_bytes=1024, opener=opener, sleep=no_sleep)

    def test_enforces_maximum_payload_size(self):
        opener = scripted_opener(b"x" * 2048)
        with self.assertRaisesRegex(SourceValidationError, "safety limit"):
            download_bytes(OFFICIAL_URLS[KEV_SOURCE], max_bytes=1024, opener=opener, sleep=no_sleep)

    def test_empty_body_is_an_error(self):
        opener = scripted_opener(b"")
        with self.assertRaisesRegex(SourceUnavailableError, "Empty response"):
            download_bytes(OFFICIAL_URLS[KEV_SOURCE], max_bytes=1024, opener=opener, sleep=no_sleep)


class SnapshotFetchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "raw"

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_kev_download_writes_checksummed_snapshot_and_manifest(self):
        payload = kev_document()
        opener = scripted_opener(payload)
        manifest = fetch_source(KEV_SOURCE, root=self.root, opener=opener, sleep=no_sleep, now=NOW)

        self.assertEqual(manifest["sha256"], sha256_bytes(payload))
        self.assertEqual(manifest["requested_url"], OFFICIAL_URLS[KEV_SOURCE])
        self.assertEqual(manifest["final_url"], OFFICIAL_URLS[KEV_SOURCE])
        self.assertEqual(manifest["retrieval_method"], "https_download")
        self.assertEqual(manifest["retrieved_utc"], "2026-10-12T12:00:00Z")
        self.assertEqual(manifest["snapshot_date"], "2026-10-08")
        self.assertEqual(manifest["metadata"]["catalog_version"], "2026.10.08")
        self.assertTrue(Path(manifest["_manifest_path"]).is_file())
        self.assertEqual(verify_snapshot(manifest).read_bytes(), payload)
        self.assertNotIn("data/raw", str(self.root))

    def test_epss_download_records_model_version_and_score_date(self):
        opener = scripted_opener(EPSS_REAL_EXCERPT)
        manifest = fetch_source(EPSS_SOURCE, root=self.root, opener=opener, sleep=no_sleep, now=NOW)
        self.assertEqual(manifest["metadata"]["model_version"], "v2026.06.15")
        self.assertEqual(manifest["snapshot_date"], "2026-10-11")
        self.assertEqual(manifest["file"].rsplit(".", 1)[-1], "csv")

    def test_invalid_payload_is_never_written(self):
        opener = scripted_opener(b"<html>error page</html>")
        with self.assertRaisesRegex(Exception, "validation failed"):
            fetch_source(KEV_SOURCE, root=self.root, opener=opener, sleep=no_sleep, now=NOW)
        self.assertEqual(list_manifests(KEV_SOURCE, self.root), [])
        self.assertFalse((self.root / KEV_SOURCE).exists() and any((self.root / KEV_SOURCE).iterdir()))

    def test_fresh_cache_is_reused_without_network_and_refresh_forces_download(self):
        opener = scripted_opener(kev_document())
        first = fetch_source(KEV_SOURCE, root=self.root, opener=opener, sleep=no_sleep, now=NOW)

        blocked = scripted_opener(urllib.error.URLError("must not be called"))
        cached = fetch_source(
            KEV_SOURCE, root=self.root, opener=blocked, sleep=no_sleep, now=NOW + timedelta(hours=2)
        )
        self.assertTrue(cached["_reused_cached_snapshot"])
        self.assertEqual(cached["sha256"], first["sha256"])
        self.assertEqual(blocked.calls, [])

        with self.assertRaises(SourceUnavailableError):
            fetch_source(
                KEV_SOURCE, root=self.root, opener=blocked, sleep=no_sleep, now=NOW + timedelta(hours=2), refresh=True
            )
        self.assertEqual(len(blocked.calls), 4)

    def test_stale_cache_is_not_reused(self):
        opener = scripted_opener(kev_document())
        fetch_source(KEV_SOURCE, root=self.root, opener=opener, sleep=no_sleep, now=NOW)
        later = NOW + timedelta(hours=25)
        self.assertIsNone(find_reusable_snapshot(KEV_SOURCE, OFFICIAL_URLS[KEV_SOURCE], self.root, 24, now=later))

    def test_cache_from_another_url_is_not_reused(self):
        opener = scripted_opener(kev_document())
        fetch_source(KEV_SOURCE, root=self.root, opener=opener, sleep=no_sleep, now=NOW)
        self.assertIsNone(
            find_reusable_snapshot(KEV_SOURCE, "https://mirror.example.org/kev.json", self.root, 24, now=NOW)
        )

    def test_tampered_snapshot_fails_checksum_verification(self):
        manifest = fetch_source(
            KEV_SOURCE, root=self.root, opener=scripted_opener(kev_document()), sleep=no_sleep, now=NOW
        )
        Path(manifest["_manifest_path"]).parent.joinpath(manifest["file"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(SourceValidationError, "checksum mismatch"):
            verify_snapshot(manifest)

    def test_local_import_records_declared_origin(self):
        source_file = Path(self._tmp.name) / "known_exploited_vulnerabilities.json"
        source_file.write_bytes(kev_document())
        origin = "https://github.com/cisagov/kev-data/blob/abc/known_exploited_vulnerabilities.json"
        manifest = import_local_snapshot(KEV_SOURCE, source_file, origin_url=origin, root=self.root, now=NOW)
        self.assertEqual(manifest["retrieval_method"], "local_import")
        self.assertEqual(manifest["declared_origin"], origin)
        self.assertEqual(manifest["snapshot_date"], "2026-10-08")

    def test_repeated_identical_download_does_not_duplicate_files(self):
        payload = kev_document()
        fetch_source(KEV_SOURCE, root=self.root, opener=scripted_opener(payload), sleep=no_sleep, now=NOW)
        fetch_source(
            KEV_SOURCE, root=self.root, opener=scripted_opener(payload), sleep=no_sleep, now=NOW, refresh=True
        )
        data_files = [
            p for p in (self.root / KEV_SOURCE).iterdir() if not p.name.endswith(".manifest.json")
        ]
        manifests = list_manifests(KEV_SOURCE, self.root)
        self.assertEqual(len(data_files), 1)
        self.assertEqual(len(manifests), 1)


if __name__ == "__main__":
    unittest.main()
