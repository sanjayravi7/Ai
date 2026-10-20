"""The prospective store: create-once, content-addressed, path-safe.

These tests exercise the storage primitive directly.  Capture and verification
tests use the same primitive through their own entry points; here the point is
the guarantee itself — nothing is overwritten, identical bytes collapse, and a
symlink or ``..`` cannot redirect a write or a read.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from vulnova.acquisition.store import StoreError
from vulnova.prospective import constants as C
from vulnova.prospective.store import (
    CREATED,
    IDENTICAL,
    ProspectiveStore,
    StoreConflict,
    atomic_create,
    atomic_replace,
)


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# --------------------------------------------------------------- create-once
def test_identical_bytes_are_filed_once(tmp_path):
    store = ProspectiveStore(tmp_path)
    first = store.store_artifact(C.KEV, b"catalog")
    second = store.store_artifact(C.KEV, b"catalog")

    assert first == second
    assert first.relative_path == f"artifacts/kev/{_sha(b'catalog')}.json"
    assert len(list((tmp_path / "artifacts" / "kev").iterdir())) == 1


def test_different_bytes_on_one_key_are_stored_beside_each_other(tmp_path):
    store = ProspectiveStore(tmp_path)
    first = store.store_artifact(C.EPSS, b"day-one")
    second = store.store_artifact(C.EPSS, b"day-two")

    assert first.relative_path != second.relative_path
    assert store.read_artifact(first.relative_path) == b"day-one"
    assert store.read_artifact(second.relative_path) == b"day-two"


def test_identical_run_bytes_are_reported_identical(tmp_path):
    store = ProspectiveStore(tmp_path)
    assert store.store_run("20261020T140000Z-aaaaaaaaaaaa", b"{}\n") == CREATED
    assert store.store_run("20261020T140000Z-aaaaaaaaaaaa", b"{}\n") == IDENTICAL


def test_a_run_id_collision_with_different_bytes_never_overwrites(tmp_path):
    store = ProspectiveStore(tmp_path)
    run_id = "20261020T140000Z-aaaaaaaaaaaa"
    store.store_run(run_id, b'{"a": 1}\n')

    with pytest.raises(StoreConflict) as excinfo:
        store.store_run(run_id, b'{"a": 2}\n')
    assert "never overwritten" in str(excinfo.value)
    assert store.read_run(run_id) == b'{"a": 1}\n'


def test_a_tampered_artifact_is_not_silently_replaced(tmp_path):
    store = ProspectiveStore(tmp_path)
    stored = store.store_artifact(C.KEV, b"original")
    target = tmp_path / stored.relative_path
    target.write_bytes(b"tampered")

    with pytest.raises(StoreConflict):
        store.store_artifact(C.KEV, b"original")
    assert target.read_bytes() == b"tampered"


def test_atomic_create_reports_identical_but_leaves_one_file(tmp_path):
    path = tmp_path / "file.bin"
    assert atomic_create(path, b"x") == CREATED
    assert atomic_create(path, b"x") == IDENTICAL
    assert [item.name for item in tmp_path.iterdir()] == ["file.bin"]


def test_atomic_create_cleans_up_its_temporary_file_on_conflict(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"existing")
    with pytest.raises(StoreConflict):
        atomic_create(path, b"different")
    assert path.read_bytes() == b"existing"
    assert not list(tmp_path.glob(".tmp-*"))


def test_the_fallback_writer_is_used_when_hard_links_are_unavailable(tmp_path, monkeypatch):
    def no_links(*args, **kwargs):  # noqa: ARG001
        raise OSError("links unsupported")

    monkeypatch.setattr(os, "link", no_links)
    path = tmp_path / "file.bin"
    assert atomic_create(path, b"data") == CREATED
    assert path.read_bytes() == b"data"
    assert not list(tmp_path.glob(".tmp-*"))


def test_concurrent_creates_produce_exactly_one_file(tmp_path):
    path = tmp_path / "race.bin"
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: atomic_create(path, b"same"), range(8)))
    assert outcomes.count(CREATED) == 1
    assert outcomes.count(IDENTICAL) == 7
    assert path.read_bytes() == b"same"


# ------------------------------------------------------------- path safety
def test_traversal_is_refused_on_write(tmp_path):
    store = ProspectiveStore(tmp_path / "store")
    with pytest.raises(StoreError):
        store.store_run("../escape", b"{}")


def test_traversal_is_refused_on_read(tmp_path):
    store = ProspectiveStore(tmp_path / "store")
    with pytest.raises(StoreError):
        store.read_artifact("../../etc/passwd")


def test_an_absolute_path_is_refused(tmp_path):
    store = ProspectiveStore(tmp_path / "store")
    with pytest.raises(StoreError):
        store.artifact_path("/etc/passwd")


def test_a_symlink_inside_the_store_is_not_followed(tmp_path):
    store = ProspectiveStore(tmp_path / "store")
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"secret")
    link = tmp_path / "store" / "artifacts" / "kev" / f"{_sha(b'secret')}.json"
    link.parent.mkdir(parents=True)
    os.symlink(outside, link)

    with pytest.raises(StoreError):
        store.read_artifact(link.relative_to(tmp_path / "store").as_posix())
    # The write is refused at resolution time (the link points outside the
    # store, which is a stronger refusal than a byte conflict).
    with pytest.raises(StoreError):
        store.store_artifact(C.KEV, b"secret")
    assert outside.read_bytes() == b"secret"


def test_a_directory_cannot_masquerade_as_an_artifact(tmp_path):
    store = ProspectiveStore(tmp_path / "store")
    target = tmp_path / "store" / "artifacts" / "kev" / f"{_sha(b'dir')}.json"
    target.mkdir(parents=True)
    with pytest.raises(StoreConflict):
        store.store_artifact(C.KEV, b"dir")


def test_an_unknown_capture_kind_is_refused(tmp_path):
    store = ProspectiveStore(tmp_path)
    with pytest.raises(StoreError):
        store.store_artifact("epss-mirror", b"x")


def test_a_directory_escape_through_an_intermediate_symlink_is_refused(tmp_path):
    store_root = tmp_path / "store"
    (store_root / "artifacts").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, store_root / "artifacts" / "kev")

    store = ProspectiveStore(store_root)
    with pytest.raises(StoreError):
        store.store_artifact(C.KEV, b"payload")
    assert not list(outside.iterdir())


# ------------------------------------------------------------------ reading
def test_run_ids_are_sorted_and_ignore_other_files(tmp_path):
    store = ProspectiveStore(tmp_path)
    store.store_run("20261020T140000Z-bbbbbbbbbbbb", b"{}")
    store.store_run("20261019T140000Z-aaaaaaaaaaaa", b"{}")
    (tmp_path / "runs" / "notes.txt").write_text("ignore me")
    (tmp_path / "runs" / "subdir").mkdir()

    assert store.run_ids() == [
        "20261019T140000Z-aaaaaaaaaaaa",
        "20261020T140000Z-bbbbbbbbbbbb",
    ]


def test_a_missing_run_raises_instead_of_returning_empty(tmp_path):
    store = ProspectiveStore(tmp_path)
    with pytest.raises(OSError):
        store.read_run("20261020T140000Z-aaaaaaaaaaaa")


def test_artifact_digest_of_a_missing_file_is_none(tmp_path):
    store = ProspectiveStore(tmp_path)
    assert store.artifact_digest(f"artifacts/kev/{'0' * 64}.json") is None


def test_artifact_digest_reports_size_and_hash(tmp_path):
    store = ProspectiveStore(tmp_path)
    stored = store.store_artifact(C.KEV, b"bytes")
    digest = store.artifact_digest(stored.relative_path)
    assert digest == {"bytes": 5, "sha256": _sha(b"bytes")}


def test_the_store_survives_reopening(tmp_path):
    first = ProspectiveStore(tmp_path)
    stored = first.store_artifact(C.KEV, b"durable")
    first.store_run("20261020T140000Z-aaaaaaaaaaaa", b'{"run": 1}\n')

    second = ProspectiveStore(tmp_path)
    assert second.read_artifact(stored.relative_path) == b"durable"
    assert second.read_run("20261020T140000Z-aaaaaaaaaaaa") == b'{"run": 1}\n'
    assert second.run_ids() == ["20261020T140000Z-aaaaaaaaaaaa"]


# ------------------------------------------------------------- replacements
def test_atomic_replace_is_available_only_for_regenerable_outputs(tmp_path):
    path = tmp_path / "report.md"
    atomic_replace(path, b"one")
    atomic_replace(path, b"two")
    assert path.read_bytes() == b"two"


def test_atomic_replace_leaves_no_temporary_file(tmp_path):
    path = tmp_path / "report.md"
    atomic_replace(path, b"body")
    assert not list(tmp_path.glob(".tmp-*"))
