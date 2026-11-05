"""The recorded size describes the content recorded beside it (F5).

The full VM test of 2026-10-04 (F5 in reports/VM_TEST_REPORT_2026-10-04.md;
FIXES.md defect 12 had left it as "not changed") saw `file_baseline` blocks with
`file_size: 0` beside the full 16,368-byte file's hash, and events with
`size=0` and entropy 5.86. The size was read before the bytes landed, the hash
and the sample after. Where a hash is recorded, the size must be the length of
the bytes hashed; where only a sample is read, the size is taken after the read
and a change is said, not hidden.

The race is staged with the hooks test_unreadable_is_a_lock_not_a_race.py uses:
the write lands inside one of the Monitor's own looks at the file.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import detection  # noqa: E402
import pipeline  # noqa: E402


@pytest.fixture(autouse=True)
def quiet_state():
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def lands_inside_read_magic(monkeypatch, then):
    """read_magic sees the file as it was at the size, then the write lands."""
    real = monitor_app.read_magic

    def racing(path, *args, **kwargs):
        magic = real(path, *args, **kwargs)
        then(path)
        return magic

    monkeypatch.setattr(monitor_app, "read_magic", racing)
    monkeypatch.setattr(detection, "read_magic", racing)


def lands_after_the_sample(monkeypatch, then):
    """The sample is taken, then the write lands, before the hash."""
    real = monitor_app.sample_file

    def racing(path, *args, **kwargs):
        sampled = real(path, *args, **kwargs)
        then(path)
        return sampled

    monkeypatch.setattr(monitor_app, "sample_file", racing)


def test_a_file_that_grows_after_its_size_is_taken_records_the_hashed_length(tmp_path, monkeypatch):
    """The VM's case: size 0, then the whole file, then the hash."""
    target = tmp_path / "quarterly.docx"
    target.write_bytes(b"")
    payload = os.urandom(16368)
    lands_inside_read_magic(monkeypatch, lambda p: Path(p).write_bytes(payload))

    event = monitor_app.handle_event(str(target), "created")

    assert event["file_hash"] == hashlib.sha256(payload).hexdigest()
    assert event["file_size"] == len(payload), "the size must be the length of the bytes hashed"
    assert event["size_changed_during_read"] is True


def test_a_file_that_grows_between_the_sample_and_the_hash_records_the_hashed_length(tmp_path, monkeypatch):
    target = tmp_path / "ledger_export.xlsx"
    first = os.urandom(8192)
    more = os.urandom(4096)
    target.write_bytes(first)

    def append(path):
        with open(path, "ab") as handle:
            handle.write(more)

    lands_after_the_sample(monkeypatch, append)

    event = monitor_app.handle_event(str(target), "modified")

    assert event["file_hash"] == hashlib.sha256(first + more).hexdigest()
    assert event["file_size"] == len(first) + len(more)
    assert event["size_changed_during_read"] is True


def test_a_file_that_does_not_change_records_its_size_and_no_change(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_bytes(b"minutes of the meeting\n" * 400)

    event = monitor_app.handle_event(str(target), "modified")

    assert event["file_size"] == target.stat().st_size
    assert event.get("size_changed_during_read") in (False, None)


def test_features_without_a_hash_take_the_size_after_the_read_and_say_it_moved(tmp_path, monkeypatch):
    """/features reads a sample only, so it says the size moved instead."""
    target = tmp_path / "payload.bin"
    target.write_bytes(b"")
    payload = os.urandom(32768)
    lands_inside_read_magic(monkeypatch, lambda p: Path(p).write_bytes(payload))

    features = monitor_app.extract_features(str(target))

    assert features["file_size"] == len(payload)
    assert features["size_changed_during_read"] is True


def test_the_baseline_block_records_the_length_of_the_bytes_it_hashed(tmp_path, monkeypatch):
    """The ledger half: the two file_baseline blocks the VM wrote with size 0."""
    writes: list[dict] = []

    def capture(client, base_url, path, payload, *args, **kwargs):
        if path == "/ledger/log":
            writes.append(payload)
            return {"block_id": len(writes)}
        return {}

    monkeypatch.setattr(pipeline, "_post", capture)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", True)
    monitor_app._ensure_worker()

    target = tmp_path / "handbook.txt"
    target.write_bytes(b"")
    body = b"Chapter 1. Policies and procedures.\n" * 455  # 16,380 bytes of plain text
    lands_inside_read_magic(monkeypatch, lambda p: Path(p).write_bytes(body))

    event = monitor_app.handle_event(str(target), "created")
    assert event["suspicious"] is False
    monitor_app._work.join()

    (baseline,) = [w["event_data"] for w in writes if w["event_type"] == "file_baseline"]
    assert baseline["file_hash"] == hashlib.sha256(body).hexdigest()
    assert baseline["file_size"] == len(body)
    assert baseline["size_changed_during_read"] is True
