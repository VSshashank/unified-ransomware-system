""""Unreadable" must mean the bytes could not be had - not that a write landed mid-look.

Found re-testing fix/windows-integration-defects on the Windows VM, 2026-10-04.
`test_tc01_file_creation_on_the_watched_path_is_detected` failed in the final
full pass with the event that saw the whole 32,768-byte file carrying entropy
`None`: the verdict "unreadable". Nothing was locked. `handle_event` (and
`extract_features`) looked at the file three times - the leading bytes, then
the size, then the sample - and the write landed between the first two: the
leading bytes were read from the still-empty file, the size after the write, so
`looks_unreadable(b"", 32768)` said "bytes exist and we got none". The same race
the other way round is why the diagnostic that afternoon logged `created`
events with `file_size: 0` and entropy 7.99, and why two file_baseline blocks
in the elevated run record `file_size: 0` beside the full file's hash.

An event that says "unreadable" for a file being written is not a harmless
wrong label: an unreadable reading is never suspicious and nothing re-reads it,
so if no later notification comes, the content is never scored.

The size is now taken before the leading bytes, so a file that grows between
the looks is read as what it now holds. And an empty read of a file that had
bytes is checked against the size once more before it is called a lock: a file
truncated in between (an overwrite's first step) is empty, not locked.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import detection  # noqa: E402


@pytest.fixture(autouse=True)
def quiet_state():
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def write_lands_after_the_leading_bytes(monkeypatch, then):
    """read_magic sees the file as it is, then `then()` runs - the write landing."""
    real = monitor_app.read_magic

    def racing(path, *args, **kwargs):
        magic = real(path, *args, **kwargs)
        then(path)
        return magic

    monkeypatch.setattr(monitor_app, "read_magic", racing)
    monkeypatch.setattr(detection, "read_magic", racing)


def test_a_file_written_between_the_looks_is_scored_not_called_unreadable(tmp_path, monkeypatch):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"")
    payload = os.urandom(32768)
    write_lands_after_the_leading_bytes(monkeypatch, lambda p: Path(p).write_bytes(payload))

    event = monitor_app.handle_event(str(target), "created")

    assert event["verdict"] != "unreadable", event["reason"]
    assert event["entropy"] is not None and event["entropy"] > 7.0
    assert event["suspicious"] is True


def test_a_file_truncated_between_the_looks_is_empty_not_locked(tmp_path, monkeypatch):
    target = tmp_path / "report.docx"
    target.write_bytes(os.urandom(8192))
    real = monitor_app.read_magic

    def truncate_first(path, *args, **kwargs):
        Path(path).write_bytes(b"")  # an overwrite's first step lands before the read
        return real(path, *args, **kwargs)

    monkeypatch.setattr(monitor_app, "read_magic", truncate_first)

    event = monitor_app.handle_event(str(target), "modified")

    assert event["verdict"] != "unreadable", event["reason"]
    assert event["file_size"] == 0


def test_a_file_that_really_cannot_be_read_is_still_unreadable(tmp_path, monkeypatch):
    """The lock case must survive: bytes on disk, none obtainable."""
    target = tmp_path / "locked.docx"
    target.write_bytes(os.urandom(8192))

    def deny(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(detection, "open", deny, raising=False)
    monkeypatch.setattr(detection, "READ_RETRY_BUDGET_SECONDS", 0.0)

    event = monitor_app.handle_event(str(target), "modified")

    assert event["verdict"] == "unreadable"
    assert event["entropy"] is None
    assert event["suspicious"] is False
