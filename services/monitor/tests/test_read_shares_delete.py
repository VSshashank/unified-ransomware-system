"""The Monitor's reads must not stop anyone renaming or deleting the file.

Found re-testing fix/windows-integration-defects on the Windows VM, 2026-10-04.
A process that wrote a file in the watched tree and renamed it straight away -
the defect 2 re-check, and what every atomic save does - failed 6 of 6 times
with PermissionError [WinError 32] while the Monitor was watching, and
succeeded 6 of 6 times with the watch stopped. Python's `open` asks Windows for
FILE_SHARE_READ | FILE_SHARE_WRITE but not FILE_SHARE_DELETE, so for as long as
the Monitor held a just-written file open to sample and hash it, nobody else
could rename or delete it. Office's save-to-temp-then-rename, editors' atomic
saves and installers all do exactly that, within milliseconds of the write the
Monitor is reacting to.

`open_for_read` now opens with all three share modes on Windows. The rest of
its contract is unchanged and is asserted here too: a missing file raises
FileNotFoundError, a directory raises PermissionError without waiting out the
retry budget, and a file someone else holds exclusively still raises
PermissionError after it.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import detection  # noqa: E402
from detection import open_for_read  # noqa: E402

windows_only = pytest.mark.skipif(os.name != "nt", reason="share modes are a Windows concept")


@windows_only
def test_a_file_being_read_can_be_renamed(tmp_path):
    target = tmp_path / "report.docx"
    target.write_bytes(b"x" * 8192)

    with open_for_read(str(target)) as handle:
        os.replace(target, tmp_path / "report.docx.locked")
        # The read goes on against the same file, under its new name.
        assert handle.read() == b"x" * 8192

    assert (tmp_path / "report.docx.locked").read_bytes() == b"x" * 8192
    assert not target.exists()


@windows_only
def test_a_file_being_read_can_be_deleted(tmp_path):
    target = tmp_path / "scratch.tmp"
    target.write_bytes(b"y" * 4096)

    with open_for_read(str(target)) as handle:
        os.remove(target)
        assert handle.read(4) == b"yyyy"

    assert not target.exists()


@windows_only
def test_a_file_being_read_can_still_be_written(tmp_path):
    """FILE_SHARE_WRITE was already granted by `open`; it must stay granted."""
    target = tmp_path / "log.txt"
    target.write_bytes(b"first\n")

    with open_for_read(str(target)) as handle:
        with open(target, "ab") as writer:
            writer.write(b"second\n")
        assert handle.read() == b"first\nsecond\n"


def test_a_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_for_read(str(tmp_path / "nope.bin"))


def test_a_directory_is_refused_without_waiting_out_the_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(detection, "READ_RETRY_BUDGET_SECONDS", 2.0)
    started = time.monotonic()

    with pytest.raises(PermissionError):
        open_for_read(str(tmp_path))

    assert time.monotonic() - started < 1.0


@windows_only
def test_a_file_held_exclusively_is_still_retried_then_refused(tmp_path, monkeypatch):
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    target = tmp_path / "held.bin"
    target.write_bytes(b"z" * 1024)
    # Share mode 0: nobody else may open it at all, for any access.
    handle = kernel32.CreateFileW(str(target), 0x80000000, 0, None, 3, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value
    monkeypatch.setattr(detection, "READ_RETRY_BUDGET_SECONDS", 0.05)
    try:
        started = time.monotonic()
        with pytest.raises(PermissionError):
            open_for_read(str(target))
        # It waited for the lock to clear before giving up.
        assert time.monotonic() - started >= 0.04
    finally:
        kernel32.CloseHandle(handle)

    with open_for_read(str(target)) as readable:
        assert readable.read() == b"z" * 1024
