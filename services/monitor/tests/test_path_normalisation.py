"""Defect 4 of the Windows integration test, at the source: one spelling per path.

The VM's Monitor stored `C:/URDS-main/watched_files\\tc01\\file.docx`: the
watch path was posted with forward slashes and watchdog joins with
backslashes. The ledger then matched only that spelling, so recovery verified
nothing for anyone who typed the path. The ledger side is
services/ledger/tests/test_path_spellings.py; this is the Monitor side.

What has to hold:

    1. `normalise_path` is normpath of the absolute path, case kept      (a)
    2. `handle_event` stores that form for `file_path` and `renamed_from`  (b)
    3. `/monitor/start` normalises the watch path, so every event
       watchdog reports carries the same form                           (c)
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402

windows_only = pytest.mark.skipif(os.name != "nt", reason="drive letters and backslashes are Windows spellings")


def _mixed(path: Path) -> str:
    """The VM's spelling: forward slashes up to the watched folder, backslashes after."""
    return str(path.parent).replace("\\", "/") + "\\" + path.name


# --------------------------------------------------------------- (a) the function


@windows_only
def test_a_the_vms_recorded_spelling_becomes_the_typed_one():
    assert monitor_app.normalise_path("C:/URDS-main/watched_files\\tc01\\file.docx") == (
        "C:\\URDS-main\\watched_files\\tc01\\file.docx"
    )


@windows_only
def test_a_case_is_kept_as_given_on_windows():
    """Folding is the reader's job (the ledger compares case-insensitively)."""
    assert monitor_app.normalise_path("C:/Users/Demo/Q3 Forecast.XLSX") == "C:\\Users\\Demo\\Q3 Forecast.XLSX"


def test_a_dot_segments_and_doubled_separators_go(tmp_path):
    messy = f"{tmp_path}{os.sep}{os.sep}sub{os.sep}.{os.sep}..{os.sep}report.docx"
    assert monitor_app.normalise_path(messy) == str(tmp_path / "report.docx")


def test_a_a_relative_path_is_made_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert monitor_app.normalise_path("report.docx") == str(tmp_path / "report.docx")


# -------------------------------------------------------------- (b) handle_event


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", False)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def test_b_the_event_carries_the_normalised_path(quiet, tmp_path):
    target = tmp_path / "board_minutes.docx"
    target.write_bytes(os.urandom(4096))
    messy = f"{tmp_path}{os.sep}.{os.sep}board_minutes.docx"

    event = monitor_app.handle_event(messy, "modified")

    assert event["file_path"] == str(target)


@windows_only
def test_b_the_vms_mixed_spelling_is_stored_as_the_typed_one(quiet, tmp_path):
    target = tmp_path / "tc01" / "file.docx"
    target.parent.mkdir()
    target.write_bytes(os.urandom(4096))

    event = monitor_app.handle_event(_mixed(target), "modified")

    assert event["file_path"] == str(target)
    assert "/" not in event["file_path"]


def test_b_a_renames_old_name_is_normalised_too(quiet, tmp_path):
    old = tmp_path / "q3.xlsx"
    new = tmp_path / "q3.xlsx.locked"
    new.write_bytes(os.urandom(4096))

    event = monitor_app.handle_event(
        f"{tmp_path}{os.sep}.{os.sep}q3.xlsx.locked",
        "renamed",
        renamed_from=f"{tmp_path}{os.sep}sub{os.sep}..{os.sep}q3.xlsx",
    )

    assert event["file_path"] == str(new)
    assert event["renamed_from"] == str(old)


def test_b_a_deletion_is_normalised_too(quiet, tmp_path):
    event = monitor_app.handle_event(f"{tmp_path}{os.sep}.{os.sep}gone.docx", "deleted")

    assert event["file_path"] == str(tmp_path / "gone.docx")


# ------------------------------------------------------ (c) the watch path, live


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", False)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    with TestClient(monitor_app.app) as test_client:
        yield test_client
        test_client.post("/monitor/stop", json={})
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _wait_for_event(name: str, timeout: float = 5.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for event in list(monitor_app.EVENTS):
            if event["file_path"].endswith(name) and event["file_size"] > 0:
                return event
        time.sleep(0.02)
    return None


def _messy_watch_path(tmp_path: Path) -> str:
    """Forward slashes on Windows, as the VM's operator posted it; elsewhere a
    doubled separator and a trailing one, which normpath also removes."""
    if os.name == "nt":
        return str(tmp_path).replace("\\", "/") + "/"
    return f"{tmp_path.parent}//{tmp_path.name}/"


def test_c_start_normalises_the_watch_path_and_every_event_follows(client, tmp_path):
    response = client.post("/monitor/start", json={"watch_path": _messy_watch_path(tmp_path)})
    assert response.status_code == 200, response.text
    assert response.json()["watch_path"] == str(tmp_path)
    assert client.get("/monitor/status").json()["watch_path"] == str(tmp_path)

    (tmp_path / "tc01").mkdir()
    target = tmp_path / "tc01" / "file.docx"
    target.write_bytes(os.urandom(8192))

    event = _wait_for_event("file.docx")
    assert event is not None, "watchdog reported nothing"
    assert event["file_path"] == str(target)


@windows_only
def test_c_the_operators_case_is_kept_not_folded(client, tmp_path):
    """Posted in upper case, which NTFS resolves to the same folder."""
    posted = str(tmp_path).upper()
    response = client.post("/monitor/start", json={"watch_path": posted})
    assert response.status_code == 200, response.text
    assert response.json()["watch_path"] == posted

    (tmp_path / "notes.docx").write_bytes(os.urandom(8192))

    event = _wait_for_event("notes.docx")
    assert event is not None, "watchdog reported nothing"
    assert event["file_path"].startswith(posted + "\\")
