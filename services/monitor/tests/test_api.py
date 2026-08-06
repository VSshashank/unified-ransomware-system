"""Monitor API contract and live file watching.

Covers TC-01 (a file event on the watched path is detected and captured) and the
request/response shapes the gateway and dashboard depend on.
"""

import os
import time

import pytest
from fastapi.testclient import TestClient

import app as monitor_app


@pytest.fixture
def client():
    with TestClient(monitor_app.app) as test_client:
        yield test_client
    test_client.post("/monitor/stop")


@pytest.fixture(autouse=True)
def clean_state():
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()


def wait_for_event(predicate, timeout=5.0, interval=0.02):
    """Watchdog is asynchronous; poll rather than sleep a fixed amount."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for event in list(monitor_app.EVENTS):
            if predicate(event):
                return event
        time.sleep(interval)
    return None


# -------------------------------------------------------------------- contract


def test_health_reports_service_and_threshold(client):
    body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert body["service"] == "monitor"
    assert "entropy_threshold" in body


def test_start_returns_contract_fields(client, tmp_path):
    body = client.post(
        "/monitor/start",
        json={"watch_path": str(tmp_path), "recursive": True, "file_patterns": ["*.docx"]},
    ).json()

    assert body["status"] == "monitoring"
    assert body["monitor_id"].startswith("mon_")
    assert body["watch_path"] == str(tmp_path)
    assert body["recursive"] is True
    assert body["file_patterns"] == ["*.docx"]


def test_start_rejects_a_path_that_is_not_a_directory(client, tmp_path):
    response = client.post("/monitor/start", json={"watch_path": str(tmp_path / "nope")})
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "INVALID_WATCH_PATH"
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}
    assert "details" in body


def test_status_returns_contract_fields(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})
    body = client.get("/monitor/status").json()

    assert body["status"] == "active"
    assert body["monitor_id"] is not None
    assert isinstance(body["files_monitored"], int)
    assert isinstance(body["events_captured"], int)
    assert isinstance(body["uptime_seconds"], int)


def test_stop_marks_the_monitor_inactive(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})
    stop = client.post("/monitor/stop").json()
    assert stop["status"] == "stopped"
    assert client.get("/monitor/status").json()["status"] == "stopped"


def test_validation_error_uses_the_shared_envelope(client):
    response = client.post("/monitor/start", json={})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BAD_REQUEST"


# --------------------------------------------------------------------- TC-01


def test_tc01_file_creation_on_the_watched_path_is_detected(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "recursive": True})

    target = tmp_path / "payload.bin"
    target.write_bytes(os.urandom(32768))

    event = wait_for_event(lambda e: e["file_path"].endswith("payload.bin"))
    assert event is not None, "watchdog did not report the created file"
    assert event["event_type"] in {"created", "modified"}
    assert event["entropy"] > 7.0
    assert event["suspicious"] is True


def test_tc01_recursive_watch_picks_up_subdirectories(client, tmp_path):
    nested = tmp_path / "documents" / "q4"
    nested.mkdir(parents=True)
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "recursive": True})

    (nested / "deep.bin").write_bytes(os.urandom(16384))

    assert wait_for_event(lambda e: e["file_path"].endswith("deep.bin")) is not None


def test_detected_event_carries_file_hash_for_the_ledger(client, tmp_path):
    """SI's recovery integrity check reads `file_hash` back out of the ledger."""
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})
    (tmp_path / "doc.bin").write_bytes(os.urandom(8192))

    event = wait_for_event(lambda e: e["file_path"].endswith("doc.bin"))
    assert event is not None
    assert event["file_hash"] is not None
    assert len(event["file_hash"]) == 64


def test_events_endpoint_returns_newest_first(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})
    for index in range(3):
        (tmp_path / f"f{index}.bin").write_bytes(os.urandom(2048))
        time.sleep(0.05)

    wait_for_event(lambda e: e["file_path"].endswith("f2.bin"))
    events = client.get("/monitor/events", params={"limit": 10}).json()["events"]

    assert events, "no events returned"
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


def test_event_buffer_is_bounded(client, tmp_path):
    """The old implementation appended without limit for the process lifetime."""
    assert monitor_app.EVENTS.maxlen == monitor_app.MAX_EVENTS
    for index in range(monitor_app.MAX_EVENTS + 50):
        monitor_app._record({"file_path": f"/tmp/f{index}", "timestamp": "t"})
    assert len(monitor_app.EVENTS) == monitor_app.MAX_EVENTS


def test_status_counts_distinct_files_not_events(client, tmp_path):
    monitor_app._record({"file_path": "/watch/a.txt", "timestamp": "t"})
    monitor_app._record({"file_path": "/watch/a.txt", "timestamp": "t"})
    monitor_app._record({"file_path": "/watch/b.txt", "timestamp": "t"})

    body = client.get("/monitor/status").json()
    assert body["files_monitored"] == 2
    assert body["events_captured"] == 3


# ------------------------------------------------------------------- /features


def test_features_are_measured_from_the_real_file(client, tmp_path):
    target = tmp_path / "sample.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(50000))

    body = client.post("/features", json={"path": str(target)}).json()

    assert body["magic_bytes"] == "89504E47"
    assert body["file_size"] == target.stat().st_size
    assert body["container_format"] == "png"
    assert body["suspicious"] is False
    assert 0.0 <= body["modification_rate"] <= 1.0


def test_features_are_deterministic_for_the_same_file(client, tmp_path):
    """The previous implementation returned a random pe_imports_count per call."""
    target = tmp_path / "sample.bin"
    target.write_bytes(os.urandom(20000))

    first = client.post("/features", json={"path": str(target)}).json()
    second = client.post("/features", json={"path": str(target)}).json()

    assert first == second


def test_features_on_missing_file_returns_404_envelope(client):
    response = client.post("/features", json={"path": "/nonexistent/file.bin"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "FILE_NOT_FOUND"
