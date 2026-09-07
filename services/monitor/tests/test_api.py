"""Monitor API contract and live file watching.

Covers TC-01 (a file event on the watched path is detected and captured) and the
request/response shapes the gateway and dashboard depend on.
"""

import io
import os
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

import app as monitor_app
import synthetic_corpus


@pytest.fixture
def client():
    with TestClient(monitor_app.app) as test_client:
        yield test_client
    test_client.post("/monitor/stop")


@pytest.fixture(autouse=True)
def clean_state():
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    # Module state, so a test that starts a filtered monitor would otherwise
    # silently filter every test that runs after it.
    monitor_app._file_patterns = []
    monitor_app.ENTROPY_HISTORY.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app._file_patterns = []
    monitor_app.ENTROPY_HISTORY.clear()


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


def test_stop_accepts_the_documented_monitor_id(client, tmp_path):
    """Listing 3.3 sends {monitor_id}; it used to be ignored entirely."""
    started = client.post("/monitor/start", json={"watch_path": str(tmp_path)}).json()

    stop = client.post("/monitor/stop", json={"monitor_id": started["monitor_id"]})

    assert stop.status_code == 200
    assert stop.json()["monitor_id"] == started["monitor_id"]
    assert client.get("/monitor/status").json()["status"] == "stopped"


def test_stop_refuses_a_monitor_id_that_is_not_running(client, tmp_path):
    """Accepting an id and ignoring it lets a caller believe it stopped one
    monitor while another kept running."""
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})

    stop = client.post("/monitor/stop", json={"monitor_id": "mon_nope"})

    assert stop.status_code == 404
    assert stop.json()["error"]["code"] == "UNKNOWN_MONITOR_ID"
    # Still running: a refused stop must not have stopped anything.
    assert client.get("/monitor/status").json()["status"] == "active"


def test_stop_without_a_body_still_stops_what_is_running(client, tmp_path):
    """The id stays optional - one monitor runs per process, and every existing
    caller posts an empty body."""
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})

    assert client.post("/monitor/stop").status_code == 200
    assert client.get("/monitor/status").json()["status"] == "stopped"


def test_validation_error_uses_the_shared_envelope(client):
    response = client.post("/monitor/start", json={})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BAD_REQUEST"


# --------------------------------------------------------------------- TC-01


def test_tc01_file_creation_on_the_watched_path_is_detected(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "recursive": True})

    target = tmp_path / "payload.bin"
    payload = os.urandom(32768)
    target.write_bytes(payload)

    # Wait for the event that saw the *whole* file, not merely the first event
    # for this path. `write_bytes` creates the file and then fills it, and
    # watchdog is free to deliver `created` while it is still empty - the
    # monitor then reads a 0-byte file and reports entropy 0.0, entirely
    # correctly. Selecting on `file_path` alone latches onto that reading and
    # the test fails intermittently on a race in the fixture rather than on
    # anything the detector did. Observed once in 9 runs on Linux.
    #
    # `file_size` is what distinguishes the two readings, so it is what the
    # predicate matches on. The assertions below still carry their weight: the
    # wait establishes *which* write the event observed, and entropy and
    # suspicious are then asserted rather than assumed.
    event = wait_for_event(
        lambda e: e["file_path"].endswith("payload.bin") and e["file_size"] == len(payload)
    )
    assert event is not None, "watchdog did not report the created file at its full size"
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


def test_differential_entropy_catches_in_place_encryption_end_to_end(client, tmp_path):
    """A document that was ordinary text and is now ciphertext, over the live
    watcher. The header is left as a valid ZIP throughout, so magic-byte
    verification clears the file at both readings and only the rise sees it."""
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})

    # The baseline reading has to be taken by the watcher, so it is written
    # after monitoring starts.
    target = tmp_path / "quarterly_report.docx"
    target.write_bytes(b"PK\x03\x04" + b"quarterly figures, nothing unusual. " * 400)

    baseline = wait_for_event(lambda e: e["file_path"].endswith("quarterly_report.docx"))
    assert baseline is not None
    assert baseline["suspicious"] is False
    monitor_app.EVENTS.clear()

    # Encrypted in place, keeping the name and the container header.
    target.write_bytes(b"PK\x03\x04" + os.urandom(16384))

    event = wait_for_event(
        lambda e: e["file_path"].endswith("quarterly_report.docx") and e["suspicious"]
    )
    assert event is not None, "in-place encryption behind a valid ZIP header was not detected"
    assert event["verdict"] == "suspected_encryption"
    assert event["entropy_delta"] is not None and event["entropy_delta"] >= 2.0
    assert "rose" in event["reason"]


def test_ordinary_file_lifecycles_produce_no_differential_false_positives(tmp_path):
    """Table 5.7 names differential entropy as a false-positive mitigation, so it
    had better not be a source of them.

    The static false-positive benchmark scores each file once and never builds
    history, so it cannot exercise this rule at all. These are the sequences a
    real desktop produces: archives written in passes, documents edited, office
    files re-saved. None of them is replacement, and none may be flagged.
    """
    monitor_app.ENTROPY_HISTORY.clear()
    flagged = []

    def drive(name, writes):
        path = tmp_path / name
        for index, payload in enumerate(writes):
            path.write_bytes(payload)
            event = monitor_app.handle_event(str(path), "created" if index == 0 else "modified")
            if event and event["suspicious"]:
                flagged.append((name, index, event["verdict"], event["entropy_delta"]))

    def zip_bytes(count):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for index in range(count):
                archive.writestr(f"photo_{index}.bin", os.urandom(16 * 1024))
        return buffer.getvalue()

    # An archive created empty, then written, then added to.
    drive("photos.zip", [b"", zip_bytes(2), zip_bytes(6), zip_bytes(12)])
    # A document edited repeatedly.
    text = b"the quarterly figures are in line with expectations. "
    drive("report.txt", [text * 100, text * 400, text * 900])
    # An office file re-saved: a .docx is a ZIP, so it sits near 8.0 throughout.
    drive("deck.docx", [zip_bytes(3), zip_bytes(4), zip_bytes(5)])
    # A large download landing in pieces. Every write but the last is a real MP4
    # cut short, which is what a partial download *is* - the box chain is sound
    # and the final box has not finished arriving. Structural validation has to
    # read that as "not finished" rather than "not an MP4", or every large file
    # anyone downloads onto a watched path becomes an alert while it lands.
    movie = synthetic_corpus.build_mp4(900_000)
    drive("movie.mp4", [movie[:64_000], movie[:256_000], movie])

    assert not flagged, f"differential entropy produced false positives: {flagged}"


def test_a_file_seen_once_reports_no_entropy_delta(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})
    (tmp_path / "fresh.bin").write_bytes(os.urandom(8192))

    event = wait_for_event(lambda e: e["file_path"].endswith("fresh.bin"))
    assert event is not None
    assert event["entropy_delta"] is None


def test_file_patterns_filter_the_files_that_are_processed(client, tmp_path):
    """Listing 3.1's file_patterns used to be stored and echoed but never applied.

    gateway.yaml marks the field required, so a caller asking to watch only
    *.pdf got every file instead, with nothing to indicate the filter had been
    discarded.
    """
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "file_patterns": ["*.pdf"]})

    (tmp_path / "report.pdf").write_bytes(b"%PDF-1.4\n" + os.urandom(2048))
    (tmp_path / "notes.txt").write_text("nothing to see here")

    assert wait_for_event(lambda e: e["file_path"].endswith("report.pdf")) is not None
    # Give the unwanted event the same chance to show up before ruling it out.
    assert wait_for_event(lambda e: e["file_path"].endswith("notes.txt"), timeout=1.0) is None


def test_an_empty_pattern_list_still_watches_everything(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "file_patterns": []})

    (tmp_path / "anything.xyz").write_bytes(os.urandom(2048))

    assert wait_for_event(lambda e: e["file_path"].endswith("anything.xyz")) is not None


def test_status_reports_the_filter_in_force(client, tmp_path):
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "file_patterns": ["*.doc", "*.pdf"]})

    assert client.get("/monitor/status").json()["file_patterns"] == ["*.doc", "*.pdf"]


@pytest.mark.parametrize(
    "path,patterns,expected",
    [
        ("/watch/report.pdf", ["*.pdf"], True),
        ("/watch/report.txt", ["*.pdf"], False),
        ("/watch/report.txt", [], True),
        ("/watch/a.doc", ["*.doc", "*.pdf", "*.jpg"], True),
        # Listing 3.1's own example list.
        ("/watch/photo.jpg", ["*.doc", "*.pdf", "*.jpg"], True),
        ("/watch/photo.png", ["*.doc", "*.pdf", "*.jpg"], False),
        # A directory-bearing pattern matches the whole path.
        ("/watch/reports/q4.pdf", ["*/reports/*"], True),
        ("/watch/other/q4.pdf", ["*/reports/*"], False),
    ],
)
def test_pattern_matching(path, patterns, expected):
    assert monitor_app.matches_patterns(path, patterns) is expected


def test_pattern_matching_ignores_case_where_the_filesystem_does():
    """fnmatch normalises case per platform, matching how the FS behaves."""
    expected = os.path.normcase("A.PDF") == os.path.normcase("a.pdf")
    assert monitor_app.matches_patterns("/watch/report.PDF", ["*.pdf"]) is expected


def test_detected_event_carries_every_feature_the_model_scores(client, tmp_path):
    """The dashboard scores an event straight off /monitor/events.

    Anything missing here is not defaulted by the ML engine - features_to_vector
    interpolates it from entropy instead, which is what made a legitimate ZIP
    render as a threat on the banner. All seven of the behavioural model's
    inputs have to be derivable from the event alone.
    """
    client.post("/monitor/start", json={"watch_path": str(tmp_path)})
    (tmp_path / "scored.bin").write_bytes(os.urandom(8192))

    event = wait_for_event(lambda e: e["file_path"].endswith("scored.bin"))
    assert event is not None
    for field in [
        "entropy",
        "file_size",
        "magic_bytes",
        "container_format",
        "ransom_extension",
        "printable_ratio",
        "byte_value_std",
        "chi_square_uniformity",
    ]:
        assert field in event, f"{field} missing from the event the dashboard scores"

    # Measured, not interpolated: random bytes sit at ~0.371 printable.
    assert 0.3 < event["printable_ratio"] < 0.45


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
    target.write_bytes(synthetic_corpus.build_png(50000))

    body = client.post("/features", json={"path": str(target)}).json()

    assert body["magic_bytes"] == "89504E47"
    assert body["file_size"] == target.stat().st_size
    assert body["container_format"] == "png"
    assert body["container_valid"] is True
    assert body["suspicious"] is False
    assert 0.0 <= body["modification_rate"] <= 1.0


def test_features_report_a_forged_container_as_forged(client, tmp_path):
    """The same eight magic bytes, nothing behind them.

    This file used to be what the test above wrote, and the endpoint used to
    call it a PNG. It is the `spoofer` evasion in a single file: the header is
    free to write, and until the structure was checked it bought the container
    exemption outright.
    """
    target = tmp_path / "spoofed.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(50000))

    body = client.post("/features", json={"path": str(target)}).json()

    assert body["container_format"] == "png"
    assert body["container_valid"] is False
    assert body["suspicious"] is True
    assert body["signal"] == "structural_mismatch"


def test_features_do_not_judge_a_format_with_no_validator(client, tmp_path):
    """`None` is not `False`. A RAR nobody parses stays exempt, as before."""
    target = tmp_path / "archive.rar"
    target.write_bytes(b"Rar!\x1a\x07\x00" + os.urandom(50000))

    body = client.post("/features", json={"path": str(target)}).json()

    assert body["container_format"] == "rar"
    assert body["container_valid"] is None
    assert body["suspicious"] is False


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


# ------------------------------------------------------- observer selection


def test_polling_is_chosen_on_a_mount_that_carries_no_inotify(monkeypatch, tmp_path):
    """A Windows bind mount accepts inotify watches and never fires them.

    Verified on Windows 11 build 26200 against Docker Desktop: a host-side write
    into the bind-mounted watch path produced zero events, while the identical
    write made inside the container produced ten. The native backend reports
    healthy throughout, so the mount type has to drive the choice.
    """
    monkeypatch.setattr(monitor_app, "OBSERVER_MODE", "auto")
    monkeypatch.setattr(monitor_app, "filesystem_for", lambda path: "virtiofs")

    observer, backend, reason = monitor_app.build_observer(str(tmp_path))
    observer.stop()

    assert backend == "polling"
    assert "virtiofs" in reason


def test_native_is_kept_on_a_normal_filesystem(monkeypatch, tmp_path):
    """Polling costs a stat sweep per interval; it is not the default."""
    monkeypatch.setattr(monitor_app, "OBSERVER_MODE", "auto")
    monkeypatch.setattr(monitor_app, "filesystem_for", lambda path: "ext4")

    observer, backend, _ = monitor_app.build_observer(str(tmp_path))
    observer.stop()

    assert backend == "native"


@pytest.mark.parametrize("mode,expected", [("polling", "polling"), ("native", "native")])
def test_the_backend_can_be_forced(monkeypatch, tmp_path, mode, expected):
    monkeypatch.setattr(monitor_app, "OBSERVER_MODE", mode)
    monkeypatch.setattr(monitor_app, "filesystem_for", lambda path: "ext4")

    observer, backend, reason = monitor_app.build_observer(str(tmp_path))
    observer.stop()

    assert backend == expected
    assert "MONITOR_OBSERVER" in reason


def test_filesystem_for_picks_the_longest_matching_mountpoint(monkeypatch):
    """/watch must resolve to its own bind mount, not to the root filesystem."""
    mounts = "/dev/sda1 / ext4 rw 0 0\ndrvfs /watch virtiofs rw 0 0\n"
    monkeypatch.setattr(monitor_app.os.path, "realpath", lambda p: "/watch/docs")
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO(mounts))

    assert monitor_app.filesystem_for("/watch/docs") == "virtiofs"


def test_filesystem_for_is_quiet_where_there_is_no_proc(monkeypatch):
    """Off Linux there is no /proc/mounts; that is not an error."""

    def no_proc(*args, **kwargs):
        raise OSError("no /proc")

    monkeypatch.setattr("builtins.open", no_proc)
    assert monitor_app.filesystem_for("/watch") == ""


def test_status_reports_which_backend_is_watching(client, tmp_path):
    """A silent native watch is indistinguishable from a quiet disk otherwise."""
    client.post("/monitor/start", json={"watch_path": str(tmp_path), "recursive": False})
    body = client.get("/monitor/status").json()

    assert body["observer_backend"] in {"native", "polling"}
    assert body["observer_reason"]
