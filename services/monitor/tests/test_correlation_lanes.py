"""Defect 3 of the Windows integration test: correlation blocked the watchdog thread.

Measured on the VM: the locker family wrote 20 files in about 0.1 s, and their
detection events were stamped about 250 ms apart - one attribution grace each -
the last at least 4.77 s after its write, while `detection_latency_ms` read
2-17 ms because it is measured before the wait.

What has to hold, each asserted below:

    1. twenty suspicious events inside 50 ms, against a source that never
       answers, are all correlated in about one grace, not twenty       (b)
    2. the watchdog thread is not held while they are                   (b)
    3. every file's events stay in order                                (a, c)
    4. `observed_at`, `queue_wait_ms` and `response_dispatched_at` are on
       the event, and `detection_latency_ms` still excludes queueing     (c)
    5. a full lane runs the job inline rather than dropping a detection  (a)
    6. an attribution wait that overruns its deadline says by how much   (d)
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest
from watchdog.events import FileModifiedEvent

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import dispatch  # noqa: E402
import pipeline  # noqa: E402
from attribution import AttributionSource, Attributor, WriteLog  # noqa: E402
from dispatch import CorrelationLanes, lane_for  # noqa: E402

GRACE_MS = 250.0


# ------------------------------------------------------------- (a) the lanes


def test_a_a_path_always_lands_on_the_same_lane():
    lanes = 4
    for path in (r"C:\watched\a.docx", "/watch/b.xlsx", r"C:\watched\sub\c.pdf"):
        first = lane_for(path, lanes)
        assert 0 <= first < lanes
        assert all(lane_for(path, lanes) == first for _ in range(10))
    assert lane_for(r"C:\watched\a.docx", 1) == 0


@pytest.mark.skipif(os.name != "nt", reason="case folding is a Windows path rule")
def test_a_two_spellings_of_one_windows_path_share_a_lane():
    assert lane_for(r"C:\Watched\A.DOCX", 8) == lane_for("c:/watched/a.docx", 8)


def test_a_one_paths_jobs_run_in_order_even_behind_a_slow_one():
    lanes = CorrelationLanes(lanes=4)
    lanes.start()
    ran: list[int] = []
    try:
        for index in range(6):
            def job(wait_ms, index=index):
                if index == 0:
                    time.sleep(0.1)  # the slow first job must not be overtaken
                ran.append(index)
            assert lanes.submit(r"C:\watched\same.docx", job) is True
        assert lanes.drain(timeout=5.0)
    finally:
        lanes.stop()
    assert ran == list(range(6))


def test_a_a_full_lane_runs_the_job_inline_instead_of_dropping_it():
    lanes = CorrelationLanes(lanes=1, queue_max=1)
    lanes.start()
    release = threading.Event()
    ran: list[str] = []
    try:
        lanes.submit("/w/blocker", lambda wait_ms: (release.wait(5.0), ran.append("blocker")))
        time.sleep(0.05)  # the blocker is running, the queue is empty
        assert lanes.submit("/w/queued", lambda wait_ms: ran.append("queued")) is True
        waits: list[float] = []
        overflowed = lanes.submit("/w/overflow", lambda wait_ms: (waits.append(wait_ms), ran.append("overflow")))
        assert overflowed is False
        assert ran == ["overflow"] and waits == [0.0]  # ran at once, on this thread
        release.set()
        assert lanes.drain(timeout=5.0)
    finally:
        release.set()
        lanes.stop()
    assert sorted(ran) == ["blocker", "overflow", "queued"]  # nothing dropped
    assert lanes.stats()["ran_inline"] == 1


def test_a_lanes_that_are_not_running_run_the_job_inline():
    lanes = CorrelationLanes(lanes=2)
    ran = []
    assert lanes.submit("/w/x", lambda wait_ms: ran.append(wait_ms)) is False
    assert ran == [0.0]


def test_a_stopping_finishes_what_is_queued():
    lanes = CorrelationLanes(lanes=1)
    lanes.start()
    ran = []
    for index in range(5):
        lanes.submit("/w/p", lambda wait_ms, index=index: (time.sleep(0.01), ran.append(index)))
    lanes.stop(timeout=5.0)
    assert ran == [0, 1, 2, 3, 4]
    assert lanes.running is False


def test_a_a_failing_job_does_not_stop_its_lane():
    lanes = CorrelationLanes(lanes=1)
    lanes.start()
    ran = []
    try:
        lanes.submit("/w/p", lambda wait_ms: 1 / 0)
        lanes.submit("/w/p", lambda wait_ms: ran.append("after"))
        assert lanes.drain(timeout=5.0)
    finally:
        lanes.stop()
    assert ran == ["after"]
    assert lanes.stats()["failed"] == 1


# ---------------------------------------- (b) twenty events, a source that never answers


class SilentKernelSource(AttributionSource):
    """Live and kernel-grade, and it never delivers anything - the worst case
    for the old design, where every event then paid the full grace."""

    name = "fake-silent-4663"
    kernel_grade = True
    delivery_horizon_ms = 1500.0

    def start(self) -> bool:
        self.available = True
        return True


@pytest.fixture
def watched(monkeypatch, tmp_path):
    log = WriteLog()
    source = SilentKernelSource(log)
    source.start()
    monkeypatch.setattr(monitor_app, "attributor", Attributor(log=log, source=source))
    monkeypatch.setattr(attribution, "GRACE_MS", GRACE_MS)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", False)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    lanes = monitor_app._lanes  # the instance started here is the one stopped
    lanes.start()
    yield tmp_path
    lanes.stop(timeout=5.0)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _burst(directory: Path, count: int) -> list[Path]:
    files = []
    for index in range(count):
        target = directory / f"quarterly_report_{index:02d}.docx"
        target.write_bytes(os.urandom(32 * 1024))
        files.append(target)
    return files


def _spy_on_resolve(monkeypatch) -> list[int]:
    """The threads `resolve` ran on - the one wait this defect is about."""
    threads: list[int] = []
    real = monitor_app.attributor.resolve

    def resolve(*args, **kwargs):
        threads.append(threading.get_ident())
        return real(*args, **kwargs)

    monkeypatch.setattr(monitor_app.attributor, "resolve", resolve)
    return threads


def _deliver(files: list[Path]) -> tuple[float, float]:
    """Hand the burst over the way watchdog does, on this (the observer) thread."""
    handler = monitor_app.MonitorHandler()
    started = time.perf_counter()
    for target in files:
        handler.on_modified(FileModifiedEvent(str(target)))
    return started, time.perf_counter()


def _assert_one_grace_not_twenty(events: list[dict], started: float, handed_over: float, finished: float) -> None:
    """The timing half, measured so that a slow host cannot fake it either way.

    Classification stays on the observer thread by design (dispatch.py), so on
    a loaded host handing twenty files over takes as long as classifying them -
    the base commit's own latency benchmarks read p95 109-200 ms on the day this
    was written. What must not be on that thread is any attribution wait, so the
    bounds are stated against the events' own `detection_latency_ms`, not
    against an assumed classification cost: the old design pays twenty graces
    (5 s at 250 ms), and this one pays one, after the last hand-over.
    """
    total_ms = (finished - started) * 1000
    watchdog_ms = (handed_over - started) * 1000
    after_ms = (finished - handed_over) * 1000
    classifying_ms = sum(e["detection_latency_ms"] for e in events)
    # The thread watchdog calls in on spent its time classifying, not waiting.
    assert watchdog_ms - classifying_ms < GRACE_MS, (
        f"the watchdog thread was held {watchdog_ms - classifying_ms:.0f}ms beyond classifying"
    )
    # Everything was correlated about one grace after the last hand-over.
    assert after_ms < GRACE_MS + 250, f"correlation finished {after_ms:.0f}ms after the last hand-over"
    assert total_ms < classifying_ms + GRACE_MS + 500, f"20 events took {total_ms:.0f}ms"
    assert total_ms < 20 * GRACE_MS, f"20 events took {total_ms:.0f}ms - the old design's twenty graces"


def test_b_twenty_events_inside_50ms_are_correlated_in_one_grace_not_twenty(watched, monkeypatch):
    files = _burst(watched, 20)
    resolved_on = _spy_on_resolve(monkeypatch)

    started, handed_over = _deliver(files)
    assert monitor_app._lanes.drain(timeout=10.0)
    finished = time.perf_counter()

    events = [e for e in monitor_app.EVENTS if e.get("suspicious")]
    assert len(events) == 20, f"{len(events)} suspicious events"
    assert all(e["queue_wait_ms"] is not None for e in events)

    # Not one attribution wait ran on the thread watchdog calls in on. This is
    # the defect itself, asserted without a clock.
    assert len(resolved_on) == 20
    assert threading.get_ident() not in resolved_on
    _assert_one_grace_not_twenty(events, started, handed_over, finished)

    for event in events:
        assert event["attribution_confidence"] == attribution.UNKNOWN
        assert event["attribution_pending"] is True  # the question is open, not answered
        assert event["attribution_waited_ms"] <= GRACE_MS + 150, event["attribution_waited_ms"]


def test_b_the_same_twenty_through_one_lane_still_take_one_grace(watched, monkeypatch):
    """The deadline is observation + grace, so queueing is charged to it."""
    one_lane = CorrelationLanes(lanes=1)
    monkeypatch.setattr(monitor_app, "_lanes", one_lane)
    one_lane.start()
    files = _burst(watched, 20)
    resolved_on = _spy_on_resolve(monkeypatch)
    try:
        started, handed_over = _deliver(files)
        assert one_lane.drain(timeout=10.0)
        finished = time.perf_counter()
    finally:
        one_lane.stop()

    events = [e for e in monitor_app.EVENTS if e.get("suspicious")]
    assert len(events) == 20
    assert len(resolved_on) == 20 and threading.get_ident() not in resolved_on
    _assert_one_grace_not_twenty(events, started, handed_over, finished)


# ------------------------------------------------------------- (c) the event fields


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_c_queueing_is_reported_and_kept_out_of_detection_latency(watched):
    """Three events on one path share a lane: the later ones wait, and say so."""
    target = watched / "board_minutes.docx"
    handler = monitor_app.MonitorHandler()
    for _ in range(3):
        target.write_bytes(os.urandom(32 * 1024))
        handler.on_modified(FileModifiedEvent(str(target)))
    assert monitor_app._lanes.drain(timeout=10.0)

    events = [e for e in monitor_app.EVENTS if e.get("suspicious")]
    assert len(events) == 3
    for event in events:
        assert event["detection_latency_ms"] < 100, event["detection_latency_ms"]
        assert _iso(event["observed_at"]) <= _iso(event["timestamp"])
    # The second waited for the first one's grace, behind it in the same lane.
    assert events[1]["queue_wait_ms"] > 100, [e["queue_wait_ms"] for e in events]
    assert events[1]["detection_latency_ms"] < events[1]["queue_wait_ms"]


def test_c_a_files_events_reach_the_pipeline_queue_in_order(watched, monkeypatch):
    captured: queue.Queue = queue.Queue()
    monkeypatch.setattr(monitor_app, "_work", captured)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    target = watched / "ledger_export.xlsx"
    handler = monitor_app.MonitorHandler()
    for _ in range(4):
        target.write_bytes(os.urandom(32 * 1024))
        handler.on_modified(FileModifiedEvent(str(target)))
    assert monitor_app._lanes.drain(timeout=10.0)

    handed_on = []
    while not captured.empty():
        item = captured.get_nowait()
        if item[0] == "detection":
            handed_on.append(item[1]["event_id"])
    recorded = [e["event_id"] for e in monitor_app.EVENTS if e.get("suspicious")]
    assert handed_on == recorded and len(recorded) == 4


def test_c_a_benign_event_has_observed_at_and_no_queue_wait(watched):
    target = watched / "notes.txt"
    target.write_text("minutes of the meeting\n" * 200)

    event = monitor_app.handle_event(str(target), "created")

    assert event["suspicious"] is False
    assert event["observed_at"] is not None
    assert event["queue_wait_ms"] is None
    assert event["response_dispatched_at"] is None


def test_c_a_direct_call_correlates_before_it_returns(watched):
    target = watched / "direct.docx"
    target.write_bytes(os.urandom(32 * 1024))

    event = monitor_app.handle_event(str(target), "modified")

    assert event["queue_wait_ms"] == 0.0
    assert event["attribution_reason"] != "pending: queued for correlation"


def test_c_response_dispatched_at_is_recorded_when_the_pipeline_asks(monkeypatch, tmp_path):
    sent = []

    def fake_post(client, base_url, path, payload, *args, **kwargs):
        sent.append(path)
        if path == "/ledger/log":
            return {"block_id": 1}
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.9, "threat_level": "critical"}
        return {"status": "success", "actions_taken": []}

    monkeypatch.setattr(pipeline, "_post", fake_post)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monitor_app._ensure_worker()
    target = tmp_path / "victim.docx"
    target.write_bytes(os.urandom(32 * 1024))

    event = monitor_app.handle_event(str(target), "modified")
    monitor_app._work.join()
    try:
        assert "/response/trigger" in sent
        assert event["response_dispatched_at"] is not None
        assert _iso(event["response_dispatched_at"]) >= _iso(event["observed_at"])
    finally:
        monitor_app.EVENTS.clear()
        monitor_app._SEEN_FILES.clear()


def test_c_status_reports_the_lanes(watched):
    from fastapi.testclient import TestClient

    status = TestClient(monitor_app.app).get("/monitor/status").json()

    assert status["correlation"]["running"] is True
    assert status["correlation"]["lanes"] == dispatch.DEFAULT_LANES
    assert "ran_inline" in status["correlation"]


# ------------------------------------------------------------ (d) the overrun, measured


def test_d_a_wait_that_returns_late_reports_its_overrun():
    """What the VM's 766 ms against a 250 ms grace would have said about itself."""
    log = WriteLog()
    source = SilentKernelSource(log)
    source.start()
    at = Attributor(log=log, source=source)
    original = log.lookup

    def slow_lookup(*args, **kwargs):
        time.sleep(0.3)  # the thread is held past its deadline
        return original(*args, **kwargs)

    log.lookup = slow_lookup
    now = time.time()
    answer = at.resolve(r"C:\watched\x.docx", observed_at=now, read_at=now, horizon_from=time.perf_counter(), grace_ms=100)

    assert answer.wait_overrun_ms >= 150, answer.wait_overrun_ms
    assert answer.as_event_fields()["attribution_wait_overrun_ms"] == round(answer.wait_overrun_ms, 3)


def test_d_a_wait_that_returns_on_time_reports_no_overrun():
    log = WriteLog()
    source = SilentKernelSource(log)
    source.start()
    at = Attributor(log=log, source=source)
    now = time.time()

    answer = at.resolve(r"C:\watched\x.docx", observed_at=now, read_at=now, horizon_from=time.perf_counter(), grace_ms=50)

    assert answer.wait_overrun_ms < 50
