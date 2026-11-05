"""Defect 2 of the Windows integration test: a renamed file was correlated under its new name only.

The VM's locker family rewrites each document and then renames it to
`*.locked`. 20 of 20 were detected and 0 of 20 were correlated: the detection
fires on the rename (the new name holds the ciphertext), the lookup asked who
wrote the *new* name, and the only audited write was on the *old* one. The
rename itself is not a WriteData/AppendData access, so there is no record for
it and `parse_4663` is right to drop one.

What has to hold:

    1. the watchdog handler passes both names                          (a)
    2. a write by one process, then a rename, is CERTAIN for it         (b, d)
    3. writes by two processes - under either name - are not CERTAIN    (b)
    4. the event keeps the new name as `file_path` and records the old
       one as `renamed_from`, in /monitor/events and on the chain        (c)
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest
from watchdog.events import DirMovedEvent, FileMovedEvent

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import CERTAIN, PROBABLE, UNKNOWN, AttributionSource, Attributor, ProcessFacts, WriteLog  # noqa: E402

OLD = r"C:\watched\q3_forecast.xlsx"
NEW = r"C:\watched\q3_forecast.xlsx.locked"
LOCKER = r"C:\Temp\locker.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"
ATTACKER = 4242
BENIGN = 1717
T0 = 1_790_000_000.0


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class KernelSource(AttributionSource):
    """Kernel-grade; `lag_ms` > 0 behaves like the Security channel."""

    name = "fake-kernel"
    kernel_grade = True

    def __init__(self, log: WriteLog, horizon_ms: float = 0.0) -> None:
        super().__init__(log)
        self.delivery_horizon_ms = horizon_ms
        self._timers: list[threading.Timer] = []

    def start(self) -> bool:
        self.available = True
        return True

    def deliver(self, path: str, pid: int, image: str, written_at: float, lag_ms: float) -> None:
        timer = threading.Timer(lag_ms / 1000.0, lambda: self.log.record(path, pid, image, written_at=written_at))
        timer.daemon = True
        timer.start()
        self._timers.append(timer)

    def cancel(self) -> None:
        for timer in self._timers:
            timer.cancel()


def build(horizon_ms: float = 0.0, clock=None) -> Attributor:
    log = WriteLog(clock=clock)
    source = KernelSource(log, horizon_ms)
    source.start()
    alive = lambda pid: ProcessFacts(pid=pid, image=LOCKER, created_at=time.time() - 3600)  # noqa: E731
    return Attributor(log=log, source=source, probe=alive, clock=clock)


# ------------------------------------------------------------- (a) the handler


def test_a_the_watchdog_handler_passes_both_names(monkeypatch):
    calls = []
    monkeypatch.setattr(monitor_app, "handle_event", lambda *args, **kwargs: calls.append((args, kwargs)))

    monitor_app.MonitorHandler().on_moved(FileMovedEvent(OLD, NEW))

    # The names, not the whole call: other keyword arguments (the correlation
    # lanes, since defect 3) are not what this test is about.
    ((args, kwargs),) = calls
    assert args == (NEW, "renamed")
    assert kwargs["renamed_from"] == OLD


def test_a_a_directory_rename_is_still_ignored(monkeypatch):
    calls = []
    monkeypatch.setattr(monitor_app, "handle_event", lambda *args, **kwargs: calls.append(args))

    monitor_app.MonitorHandler().on_moved(DirMovedEvent(r"C:\watched\a", r"C:\watched\b"))

    assert calls == []


# ------------------------------------------------------- (b) the lookup, on a clock


def _after_horizon(at: Attributor, clock: Clock, **kwargs):
    clock.now = T0 + 5.0
    return at.resolve(NEW, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0, **kwargs)


def test_b_a_write_then_a_rename_by_one_process_is_certain():
    clock = Clock(T0 + 0.3)
    at = build(horizon_ms=1500.0, clock=clock)
    at.log.record(OLD, ATTACKER, LOCKER, written_at=T0 - 0.004)  # the rewrite, under the old name

    answer = _after_horizon(at, clock, also=(OLD,))

    assert answer.confidence == CERTAIN, answer.reason
    assert answer.pid == ATTACKER and answer.image == LOCKER
    assert answer.kill_authorised is True


def test_b_asking_about_the_new_name_alone_is_the_defect_as_measured():
    """0 of 20 on the VM: the record exists, and it is under the other name."""
    clock = Clock(T0 + 0.3)
    at = build(horizon_ms=1500.0, clock=clock)
    at.log.record(OLD, ATTACKER, LOCKER, written_at=T0 - 0.004)

    answer = _after_horizon(at, clock)

    assert answer.confidence == UNKNOWN


def test_b_writes_by_two_processes_then_a_rename_are_not_certain():
    clock = Clock(T0 + 0.3)
    at = build(horizon_ms=1500.0, clock=clock)
    at.log.record(OLD, BENIGN, NOTEPAD, written_at=T0 - 0.009)
    at.log.record(OLD, ATTACKER, LOCKER, written_at=T0 - 0.004)

    answer = _after_horizon(at, clock, also=(OLD,))

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {BENIGN, ATTACKER}
    assert answer.kill_authorised is False


def test_b_a_rename_over_a_file_another_process_wrote_is_not_certain():
    """A writer of the *new* name competes as well: the rename replaced its file."""
    clock = Clock(T0 + 0.3)
    at = build(horizon_ms=1500.0, clock=clock)
    at.log.record(NEW, BENIGN, NOTEPAD, written_at=T0 - 0.500)
    at.log.record(OLD, ATTACKER, LOCKER, written_at=T0 - 0.004)

    answer = _after_horizon(at, clock, also=(OLD,))

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {BENIGN, ATTACKER}


# ------------------------------------------- (c) the event and the chain, for real


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, float]] = []
        self._block = 500

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        self.calls.append((path, payload, time.perf_counter()))
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            self._block += 1
            return {"block_id": self._block}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["admin_notified"]}
        if path == "/response/terminate":
            return {"status": "terminated", "process_id": payload["process_id"], "incident_id": payload["incident_id"]}
        return {}

    def posts(self, path: str) -> list[dict]:
        return [payload for p, payload, _ in self.calls if p == path]

    def blocks(self, event_type: str) -> list[dict]:
        return [p["event_data"] for p in self.posts("/ledger/log") if p["event_type"] == event_type]


@pytest.fixture
def monitor(monkeypatch):
    capture = Capture()
    monkeypatch.setattr(pipeline, "_post", capture)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monitor_app.ENTROPY_HISTORY.clear()

    def use(at: Attributor, pipeline_enabled: bool) -> Capture:
        monkeypatch.setattr(monitor_app, "attributor", at)
        monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", pipeline_enabled)
        if pipeline_enabled:
            monitor_app._ensure_worker()
        return capture

    yield use
    if monitor_app._pending is not None:
        monitor_app._pending.stop(timeout=2.0)
        monitor_app._pending = None
    monitor_app._escalations.join()
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS.clear()
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _rewrite_and_rename(tmp_path: Path, name: str = "q3_forecast.xlsx") -> tuple[str, str, float]:
    """What the locker family does: overwrite in place, then rename."""
    old = tmp_path / name
    old.write_bytes(b"PK\x03\x04" + b"quarterly numbers " * 2000)
    written_at = time.time()
    old.write_bytes(os.urandom(64 * 1024))
    new = tmp_path / f"{name}.locked"
    old.rename(new)
    return str(old), str(new), written_at


def test_c_the_event_keeps_the_new_name_records_the_old_one_and_names_the_writer(monitor, tmp_path):
    at = build(horizon_ms=0.0)
    monitor(at, pipeline_enabled=False)
    old, new, written_at = _rewrite_and_rename(tmp_path)
    at.log.record(old, ATTACKER, LOCKER, written_at=written_at)

    event = monitor_app.handle_event(new, "renamed", renamed_from=old)

    assert event["suspicious"] is True
    assert event["file_path"] == new
    assert event["renamed_from"] == old
    assert event["attribution_confidence"] == CERTAIN, event["attribution_reason"]
    assert event["process_id"] == ATTACKER


def test_c_an_ordinary_event_says_it_was_not_renamed(monitor, tmp_path):
    monitor(build(), pipeline_enabled=False)
    target = tmp_path / "notes.docx"
    target.write_bytes(os.urandom(4096))

    event = monitor_app.handle_event(str(target), "modified")

    assert event["renamed_from"] is None


def test_c_the_file_event_block_carries_both_names(monitor, tmp_path):
    at = build(horizon_ms=0.0)
    capture = monitor(at, pipeline_enabled=True)
    old, new, written_at = _rewrite_and_rename(tmp_path)
    at.log.record(old, ATTACKER, LOCKER, written_at=written_at)

    monitor_app.handle_event(new, "renamed", renamed_from=old)
    monitor_app._work.join()

    (block,) = capture.blocks("file_event")
    assert block["file_path"] == new
    assert block["renamed_from"] == old
    assert block["attribution_confidence"] == CERTAIN
    (trigger,) = capture.posts("/response/trigger")
    assert trigger["action_required"] == "terminate_process"
    assert trigger["process_id"] == ATTACKER


# --------------------------------------- (d) the VM's locker shape, in real time


def test_d_rewrite_then_rename_with_a_late_record_escalates_inside_two_seconds(monitor, tmp_path):
    """The locker run as the VM saw it: rename detected, 4663 on the old name a second later."""
    at = build(horizon_ms=attribution.HORIZON_MS)
    capture = monitor(at, pipeline_enabled=True)
    old, new, written_at = _rewrite_and_rename(tmp_path)
    at.source.deliver(old, ATTACKER, LOCKER, written_at=written_at, lag_ms=1000)
    try:
        observed_mono = time.perf_counter()
        event = monitor_app.handle_event(new, "renamed", renamed_from=old)
        assert event["attribution_pending"] is True

        deadline = time.perf_counter() + 3.0
        while not capture.posts("/response/terminate") and time.perf_counter() < deadline:
            time.sleep(0.01)
    finally:
        at.source.cancel()

    (terminate,) = capture.posts("/response/terminate")
    assert terminate["process_id"] == ATTACKER
    terminate_at = next(t for p, _, t in capture.calls if p == "/response/terminate")
    assert (terminate_at - observed_mono) * 1000 < 2000

    deadline = time.perf_counter() + 1.0
    while not capture.blocks("attribution_escalation") and time.perf_counter() < deadline:
        time.sleep(0.01)
    (escalation,) = capture.blocks("attribution_escalation")
    assert escalation["file_path"] == new and escalation["renamed_from"] == old
    assert escalation["attribution_confidence"] == CERTAIN
    assert escalation["result"] == "terminated"
