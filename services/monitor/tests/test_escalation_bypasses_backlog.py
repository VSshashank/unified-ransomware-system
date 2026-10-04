"""F2a: the attribution question opens at detection, not behind the pipeline.

The full VM test of 2026-10-04 (F2 in reports/VM_TEST_REPORT_2026-10-04.md)
killed the first write after a 20-write burst 6.92 s after it was written, and
the re-check before it measured 5.2 s twice. The horizon was never the cause:
it runs from the read. The question was registered only after the one pipeline
worker had done ML, ledger and response for every detection queued ahead of
it, and a question that does not exist cannot close.

Here the downstream calls are slowed (stubs that sleep) so the queue is several
seconds deep, a burst of 20 suspicious writes goes in, and then one write by a
fresh process. Its kill must be asked for within the delivery horizon (plus the
clock tolerance) and 500 ms of its read, however deep the queue. On 786dd42 it
waits for the queue.

The ordering rule from `_run_detection` still holds: if the question closes
before the pipeline reaches the incident, the kill goes out at once and only its
`attribution_escalation` block waits, behind the incident's own
`response_action` block.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import AttributionSource, Attributor, ProcessFacts, WriteLog  # noqa: E402

HORIZON_MS = 1500.0
BURSTER = 3030
FRESH = 4242
WRITER = r"C:\Temp\writer.exe"
LOCKER = r"C:\Temp\locker.exe"

# One detection's trip through the stubbed pipeline: predict, file_event,
# trigger, response_action. About 0.3 s, so 20 burst detections queue ~6 s.
SLOW = {"/predict": 0.10, "/ledger/log": 0.05, "/response/trigger": 0.10}
BURST = 20
BUDGET_S = (HORIZON_MS + attribution.CLOCK_TOLERANCE_MS) / 1000.0 + 0.5


class LaggingKernelSource(AttributionSource):
    name = "fake-lagging-4663"
    kernel_grade = True
    delivery_horizon_ms = HORIZON_MS

    def __init__(self, log: WriteLog) -> None:
        super().__init__(log)
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


class SlowDownstream:
    """The ML engine, ledger and Response service, slowed to make a backlog."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, float]] = []
        self.lock = threading.Lock()

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        time.sleep(SLOW.get(path, 0.0))
        with self.lock:
            self.calls.append((path, payload, time.perf_counter()))
            block_id = len(self.calls)
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return {"block_id": block_id}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["network_isolation_planned", "admin_notified"]}
        if path == "/response/terminate":
            return {"status": "terminated", "process_id": payload["process_id"], "incident_id": payload["incident_id"]}
        return {}

    def snapshot(self) -> list[tuple[str, dict, float]]:
        with self.lock:
            return list(self.calls)


@pytest.fixture
def backlogged(monkeypatch):
    log = WriteLog()
    source = LaggingKernelSource(log)
    source.start()
    started = time.time() - 60
    images = {BURSTER: WRITER, FRESH: LOCKER}
    at = Attributor(log=log, source=source,
                    probe=lambda pid: ProcessFacts(pid=pid, image=images.get(pid), created_at=started))
    downstream = SlowDownstream()
    monkeypatch.setattr(pipeline, "_post", downstream)
    monkeypatch.setattr(monitor_app, "attributor", at)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app._ensure_worker()
    yield source, downstream
    source.cancel()
    monitor_app._work.join()
    if monitor_app._pending is not None:
        monitor_app._pending.stop(timeout=2.0)
        monitor_app._pending = None
    monitor_app._escalations.join()
    monitor_app._work.join()
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS.clear()
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_the_first_write_after_a_burst_is_killed_within_the_horizon_not_the_backlog(backlogged, tmp_path):
    source, downstream = backlogged

    for index in range(BURST):
        target = tmp_path / f"burst_{index:02d}.docx"
        written_at = time.time()
        target.write_bytes(os.urandom(32 * 1024))
        source.deliver(str(target), BURSTER, WRITER, written_at=written_at, lag_ms=300)
        assert monitor_app.handle_event(str(target), "modified")["suspicious"] is True

    fresh = tmp_path / "board_minutes.docx"
    written_at = time.time()
    fresh.write_bytes(os.urandom(64 * 1024))
    # Its 4663 arrives a second later, as the VM measured (median 888 ms).
    source.deliver(str(fresh), FRESH, LOCKER, written_at=written_at, lag_ms=1000)
    before_read = time.perf_counter()  # the read happens after this, so the bound is strict
    event = monitor_app.handle_event(str(fresh), "modified")
    assert event["suspicious"] is True

    def fresh_kill():
        return next((t for p, payload, t in downstream.snapshot()
                     if p == "/response/terminate" and payload["process_id"] == FRESH), None)

    assert _wait_for(lambda: fresh_kill() is not None, timeout=15.0), "no kill was ever asked for"
    elapsed = fresh_kill() - before_read
    queued_behind = BURST * sum(SLOW.values())
    print(f"fresh writer's kill asked for {elapsed:.3f}s after its read (budget {BUDGET_S:.2f}s)")
    assert elapsed <= BUDGET_S, (
        f"kill asked for {elapsed:.2f}s after the read; budget {BUDGET_S:.2f}s "
        f"(the pipeline queue ahead of it was about {queued_behind:.1f}s deep)"
    )

    # The kill carried the incident the pipeline later opened for this file.
    incident = event["incident_id"]
    (terminate,) = [payload for p, payload, _ in downstream.snapshot()
                    if p == "/response/terminate" and payload["process_id"] == FRESH]
    assert terminate["incident_id"] == incident

    # And only the block waited: the escalation block comes after the
    # incident's own response_action block in the chain.
    def blocks():
        return [payload["event_data"] for p, payload, _ in downstream.snapshot() if p == "/ledger/log"]

    assert _wait_for(lambda: any(b.get("incident_id") == incident and "outcome" in b for b in blocks()),
                     timeout=20.0), "the escalation block was never written"
    mine = [b for b in blocks() if b.get("incident_id") == incident]
    kinds = ["escalation" if "outcome" in b else ("response" if "actions_taken" in b else "file_event") for b in mine]
    assert kinds.index("escalation") > kinds.index("response"), kinds
    assert kinds.index("response") > kinds.index("file_event"), kinds
    (escalation,) = [b for b in mine if "outcome" in b]
    assert escalation["result"] == "terminated"
    assert event["attribution_escalation"]["result"] == "terminated"
