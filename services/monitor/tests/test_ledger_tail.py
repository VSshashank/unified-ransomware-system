"""The pipeline worker hands its last ledger block to a second thread.

`_drain` writes, per suspicious event: the ML call, the `file_event` block, the
Response call (which writes its own `response_action` block) and the Monitor's own
`response_action` block - each a disk commit before the next event's ML call could
start - and an escalation block that had to wait behind them also ran there. On a
slow disk a 20-file burst fell 4-8 s behind the events (R22, 2026-10-06).

`MONITOR_DEFER_TAIL_BLOCKS` (default on) hands the Monitor's `response_action` block,
and an escalation block that was waiting for it, to `_run_tail`, so the worker moves
on while it commits and the ledger can carry both in one commit.

Pinned here:
  * the order inside one incident is unchanged - file_event, the response block,
    then the escalation block - and every block is written;
  * `_work.join()` still means "every block is in the chain" (the existing tests
    rely on it), because the tail, not the worker, reports the item done;
  * the worker really does not wait (overlap), and with the flag off it does;
  * a block that fails to write does not stop the tail or leave a join hanging.

The stubs are the ones `test_escalation_bypasses_backlog.py` uses.
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
import pipeline  # noqa: E402
from attribution import AttributionSource, Attributor, ProcessFacts, WriteLog  # noqa: E402

BURSTER = 3030
WRITER = r"C:\Temp\writer.exe"
BURST = 10


class KernelSource(AttributionSource):
    name = "fake-kernel-4663"
    kernel_grade = True
    delivery_horizon_ms = 300.0

    def __init__(self, log: WriteLog) -> None:
        super().__init__(log)

    def start(self) -> bool:
        self.available = True
        return True


class Downstream:
    """ML engine, ledger and Response. Calls are recorded with when they started and ended."""

    def __init__(self, latency: dict[str, float], fail_once_on: str | None = None) -> None:
        self.latency = latency
        self.fail_once_on = fail_once_on
        self.lock = threading.Lock()
        self.calls: list[dict] = []

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        started = time.perf_counter()
        kind = payload.get("event_type") if path == "/ledger/log" else path
        time.sleep(self.latency.get(kind, 0.0))
        with self.lock:
            fail = self.fail_once_on == kind
            if fail:
                self.fail_once_on = None
            self.calls.append({"path": path, "kind": kind, "payload": payload, "start": started, "end": time.perf_counter()})
            block_id = len(self.calls)
        if fail:
            raise RuntimeError("the ledger went away")
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return {"block_id": block_id}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["network_isolation_planned", "admin_notified"]}
        if path == "/response/terminate":
            return {"status": "terminated", "process_id": payload["process_id"], "incident_id": payload["incident_id"]}
        return {}

    def snapshot(self) -> list[dict]:
        with self.lock:
            return list(self.calls)

    def ledger(self) -> list[dict]:
        return [c for c in self.snapshot() if c["path"] == "/ledger/log"]


def _burst(tmp_path, count: int, source=None, log=None) -> list[dict]:
    events = []
    for index in range(count):
        target = tmp_path / f"burst_{index:02d}.docx"
        written_at = time.time()
        target.write_bytes(os.urandom(32 * 1024))
        if source is not None:
            log.record(str(target), BURSTER, WRITER, written_at=written_at)
        events.append(monitor_app.handle_event(str(target), "modified"))
    return events


def _settle(timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    for queue_ in (monitor_app._escalations, monitor_app._work):
        remaining = max(0.1, deadline - time.monotonic())
        done = threading.Event()
        threading.Thread(target=lambda q=queue_: (q.join(), done.set()), daemon=True).start()
        assert done.wait(remaining), "a queue never drained"
    monitor_app._escalations.join()
    monitor_app._work.join()


@pytest.fixture
def rig(monkeypatch):
    def build(latency, kernel=False, fail_once_on=None):
        log = WriteLog()
        source = KernelSource(log) if kernel else None
        if source:
            source.start()
        started = time.time() - 60
        at = Attributor(log=log, source=source, probe=lambda pid: ProcessFacts(pid=pid, image=WRITER, created_at=started))
        downstream = Downstream(latency, fail_once_on)
        monkeypatch.setattr(pipeline, "_post", downstream)
        monkeypatch.setattr(monitor_app, "attributor", at)
        monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
        monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
        monitor_app.ENTROPY_HISTORY.clear()
        monitor_app._ensure_worker()
        return log, source, downstream

    yield build
    monitor_app._work.join()
    monitor_app._escalations.join()
    if monitor_app._pending is not None:
        monitor_app._pending.stop(timeout=2.0)
        monitor_app._pending = None
    monitor_app._work.join()
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS.clear()
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _kind_of(call: dict) -> str:
    data = call["payload"]["event_data"]
    if "outcome" in data:
        return "escalation"
    return {"file_event": "file_event", "response_action": "response"}.get(call["kind"], call["kind"])


def test_a_burst_keeps_each_incidents_blocks_in_order_and_writes_all_of_them(rig, tmp_path):
    log, source, downstream = rig({"/predict": 0.02, "file_event": 0.02, "response_action": 0.03, "/response/trigger": 0.02}, kernel=True)
    events = _burst(tmp_path, BURST, source, log)
    assert all(e["suspicious"] for e in events)
    _settle()

    by_incident: dict[str, list[str]] = {}
    for call in downstream.ledger():
        incident = call["payload"]["event_data"].get("incident_id")
        by_incident.setdefault(incident, []).append(_kind_of(call))
    assert len(by_incident) == BURST
    for incident, kinds in by_incident.items():
        assert kinds.count("file_event") == 1 and kinds.count("response") == 1, (incident, kinds)
        assert kinds.index("file_event") < kinds.index("response"), (incident, kinds)
        if "escalation" in kinds:
            assert kinds.index("response") < kinds.index("escalation"), (incident, kinds)


def test_join_returns_only_when_every_block_is_written(rig, tmp_path):
    _, _, downstream = rig({"response_action": 0.08})
    _burst(tmp_path, 6)
    monitor_app._work.join()
    written = [c for c in downstream.ledger() if c["kind"] == "response_action"]
    assert len(written) == 6, "join returned before the handed-off blocks were written"
    assert all(c["end"] <= time.perf_counter() for c in written)


def _overlaps(downstream: Downstream) -> int:
    """Pairs where an event's ML call began before the previous event's response block finished."""
    calls = downstream.snapshot()
    predicts = sorted((c for c in calls if c["path"] == "/predict"), key=lambda c: c["start"])
    responses = sorted((c for c in calls if c["kind"] == "response_action"), key=lambda c: c["start"])
    return sum(1 for later, prior in zip(predicts[1:], responses) if later["start"] < prior["end"])


def test_the_worker_moves_on_while_the_tail_block_commits(rig, tmp_path):
    _, _, downstream = rig({"/predict": 0.01, "response_action": 0.12})
    _burst(tmp_path, 6)
    _settle()
    assert _overlaps(downstream) >= 4, "the worker waited for each response block before the next event"


def test_with_the_flag_off_the_worker_waits_as_before(rig, tmp_path, monkeypatch):
    monkeypatch.setattr(monitor_app, "DEFER_TAIL_BLOCKS", False)
    _, _, downstream = rig({"/predict": 0.01, "response_action": 0.12})
    _burst(tmp_path, 6)
    _settle()
    assert _overlaps(downstream) == 0
    assert len([c for c in downstream.ledger() if c["kind"] == "response_action"]) == 6


def test_a_block_that_fails_to_write_does_not_stop_the_tail_or_hang_the_join(rig, tmp_path):
    _, _, downstream = rig({"response_action": 0.01}, fail_once_on="response_action")
    _burst(tmp_path, 5)
    _settle()
    written = [c for c in downstream.ledger() if c["kind"] == "response_action"]
    assert len(written) == 5, "every block was attempted, including after the failure"
    assert monitor_app._tail_thread is not None and monitor_app._tail_thread.is_alive()


def test_a_detection_run_outside_the_worker_writes_inline(rig, tmp_path):
    """No queue to settle on, so nothing is handed over."""
    _, _, downstream = rig({})
    event = {"file_path": str(tmp_path / "direct.docx"), "event_id": "evt_direct", "event_type": "modified",
             "incident_id": "inc_direct"}
    verdict = {"suspicious": True, "verdict": "suspicious", "entropy": 7.9}
    before = monitor_app._tail.qsize()
    handed = monitor_app._run_detection(None, event, {}, verdict)
    assert handed is False
    assert monitor_app._tail.qsize() == before
    kinds = [c["kind"] for c in downstream.ledger()]
    assert kinds == ["file_event", "response_action"], kinds
