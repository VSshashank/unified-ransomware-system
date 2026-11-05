"""F6, defect 25: one incident per file, not one per watchdog notification.

Windows reports one write as one to three notifications - `created`, then one
or two `modified` - a few milliseconds apart. Each suspicious one used to open
its own incident: its own attribution question, its own `file_event`,
`response_action` and `attribution_escalation` blocks, and its own terminate
request. The 2026-10-05 elevated run's ledger (run 2) holds 530 `file_event`
blocks for 275 suspicious files: 222 files with two, 13 with three or four. The
extra terminate requests are also what R16's kill queued behind.

So while an incident's question is open, a further suspicious `modified`
notification for the same path that read the same bytes joins it. What must
not change, and is tested here beside the fix:

  * every notification is still in /monitor/events;
  * a different PID writing the same path is still seen, and still lowers
    confidence - whether its bytes differ (its own incident, as before) or not
    (the joined notification's write is waited for over its own full delivery
    horizon, so its record is not missed);
  * a new file is never folded into an older incident (a `created`, or a
    deletion in between), different bytes are never folded, and a rename is
    handled as before;
  * a notification after the question closed, or past the coalescing window,
    opens its own incident.

The horizon clock is injected (`Clock`) so nothing here waits for a horizon.
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
SPAN_S = (HORIZON_MS + attribution.CLOCK_TOLERANCE_MS) / 1000.0
WRITER = 5150
OTHER = 6260
IMAGES = {WRITER: r"C:\Temp\encryptor.exe", OTHER: r"C:\Temp\backup.exe"}


class Clock:
    """The horizon clock: the real perf_counter until frozen at an instant."""

    def __init__(self) -> None:
        self.frozen: float | None = None

    def __call__(self) -> float:
        return self.frozen if self.frozen is not None else time.perf_counter()


class KernelSource(AttributionSource):
    name = "fake-4663"
    kernel_grade = True
    delivery_horizon_ms = HORIZON_MS

    def start(self) -> bool:
        self.available = True
        return True


class Downstream:
    """ML, ledger and Response, in-process. Records every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.lock = threading.Lock()

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        with self.lock:
            self.calls.append((path, payload))
            block_id = len(self.calls)
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return {"block_id": block_id}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["network_isolation_planned", "admin_notified"]}
        if path == "/response/terminate":
            return {"status": "terminated", "process_id": payload["process_id"]}
        return {}

    def of(self, path: str) -> list[dict]:
        with self.lock:
            return [payload for p, payload in self.calls if p == path]

    def blocks(self, event_type: str) -> list[dict]:
        return [p["event_data"] for p in self.of("/ledger/log") if p["event_type"] == event_type]


@pytest.fixture
def rig(monkeypatch):
    clock = Clock()
    log = WriteLog(clock=clock)
    source = KernelSource(log)
    source.start()
    long_ago = time.time() - 600
    at = Attributor(log=log, source=source, clock=clock,
                    probe=lambda pid: ProcessFacts(pid=pid, image=IMAGES.get(pid), created_at=long_ago))
    downstream = Downstream()
    monkeypatch.setattr(pipeline, "_post", downstream)
    monkeypatch.setattr(monitor_app, "attributor", at)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app._ensure_worker()
    yield clock, log, downstream
    close_everything(clock)
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


def close_everything(clock: Clock) -> None:
    """Move the horizon clock past every horizon and let every question close."""
    clock.frozen = time.perf_counter() + 60.0
    pending = monitor_app._pending
    if pending is not None:
        pending._wake.set()
        assert _wait_for(lambda: pending.depth() == 0, timeout=5.0), "questions never closed"
    monitor_app._escalations.join()
    monitor_app._work.join()


def write(path: Path, log: WriteLog, pid: int = WRITER, data: bytes | None = None) -> None:
    """New random bytes (or `data`) at `path`, and the audit record of who wrote them."""
    written_at = time.time()
    path.write_bytes(os.urandom(32 * 1024) if data is None else data)
    log.record(str(path), pid, IMAGES[pid], written_at=written_at)


def notify(path: Path, event_type: str, renamed_from: Path | None = None) -> dict:
    event = monitor_app.handle_event(str(path), event_type,
                                     renamed_from=str(renamed_from) if renamed_from else None)
    assert event is not None and event["suspicious"] is True, event
    return event


def events_for(path: Path) -> list[dict]:
    key = monitor_app.normalise_path(str(path))
    with monitor_app._LOCK:
        return [e for e in monitor_app.EVENTS if e["file_path"] == key]


def opened() -> int:
    return monitor_app._pending.opened if monitor_app._pending is not None else 0


# ------------------------------------------------------------------ the fix


def test_created_then_two_modified_are_one_incident(rig, tmp_path):
    clock, log, downstream = rig
    target = tmp_path / "budget_2026.xlsx"
    write(target, log)

    first = notify(target, "created")
    second = notify(target, "modified")
    third = notify(target, "modified")
    monitor_app._work.join()

    # One question, one file_event, one response.
    assert opened() == 1, f"{opened()} attribution questions opened for one write"
    assert len([b for b in downstream.blocks("file_event") if b["file_path"] == first["file_path"]]) == 1
    assert len(downstream.of("/response/trigger")) == 1

    # Every notification is still on /monitor/events, all in the one incident.
    seen = events_for(target)
    assert [e["event_id"] for e in seen] == [first["event_id"], second["event_id"], third["event_id"]]
    assert {e["incident_id"] for e in seen} == {first["incident_id"]}
    assert second["coalesced_into"] == first["incident_id"]
    assert third["coalesced_into"] == first["incident_id"]

    close_everything(clock)

    # One question closes, one terminate request for the one writer.
    terminations = downstream.of("/response/terminate")
    assert [t["process_id"] for t in terminations] == [WRITER]
    assert terminations[0]["incident_id"] == first["incident_id"]
    (escalation,) = downstream.blocks("attribution_escalation")
    assert escalation["incident_id"] == first["incident_id"]
    assert escalation["result"] == "terminated"
    # The chain says which notifications the incident covered.
    assert escalation["coalesced_event_ids"] == [second["event_id"], third["event_id"]]


def test_the_joined_notifications_carry_the_closing_answer(rig, tmp_path):
    clock, log, downstream = rig
    target = tmp_path / "minutes.docx"
    write(target, log)
    first = notify(target, "created")
    second = notify(target, "modified")
    close_everything(clock)

    assert first["attribution_confidence"] == attribution.CERTAIN
    # Not left reading "pending" for ever on /monitor/events.
    assert second["attribution_confidence"] == attribution.CERTAIN
    assert second["process_id"] == WRITER
    assert second["attribution_pending"] is False
    assert first["coalesced_event_ids"] == [second["event_id"]]


def test_an_older_incident_still_answers_its_joined_notifications(rig, tmp_path):
    """A newer incident on the same path (other bytes) must not orphan the older one's."""
    clock, log, downstream = rig
    target = tmp_path / "forecast.xlsx"
    write(target, log)
    first = notify(target, "created")
    joined = notify(target, "modified")
    write(target, log)
    newer = notify(target, "modified")
    assert joined["coalesced_into"] == first["incident_id"]
    assert newer["incident_id"] != first["incident_id"]
    close_everything(clock)

    assert joined["attribution_pending"] is False, joined
    assert joined["attribution_confidence"] == first["attribution_confidence"]


def test_the_lanes_join_in_order_too(rig, tmp_path):
    """The watchdog path: correlation on the lane that owns the path."""
    clock, log, downstream = rig
    monitor_app._lanes.start()
    target = tmp_path / "ledger.pdf"
    write(target, log)
    ids = []
    for kind in ("created", "modified", "modified"):
        event = monitor_app.handle_event(str(target), kind, lanes=monitor_app._lanes)
        ids.append(event["event_id"])
    assert monitor_app._lanes.drain(timeout=5.0)
    monitor_app._work.join()

    assert opened() == 1
    assert len(downstream.blocks("file_event")) == 1
    assert len({e["incident_id"] for e in events_for(target)}) == 1
    assert [e["event_id"] for e in events_for(target)] == ids


def test_a_joined_notifications_write_is_waited_for_over_its_own_horizon(rig, tmp_path, monkeypatch):
    """The incident closes no earlier than the last joined notification's horizon.

    Otherwise a record for the joined write - another writer's, say - arriving
    late but inside its horizon would never be counted.
    """
    clock, log, downstream = rig
    monkeypatch.setattr(monitor_app, "COALESCE_MS", 1000.0, raising=False)
    target = tmp_path / "plan.docx"
    write(target, log)
    notify(target, "created")
    after_first = time.perf_counter()
    time.sleep(0.3)
    before_second = time.perf_counter()
    notify(target, "modified")
    after_second = time.perf_counter()
    monitor_app._work.join()

    # Past the first notification's horizon, short of the second's.
    clock.frozen = after_first + SPAN_S + 0.01
    assert clock.frozen < before_second + SPAN_S
    monitor_app._pending._wake.set()
    time.sleep(0.3)
    assert monitor_app._pending.stats()["closed"] == {}, monitor_app._pending.stats()
    assert downstream.of("/response/terminate") == []

    clock.frozen = after_second + SPAN_S + 0.01
    monitor_app._pending._wake.set()
    assert _wait_for(lambda: downstream.of("/response/terminate"), timeout=5.0)
    assert [t["process_id"] for t in downstream.of("/response/terminate")] == [WRITER]


# ------------------------------------------------- what must not change (guards)


@pytest.mark.parametrize("same_bytes", [False, True], ids=["other_bytes", "identical_bytes"])
def test_a_second_writer_is_seen_and_lowers_confidence(rig, tmp_path, monkeypatch, same_bytes):
    """Another process writes the file after the first notification was read.

    With other bytes its notification is its own incident, as before. With
    identical bytes it joins the open incident - and the incident's window and
    horizon now cover it, so the second writer is still a competitor. Either
    way the answer covering the second notification names both and is not
    CERTAIN, and the second writer is never a kill target.
    """
    clock, log, downstream = rig
    monkeypatch.setattr(monitor_app, "COALESCE_MS", 1000.0, raising=False)
    target = tmp_path / "shared.xlsx"
    data = os.urandom(32 * 1024)
    write(target, log, WRITER, data=data)
    first = notify(target, "modified")
    # After the first read, outside its clock tolerance.
    time.sleep(0.12)
    write(target, log, OTHER, data=data if same_bytes else None)
    second = notify(target, "modified")
    close_everything(clock)

    assert second["attribution_confidence"] != attribution.CERTAIN, second
    assert OTHER in second["attribution_candidates"], second
    assert WRITER in second["attribution_candidates"], second
    assert OTHER not in [t["process_id"] for t in downstream.of("/response/terminate")]
    if same_bytes:
        # Joined: the one incident's answer is the lowered one, so no kill at all.
        assert second["coalesced_into"] == first["incident_id"]
        assert first["attribution_confidence"] != attribution.CERTAIN, first
        assert downstream.of("/response/terminate") == []


def test_different_bytes_are_never_folded(rig, tmp_path):
    """A notification that read other content is a further write: its own incident."""
    clock, log, downstream = rig
    target = tmp_path / "draft.docx"
    write(target, log)
    first = notify(target, "created")
    write(target, log)
    second = notify(target, "modified")
    assert second["file_hash"] != first["file_hash"]
    assert second["incident_id"] != first["incident_id"]
    assert second.get("coalesced_into") is None
    monitor_app._work.join()
    assert len(downstream.blocks("file_event")) == 2


def test_a_created_notification_never_joins(rig, tmp_path):
    clock, log, downstream = rig
    target = tmp_path / "report.docx"
    write(target, log)
    first = notify(target, "created")
    write(target, log)
    again = notify(target, "created")
    assert again["incident_id"] != first["incident_id"]
    assert "coalesced_into" not in again or again["coalesced_into"] is None
    monitor_app._work.join()
    assert opened() == 2


def test_a_new_file_after_a_deletion_is_never_folded(rig, tmp_path):
    clock, log, downstream = rig
    target = tmp_path / "invoice.pdf"
    write(target, log)
    first = notify(target, "modified")
    target.unlink()
    monitor_app.handle_event(str(target), "deleted")
    write(target, log)
    # Even a `modified` for the new file: a deletion was seen in between.
    later = notify(target, "modified")
    assert later["incident_id"] != first["incident_id"]
    assert later.get("coalesced_into") in (None, later["incident_id"])


def test_a_rename_is_handled_as_before(rig, tmp_path):
    clock, log, downstream = rig
    source = tmp_path / "contract.docx"
    locked = tmp_path / "contract.docx.locked"
    write(source, log)
    original = notify(source, "modified")
    os.replace(source, locked)
    renamed = notify(locked, "renamed", renamed_from=source)

    assert renamed["incident_id"] != original["incident_id"]
    assert renamed["renamed_from"] == monitor_app.normalise_path(str(source))
    assert renamed.get("coalesced_into") is None
    monitor_app._work.join()
    assert opened() == 2

    # A rename onto a path whose incident is open is not folded either.
    write(source, log)
    fresh = notify(source, "created")
    os.replace(source, locked)
    over = notify(locked, "renamed", renamed_from=source)
    assert over["incident_id"] not in {renamed["incident_id"], fresh["incident_id"]}


def test_a_notification_past_the_coalescing_window_opens_its_own_incident(rig, tmp_path, monkeypatch):
    clock, log, downstream = rig
    monkeypatch.setattr(monitor_app, "COALESCE_MS", 100.0, raising=False)
    target = tmp_path / "late.docx"
    write(target, log)
    first = notify(target, "created")
    time.sleep(0.25)
    second = notify(target, "modified")
    assert second["incident_id"] != first["incident_id"]
    monitor_app._work.join()
    assert opened() == 2


def test_a_notification_after_the_question_closed_opens_its_own_incident(rig, tmp_path, monkeypatch):
    clock, log, downstream = rig
    monkeypatch.setattr(monitor_app, "COALESCE_MS", 60_000.0, raising=False)
    target = tmp_path / "closed.docx"
    write(target, log)
    first = notify(target, "created")
    close_everything(clock)
    clock.frozen = None

    second = notify(target, "modified")
    assert second["incident_id"] != first["incident_id"]
    assert second.get("coalesced_into") is None
    monitor_app._work.join()
    assert opened() == 2
