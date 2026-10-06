"""Defect 22 review follow-ups: a PID reused before its kill request goes out.

`escalation_action` probes the PID just before it asks `/response/terminate`
for a kill (`_writer_started_at`). When the probe shows that the PID's current
owner started after the write - the writer exited and Windows handed its number
to a new process - the probe knew, but the request went out anyway, and the
Response service kills by PID alone: the new, innocent owner died. The same
happened when the kill memory had forgotten an earlier kill (count or age
bound) and the PID was then reused.

And `terminated_earlier` decided "the write came before our kill" on the wall
clock alone, so a wall clock stepped forward just as a kill went out made the
Monitor claim, for a later process that wrote and exited by itself, that this
Monitor had killed it.

Everything runs on the calling thread: `pipeline.bind_escalation_thread` is
thread-local, so binding it here makes this thread "the escalation thread".
`pipeline.time` is replaced, so the wall clock (`time.time`) and the horizon
clock (`time.perf_counter`, what `Question.horizon_from` is stamped with) are
both injected; the kill memory gets its own monotonic clock. No sleeps, except
the one integration test, which waits on events (each well under a second).
"""

from __future__ import annotations

import sys
import threading
import time
import types
import uuid
from pathlib import Path

import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import (  # noqa: E402
    CERTAIN,
    UNKNOWN,
    Attribution,
    Attributor,
    ProbeUnavailable,
    ProcessFacts,
    Question,
    WriteLog,
)

W = 1_700_000_000.0  # an arbitrary system-clock epoch; never time.time()
IMG = r"C:\Temp\encryptor.exe"
OTHER_IMG = r"C:\Windows\innocent_editor.exe"
TOL = attribution.CLOCK_TOLERANCE_MS / 1000.0


class Host:
    """The processes that exist, as the Monitor's probe and Response see them."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.alive: dict[int, ProcessFacts] = {}
        self.probe_raises = False

    def spawn(self, pid: int, image: str, created_at: float | None) -> None:
        with self.lock:
            self.alive[pid] = ProcessFacts(pid=pid, image=image, created_at=created_at)

    def exit(self, pid: int) -> ProcessFacts | None:
        with self.lock:
            return self.alive.pop(pid, None)

    def probe(self, pid: int):
        if self.probe_raises:
            raise ProbeUnavailable("access denied (test)")
        with self.lock:
            return self.alive.get(pid)


class Downstream:
    """Response kills whatever holds the PID - it checks nothing else, like the
    real /response/terminate - and refuses a dead PID (409, which `_post` turns
    into None). The ledger accepts everything."""

    def __init__(self, host: Host) -> None:
        self.host = host
        self.terminates: list[dict] = []
        self.killed: list[ProcessFacts] = []
        self.blocks: list[dict] = []

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        if path == "/response/terminate":
            self.terminates.append(payload)
            victim = self.host.exit(payload["process_id"])
            if victim is None:
                return None
            self.killed.append(victim)
            return {"status": "terminated", "process_id": payload["process_id"], "method": "sigterm"}
        if path == "/ledger/log":
            self.blocks.append(payload)
        return {"block_id": len(self.blocks)}

    def requests_for(self, pid: int) -> int:
        return sum(1 for p in self.terminates if p["process_id"] == pid)


class FakeTime:
    """Replaces the `time` module inside pipeline: clocks the test controls."""

    def __init__(self, wall: float) -> None:
        self.wall = wall
        self.perf = 1000.0

    def time(self) -> float:
        return self.wall

    def perf_counter(self) -> float:
        return self.perf

    def monotonic(self) -> float:
        return self.perf


@pytest.fixture
def rig(monkeypatch):
    host = Host()
    down = Downstream(host)
    clock = FakeTime(W)
    mono = types.SimpleNamespace(t=0.0)
    monkeypatch.setattr(pipeline, "_post", down)
    monkeypatch.setattr(pipeline, "time", clock)
    registry = pipeline.TerminationRegistry(clock=lambda: mono.t)
    monkeypatch.setattr(pipeline, "TERMINATIONS", registry)
    pipeline.bind_escalation_thread(host.probe)
    try:
        yield types.SimpleNamespace(host=host, down=down, clock=clock, mono=mono, registry=registry)
    finally:
        pipeline._ESCALATION_THREAD.__dict__.clear()


def answer(pid: int, image: str, written_at: float) -> Attribution:
    return Attribution(pid=pid, image=image, confidence=CERTAIN, source="fake-4663",
                       reason="exactly one writer (test)", written_at=written_at,
                       delivered_at=written_at + 0.9)


def question_for(a: Attribution, read_mono: float = 0.0) -> Question:
    """The question `a` closed. `read_mono` is `horizon_from`: when the bytes
    were read, on the horizon clock (0.0, the dataclass default, = not given)."""
    key = "inc_" + uuid.uuid4().hex[:12]
    return Question(key=key, path=r"C:\watch\f.docx", also=(), observed_at=a.written_at + 0.01,
                    read_at=a.written_at + 0.02, settle_at=a.written_at + 1.57, first=a,
                    horizon_from=read_mono)


def verified(host: Host, a: Attribution) -> Attribution:
    """What Attributor.final does to a CERTAIN answer at the horizon."""
    checked, outcome = Attributor(log=WriteLog(), probe=host.probe).verify(a)
    assert outcome == "verified" and checked.kill_authorised, outcome
    return checked


def act(a: Attribution, read_mono: float = 0.0):
    q = question_for(a, read_mono)
    action = pipeline.escalation_action(None, q, a)
    return q, action, pipeline.escalation_result(a, action)


# ------------------------------------------- the PID reused before the first request


@pytest.mark.parametrize("new_image", [IMG, OTHER_IMG], ids=["same_image", "other_image"])
def test_a_pid_reused_before_its_first_kill_request_is_not_killed(rig, new_image):
    """Verified at the horizon; then the writer exits and its PID goes to a
    process started 1.5 s after the write, before the escalation thread asks
    for the kill. The probe sees the new owner; no request may go out."""
    host, down = rig.host, rig.down
    host.spawn(701, IMG, W - 60)
    a = verified(host, answer(701, IMG, W - 2.0))
    host.exit(701)
    host.spawn(701, new_image, W - 0.5)  # cannot be the writer: started after the write
    q, action, result = act(a)

    assert down.requests_for(701) == 0, f"killed {down.killed}: the PID's new owner, for the old owner's write"
    assert host.probe(701) is not None
    assert result == "pid_reused_before_kill", result
    assert action["termination"] is None and action["response_dispatched_at"] is None

    # The block says so, truthfully: a kill was authorised and not sent, and why.
    out = pipeline.record_escalation(None, {"event_id": "evt_1", "file_path": q.path}, q, a, "verified", action)
    record = out["record"]
    assert out["result"] == record["result"] == "pid_reused_before_kill"
    assert record["action_requested"] == "terminate_process"
    assert record["termination"] is None and record["response_dispatched_at"] is None
    assert record["process_id"] == 701 and record["attribution_confidence"] == CERTAIN  # C-16: certain
    reuse = record["pid_reused_before_kill"]
    assert reuse["process_started_at"] == attribution.iso_utc(W - 0.5)
    assert reuse["written_at"] == attribution.iso_utc(W - 2.0)
    assert "terminated_earlier" not in record
    assert down.blocks[-1]["event_data"]["result"] == "pid_reused_before_kill"


def test_an_evicted_kill_and_then_a_reused_pid_does_not_kill_the_new_owner(rig, monkeypatch):
    """The kill memory holds one entry; 705's kill is forgotten when 706 is
    killed, then 705 goes to a new process. A stale answer about the first 705
    must not kill it."""
    host, down = rig.host, rig.down
    small = pipeline.TerminationRegistry(max_entries=1, clock=lambda: rig.mono.t)
    monkeypatch.setattr(pipeline, "TERMINATIONS", small)
    host.spawn(705, IMG, W - 60)
    host.spawn(706, IMG, W - 50)
    stale = verified(host, answer(705, IMG, W - 1.9))  # verified while 705 was still the writer
    assert act(answer(705, IMG, W - 2.0))[2] == "terminated"
    assert act(answer(706, IMG, W - 2.0))[2] == "terminated"
    assert small.entries(705) == []  # forgotten
    host.spawn(705, IMG, W + 0.5)
    rig.clock.wall = W + 1.0
    _, _, result = act(stale)

    assert down.requests_for(705) == 1, "eviction let a stale answer kill the PID's new owner"
    assert host.probe(705) is not None
    assert result == "pid_reused_before_kill", result


def test_an_aged_out_kill_and_then_a_reused_pid_does_not_kill_the_new_owner(rig, monkeypatch):
    host, down, mono = rig.host, rig.down, rig.mono
    short = pipeline.TerminationRegistry(memory_s=10.0, clock=lambda: mono.t)
    monkeypatch.setattr(pipeline, "TERMINATIONS", short)
    host.spawn(709, IMG, W - 60)
    stale = verified(host, answer(709, IMG, W - 1.9))
    assert act(answer(709, IMG, W - 2.0))[2] == "terminated"
    mono.t = 11.0  # past the age bound
    assert short.entries(709) == []
    host.spawn(709, OTHER_IMG, W + 0.5)
    rig.clock.wall = W + 1.0
    _, _, result = act(stale)

    assert down.requests_for(709) == 1
    assert host.probe(709) is not None
    assert result == "pid_reused_before_kill", result


# -------------------------------------- terminated_earlier and a stepped wall clock


def test_terminated_earlier_is_not_claimed_after_a_wall_clock_step_at_dispatch(rig):
    """The wall clock is stepped forward an hour just as the first kill goes
    out (VirtualBox time sync), then corrected. A new process gets the PID,
    writes - its bytes read 2 s after the kill by the monotonic clock - and
    exits by itself before its question is dispatched. That was not this
    Monitor's kill, so it must not be recorded as one."""
    host, down, clock = rig.host, rig.down, rig.clock
    host.spawn(702, IMG, W - 60)
    clock.wall, clock.perf = W + 3600.0, 1000.0  # stepped, as the kill is sent
    assert act(answer(702, IMG, W - 2.0), read_mono=998.0)[2] == "terminated"
    clock.wall = W + 0.2  # ... and corrected
    host.spawn(702, IMG, W + 1.0)
    a_new = verified(host, answer(702, IMG, W + 1.2))
    host.exit(702)  # it exits on its own
    clock.wall, clock.perf = W + 2.0, 1002.5
    _, action, result = act(a_new, read_mono=1001.2)

    assert result == "termination_refused_or_unreachable", (
        f"{result!r}: the ledger would say pid 702 (started W+1.0) died of the kill sent at W "
        f"(stamped W+3600 by the stepped clock), though it exited by itself"
    )
    assert "terminated_earlier" not in action
    assert down.requests_for(702) == 2


def test_terminated_earlier_still_holds_when_both_clocks_agree(rig):
    """The control: no step, a second question about a write the killed process
    made, read before the kill on the monotonic clock. Skipped, as defect 22
    intends, and recorded as `terminated_earlier`."""
    host, down, clock = rig.host, rig.down, rig.clock
    host.spawn(703, IMG, W - 60)
    clock.wall, clock.perf = W, 1000.0
    first = act(answer(703, IMG, W - 2.0), read_mono=998.0)
    assert first[2] == "terminated"
    clock.wall, clock.perf = W + 0.4, 1000.4
    _, action, result = act(answer(703, IMG, W - 1.9), read_mono=998.1)
    assert result == "terminated_earlier"
    assert action["terminated_earlier"]["incident_id"] == first[0].key
    assert down.requests_for(703) == 1


# ------------------------------------------------- inconclusive: today's behaviour


def test_an_unreadable_start_time_still_sends_the_request(rig):
    """The PID's owner cannot be dated: not provably a later process, so the
    request goes out exactly as before (the gate already passed at the close)."""
    host, down = rig.host, rig.down
    host.spawn(710, IMG, W - 60)
    a = verified(host, answer(710, IMG, W - 2.0))
    host.spawn(710, IMG, None)
    _, _, result = act(a)
    assert down.requests_for(710) == 1
    assert result == "terminated"


def test_a_probe_that_fails_at_dispatch_still_sends_the_request(rig):
    host, down = rig.host, rig.down
    host.spawn(711, IMG, W - 60)
    a = verified(host, answer(711, IMG, W - 2.0))
    host.probe_raises = True
    _, _, result = act(a)
    assert down.requests_for(711) == 1
    assert result == "terminated"
    assert len(rig.registry) == 1 and rig.registry.entries(711)[0].created_at is None


def test_a_pid_already_gone_still_sends_the_request_and_records_the_refusal(rig):
    host, down = rig.host, rig.down
    host.spawn(712, IMG, W - 60)
    a = verified(host, answer(712, IMG, W - 2.0))
    host.exit(712)
    _, _, result = act(a)
    assert down.requests_for(712) == 1
    assert result == "termination_refused_or_unreachable"


def test_an_owner_started_inside_the_clock_tolerance_is_still_asked_for(rig):
    """The same start-time rule `Attributor.verify` uses: a start no later than
    the write plus the tolerance is not provably a later process."""
    host, down = rig.host, rig.down
    host.spawn(713, IMG, W - 2.0 + TOL)
    a = verified(host, answer(713, IMG, W - 2.0))
    _, _, result = act(a)
    assert down.requests_for(713) == 1
    assert result == "terminated"


# --------------------------------------- through the escalation thread (the queue wait)


def test_a_pid_reused_while_its_question_waits_behind_a_slow_kill_is_not_killed(monkeypatch):
    """The reviewers' race: W's verified question waits on the escalation thread
    behind another PID's slow kill; meanwhile W exits and its number goes to an
    unrelated process. When W's turn comes, its new owner must not be killed."""
    host = Host()
    slow_entered, release = threading.Event(), threading.Event()
    calls: list[tuple[str, dict]] = []
    lock = threading.Lock()
    SLOW, WPID = 8800, 8804

    def downstream(client, base_url, path, payload, *args, **kwargs):
        with lock:
            calls.append((path, payload))
        if path == "/response/terminate":
            if payload["process_id"] == SLOW:
                slow_entered.set()
                release.wait(5.0)
            victim = host.exit(payload["process_id"])
            return None if victim is None else {"status": "terminated", "process_id": payload["process_id"]}
        return {"block_id": len(calls)}

    monkeypatch.setattr(pipeline, "_post", downstream)
    monkeypatch.setattr(monitor_app, "attributor", Attributor(log=WriteLog(), probe=host.probe))
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    pipeline.TERMINATIONS.clear()
    monitor_app._ensure_escalator()

    def closed(pid: int, image: str, name: str, written_at: float):
        event_id = "evt_" + uuid.uuid4().hex[:12]
        event = {"event_id": event_id, "file_path": rf"C:\watch\{name}",
                 "incident_id": monitor_app.incident_id_for(event_id)}
        first = Attribution(pid=None, image=None, confidence=UNKNOWN, reason="no record yet",
                            source="fake-4663", pending=True)
        q = Question(key=event["incident_id"], path=event["file_path"], also=(),
                     observed_at=written_at + 0.01, read_at=written_at + 0.02,
                     settle_at=written_at + 1.57, first=first, context=event)
        return q, answer(pid, image, written_at), event

    try:
        now = time.time()  # a timestamp to anchor start times, never a duration
        host.spawn(SLOW, r"C:\Temp\a.exe", now - 100)
        host.spawn(WPID, r"C:\Temp\w.exe", now - 100)
        q1, a1, _ = closed(SLOW, r"C:\Temp\a.exe", "a.docx", now - 3)
        q2, a2, e2 = closed(WPID, r"C:\Temp\w.exe", "w.docx", now - 2)
        monitor_app._on_question_closed(q1, a1, "verified")
        monitor_app._on_question_closed(q2, a2, "verified")
        assert slow_entered.wait(5.0), "the slow kill never started"
        host.exit(WPID)
        host.spawn(WPID, OTHER_IMG, now)  # created 2 s after W's write
        release.set()
        monitor_app._escalations.join()
        monitor_app._work.join()
    finally:
        release.set()
        pipeline.TERMINATIONS.clear()

    with lock:
        to_w = [p for path, p in calls if path == "/response/terminate" and p["process_id"] == WPID]
        blocks = [p["event_data"] for path, p in calls
                  if path == "/ledger/log" and p["event_type"] == "attribution_escalation"]
    assert not to_w, "the PID's new owner was killed for the old owner's write"
    assert host.probe(WPID) is not None
    assert e2["attribution_escalation"]["result"] == "pid_reused_before_kill"
    assert [b["result"] for b in blocks if b["incident_id"] == q2.key] == ["pid_reused_before_kill"]
