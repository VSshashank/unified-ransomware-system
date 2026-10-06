"""Freeze-first, Monitor side (FIXES.md defect 26): suspend a sole writer early, then kill or resume.

The Response service already holds suspensions under leases. Nothing in the
Monitor asked for one. This is the Monitor side: as soon as a kernel-grade
answer names exactly one writer - well before the delivery horizon has closed -
the process is frozen under a lease; at the horizon it is killed if the KILL
gate is satisfied then (the terminate carries the lease, so it is released), and
resumed otherwise.

The cases that must NEVER produce a kill are the safety-invariant table's:
two writers in the window, two writers across a rename, a stale record, an
exited PID, a reused PID, identity unprovable, an evicted competitor. Each is
driven end to end below with a REAL child process, and asserts what happened to
that process - frozen at most, then running again, never killed - rather than
what the Monitor said it asked for.

Real: the child, the write log, the attributor and its identity probe
(psutil), the pending sweeper, the escalator, and every file the events are
about. Stubbed: the Response service, which does the real thing to the real
child (`_suspend_rig.ResponseStub`), and the audit record, which needs an
elevated Security-log subscription this machine cannot have: it is a
`WriteLog.record` naming the child. Nothing here proves the Security channel
delivers in time; it proves what the Monitor does with an answer.

The horizon clock is injected, so nothing waits for a horizon.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import httpx
import psutil
import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import AttributionSource, Attributor, ProbeUnavailable, ProcessFacts, WriteLog  # noqa: E402
from _suspend_rig import Child, ResponseStub  # noqa: E402

HORIZON_MS = 1500.0
SPAN_S = (HORIZON_MS + attribution.CLOCK_TOLERANCE_MS) / 1000.0


@pytest.fixture
def suspend_policy():
    import suspend_policy as module  # absent on the base: every test below fails there

    return module


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


class InferredSource(KernelSource):
    name = "fake-inferred"
    kernel_grade = False


def wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class Rig:
    def __init__(self, clock, log, source, stub, policy, watch, make_child):
        self.clock, self.log, self.source, self.stub, self.policy = clock, log, source, stub, policy
        self.watch = watch
        self._make_child = make_child
        self.written_at: dict[Path, float] = {}

    def child(self) -> Child:
        return self._make_child()

    def close_everything(self) -> None:
        """Move the horizon clock past every horizon and let every question close."""
        self.clock.frozen = time.perf_counter() + 60.0
        pending = monitor_app._pending
        if pending is not None:
            pending._wake.set()
            assert wait_for(lambda: pending.depth() == 0, timeout=8.0), "questions never closed"
        monitor_app._escalations.join()
        monitor_app._work.join()

    # -- the file a write produced -------------------------------------------

    def write(self, name: str, child: Child | None = None, *, age: float = 0.0, image=None,
              data: bytes | None = None) -> Path:
        """New random bytes at `name` and, if `child`, the audit record naming it."""
        path = self.watch / name
        written_at = time.time() - age
        self.written_at[path] = written_at
        path.write_bytes(os.urandom(32 * 1024) if data is None else data)
        if child is not None:
            self.log.record(str(path), child.pid, image or child.image, written_at=written_at)
        return path

    def late_record(self, path: Path, child: Child) -> None:
        """A second writer's audit record, delivered NOW for a write made at the same moment as the
        first writer's - before the event - which is what a 4663 delivery lag looks like. (A write
        made after the bytes were read is not a competitor: the lookup rightly ignores it.)"""
        self.log.record(str(path), child.pid, child.image, written_at=self.written_at[path])

    def settle(self) -> None:
        """Wait for every suspend request in flight. The request is made on a thread of its own, and
        the hold's lock is held until its record is on the event."""
        for hold in list(self.policy._by_incident.values()):
            assert hold.lock.acquire(timeout=10.0), "a suspend request never finished"
            hold.lock.release()

    def notify(self, path: Path, kind: str = "created", renamed_from: Path | None = None) -> dict:
        event = monitor_app.handle_event(str(path), kind,
                                         renamed_from=str(renamed_from) if renamed_from else None)
        assert event is not None and event["suspicious"] is True, event
        self.settle()
        return event


def build(monkeypatch, tmp_path, make_child, suspend_policy, *, probe=None, maxlen=None,
          source_cls=KernelSource) -> Rig:
    clock = Clock()
    log = WriteLog(clock=clock, **({"maxlen": maxlen} if maxlen else {}))
    source = source_cls(log)
    source.start()
    attributor = Attributor(log=log, source=source, clock=clock, probe=probe)
    stub = ResponseStub()
    policy = suspend_policy.SuspendPolicy(client=httpx.Client(transport=httpx.MockTransport(stub.handler)))
    watch = tmp_path / "watched"
    watch.mkdir()
    monkeypatch.setattr(suspend_policy, "POLICY", policy)
    monkeypatch.setattr(pipeline, "_post", stub.post)
    monkeypatch.setattr(monitor_app, "attributor", attributor)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monkeypatch.setattr(monitor_app, "_watch_path", str(watch))
    monkeypatch.delenv("MONITOR_SUSPEND_FIRST", raising=False)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app._ensure_worker()
    return Rig(clock, log, source, stub, policy, watch, make_child)


@pytest.fixture
def make_child(tmp_path):
    made: list[Child] = []

    def make() -> Child:
        child = Child(tmp_path / f"beat{len(made)}")
        made.append(child)
        assert child.is_running(), "the heartbeat child never started beating"
        return child

    try:
        yield make
    finally:
        for child in made:
            child.release()


@pytest.fixture
def make_rig(monkeypatch, tmp_path, make_child, suspend_policy):
    rigs: list[Rig] = []

    def make(**kwargs) -> Rig:
        rig = build(monkeypatch, tmp_path, make_child, suspend_policy, **kwargs)
        rigs.append(rig)
        return rig

    try:
        yield make
    finally:
        for rig in rigs:
            rig.clock.frozen = time.perf_counter() + 60.0
        if monitor_app._pending is not None:
            monitor_app._pending._wake.set()
            wait_for(lambda: monitor_app._pending.depth() == 0, timeout=5.0)
            monitor_app._pending.stop(timeout=2.0)
            monitor_app._pending = None
        monitor_app._escalations.join()
        monitor_app._work.join()
        with monitor_app._ANCHORS_LOCK:
            monitor_app._ANCHORS.clear()
        monitor_app.EVENTS.clear()
        monitor_app._SEEN_FILES.clear()
        monitor_app.ENTROPY_HISTORY.clear()


@pytest.fixture
def rig(make_rig):
    return make_rig()


def assert_spared(rig: Rig, *children: Child, suspended: bool = False) -> None:
    """Nothing was killed, and nothing is left frozen."""
    assert rig.stub.of("/response/terminate") == [], rig.stub.of("/response/terminate")
    for child in children:
        assert child.alive(), "the process was killed"
        assert child.is_running(), "the process was left frozen"
    if not suspended:
        assert rig.stub.of("/response/suspend") == []


# ============================================================ the contract itself


def test_a_sole_writer_is_frozen_at_the_first_answer_then_killed_at_the_horizon(rig):
    victim = rig.child()
    path = rig.write("report.docx", victim)
    event = rig.notify(path)

    # Frozen NOW: the first answer is pending, the horizon is a second and a half away.
    assert event["attribution_confidence"] == attribution.PROBABLE and event["attribution_pending"] is True
    (request,) = rig.stub.of("/response/suspend")
    assert request["process_id"] == victim.pid
    assert request["incident_id"] == event["incident_id"]
    assert victim.is_frozen(), "the writer must be frozen before the horizon has closed"
    assert rig.stub.of("/response/terminate") == []

    rig.close_everything()

    # Killed at the horizon, and the terminate names the lease so it is released.
    (terminate,) = rig.stub.of("/response/terminate")
    assert terminate["process_id"] == victim.pid
    assert terminate["lease_id"] == event["suspension"]["lease_id"]
    assert not victim.alive()
    assert rig.stub.lease(terminate["lease_id"])["state"] == "terminated"
    assert rig.stub.of("/response/resume") == [], "a lease that becomes a kill is not also resumed"

    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["result"] == "terminated"
    assert block["lease_id"] == terminate["lease_id"]
    assert block["suspension"]["outcome"] == "terminated"
    assert block["suspension"]["suspended_at"]


def test_the_request_carries_the_gate_the_evidence_and_a_lease_past_the_horizon(rig, suspend_policy):
    victim = rig.child()
    rig.notify(rig.write("minutes.docx", victim))
    (request,) = rig.stub.of("/response/suspend")

    assert request["gate"] == "suspend_authorised"
    assert request["attribution_confidence"] == attribution.PROBABLE
    assert request["attribution_source"] == "fake-4663"
    assert "one writer so far" in request["attribution_reason"]
    assert request["image"] == victim.image
    # The identity attribution proved: the Response service refuses a different process.
    assert abs(float(request["started_at"]) - victim.started_at) < 0.05
    horizon_s = (HORIZON_MS + attribution.CLOCK_TOLERANCE_MS) / 1000.0
    assert request["lease_seconds"] == suspend_policy.SUSPEND_LEASE_S
    assert request["lease_seconds"] > horizon_s + 0.2, "the lease has to outlive the horizon and the kill's dispatch"
    assert request["reason"]


def test_the_lease_length_is_a_named_constant_built_from_the_existing_ones(suspend_policy):
    assert suspend_policy.SUSPEND_LEASE_S == pytest.approx(
        (attribution.HORIZON_MS + attribution.CLOCK_TOLERANCE_MS + suspend_policy.KILL_DISPATCH_MARGIN_MS) / 1000.0)


def test_the_lease_length_is_overridable_from_the_environment():
    """In a fresh interpreter: re-importing here would leave two copies of the module."""
    import subprocess  # noqa: PLC0415

    out = subprocess.run(
        [sys.executable, "-c", "import suspend_policy as s; print(s.SUSPEND_LEASE_S)"],
        cwd=str(MONITOR_DIR), env={**os.environ, "MONITOR_SUSPEND_LEASE_S": "3.25"},
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr[-500:]
    assert float(out.stdout.strip()) == 3.25


# ================================ the safety-invariant cases: never a kill, never left frozen


def test_two_writers_in_the_window_are_never_frozen_or_killed(rig):
    first, second = rig.child(), rig.child()
    path = rig.write("shared.xlsx", first)
    rig.log.record(str(path), second.pid, second.image, written_at=time.time() - 0.1)
    event = rig.notify(path)
    assert sorted(event["attribution_candidates"]) == sorted([first.pid, second.pid])
    rig.close_everything()
    assert_spared(rig, first, second)


def test_two_writers_across_a_rename_are_never_frozen_or_killed(rig):
    old_name_writer, new_name_writer = rig.child(), rig.child()
    old = rig.write("draft.docx", old_name_writer)
    new = rig.write("final.xlsx", new_name_writer, age=0.2)
    event = rig.notify(new, "renamed", renamed_from=old)
    assert len(event["attribution_candidates"]) == 2, event
    rig.close_everything()
    assert_spared(rig, old_name_writer, new_name_writer)


def test_a_stale_record_is_never_frozen_or_killed(rig):
    bystander = rig.child()
    path = rig.write("old.docx", bystander, age=2.5)  # a write long before the event
    event = rig.notify(path)
    assert event["process_id"] is None
    rig.close_everything()
    assert_spared(rig, bystander)


def test_an_exited_pid_is_never_frozen_or_killed(rig):
    gone = rig.child()
    path = rig.write("late.docx", gone)
    gone.kill()
    rig.notify(path)
    rig.close_everything()
    assert rig.stub.of("/response/suspend") == []
    assert rig.stub.of("/response/terminate") == []


def test_a_reused_pid_by_start_time_is_never_frozen_or_killed(make_rig):
    """The number now belongs to a process created after the write."""
    holder = {}
    rig = make_rig(probe=lambda pid: ProcessFacts(pid=pid, image=holder["image"], created_at=time.time() + 5.0))
    newcomer = rig.child()
    holder["image"] = newcomer.image
    path = rig.write("reused.docx", newcomer)
    rig.notify(path)
    rig.close_everything()
    assert_spared(rig, newcomer)


def test_a_reused_pid_by_image_is_never_frozen_or_killed(rig):
    """The audit record names one image; the process behind the PID is another."""
    newcomer = rig.child()
    path = rig.write("reused2.docx", newcomer, image=r"C:\Users\victim\Downloads\encryptor.exe")
    rig.notify(path)
    rig.close_everything()
    assert_spared(rig, newcomer)


@pytest.mark.parametrize(
    "facts",
    [pytest.param("raises", id="probe_raises"), pytest.param("blind", id="no_image_no_start_time")],
)
def test_an_unprovable_identity_is_never_frozen_or_killed(make_rig, facts):
    def probe(pid):
        if facts == "raises":
            raise ProbeUnavailable("access denied (test)")
        return ProcessFacts(pid=pid, image=None, created_at=None)

    rig = make_rig(probe=probe)
    writer = rig.child()
    rig.notify(rig.write("blind.docx", writer))
    rig.close_everything()
    assert_spared(rig, writer)


def test_an_evicted_competitor_is_never_frozen_or_killed(make_rig):
    """The log lost a record inside the competition window: a second writer cannot be ruled out."""
    rig = make_rig(maxlen=3)
    writer = rig.child()
    now = time.time()
    for n in range(3):
        rig.log.record(str(rig.watch / f"unrelated{n}.bin"), 99_000 + n, r"C:\x\y.exe", written_at=now - 0.1)
    path = rig.write("victim.docx", writer)  # this record pushes one of those out, inside the window
    assert rig.log.evicted >= 1
    event = rig.notify(path)
    assert event["attribution_candidates"] == [writer.pid]
    rig.close_everything()
    assert_spared(rig, writer)


# ----------------------------------- a second writer turns up while the lease is held


def test_a_second_writer_during_the_lease_resumes_at_once_and_never_kills(rig):
    """The second writer's record arrives after the first answer (4663 delivery lag), for a
    write that happened before the event. The question closes early as ambiguous."""
    victim, other = rig.child(), rig.child()
    path = rig.write("contested.docx", victim)
    event = rig.notify(path)
    assert victim.is_frozen()
    (suspend,) = rig.stub.of("/response/suspend")
    lease_id = event["suspension"]["lease_id"]

    rig.late_record(path, other)

    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0), "never resumed"
    (resume,) = rig.stub.of("/response/resume")
    assert resume["lease_id"] == lease_id
    assert victim.is_running(), "the lease was released but the process is still frozen"
    rig.close_everything()
    assert_spared(rig, victim, other, suspended=True)
    assert len(rig.stub.of("/response/suspend")) == 1

    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["result"] == "not_escalated"
    assert block["action_requested"] is None
    assert block["suspension"]["lease_id"] == lease_id
    assert block["suspension"]["outcome"] == "resumed"
    assert "kill gate" in block["suspension"]["reason"] and "not" in block["suspension"]["reason"]
    assert block["process_id"] is None, "C-16: a probable answer names no process in the chain"


def test_a_second_writer_resumes_the_process_exactly_once(rig):
    victim, other = rig.child(), rig.child()
    path = rig.write("twice.docx", victim)
    rig.notify(path)
    rig.late_record(path, other)
    rig.close_everything()
    assert len(rig.stub.of("/response/resume")) == 1
    assert len(rig.stub.blocks("attribution_escalation")) == 1


# ====================================================== nothing short of the gate reaches suspend


def test_a_source_that_is_not_kernel_grade_never_suspends(make_rig):
    rig = make_rig(source_cls=InferredSource)
    writer = rig.child()
    event = rig.notify(rig.write("inferred.docx", writer))
    assert event["attribution_confidence"] == attribution.PROBABLE
    rig.close_everything()
    assert_spared(rig, writer)


def test_a_path_outside_the_watched_root_never_suspends(rig, monkeypatch, tmp_path):
    writer = rig.child()
    path = rig.write("outside.docx", writer)
    monkeypatch.setattr(monitor_app, "_watch_path", str(tmp_path / "somewhere_else"))
    rig.notify(path)
    rig.close_everything()
    assert rig.stub.of("/response/suspend") == []


def test_with_no_watch_started_nothing_is_suspended(rig, monkeypatch):
    writer = rig.child()
    path = rig.write("nowatch.docx", writer)
    monkeypatch.setattr(monitor_app, "_watch_path", None)
    rig.notify(path)
    rig.close_everything()
    assert rig.stub.of("/response/suspend") == []


def test_the_benign_workload_shape_suspends_nothing(rig):
    """An hour of benign work, in miniature: one process writing many ordinary files.
    Ordinary files are not suspicious, open no question and so never reach the gate."""
    worker = rig.child()
    for n in range(40):
        path = rig.write(f"notes_{n}.txt", worker, data=(b"meeting notes, item %d\n" % n) * 200)
        event = monitor_app.handle_event(str(path), "created")
        assert event is not None and event["suspicious"] is False
    rig.close_everything()
    assert rig.stub.of("/response/suspend") == []
    assert rig.stub.of("/response/terminate") == []
    assert worker.is_running()


# ===================================================== once per PID, never once per file


def test_two_notifications_for_the_same_file_are_one_suspend(rig):
    victim = rig.child()
    path = rig.write("budget.xlsx", victim)
    first = rig.notify(path, "created")
    second = rig.notify(path, "modified")
    assert second.get("coalesced_into") == first["incident_id"]
    assert len(rig.stub.of("/response/suspend")) == 1
    rig.close_everything()
    assert len(rig.stub.of("/response/suspend")) == 1
    assert len(rig.stub.of("/response/terminate")) == 1


def test_many_files_by_one_writer_are_one_suspend_and_one_kill(rig):
    victim = rig.child()
    events = [rig.notify(rig.write(f"doc_{n}.xlsx", victim)) for n in range(5)]
    assert len(rig.stub.of("/response/suspend")) == 1, "suspension nests: one request per PID, not per file"
    assert victim.is_frozen()
    rig.close_everything()
    assert len(rig.stub.of("/response/suspend")) == 1
    assert [t["process_id"] for t in rig.stub.of("/response/terminate")] == [victim.pid]
    lease_ids = {e["suspension"]["lease_id"] for e in events}
    assert len(lease_ids) == 1, "every incident of the writer names the one lease"


def test_a_resumed_process_is_not_frozen_again_straight_away(rig):
    """A benign process that keeps writing flagged files must not be frozen for a horizon per file."""
    victim, other = rig.child(), rig.child()
    path = rig.write("first.docx", victim)
    rig.notify(path)
    rig.late_record(path, other)
    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0)
    again = rig.write("second.docx", victim)
    rig.notify(again)
    assert len(rig.stub.of("/response/suspend")) == 1, "cooldown after a resume"
    rig.close_everything()
    assert victim.is_running() or not victim.alive()


# ============== the audit record that arrives after the first look (the usual case on the VM)
#
# The first look runs at detection, and the 4663 for the write arrives 0.1-1.3 s
# later: the first answer usually names nobody. The answer that first names a
# sole writer is the one a re-ask of the open question finds, on the pending
# sweeper's thread, so freeze-first must fire there too.


def test_a_record_that_arrives_after_the_first_look_freezes_the_writer_then_kills_it(rig):
    victim = rig.child()
    path = rig.write("lagged.docx")  # written; its audit record is still in flight
    event = rig.notify(path)
    assert event["process_id"] is None and event["attribution_pending"] is True
    assert rig.stub.of("/response/suspend") == [], "nothing is named yet"

    rig.late_record(path, victim)  # the 4663 is delivered, about a second later
    assert wait_for(lambda: rig.stub.of("/response/suspend"), timeout=8.0), "the re-ask never froze the writer"
    assert victim.is_frozen(), "frozen long before the horizon"
    assert wait_for(lambda: "suspension" in event, timeout=5.0)
    assert event["suspension"]["outcome"] == "suspended"
    assert rig.stub.of("/response/terminate") == []

    rig.close_everything()
    (terminate,) = rig.stub.of("/response/terminate")
    assert terminate["process_id"] == victim.pid and terminate["lease_id"] == event["suspension"]["lease_id"]
    assert not victim.alive()
    assert len(rig.stub.of("/response/suspend")) == 1


def test_a_lagged_second_writer_after_the_freeze_resumes_and_never_kills(rig):
    victim, other = rig.child(), rig.child()
    path = rig.write("lagged2.docx")
    rig.notify(path)
    rig.late_record(path, victim)
    assert wait_for(lambda: rig.stub.of("/response/suspend"), timeout=8.0)
    assert victim.is_frozen()
    rig.late_record(path, other)  # the second writer's record, later still
    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0), "never resumed"
    rig.close_everything()
    assert_spared(rig, victim, other, suspended=True)
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["suspension"]["outcome"] == "resumed"


def test_the_sweeper_is_not_held_up_by_a_slow_response(rig):
    """The re-ask runs on the thread that closes questions at their horizon. A slow Response
    service must cost it nothing: the request is made on a thread of its own."""
    victim = rig.child()
    path = rig.write("slow.docx", victim)
    rig.stub.suspend_delay = 0.4
    event = {"incident_id": "inc_slowtest", "file_path": str(path)}
    written = rig.written_at[path]
    answer = monitor_app.attributor.resolve(str(path), observed_at=written + 0.01, read_at=written + 0.02,
                                            horizon_from=time.perf_counter())
    assert answer.pid == victim.pid and answer.pending

    started = time.perf_counter()
    result = rig.policy.on_first_answer(monitor_app.attributor, event, answer, str(path), (str(rig.watch),),
                                        parked=True, incident_id="inc_slowtest", background=True)
    assert time.perf_counter() - started < 0.2, "the caller was made to wait for Response"
    assert result is None
    assert wait_for(lambda: "suspension" in event, timeout=5.0)
    assert event["suspension"]["outcome"] == "suspended"
    assert victim.is_frozen()


def test_a_close_that_comes_while_the_suspend_is_in_flight_waits_for_it(rig, suspend_policy):
    """The lease is registered before the request goes out, so a question closing meanwhile
    cannot miss it and leave the process frozen."""
    victim = rig.child()
    path = rig.write("race.docx", victim)
    rig.stub.suspend_delay = 0.3
    event = {"incident_id": "inc_race", "file_path": str(path)}
    written = rig.written_at[path]
    answer = monitor_app.attributor.resolve(str(path), observed_at=written + 0.01, read_at=written + 0.02,
                                            horizon_from=time.perf_counter())
    rig.policy.on_first_answer(monitor_app.attributor, event, answer, str(path), (str(rig.watch),),
                               parked=True, incident_id="inc_race", background=True)
    question = attribution.Question(key="inc_race", path=str(path), also=(), observed_at=written,
                                    read_at=written, settle_at=written + 1.5, first=answer)
    closing = attribution.Attribution(pid=victim.pid, image=victim.image, confidence=attribution.PROBABLE,
                                      reason="two writers", candidates=(victim.pid, 1))
    lease = suspend_policy.on_close(question, closing)  # called at once, mid-request
    assert lease is not None and lease["action"] == "resume" and lease["outcome"] == "resumed"
    assert victim.is_running(), "the close missed the lease and left the process frozen"


def test_the_same_answer_reaching_the_hook_again_is_judged_once(make_rig):
    probed = []

    def probe(pid):
        probed.append(pid)
        return attribution.probe_process(pid)

    rig = make_rig(probe=probe)
    victim = rig.child()
    path = rig.write("again.docx")
    rig.notify(path)
    rig.late_record(path, victim)
    assert wait_for(lambda: rig.stub.of("/response/suspend"), timeout=8.0)
    before = len(probed)
    for n in range(6):  # every recorded write wakes the sweeper, which re-asks every open question
        rig.log.record(str(rig.watch / f"unrelated{n}.bin"), 99_000 + n, "other.exe", written_at=time.time())
        time.sleep(0.05)
    assert len(probed) == before, "the same answer was assessed again and again"
    assert len(rig.stub.of("/response/suspend")) == 1


# ============================================================ a Monitor that stops frees everything


def test_monitor_stop_releases_every_lease_it_holds(rig, monkeypatch):
    first, second = rig.child(), rig.child()
    rig.notify(rig.write("a.docx", first))
    rig.notify(rig.write("b.docx", second))
    assert first.is_frozen() and second.is_frozen()
    assert len(rig.stub.of("/response/suspend")) == 2

    response = monitor_app.stop_monitoring(None)
    assert response.status_code == 200

    released = rig.stub.of("/response/resume")
    assert len(released) == 2
    assert {r["lease_id"] for r in released} == {
        e["suspension"]["lease_id"] for e in monitor_app.EVENTS if "suspension" in e}
    assert all("monitor_stop" in r["reason"] or "stop" in r["reason"] for r in released)
    assert first.is_running() and second.is_running(), "stopping the Monitor left a process frozen"
    # Releasing is idempotent: stopping again asks for nothing.
    monitor_app.stop_monitoring(None)
    assert len(rig.stub.of("/response/resume")) == 2


def test_a_stop_that_comes_while_a_suspend_is_in_flight_still_releases_it(rig):
    victim = rig.child()
    path = rig.write("inflight_stop.docx", victim)
    rig.stub.suspend_delay = 0.4
    event = {"incident_id": "inc_inflight", "file_path": str(path)}
    written = rig.written_at[path]
    answer = monitor_app.attributor.resolve(str(path), observed_at=written + 0.01, read_at=written + 0.02,
                                            horizon_from=time.perf_counter())
    rig.policy.on_first_answer(monitor_app.attributor, event, answer, str(path), (str(rig.watch),),
                               parked=True, incident_id="inc_inflight", background=True)
    released = rig.policy.release_all("monitor_stop")  # while the request is still on its way
    assert released["released"] == 1, released
    assert victim.is_running(), "the stop missed a suspend that was still in flight"
    assert len(rig.stub.of("/response/resume")) == 1


def test_the_lifespan_shutdown_releases_every_lease_it_holds(rig):
    from fastapi.testclient import TestClient

    victim = rig.child()
    rig.notify(rig.write("shutdown.docx", victim))
    assert victim.is_frozen()
    with TestClient(monitor_app.app):
        pass  # leaving the block runs the shutdown handlers
    assert len(rig.stub.of("/response/resume")) == 1
    assert victim.is_running()


def test_after_shutdown_nothing_new_is_suspended(rig, suspend_policy):
    victim = rig.child()
    rig.policy.shutdown()
    rig.notify(rig.write("after.docx", victim))
    assert rig.stub.of("/response/suspend") == []


def test_a_question_closing_after_the_stop_still_kills_the_certain_writer(rig):
    """Stopping released the lease; the kill the horizon authorises is the ordinary one."""
    victim = rig.child()
    event = rig.notify(rig.write("late_kill.docx", victim))
    monitor_app.stop_monitoring(None)
    assert victim.is_running()
    rig.close_everything()
    (terminate,) = rig.stub.of("/response/terminate")
    assert terminate["process_id"] == victim.pid
    assert "lease_id" not in terminate or terminate["lease_id"] is None
    assert event["suspension"]["lease_id"]


# =============================================================== the switch: today's behaviour


def run_sole_writer(rig):
    victim = rig.child()
    event = rig.notify(rig.write("switch.docx", victim))
    rig.close_everything()
    return victim, event


@pytest.mark.parametrize("value", ["0", "false", "off", "no"])
def test_switched_off_the_monitor_behaves_exactly_as_before(rig, monkeypatch, value):
    monkeypatch.setenv("MONITOR_SUSPEND_FIRST", value)
    victim, event = run_sole_writer(rig)

    assert rig.stub.of("/response/suspend") == [] and rig.stub.of("/response/resume") == []
    (terminate,) = rig.stub.of("/response/terminate")
    # Today's payload, key for key.
    assert set(terminate) == {"process_id", "incident_id", "reason", "force",
                              "attribution_confidence", "attribution_source"}
    assert "suspension" not in event
    (block,) = rig.stub.blocks("attribution_escalation")
    assert "lease_id" not in block and "suspension" not in block
    assert block["result"] == "terminated"
    assert not victim.alive()


def test_the_switch_defaults_to_on(suspend_policy, monkeypatch):
    monkeypatch.delenv("MONITOR_SUSPEND_FIRST", raising=False)
    assert suspend_policy.enabled() is True
    monkeypatch.setenv("MONITOR_SUSPEND_FIRST", "1")
    assert suspend_policy.enabled() is True
    monkeypatch.setenv("MONITOR_SUSPEND_FIRST", "0")
    assert suspend_policy.enabled() is False


def test_switching_off_after_a_suspend_still_resumes_what_is_held(rig, monkeypatch):
    victim, other = rig.child(), rig.child()
    path = rig.write("flip.docx", victim)
    rig.notify(path)
    monkeypatch.setenv("MONITOR_SUSPEND_FIRST", "0")
    rig.late_record(path, other)
    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0)
    assert victim.is_running()


# ======================================== Response unreachable or refusing: nothing else changes


def test_response_unreachable_changes_nothing_about_detection_or_the_kill(rig):
    rig.stub.suspend_mode = "unreachable"
    victim = rig.child()
    started = time.perf_counter()
    event = rig.notify(rig.write("down.docx", victim))
    assert time.perf_counter() - started < 3.0, "an unreachable Response must not stall detection"

    assert event["suspicious"] is True and event["attribution_pending"] is True
    assert event["suspension"]["outcome"] == "unreachable"
    assert victim.is_running()
    rig.close_everything()

    (terminate,) = rig.stub.of("/response/terminate")
    assert terminate["process_id"] == victim.pid
    assert "lease_id" not in terminate or terminate["lease_id"] is None
    assert not victim.alive()
    assert len(rig.stub.blocks("file_event")) == 1
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["result"] == "terminated"
    assert rig.stub.of("/response/resume") == [], "nothing was suspended, so nothing is resumed"


@pytest.mark.parametrize("code", ["PID_REUSED", "SYSTEM_PROCESS", "PID_NAMESPACE_ISOLATED", "MONITOR_OR_ANCESTOR",
                                  "MONITOR_PID_INVALID", "SHUTTING_DOWN", "LEASE_STATE_UNCERTAIN"])
def test_a_409_means_do_nothing_else_and_carry_on(rig, code):
    rig.stub.suspend_mode = f"refuse:{code}"
    victim = rig.child()
    event = rig.notify(rig.write(f"refused_{code}.docx", victim))
    assert event["suspension"]["outcome"] == "refused"
    assert event["suspension"]["code"] == code
    assert victim.is_running()
    rig.close_everything()
    (terminate,) = rig.stub.of("/response/terminate")  # the ordinary kill, unaffected
    assert terminate["process_id"] == victim.pid
    assert rig.stub.of("/response/resume") == []


def test_a_refusal_that_is_not_about_one_process_backs_off(rig):
    """Docker: Response cannot suspend a host PID, whatever the PID. Do not ask again per file."""
    rig.stub.suspend_mode = "refuse:PID_NAMESPACE_ISOLATED"
    victim, other = rig.child(), rig.child()
    rig.notify(rig.write("one.docx", victim))
    rig.notify(rig.write("two.docx", other))
    assert len(rig.stub.of("/response/suspend")) == 1


def test_a_lease_someone_else_holds_is_not_resumed_by_the_monitor(rig):
    """Response says already_held: the Monitor did not freeze it and must not unfreeze it."""
    victim, other = rig.child(), rig.child()
    pid = victim.pid
    rig.stub.dispatch("/response/suspend", {
        "process_id": pid, "incident_id": "operator", "lease_seconds": 30.0, "reason": "operator"})
    path = rig.write("held.docx", victim)
    event = rig.notify(path)
    assert event["suspension"]["already_held"] is True
    rig.late_record(path, other)
    rig.close_everything()
    assert rig.stub.of("/response/resume") == []
    assert rig.stub.of("/response/terminate") == []


# ---- a reply that never arrives is not a refusal: the process may be frozen under a lease unknown to us


def test_a_lost_reply_to_the_suspend_is_undone_by_pid_when_the_kill_gate_is_not_met(rig):
    """The cold first suspend against the real Response service took longer than a short timeout,
    and was carried out. The Monitor must not conclude nothing happened."""
    rig.stub.suspend_mode = "lost_reply"
    victim, other = rig.child(), rig.child()
    path = rig.write("lost.docx", victim)
    event = rig.notify(path)
    assert event["suspension"]["outcome"] == "uncertain"
    assert event["suspension"]["lease_id"] is None
    assert victim.is_frozen(), "the stub carried it out"

    rig.late_record(path, other)  # the question closes early: a second writer
    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0), "never resumed"
    (resume,) = rig.stub.of("/response/resume")
    assert resume["process_id"] == victim.pid and "lease_id" not in resume, "undone by PID: no lease id is known"
    assert victim.is_running()
    rig.close_everything()
    assert_spared(rig, victim, other, suspended=True)
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["suspension"]["outcome"] == "resumed"


def test_a_lost_reply_does_not_stop_the_kill_which_names_no_lease(rig):
    rig.stub.suspend_mode = "lost_reply"
    victim = rig.child()
    event = rig.notify(rig.write("lost_kill.docx", victim))
    assert event["suspension"]["outcome"] == "uncertain"
    rig.close_everything()
    (terminate,) = rig.stub.of("/response/terminate")
    assert terminate["process_id"] == victim.pid
    assert "lease_id" not in terminate, "no lease id was ever received"
    assert not victim.alive()
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["result"] == "terminated" and block["suspension"]["outcome"] == "terminated"


def test_monitor_stop_releases_a_lease_whose_reply_was_lost_by_pid(rig):
    rig.stub.suspend_mode = "lost_reply"
    victim = rig.child()
    rig.notify(rig.write("lost_stop.docx", victim))
    assert victim.is_frozen()
    monitor_app.stop_monitoring(None)
    (released,) = rig.stub.of("/response/resume")
    assert released["process_id"] == victim.pid
    assert victim.is_running()


def test_a_connection_that_never_opened_is_unreachable_not_uncertain(rig):
    """Nothing was sent, so there is nothing to undo: no resume is ever asked for."""
    rig.stub.suspend_mode = "unreachable"
    victim = rig.child()
    event = rig.notify(rig.write("never_sent.docx", victim))
    assert event["suspension"]["outcome"] == "unreachable"
    rig.close_everything()
    assert rig.stub.of("/response/resume") == []


# =============================================================== on_close, directly


def test_a_closing_answer_naming_a_different_process_resumes_and_does_not_kill_the_frozen_one(rig, suspend_policy):
    victim = rig.child()
    event = rig.notify(rig.write("swap.docx", victim))
    question = attribution.Question(key=event["incident_id"], path=event["file_path"], also=(), observed_at=1.0,
                                    read_at=1.0, settle_at=2.0, first=attribution.Attribution(
                                        pid=victim.pid, image=victim.image, confidence=attribution.PROBABLE,
                                        reason="x"))
    elsewhere = attribution.Attribution(pid=victim.pid + 1, image="x", confidence=attribution.CERTAIN,
                                        reason="a different writer", candidates=(victim.pid + 1,))
    lease = suspend_policy.on_close(question, elsewhere)
    assert lease["action"] == "resume" and lease["outcome"] == "resumed"
    assert victim.is_running()


def test_on_close_for_a_question_that_holds_no_lease_does_nothing(suspend_policy, rig):
    question = attribution.Question(key="inc_unknown", path="x", also=(), observed_at=1.0, read_at=1.0,
                                    settle_at=2.0, first=attribution.Attribution(
                                        pid=1, image=None, confidence=attribution.UNKNOWN, reason="x"))
    answer = attribution.Attribution(pid=1, image=None, confidence=attribution.CERTAIN, reason="x",
                                     candidates=(1,))
    assert suspend_policy.on_close(question, answer) is None
    assert rig.stub.requests == []
