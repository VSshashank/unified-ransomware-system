"""R16 / defect 22: a kill must not wait behind another writer's escalations.

The VM test of 2026-10-05 (R16 in VM_TEST_REPORT_2026-10-05_dc089ff.md): 20
rapid writes by process A, then one write by a fresh process B. B's question
closed on time, but B's `/response/terminate` went out 0.9-8.7 s later,
behind 4-22 of A's escalations, sent one at a time 0.30-0.38 s apart. The
first of them killed A; every later one was refused ("PID ... does not
exist") after a full round trip. `test_escalation_bypasses_backlog.py` stubs
the Response call as instant, so it could not see this.

Here the Response stub behaves like the real one, measured on the VM: about
300 ms a call, and a refusal for a PID that is not running. The escalation
thread is fed directly - 22 of A's closed `certain` questions (2-4 per file,
the F6 shape) and then B's - so the test does not depend on how many
notifications the watcher produces per write. B's request must go out within
500 ms of B's question closing, which is the "horizon + 500 ms" of the brief
counted from the close.

The other tests pin what the fix must not do: skip a fresh PID because of
another PID's state, skip a PID that has been reused by a new process, or let
a stale answer about the killed process kill whatever holds its PID now.
"""

from __future__ import annotations

import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import CERTAIN, UNKNOWN, Attribution, Attributor, ProcessFacts, Question, WriteLog  # noqa: E402

BURSTER = 3030
FRESH = 4242
WRITER = r"C:\Temp\writer.exe"
LOCKER = r"C:\Temp\locker.exe"

# One /response/terminate round trip as the VM measured it (0.30-0.38 s), and
# one ledger write. Sleeps well under a second; timing is perf_counter.
TERMINATE_S = 0.30
LEDGER_S = 0.02
# The F6 shape: 2-4 questions per file, 8 files.
PER_FILE = (3, 2, 4, 2, 3, 2, 4, 2)
BUDGET_S = 0.5


class Host:
    """The processes that exist, as the Monitor's probe and Response see them."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.alive: dict[int, ProcessFacts] = {}

    def spawn(self, pid: int, image: str, created_at: float) -> None:
        with self.lock:
            self.alive[pid] = ProcessFacts(pid=pid, image=image, created_at=created_at)

    def kill(self, pid: int) -> ProcessFacts | None:
        with self.lock:
            return self.alive.pop(pid, None)

    def probe(self, pid: int) -> ProcessFacts | None:
        with self.lock:
            return self.alive.get(pid)


class RealisticDownstream:
    """Ledger and Response. Terminate takes ~300 ms and refuses a dead PID.

    A refusal is a 409 from the real service, which `pipeline._post` turns into
    None - so the stub returns None for it, as `_post` would.
    """

    def __init__(self, host: Host) -> None:
        self.host = host
        self.lock = threading.Lock()
        # (path, payload, sent_at, finished_at), perf_counter.
        self.calls: list[tuple[str, dict, float, float]] = []

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        sent = time.perf_counter()
        result: dict | None = {}
        if path == "/response/terminate":
            time.sleep(TERMINATE_S)
            killed = self.host.kill(payload["process_id"])
            result = None if killed is None else {
                "status": "terminated", "process_id": payload["process_id"], "process_name": "x.exe",
                "method": "sigterm", "incident_id": payload["incident_id"],
            }
        elif path == "/ledger/log":
            time.sleep(LEDGER_S)
            result = {"block_id": len(self.calls) + 1}
        with self.lock:
            self.calls.append((path, payload, sent, time.perf_counter()))
        return result

    def terminates(self, pid: int | None = None) -> list[tuple[dict, float]]:
        with self.lock:
            return [(payload, sent) for p, payload, sent, _ in self.calls
                    if p == "/response/terminate" and (pid is None or payload["process_id"] == pid)]

    def escalation_blocks(self) -> list[dict]:
        with self.lock:
            return [payload["event_data"] for p, payload, _, _ in self.calls
                    if p == "/ledger/log" and payload["event_type"] == "attribution_escalation"]


@pytest.fixture
def escalator(monkeypatch):
    host = Host()
    at = Attributor(log=WriteLog(), probe=host.probe)
    downstream = RealisticDownstream(host)
    monkeypatch.setattr(pipeline, "_post", downstream)
    monkeypatch.setattr(monitor_app, "attributor", at)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    if hasattr(pipeline, "TERMINATIONS"):
        pipeline.TERMINATIONS.clear()
    monitor_app._ensure_escalator()
    # The Monitor starts this thread with the watch (`_ensure_worker`), long
    # before a question can close, and its first act is to build an httpx
    # client - 200-380 ms on the VM. Let that finish before anything is timed:
    # one unattributed question, closed and written, then forgotten.
    warm_q, _, _ = _closed(FRESH, LOCKER, "warmup.docx", time.time() - 2.0)
    monitor_app._on_question_closed(warm_q, warm_q.first, "no_record")
    monitor_app._escalations.join()
    with downstream.lock:
        downstream.calls.clear()
    yield host, downstream
    monitor_app._escalations.join()
    monitor_app._work.join()
    if hasattr(pipeline, "TERMINATIONS"):
        pipeline.TERMINATIONS.clear()
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS.clear()


def _closed(pid: int, image: str, name: str, written_at: float) -> tuple[Question, Attribution, dict]:
    """A question that closed CERTAIN for `pid`, as `Attributor.final` hands it on."""
    event_id = "evt_" + uuid.uuid4().hex[:12]
    event = {"event_id": event_id, "file_path": rf"C:\watch\{name}", "incident_id": monitor_app.incident_id_for(event_id)}
    first = Attribution(pid=None, image=None, confidence=UNKNOWN, reason="no record yet",
                        source="fake-4663", pending=True)
    question = Question(key=event["incident_id"], path=event["file_path"], also=(),
                        observed_at=written_at + 0.01, read_at=written_at + 0.02,
                        settle_at=written_at + 1.57, first=first, context=event)
    answer = Attribution(pid=pid, image=image, confidence=CERTAIN, source="fake-4663",
                         reason=f"one writer; pid {pid} verified as the writer by image and start time",
                         written_at=written_at, delivered_at=written_at + 0.9)
    assert answer.kill_authorised
    return question, answer, event


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def test_a_fresh_writers_kill_is_not_queued_behind_a_dead_writers_escalations(escalator):
    host, downstream = escalator
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)
    host.spawn(FRESH, LOCKER, created_at=now - 30)

    # A's 8 files were written ~2 s ago, so their questions all close now.
    burst = []
    for index, copies in enumerate(PER_FILE):
        for _ in range(copies):
            burst.append(_closed(BURSTER, WRITER, f"burst_{index:02d}.docx", now - 2.0 + index * 0.01))
    fresh_q, fresh_a, fresh_event = _closed(FRESH, LOCKER, "board_minutes.docx", now - 1.6)

    for question, answer, _ in burst:
        monitor_app._on_question_closed(question, answer, "verified")
    closed_at = time.perf_counter()
    monitor_app._on_question_closed(fresh_q, fresh_a, "verified")

    assert _wait_for(lambda: downstream.terminates(FRESH), timeout=20.0), "B's kill was never asked for"
    (_, sent), = downstream.terminates(FRESH)
    elapsed = sent - closed_at
    a_requests = len(downstream.terminates(BURSTER))
    print(f"B's terminate went out {elapsed:.3f}s after its question closed, behind "
          f"{len(burst)} of A's escalations; A got {a_requests} terminate request(s)")
    assert elapsed <= BUDGET_S, (
        f"B's kill went out {elapsed:.2f}s after its question closed (budget {BUDGET_S:.2f}s); "
        f"A was sent {a_requests} terminate requests for {len(burst)} questions"
    )

    monitor_app._escalations.join()
    monitor_app._work.join()
    # A was killed once, and asked about once.
    assert a_requests == 1
    assert host.probe(BURSTER) is None and host.probe(FRESH) is None


def test_the_later_questions_about_a_killed_process_say_so_truthfully(escalator):
    host, downstream = escalator
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)

    closed = [_closed(BURSTER, WRITER, f"burst_{i:02d}.docx", now - 2.0 + i * 0.01) for i in range(4)]
    for question, answer, _ in closed:
        monitor_app._on_question_closed(question, answer, "verified")
    monitor_app._escalations.join()
    monitor_app._work.join()

    assert len(downstream.terminates(BURSTER)) == 1
    blocks = {b["incident_id"]: b for b in downstream.escalation_blocks()}
    first_incident = closed[0][0].key
    assert blocks[first_incident]["result"] == "terminated"
    for question, _, event in closed[1:]:
        block = blocks[question.key]
        # The answer was right and the process is dead: neither refused nor unreachable.
        assert block["result"] == "terminated_earlier", block["result"]
        assert block["action_requested"] == "terminate_process"
        assert block["termination"] is None and block["response_dispatched_at"] is None
        # C-16: CERTAIN, so it names the process; and it says which incident's kill it was.
        assert block["process_id"] == BURSTER and block["attribution_confidence"] == CERTAIN
        assert block["terminated_earlier"]["incident_id"] == first_incident
        assert event["attribution_escalation"]["result"] == "terminated_earlier"


def test_a_fresh_pid_is_never_skipped_because_another_pid_was_killed(escalator):
    host, downstream = escalator
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)
    host.spawn(FRESH, WRITER, created_at=now - 30)  # same image, different process

    for question, answer, _ in (_closed(BURSTER, WRITER, "a.docx", now - 2.0),
                                _closed(BURSTER, WRITER, "a2.docx", now - 1.9),
                                _closed(FRESH, WRITER, "b.docx", now - 1.8)):
        monitor_app._on_question_closed(question, answer, "verified")
    monitor_app._escalations.join()
    monitor_app._work.join()

    assert len(downstream.terminates(FRESH)) == 1
    assert host.probe(FRESH) is None


def test_a_reused_pid_is_still_killed_when_its_own_answer_is_certain(escalator):
    host, downstream = escalator
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)
    q, a, _ = _closed(BURSTER, WRITER, "a.docx", now - 2.0)
    monitor_app._on_question_closed(q, a, "verified")
    monitor_app._escalations.join()
    assert host.probe(BURSTER) is None

    # Windows hands the number to a new process with the same image, which
    # then writes - after the kill, so after the first process was gone.
    reborn = time.time() + 0.2
    host.spawn(BURSTER, WRITER, created_at=reborn)
    q2, a2, event2 = _closed(BURSTER, WRITER, "b.docx", reborn + 0.1)
    monitor_app._on_question_closed(q2, a2, "verified")
    monitor_app._escalations.join()
    monitor_app._work.join()

    assert len(downstream.terminates(BURSTER)) == 2
    assert host.probe(BURSTER) is None
    assert event2["attribution_escalation"]["result"] == "terminated"


def test_a_stale_answer_about_the_killed_process_does_not_kill_the_pids_new_owner(escalator):
    host, downstream = escalator
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)
    q1, a1, _ = _closed(BURSTER, WRITER, "a.docx", now - 2.0)
    monitor_app._on_question_closed(q1, a1, "verified")
    monitor_app._escalations.join()

    # The number is reused before A's second question - about a write A made
    # before it was killed - is dispatched.
    host.spawn(BURSTER, WRITER, created_at=time.time() + 0.2)
    q2, a2, event2 = _closed(BURSTER, WRITER, "a2.docx", now - 1.9)
    monitor_app._on_question_closed(q2, a2, "verified")
    monitor_app._escalations.join()
    monitor_app._work.join()

    assert len(downstream.terminates(BURSTER)) == 1, "the PID's new owner was killed for the old one's write"
    assert host.probe(BURSTER) is not None
    assert event2["attribution_escalation"]["result"] == "terminated_earlier"


def test_a_reused_pid_whose_new_owner_also_exited_is_not_called_terminated_earlier(escalator):
    host, downstream = escalator
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)
    q1, a1, _ = _closed(BURSTER, WRITER, "a.docx", now - 2.0)
    monitor_app._on_question_closed(q1, a1, "verified")
    monitor_app._escalations.join()

    # A new process got the number, wrote after the kill, and exited by itself
    # before its question closed: it was not this Monitor's kill, so the
    # request goes out as before and the refusal is what gets recorded.
    q2, a2, event2 = _closed(BURSTER, WRITER, "b.docx", time.time() + 0.3)
    monitor_app._on_question_closed(q2, a2, "verified")
    monitor_app._escalations.join()
    monitor_app._work.join()

    assert len(downstream.terminates(BURSTER)) == 2
    assert event2["attribution_escalation"]["result"] == "termination_refused_or_unreachable"


def test_direct_escalate_callers_are_unchanged(monkeypatch):
    """The safety-invariant tests call `pipeline.escalate` directly, off the
    escalation thread: there it asks Response every time, exactly as before."""
    host = Host()
    downstream = RealisticDownstream(host)
    monkeypatch.setattr(pipeline, "_post", downstream)
    now = time.time()
    host.spawn(BURSTER, WRITER, created_at=now - 60)
    results = []
    for name in ("a.docx", "b.docx"):
        q, a, event = _closed(BURSTER, WRITER, name, now - 2.0)
        results.append(pipeline.escalate(None, event, q, a, "verified")["result"])
    assert results == ["terminated", "termination_refused_or_unreachable"]
    assert len(downstream.terminates(BURSTER)) == 2
