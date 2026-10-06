"""Defect 22 review follow-up (R-RACE): a kill still waited under load.

Defect 22 bounded a fresh writer's kill to the attribution horizon plus a small
margin. The concurrency review showed four ways the escalation thread still
broke that bound (reviewer scripts s1_flood, s2_owed_starvation,
s3_response_hang, s7_kill_behind_ledger):

(c) a question with nothing queued behind it wrote its ledger block on the
    escalation thread, so a second PID's kill closing meanwhile waited for that
    write (0.70 s measured, up to DOWNSTREAM_TIMEOUT);
(d) blocks owed after a kill were written only when the queue was momentarily
    empty, so under a steady stream of kills none were written and the backlog
    grew with the run;
(b) a terminate that timed out or was unreachable was not remembered, so each
    of one process's questions paid the full timeout again, in front of a fresh
    PID's kill;
(a) kills for different PIDs went out strictly one at a time.

Each test builds an escalation thread of its own on a queue of its own (as
`test_f_the_escalation_client_is_built_with_the_worker...` does), with a
Response stub that takes a fixed time per call and refuses a PID that is not
running, as the real one does. No sleep is longer than 1 s; durations are
`time.perf_counter`; `time.time()` only anchors process start and write times.
"""

from __future__ import annotations

import queue
import random
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import CERTAIN, UNKNOWN, Attribution, Attributor, ProcessFacts, Question, WriteLog  # noqa: E402

ENC = r"C:\Temp\enc.exe"
FRESH_IMG = r"C:\Temp\fresh.exe"


class Host:
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


class Downstream:
    """Ledger and Response, standing in for `pipeline._post`.

    A terminate takes `terminate_s` and returns None for a PID that is not
    running (the real service's 409, as `_post` returns it). A PID in `hang`
    waits that many seconds and then returns None, as `_post` does when httpx
    times out. `hold_next_block(s)` holds the next `attribution_escalation`
    write for `s` seconds and sets `ledger_busy` while it is held.
    """

    def __init__(self, host: Host, terminate_s: float = 0.30, ledger_s: float = 0.002) -> None:
        self.host = host
        self.terminate_s = terminate_s
        self.ledger_s = ledger_s
        self.hang: dict[int, float] = {}
        self.lock = threading.Lock()
        self.calls: list[tuple[str, dict, float, float, object]] = []
        self.in_flight: dict[int, int] = {}
        self.overlaps: list[int] = []
        self._hold: float | None = None
        self.ledger_busy = threading.Event()

    def hold_next_block(self, seconds: float) -> None:
        assert seconds <= 1.0
        with self.lock:
            self._hold = seconds
        self.ledger_busy.clear()

    def reset(self) -> None:
        with self.lock:
            self.calls.clear()
            self.overlaps.clear()

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        sent = time.perf_counter()
        result: object = {}
        if path == "/response/terminate":
            pid = payload["process_id"]
            with self.lock:
                if self.in_flight.get(pid):
                    self.overlaps.append(pid)
                self.in_flight[pid] = self.in_flight.get(pid, 0) + 1
            try:
                if pid in self.hang:
                    threading.Event().wait(self.hang[pid])  # never set: a timeout
                    result = None
                else:
                    if self.terminate_s:
                        time.sleep(self.terminate_s)
                    killed = self.host.kill(pid)
                    result = None if killed is None else {
                        "status": "terminated", "process_id": pid, "incident_id": payload["incident_id"]}
            finally:
                with self.lock:
                    self.in_flight[pid] -= 1
        elif path == "/ledger/log":
            hold = None
            with self.lock:
                if payload["event_type"] == "attribution_escalation" and self._hold:
                    hold, self._hold = self._hold, None
            if hold:
                self.ledger_busy.set()
                threading.Event().wait(hold)
            elif self.ledger_s:
                time.sleep(self.ledger_s)
            with self.lock:
                result = {"block_id": len(self.calls) + 1}
        with self.lock:
            self.calls.append((path, payload, sent, time.perf_counter(), result))
        return result

    def terminates(self, pid: int | None = None) -> list[tuple[dict, float, float]]:
        with self.lock:
            return [(p, s, d) for path, p, s, d, _ in self.calls
                    if path == "/response/terminate" and (pid is None or p["process_id"] == pid)]

    def blocks(self) -> list[dict]:
        with self.lock:
            return [p["event_data"] for path, p, _, _, _ in self.calls
                    if path == "/ledger/log" and p["event_type"] == "attribution_escalation"]


def _closed(pid: int, image: str, name: str, written_at: float):
    """A question that closed CERTAIN for `pid`, as `Attributor.final` hands it on."""
    event_id = "evt_" + uuid.uuid4().hex[:12]
    event = {"event_id": event_id, "file_path": rf"C:\watch\{name}",
             "incident_id": monitor_app.incident_id_for(event_id)}
    first = Attribution(pid=None, image=None, confidence=UNKNOWN, reason="no record yet",
                        source="fake-4663", pending=True)
    question = Question(key=event["incident_id"], path=event["file_path"], also=(),
                        observed_at=written_at + 0.01, read_at=written_at + 0.02,
                        settle_at=written_at + 1.57, first=first, context=event)
    answer = Attribution(pid=pid, image=image, confidence=CERTAIN, source="fake-4663",
                         reason=f"one writer; pid {pid} verified", written_at=written_at,
                         delivered_at=written_at + 0.9)
    assert answer.kill_authorised
    return question, answer, event


def _unattributed(name: str):
    q, _, event = _closed(1, ENC, name, time.time() - 2.0)
    return q, q.first, event


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return bool(predicate())


def _join(q: queue.Queue, timeout: float) -> bool:
    done = threading.Event()
    threading.Thread(target=lambda: (q.join(), done.set()), daemon=True).start()
    return _wait_for(done.is_set, timeout)


def _escalation_threads(exclude: set) -> list[threading.Thread]:
    return [t for t in threading.enumerate()
            if t not in exclude and t.name.startswith("monitor-escalation") and t.is_alive()]


@pytest.fixture
def rig(monkeypatch):
    host = Host()
    state = SimpleNamespace(host=host, down=None, before=set(), stopped=False)
    monkeypatch.setattr(monitor_app, "_escalations", queue.Queue())
    monkeypatch.setattr(monitor_app, "_escalator", None)
    monkeypatch.setattr(monitor_app, "attributor", Attributor(log=WriteLog(), probe=host.probe))
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    registries = [r for r in (getattr(pipeline, "TERMINATIONS", None), getattr(pipeline, "UNCONFIRMED", None)) if r]
    for r in registries:
        r.clear()

    def start(down: Downstream, workers: int | None = None) -> None:
        monkeypatch.setattr(pipeline, "_post", down)
        if workers is not None:
            monkeypatch.setattr(monitor_app, "KILL_WORKERS", workers, raising=False)
        state.down = down
        state.before = set(threading.enumerate())
        monitor_app._ensure_worker()  # what /monitor/start calls
        # The thread builds its HTTP client first; let that finish before timing.
        q, a, _ = _unattributed("warmup.docx")
        monitor_app._on_question_closed(q, a, "no_record")
        assert _join(monitor_app._escalations, 15.0)
        down.reset()

    def stop() -> list[threading.Thread]:
        """The sentinel the Monitor's tests stop the thread with; then what is still running."""
        escalator = monitor_app._escalator
        monitor_app._escalations.put(None)
        if escalator is not None:
            escalator.join(timeout=15.0)
        _wait_for(lambda: not _escalation_threads(state.before), 5.0)
        state.stopped = True
        return _escalation_threads(state.before)

    state.start, state.stop = start, stop
    try:
        yield state
    finally:
        if not state.stopped and state.down is not None:
            stop()
        _join(monitor_app._work, 15.0)
        for r in registries:
            r.clear()
        with monitor_app._ANCHORS_LOCK:
            monitor_app._ANCHORS.clear()


# --------------------------------------------- (c) a kill behind a lone ledger write


def test_c_a_kill_does_not_wait_behind_a_lone_questions_ledger_write(rig):
    """S7: A's question closes alone and its block write is held (a slow ledger);
    B's question closes meanwhile. B's kill must not wait for A's block."""
    down = Downstream(rig.host, terminate_s=0.05)
    rig.start(down)
    now = time.time()
    rig.host.spawn(8900, ENC, now - 100)
    rig.host.spawn(8904, FRESH_IMG, now - 100)
    down.hold_next_block(0.8)
    qa, aa, _ = _closed(8900, ENC, "a.docx", now - 3)
    qb, ab, _ = _closed(8904, FRESH_IMG, "b.docx", now - 3)

    monitor_app._on_question_closed(qa, aa, "verified")
    assert down.ledger_busy.wait(5.0), "A's block write never started"
    closed_at = time.perf_counter()
    monitor_app._on_question_closed(qb, ab, "verified")
    assert _wait_for(lambda: down.terminates(8904), 5.0), "B's kill was never asked for"
    (_, sent, _), = down.terminates(8904)
    elapsed = sent - closed_at
    print(f"B's terminate went out {elapsed:.3f}s after B closed, during A's 0.8 s block write")
    assert elapsed <= 0.25, f"B's kill waited {elapsed:.2f}s behind A's ledger write"

    assert _join(monitor_app._escalations, 10.0)
    assert sorted(b["process_id"] for b in down.blocks()) == [8900, 8904]


# ------------------------------------------- (d) owed blocks under a stream of kills


def test_d_owed_blocks_keep_being_written_under_a_steady_stream_of_kills(rig):
    """S2: a fresh PID's question every 0.25 s, each kill 0.30 s, so the queue is
    never empty. Blocks owed (kills answered, block not yet written) must stay
    bounded while the stream runs, not grow with it."""
    down = Downstream(rig.host, terminate_s=0.30)
    rig.start(down)
    now = time.time()
    samples: list[tuple[float, int, int]] = []
    streaming = threading.Event()
    streaming.set()

    def sampler():
        t0 = time.perf_counter()
        while streaming.is_set():
            samples.append((time.perf_counter() - t0, len(down.terminates()), len(down.blocks())))
            time.sleep(0.05)

    s = threading.Thread(target=sampler, daemon=True)
    s.start()
    for i in range(12):
        pid = 9000 + i
        rig.host.spawn(pid, ENC, now - 50)
        q, a, _ = _closed(pid, ENC, f"s{i}.docx", time.time() - 2)
        monitor_app._on_question_closed(q, a, "verified")
        time.sleep(0.25)
    streaming.clear()
    s.join(timeout=1.0)

    owed = [k - b for _, k, b in samples]
    kills_in_stream, blocks_in_stream = samples[-1][1], samples[-1][2]
    print(f"during the stream: {kills_in_stream} kills answered, {blocks_in_stream} blocks written, "
          f"most owed at once {max(owed)}")
    assert max(owed) <= 2, f"blocks owed grew to {max(owed)} while kills kept coming: {samples[::4]}"
    assert _join(monitor_app._escalations, 20.0)
    assert len(down.blocks()) == 12


# ---------------------------------------------- (b) a terminate that timed out


def test_b_a_timed_out_terminate_is_not_paid_again_by_each_later_question(rig):
    """S3(b): H's terminate times out (0.5 s here, DOWNSTREAM_TIMEOUT 3 s live).
    H has 10 questions, then a fresh B closes. H's later questions must not each
    pay a timeout, B must not wait behind them, and nothing unconfirmed is
    recorded as done."""
    H, B = 8101, 8200
    timeout = 0.5
    down = Downstream(rig.host, terminate_s=0.05)
    down.hang[H] = timeout
    rig.start(down)
    now = time.time()
    rig.host.spawn(H, ENC, now - 100)
    rig.host.spawn(B, FRESH_IMG, now - 100)
    h_items = [_closed(H, ENC, f"h{i}.docx", now - 3 + i * 0.01) for i in range(10)]
    bq, ba, _ = _closed(B, FRESH_IMG, "b.docx", now - 2)

    for q, a, _ in h_items:
        monitor_app._on_question_closed(q, a, "verified")
    closed_at = time.perf_counter()
    monitor_app._on_question_closed(bq, ba, "verified")
    assert _wait_for(lambda: down.terminates(B), 15.0), "B's kill was never asked for"
    b_sent = down.terminates(B)[0][1] - closed_at
    assert _join(monitor_app._escalations, 20.0)
    attempts = len(down.terminates(H))
    print(f"H: {attempts} terminate attempts for 10 questions; B's kill went out {b_sent:.2f}s after B closed")

    assert attempts <= 2, f"each of H's questions paid the timeout again: {attempts} attempts"
    assert b_sent <= timeout + 0.35, f"B waited {b_sent:.2f}s behind H's timed-out terminates"

    blocks = {b["incident_id"]: b for b in down.blocks()}
    assert len(blocks) == 11, "an escalation was lost"
    results = [blocks[q.key]["result"] for q, _, _ in h_items]
    # Never recorded as done: no kill of H was confirmed.
    assert not {"terminated", "terminated_earlier"} & set(results), results
    assert pipeline.TERMINATIONS.find(H) is None
    assert rig.host.probe(H) is not None
    asked = [r for r in results if r == "termination_refused_or_unreachable"]
    skipped = [r for r in results if r != "termination_refused_or_unreachable"]
    assert len(asked) == attempts
    assert set(skipped) <= {"termination_unconfirmed_earlier"}, results
    for q, _, event in h_items:
        block = blocks[q.key]
        if block["result"] == "termination_unconfirmed_earlier":
            assert block["termination"] is None and block["response_dispatched_at"] is None
            assert block["action_requested"] == "terminate_process" and block["process_id"] == H
            earlier = block["termination_unconfirmed_earlier"]
            assert earlier["attempts"] == attempts
            assert earlier["incident_id"] in {qq.key for qq, _, _ in h_items}
            assert event["attribution_escalation"]["result"] == "termination_unconfirmed_earlier"
    assert blocks[bq.key]["result"] == "terminated"


def test_b_a_write_made_after_the_unconfirmed_attempts_is_asked_for_again(rig):
    """The skip covers only writes made before the unconfirmed attempts: a later
    write by the same live process is new evidence, and its kill is asked for."""
    H = 8102
    down = Downstream(rig.host, terminate_s=0.05)
    down.hang[H] = 0.2
    rig.start(down)
    now = time.time()
    rig.host.spawn(H, ENC, now - 100)
    for i in range(4):
        q, a, _ = _closed(H, ENC, f"h{i}.docx", now - 3 + i * 0.01)
        monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 10.0)
    before = len(down.terminates(H))

    q, a, event = _closed(H, ENC, "later.docx", time.time() + 0.05)
    monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 10.0)
    assert len(down.terminates(H)) == before + 1
    assert event["attribution_escalation"]["result"] == "termination_refused_or_unreachable"


def test_b_a_refused_or_lost_terminate_for_another_process_on_the_pid_does_not_cover(rig):
    """An unconfirmed attempt against one process says nothing about a later
    process that holds the same PID number and wrote after it started."""
    H = 8103
    down = Downstream(rig.host, terminate_s=0.05)
    down.hang[H] = 0.1
    rig.start(down)
    now = time.time()
    rig.host.spawn(H, ENC, now - 100)
    for i in range(3):
        q, a, _ = _closed(H, ENC, f"h{i}.docx", now - 3 + i * 0.01)
        monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 10.0)
    first_attempts = len(down.terminates(H))
    del down.hang[H]
    # H is gone; a new process gets the number and writes.
    rig.host.kill(H)
    reborn = time.time() + 0.1
    rig.host.spawn(H, ENC, reborn)
    q, a, event = _closed(H, ENC, "new_owner.docx", reborn + 0.1)
    monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 10.0)
    assert len(down.terminates(H)) == first_attempts + 1
    assert event["attribution_escalation"]["result"] == "terminated"


# ------------------------------------------- (a) the bound, with a pool of kill workers


def test_with_a_kill_pool_a_fresh_pid_is_asked_for_within_500ms_behind_twenty_pids(rig):
    """The acceptance bound: a fresh PID's terminate is requested within 500 ms
    of its question closing (horizon + 500 ms from its read) with 20 other PIDs'
    escalations queued (10 questions each, the S1 shape, half of them waiting
    for their incident's own blocks), a Response that takes 300 ms a call, and a
    ledger write in progress.

    Run with MONITOR_KILL_WORKERS=16: 20 kills of 300 ms ahead of the fresh one
    need at least 11 requests in flight to meet 500 ms. One process never has
    two terminates in flight, no escalation is lost, and stop leaves no thread.
    """
    down = Downstream(rig.host, terminate_s=0.30)
    rig.start(down, workers=16)
    now = time.time()
    pids = [7000 + i for i in range(20)]
    fresh = 7999
    for i, pid in enumerate(pids):
        rig.host.spawn(pid, rf"C:\Temp\enc{i % 3}.exe", now - 100)
    rig.host.spawn(fresh, FRESH_IMG, now - 100)
    items = [_closed(pid, rf"C:\Temp\enc{i % 3}.exe", f"f_{pid}_{j}.docx", now - 3 + j * 0.01)
             for i, pid in enumerate(pids) for j in range(10)]
    random.Random(22).shuffle(items)
    for k, (q, _, event) in enumerate(items):
        if k % 2:
            with monitor_app._ANCHORS_LOCK:
                monitor_app._ANCHORS[event["event_id"]] = {"question": q, "in_chain": False}

    # A ledger write in progress: a lone unattributed question's block, held.
    down.hold_next_block(0.8)
    lq, la, _ = _unattributed("lone.docx")
    monitor_app._on_question_closed(lq, la, "no_record")
    assert down.ledger_busy.wait(5.0)
    for q, a, _ in items:
        monitor_app._on_question_closed(q, a, "verified")
    fq, fa, _ = _closed(fresh, FRESH_IMG, "board_minutes.docx", now - 1.6)
    closed_at = time.perf_counter()
    monitor_app._on_question_closed(fq, fa, "verified")

    assert _wait_for(lambda: down.terminates(fresh), 20.0), "the fresh PID's kill was never asked for"
    (_, sent, _), = down.terminates(fresh)
    elapsed = sent - closed_at
    print(f"fresh PID's terminate went out {elapsed:.3f}s after its question closed, "
          f"behind {len(items)} questions over {len(pids)} PIDs")
    assert elapsed <= 0.5, f"fresh PID's kill went out {elapsed:.2f}s after its question closed"

    assert _join(monitor_app._escalations, 30.0)
    assert _join(monitor_app._work, 30.0)
    assert down.overlaps == [], f"overlapping terminates for {down.overlaps}"
    for pid in pids + [fresh]:
        assert len(down.terminates(pid)) == 1, pid
        assert rig.host.probe(pid) is None, f"{pid} left alive"
    keys = [b["incident_id"] for b in down.blocks()]
    expected = {q.key for q, _, _ in items} | {fq.key, lq.key}
    assert sorted(keys) == sorted(expected), "an escalation block is missing or written twice"
    assert rig.stop() == [], "threads still running after stop"


# ------------------------------------------------- guards: ordering and a clean stop


def test_an_escalation_block_still_waits_for_its_incidents_own_blocks(rig, monkeypatch):
    """The kill goes out at once; the block waits behind the incident's own
    `response_action` on `_work`, and the question is done once it is queued."""
    down = Downstream(rig.host, terminate_s=0.05)
    rig.start(down)
    held = queue.Queue()  # a `_work` nobody drains: the pipeline is behind
    monkeypatch.setattr(monitor_app, "_work", held)
    now = time.time()
    rig.host.spawn(8300, ENC, now - 100)
    q, a, event = _closed(8300, ENC, "x.docx", now - 3)
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS[event["event_id"]] = {"question": q, "in_chain": False}
    monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 10.0)
    assert len(down.terminates(8300)) == 1
    assert down.blocks() == []
    kind, *payload = held.get_nowait()
    assert kind == "escalation" and payload[1] is q
    monitor_app._run_escalation_record(None, *payload)
    (block,) = down.blocks()
    assert block["incident_id"] == q.key and block["result"] == "terminated"


def test_stop_flushes_every_owed_block_and_leaves_no_thread(rig):
    down = Downstream(rig.host, terminate_s=0.05, ledger_s=0.05)
    rig.start(down)
    now = time.time()
    items = []
    for i in range(6):
        rig.host.spawn(8400 + i, ENC, now - 100)
        items.append(_closed(8400 + i, ENC, f"st{i}.docx", now - 3))
    for q, a, _ in items:
        monitor_app._on_question_closed(q, a, "verified")
    left = rig.stop()
    assert left == [], f"still running after stop: {[t.name for t in left]}"
    assert sorted(b["incident_id"] for b in down.blocks()) == sorted(q.key for q, _, _ in items)
    assert all(rig.host.probe(8400 + i) is None for i in range(6))
