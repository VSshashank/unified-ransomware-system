"""The kill pool is the default (16 workers), and it is safe.

Until now `MONITOR_KILL_WORKERS` defaulted to 1: kills for different PIDs went
out one at a time, so with 20 different writers the 20th kill waited behind 19
others (20 x 300 ms on the VM). The pool was built in defect 22 (`_KillLanes`,
`_Escalator`) but left off. These tests hold the pool to what makes it safe to
leave on:

(a) 20 different PIDs, a Response that takes ~300 ms per terminate: the last
    kill is requested within about a second of the horizon, not after 20 x
    300 ms. Runs at the default worker count, so it is skipped when
    MONITOR_KILL_WORKERS is set in the environment (that is the "old behaviour
    is still selectable" run).
(b) the same PID queued twice is killed once; the second question closes as
    `terminated_earlier` and is never sent to Response, with 16 workers.
(c) a pool worker that raises is logged and survives: the pool stays at full
    size and every question is still closed.
(d) start -> stop -> start leaks no thread, through the real endpoints and
    through the sentinel that stops the escalation threads.

Durations are `time.perf_counter`; the Response stub and ledger are the ones
from test_escalation_kill_latency_under_load (no real process is killed).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as monitor_app  # noqa: E402
import pipeline  # noqa: E402
from test_escalation_kill_latency_under_load import (  # noqa: E402,F401  (rig is a fixture)
    ENC,
    Downstream,
    _closed,
    _escalation_threads,
    _join,
    _wait_for,
    rig,
)

POOL = 16
THREADS = POOL + 2  # the kill workers, the intake thread, the ledger writer

env_override = pytest.mark.skipif(
    "MONITOR_KILL_WORKERS" in os.environ,
    reason="MONITOR_KILL_WORKERS is set: this test is about the default",
)


def _kill_workers(exclude: set) -> list[threading.Thread]:
    return [t for t in _escalation_threads(exclude) if t.name.startswith("monitor-escalation-kill-")]


@env_override
def test_the_default_is_sixteen_kill_workers():
    assert monitor_app.KILL_WORKERS == POOL


@env_override
def test_a_burst_of_twenty_different_pids_is_not_killed_one_at_a_time(rig):
    """(a) 20 writers, 300 ms per terminate, all due at the same moment. One at a
    time the last request goes out 19 x 300 ms = 5.7 s after the first; with the
    pool it is 2 rounds, ~0.3 s. Asserted on a monotonic clock with margin."""
    down = Downstream(rig.host, terminate_s=0.30)
    rig.start(down)  # the default worker count
    now = time.time()
    pids = [6100 + i for i in range(20)]
    items = []
    for i, pid in enumerate(pids):
        rig.host.spawn(pid, ENC, now - 100)
        items.append(_closed(pid, ENC, f"w{pid}.docx", now - 3))

    horizon = time.perf_counter()
    for q, a, _ in items:
        monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 30.0)

    sent = sorted(s for pid in pids for (_, s, _) in down.terminates(pid))
    assert len(sent) == 20, "a PID was not killed, or was killed twice"
    last = sent[-1] - horizon
    print(f"last of 20 terminates went out {last:.3f}s after the horizon "
          f"(first {sent[0] - horizon:.3f}s); 20 x 300 ms serial would be 6 s")
    assert last <= 1.0, f"the 20th kill went out {last:.2f}s after the horizon"
    assert down.overlaps == []
    assert all(rig.host.probe(pid) is None for pid in pids)
    assert rig.stop() == []


def test_the_same_pid_queued_twice_is_killed_once(rig):
    """(b) Two closed questions name the same PID at once, 16 workers. Only the
    first reaches Response; the second sees its result and closes as
    `terminated_earlier` (and so does a third, and one for another PID is not
    held up by them)."""
    down = Downstream(rig.host, terminate_s=0.30)
    rig.start(down, workers=POOL)
    now = time.time()
    rig.host.spawn(6200, ENC, now - 100)
    rig.host.spawn(6201, ENC, now - 100)
    same = [_closed(6200, ENC, f"d{i}.docx", now - 3 + i * 0.01) for i in range(3)]
    other = _closed(6201, ENC, "o.docx", now - 3)

    for q, a, _ in [*same, other]:
        monitor_app._on_question_closed(q, a, "verified")
    assert _join(monitor_app._escalations, 30.0)
    assert _join(monitor_app._work, 30.0)

    assert len(down.terminates(6200)) == 1, "the same PID was sent to Response more than once"
    assert len(down.terminates(6201)) == 1
    assert down.overlaps == []
    results = [event["attribution_escalation"]["result"] for _, _, event in same]
    assert results == ["terminated", "terminated_earlier", "terminated_earlier"], results
    assert other[2]["attribution_escalation"]["result"] == "terminated"
    blocks = {b["incident_id"]: b["result"] for b in down.blocks()}
    assert blocks == {q.key: e["attribution_escalation"]["result"] for q, _, e in [*same, other]}
    assert rig.stop() == []


def test_a_worker_that_raises_is_logged_and_the_pool_stays_full(rig, monkeypatch, caplog):
    """(c) More poisoned questions than there are workers: if a raise killed its
    worker the pool would be empty after 16 and the rest would never be taken."""
    down = Downstream(rig.host, terminate_s=0.02)
    rig.start(down, workers=POOL)
    assert len(_kill_workers(rig.before)) == POOL

    real = monitor_app._escalation_act
    poisoned = set(range(6300, 6320))  # 20 > 16 workers

    def act(client, item):
        if int(item[1].pid) in poisoned:
            raise RuntimeError("worker defect (test)")
        return real(client, item)

    monkeypatch.setattr(monitor_app, "_escalation_act", act)
    now = time.time()
    good = list(range(6400, 6420))
    items = []
    for pid in [*poisoned, *good]:
        rig.host.spawn(pid, ENC, now - 100)
        items.append(_closed(pid, ENC, f"x{pid}.docx", now - 3))
    for q, a, _ in items:
        monitor_app._on_question_closed(q, a, "verified")

    closed = _join(monitor_app._escalations, 20.0)
    alive = len(_kill_workers(rig.before))
    assert alive == POOL, f"the pool shrank to {alive} workers"
    assert closed, "questions were left unclosed behind dead workers"
    assert all(rig.host.probe(pid) is None for pid in good), "a good PID was never killed"
    assert any("worker defect" in r.getMessage() or (r.exc_info and "worker defect" in str(r.exc_info[1]))
               for r in caplog.records), "the worker's exception was not logged"
    assert rig.stop() == []


def test_start_stop_start_leaks_no_threads(rig, monkeypatch, tmp_path):
    """(d) Through the real endpoints: /monitor/stop does not stop the escalation
    threads (a closing question still needs them), so a second start must reuse
    them, not add a second pool. Then the sentinel stops all of them with none
    left blocked, and the next start builds exactly one pool again."""
    monkeypatch.setenv("ATTRIBUTION_SOURCE", "off")
    monkeypatch.setattr(monitor_app, "KILL_WORKERS", POOL)
    down = Downstream(rig.host, terminate_s=0.02)
    monkeypatch.setattr(pipeline, "_post", down)
    rig.down = down
    rig.before = set(threading.enumerate())

    def start():
        response = monitor_app.start_monitoring(monitor_app.MonitorStartRequest(watch_path=str(tmp_path)))
        assert response.status_code == 200
        assert _wait_for(lambda: len(_escalation_threads(rig.before)) == THREADS, 10.0)

    def threads_now() -> int:
        return len(threading.enumerate())

    seen = []
    try:
        for _ in range(3):
            start()
            seen.append(len(_escalation_threads(rig.before)))
            monitor_app.stop_monitoring()
        assert seen == [THREADS] * 3, f"escalation threads across three starts: {seen}"
        baseline = threads_now()
        for _ in range(2):
            start()
            monitor_app.stop_monitoring()
        assert _wait_for(lambda: threads_now() <= baseline, 5.0), (
            f"threads grew over start/stop cycles: {baseline} -> {threads_now()}")

        assert rig.stop() == [], "threads still running after the sentinel"
        rig.stopped = False
        start()
        assert len(_escalation_threads(rig.before)) == THREADS
        monitor_app.stop_monitoring()
        assert rig.stop() == []
    finally:
        monitor_app.stop_monitoring()
