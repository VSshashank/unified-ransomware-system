"""Defect 26, review follow-ups (R-SAFE and R-RACE on the merged branch).

1. Response stamped `gate: "suspend_authorised"` on every suspend block. That
   gate was never built (package E2 was dropped), so the string claimed an
   evaluation nobody made: an operator suspend asserting `certain` looked
   gated. Now the caller's gate claim is recorded as the caller's, with
   `gate_verified: false`, and a request without one says so.
2. `URDS_MONITOR_PID="<a> <b>"` silently protected nothing. Spaces, commas and
   semicolons all separate; an unparsable value refuses every suspend.
3. Lease expiry waited on ledger I/O (the reaper wrote each ended lease's block
   before its next pass) and on a watchdog respawn (done under the table
   lock), and a suspend after shutdown was granted and never reaped.
4. `NaN` / `Infinity` `lease_seconds` was a 500, not a 400.
5. A false "not running" from psutil on a held handle ended the lease without
   resuming and suspended again: frozen, with no lease.

Real children (conftest.py) where a process is involved; injected clocks and
stub watchdogs/ledgers for the timing. No sleep is longer than 0.05 s.
"""

from __future__ import annotations

import threading
import time

import psutil
import pytest
from fastapi.testclient import TestClient

import actions
import app as response_app
import lease_watchdog
import leases
from leases import LeaseError, LeaseTable


class Clock:
    def __init__(self) -> None:
        self.now = 70_000.0
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.now += seconds


class Fake:
    """Nests like NtSuspendProcess."""

    def __init__(self, pid: int, created: float | None = 1_700_000_000.0) -> None:
        self.pid = pid
        self.count = 0
        self.created = created
        self.alive = True

    def suspend(self) -> None:
        self.count += 1

    def resume(self) -> bool:
        if not self.alive:
            return False
        self.count = max(0, self.count - 1)
        return True

    def is_running(self) -> bool:
        return self.alive

    def exe(self) -> str:
        return "C:\\work\\w.exe"

    def create_time(self) -> float:
        if self.created is None:
            raise psutil.AccessDenied(self.pid)
        return self.created


def take(table, handle, seconds=1.0, vet=None):
    return table.acquire(handle.pid, incident_id="inc", lease_seconds=seconds, reason="r",
                         vet=vet or (lambda: handle), suspend=lambda h: h.suspend())


def wait_until(predicate, within: float) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def blocks(monkeypatch):
    recorded: list[tuple[str, dict]] = []
    monkeypatch.setattr(response_app, "log_action",
                        lambda t, d: recorded.append((t, d)) or {"block_id": len(recorded)})
    monkeypatch.delenv("URDS_MONITOR_PID", raising=False)
    monkeypatch.delenv("RESPONSE_PID_NAMESPACE", raising=False)
    return recorded


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def table(monkeypatch, clock, blocks):
    t = response_app.build_lease_table(watchdog=None, clock=clock)
    monkeypatch.setattr(response_app, "LEASES", t)
    return t


@pytest.fixture
def client(table):
    with TestClient(response_app.app) as c:
        yield c


def body_for(child, **over):
    b = {"process_id": child.pid, "incident_id": "inc-rv", "lease_seconds": 2.0, "reason": "r",
         "attribution_confidence": "certain", "attribution_source": "operator-typed",
         "attribution_reason": "because I said so", "image": child.image, "started_at": child.started_at}
    b.update(over)
    return b


def of_type(blocks, kind):
    return [d for t, d in blocks if t == kind]


# ------------------------------------------------------------------ 1. the gate


def test_an_operator_suspend_without_a_gate_records_none_and_says_why(client, child, blocks, table, clock):
    lease_id = client.post("/response/suspend", json=body_for(child)).json()["lease_id"]
    client.post("/response/resume", json={"lease_id": lease_id, "incident_id": "inc-rv", "reason": "done"})
    (suspended,) = of_type(blocks, "process_suspended")
    (resumed,) = of_type(blocks, "process_resumed")
    for block in (suspended, resumed):
        assert block["gate"] is None, "Response must not invent a gate"
        assert block["gate_verified"] is False
        assert block["gate_reason"] == "no gate supplied (operator request)"
        assert block["attribution_supplied_by"] == "caller"
        assert block["attribution_confidence"] == "certain"  # recorded, as the caller's claim


def test_a_gate_the_caller_claims_is_recorded_verbatim_and_unverified(client, child, blocks, table, clock):
    lease_id = client.post("/response/suspend",
                           json=body_for(child, gate="suspend_authorised")).json()["lease_id"]
    clock.advance(2.0)
    table.reap()
    assert table.drain()
    (suspended,) = of_type(blocks, "process_suspended")
    (expired,) = of_type(blocks, "process_resumed")
    for block in (suspended, expired):
        assert block["lease_id"] == lease_id
        assert block["gate"] == "suspend_authorised"
        assert block["gate_verified"] is False
        assert "claimed by the caller" in block["gate_reason"]
        assert block["attribution_supplied_by"] == "caller"


def test_a_refusal_records_the_gate_the_same_way(client, child, blocks):
    client.post("/response/suspend", json=body_for(child, started_at=child.started_at - 30))
    (refused,) = of_type(blocks, "process_suspended")
    assert refused["outcome"] == "refused"
    assert refused["gate"] is None and refused["gate_verified"] is False
    assert refused["gate_reason"] == "no gate supplied (operator request)"


# ------------------------------------------------------------- 2. URDS_MONITOR_PID


@pytest.mark.parametrize("separator", [" ", ",", ";", ", ", " ; "])
def test_every_separator_protects_the_monitor(monkeypatch, child, separator):
    monkeypatch.delenv("RESPONSE_PID_NAMESPACE", raising=False)
    monkeypatch.setenv("URDS_MONITOR_PID", f"999999{separator}{child.pid}")
    with pytest.raises(actions.SuspendRefused) as refused:
        actions.vet_suspend(child.pid, child.image, child.started_at)
    assert refused.value.code == "MONITOR_OR_ANCESTOR"


@pytest.mark.parametrize("value", ["12x", "monitor", "-5", "4 and 7", "0"])
def test_an_unparsable_monitor_pid_refuses_every_suspend_and_records_it(client, child, blocks, monkeypatch, value):
    monkeypatch.setenv("URDS_MONITOR_PID", value)
    response = client.post("/response/suspend", json=body_for(child))
    assert response.status_code == 409
    assert response.json()["code"] == "MONITOR_PID_INVALID"
    (refused,) = of_type(blocks, "process_suspended")
    assert refused["code"] == "MONITOR_PID_INVALID"
    assert child.is_running()


# ------------------------------------------------- 3. expiry waits on nothing


def test_expiry_does_not_wait_behind_another_leases_ledger_write(clock):
    """R-RACE R1: A's block takes long to write; B, expiring meanwhile, must not wait for it."""
    gate = threading.Event()
    a_writing = threading.Event()

    def slow_end(lease):
        if lease.process_id == 200:
            a_writing.set()
            gate.wait(5)

    table = LeaseTable(resume=lambda h: h.resume(), clock=clock, on_end=slow_end)
    a, b = Fake(200), Fake(201)
    take(table, a, seconds=1.0)
    take(table, b, seconds=1.2)
    table.start(interval=0.01)
    try:
        clock.advance(1.0)
        assert a_writing.wait(2), "A never expired"
        clock.advance(0.5)  # B is now past its deadline while A's block is still being written
        assert wait_until(lambda: b.count == 0, 0.8), "B stayed frozen behind A's ledger write"
    finally:
        gate.set()
        table.stop()


class RespawningWatchdog:
    """Behaves like the real one: hold() on a dead watchdog respawns it, which is slow."""

    def __init__(self) -> None:
        self.spawn_gate = threading.Event()
        self.alive = True

    def _spawn(self) -> None:
        self.spawn_gate.wait(5)
        self.alive = True

    def start(self) -> None:
        if not self.alive:
            self._spawn()

    def hold(self, *args) -> None:
        if not self.alive:
            self._spawn()

    def drop(self, *args) -> None:
        pass

    def pids(self):
        return set()

    def close(self) -> None:
        pass


def test_expiry_does_not_wait_behind_a_watchdog_respawn(clock):
    """R-RACE R1: a respawn (up to 15 s) must not happen under the table lock."""
    watchdog = RespawningWatchdog()
    table = LeaseTable(resume=lambda h: h.resume(), clock=clock, watchdog=watchdog)
    held = Fake(300)
    take(table, held, seconds=1.0)
    table.start(interval=0.01)
    watchdog.alive = False  # it died; the next suspend respawns it
    other = threading.Thread(target=lambda: take(table, Fake(301)), daemon=True)
    try:
        other.start()
        time.sleep(0.05)
        clock.advance(2.0)
        assert wait_until(lambda: held.count == 0, 0.8), "an expired lease waited for the respawn"
    finally:
        watchdog.spawn_gate.set()
        other.join(timeout=5)
        table.resume_all(reason="cleanup", by="shutdown")
        table.stop()


def test_a_watchdog_drop_does_not_wait_behind_its_own_respawn(monkeypatch):
    """The real Watchdog: drop() runs under the table lock, so it must never wait for a spawn."""
    gate = threading.Event()

    def slow_popen(*args, **kwargs):
        gate.wait(5)
        raise OSError("no interpreter (test)")

    monkeypatch.setattr(lease_watchdog.subprocess, "Popen", slow_popen)
    watchdog = lease_watchdog.Watchdog()
    spawning = threading.Thread(target=lambda: pytest.raises(LeaseError, watchdog.start), daemon=True)
    spawning.start()
    time.sleep(0.05)
    try:
        started = time.monotonic()
        watchdog.drop("lease_x")
        assert time.monotonic() - started < 0.5, "drop() waited for a respawn in progress"
    finally:
        gate.set()
        spawning.join(timeout=5)


def test_a_suspend_after_shutdown_is_refused(clock):
    """R-RACE R1: granted after resume_all + stop, it would never be reaped."""
    table = LeaseTable(resume=lambda h: h.resume(), clock=clock)
    table.start(interval=0.01)
    table.resume_all(reason="response_shutdown", by="shutdown")
    table.stop()
    late = Fake(400)
    with pytest.raises(LeaseError) as refused:
        take(table, late)
    assert refused.value.code == "SHUTTING_DOWN"
    assert late.count == 0
    table.start(interval=0.01)  # a restart accepts suspends again
    try:
        take(table, late)
        assert late.count == 1
    finally:
        table.resume_all(reason="cleanup", by="shutdown")
        table.stop()


def test_the_service_refuses_a_suspend_once_its_lifespan_has_ended(table, child, blocks):
    with TestClient(response_app.app):
        pass
    response = TestClient(response_app.app).post("/response/suspend", json=body_for(child))
    assert response.status_code == 409
    assert response.json()["code"] == "SHUTTING_DOWN"
    assert child.is_running()


# ------------------------------------------------------- 4. NaN / Infinity


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_lease_seconds_is_a_400(table, child, blocks, bad):
    import json

    raw = json.dumps(body_for(child)).replace('"lease_seconds": 2.0', f'"lease_seconds": {bad}')
    with TestClient(response_app.app, raise_server_exceptions=False) as c:
        response = c.post("/response/suspend", content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "BAD_REQUEST"
    assert table.held() == []
    assert child.is_running()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.0, -1.0])
def test_the_table_itself_refuses_a_non_finite_or_non_positive_lease(clock, bad):
    table = LeaseTable(resume=lambda h: h.resume(), clock=clock)
    handle = Fake(500)
    with pytest.raises(LeaseError) as refused:
        take(table, handle, seconds=bad)
    assert refused.value.code == "INVALID_LEASE"
    assert handle.count == 0 and table.held() == []


# ------------------------------------------- 5. a false "not running"


def test_a_false_not_running_does_not_nest_a_second_suspend(table, child):
    """R-SAFE R7b, on a real child: psutil wrongly says the held process is gone."""
    vet = lambda: actions.vet_suspend(child.pid, child.image, child.started_at)  # noqa: E731
    lease, _ = table.acquire(child.pid, incident_id="i", lease_seconds=5.0, reason="r",
                             vet=vet, suspend=actions.suspend_process)
    lease.handle.is_running = lambda: False
    again, already = table.acquire(child.pid, incident_id="j", lease_seconds=5.0, reason="r",
                                   vet=vet, suspend=actions.suspend_process)
    assert already and again is lease, "the same process was given a second lease"
    table.release(lease_id=lease.lease_id, reason="t")
    assert table.held() == []
    assert child.is_running(), "frozen with no lease held: suspended twice, resumed once"


def test_a_really_reused_pid_still_gets_a_fresh_lease(clock):
    table = LeaseTable(resume=lambda h: h.resume(), clock=clock)
    old = Fake(600, created=1_700_000_000.0)
    first, _ = take(table, old)
    old.alive = False
    reborn = Fake(600, created=1_700_000_500.0)
    second, already = take(table, reborn)
    assert not already and second is not first
    assert first.state == leases.GONE
    assert reborn.count == 1


def test_an_unprovable_identity_refuses_rather_than_risk_nesting(clock):
    table = LeaseTable(resume=lambda h: h.resume(), clock=clock)
    old = Fake(700)
    first, _ = take(table, old)
    old.alive = False
    unreadable = Fake(700, created=None)
    with pytest.raises(LeaseError) as refused:
        take(table, unreadable)
    assert refused.value.code == "LEASE_STATE_UNCERTAIN"
    assert unreadable.count == 0
    assert table.held_for(700) is first  # still held; the reaper still ends it
