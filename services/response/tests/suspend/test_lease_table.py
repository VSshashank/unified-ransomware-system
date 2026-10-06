"""The lease table on its own: one suspension per PID, and every lease ends.

Defect 26 (F2b, Response side). No process is touched here: the handle is a
fake that counts suspends and resumes the way `NtSuspendProcess` does (they
nest), and time is an injected monotonic clock, so expiry is exact and nothing
sleeps. The real-process versions of these are in test_suspend_real.py.
"""

from __future__ import annotations

import pytest

import leases
from leases import GONE, HELD, RESUMED, TERMINATED, LeaseError, LeaseTable


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeProcess:
    """Suspension nests, as on Windows: n suspends need n resumes."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.count = 0
        self.suspends = 0
        self.alive = True

    def suspend(self) -> None:
        self.count += 1
        self.suspends += 1

    def resume(self) -> bool:
        if not self.alive:
            return False
        self.count = max(0, self.count - 1)
        return True

    @property
    def frozen(self) -> bool:
        return self.count > 0

    def is_running(self) -> bool:
        return self.alive

    def exe(self) -> str:
        return f"C:\\work\\writer{self.pid}.exe"

    def create_time(self) -> float:
        return 1_700_000_000.0 + self.pid


class FakeWatchdog:
    def __init__(self, fail: bool = False) -> None:
        self.held: dict[str, int] = {}
        self.log: list[tuple] = []
        self.fail = fail

    def hold(self, lease_id, pid, started_at, image, seconds):
        if self.fail:
            raise LeaseError("WATCHDOG_UNAVAILABLE", "the watchdog is down")
        self.held[lease_id] = pid
        self.log.append(("hold", lease_id, pid))

    def drop(self, lease_id):
        self.held.pop(lease_id, None)
        self.log.append(("drop", lease_id))

    def pids(self):
        return {4242}

    def start(self):
        pass

    def close(self):
        pass


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def ended():
    return []


@pytest.fixture
def table(clock, ended):
    return LeaseTable(resume=lambda p: p.resume(), clock=clock, max_seconds=10.0, on_end=ended.append)


def take(table, process, seconds=2.0, incident="inc-1"):
    return table.acquire(
        process.pid,
        incident_id=incident,
        lease_seconds=seconds,
        reason="sole writer",
        vet=lambda: process,
        suspend=lambda p: p.suspend(),
        attribution_confidence="probable",
        attribution_source="windows-security-4663",
        attribution_reason="one writer so far; pending",
    )


def test_a_suspend_creates_a_held_lease(table):
    process = FakeProcess(501)
    lease, already = take(table, process)
    assert not already
    assert lease.state == HELD
    assert process.frozen
    assert table.held_for(501) is lease
    assert lease.gate_fields() == {
        "attribution_confidence": "probable",
        "attribution_source": "windows-security-4663",
        "attribution_reason": "one writer so far; pending",
        # Review follow-up R8c: no gate is invented; the caller supplied none.
        "attribution_supplied_by": "caller",
        "gate": None,
        "gate_verified": False,
        "gate_reason": "no gate supplied (operator request)",
    }


def test_a_second_suspend_of_the_same_pid_is_a_no_op(table):
    """Suspension nests; a second suspend would need a second resume."""
    process = FakeProcess(502)
    first, _ = take(table, process, incident="inc-1")
    second, already = take(table, process, incident="inc-2")
    assert already
    assert second is first
    assert process.suspends == 1
    # One resume is enough to unfreeze it, because it was suspended once.
    table.release(lease_id=first.lease_id, reason="second writer", by="caller")
    assert not process.frozen


def test_the_lease_is_capped(table):
    lease, _ = take(table, FakeProcess(503), seconds=3600)
    assert lease.lease_seconds == 10.0
    assert lease.lease_seconds_requested == 3600


def test_a_lease_does_not_expire_before_its_deadline(table, clock):
    process = FakeProcess(504)
    take(table, process, seconds=2.0)
    clock.advance(1.999)
    assert table.reap() == []
    assert process.frozen


def test_an_expired_lease_resumes_the_process_on_its_own(table, clock, ended):
    """The backstop for a caller that never comes back - a crashed Monitor."""
    process = FakeProcess(505)
    lease, _ = take(table, process, seconds=2.0)
    clock.advance(2.0)
    assert table.reap() == [lease]
    assert not process.frozen
    assert lease.state == RESUMED
    assert lease.ended_by == "lease_expiry"
    assert lease.ended_reason == "lease_expired"
    assert lease.held_ms == 2000.0
    assert ended == [lease]
    assert table.held_for(505) is None


def test_resume_is_idempotent(table):
    process = FakeProcess(506)
    lease, _ = take(table, process)
    assert table.release(lease_id=lease.lease_id, reason="r", by="caller") == (lease, True, True)
    again = table.release(lease_id=lease.lease_id, reason="r", by="caller")
    assert again == (lease, False, False)
    assert process.count == 0


def test_resume_never_touches_a_process_this_table_did_not_suspend(table):
    stranger = FakeProcess(507)
    stranger.suspend()  # suspended by someone else - a debugger, say
    assert table.release(process_id=507, reason="r", by="caller") == (None, False, False)
    assert stranger.frozen


def test_an_unknown_lease_id_resumes_nothing(table):
    assert table.release(lease_id="lease_nope", reason="r", by="caller") == (None, False, False)


def test_shutdown_resumes_everything_held(table, ended):
    processes = [FakeProcess(pid) for pid in (601, 602, 603)]
    for process in processes:
        take(table, process)
    resumed = table.resume_all(reason="response_shutdown", by="shutdown")
    assert len(resumed) == 3
    assert not any(p.frozen for p in processes)
    assert {lease.ended_by for lease in ended} == {"shutdown"}
    assert table.held() == []


def test_one_failed_resume_does_not_stop_the_others(clock):
    def resume(p):
        if p.pid == 701:
            raise PermissionError("access denied")
        return p.resume()

    table = LeaseTable(resume=resume, clock=clock)
    bad, good = FakeProcess(701), FakeProcess(702)
    take(table, bad)
    take(table, good)
    table.resume_all(reason="response_shutdown", by="shutdown")
    assert not good.frozen
    # The failed one is still held, so the reaper and the watchdog still try.
    assert table.held_for(701) is not None


def test_terminate_closes_the_lease_without_resuming(table, ended):
    process = FakeProcess(801)
    lease, _ = take(table, process)
    assert table.end_for_terminate(801) is lease
    assert lease.state == TERMINATED
    assert process.frozen  # killed, not resumed: there is nothing to run
    assert table.held_for(801) is None
    assert ended == []  # the terminate block records it, not a resume block


def test_a_held_process_that_died_is_closed_out_before_a_new_lease(table, ended):
    process = FakeProcess(901)
    first, _ = take(table, process)
    process.alive = False
    reborn = FakeProcess(901)  # the number, recycled - by a process started later
    reborn.create_time = lambda: 1_700_000_000.0 + 901 + 60.0
    second, already = take(table, reborn)
    assert not already
    assert second.lease_id != first.lease_id
    assert first.state == GONE
    assert ended == [first]


def test_a_refused_vet_creates_no_lease(table):
    def refuse():
        raise RuntimeError("refused")

    with pytest.raises(RuntimeError):
        table.acquire(1001, incident_id="i", lease_seconds=2, reason="r", vet=refuse, suspend=lambda p: p.suspend())
    assert table.held() == []


def test_the_watchdog_hears_of_a_lease_before_the_suspend(clock):
    order = []
    watchdog = FakeWatchdog()
    original = watchdog.hold
    watchdog.hold = lambda *a: (order.append("hold"), original(*a))
    table = LeaseTable(resume=lambda p: p.resume(), clock=clock, watchdog=watchdog)
    process = FakeProcess(1101)
    table.acquire(1101, incident_id="i", lease_seconds=2, reason="r", vet=lambda: process,
                  suspend=lambda p: (order.append("suspend"), p.suspend()))
    assert order == ["hold", "suspend"]
    table.resume_all(reason="x", by="shutdown")
    assert watchdog.held == {}


def test_no_watchdog_no_suspend(clock):
    """A configured watchdog that is down refuses the suspend: nothing frozen
    that a crash of this service could leave frozen."""
    table = LeaseTable(resume=lambda p: p.resume(), clock=clock, watchdog=FakeWatchdog(fail=True))
    process = FakeProcess(1201)
    with pytest.raises(LeaseError) as raised:
        table.acquire(1201, incident_id="i", lease_seconds=2, reason="r", vet=lambda: process,
                      suspend=lambda p: p.suspend())
    assert raised.value.code == "WATCHDOG_UNAVAILABLE"
    assert not process.frozen
    assert table.held() == []


def test_a_failed_suspend_tells_the_watchdog_to_forget_it(clock):
    watchdog = FakeWatchdog()
    table = LeaseTable(resume=lambda p: p.resume(), clock=clock, watchdog=watchdog)

    def fail(_):
        raise RuntimeError("access denied")

    with pytest.raises(RuntimeError):
        table.acquire(1301, incident_id="i", lease_seconds=2, reason="r", vet=lambda: FakeProcess(1301),
                      suspend=fail)
    assert watchdog.held == {}


def test_the_listing_has_the_contract_shape(table):
    lease, _ = take(table, FakeProcess(1401))
    table.release(lease_id=lease.lease_id, reason="r", by="caller")
    held, _ = take(table, FakeProcess(1402))
    listing = table.list()
    assert [row["lease_id"] for row in listing] == [held.lease_id, lease.lease_id]
    assert set(listing[0]) == {"lease_id", "process_id", "incident_id", "expires_at", "state"}
    assert [row["state"] for row in listing] == [HELD, RESUMED]


def test_the_reaper_thread_expires_leases(clock):
    """The background loop, not just `reap()`: started, it ends an expired lease."""
    import threading

    done = threading.Event()
    table = LeaseTable(resume=lambda p: p.resume(), clock=clock, on_end=lambda lease: done.set())
    process = FakeProcess(1501)
    take(table, process, seconds=1.0)
    table.start(interval=0.01)
    try:
        clock.advance(1.0)
        assert done.wait(timeout=1.0)
        assert not process.frozen
    finally:
        table.stop()


def test_history_is_bounded(table, monkeypatch):
    monkeypatch.setattr(leases, "HISTORY_LIMIT", 3)
    for pid in range(2001, 2006):
        lease, _ = take(table, FakeProcess(pid))
        table.release(lease_id=lease.lease_id, reason="r", by="caller")
    assert len(table.list()) == 3
