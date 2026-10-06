"""A Response service that dies holding a lease does not leave the process frozen.

Defect 26 (F2b, Response side). The lease's own expiry, the lifespan shutdown
and `atexit` all run inside the Response process; none of them runs when that
process is killed outright. The watchdog child does. These tests kill a real
stand-in for the service (`_holder.py`) while it holds a real suspension and
check the suspended child starts beating again.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from fastapi.testclient import TestClient

import app as response_app

HOLDER = Path(__file__).resolve().with_name("_holder.py")


class Holder:
    def __init__(self, child, lease_seconds: float, grace: float) -> None:
        self.popen = subprocess.Popen(
            [sys.executable, str(HOLDER), str(child.pid), repr(child.started_at), str(lease_seconds), str(grace)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        line = self.popen.stdout.readline().split()
        assert line and line[0] == "held", f"the holder did not take the lease: {line!r}"
        self.pid = int(line[1])
        self.lease_id = line[2]
        self.watchdog_pids = [int(p) for p in line[3].split(",")]

    def kill_hard(self) -> None:
        """TerminateProcess / SIGKILL: no lifespan, no atexit, no finally."""
        psutil.Process(self.pid).kill()

    def cleanup(self) -> None:
        for pid in [self.pid, *self.watchdog_pids]:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
        if self.popen.poll() is None:
            self.popen.kill()
        self.popen.wait(timeout=5)
        self.popen.stdout.close()


def gone_within(pids, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not any(psutil.pid_exists(p) for p in pids):
            return True
        time.sleep(0.05)
    return False


def test_a_hard_killed_service_does_not_leave_the_process_frozen(child):
    holder = Holder(child, lease_seconds=30.0, grace=30.0)
    try:
        assert child.is_frozen(), "the holder's suspension did not take"
        holder.kill_hard()
        # Neither the lease (30 s) nor the grace (30 s) is near: only the
        # broken pipe can have woken the watchdog.
        assert child.is_running(within=5.0), "the child stayed frozen after the service died"
        assert gone_within(holder.watchdog_pids, 5.0), "the watchdog outlived its work"
    finally:
        holder.cleanup()


def test_a_process_tree_kill_of_the_service_does_not_leave_the_process_frozen(child):
    """`taskkill /T /F`, or a service wrapper that kills the tree on stop: every
    descendant of the service dies with it. The watchdog must not be one."""
    holder = Holder(child, lease_seconds=30.0, grace=30.0)
    try:
        assert child.is_frozen()
        root = psutil.Process(holder.popen.pid)
        tree = [root, *root.children(recursive=True)]
        assert not set(holder.watchdog_pids) & {p.pid for p in tree}, "the watchdog is in the service's tree"
        for process in tree:
            try:
                process.kill()
            except psutil.Error:
                pass
        assert child.is_running(within=5.0), "the child stayed frozen after a tree kill"
    finally:
        holder.cleanup()


def test_a_stuck_service_lease_is_resumed_by_the_watchdog(child):
    """The holder stays alive but never reaps (its reaper is not running)."""
    holder = Holder(child, lease_seconds=0.3, grace=0.3)
    try:
        assert child.is_running(within=5.0), "the watchdog did not resume an overdue lease"
        assert holder.popen.poll() is None  # the service is still alive
    finally:
        holder.cleanup()


def test_the_watchdog_leaves_a_recycled_pid_alone(child):
    """Before resuming, the PID must still be the leased process (start time)."""
    import lease_watchdog

    child.process.suspend()
    try:
        lease_watchdog._resume({"lease_id": "l", "pid": child.pid, "started_at": child.started_at - 30.0,
                                "image": None}, "test")
        assert child.is_frozen()
        lease_watchdog._resume({"lease_id": "l", "pid": child.pid, "started_at": child.started_at,
                                "image": None}, "test")
        assert child.is_running()
    finally:
        child.process.resume()


def test_the_service_starts_its_watchdog_and_never_suspends_it(monkeypatch, child):
    from lease_watchdog import Watchdog

    recorded = []
    monkeypatch.setattr(response_app, "log_action", lambda t, d: recorded.append((t, d)))
    monkeypatch.delenv("URDS_MONITOR_PID", raising=False)
    monkeypatch.delenv("RESPONSE_PID_NAMESPACE", raising=False)
    table = response_app.build_lease_table(watchdog=Watchdog())
    monkeypatch.setattr(response_app, "LEASES", table)
    with TestClient(response_app.app) as client:
        watchdog_pids = table.watchdog.pids()
        assert watchdog_pids, "the lifespan did not start the watchdog"
        for pid in watchdog_pids:
            response = client.post("/response/suspend", json={
                "process_id": pid, "incident_id": "inc-w", "lease_seconds": 2, "reason": "r",
                "attribution_confidence": "probable", "attribution_source": "windows-security-4663",
                "attribution_reason": "r", "started_at": psutil.Process(pid).create_time(),
            })
            assert response.status_code == 409
            assert response.json()["code"] in {"LEASE_WATCHDOG", "RESPONSE_OR_ANCESTOR"}
        ok = client.post("/response/suspend", json={
            "process_id": child.pid, "incident_id": "inc-w", "lease_seconds": 5, "reason": "r",
            "attribution_confidence": "probable", "attribution_source": "windows-security-4663",
            "attribution_reason": "r", "started_at": child.started_at,
        })
        assert ok.status_code == 200, ok.text
        assert child.is_frozen()
    assert child.is_running()
    assert gone_within(watchdog_pids, 5.0), "shutdown left the watchdog running"


def test_a_watchdog_that_cannot_start_refuses_the_suspend(monkeypatch, child):
    from lease_watchdog import Watchdog

    recorded = []
    monkeypatch.setattr(response_app, "log_action", lambda t, d: recorded.append((t, d)))
    monkeypatch.delenv("URDS_MONITOR_PID", raising=False)
    monkeypatch.delenv("RESPONSE_PID_NAMESPACE", raising=False)
    broken = Watchdog(python=str(Path(sys.executable).with_name("no-such-python.exe")))
    table = response_app.build_lease_table(watchdog=broken)
    monkeypatch.setattr(response_app, "LEASES", table)
    with TestClient(response_app.app) as client:
        response = client.post("/response/suspend", json={
            "process_id": child.pid, "incident_id": "inc-w", "lease_seconds": 2, "reason": "r",
            "attribution_confidence": "probable", "attribution_source": "windows-security-4663",
            "attribution_reason": "r", "started_at": child.started_at,
        })
    assert response.status_code == 409
    assert response.json()["code"] == "WATCHDOG_UNAVAILABLE"
    assert child.is_running()
    ((event_type, block),) = recorded
    assert event_type == "process_suspended" and block["outcome"] == "refused"
