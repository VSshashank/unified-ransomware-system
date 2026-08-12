"""Process termination and network isolation.

Covers TC-07 (a detected ransomware process is terminated, target <2s) and the
guards that stop a wrong PID from taking the host down with it.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

import actions
from actions import TerminationError, build_plan, guard, isolate_host, terminate_process

REPORTS = Path(__file__).resolve().parents[3] / "reports"
KILL_TIME_TARGET_S = 2.0

# Opt-in, so a plain `pytest -q` leaves committed evidence untouched. See the
# note in services/monitor/tests/test_benchmarks.py.
WRITE_REPORTS = os.getenv("URDS_WRITE_REPORTS", "").lower() in {"1", "true", "yes"}

# Windows has no signal to ignore: psutil's terminate() and kill() both call
# TerminateProcess, which is unconditional. A test for "the process survived
# SIGTERM, so we escalated" is asserting a POSIX guarantee, not a bug in
# actions.py - the Windows outcome (dead on the first call) is the better one.
posix_signals_only = pytest.mark.skipif(
    os.name == "nt", reason="SIGTERM cannot be ignored on Windows; terminate() is TerminateProcess"
)


@pytest.fixture
def victim():
    """A real child process that ignores nothing and exits on SIGTERM."""
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    yield process
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)


@pytest.fixture
def stubborn_victim():
    """Ignores SIGTERM, so only SIGKILL ends it."""
    code = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)"
    process = subprocess.Popen([sys.executable, "-c", code])
    time.sleep(0.4)  # let the handler install before we signal it
    yield process
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)


# ------------------------------------------------------------------- TC-07


def test_tc07_ransomware_process_is_terminated(victim):
    assert psutil.pid_exists(victim.pid)

    result = terminate_process(victim.pid, force=True)

    assert result["status"] == "terminated"
    assert result["process_id"] == victim.pid
    assert result["method"] in {"sigterm", "sigkill"}
    victim.wait(timeout=5)
    assert not psutil.pid_exists(victim.pid) or psutil.Process(victim.pid).status() == psutil.STATUS_ZOMBIE


@pytest.mark.benchmark
def test_tc07_termination_completes_within_2_seconds(victim):
    result = terminate_process(victim.pid, force=True)
    elapsed_s = result["termination_time_ms"] / 1000

    if WRITE_REPORTS:
        REPORTS.mkdir(exist_ok=True)
        existing = {}
        path = REPORTS / "as_benchmarks.json"
        if path.exists():
            existing = json.loads(path.read_text())
        existing["process_kill_time_s"] = {"measured": round(elapsed_s, 4), "target": KILL_TIME_TARGET_S}
        path.write_text(json.dumps(existing, indent=2))

    print(f"\nprocess kill time: {elapsed_s * 1000:.1f}ms (target <2000ms)")
    assert elapsed_s < KILL_TIME_TARGET_S


@posix_signals_only
def test_process_ignoring_sigterm_is_escalated_to_sigkill(stubborn_victim):
    result = terminate_process(stubborn_victim.pid, force=True)

    assert result["method"] == "sigkill"
    assert result["termination_time_ms"] / 1000 < KILL_TIME_TARGET_S
    stubborn_victim.wait(timeout=5)


@posix_signals_only
def test_process_ignoring_sigterm_without_force_is_reported_not_silently_left(stubborn_victim):
    with pytest.raises(TerminationError, match="ignored SIGTERM"):
        terminate_process(stubborn_victim.pid, force=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows-only termination semantics")
def test_on_windows_a_stubborn_process_still_dies(stubborn_victim):
    """The escalation path has no Windows equivalent, and needs none.

    psutil maps both terminate() and kill() to TerminateProcess, which no
    process can ignore or handle. So SIG_IGN on SIGTERM changes nothing here:
    the first call already ends the process, and the <2s target still holds.
    """
    result = terminate_process(stubborn_victim.pid, force=True)

    assert result["status"] == "terminated"
    assert result["termination_time_ms"] / 1000 < KILL_TIME_TARGET_S
    stubborn_victim.wait(timeout=5)
    assert not psutil.pid_exists(stubborn_victim.pid)


# ------------------------------------------------------------------- guards


@pytest.mark.parametrize("pid", [0, 1, -1])
def test_reserved_pids_are_refused(pid):
    with pytest.raises(TerminationError, match="reserved|does not exist"):
        guard(pid)


def test_own_process_is_refused():
    import os

    with pytest.raises(TerminationError, match="itself or one of its ancestors"):
        guard(os.getpid())


def test_parent_process_is_refused():
    import os

    with pytest.raises(TerminationError, match="itself or one of its ancestors"):
        guard(os.getppid())


def test_nonexistent_pid_is_refused():
    # Search downward from the max for a PID nothing is using.
    candidate = 4_000_000
    while psutil.pid_exists(candidate) and candidate > 100_000:
        candidate -= 1
    with pytest.raises(TerminationError, match="does not exist"):
        guard(candidate)


def test_protected_system_process_is_refused(victim, monkeypatch):
    monkeypatch.setattr(psutil.Process, "name", lambda self: "systemd")
    with pytest.raises(TerminationError, match="protected system process"):
        guard(victim.pid)


def test_terminate_on_missing_pid_raises_rather_than_reporting_success():
    candidate = 4_000_000
    while psutil.pid_exists(candidate) and candidate > 100_000:
        candidate -= 1
    with pytest.raises(TerminationError):
        terminate_process(candidate)


# ---------------------------------------------------------------- isolation


def test_isolation_plan_is_built_for_this_platform():
    plan = build_plan("full", allow_localhost=True)
    assert plan.backend in {"iptables", "pfctl", "netsh", "none"}
    assert isinstance(plan.reason, str) and plan.reason


def test_isolation_is_not_enforced_unless_explicitly_enabled(monkeypatch):
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", False)
    result = isolate_host(level="full", duration_seconds=300)

    assert result["enforced"] is False
    assert result["status"] == "simulated"
    assert "RESPONSE_ISOLATION_ENABLED" in result["reason"]
    # The rules it *would* apply are still reported - that is the useful part.
    assert isinstance(result["planned_rules"], list)


def test_isolation_reports_unsupported_platform_rather_than_claiming_success(monkeypatch):
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", True)
    monkeypatch.setattr(actions.platform, "system", lambda: "Plan9")

    result = isolate_host(level="full")

    assert result["enforced"] is False
    assert result["status"] == "unsupported"
    assert "Plan9" in result["reason"]


def test_isolation_never_shells_out_while_disabled(monkeypatch):
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", False)

    def explode(*args, **kwargs):
        raise AssertionError("subprocess.run must not be called when isolation is disabled")

    monkeypatch.setattr(actions.subprocess, "run", explode)
    assert isolate_host(level="full")["enforced"] is False


def test_isolation_applies_rules_when_enabled(monkeypatch):
    calls = []
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", True)
    monkeypatch.setattr(actions.platform, "system", lambda: "Linux")
    monkeypatch.setattr(actions.shutil, "which", lambda name: f"/sbin/{name}")
    monkeypatch.setattr(actions.subprocess, "run", lambda cmd, **kw: calls.append(cmd))

    result = isolate_host(level="full", allow_localhost=True)

    assert result["enforced"] is True
    assert result["status"] == "isolated"
    assert any("DROP" in " ".join(c) for c in calls)
    assert any("lo" in c for c in calls), "localhost carve-out was requested but not applied"


def test_isolation_failure_is_reported_as_failed_not_isolated(monkeypatch):
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", True)
    monkeypatch.setattr(actions.platform, "system", lambda: "Linux")
    monkeypatch.setattr(actions.shutil, "which", lambda name: f"/sbin/{name}")

    def fail(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(actions.subprocess, "run", fail)

    result = isolate_host(level="full")
    assert result["status"] == "failed"
    assert result["enforced"] is False
