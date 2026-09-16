"""TC-26 (AS), Response half: what the termination guard refuses now that a PID
can arrive from attribution rather than from an operator.

Before attribution, every `process_id` reaching `/response/trigger` had been
typed by a human or handed in by a test. The guard's job was to stop an obvious
mistake. Now the PID can come from a Security-log record parsed by machine, and
one wrong answer means killing an arbitrary process on the host - so the guard's
job changed from catching typos to bounding a blast radius, and it is tested as
that.

`PROTECTED_NAMES` is a denylist and a denylist only covers what someone thought
to add. `lsass.exe` is on it; `LsaIso.exe`, `fontdrvhost.exe` and everything
else under System32 were not. `_guard_image_path` closes that by location
instead of by name.

WHAT IS DELIBERATELY *NOT* REFUSED

A process whose image path cannot be read. On Windows that is the ordinary
result for a process owned by another user, and refusing on unreadability would
reject most of what this guard exists to permit. Those still face the name
check. That is a real residual and it is named here rather than left for
someone to find in the code.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import psutil
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import actions  # noqa: E402
from actions import PROTECTED_IMAGE_ROOTS, TerminationError, guard  # noqa: E402


@pytest.fixture
def victim():
    """A process this test owns, which the guard must allow."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    yield proc
    proc.kill()
    proc.wait(timeout=5)


# ------------------------------------------------------------- still permitted


def test_tc26_r_an_ordinary_process_is_still_killable(victim):
    """The guard must not have become so strict it blocks its own purpose."""
    guard(victim.pid)  # does not raise


# --------------------------------------------------------------- still refused


def test_tc26_s_the_responder_cannot_be_asked_to_kill_itself():
    with pytest.raises(TerminationError, match="itself or one of its ancestors"):
        guard(os.getpid())


@pytest.mark.parametrize("pid", [0, 1, -1])
def test_tc26_t_reserved_pids_are_refused(pid):
    with pytest.raises(TerminationError, match="reserved"):
        guard(pid)


def test_tc26_u_a_pid_that_does_not_exist_is_refused_with_a_reason():
    ghost = 999_999
    while psutil.pid_exists(ghost):
        ghost += 1
    with pytest.raises(TerminationError, match="does not exist"):
        guard(ghost)


# ------------------------------------------------- the new location guard


def test_tc26_v_protected_roots_are_configured_for_this_platform():
    assert PROTECTED_IMAGE_ROOTS, "an empty root list would make the location guard a no-op"
    if os.name == "nt":
        assert any("windows" in r.lower() for r in PROTECTED_IMAGE_ROOTS)


def test_tc26_w_a_process_running_from_a_protected_root_is_refused(victim, monkeypatch):
    """The case `PROTECTED_NAMES` misses: a system binary nobody listed.

    The victim's image is faked rather than killing something real out of
    System32 to find out. What is under test is the location rule, and the
    location is the only input it reads.
    """
    protected_exe = os.path.join(PROTECTED_IMAGE_ROOTS[0], "System32", "fontdrvhost.exe")
    real_exe = psutil.Process.exe

    def fake_exe(self):
        return protected_exe if self.pid == victim.pid else real_exe(self)

    monkeypatch.setattr(psutil.Process, "exe", fake_exe)

    with pytest.raises(TerminationError, match="protected system location"):
        guard(victim.pid)


def test_tc26_x_a_lookalike_path_outside_the_root_is_not_refused(victim, monkeypatch):
    """`C:\\Windows-backup\\evil.exe` must not match `C:\\Windows`.

    A prefix test written as a bare `startswith` would refuse it, and an
    attacker who reads this guard would put their payload exactly there.
    """
    root = PROTECTED_IMAGE_ROOTS[0].rstrip("\\/")
    lookalike = f"{root}-backup{os.sep}locker.exe"
    real_exe = psutil.Process.exe

    def fake_exe(self):
        return lookalike if self.pid == victim.pid else real_exe(self)

    monkeypatch.setattr(psutil.Process, "exe", fake_exe)

    guard(victim.pid)  # does not raise


def test_tc26_y_an_unreadable_image_path_is_permitted_not_refused(victim, monkeypatch):
    """The documented residual, asserted so it stays deliberate."""
    real_exe = psutil.Process.exe

    def fake_exe(self):
        if self.pid == victim.pid:
            raise psutil.AccessDenied(victim.pid)
        return real_exe(self)

    monkeypatch.setattr(psutil.Process, "exe", fake_exe)

    guard(victim.pid)  # does not raise - the name check still applied above


def test_tc26_z_the_name_denylist_still_applies_to_an_unreadable_image(victim, monkeypatch):
    """Unreadable location must not become a way past the name check."""
    real_name = psutil.Process.name
    real_exe = psutil.Process.exe

    def fake_name(self):
        return "lsass.exe" if self.pid == victim.pid else real_name(self)

    def fake_exe(self):
        if self.pid == victim.pid:
            raise psutil.AccessDenied(victim.pid)
        return real_exe(self)

    monkeypatch.setattr(psutil.Process, "name", fake_name)
    monkeypatch.setattr(psutil.Process, "exe", fake_exe)

    with pytest.raises(TerminationError, match="protected system process"):
        guard(victim.pid)
