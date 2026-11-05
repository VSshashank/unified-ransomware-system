"""Real child processes for the suspend/resume tests, and the net under them.

Every test here that freezes something freezes a process it started itself: a
Python child that appends one byte to a heartbeat file every 10 ms. "Frozen"
and "running" are judged by whether that file grows, because on Windows
`psutil.Process.status()` keeps saying "running" for a suspended process
(measured on the test VM: it never reports "stopped").

The venv's `python.exe` on Windows is a launcher that starts the real
interpreter as its own child, so `Popen.pid` is not the process that runs the
code. The child prints `os.getpid()` and that is the PID every test uses.

Nothing may be left frozen. Each child is resumed (several times, because
suspension nests on Windows) and then killed, in the fixture's `finally`, at
session end, and at interpreter exit - whichever comes first does it, the
others find nothing to do.
"""

from __future__ import annotations

import atexit
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

HERE = Path(__file__).resolve().parent
SERVICE = HERE.parents[1]
if str(SERVICE) not in sys.path:
    sys.path.insert(0, str(SERVICE))

HEARTBEAT_SOURCE = (
    "import os, sys, time\n"
    "path = sys.argv[1]\n"
    "out = open(path, 'ab', buffering=0)\n"
    "print(os.getpid(), flush=True)\n"
    "deadline = time.monotonic() + 60\n"
    "while time.monotonic() < deadline:\n"
    "    out.write(b'.')\n"
    "    time.sleep(0.01)\n"
)

#: (launcher Popen, real pid) for every child any test started.
_CHILDREN: list[tuple[subprocess.Popen, int]] = []


def _release(pid: int) -> None:
    """Resume as often as it could have been suspended, then kill."""
    try:
        process = psutil.Process(pid)
    except psutil.Error:
        return
    for _ in range(8):
        try:
            process.resume()
        except psutil.Error:
            break
    try:
        process.kill()
    except psutil.Error:
        pass


def release_all() -> None:
    while _CHILDREN:
        popen, pid = _CHILDREN.pop()
        _release(pid)
        if popen.poll() is None:
            try:
                popen.kill()
            except OSError:
                pass
        try:
            popen.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for stream in (popen.stdout, popen.stderr, popen.stdin):
            if stream is not None:
                stream.close()


atexit.register(release_all)


def pytest_sessionfinish(session, exitstatus):
    release_all()


class Child:
    """A heartbeat process this test owns."""

    def __init__(self, beat: Path, source: str = HEARTBEAT_SOURCE, extra: tuple[str, ...] = ()):
        self.beat = beat
        self.popen = subprocess.Popen(
            [sys.executable, "-c", source, str(beat), *extra],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        line = self.popen.stdout.readline()
        self.pid = int(line.split()[0])
        self.line = line
        _CHILDREN.append((self.popen, self.pid))
        self.process = psutil.Process(self.pid)
        self.image = self.process.exe()
        self.started_at = self.process.create_time()

    def size(self) -> int:
        try:
            return os.path.getsize(self.beat)
        except OSError:
            return 0

    def is_running(self, within: float = 3.0) -> bool:
        """The heartbeat grows within `within` seconds (polled, short sleeps)."""
        start = self.size()
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            time.sleep(0.05)
            if self.size() > start:
                return True
        return False

    def is_frozen(self, settle: float = 0.1, window: float = 0.4) -> bool:
        """The heartbeat does not grow at all across `window` seconds."""
        time.sleep(settle)
        start = self.size()
        time.sleep(window)
        return self.size() == start

    def release(self) -> None:
        _release(self.pid)
        if self.popen.poll() is None:
            self.popen.kill()
        self.popen.wait(timeout=5)


@pytest.fixture
def make_child(tmp_path):
    made: list[Child] = []

    def make(source: str = HEARTBEAT_SOURCE, extra: tuple[str, ...] = ()) -> Child:
        child = Child(tmp_path / f"beat{len(made)}", source, extra)
        made.append(child)
        # Started, and visibly running, before any test acts on it.
        assert child.is_running(), "the heartbeat child never started beating"
        return child

    try:
        yield make
    finally:
        for child in made:
            child.release()


@pytest.fixture
def child(make_child):
    return make_child()
