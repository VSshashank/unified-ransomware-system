"""Shared pieces for the freeze-first tests: real child processes and a Response stub.

The children are real. A Python process that appends one byte to a heartbeat
file every 10 ms stands for "the writer"; it is "frozen" when the file stops
growing and "running" when it grows, because on Windows `psutil.Process.status()`
keeps saying "running" for a suspended process (the Response service's own
tests found the same; services/response/tests/suspend/conftest.py). The venv's
`python.exe` on Windows is a launcher that starts the real interpreter as its
own child, so the child prints `os.getpid()` and that is the PID used.

The audit record is not real: nothing here can read the Security log (it needs
elevation), so the "4663" is a `WriteLog.record` naming the child, exactly as
the other attribution tests do. What is real is the process that gets frozen,
resumed or killed, and every identity check the Monitor makes on it.

The Response service is a stub, but one that does the real thing to the real
child: `/response/suspend` calls `psutil.Process.suspend`, `/resume` resumes,
`/terminate` kills, and every request is recorded, so a test can say "this
process was frozen, then resumed, and never killed" from what happened to it
rather than from what the Monitor said it asked for.

Nothing may be left frozen. Every child is resumed (suspension nests) and
killed in the fixture's `finally`, at session end and at interpreter exit.
"""

from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import psutil

HEARTBEAT_SOURCE = (
    "import os, sys, time\n"
    "out = open(sys.argv[1], 'ab', buffering=0)\n"
    "print(os.getpid(), flush=True)\n"
    "deadline = time.monotonic() + 120\n"
    "while time.monotonic() < deadline:\n"
    "    out.write(b'.')\n"
    "    time.sleep(0.01)\n"
)

_CHILDREN: list[tuple[subprocess.Popen, int]] = []


def _release(pid: int) -> None:
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


def release_all_children() -> None:
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


atexit.register(release_all_children)


class Child:
    """A heartbeat process this test owns."""

    def __init__(self, beat: Path):
        self.beat = beat
        self.popen = subprocess.Popen(
            [sys.executable, "-c", HEARTBEAT_SOURCE, str(beat)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.pid = int(self.popen.stdout.readline().split()[0])
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
        start = self.size()
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            time.sleep(0.05)
            if self.size() > start:
                return True
        return False

    def is_frozen(self, settle: float = 0.1, window: float = 0.4) -> bool:
        time.sleep(settle)
        start = self.size()
        time.sleep(window)
        return self.size() == start

    def alive(self) -> bool:
        try:
            return self.process.is_running() and self.process.status() != psutil.STATUS_ZOMBIE
        except psutil.Error:
            return False

    def kill(self) -> None:
        _release(self.pid)
        self.popen.wait(timeout=5)

    def release(self) -> None:
        _release(self.pid)
        if self.popen.poll() is None:
            self.popen.kill()
        self.popen.wait(timeout=5)


class ResponseStub:
    """What the Response service would do, to the real child, with every request recorded."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[tuple[str, dict]] = []
        #: "ok" | "refuse:<CODE>" | "unreachable" (suspend and resume only: nothing is
        #: carried out) | "lost_reply" (a suspend is carried out and its answer is lost)
        self.suspend_mode = "ok"
        #: seconds the stub takes to answer a suspend (a slow Response service)
        self.suspend_delay = 0.0
        self.leases: dict[str, dict] = {}
        self._by_pid: dict[int, str] = {}
        self._n = 0

    # -- what a test reads ------------------------------------------------

    def of(self, path: str) -> list[dict]:
        with self.lock:
            return [payload for p, payload in self.requests if p == path]

    def blocks(self, event_type: str) -> list[dict]:
        return [p["event_data"] for p in self.of("/ledger/log") if p["event_type"] == event_type]

    def lease(self, lease_id: str) -> dict:
        with self.lock:
            return dict(self.leases[lease_id])

    # -- the two ways in -----------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        """The transport the Monitor's own client talks through."""
        payload = json.loads(request.content or b"{}")
        if self.suspend_mode == "unreachable" and request.url.path in ("/response/suspend", "/response/resume"):
            with self.lock:
                self.requests.append((request.url.path, payload))
            raise httpx.ConnectError("connection refused (test)", request=request)
        status, body = self.dispatch(request.url.path, payload)
        if self.suspend_mode == "lost_reply" and request.url.path == "/response/suspend":
            # The service did it; the answer never arrived.
            raise httpx.ReadTimeout("the reply was lost (test)", request=request)
        return httpx.Response(status, json=body)

    def post(self, client, base_url, path, payload, *args, **kwargs):
        """Stands in for `pipeline._post`: the body on success, None on a refusal."""
        status, body = self.dispatch(path, payload)
        return body if status < 400 else None

    def dispatch(self, path: str, payload: dict) -> tuple[int, dict]:
        with self.lock:
            self.requests.append((path, payload))
            n = len(self.requests)
        if path == "/predict":
            return 200, {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return 200, {"block_id": n}
        if path == "/response/trigger":
            return 200, {"status": "success", "actions_taken": ["network_isolation_planned"]}
        if path == "/response/suspend":
            return self._suspend(payload)
        if path == "/response/resume":
            return self._resume(payload)
        if path == "/response/terminate":
            return self._terminate(payload)
        return 200, {}

    # -- the three actions, on the real process ----------------------------

    def _suspend(self, p: dict) -> tuple[int, dict]:
        if self.suspend_delay:
            time.sleep(self.suspend_delay)
        if self.suspend_mode.startswith("refuse:"):
            code = self.suspend_mode.split(":", 1)[1]
            return 409, {"code": code, "message": f"refused by the stub: {code}"}
        pid = p["process_id"]
        with self.lock:
            held = self._by_pid.get(pid)
            if held and self.leases[held]["state"] == "held":
                lease = self.leases[held]
                return 200, {"lease_id": held, "process_id": pid, "suspended": True,
                             "expires_at": lease["expires_at"], "already_held": True,
                             "incident_id": lease["incident_id"], "lease_seconds": lease["lease_seconds"]}
        try:
            process = psutil.Process(pid)
            claimed = p.get("started_at")
            if claimed is not None and process.create_time() > float(claimed) + 0.05:
                return 409, {"code": "PID_REUSED", "message": "created after started_at"}
            if p.get("image") and os.path.normcase(process.exe()) != os.path.normcase(p["image"]):
                return 409, {"code": "PID_REUSED", "message": "image differs"}
            process.suspend()
        except psutil.NoSuchProcess:
            return 409, {"code": "PID_GONE", "message": "gone"}
        with self.lock:
            self._n += 1
            lease_id = f"lease_{self._n}"
            self.leases[lease_id] = {
                "pid": pid, "incident_id": p["incident_id"], "state": "held",
                "lease_seconds": p["lease_seconds"], "expires_at": f"+{p['lease_seconds']}s",
                "request": p,
            }
            self._by_pid[pid] = lease_id
        return 200, {"lease_id": lease_id, "process_id": pid, "suspended": True,
                     "expires_at": f"+{p['lease_seconds']}s", "already_held": False,
                     "incident_id": p["incident_id"], "lease_seconds": p["lease_seconds"]}

    def _resume(self, p: dict) -> tuple[int, dict]:
        with self.lock:
            lease_id = p.get("lease_id") or self._by_pid.get(p.get("process_id"))
            lease = self.leases.get(lease_id)
            if lease is None:
                return 200, {"lease_id": lease_id, "resumed": False, "state": "unknown"}
            if lease["state"] != "held":
                return 200, {"lease_id": lease_id, "resumed": False, "state": lease["state"]}
            lease["state"] = "resumed"
            pid = lease["pid"]
        try:
            psutil.Process(pid).resume()
        except psutil.NoSuchProcess:
            pass
        return 200, {"lease_id": lease_id, "resumed": True, "state": "resumed", "process_id": pid}

    def _terminate(self, p: dict) -> tuple[int, dict]:
        pid = p["process_id"]
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return 409, {"code": "TERMINATION_REFUSED"}
        # The real service kills a suspended process the same way.
        process.kill()
        try:
            process.wait(timeout=5)
        except psutil.Error:
            pass
        with self.lock:
            lease_id = p.get("lease_id") or self._by_pid.get(pid)
            if lease_id in self.leases and self.leases[lease_id]["state"] == "held":
                self.leases[lease_id]["state"] = "terminated"
        return 200, {"status": "terminated", "process_id": pid, "method": "sigterm",
                     "lease_id": lease_id, "lease_released": bool(lease_id)}
