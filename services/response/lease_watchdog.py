"""The out-of-process backstop: nothing stays frozen because Response died.

The lease table's reaper, the FastAPI shutdown hook and `atexit` all run inside
the Response service. None of them runs if that process is killed outright
(`taskkill /F`, `kill -9`, a crash in native code, the OOM killer), and a
process suspended at that moment would stay suspended until someone noticed.
"A crash must never leave a process frozen" needs something that is not the
process that crashed.

This is that something: a small child process started with the service. The
service tells it about every lease *before* suspending (`hold`) and when the
lease ends (`drop`), one JSON line each on the child's stdin. The child resumes
everything still held when:

  * its stdin reaches EOF - the service's end of the pipe closes when the
    service dies, however it dies;
  * the service's PID is gone (checked twice a second, as well as EOF);
  * a lease is still held `grace` seconds after its own expiry - the service is
    alive but its reaper is not doing its job.

Before resuming, it checks the PID is still the process the lease was taken on
(start time, else image), so a recycled PID is left alone.

What it cannot survive: being killed together with the service (`taskkill /T`,
a job object that kills the tree, `docker kill` of the container). That limit
is documented, not hidden; see docs/fixes_drafts/defect-26-e1.md.

Run as a script only by `Watchdog.start()`. Requires psutil, like the service.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

#: How long past a lease's own expiry the watchdog waits before resuming it on
#: its own. The service's reaper runs every 0.1 s, so in normal operation the
#: watchdog never acts on this; it is for a service that is alive but stuck.
WATCHDOG_GRACE_SECONDS = float(os.getenv("RESPONSE_WATCHDOG_GRACE_SECONDS", "2.0"))

#: How long `start()` waits for the child to say it is ready.
STARTUP_TIMEOUT_SECONDS = float(os.getenv("RESPONSE_WATCHDOG_STARTUP_SECONDS", "15"))


def _lease_error(code: str, message: str):
    from leases import LeaseError  # noqa: PLC0415 - avoid a cycle at import

    return LeaseError(code, message)


# ======================================================================== client


class Watchdog:
    """The service's handle on its watchdog.

    The watchdog is started through a short-lived intermediate process
    (`--detach`) that starts the real one and exits at once, so the watchdog
    is not a descendant of this service. A process-tree kill of the service
    (`taskkill /T /F`, which service wrappers such as NSSM do by default, or a
    kill of the process group on POSIX) then does not reach it. Measured on
    the test VM before this was done: a tree kill took the watchdog down with
    the service and the suspended process stayed frozen.
    """

    def __init__(self, grace: float = WATCHDOG_GRACE_SECONDS, python: str | None = None) -> None:
        self.grace = grace
        self.python = python or sys.executable
        self._pipe = None  # our end of the watchdog's stdin
        self._watch = None  # psutil.Process of the watchdog itself
        #: Guards the pipe and `_held`; only ever held briefly. `drop()` runs
        #: under the lease table's lock, so it must never wait for a spawn.
        self._lock = threading.Lock()
        #: Serialises spawns, which can take seconds; nothing else waits on it.
        self._spawn_lock = threading.Lock()
        #: lease_id -> (pid, started_at, image, monotonic deadline), so a
        #: respawned watchdog is told about everything still held.
        self._held: dict[str, tuple[int, float | None, str | None, float]] = {}

    def pids(self) -> set[int]:
        """The watchdog, and the venv launcher above it if there is one."""
        watch = self._watch
        if watch is None:
            return set()
        out = {watch.pid}
        try:
            parent = watch.parent()
            if parent is not None and parent.pid != os.getpid():
                out.add(parent.pid)
        except Exception:
            pass
        return out

    def alive(self) -> bool:
        watch = self._watch
        if watch is None or self._pipe is None:
            return False
        try:
            return watch.is_running()  # psutil: False if the PID was reused
        except Exception:
            return False

    def start(self) -> None:
        """Make sure it is running, spawning (and re-arming) it if not.

        The lease table calls this *outside* its own lock before every suspend
        (review finding R-RACE 5: a respawn under the table lock held up every
        expiry for up to 20 s).
        """
        with self._spawn_lock:
            if self.alive():
                return
            pipe, watch = self._launch()
            with self._lock:
                self._pipe, self._watch = pipe, watch
                # Re-arm a respawned watchdog with whatever is still held.
                now = time.monotonic()
                for lease_id, (pid, started_at, image, deadline) in self._held.items():
                    self._send({"op": "hold", "lease_id": lease_id, "pid": pid, "started_at": started_at,
                                "image": image, "seconds": max(0.0, deadline - now)})

    def hold(self, lease_id: str, pid: int, started_at: float | None, image: str | None, seconds: float) -> None:
        """Tell it about a lease. Never spawns: a dead watchdog refuses the suspend."""
        with self._lock:
            if not self.alive():
                raise _lease_error("WATCHDOG_UNAVAILABLE", "the lease watchdog is not running; refusing to "
                                   "suspend anything a crash of this service could leave frozen")
            deadline = time.monotonic() + seconds
            self._held[lease_id] = (pid, started_at, image, deadline)
            self._send({"op": "hold", "lease_id": lease_id, "pid": pid, "started_at": started_at,
                        "image": image, "seconds": seconds})

    def drop(self, lease_id: str) -> None:
        with self._lock:
            self._held.pop(lease_id, None)
            if self.alive():
                try:
                    self._send({"op": "drop", "lease_id": lease_id})
                except Exception as exc:  # best effort; it only means a harmless extra resume later
                    logger.warning("lease watchdog: drop %s not delivered: %s", lease_id, exc)

    def close(self) -> None:
        """Normal shutdown: close the pipe; the watchdog resumes what is left and exits."""
        with self._lock:
            pipe, self._pipe = self._pipe, None
            watch, self._watch = self._watch, None
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass
        if watch is not None:
            try:
                watch.wait(timeout=5)
            except Exception:
                try:
                    watch.kill()
                except Exception:
                    pass

    # -- internals ----------------------------------------------------------

    def _launch(self):
        """Start a watchdog and return (its stdin, its psutil.Process). Touches no state."""
        import psutil  # noqa: PLC0415 - a requirement of this service

        script = str(Path(__file__).resolve())
        try:
            starter = subprocess.Popen(
                [self.python, "-u", script, "--detach", "--parent", str(os.getpid()), "--grace", str(self.grace)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True,
                bufsize=1,
                cwd=str(Path(script).parent),
            )
        except OSError as exc:
            raise _lease_error("WATCHDOG_UNAVAILABLE", f"the lease watchdog could not be started: {exc}") from exc

        ready: queue.Queue = queue.Queue()
        threading.Thread(target=lambda: ready.put(starter.stdout.readline()), daemon=True).start()
        try:
            line = ready.get(timeout=STARTUP_TIMEOUT_SECONDS)
        except queue.Empty:
            line = ""
        try:
            starter.wait(timeout=5)  # the intermediate exits as soon as it has started the watchdog
        except subprocess.TimeoutExpired:
            starter.kill()
        watch = None
        if line.startswith("ready "):
            try:
                watch = psutil.Process(int(line.split()[1]))
            except (psutil.Error, ValueError):
                watch = None
        if watch is None:
            for stream in (starter.stdin, starter.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
            raise _lease_error(
                "WATCHDOG_UNAVAILABLE",
                f"the lease watchdog did not start (said {line.strip()!r}); refusing to suspend "
                "anything a crash of this service could leave frozen",
            )
        # Its stdout has served its purpose (the ready line). Its stdin stays
        # open for as long as this process lives; its closing is the signal.
        starter.stdout.close()
        return starter.stdin, watch

    def _send(self, message: dict) -> None:
        try:
            self._pipe.write(json.dumps(message) + "\n")
            self._pipe.flush()
        except (OSError, ValueError, AttributeError) as exc:
            raise _lease_error("WATCHDOG_UNAVAILABLE", f"the lease watchdog is not reachable: {exc}") from exc


# ======================================================================== child


def _same_process(process, started_at: float | None, image: str | None) -> bool:
    try:
        if started_at is not None:
            return abs(float(process.create_time()) - float(started_at)) < 0.01
        if image:
            return os.path.normcase(process.exe()) == os.path.normcase(image)
    except Exception:
        return False
    return True


def _resume(entry: dict, why: str) -> None:
    import psutil  # noqa: PLC0415

    pid = entry["pid"]
    try:
        process = psutil.Process(pid)
    except psutil.Error:
        _say(f"pid {pid} (lease {entry['lease_id']}) already gone; {why}")
        return
    if not _same_process(process, entry.get("started_at"), entry.get("image")):
        _say(f"pid {pid} is no longer the leased process; left alone ({why})")
        return
    try:
        process.resume()
        _say(f"resumed pid {pid} (lease {entry['lease_id']}): {why}")
    except psutil.Error as exc:
        _say(f"could not resume pid {pid} (lease {entry['lease_id']}): {exc}")


def _say(text: str) -> None:
    print(f"[lease-watchdog {os.getpid()}] {text}", file=sys.stderr, flush=True)


def _parent_alive(parent_pid: int, parent_created: float | None) -> bool:
    import psutil  # noqa: PLC0415

    try:
        process = psutil.Process(parent_pid)
        return parent_created is None or abs(process.create_time() - parent_created) < 0.01
    except psutil.Error:
        return False


def main(argv: list[str] | None = None) -> int:
    import psutil  # noqa: PLC0415 - fail here, before saying ready

    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", type=int, required=True)
    parser.add_argument("--grace", type=float, default=WATCHDOG_GRACE_SECONDS)
    parser.add_argument("--detach", action="store_true",
                        help="start the watchdog as a non-descendant and exit (see Watchdog)")
    args = parser.parse_args(argv)

    if args.detach:
        if os.name == "nt":
            options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            options = {"start_new_session": True}
        # The watchdog inherits this process's stdin and stdout, which are the
        # service's pipes. This process then exits, so the watchdog's parent
        # is gone and a tree kill rooted at the service does not find it.
        subprocess.Popen(
            [sys.executable, "-u", str(Path(__file__).resolve()),
             "--parent", str(args.parent), "--grace", str(args.grace)],
            stdin=sys.stdin, stdout=sys.stdout, cwd=str(Path(__file__).resolve().parent), **options,
        )
        return 0

    try:
        parent_created = psutil.Process(args.parent).create_time()
    except psutil.Error:
        return 2  # the service is already gone; nothing to watch

    lines: queue.Queue = queue.Queue()

    def read() -> None:
        for line in sys.stdin:
            lines.put(line)
        lines.put(None)  # EOF

    threading.Thread(target=read, daemon=True).start()
    print(f"ready {os.getpid()}", flush=True)

    held: dict[str, dict] = {}
    next_parent_check = time.monotonic()
    while True:
        try:
            line = lines.get(timeout=0.05)
        except queue.Empty:
            line = ""
        if line is None:
            for entry in list(held.values()):
                _resume(entry, "the Response service closed its end (exited or crashed)")
            return 0
        if line:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("op") == "hold":
                message["deadline"] = time.monotonic() + float(message.get("seconds") or 0) + args.grace
                held[message["lease_id"]] = message
            elif message.get("op") == "drop":
                held.pop(message.get("lease_id"), None)

        now = time.monotonic()
        for lease_id, entry in list(held.items()):
            if now >= entry["deadline"]:
                _resume(entry, f"still held {args.grace:.1f}s after the lease expired; "
                               "the service did not release it")
                held.pop(lease_id, None)
        if now >= next_parent_check:
            next_parent_check = now + 0.5
            if not _parent_alive(args.parent, parent_created):
                for entry in list(held.values()):
                    _resume(entry, "the Response service is gone")
                return 0


if __name__ == "__main__":
    sys.exit(main())
