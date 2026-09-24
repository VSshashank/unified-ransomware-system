"""Correlation off the watchdog thread, sharded by path - defect 3.

Watchdog delivers every filesystem event on one observer thread. Until this
module existed, `handle_event` ran on that thread from start to finish:
classification, then `attributor.resolve`, then the hand-off to the pipeline.
The resolve could wait up to the attribution grace for a 4663 that - as the VM
later measured - arrives about a second late, so every unattributable
suspicious event held the only thread that consumed events for the whole grace.

The Windows integration test measured what that costs. The locker family wrote
20 files in about 0.1 s; their detection events were stamped about 250 ms
apart, one grace each, and the last came at least 4.77 s after its write -
while `detection_latency_ms` reported 2-17 ms, because it is measured before
the wait. fix/evidence-integrity measured the same arithmetic on its agent:
5.9 ms of detection plus 251.7 ms of grace is 3.9 events/s against an attack
producing ~40/s, and `agent/dispatch.py` is its answer. This is that answer,
ported, with the parts that do not fit the Monitor changed:

  * **What moves.** Only correlation - the first attribution look and the
    hand-off to the ML -> ledger -> response fan-out. Classification stays on
    the observer thread: it is bounded (a 40 ms lock-retry budget per read; the
    VM measured a 3.4 ms median and a 46.4 ms maximum), and keeping it there
    keeps `/monitor/events` in the order watchdog reported, which one thread
    recording does by construction and several would not.
  * **Sharding.** By path, with crc32 rather than `hash()` (salted per process,
    so the lane a path lands on would change every run). Every event for one
    file is correlated and handed on in order by one thread, so a file's
    pipeline items reach `_work` in the order its events happened. A rename is
    sharded by its new name, the one whose state the event touches.
  * **A full lane does not drop.** The agent discards its oldest queued event,
    because there the oldest had already aged out of its attribution window.
    Here attribution is anchored to the event's own observation time and
    nothing ages out, and a dropped job would be a detection that never gets a
    response. A job that finds its lane full runs inline on the caller instead
    and is counted, so the worst case under a burst is the old behaviour for
    that one event, not a missing incident.
  * **Nothing here waits for attribution.** The lane calls `resolve` with a
    deadline of *observation + grace*, not *now + grace*. A job that sat in the
    queue has already spent part of its grace, so twenty jobs queued behind one
    another finish about one grace after the last was observed, not twenty
    graces later - on a single lane as much as on four. At the default grace
    of 0 ms (defect 1) no job waits at all.

THE 766 ms OVERRUN

One post-reboot event reported `attribution_waited_ms: 766` against a 250 ms
grace, cause unknown. It cannot be pinned from the code alone, so here is what
can be said. The loop could only exceed its deadline by one iteration unless its
thread was not scheduled: it looked, slept 10 ms, and looked again, and the
deadline test ran on every look. 766 is 49 ticks of `GetTickCount64`, the
15.625 ms clock `time.monotonic()` is on the test host's Python, so about
516 ms passed in which the observer thread did not get to look again. On the
reboot run's timeline that stretch (06:08:19.03 to 19.80) is when, at the
measured ~1 s lag, the 4663 records for the forty-odd decoy-creation writes
made at 18.30-18.43 would have been delivered and parsed, and it is when the
first pipeline run after the reboot started, on a 4-vCPU VM. Either is a
plausible way to keep one thread off the CPU for half a second; neither is
proven. What *is* established is that the old design turned whatever held that
thread directly into detection backlog, because the wait ran on the only thread
that consumes watchdog events.

So the fix removes the consequence, and makes a recurrence measurable instead
of mysterious: the wait no longer runs on the observer thread; its deadline is
anchored to the observation, so a late wake-up shortens the waits after it
instead of adding to them; it is a condition-variable wait woken by the write
log rather than a sleep-poll; `attribution_waited_ms` is measured on
`perf_counter` (100 ns) rather than `GetTickCount64`; and the event now carries
`attribution_wait_overrun_ms`, how far past its deadline the wait actually
returned, next to `queue_wait_ms`.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("monitor.dispatch")

#: Four, as fix/evidence-integrity settled on. A lane's work is a dictionary
#: lookup and a queue put at the default grace, so this is about isolation - a
#: slow path does not hold up the others - more than about throughput.
DEFAULT_LANES = int(os.getenv("MONITOR_CORRELATION_LANES", "4"))

#: Jobs one lane holds before the next one runs inline on the caller instead.
DEFAULT_QUEUE_MAX = int(os.getenv("MONITOR_CORRELATION_QUEUE_MAX", "512"))

#: How often a saturated dispatcher may say so, in seconds, so the warning is
#: not itself load during the burst it describes.
OVERFLOW_LOG_INTERVAL_S = 2.0


def lane_for(path: str, lanes: int) -> int:
    """Which lane owns this path. Deterministic across runs (crc32, not hash())."""
    if lanes <= 1:
        return 0
    try:
        key = os.path.normcase(path)
    except (TypeError, ValueError):
        key = str(path)
    return zlib.crc32(key.encode("utf-8", "replace")) % lanes


@dataclass
class Job:
    """One event's correlation work, stamped when it was handed over."""

    path: str
    #: Called on the lane with the milliseconds the job waited in the queue.
    run: Callable[[float], None]
    submitted: float = field(default_factory=time.perf_counter)


class _Lane:
    """One worker thread and the queue only it reads."""

    def __init__(self, index: int, queue_max: int) -> None:
        self.index = index
        self.queue_max = max(1, int(queue_max))
        self._items: deque[Job] = deque()
        self._cv = threading.Condition()
        self._stopping = False
        self._busy = False
        self._thread: threading.Thread | None = None

        self.submitted = 0
        self.processed = 0
        self.failed = 0
        self.max_depth = 0
        self.max_wait_ms = 0.0
        self.last_wait_ms = 0.0

    def start(self) -> None:
        with self._cv:
            self._stopping = False
        self._thread = threading.Thread(target=self._run, name=f"monitor-correlation-{self.index}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float) -> None:
        with self._cv:
            self._stopping = True
            self._cv.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def offer(self, job: Job) -> bool:
        """Queue the job. False if the lane is full or stopping."""
        with self._cv:
            if self._stopping or len(self._items) >= self.queue_max:
                return False
            self._items.append(job)
            self.submitted += 1
            self.max_depth = max(self.max_depth, len(self._items))
            self._cv.notify()
            return True

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._items and not self._stopping:
                    self._cv.wait(timeout=0.5)
                if not self._items and self._stopping:
                    return
                job = self._items.popleft()
                self._busy = True
            try:
                wait_ms = (time.perf_counter() - job.submitted) * 1000.0
                self.last_wait_ms = wait_ms
                self.max_wait_ms = max(self.max_wait_ms, wait_ms)
                job.run(wait_ms)
            except Exception:  # one bad file cannot stop a lane
                self.failed += 1
                logger.exception("correlation lane %d failed on %s", self.index, job.path)
            finally:
                with self._cv:
                    self._busy = False
                    self.processed += 1
                    self._cv.notify_all()

    def idle(self) -> bool:
        with self._cv:
            return not self._items and not self._busy

    def depth(self) -> int:
        with self._cv:
            return len(self._items)

    def stats(self) -> dict:
        return {
            "lane": self.index,
            "submitted": self.submitted,
            "processed": self.processed,
            "failed": self.failed,
            "depth": self.depth(),
            "max_depth": self.max_depth,
            "max_wait_ms": round(self.max_wait_ms, 3),
            "last_wait_ms": round(self.last_wait_ms, 3),
        }


class CorrelationLanes:
    """Path-sharded lanes between the watchdog thread and the pipeline."""

    def __init__(self, lanes: int = DEFAULT_LANES, queue_max: int = DEFAULT_QUEUE_MAX) -> None:
        self.lane_count = max(1, int(lanes))
        self.queue_max = max(1, int(queue_max))
        self._lanes = [_Lane(i, self.queue_max) for i in range(self.lane_count)]
        self._running = False
        self._lock = threading.Lock()
        self._last_overflow_log = 0.0
        self.inline = 0

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            for lane in self._lanes:
                lane.start()
            self._running = True
        logger.info("correlation: %d lanes, %d jobs each", self.lane_count, self.queue_max)

    def stop(self, timeout: float = 5.0) -> dict:
        """Finish what is queued, then stop. Queued detections still get a response."""
        self.drain(timeout=timeout)
        with self._lock:
            for lane in self._lanes:
                lane.stop(timeout=timeout)
            self._running = False
        return self.stats()

    def submit(self, path: str, run: Callable[[float], None]) -> bool:
        """Called on the watchdog thread. Queues and returns.

        Returns False when the job could not be queued - lanes not running, or
        this path's lane full - in which case it has already been run inline,
        with a queue wait of zero. Never drops it.
        """
        job = Job(path=path, run=run)
        lane = self._lanes[lane_for(path, self.lane_count)]
        if self._running and lane.offer(job):
            return True
        self.inline += 1
        if self._running:
            self._note_overflow()
        run(0.0)
        return False

    def _note_overflow(self) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_overflow_log < OVERFLOW_LOG_INTERVAL_S:
                return
            self._last_overflow_log = now
        logger.warning(
            "correlation lanes are saturated: %d jobs have run inline on the watchdog "
            "thread so far rather than be dropped",
            self.inline,
        )

    def drain(self, timeout: float = 10.0) -> bool:
        """Wait until every lane is empty and idle. For shutdown and tests."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(lane.idle() for lane in self._lanes):
                return True
            time.sleep(0.005)
        return all(lane.idle() for lane in self._lanes)

    def stats(self) -> dict:
        lanes = [lane.stats() for lane in self._lanes]
        return {
            "running": self._running,
            "lanes": self.lane_count,
            "queue_max_per_lane": self.queue_max,
            "submitted": sum(item["submitted"] for item in lanes),
            "processed": sum(item["processed"] for item in lanes),
            "failed": sum(item["failed"] for item in lanes),
            # Jobs that ran on the caller because their lane was full (or the
            # lanes were not running). Not dropped - counted.
            "ran_inline": self.inline,
            "depth": sum(item["depth"] for item in lanes),
            "max_depth": max((item["max_depth"] for item in lanes), default=0),
            "max_wait_ms": max((item["max_wait_ms"] for item in lanes), default=0.0),
            "per_lane": lanes,
        }
