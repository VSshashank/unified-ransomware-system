"""Getting a filesystem event off the watchdog thread before it costs 250 ms.

Phase 3's acceptance failed here. Not because a signal was wrong - the canary
was written to exactly as designed, and the velocity tracker and the
shadow-copy guard have their regressions - but because the agent could not
consume events as fast as an attack produced them.

The arithmetic, measured on the host that ran it:

    detection                        5.9 ms
    attribution grace              251.7 ms
    -----------------------------------------------
    per unattributable event       257.6 ms  ->  3.9 events/s
    the attack produced                         ~40 events/s

A 10.3:1 deficit. `app.handle_event` resolves attribution inline, and
`Attributor.resolve` blocks its caller for the full grace period whenever no
4663 record matches. The agent drove `handle_event` from the single watchdog
dispatch thread, so one unattributable write cost a quarter of a second of the
only thread that processed events.

Worse, it is self-reinforcing. `WriteLog.lookup` measures its window backwards
from the moment of the lookup, so an event handled more than
ATTRIBUTION_WINDOW_MS after it happened can no longer match the audit record
that explains it: the record arrived on time and aged out while the event sat
in the backlog. Every event the backlog delays becomes unattributable, every
unattributable event pays the full grace, and the lag grows without bound.
That is why the acceptance saw 40 of 40 documents destroyed with nothing
suspended, and why the agent was still logging events from the run a full
minute after it finished.

This module is half of the fix: the watchdog thread appends and returns, and
the work happens on lanes.

It is only half. Lanes alone still failed, because a lane that blocks for a
second per unattributed write is four lanes at sixteen events a second, and a
burst produces hundreds. The other half is refusing to block at all -
`agent/pending.py` - which is where the measurement of what the Security
channel actually delivers, and when, is written down. Nothing here waits for
attribution any more; `Agent._process` asks with `grace_ms=0` and parks the
event if the answer has not arrived.

Lanes are sharded by path rather than taken round-robin, so every event for
one file is handled in order by one thread. `app._record`'s first-sighting
test and the entropy history are both per-path, and two threads racing on the
same path would manufacture a second baseline out of a second write.

When a lane is full the *oldest* queued event is dropped, not the newest. The
oldest is the one whose attribution window has already expired; it is worth
less than the event arriving now, which can still name a process. Drops are
counted, logged, and reported by `Agent.status()`. They are never silent: an
agent that quietly discards writes is an agent claiming a coverage it does not
have.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import zlib
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger("urds-agent.dispatch")

#: Lanes, and therefore the number of events that can be in detection at once.
#: Four rather than one per core: the work is a file read, a hash and an
#: entropy pass, so it is as much disk as CPU, and every extra lane is another
#: thread contending for the same GIL between those reads.
DEFAULT_LANES = 4

#: Events one lane will hold before it starts dropping the oldest.
DEFAULT_QUEUE_MAX = 512

#: How often a saturated dispatcher is allowed to say so, in seconds. Without
#: this the log line is itself a load source during the burst it describes.
DROP_LOG_INTERVAL_S = 2.0


@dataclass(frozen=True)
class Event:
    """One filesystem event, stamped when the watchdog handed it over."""

    path: str
    kind: str
    queued_at: float

    def age_ms(self, now: float | None = None) -> float:
        moment = time.monotonic() if now is None else now
        return (moment - self.queued_at) * 1000.0


def lane_for(path: str, lanes: int) -> int:
    """Which lane owns this path.

    crc32 over the normalised path rather than `hash()`: `hash()` of a string
    is salted per process, so the same path would land on a different lane on
    every run and the ordering guarantee would be untestable.
    """
    if lanes <= 1:
        return 0
    try:
        key = os.path.normcase(path)
    except (TypeError, ValueError):
        key = str(path)
    return zlib.crc32(key.encode("utf-8", "replace")) % lanes


class _Lane:
    """One worker thread and the queue only it reads."""

    def __init__(self, index: int, handler, queue_max: int) -> None:
        self.index = index
        self._handler = handler
        self._queue_max = max(1, int(queue_max))
        self._items: deque[Event] = deque()
        self._cv = threading.Condition()
        self._stopping = False
        self._busy = False
        self._thread: threading.Thread | None = None

        self.submitted = 0
        self.processed = 0
        self.dropped = 0
        self.failed = 0
        self.max_depth = 0
        self.max_lag_ms = 0.0
        self.last_lag_ms = 0.0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._stopping = False
        self._thread = threading.Thread(
            target=self._run, name=f"urds-lane-{self.index}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        with self._cv:
            self._stopping = True
            self._cv.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # -- the two ends ------------------------------------------------------

    def submit(self, event: Event) -> bool:
        """Append. Returns False if an older event had to be discarded first."""
        with self._cv:
            dropped = False
            if len(self._items) >= self._queue_max:
                self._items.popleft()
                self.dropped += 1
                dropped = True
            self._items.append(event)
            self.submitted += 1
            if len(self._items) > self.max_depth:
                self.max_depth = len(self._items)
            self._cv.notify()
        return not dropped

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._items and not self._stopping:
                    self._cv.wait(timeout=0.5)
                if self._stopping and not self._items:
                    return
                event = self._items.popleft()
                self._busy = True
            try:
                lag = event.age_ms()
                self.last_lag_ms = lag
                if lag > self.max_lag_ms:
                    self.max_lag_ms = lag
                self._handler(event)
            except Exception:  # noqa: BLE001 - one bad file cannot stop a lane
                self.failed += 1
                logger.exception("lane %d failed on %s", self.index, event.path)
            finally:
                with self._cv:
                    self._busy = False
                    self.processed += 1
                    self._cv.notify_all()

    # -- reporting ---------------------------------------------------------

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
            "dropped": self.dropped,
            "failed": self.failed,
            "depth": self.depth(),
            "max_depth": self.max_depth,
            "max_lag_ms": round(self.max_lag_ms, 3),
            "last_lag_ms": round(self.last_lag_ms, 3),
        }


class Dispatcher:
    """Path-sharded lanes between the watchdog and detection."""

    def __init__(self, handler, lanes: int = DEFAULT_LANES,
                 queue_max: int = DEFAULT_QUEUE_MAX) -> None:
        self.lane_count = max(1, int(lanes))
        self.queue_max = max(1, int(queue_max))
        self._lanes = [_Lane(i, handler, self.queue_max)
                       for i in range(self.lane_count)]
        self._running = False
        self._last_drop_log = 0.0
        self._drop_log_lock = threading.Lock()

    def start(self) -> None:
        if self._running:
            return
        for lane in self._lanes:
            lane.start()
        self._running = True
        logger.info("dispatch: %d lanes, %d events each",
                    self.lane_count, self.queue_max)

    def stop(self, timeout: float = 5.0) -> dict:
        if not self._running:
            return self.stats()
        for lane in self._lanes:
            lane.stop(timeout=timeout)
        self._running = False
        return self.stats()

    def submit(self, path: str, kind: str) -> bool:
        """Called on a watchdog thread. Appends and returns."""
        event = Event(path=path, kind=kind, queued_at=time.monotonic())
        lane = self._lanes[lane_for(path, self.lane_count)]
        accepted = lane.submit(event)
        if not accepted:
            self._note_drop()
        return accepted

    def _note_drop(self) -> None:
        now = time.monotonic()
        with self._drop_log_lock:
            if now - self._last_drop_log < DROP_LOG_INTERVAL_S:
                return
            self._last_drop_log = now
        logger.warning(
            "dispatch is saturated: %d events dropped so far. The oldest "
            "queued event is discarded first, because its attribution window "
            "has already expired. Writes are being missed.", self.dropped)

    def drain(self, timeout: float = 10.0) -> bool:
        """Wait until every lane is empty and idle. For tests and shutdown."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(lane.idle() for lane in self._lanes):
                return True
            time.sleep(0.01)
        return all(lane.idle() for lane in self._lanes)

    # -- reporting ---------------------------------------------------------

    @property
    def dropped(self) -> int:
        return sum(lane.dropped for lane in self._lanes)

    @property
    def processed(self) -> int:
        return sum(lane.processed for lane in self._lanes)

    @property
    def submitted(self) -> int:
        return sum(lane.submitted for lane in self._lanes)

    def depth(self) -> int:
        return sum(lane.depth() for lane in self._lanes)

    def stats(self) -> dict:
        lanes = [lane.stats() for lane in self._lanes]
        return {
            "running": self._running,
            "lanes": self.lane_count,
            "queue_max_per_lane": self.queue_max,
            "submitted": sum(item["submitted"] for item in lanes),
            "processed": sum(item["processed"] for item in lanes),
            "dropped": sum(item["dropped"] for item in lanes),
            "failed": sum(item["failed"] for item in lanes),
            "depth": sum(item["depth"] for item in lanes),
            "max_depth": max((item["max_depth"] for item in lanes), default=0),
            "max_lag_ms": max((item["max_lag_ms"] for item in lanes), default=0.0),
            "per_lane": lanes,
        }
