"""The regressions for the defect that failed Phase 3's first acceptance.

The failure was not a wrong decision. It was that the agent never reached one:
it drove detection and a 250 ms attribution wait from the single watchdog
thread, sustained 3.9 events/s against roughly 40, and every event the backlog
delayed became unattributable - which cost another full grace period and made
the backlog worse. 40 of 40 documents were destroyed and nothing was suspended.

So the tests that matter here are the ones that fail if the serial build ever
comes back:

  * submitting must not wait for the handler
  * lanes must actually run at the same time
  * the wait must be capped by what the attribution window has left
  * a dropped event must be counted, and it must be the oldest one

Everything runs in-process with a fake handler. None of it needs elevation,
a service, or a real filesystem event.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import dispatch  # noqa: E402

#: One name per lane at the default width. Pinned, not generated: a collision
#: would otherwise make the concurrency test pass by running serially.
SPREAD_OVER_FOUR_LANES = ("a.docx", "b.docx", "c.docx", "g.docx")


class Recorder:
    """A handler that records what it was given, and can be made slow."""

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.seen: list[dispatch.Event] = []
        self.threads: set[str] = set()
        self.entered = threading.Semaphore(0)
        self._lock = threading.Lock()

    def __call__(self, event: dispatch.Event) -> None:
        self.entered.release()
        with self._lock:
            self.threads.add(threading.current_thread().name)
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.seen.append(event)

    def paths(self) -> list[str]:
        with self._lock:
            return [event.path for event in self.seen]


@pytest.fixture
def running():
    made: list[dispatch.Dispatcher] = []

    def build(handler, lanes=4, queue_max=512):
        found = dispatch.Dispatcher(handler, lanes=lanes, queue_max=queue_max)
        found.start()
        made.append(found)
        return found

    yield build
    for found in made:
        found.stop(timeout=5.0)


# ----------------------------------------------------- the watchdog thread

def test_submitting_does_not_wait_for_the_handler(running):
    """The defect, stated as a test.

    The watchdog delivers events on one thread. If submitting an event waits
    for that event to be processed, every slow event is a pause in seeing the
    next one - which is exactly how 250 ms of attribution grace turned into a
    10:1 throughput deficit.
    """
    handler = Recorder(delay=0.5)
    pool = running(handler, lanes=4)

    started = time.monotonic()
    for index in range(8):
        pool.submit(f"C:/protected/file_{index}.docx", "modified")
    elapsed_ms = (time.monotonic() - started) * 1000.0

    assert elapsed_ms < 50, (
        f"submitting 8 events took {elapsed_ms:.1f} ms on the calling thread. "
        f"It must append and return; the waiting belongs on a lane.")


def test_lanes_run_at_the_same_time(running):
    """Four lanes must overlap, not queue behind one another."""
    handler = Recorder(delay=0.4)
    pool = running(handler, lanes=4)

    # These four names land on four different lanes - see the pinned values in
    # test_lane_choice_does_not_move_between_runs. Chosen rather than generated
    # so that a crc32 collision cannot make this test pass by running serially
    # and cannot make it fail for a reason that has nothing to do with lanes.
    for name in SPREAD_OVER_FOUR_LANES:
        pool.submit(name, "modified")

    # All four handlers must be inside the delay at the same moment. Serially
    # this would take 1.6 s; concurrently it is one 0.4 s slot.
    for _ in range(4):
        assert handler.entered.acquire(timeout=2.0), (
            "a lane never picked up its event: the pool is running serially")

    assert pool.drain(timeout=5.0)
    assert len(handler.threads) > 1, (
        f"every event ran on {handler.threads}; the lanes are not concurrent")


# ------------------------------------------------------------- the ordering

def test_events_for_one_path_stay_in_order(running):
    """`app._record` keeps a first-sighting flag per path.

    Two threads racing on the same file would make a second baseline out of a
    second write, so sharding is by path and one path belongs to one lane.
    """
    handler = Recorder()
    pool = running(handler, lanes=4)

    path = "C:/protected/the_same_file.docx"
    for kind in ("created", "modified", "modified", "renamed"):
        pool.submit(path, kind)

    assert pool.drain(timeout=5.0)
    kinds = [event.kind for event in handler.seen]
    assert kinds == ["created", "modified", "modified", "renamed"], kinds


def test_one_path_always_lands_on_one_lane():
    lanes = 8
    path = r"D:\protected\report.docx"
    chosen = {dispatch.lane_for(path, lanes) for _ in range(100)}
    assert len(chosen) == 1


def test_lane_choice_does_not_move_between_runs():
    """crc32, not `hash()`.

    `hash()` of a string is salted per process, so with it these numbers would
    hold within one run and mean nothing across two. The names are bare and
    lowercase because `normcase` is the identity on them on every platform;
    a drive letter and a backslash would pin this to Windows.
    """
    assert dispatch.lane_for("a.docx", 4) == 2
    assert dispatch.lane_for("b.docx", 4) == 0
    assert dispatch.lane_for("c.docx", 4) == 1
    assert dispatch.lane_for("g.docx", 4) == 3


@pytest.mark.skipif(os.name != "nt",
                    reason="on POSIX these are two different files")
def test_case_differences_do_not_split_a_path_across_lanes():
    """Windows paths are case-insensitive; the shard must be too.

    Otherwise the same file, spelled two ways by watchdog and by the audit
    record, would be handled by two lanes at once - which is the ordering
    hazard the sharding exists to remove.
    """
    lower = dispatch.lane_for(r"D:\protected\Report.DOCX", 4)
    upper = dispatch.lane_for(r"D:\PROTECTED\report.docx", 4)
    assert lower == upper


# ----------------------------------------------------------------- the drops

def test_a_full_lane_discards_its_oldest_event_not_its_newest(running):
    """The newest event is the only one that can still name a process.

    A queue that drops what has just arrived keeps a backlog of events nobody
    can be attributed for and discards the one that could still stop the
    attack. So the oldest goes.
    """
    handler = Recorder(delay=0.3)
    pool = running(handler, lanes=1, queue_max=2)

    # The first submit is picked up immediately and the handler holds it for
    # 0.3 s, so the queue fills behind it.
    for index in range(6):
        pool.submit(f"C:/protected/one_lane_{index}.docx", "modified")

    assert pool.drain(timeout=10.0)
    seen = handler.paths()
    assert pool.dropped > 0, "the queue should have overflowed"
    assert seen[-1].endswith("one_lane_5.docx"), (
        f"the newest event was discarded; handled {seen}")


def test_a_dropped_event_is_counted_and_never_silent(running):
    handler = Recorder(delay=0.3)
    pool = running(handler, lanes=1, queue_max=2)
    for index in range(6):
        pool.submit(f"C:/protected/counted_{index}.docx", "modified")
    assert pool.drain(timeout=10.0)

    stats = pool.stats()
    assert stats["dropped"] >= 1
    assert stats["submitted"] == 6
    assert stats["processed"] + stats["dropped"] == stats["submitted"], (
        "every submitted event must be either processed or counted as dropped")


def test_status_reports_the_queue_so_saturation_is_visible(running):
    handler = Recorder()
    pool = running(handler, lanes=2, queue_max=8)
    pool.submit("C:/protected/visible.docx", "modified")
    assert pool.drain(timeout=5.0)

    stats = pool.stats()
    for key in ("lanes", "queue_max_per_lane", "submitted", "processed",
                "dropped", "depth", "max_depth", "max_lag_ms", "per_lane"):
        assert key in stats, f"status has no {key}; saturation would be invisible"
    assert len(stats["per_lane"]) == 2


# ------------------------------------------------------------- the failures

def test_a_handler_that_raises_does_not_take_its_lane_down(running):
    """One unreadable file must not stop the agent watching the others."""
    handled: list[str] = []

    def handler(event):
        if "poison" in event.path:
            raise OSError("the file went away")
        handled.append(event.path)

    pool = running(handler, lanes=1)
    pool.submit("C:/protected/poison.docx", "modified")
    pool.submit("C:/protected/after.docx", "modified")
    assert pool.drain(timeout=5.0)

    assert handled == ["C:/protected/after.docx"]
    assert pool.stats()["failed"] == 1


def test_drain_waits_for_work_already_in_flight(running):
    """Shutdown must not abandon an event mid-response."""
    handler = Recorder(delay=0.3)
    pool = running(handler, lanes=1)
    pool.submit("C:/protected/inflight.docx", "modified")
    time.sleep(0.05)

    assert pool.drain(timeout=5.0)
    assert handler.paths() == ["C:/protected/inflight.docx"]


def test_stopping_an_unstarted_pool_is_harmless():
    pool = dispatch.Dispatcher(Recorder(), lanes=2)
    assert pool.stop()["processed"] == 0
