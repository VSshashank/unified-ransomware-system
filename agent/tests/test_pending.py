"""The regressions for parking an event instead of blocking on attribution.

`scripts/measure_attribution_lag.py` measured the Security channel on a real
host and found delivery bounded near one second and independent of write rate -
a flush timer. The 250 ms blocking grace therefore caught a minority of records
at any rate and none at all under burst, while costing a quarter second of a
worker per unattributed write.

What replaces it has to hold four properties, and each has a test here that
fails if it is ever traded away:

  * an event whose writer is not yet known is parked, not decided on
  * it is acted on the moment the writer *is* known
  * if the writer is never known it is still acted on, as `unknown`
  * it is acted on exactly once, either way

The last one matters most. Responding twice to one write would put two
adjudications in the hash chain for one event, which is the shape of defect
this project has already had to correct once.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import pending  # noqa: E402


class Answers:
    """A stand-in for the audit log: says `unknown` until told otherwise."""

    def __init__(self) -> None:
        self._named: dict[str, int] = {}
        self.asked = 0
        self._lock = threading.Lock()

    def name(self, path: str, pid: int) -> None:
        with self._lock:
            self._named[path] = pid

    def __call__(self, path: str) -> dict:
        with self._lock:
            self.asked += 1
            pid = self._named.get(path)
        if pid is None:
            return {"process_id": None, "attribution_confidence": "unknown",
                    "attribution_reason": "no audited write yet"}
        return {"process_id": pid, "attribution_confidence": "certain",
                "attribution_reason": "exactly one process wrote this path"}


class Responses:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bool, int | None]] = []
        self._lock = threading.Lock()

    def __call__(self, parked: pending.Parked, attributed: bool) -> None:
        with self._lock:
            self.calls.append((parked.path, attributed,
                               parked.event.get("process_id")))

    def paths(self) -> list[str]:
        with self._lock:
            return [call[0] for call in self.calls]


@pytest.fixture
def running():
    made: list[pending.PendingAttribution] = []

    def build(resolve, respond, window_ms=3000.0, poll_ms=5.0, max_pending=4096):
        found = pending.PendingAttribution(
            resolve=resolve, respond=respond, window_ms=window_ms,
            poll_ms=poll_ms, max_pending=max_pending)
        found.start()
        made.append(found)
        return found

    yield build
    for found in made:
        found.stop(timeout=5.0)


def _wait_for(predicate, timeout=5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


# ------------------------------------------------------- the record arrives

def test_a_parked_event_is_acted_on_when_its_writer_is_named(running):
    """The whole point: the response fires when the record lands, not on a timer."""
    answers, responses = Answers(), Responses()
    queue = running(answers, responses)

    event = {"file_path": "x.docx", "suspicious": True}
    queue.add(event, "x.docx", "modified", time.monotonic(), canary_path=False)

    assert not _wait_for(lambda: responses.calls, timeout=0.2), (
        "responded before anybody was named")

    answers.name("x.docx", 4242)
    assert _wait_for(lambda: responses.calls), "never responded once named"

    path, attributed, pid = responses.calls[0]
    assert (path, attributed, pid) == ("x.docx", True, 4242)
    assert event["attribution_confidence"] == "certain"


def test_the_response_follows_the_record_closely(running):
    """Re-asking is cheap, so the delay must be the poll interval, not a wait."""
    answers, responses = Answers(), Responses()
    queue = running(answers, responses, poll_ms=10.0)

    queue.add({"suspicious": True}, "quick.docx", "modified",
              time.monotonic(), canary_path=False)
    time.sleep(0.05)

    named_at = time.monotonic()
    answers.name("quick.docx", 7)
    assert _wait_for(lambda: responses.calls)
    delay_ms = (time.monotonic() - named_at) * 1000.0

    assert delay_ms < 150, (
        f"took {delay_ms:.0f} ms to notice the record; the old inline grace "
        f"was 250 ms and this must beat it, not match it")


def test_the_window_is_carried_on_the_event_not_on_the_clock(running):
    """Expiry runs from when the write was queued, not from when it was parked."""
    answers, responses = Answers(), Responses()
    queue = running(answers, responses, window_ms=3000.0)

    # Queued two seconds ago: one second of window left, not three.
    queue.add({"suspicious": True}, "old.docx", "modified",
              time.monotonic() - 2.0, canary_path=False)
    assert _wait_for(lambda: responses.calls, timeout=2.0)
    assert responses.calls[0][1] is False


# --------------------------------------------------- the record never comes

def test_an_event_that_never_names_a_writer_is_still_acted_on(running):
    """Parking must not be a way for an event to disappear.

    The response for an unattributed event is `isolate_and_log` and no
    suspension - but it is a response, and it is recorded.
    """
    answers, responses = Answers(), Responses()
    queue = running(answers, responses, window_ms=200.0)

    event = {"suspicious": True}
    queue.add(event, "orphan.docx", "modified", time.monotonic(),
              canary_path=False)

    assert _wait_for(lambda: responses.calls, timeout=3.0)
    path, attributed, pid = responses.calls[0]
    assert (path, attributed, pid) == ("orphan.docx", False, None)
    assert event["attribution_confidence"] == "unknown"


def test_an_event_is_acted_on_exactly_once(running):
    """Two adjudications for one write is the defect class this project corrected."""
    answers, responses = Answers(), Responses()
    queue = running(answers, responses, window_ms=300.0, poll_ms=5.0)

    answers.name("once.docx", 11)
    queue.add({"suspicious": True}, "once.docx", "modified", time.monotonic(),
              canary_path=False)

    assert _wait_for(lambda: responses.calls)
    time.sleep(0.5)          # well past the window, so expiry would also fire
    assert responses.paths().count("once.docx") == 1


def test_stopping_responds_to_whatever_is_still_parked():
    """"The agent stopped" must not read as "the agent found these fine"."""
    answers, responses = Answers(), Responses()
    queue = pending.PendingAttribution(
        resolve=answers, respond=responses, window_ms=60_000.0, poll_ms=5.0)
    queue.start()
    queue.add({"suspicious": True}, "inflight.docx", "modified",
              time.monotonic(), canary_path=False)
    time.sleep(0.05)

    stats = queue.stop(timeout=5.0)
    assert responses.paths() == ["inflight.docx"]
    assert responses.calls[0][1] is False
    assert stats["expired_without_a_writer"] == 1


# --------------------------------------------------------------- the limits

def test_a_full_queue_discards_its_oldest_and_still_responds_to_it(running):
    """The oldest is closest to expiring, so it is the one least likely to resolve.

    Discarding it is a judgement about which event is worth holding, not a
    licence to lose it: the discarded event is responded to on the way out.
    """
    answers, responses = Answers(), Responses()
    queue = running(answers, responses, window_ms=60_000.0, max_pending=2)

    for index in range(4):
        queue.add({"suspicious": True}, f"f{index}.docx", "modified",
                  time.monotonic(), canary_path=False)

    assert _wait_for(lambda: len(responses.calls) >= 2)
    assert queue.stats()["dropped"] == 2
    assert responses.paths()[:2] == ["f0.docx", "f1.docx"], responses.paths()


def test_a_resolver_that_raises_does_not_stop_the_sweep(running):
    responses = Responses()
    state = {"fail": True}

    def resolve(path):
        if state["fail"]:
            raise OSError("the log went away")
        return {"process_id": 9, "attribution_confidence": "certain"}

    queue = running(resolve, responses, window_ms=60_000.0, poll_ms=5.0)
    queue.add({"suspicious": True}, "flaky.docx", "modified",
              time.monotonic(), canary_path=False)
    time.sleep(0.1)
    assert not responses.calls

    state["fail"] = False
    assert _wait_for(lambda: responses.calls)
    assert responses.calls[0][2] == 9
    assert queue.stats()["failed"] > 0


def test_stats_report_what_was_parked_and_what_became_of_it(running):
    answers, responses = Answers(), Responses()
    queue = running(answers, responses, window_ms=150.0, poll_ms=5.0)

    answers.name("named.docx", 3)
    queue.add({"suspicious": True}, "named.docx", "modified",
              time.monotonic(), canary_path=False)
    queue.add({"suspicious": True}, "nameless.docx", "modified",
              time.monotonic(), canary_path=False)

    assert _wait_for(lambda: len(responses.calls) >= 2, timeout=3.0)
    stats = queue.stats()
    assert stats["parked"] == 2
    assert stats["resolved_by_re_asking"] == 1
    assert stats["expired_without_a_writer"] == 1
    assert stats["resolve_lag_ms_median"] is not None
