"""A question that closes with no record says why it found none.

R22 rep 1 (2026-10-06 and 2026-10-07) twice left a fresh writer unidentified and so
unkilled: "no audited write to this path ... and none arrived within the 1500ms delivery
horizon". That sentence cannot tell a record that never came from one that came too late
or one that was stamped outside the window, and the three have different fixes. `miss_detail`
says which. It is evidence for whoever reads the ledger: no gate reads it, and it never
changes the answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))

import attribution  # noqa: E402
from attribution import UNKNOWN, WriteLog  # noqa: E402

PATH = r"C:\watch\victim.docx"
HORIZON_MS = 1500.0
EVENT = 1_000_000.0  # epoch seconds the Monitor observed the change


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def ask(log: WriteLog, clock: Clock, started: float):
    """The lookup a closing question makes: the horizon has passed since `started`."""
    return log.lookup(
        PATH,
        observed_at=EVENT,
        read_at=EVENT,
        horizon_ms=HORIZON_MS,
        horizon_from=started,
        clock_now=clock.now,
        source="test",
        kernel_grade=True,
    )


def closed_after_horizon(log: WriteLog, clock: Clock):
    started = clock.now
    clock.now += (HORIZON_MS + 400.0) / 1000.0
    return ask(log, clock, started)


def test_nothing_ever_delivered():
    clock = Clock()
    log = WriteLog(clock=clock)
    answer = closed_after_horizon(log, clock)
    assert answer.confidence == UNKNOWN and answer.pid is None
    assert "ever delivered" in answer.miss_detail


def test_a_record_that_arrived_after_the_horizon_is_named_as_late_and_is_still_not_an_answer():
    clock = Clock()
    log = WriteLog(clock=clock)
    started = clock.now
    clock.now += 2.2  # delivered 700 ms past the 1.5 s horizon (plus the tolerance)
    log.record(PATH, 4242, "writer.exe", written_at=EVENT - 0.1)
    answer = ask(log, clock, started)
    assert answer.confidence == UNKNOWN and answer.pid is None and not answer.kill_authorised
    assert "after the horizon" in answer.miss_detail and "4242" in answer.miss_detail


def test_a_record_older_than_the_window_is_named_as_old():
    clock = Clock()
    log = WriteLog(clock=clock)
    started = clock.now
    log.record(PATH, 4242, "writer.exe", written_at=EVENT - 2.0)  # inside competition, outside the 750 ms window
    clock.now += (HORIZON_MS + 400.0) / 1000.0
    answer = ask(log, clock, started)
    assert answer.confidence == UNKNOWN and answer.pid is None
    assert "older than the window" in answer.miss_detail


def test_a_record_far_from_the_event_reports_how_far():
    clock = Clock()
    log = WriteLog(clock=clock)
    started = clock.now
    log.record(PATH, 4242, "writer.exe", written_at=EVENT - 60.0)
    clock.now += (HORIZON_MS + 400.0) / 1000.0
    answer = ask(log, clock, started)
    assert answer.confidence == UNKNOWN and answer.pid is None
    assert "nearest record" in answer.miss_detail and "-60000ms" in answer.miss_detail


def test_a_question_still_open_has_no_detail_yet():
    clock = Clock()
    log = WriteLog(clock=clock)
    answer = ask(log, clock, clock.now)
    assert answer.pending is True
    assert answer.miss_detail is None


def test_a_matched_record_still_wins_and_carries_no_detail():
    clock = Clock()
    log = WriteLog(clock=clock)
    started = clock.now
    log.record(PATH, 4242, "writer.exe", written_at=EVENT - 0.1)
    clock.now += (HORIZON_MS + 400.0) / 1000.0
    answer = ask(log, clock, started)
    assert answer.pid == 4242 and answer.confidence == attribution.CERTAIN
    assert answer.miss_detail is None


def test_the_detail_is_not_part_of_the_answers_identity():
    a = attribution.Attribution(pid=None, image=None, confidence=UNKNOWN, reason="x", miss_detail="one")
    b = attribution.Attribution(pid=None, image=None, confidence=UNKNOWN, reason="x", miss_detail="two")
    assert a == b
    assert "miss_detail" not in a.as_event_fields()


def test_the_events_view_carries_the_miss_detail_with_the_escalation():
    import app as monitor_app

    event: dict = {}
    question = type("Q", (), {"first": attribution.Attribution(pid=None, image=None, confidence=UNKNOWN, reason="first")})()
    answer = attribution.Attribution(pid=None, image=None, confidence=UNKNOWN, reason="final")
    record = {"result": "not_escalated", "response_dispatched_at": None, "audit_miss": "no record for this path was ever delivered"}
    monitor_app._show_closed(event, question, answer, "no_record", record, None)
    assert event["attribution_escalation"]["audit_miss"].startswith("no record")
    record.pop("audit_miss")
    event2: dict = {}
    monitor_app._show_closed(event2, question, answer, "no_record", record, None)
    assert "audit_miss" not in event2["attribution_escalation"]
