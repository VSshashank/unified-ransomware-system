"""Which writer a PROBABLE answer names, when several wrote the path.

Found by the elevated re-check on the Windows VM, 2026-10-04 (run
20261004_115048). The check encrypted a file and asked the Response service to
restore it as soon as the detection appeared. The restore opened the file for
writing 27 ms after the Monitor observed the encryption - inside the 50 ms
clock tolerance after the read, so it was rightly counted as a possible
competitor and the answer stayed PROBABLE with four candidates. But the answer
reported "the most recent" writer, which was the restore, so the event and the
ledger said the Response service had probably encrypted the file. The
encryptor, whose write preceded the observation, was only in the candidate
list.

A PROBABLE answer is never acted on (`kill_authorised` needs CERTAIN), so this
changes no response. It changes which PID the record names: the most recent
writer whose write preceded the observation - allowing one tick of the clock
`observed_at` is read on, since a precise TimeCreated can sit up to one tick
after it - and only if there is none, the most recent overall. The candidates,
the confidence and the reason's count are unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import attribution  # noqa: E402
from attribution import PROBABLE, AttributionSource, Attributor, ProcessFacts, WriteLog  # noqa: E402

PATH = r"C:\watched\report_2.txt"
ENCRYPTOR, RESTORER, EARLIER = 4604, 6388, 9508
IMAGE = r"C:\Python312\python.exe"
T0 = 1_791_093_661.685  # observed_at in the VM run
TICK = attribution.OBSERVATION_TICK_S


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class KernelSource(AttributionSource):
    name = "fake-4663"
    kernel_grade = True
    delivery_horizon_ms = 1500.0

    def start(self) -> bool:
        self.available = True
        return True


def build() -> Attributor:
    clock = Clock(T0 + 0.3)  # records arrive 300 ms after the observation, inside the horizon
    log = WriteLog(clock=clock)
    source = KernelSource(log)
    source.start()
    alive = lambda pid: ProcessFacts(pid=pid, image=IMAGE, created_at=T0 - 60)  # noqa: E731
    return Attributor(log=log, source=source, probe=alive, clock=clock)


def resolve(at: Attributor, read_at: float = T0 + 0.009):
    at.clock.now = T0 + 5.0  # every horizon long closed: the answer is final
    return at.resolve(PATH, observed_at=T0, read_at=read_at, horizon_from=read_at, grace_ms=0)


def test_a_restore_just_after_the_detection_is_a_candidate_but_not_the_one_named():
    at = build()
    at.log.record(PATH, EARLIER, IMAGE, written_at=T0 - 0.600)    # a benign edit
    at.log.record(PATH, ENCRYPTOR, IMAGE, written_at=T0 - 0.005)  # the write detected
    at.log.record(PATH, RESTORER, IMAGE, written_at=T0 + 0.027)   # the VM run's restore

    answer = resolve(at)

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {EARLIER, ENCRYPTOR, RESTORER}
    assert answer.pid == ENCRYPTOR, answer.reason
    assert answer.written_at == T0 - 0.005  # the evidence is the named writer's record
    assert answer.kill_authorised is False
    assert "3 processes" in answer.reason


def test_a_write_within_one_clock_tick_after_the_observation_still_preceded_it():
    """observed_at is read on the coarser clock, so it can trail a precise record."""
    at = build()
    at.log.record(PATH, EARLIER, IMAGE, written_at=T0 - 0.300)
    at.log.record(PATH, ENCRYPTOR, IMAGE, written_at=T0 + TICK / 2)

    answer = resolve(at)

    assert answer.confidence == PROBABLE
    assert answer.pid == ENCRYPTOR


def test_with_no_write_before_the_observation_the_most_recent_is_named():
    at = build()
    first, second = T0 + TICK + 0.005, T0 + TICK + 0.010
    at.log.record(PATH, ENCRYPTOR, IMAGE, written_at=first)
    at.log.record(PATH, RESTORER, IMAGE, written_at=second)

    answer = resolve(at, read_at=T0 + TICK + 0.020)

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {ENCRYPTOR, RESTORER}
    assert answer.pid == RESTORER


def test_the_tick_is_the_observation_clock_resolution():
    import time

    assert TICK == time.get_clock_info("time").resolution
    assert TICK * 1000.0 < attribution.CLOCK_TOLERANCE_MS
