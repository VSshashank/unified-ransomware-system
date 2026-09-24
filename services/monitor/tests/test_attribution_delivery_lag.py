"""Defect 1 of the Windows integration test: the audit record arrives ~1 s late.

The VM measured the Security channel delivering 4663 to the Monitor's push
subscription 390-1032 ms after the write, median 1000 ms (35 writes). The
Monitor waited 250 ms, so a fresh write was attributed 0 times in 35; and the
attributions it did make were taken from the *previous* write's record, which
is what a record delivered "now" is, by that measurement.

What has to hold after the fix, each asserted below:

    1. a record that arrives up to ~1.5 s late, stamped with the write's own
       TimeCreated, still correlates CERTAIN when it is the only writer   (a, b)
    2. nothing is CERTAIN before the delivery horizon closes, so two writers
       whose records land in different flushes are never CERTAIN         (a, b)
    3. a stale record - a previous write, ~1 s earlier - is not evidence   (a)
    4. the escalated kill is requested inside the 2 s response budget      (b, e)
    5. a writer that exited, or whose PID now names another process, is
       never killed, and the reason is recorded                           (c, d)
    6. the escalation is a *new* ledger block, joined by incident ID       (d, e)

Most of this is decision logic and runs on an injected clock, so it neither
sleeps nor depends on a scheduler. Sections (b) and (e) run in real time on
purpose: the delivery lags in the brief (0/300/1000/1600 ms) are the thing
under test, and the real sweeper thread is what has to close on time.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import (  # noqa: E402
    CERTAIN,
    PROBABLE,
    UNKNOWN,
    AttributionSource,
    Attributor,
    PendingAttribution,
    ProbeUnavailable,
    ProcessFacts,
    WriteLog,
    parse_4663,
    same_image,
)

RANSOM = r"C:\watched\quarterly.xlsx"
OTHER = r"C:\watched\holiday_photos.zip"
LOCKER = r"C:\Temp\locker.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"

ATTACKER = 4242
BENIGN = 1717

HORIZON_MS = 1500.0
T0 = 1_790_000_000.0  # an arbitrary instant on the system clock


class Clock:
    """A system clock the test moves by hand."""

    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class LaggingKernelSource(AttributionSource):
    """What the Security channel does: kernel-grade, and late.

    Each record is stamped with the write's own time and handed to the log
    `lag_ms` after it - on a timer, so in the real-time tests it arrives while
    the Monitor is already waiting, the way a 4663 does.
    """

    name = "fake-lagging-4663"
    kernel_grade = True
    delivery_horizon_ms = HORIZON_MS

    def __init__(self, log: WriteLog) -> None:
        super().__init__(log)
        self._timers: list[threading.Timer] = []

    def start(self) -> bool:
        self.available = True
        return True

    def deliver(self, path: str, pid: int, image: str, written_at: float, lag_ms: float) -> None:
        timer = threading.Timer(
            lag_ms / 1000.0,
            lambda: self.log.record(path, pid, image, written_at=written_at),
        )
        timer.daemon = True
        timer.start()
        self._timers.append(timer)

    def cancel(self) -> None:
        for timer in self._timers:
            timer.cancel()


def alive_as(image: str, created_at: float):
    """A probe that finds the writer still running, started before the write."""
    return lambda pid: ProcessFacts(pid=pid, image=image, created_at=created_at)


def build(clock=None, probe=None, horizon_ms: float = HORIZON_MS, maxlen: int = attribution.MAX_ENTRIES):
    log = WriteLog(maxlen=maxlen, clock=clock)
    source = LaggingKernelSource(log)
    source.delivery_horizon_ms = horizon_ms
    source.start()
    return Attributor(log=log, source=source, probe=probe or alive_as(LOCKER, T0 - 60), clock=clock)


# ---------------------------------------------- (a) event-time matching, on a clock


def test_a_a_late_record_stamped_with_its_own_time_is_certain_once_the_horizon_closes():
    clock = Clock(T0 + 0.3)
    at = build(clock=clock)
    # Written 5 ms before watchdog reported it; delivered whenever - it is the
    # TimeCreated that places it, not the arrival.
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)

    early = at.resolve(RANSOM, observed_at=T0, read_at=T0 + 0.01, horizon_from=T0 + 0.01, grace_ms=0)
    assert early.confidence == PROBABLE and early.pending, early.reason
    assert early.kill_authorised is False

    clock.now = T0 + 0.01 + (attribution.CLOCK_TOLERANCE_MS + HORIZON_MS) / 1000.0 + 0.001
    final = at.resolve(RANSOM, observed_at=T0, read_at=T0 + 0.01, horizon_from=T0 + 0.01, grace_ms=0)
    assert final.confidence == CERTAIN, final.reason
    assert final.pid == ATTACKER and final.image == LOCKER
    assert final.kill_authorised is True


def test_a_a_single_writer_is_never_certain_before_the_horizon_closes():
    clock = Clock(T0)
    at = build(clock=clock)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)
    settle = T0 + (attribution.CLOCK_TOLERANCE_MS + HORIZON_MS) / 1000.0

    for moment in (T0, T0 + 0.3, T0 + 1.0, settle - 0.001):
        clock.now = moment
        answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)
        assert answer.confidence != CERTAIN, f"CERTAIN at +{(moment - T0) * 1000:.0f}ms"
        assert answer.pending is True
        assert answer.settle_at == pytest.approx(settle)


def test_a_a_stale_record_from_the_previous_write_is_not_evidence():
    """The VM's reboot run: the only record in hand was the write ~1 s earlier."""
    clock = Clock(T0)
    at = build(clock=clock)
    # Written a second before the event, delivered just as it was observed.
    at.log.record(RANSOM, BENIGN, NOTEPAD, written_at=T0 - 1.0)

    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0 + 0.01, horizon_from=T0 + 0.01, grace_ms=0)

    assert answer.confidence == UNKNOWN, answer.reason
    assert answer.pid is None
    assert answer.pending is False  # horizon long closed: this is final


def test_a_a_previous_writer_inside_the_competition_window_blocks_certain():
    """B wrote 2 s before A overwrote the file: A is likely, not certain."""
    clock = Clock(T0 + 0.3)
    at = build(clock=clock)
    at.log.record(RANSOM, BENIGN, NOTEPAD, written_at=T0 - 2.0)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)

    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0 + 0.01, horizon_from=T0 + 0.01, grace_ms=0)

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {BENIGN, ATTACKER}
    assert answer.pid == ATTACKER  # reported, never acted on
    assert answer.kill_authorised is False


def test_a_two_writers_are_final_probable_at_once():
    """More records can only add writers, so this answer does not wait."""
    clock = Clock(T0 + 0.1)
    at = build(clock=clock)
    at.log.record(RANSOM, BENIGN, NOTEPAD, written_at=T0 - 0.010)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)

    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)

    assert answer.confidence == PROBABLE and answer.pending is False
    assert at.should_park(answer) is False


def test_a_a_write_after_the_bytes_were_read_is_not_this_events_writer():
    clock = Clock(T0 + 0.6)
    at = build(clock=clock)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 + 0.5)

    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0 + 0.02, horizon_from=T0 + 0.02, grace_ms=0)

    assert answer.confidence == UNKNOWN


def test_a_a_write_between_the_notification_and_the_read_counts():
    """The read saw its bytes, so it is part of what was judged."""
    clock = Clock(T0 + 0.3)
    at = build(clock=clock)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 + 0.020)

    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0 + 0.030, horizon_from=T0 + 0.030, grace_ms=0)

    assert answer.confidence == CERTAIN and answer.pid == ATTACKER


def test_a_a_record_delivered_after_the_horizon_is_not_an_answer():
    """Whether a late sweep happens to see it must not decide the question."""
    clock = Clock(T0 + 1.6)
    at = build(clock=clock)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)  # 1.6 s after the write

    clock.now = T0 + 1.7
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)

    assert answer.confidence == UNKNOWN and answer.pending is False, answer.reason
    assert "none arrived within the 1500ms delivery horizon" in answer.reason


def test_a_a_late_competitor_still_lowers_confidence():
    """The asymmetry: too late to answer, never too late to object."""
    clock = Clock(T0 + 0.3)
    at = build(clock=clock)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)
    clock.now = T0 + 1.7
    at.log.record(RANSOM, BENIGN, NOTEPAD, written_at=T0 - 0.010)

    clock.now = T0 + 1.8
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {BENIGN, ATTACKER}


def test_a_an_evicted_competitor_blocks_certain():
    """A full buffer may have dropped the second writer; that is not "none"."""
    clock = Clock(T0 + 0.3)
    at = build(clock=clock, maxlen=3)
    at.log.record(RANSOM, BENIGN, NOTEPAD, written_at=T0 - 2.0)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)
    at.log.record(OTHER, 1, None, written_at=T0 - 0.004)
    at.log.record(OTHER, 2, None, written_at=T0 - 0.003)  # evicts BENIGN's record

    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)

    assert at.log.evicted == 1
    assert answer.confidence == PROBABLE, answer.reason
    assert "evicted" in answer.reason
    assert answer.kill_authorised is False


def test_a_an_eviction_older_than_the_competition_window_does_not_block():
    clock = Clock(T0 + 0.3)
    at = build(clock=clock, maxlen=2)
    at.log.record(OTHER, 1, None, written_at=T0 - 60.0)
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=T0 - 0.005)
    at.log.record(OTHER, 2, None, written_at=T0 - 0.004)  # evicts the minute-old one

    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)

    assert answer.confidence == CERTAIN, answer.reason


def test_a_the_first_look_charges_its_grace_from_the_observation():
    """An event that has already used its grace does not wait again."""
    at = build()
    started = time.perf_counter()
    answer = at.resolve(RANSOM, observed_at=time.time(), deadline=started - 1.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    assert answer.confidence == UNKNOWN and answer.pending is True
    assert elapsed_ms < 50, f"waited {elapsed_ms:.0f}ms past an expired deadline"


# ------------------------------------------------------------- the 4663 clock


def _event_xml(system_time: str | None = "2026-09-23T06:08:18.7812345Z", **fields) -> str:
    data = {
        "ObjectType": "File",
        "ObjectName": RANSOM,
        "AccessMask": "0x2",
        "ProcessId": "0x1092",
        "ProcessName": LOCKER,
    }
    data.update(fields)
    created = f'<TimeCreated SystemTime="{system_time}"/>' if system_time else ""
    rows = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f"<System><EventID>4663</EventID>{created}</System><EventData>{rows}</EventData></Event>"
    )


@pytest.mark.parametrize(
    "rendered, expected",
    [
        ("2026-09-23T06:08:18.7812345Z", 1790143698.7812345),
        ("2026-09-23T06:08:18.781234500Z", 1790143698.7812345),
        ("2026-09-23T06:08:18Z", 1790143698.0),
        ("2026-09-23T06:08:18.5+00:00", 1790143698.5),
    ],
)
def test_a_timecreated_is_read_from_the_system_block(rendered, expected):
    parsed = parse_4663(_event_xml(rendered))
    assert parsed["time_created"] == pytest.approx(expected, abs=1e-6)


@pytest.mark.parametrize("rendered", [None, "", "yesterday", "2026-09-23T06:08:18.78+05:30"])
def test_a_a_record_without_a_utc_event_time_is_not_recorded(rendered):
    """A late record with no time on it cannot be placed; stamping it with its
    arrival is precisely how the previous writer used to answer for the next."""
    log = WriteLog()
    source = attribution.SecurityLogSource(log)
    parsed = parse_4663(_event_xml(rendered))

    assert parsed is not None and parsed["time_created"] is None
    source.accept(parsed)

    assert len(log) == 0
    assert log.dropped_untimed == 1


def test_a_the_security_source_records_the_event_time_not_the_arrival():
    log = WriteLog()
    source = attribution.SecurityLogSource(log)
    source.accept(parse_4663(_event_xml("2026-09-23T06:08:18.7812345Z")))

    (write,) = list(log._writes)
    assert write.written_at == pytest.approx(1790143698.7812345, abs=1e-6)
    assert write.delivered_at > write.written_at  # stamped when the test ran, not at 06:08:18


def test_a_the_security_source_declares_the_measured_horizon():
    assert attribution.SecurityLogSource.kernel_grade is True
    assert attribution.SecurityLogSource.delivery_horizon_ms == attribution.HORIZON_MS


# ------------------------------------------------------------------ the defaults


def test_a_defaults_are_the_ones_the_measurement_justifies():
    """min 390 / median 1000 / max 1032 ms, and a 2 s response budget."""
    assert attribution.GRACE_MS == 0.0  # below the 390 ms minimum a grace catches nothing
    assert attribution.HORIZON_MS == 1500.0  # the 1032 ms maximum, plus margin
    assert attribution.HORIZON_MS > 1032.0
    assert attribution.WINDOW_MS == 750.0  # under the ~1 s rewrite the VM mistook for evidence
    assert attribution.COMPETITION_MS == 3000.0  # the fix/evidence-integrity window
    assert attribution.CLOCK_TOLERANCE_MS >= 2 * 15.625  # two ticks of GetSystemTimeAsFileTime

    # The escalated kill is requested at observation + tolerance + horizon; the
    # rest of the budget is one HTTP call and TerminateProcess (TC-07: 91 ms).
    escalation_at_s = (attribution.CLOCK_TOLERANCE_MS + attribution.HORIZON_MS) / 1000.0
    assert escalation_at_s + 0.091 < 2.0


def test_a_grace_window_and_horizon_are_configurable():
    env = {
        **os.environ,
        "ATTRIBUTION_GRACE_MS": "40",
        "ATTRIBUTION_WINDOW_MS": "500",
        "ATTRIBUTION_HORIZON_MS": "1200",
        "ATTRIBUTION_COMPETITION_MS": "2500",
        "ATTRIBUTION_CLOCK_TOLERANCE_MS": "30",
    }
    code = (
        "import attribution as a; "
        "print(a.GRACE_MS, a.WINDOW_MS, a.HORIZON_MS, a.COMPETITION_MS, "
        "a.CLOCK_TOLERANCE_MS, a.SecurityLogSource.delivery_horizon_ms)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=MONITOR_DIR, env=env, capture_output=True, text=True, check=True, timeout=60
    ).stdout.split()

    assert [float(v) for v in out] == [40.0, 500.0, 1200.0, 2500.0, 30.0, 1200.0]


# --------------------------------------------- (b) real delivery lags, real sweeper


def _open(at: Attributor, path: str, observed_at: float, observed_mono: float) -> attribution.Question:
    first = at.resolve(path, observed_at=observed_at, read_at=observed_at, horizon_from=observed_mono, grace_ms=0)
    assert first.confidence != CERTAIN, f"{path}: the first answer from a lagging source was CERTAIN"
    assert at.should_park(first), f"{path}: {first}"
    return at.question(
        key=f"inc_{Path(path).stem}",
        path=path,
        observed_at=observed_at,
        read_at=observed_at,
        first=first,
        horizon_from=observed_mono,
    )


def test_b_records_0_300_1000ms_late_escalate_to_certain_and_1600ms_late_does_not():
    at = build(probe=alive_as(LOCKER, time.time() - 60))
    closes: dict[str, tuple] = {}
    done = threading.Event()

    def on_closed(question, answer, outcome):
        closes[question.path] = (question, answer, outcome, time.perf_counter())
        if len(closes) == 4:
            done.set()

    pending = PendingAttribution(at, on_closed)
    pending.start()
    lags = {0: r"C:\watched\lag_0000.docx", 300: r"C:\watched\lag_0300.docx",
            1000: r"C:\watched\lag_1000.docx", 1600: r"C:\watched\lag_1600.docx"}
    observed, observed_mono = time.time(), time.perf_counter()
    try:
        for lag_ms, path in lags.items():
            at.source.deliver(path, ATTACKER, LOCKER, written_at=observed - 0.005, lag_ms=lag_ms)
        for path in lags.values():
            pending.add(_open(at, path, observed, observed_mono))
        assert done.wait(timeout=5.0), f"closed {sorted(closes)}"
    finally:
        pending.stop()
        at.source.cancel()

    for lag_ms in (0, 300, 1000):
        question, answer, outcome, closed_mono = closes[lags[lag_ms]]
        assert outcome == "verified", f"{lag_ms}ms: {outcome} - {answer.reason}"
        assert answer.confidence == CERTAIN and answer.pid == ATTACKER
        assert answer.kill_authorised is True
        # The escalation is due at the horizon and must fit the 2 s budget.
        elapsed_ms = (closed_mono - observed_mono) * 1000
        assert elapsed_ms < 1900, f"{lag_ms}ms closed at +{elapsed_ms:.0f}ms"
        assert closed_mono >= question.settle_mono, "closed before its horizon"

    _, answer, outcome, _ = closes[lags[1600]]
    assert outcome == "no_record", answer.reason
    assert answer.confidence == UNKNOWN and answer.kill_authorised is False


@pytest.mark.parametrize("first_lag, second_lag", [(300, 1000), (1000, 300), (0, 1200)])
def test_b_two_writers_in_different_flushes_are_never_certain(first_lag, second_lag):
    at = build(probe=alive_as(LOCKER, time.time() - 60))
    seen: list[attribution.Attribution] = []
    closed = threading.Event()
    result: dict = {}

    def on_closed(question, answer, outcome):
        result.update(answer=answer, outcome=outcome)
        closed.set()

    pending = PendingAttribution(at, on_closed)
    pending.start()
    observed, observed_mono = time.time(), time.perf_counter()
    try:
        at.source.deliver(RANSOM, BENIGN, NOTEPAD, written_at=observed - 0.010, lag_ms=first_lag)
        at.source.deliver(RANSOM, ATTACKER, LOCKER, written_at=observed - 0.005, lag_ms=second_lag)
        question = _open(at, RANSOM, observed, observed_mono)
        seen.append(question.first)
        pending.add(question)
        # Look at every answer along the way, not just the last one: "never
        # certain" has to hold at the moments in between as well.
        while not closed.wait(timeout=0.05):
            seen.append(at.recheck(question))
            assert time.time() - observed < 5.0
    finally:
        pending.stop()
        at.source.cancel()

    seen.append(result["answer"])
    assert all(answer.confidence != CERTAIN for answer in seen), [a.reason for a in seen if a.confidence == CERTAIN]
    assert result["outcome"] == "ambiguous"
    assert set(result["answer"].candidates) == {BENIGN, ATTACKER}
    assert result["answer"].kill_authorised is False


def test_b_even_a_record_already_in_hand_is_not_certain_on_the_first_look():
    at = build()
    observed = time.time()
    at.log.record(RANSOM, ATTACKER, LOCKER, written_at=observed - 0.005)

    first = at.resolve(RANSOM, observed_at=observed, read_at=observed)

    assert first.confidence == PROBABLE and first.pending
    assert first.kill_authorised is False
    assert at.should_park(first)


# ------------------------------------------------------- (c) identity at escalation


def _certain(written_at: float = T0 - 0.005, image: str | None = LOCKER):
    clock = Clock(T0 + 0.3)
    at = build(clock=clock)
    at.log.record(RANSOM, ATTACKER, image, written_at=written_at)
    clock.now = T0 + 5.0
    answer = at.resolve(RANSOM, observed_at=T0, read_at=T0, horizon_from=T0, grace_ms=0)
    assert answer.confidence == CERTAIN, answer.reason
    return at, answer


def test_c_the_same_process_still_running_is_verified():
    at, answer = _certain()
    at.probe = alive_as(LOCKER, T0 - 60)

    verified, outcome = at.verify(answer)

    assert outcome == "verified"
    assert verified.kill_authorised is True and verified.pid == ATTACKER
    assert "verified as the writer by image and start time" in verified.reason


def test_c_a_writer_that_exited_is_not_acted_on_and_says_why():
    at, answer = _certain()
    at.probe = lambda pid: None

    verified, outcome = at.verify(answer)

    assert outcome == "process_exited"
    assert verified.kill_authorised is False
    assert verified.confidence == PROBABLE
    assert "has exited" in verified.reason


def test_c_a_reused_pid_with_a_different_image_is_not_acted_on():
    at, answer = _certain()
    at.probe = alive_as(NOTEPAD, T0 - 60)

    verified, outcome = at.verify(answer)

    assert outcome == "pid_reused"
    assert verified.kill_authorised is False
    assert verified.pid is None and verified.confidence == UNKNOWN
    assert "reused" in verified.reason and NOTEPAD in verified.reason


def test_c_a_reused_pid_started_after_the_write_is_not_acted_on_even_with_the_same_image():
    """Two copies of the same binary: the image matches and still proves nothing."""
    at, answer = _certain()
    at.probe = alive_as(LOCKER, T0 + 0.4)

    verified, outcome = at.verify(answer)

    assert outcome == "pid_reused"
    assert verified.kill_authorised is False and verified.pid is None
    assert "created" in verified.reason


@pytest.mark.parametrize(
    "probe",
    [
        pytest.param(lambda pid: (_ for _ in ()).throw(ProbeUnavailable("access denied")), id="uninspectable"),
        pytest.param(lambda pid: ProcessFacts(pid=pid, image=None, created_at=None), id="nothing-readable"),
    ],
)
def test_c_an_unprovable_identity_is_not_acted_on(probe):
    at, answer = _certain()
    at.probe = probe

    verified, outcome = at.verify(answer)

    assert outcome == "identity_unverifiable"
    assert verified.kill_authorised is False


def test_c_a_start_time_alone_proves_identity_when_the_image_is_unreadable():
    at, answer = _certain()
    at.probe = lambda pid: ProcessFacts(pid=pid, image=None, created_at=T0 - 60)

    verified, outcome = at.verify(answer)

    assert outcome == "verified" and verified.kill_authorised is True


def test_c_image_paths_compare_the_way_windows_does():
    assert same_image(r"C:\Temp\Locker.EXE", "c:/temp/locker.exe")
    assert same_image(r"\\?\C:\Temp\locker.exe", r"C:\Temp\locker.exe")
    assert not same_image(r"C:\Temp\locker.exe", r"C:\Temp\locker2.exe")
    assert not same_image(None, LOCKER)


def test_c_a_non_certain_answer_is_not_probed_at_all():
    at = build(probe=lambda pid: pytest.fail("probed a PID the evidence did not authorise"))
    probable = attribution.Attribution(pid=ATTACKER, image=LOCKER, confidence=PROBABLE, reason="two writers")

    verified, outcome = at.verify(probable)

    assert outcome == "not_certain" and verified is probable


# ------------------------------------------------- (d) the gate, and the new block


class Capture:
    """Stands in for the ledger and the Response service."""

    def __init__(self, terminate_ok: bool = True) -> None:
        self.calls: list[tuple[str, dict, float]] = []
        self.terminate_ok = terminate_ok
        self._next_block = 100

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        self.calls.append((path, payload, time.perf_counter()))
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            self._next_block += 1
            return {"block_id": self._next_block}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["network_isolation_planned", "admin_notified"]}
        if path == "/response/terminate":
            if not self.terminate_ok:
                return None
            return {"status": "terminated", "process_id": payload["process_id"], "method": "sigterm",
                    "termination_time_ms": 12.5, "incident_id": payload["incident_id"]}
        return {}

    def posts(self, path: str) -> list[dict]:
        return [payload for p, payload, _ in self.calls if p == path]

    def blocks(self, event_type: str) -> list[dict]:
        return [payload["event_data"] for payload in self.posts("/ledger/log") if payload["event_type"] == event_type]


@pytest.fixture
def capture(monkeypatch):
    recorder = Capture()
    monkeypatch.setattr(pipeline, "_post", recorder)
    return recorder


def _question(at: Attributor, first: attribution.Attribution | None = None) -> attribution.Question:
    first = first or attribution.Attribution(
        pid=None, image=None, confidence=UNKNOWN, reason="no record yet", source=at.source.name, pending=True
    )
    return at.question(key="inc_7_evt_abc", path=RANSOM, observed_at=T0, read_at=T0, first=first, horizon_from=T0)


def test_d_an_escalation_requests_the_kill_and_writes_a_new_block_with_the_incident_id(capture):
    at, answer = _certain()
    at.probe = alive_as(LOCKER, T0 - 60)
    verified, outcome = at.verify(answer)
    event = {"event_id": "evt_abc", "file_path": RANSOM, "file_hash": "f" * 64}

    closed = pipeline.escalate(None, event, _question(at), verified, outcome)

    (terminate,) = capture.posts("/response/terminate")
    assert terminate["process_id"] == ATTACKER
    assert terminate["incident_id"] == "inc_7_evt_abc"

    (block,) = capture.blocks("attribution_escalation")
    assert block["incident_id"] == "inc_7_evt_abc"
    assert block["outcome"] == "verified" and block["result"] == "terminated"
    assert block["action_requested"] == "terminate_process"
    assert block["attribution_confidence"] == CERTAIN and block["process_id"] == ATTACKER
    assert block["initial_attribution_confidence"] == UNKNOWN
    assert block["audit_record"]["written_at"] == attribution.iso_utc(T0 - 0.005)
    assert block["response_dispatched_at"] is not None
    assert closed["result"] == "terminated"
    # Nothing else was written: the earlier blocks are not revisited.
    assert [p for p, _, _ in capture.calls] == ["/response/terminate", "/ledger/log"]


@pytest.mark.parametrize(
    "probe, outcome",
    [
        (lambda pid: None, "process_exited"),
        (alive_as(NOTEPAD, T0 - 60), "pid_reused"),
        (alive_as(LOCKER, T0 + 0.4), "pid_reused"),
    ],
)
def test_d_an_exited_or_reused_pid_is_recorded_and_never_reaches_the_response_service(capture, probe, outcome):
    at, answer = _certain()
    at.probe = probe
    verified, got = at.verify(answer)
    assert got == outcome

    pipeline.escalate(None, {"event_id": "evt_abc", "file_path": RANSOM}, _question(at), verified, got)

    assert capture.posts("/response/terminate") == []
    (block,) = capture.blocks("attribution_escalation")
    assert block["outcome"] == outcome
    assert block["result"] == "not_escalated"
    assert block["action_requested"] is None
    assert block["attribution_reason"] == verified.reason  # the reason is on the chain


@pytest.mark.parametrize(
    "answer",
    [
        attribution.Attribution(pid=ATTACKER, image=LOCKER, confidence=PROBABLE, reason="two writers"),
        attribution.Attribution(pid=ATTACKER, image=LOCKER, confidence=PROBABLE, reason="one so far", pending=True),
        attribution.Attribution(pid=None, image=None, confidence=CERTAIN, reason="no pid"),
        attribution.Attribution(pid=None, image=None, confidence=UNKNOWN, reason="nothing"),
    ],
    ids=["probable", "pending", "certain-without-pid", "unknown"],
)
def test_d_nothing_short_of_kill_authorised_reaches_terminate(capture, answer):
    assert pipeline.request_termination(None, "inc_1", answer) is None
    assert capture.calls == []


def test_d_a_refused_termination_is_recorded_as_refused(monkeypatch):
    recorder = Capture(terminate_ok=False)
    monkeypatch.setattr(pipeline, "_post", recorder)
    at, answer = _certain()
    at.probe = alive_as(LOCKER, T0 - 60)
    verified, outcome = at.verify(answer)

    closed = pipeline.escalate(None, {"event_id": "evt_abc", "file_path": RANSOM}, _question(at), verified, outcome)

    assert closed["result"] == "termination_refused_or_unreachable"
    (block,) = recorder.blocks("attribution_escalation")
    assert block["result"] == "termination_refused_or_unreachable"


# -------------------------------------- (e) end to end through handle_event, real time


@pytest.fixture
def live_monitor(monkeypatch, capture):
    """The real `handle_event` and pipeline, with a lagging kernel-grade source."""
    writer_started = time.time() - 60
    at = build(probe=alive_as(LOCKER, writer_started))
    monkeypatch.setattr(monitor_app, "attributor", at)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app._ensure_worker()
    yield at, capture
    at.source.cancel()
    if monitor_app._pending is not None:
        monitor_app._pending.stop(timeout=2.0)
        monitor_app._pending = None
    monitor_app._escalations.join()
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS.clear()
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_e_a_fresh_writer_is_isolated_at_once_and_killed_inside_two_seconds(live_monitor, tmp_path):
    at, capture = live_monitor
    target = tmp_path / "board_minutes.docx"

    written_at = time.time()
    target.write_bytes(os.urandom(64 * 1024))
    # Its 4663 turns up a second later, the way the VM measured it.
    at.source.deliver(str(target), ATTACKER, LOCKER, written_at=written_at, lag_ms=1000)
    observed_mono = time.perf_counter()
    event = monitor_app.handle_event(str(target), "modified")

    assert event["suspicious"] is True
    assert event["attribution_pending"] is True
    assert event["attribution_confidence"] != CERTAIN

    assert _wait_for(lambda: capture.posts("/response/terminate"), timeout=3.0), [c[0] for c in capture.calls]
    terminate_at = next(t for p, _, t in capture.calls if p == "/response/terminate")
    elapsed_ms = (terminate_at - observed_mono) * 1000
    assert elapsed_ms < 2000, f"kill requested at +{elapsed_ms:.0f}ms"

    # The first response was the non-destructive one, on the first answer.
    (trigger,) = capture.posts("/response/trigger")
    assert trigger["action_required"] == "isolate_and_log"
    (terminate,) = capture.posts("/response/terminate")
    assert terminate["process_id"] == ATTACKER
    assert terminate["incident_id"] == trigger["incident_id"]

    # Joined by incident ID, and written after the blocks of the first answer.
    assert _wait_for(lambda: capture.blocks("attribution_escalation"), timeout=1.0)
    (escalation,) = capture.blocks("attribution_escalation")
    assert escalation["incident_id"] == trigger["incident_id"]
    assert escalation["result"] == "terminated"
    (file_event,) = capture.blocks("file_event")
    assert file_event["attribution_pending"] is True
    order = [payload["event_type"] for payload in capture.posts("/ledger/log")]
    assert order.index("attribution_escalation") > order.index("file_event")

    # And the event on /monitor/events ends where the incident ended.
    assert _wait_for(lambda: event.get("attribution_escalation"), timeout=1.0)
    assert event["attribution_confidence"] == CERTAIN and event["process_id"] == ATTACKER
    assert event["attribution_escalation"]["initial_attribution_confidence"] != CERTAIN


def test_e_a_record_that_never_arrives_leaves_the_incident_isolated_and_says_so(live_monitor, tmp_path):
    at, capture = live_monitor
    target = tmp_path / "ledger_export.xlsx"
    target.write_bytes(os.urandom(64 * 1024))

    event = monitor_app.handle_event(str(target), "modified")
    assert event["attribution_pending"] is True

    assert _wait_for(lambda: capture.blocks("attribution_escalation"), timeout=3.0)
    (escalation,) = capture.blocks("attribution_escalation")
    assert escalation["outcome"] == "no_record"
    assert escalation["result"] == "not_escalated"
    assert capture.posts("/response/terminate") == []
    (trigger,) = capture.posts("/response/trigger")
    assert trigger["action_required"] == "isolate_and_log"


# ------------------------------------------ (f) nothing is built on the kill's path


def test_f_the_escalation_client_is_built_with_the_worker_not_when_a_question_closes(monkeypatch):
    """The first kill of a run used to pay for an HTTP client after the horizon.

    The escalation thread was started - and built its httpx.Client - only when
    the first question closed. Traced in test_e_a_fresh_writer...: 187 ms
    between the close and /response/terminate; an untraced run missed the 2 s
    budget at +2134 ms. Asserted here without a timing bound: the thread and
    its client exist before any question closes, and closing one builds none.
    """
    # A queue and a thread of this test's own: an escalation thread an earlier
    # test left running stays blocked on the old queue and never sees this one.
    monkeypatch.setattr(monitor_app, "_escalations", queue.Queue())
    monkeypatch.setattr(monitor_app, "_escalator", None)

    built: list[tuple[str, object]] = []
    real_client = httpx.Client

    def counting_client(*args, **kwargs):
        client = real_client(*args, **kwargs)
        built.append((threading.current_thread().name, client))
        return client

    monkeypatch.setattr(httpx, "Client", counting_client)
    used: list[tuple[str, object]] = []

    def escalate(client, event, question, answer, outcome):
        used.append((threading.current_thread().name, client))
        return {"result": "not_escalated", "block": None, "record": {"response_dispatched_at": None}}

    monkeypatch.setattr(pipeline, "escalate", escalate)

    monitor_app._ensure_worker()  # what /monitor/start calls
    escalator = monitor_app._escalator
    try:
        assert escalator is not None and escalator.is_alive()
        # Its client is built on its own thread, now, while nothing is due -
        # before this fix nothing was built here until a question closed.
        deadline = time.monotonic() + 10.0
        while not any(name == "monitor-escalation" for name, _ in built) and time.monotonic() < deadline:
            time.sleep(0.01)
        (escalation_client,) = [client for name, client in built if name == "monitor-escalation"]
        builds_before_close = len(built)

        answer = attribution._unattributed("no record arrived before the horizon closed", source="test")
        question = SimpleNamespace(context={"file_path": RANSOM}, first=answer)
        monitor_app._on_question_closed(question, answer, "no_record")
        monitor_app._escalations.join()

        # Closing the question built nothing: the escalation ran on the thread
        # started with the worker, with the client it built then.
        assert len(built) == builds_before_close
        assert used == [("monitor-escalation", escalation_client)]
    finally:
        monitor_app._escalations.put(None)
        if escalator is not None:
            escalator.join(timeout=5.0)
