"""TC-26 (AS): the offending process is named, and a guess never authorises a kill.

Until this row existed the project could terminate a process and could not find
one. `/response/terminate` really did SIGTERM then SIGKILL, guarded, in 91 ms -
and TC-07 proved it by handing in `victim.pid` from a process the test had
spawned itself. Nothing ever answered the other half of the question, so
`handle_event` set `process_id` to `None` for every filesystem detection and the
pipeline downgraded the response to `isolate_and_log`.

**So the row this file asserts is attribution, not termination.** TC-07 already
covers the kill. What was missing was evidence that the PID handed to it is the
right one, and evidence that a wrong-looking answer cannot reach it at all.

THE FOUR THINGS THAT HAVE TO HOLD

    1. the process that wrote the file is the process reported          (a, i)
    2. a process that wrote something else is never reported            (b)
    3. an ambiguous answer degrades - it does not round up to CERTAIN   (c, h)
    4. only CERTAIN asks for a kill; everything else isolates           (d, e, j, k)

Three and four are the safety argument and they are asserted from both ends:
at the `Attribution` level, where `kill_authorised` is computed, and at the
pipeline level, where `action_required` is chosen. A guard tested only at the
point it is defined is a guard that can be bypassed by the caller that matters.

WHY MOST OF THIS RUNS WITHOUT WINDOWS

CI is ubuntu-latest, and the real source is a Windows Security-channel
subscription needing Administrator. Splitting `parse_4663` out from the
subscription is what makes the parsing testable off Windows; driving `WriteLog`
directly is what makes the confidence logic testable anywhere. The one test that
needs a real elevated Windows host is marked `skipif` and says so - see
`test_tc26_i_*`.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import (  # noqa: E402
    CERTAIN,
    PROBABLE,
    UNKNOWN,
    Attributor,
    NullSource,
    WriteLog,
    parse_4663,
)

RANSOM = r"C:\watched\quarterly.xlsx"
OTHER = r"C:\watched\holiday_photos.zip"

ATTACKER_PID = 4242
BENIGN_PID = 1717


class FakeKernelSource(attribution.AttributionSource):
    """A live, kernel-grade source that records nothing on its own.

    Stands in for `SecurityLogSource` so the confidence logic can be driven
    from the test rather than from the Security channel. `kernel_grade` is True
    because that is the property under test in (h): it is what separates an
    observation from an inference, and CERTAIN is reachable only through it.
    """

    name = "fake-kernel"
    kernel_grade = True

    def start(self) -> bool:
        self.available = True
        return True


def build(kernel: bool = True, window_ms: float = 750) -> Attributor:
    log = WriteLog(window_ms=window_ms)
    source = FakeKernelSource(log)
    source.kernel_grade = kernel
    source.start()
    return Attributor(log=log, source=source)


# --------------------------------------------------------------- 1. it works


def test_tc26_a_the_writing_process_is_the_process_reported():
    at = build()
    at.log.record(RANSOM, ATTACKER_PID, image=r"C:\Temp\locker.exe")

    answer = at.resolve(RANSOM)

    assert answer.pid == ATTACKER_PID
    assert answer.image == r"C:\Temp\locker.exe"
    assert answer.confidence == CERTAIN
    assert answer.kill_authorised is True


def test_tc26_b_a_process_that_wrote_a_different_file_is_never_reported():
    """The false-positive direction, and the one that gets something killed."""
    at = build()
    at.log.record(OTHER, BENIGN_PID, image=r"C:\Program Files\7-Zip\7z.exe")

    answer = at.resolve(RANSOM, grace_ms=0)

    assert answer.pid is None
    assert answer.confidence == UNKNOWN
    assert answer.kill_authorised is False
    # And the benign writer is still attributable for its own path, so this is
    # a scoping result rather than the buffer simply being empty.
    assert at.resolve(OTHER).pid == BENIGN_PID


def test_tc26_b2_path_spelling_does_not_change_the_answer():
    """The audit record and watchdog do not agree on case or separators."""
    at = build()
    at.log.record(r"C:\Watched\Quarterly.XLSX", ATTACKER_PID)

    if os.name == "nt":
        assert at.resolve(RANSOM).pid == ATTACKER_PID
    else:
        # normcase is a no-op off Windows, so this asserts the weaker thing
        # that is true there: an exact match still resolves.
        assert at.resolve(r"C:\Watched\Quarterly.XLSX").pid == ATTACKER_PID


# ------------------------------------------------- 2. ambiguity degrades down


def test_tc26_c_two_writers_on_one_path_is_probable_not_certain():
    at = build()
    at.log.record(RANSOM, BENIGN_PID, image=r"C:\Windows\System32\notepad.exe")
    at.log.record(RANSOM, ATTACKER_PID, image=r"C:\Temp\locker.exe")

    answer = at.resolve(RANSOM)

    assert answer.confidence == PROBABLE
    assert set(answer.candidates) == {BENIGN_PID, ATTACKER_PID}
    # The most recent writer is reported, because it is the better guess - but
    # it is still only reported, never acted on.
    assert answer.pid == ATTACKER_PID
    assert answer.kill_authorised is False


def test_tc26_h_a_non_kernel_source_can_never_reach_certain():
    """An inference is not an observation, however unambiguous it looks."""
    at = build(kernel=False)
    at.log.record(RANSOM, ATTACKER_PID)

    answer = at.resolve(RANSOM)

    assert answer.pid == ATTACKER_PID
    assert answer.confidence == PROBABLE
    assert answer.kill_authorised is False
    assert "not a kernel-level source" in answer.reason


def test_tc26_f_a_write_older_than_the_window_is_not_evidence():
    at = build(window_ms=200)
    at.log.record(RANSOM, ATTACKER_PID, at=time.monotonic() - 5.0)

    answer = at.resolve(RANSOM, grace_ms=0)

    assert answer.confidence == UNKNOWN
    assert answer.pid is None


def test_tc26_g_the_monitor_never_attributes_a_write_to_itself():
    """A detector that can name itself is one hop from asking for its own death."""
    at = build()
    at.log.record(RANSOM, os.getpid(), image=sys.executable)

    answer = at.resolve(RANSOM, grace_ms=0)

    assert answer.pid is None
    assert answer.confidence == UNKNOWN
    assert os.getpid() in at.log.excluded


# ------------------------------------- 2b. a record older than the question
#
# The one confident *wrong* answer the system had, found by install.ps1's
# self-test in Phase 4 and fixed here because the fix changes TTS. Entries are
# stamped when the audit record was delivered, which trails the write; so a
# record delivered before the event was observed is a record of the *previous*
# write to that path, and answering with it names the wrong process with full
# confidence. docs/LIMITATIONS.md §3 has the measured instance.


def test_tc26_r_a_record_that_predates_the_event_is_not_evidence_for_it():
    """Block 16095's shape: A writes, then B overwrites while A's record stands."""
    at = build(window_ms=3000)
    now = time.monotonic()
    # A's record was delivered 1s ago - well inside the window.
    at.log.record(RANSOM, BENIGN_PID, image=r"C:\Windows\notepad.exe",
                  at=now - 1.0)
    # B overwrote the file 0.2s ago. Its record has not arrived.
    observed_at = now - 0.2

    answer = at.resolve(RANSOM, grace_ms=0, event_at=observed_at)

    assert answer.confidence == UNKNOWN, (
        "the only audited writer predates the event being judged, so it cannot "
        "be the writer of it")
    assert answer.pid is None, "naming it would be the same defect in another field"
    assert answer.kill_authorised is False
    assert "before this event was observed" in answer.reason


def test_tc26_r2_without_the_fix_that_same_evidence_reads_as_certain():
    """The old behaviour, asserted so the fix cannot be mistaken for a no-op."""
    at = build(window_ms=3000)
    now = time.monotonic()
    at.log.record(RANSOM, BENIGN_PID, at=now - 1.0)

    # Identical log, identical window - the only difference is that the caller
    # did not say when its event happened.
    answer = at.resolve(RANSOM, grace_ms=0)

    assert answer.confidence == CERTAIN
    assert answer.pid == BENIGN_PID


def test_tc26_r3_the_record_that_does_arrive_still_reaches_certain():
    """The cost is paid only by the events that were previously wrong."""
    at = build(window_ms=3000)
    now = time.monotonic()
    observed_at = now - 0.8
    at.log.record(RANSOM, BENIGN_PID, at=now - 1.5)   # A, before the event
    at.log.record(RANSOM, ATTACKER_PID, at=now - 0.1)  # B, after it

    answer = at.resolve(RANSOM, grace_ms=0, event_at=observed_at)

    # Two distinct writers in the window is PROBABLE by rule 3 above, and that
    # is the honest answer here - but the newest record now postdates the
    # event, so the lookup no longer refuses outright.
    assert answer.confidence == PROBABLE
    assert answer.pid == ATTACKER_PID

    # And with only B's record present, which is the ordinary case, it is
    # CERTAIN exactly as before.
    clean = build(window_ms=3000)
    clean.log.record(RANSOM, ATTACKER_PID, at=now - 0.1)
    named = clean.resolve(RANSOM, grace_ms=0, event_at=observed_at)
    assert named.confidence == CERTAIN
    assert named.pid == ATTACKER_PID


def test_tc26_r4_an_event_with_no_record_at_all_is_unchanged():
    """Nothing to reject, so the reason must still be the empty-log one."""
    at = build(window_ms=3000)

    answer = at.resolve(RANSOM, grace_ms=0, event_at=time.monotonic())

    assert answer.confidence == UNKNOWN
    assert "no audited write" in answer.reason


# ---------------------------------------------- 3. no source, no change at all


def test_tc26_e_without_a_source_every_answer_is_unknown():
    """The pre-attribution behaviour, preserved exactly."""
    log = WriteLog()
    at = Attributor(log=log, source=NullSource(log, "no source here"))
    at.log.record(RANSOM, ATTACKER_PID)

    answer = at.resolve(RANSOM)

    assert answer.confidence == UNKNOWN
    assert answer.pid is None
    assert answer.kill_authorised is False
    assert answer.reason == "no source here"


def test_tc26_e2_an_unavailable_source_does_not_burn_the_grace_period():
    """Waiting for a source that cannot deliver would cost the response budget."""
    log = WriteLog()
    at = Attributor(log=log, source=NullSource(log))

    started = time.monotonic()
    at.resolve(RANSOM, grace_ms=1000)
    elapsed_ms = (time.monotonic() - started) * 1000

    assert elapsed_ms < 50, f"returned in {elapsed_ms:.0f}ms; should not have waited"


def test_tc26_e3_a_live_source_with_nothing_to_say_waits_and_gives_up():
    at = build()

    started = time.monotonic()
    answer = at.resolve(RANSOM, grace_ms=120)
    elapsed_ms = (time.monotonic() - started) * 1000

    assert answer.confidence == UNKNOWN
    assert 100 <= elapsed_ms < 400, f"waited {elapsed_ms:.0f}ms; expected roughly the 120ms grace"
    assert answer.waited_ms > 0


def test_tc26_e4_a_record_arriving_inside_the_grace_period_is_still_found():
    """The race the grace period exists for: audit delivery lags watchdog."""
    at = build()
    import threading

    threading.Timer(0.05, lambda: at.log.record(RANSOM, ATTACKER_PID)).start()

    answer = at.resolve(RANSOM, grace_ms=500)

    assert answer.pid == ATTACKER_PID
    assert answer.confidence == CERTAIN


# ------------------------------------------------------ 4. the pipeline gate


class _Capture:
    """Stands in for the Response service and keeps what it was asked to do."""

    def __init__(self):
        self.payload = None

    def __call__(self, client, url, path, payload, *args, **kwargs):
        self.payload = payload
        return {"status": "success", "actions_taken": []}


@pytest.fixture
def captured(monkeypatch):
    capture = _Capture()
    monkeypatch.setattr(pipeline, "_post", capture)
    return capture


@pytest.mark.parametrize(
    "confidence, expected",
    [
        (CERTAIN, "terminate_process"),
        (PROBABLE, "isolate_and_log"),
        (UNKNOWN, "isolate_and_log"),
    ],
)
def test_tc26_d_only_certain_asks_for_a_kill(captured, confidence, expected):
    """The gate, asserted at the caller rather than only where it is defined."""
    pipeline.trigger_response(
        client=None,
        incident_id="inc_test",
        process_id=ATTACKER_PID,
        threat_level="critical",
        attribution_confidence=confidence,
    )

    assert captured.payload["action_required"] == expected
    # The PID travels either way: an isolate-and-log incident that identified a
    # probable offender should still say who it was.
    assert captured.payload["process_id"] == ATTACKER_PID


def test_tc26_j_certain_without_a_pid_still_does_not_kill(captured):
    """Belt and braces: confidence alone is not authorisation."""
    pipeline.trigger_response(
        client=None,
        incident_id="inc_test",
        process_id=None,
        threat_level="critical",
        attribution_confidence=CERTAIN,
    )

    assert captured.payload["action_required"] == "isolate_and_log"
    assert captured.payload["process_id"] == 0


def test_tc26_k_the_response_call_carries_why_it_did_or_did_not_kill(captured):
    pipeline.trigger_response(
        client=None,
        incident_id="inc_test",
        process_id=ATTACKER_PID,
        threat_level="critical",
        attribution_confidence=PROBABLE,
        attribution_reason="2 processes wrote this path",
        process_image=r"C:\Temp\locker.exe",
    )

    assert captured.payload["attribution_confidence"] == PROBABLE
    assert captured.payload["attribution_reason"] == "2 processes wrote this path"
    assert captured.payload["process_image"] == r"C:\Temp\locker.exe"


def test_tc26_k2_a_caller_that_predates_attribution_still_isolates(captured):
    """The default has to be the safe one, not the new one."""
    pipeline.trigger_response(
        client=None,
        incident_id="inc_test",
        process_id=ATTACKER_PID,
        threat_level="critical",
    )

    assert captured.payload["action_required"] == "isolate_and_log"


# ------------------------------------------------------------- 4663 parsing


def _event_xml(
    object_name: str = RANSOM,
    process_id: str = "0x1092",
    access_mask: str = "0x2",
    object_type: str = "File",
    process_name: str = r"C:\Temp\locker.exe",
) -> str:
    return f"""<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4663</EventID></System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="ObjectType">{object_type}</Data>
    <Data Name="ObjectName">{object_name}</Data>
    <Data Name="AccessMask">{access_mask}</Data>
    <Data Name="ProcessId">{process_id}</Data>
    <Data Name="ProcessName">{process_name}</Data>
  </EventData>
</Event>"""


def test_tc26_l_a_write_event_parses_to_path_pid_and_image():
    parsed = parse_4663(_event_xml())

    assert parsed is not None
    assert parsed["path"] == RANSOM
    assert parsed["pid"] == 0x1092  # 4663 writes PIDs as hex
    assert parsed["image"] == r"C:\Temp\locker.exe"


def test_tc26_m_an_append_is_a_write():
    parsed = parse_4663(_event_xml(access_mask="0x4"))
    assert parsed is not None
    assert parsed["kind"] == "write"


def test_tc26_m2_a_delete_is_attributable_and_says_so():
    """The access right that decides whether archive-and-unlink can be seen.

    `7z a -sdel` and a loop around `openssl enc -in X -out X.enc` both leave
    the original unmodified and then remove it. The process that wrote the
    ciphertext has usually exited by the time its record arrives - one openssl
    per file lives about 65 ms against roughly 1000 ms of delivery lag - while
    the process doing the deleting is the long-lived one running the campaign.
    Dropping DELETE here meant watching files disappear and being unable to say
    who removed them.
    """
    parsed = parse_4663(_event_xml(access_mask="0x10000"))

    assert parsed is not None, "DELETE must be attributable"
    assert parsed["kind"] == "delete"
    assert parsed["pid"] == 0x1092


def test_tc26_m3_a_delete_names_its_process_and_reports_what_it_did():
    log = WriteLog(window_ms=3000)
    log.record(RANSOM, 4242, r"C:\Program Files\7-Zip\7z.exe", kind="delete")

    answer = log.lookup(RANSOM, source="windows-security-4663",
                        kernel_grade=True)

    assert answer.confidence == attribution.CERTAIN
    assert answer.pid == 4242
    assert "deleted" in answer.reason, (
        f"an incident record must distinguish a deletion from an overwrite; "
        f"got {answer.reason!r}")


@pytest.mark.parametrize(
    "kwargs, why",
    [
        ({"access_mask": "0x1"}, "ReadData is neither a write nor a delete"),
        ({"access_mask": "0x80"}, "ReadAttributes is not a write"),
        ({"object_type": "Key"}, "a registry key is not a file"),
        ({"process_id": "0x0"}, "PID 0 is the idle process"),
        ({"object_name": ""}, "no path means nothing to attribute"),
    ],
)
def test_tc26_n_non_writes_are_dropped(kwargs, why):
    assert parse_4663(_event_xml(**kwargs)) is None, why


def test_tc26_o_malformed_xml_does_not_raise():
    """A callback that raises tears down the subscription silently."""
    assert parse_4663("<not xml") is None
    assert parse_4663("") is None
    assert parse_4663("<Event/>") is None


# -------------------------------------------------------------- 5. it is bounded


def test_tc26_p_the_write_log_cannot_grow_without_bound():
    """S-7 in the security audit is `_SEEN_FILES` doing exactly this."""
    log = WriteLog(maxlen=128)
    for i in range(10_000):
        log.record(f"C:/watched/file_{i}.dat", 1000 + i)

    assert len(log) == 128
    assert log.recorded == 10_000  # the counter still tells the truth


def test_tc26_q_lookup_is_cheap_enough_to_sit_in_the_response_path():
    log = WriteLog(maxlen=attribution.MAX_ENTRIES)
    for i in range(attribution.MAX_ENTRIES):
        log.record(f"C:/watched/file_{i}.dat", 1000 + i)

    started = time.perf_counter()
    for _ in range(100):
        log.lookup(RANSOM)
    per_lookup_ms = (time.perf_counter() - started) * 1000 / 100

    # Two orders of magnitude under the 2s response budget, on a full buffer.
    assert per_lookup_ms < 20, f"{per_lookup_ms:.3f}ms per lookup on a full buffer"


# ------------------------------------------------- 6. the real thing, Windows


@pytest.mark.skipif(
    os.name != "nt",
    reason="the Security-channel source is Windows-only; the rest of TC-26 covers the logic",
)
def test_tc26_i_the_real_source_reports_why_it_is_unavailable():
    """Unelevated is the normal case, and it must be legible rather than silent.

    This does not assert that attribution *works* - that needs Administrator
    and an audit policy, which `scripts/setup_attribution_audit.ps1` sets up and
    `-Verify` checks. What it asserts is that when it does not work, the reason
    reaches `/monitor/attribution` instead of the Monitor quietly attributing
    nothing forever.
    """
    log = WriteLog()
    source = attribution.SecurityLogSource(log)
    started = source.start()

    if started:
        assert source.available is True
        assert source.error is None
        source.stop()
    else:
        assert source.available is False
        assert source.error, "an unavailable source must say why"
        assert source.name in Attributor(log=log, source=source).status()["source"]
