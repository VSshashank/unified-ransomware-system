"""`Attribution.suspend_authorised`: the gate that allows a *reversible* action.

Freeze-first (FIXES.md defect 26, Monitor side) suspends a writer as soon as a
kernel-grade answer names it, before the delivery horizon has closed. That is
earlier than `kill_authorised` can ever be true, so it needs a gate of its own,
and the gate is weaker than the kill gate for one reason only: a suspension can
be undone. It is not weaker in any other way. It requires ALL of

  * a live, kernel-grade source;
  * a PID;
  * exactly one writer of the path inside the competition window so far, and
    no record evicted from the write log inside that window;
  * the identity check `Attributor.verify` makes (image and start time);
  * a PID that is not the Monitor, its ancestors, an excluded PID or a system
    process, and not under a system directory;
  * a path inside the watched roots.

A PENDING answer is allowed here and only here. Each condition is taken away in
isolation below, with the other six in place, and each alone must refuse.
`kill_authorised` is not touched: its own tests pin that, and the last tests
here pin that this gate did not move it.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import attribution  # noqa: E402
from attribution import (  # noqa: E402
    CERTAIN,
    PROBABLE,
    UNKNOWN,
    Attribution,
    Attributor,
    AttributionSource,
    NullSource,
    ProbeUnavailable,
    ProcessFacts,
    WriteLog,
)

WROTE = 1_700_000_000.0
IMG = r"C:\Users\victim\Downloads\payload.exe"
ROOT = r"C:\Users\victim\Documents"
PATH = ROOT + r"\budget.xlsx"


def satisfied(**overrides) -> Attribution:
    """An answer that meets every condition of the gate. Each test spoils one."""
    fields = dict(
        pid=4242, image=IMG, confidence=PROBABLE, reason="one writer so far (pid 4242)",
        source="windows-security-4663", candidates=(4242,), pending=True,
        written_at=WROTE, delivered_at=WROTE + 0.9,
        kernel_grade=True, window_evicted=False, identity_verified=True,
        process_started_at=WROTE - 600, protected=None, in_watched_roots=True,
    )
    fields.update(overrides)
    return Attribution(**fields)


def test_the_baseline_answer_is_authorised():
    assert satisfied().suspend_authorised is True
    assert satisfied().suspend_blockers() == []


def test_a_pending_answer_is_allowed_by_this_gate_and_never_by_the_kill_gate():
    answer = satisfied(pending=True)
    assert answer.suspend_authorised is True
    assert answer.kill_authorised is False


def test_a_certain_answer_is_allowed_too():
    answer = satisfied(confidence=CERTAIN, pending=False)
    assert answer.suspend_authorised is True


@pytest.mark.parametrize(
    "spoil",
    [
        pytest.param(dict(kernel_grade=False), id="source_is_not_kernel_grade"),
        pytest.param(dict(pid=None), id="no_pid"),
        pytest.param(dict(candidates=()), id="no_candidate"),
        pytest.param(dict(candidates=(4242, 5151)), id="two_writers"),
        pytest.param(dict(candidates=(5151,)), id="the_one_candidate_is_someone_else"),
        pytest.param(dict(window_evicted=True), id="a_record_was_evicted_inside_the_window"),
        pytest.param(dict(identity_verified=False), id="identity_not_proven"),
        pytest.param(dict(protected="the Monitor itself"), id="protected_pid"),
        pytest.param(dict(in_watched_roots=False), id="path_outside_the_watched_roots"),
        pytest.param(dict(confidence=UNKNOWN), id="nothing_attributed"),
    ],
)
def test_each_condition_alone_refuses(spoil):
    answer = satisfied(**spoil)
    assert answer.suspend_authorised is False, answer.suspend_blockers()
    assert answer.suspend_blockers(), "a refusal says which condition it was"


def test_an_answer_that_was_never_assessed_is_refused():
    """The assessment fields default to the refusing value: fail closed."""
    bare = Attribution(pid=4242, image=IMG, confidence=PROBABLE, reason="x", candidates=(4242,),
                       pending=True, source="windows-security-4663")
    assert bare.suspend_authorised is False


def test_the_new_fields_do_not_change_equality_or_the_event_shape():
    plain = Attribution(pid=1, image=None, confidence=PROBABLE, reason="r", candidates=(1,))
    assessed = replace(plain, kernel_grade=True, identity_verified=True, in_watched_roots=True)
    assert plain == assessed
    assert plain.as_event_fields() == assessed.as_event_fields()


# ------------------------------------------------ what the write log hands the gate


class Source(AttributionSource):
    name = "fake-4663"
    kernel_grade = True
    delivery_horizon_ms = 1500.0

    def start(self) -> bool:
        self.available = True
        return True


def lookup(log: WriteLog, *, kernel_grade: bool = True, path: str = "w.bin", observed_at=None):
    observed = time.time() if observed_at is None else observed_at
    return log.lookup(path, source="fake-4663", kernel_grade=kernel_grade, observed_at=observed,
                      read_at=observed, horizon_ms=1500.0, horizon_from=log.clock(), clock_now=log.clock())


def test_a_lookup_records_that_the_source_is_kernel_grade():
    log = WriteLog()
    log.record("w.bin", 7001, IMG, written_at=time.time() - 0.2)
    assert lookup(log, kernel_grade=True).kernel_grade is True
    assert lookup(log, kernel_grade=False).kernel_grade is False


def test_a_lookup_records_an_eviction_inside_the_competition_window():
    log = WriteLog(maxlen=3)
    now = time.time()
    for n in range(3):
        log.record(f"other{n}.bin", 7100 + n, IMG, written_at=now - 0.1)
    log.record("w.bin", 7001, IMG, written_at=now - 0.2)  # pushes one record out of the window
    answer = lookup(log)
    assert answer.candidates == (7001,)
    assert answer.window_evicted is True, "a second writer cannot be ruled out"


def test_no_eviction_means_none_is_reported():
    log = WriteLog()
    log.record("w.bin", 7001, IMG, written_at=time.time() - 0.2)
    assert lookup(log).window_evicted is False


# ----------------------------------------------- assess_suspend: the other conditions


def assess(*, probe=None, source=None, log=None, answer=None, path=PATH, roots=(ROOT,)):
    log = log if log is not None else WriteLog()
    source = source if source is not None else Source(log)
    if isinstance(source, Source):
        source.start()
    attributor = Attributor(
        log=log, source=source,
        probe=probe if probe is not None else (
            lambda pid: ProcessFacts(pid=pid, image=IMG, created_at=WROTE - 600)),
    )
    return attributor.assess_suspend(answer if answer is not None else single_writer(), path, roots)


def single_writer(**overrides) -> Attribution:
    fields = dict(
        pid=4242, image=IMG, confidence=PROBABLE, reason="one writer so far (pid 4242)",
        source="fake-4663", candidates=(4242,), pending=True, written_at=WROTE,
        delivered_at=WROTE + 0.9, kernel_grade=True,
    )
    fields.update(overrides)
    return Attribution(**fields)


def test_a_clean_pending_answer_passes_every_condition():
    answer, outcome = assess()
    assert outcome == "suspend_authorised"
    assert answer.suspend_authorised is True
    assert answer.process_started_at == WROTE - 600
    assert answer.pending is True and answer.confidence == PROBABLE


@pytest.mark.parametrize("pid", [os.getpid(), os.getppid()], ids=["the_monitor_itself", "its_parent"])
def test_the_monitor_and_its_ancestors_are_never_suspended(pid):
    answer, outcome = assess(answer=single_writer(pid=pid, candidates=(pid,)))
    assert answer.suspend_authorised is False
    assert outcome == "protected"
    assert answer.protected


def test_an_excluded_pid_is_never_suspended():
    log = WriteLog()
    log.exclude([4242])
    answer, outcome = assess(log=log)
    assert answer.suspend_authorised is False and outcome == "protected"


@pytest.mark.parametrize("pid", [0, 1, 4])
def test_reserved_pids_are_never_suspended(pid):
    answer, outcome = assess(answer=single_writer(pid=pid, candidates=(pid,)))
    assert answer.suspend_authorised is False and outcome == "protected"


@pytest.mark.parametrize(
    "image",
    [r"C:\Windows\System32\svchost.exe", r"c:\WINDOWS\explorer.exe", r"C:\Windows\Temp\x.exe"],
)
def test_a_process_under_a_system_directory_is_never_suspended(image):
    answer, outcome = assess(
        answer=single_writer(image=image),
        probe=lambda pid: ProcessFacts(pid=pid, image=image, created_at=WROTE - 600),
    )
    assert answer.suspend_authorised is False and outcome == "protected"
    assert "system" in answer.protected.lower()


def test_the_live_image_is_checked_as_well_as_the_recorded_one():
    """An audit record with no image still cannot hide a system process."""
    live = r"C:\Windows\System32\lsass.exe"
    answer, outcome = assess(
        answer=single_writer(image=None),
        probe=lambda pid: ProcessFacts(pid=pid, image=live, created_at=WROTE - 600),
    )
    assert answer.suspend_authorised is False and outcome == "protected"


@pytest.mark.parametrize("path", [r"C:\Users\victim\Desktop\x.docx", r"C:\Users\victim\DocumentsEvil\x.docx",
                                  r"D:\Documents\x.docx"])
def test_a_path_outside_the_watched_roots_is_refused(path):
    answer, outcome = assess(path=path)
    assert answer.suspend_authorised is False and outcome == "outside_watched_roots"


def test_no_watched_root_at_all_is_refused():
    answer, outcome = assess(roots=())
    assert answer.suspend_authorised is False and outcome == "outside_watched_roots"


def test_a_path_inside_a_nested_root_is_accepted_whatever_the_case():
    answer, outcome = assess(path=PATH.upper(), roots=(ROOT.lower(),))
    assert outcome == "suspend_authorised", outcome


def test_an_exited_process_is_refused():
    answer, outcome = assess(probe=lambda pid: None)
    assert answer.suspend_authorised is False and outcome == "process_exited"


def test_a_reused_pid_is_refused_by_start_time():
    answer, outcome = assess(probe=lambda pid: ProcessFacts(pid=pid, image=IMG, created_at=WROTE + 5.0))
    assert answer.suspend_authorised is False and outcome == "pid_reused"


def test_a_reused_pid_is_refused_by_image():
    answer, outcome = assess(
        probe=lambda pid: ProcessFacts(pid=pid, image=r"C:\Users\victim\other.exe", created_at=WROTE - 600))
    assert answer.suspend_authorised is False and outcome == "pid_reused"


def test_an_unprovable_identity_is_refused():
    answer, outcome = assess(probe=lambda pid: ProcessFacts(pid=pid, image=None, created_at=None))
    assert answer.suspend_authorised is False and outcome == "identity_unverifiable"


def test_a_process_that_cannot_be_inspected_is_refused():
    def probe(pid):
        raise ProbeUnavailable("access denied (test)")

    answer, outcome = assess(probe=probe)
    assert answer.suspend_authorised is False and outcome == "identity_unverifiable"


def test_a_source_that_is_not_live_is_refused():
    log = WriteLog()
    answer, outcome = assess(log=log, source=NullSource(log, "no audit source here"))
    assert answer.suspend_authorised is False and outcome == "no_live_kernel_source"


def test_a_live_source_that_is_not_kernel_grade_is_refused():
    log = WriteLog()

    class Inferred(Source):
        kernel_grade = False

    answer, outcome = assess(log=log, source=Inferred(log))
    assert answer.suspend_authorised is False and outcome == "no_live_kernel_source"


def test_two_writers_and_an_eviction_are_refused_before_anything_is_probed():
    probed = []

    def probe(pid):
        probed.append(pid)
        return ProcessFacts(pid=pid, image=IMG, created_at=WROTE - 600)

    two, outcome_two = assess(answer=single_writer(candidates=(4242, 5151)), probe=probe)
    evicted, outcome_evicted = assess(answer=single_writer(window_evicted=True), probe=probe)
    assert (outcome_two, outcome_evicted) == ("not_sole_writer", "window_evicted")
    assert two.suspend_authorised is False and evicted.suspend_authorised is False
    assert probed == [], "a refusal that needs no probe must not make one"


def test_assessing_never_changes_the_answer_the_pipeline_acts_on():
    """`assess_suspend` returns a copy for the policy; the first answer is untouched."""
    first = single_writer()
    before = (first.pid, first.confidence, first.pending, first.reason)
    assess(answer=first, probe=lambda pid: None)
    assert (first.pid, first.confidence, first.pending, first.reason) == before


# ----------------------------------------------------------- the kill gate did not move


@pytest.mark.parametrize(
    "answer, expected",
    [
        (Attribution(pid=1, image=None, confidence=CERTAIN, reason="r"), True),
        (Attribution(pid=1, image=None, confidence=CERTAIN, reason="r", pending=True), False),
        (Attribution(pid=1, image=None, confidence=PROBABLE, reason="r"), False),
        (Attribution(pid=None, image=None, confidence=CERTAIN, reason="r"), False),
    ],
)
def test_kill_authorised_is_unchanged(answer, expected):
    assert answer.kill_authorised is expected


def test_the_suspend_gate_flags_do_not_make_an_answer_killable():
    """Every suspend condition satisfied, and the answer is still not killable."""
    assert satisfied().kill_authorised is False
    assert satisfied(confidence=PROBABLE, pending=False).kill_authorised is False
