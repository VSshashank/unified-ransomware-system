"""Freeze-first, review findings (FIXES.md defect 26, "Review follow-ups, freeze-first").

An independent review of the Monitor side found defects. Each is pinned here by a
test of its own, written first and failing on the tip that was reviewed:

  1. A kill waited for a suspend that was still in flight. The close took the hold's
     lock, which is held for the whole suspend request, so a kill-authorised close
     sent its terminate only after the freeze had been answered (0.87 s later, with a
     stuck suspend). The kill decision comes from `answer.kill_authorised` and from
     nothing else; the hold only decorates it with a lease when it has one.
  2. `suspension.detail` (and the reason, which carried the answer's own text) could
     put a PID and an image path in a ledger block whose attribution is not certain:
     C-16 forbids that. The ledger copy is an allow-list of non-identifying fields and
     the scan checks the nested object.
  3. A resume that failed (or timed out against a slow ledger) left the hold `held`
     for ever, silently ending freeze-first for that PID.
  4. A suspend could start after `/monitor/stop` had returned.
  5. The lifespan shutdown released nothing if the app left through an exception.
  and `warm()` ignored the switch.

Real child processes behind the Response stub, as in test_suspend_first.py.
"""

from __future__ import annotations

import asyncio
import importlib.util
import itertools
import json
import re
import sys
import time
from pathlib import Path

import httpx
import pytest

MONITOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MONITOR_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from _suspend_rig import ResponseStub  # noqa: E402
from test_suspend_first import (  # noqa: E402,F401  (fixtures and helpers of the sibling file)
    make_child,
    make_rig,
    rig,
    suspend_policy,
    wait_for,
)

ROOT = Path(__file__).resolve().parents[3]


def _load_scan():
    spec = importlib.util.spec_from_file_location("urds_ledger_coverage_review", ROOT / "scripts" / "ledger_coverage.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urds_ledger_coverage_review"] = module
    spec.loader.exec_module(module)
    return module


ledger_coverage = _load_scan()


class FakeClock:
    """The policy's monotonic clock, moved by hand."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def open_question(rig, name, victim=None):
    """The file, its audit record, and the pending first answer naming the writer."""
    path = rig.write(name, victim)
    written = rig.written_at[path]
    answer = monitor_app.attributor.resolve(str(path), observed_at=written + 0.01, read_at=written + 0.02,
                                            horizon_from=time.perf_counter())
    return path, written, answer


def question_for(key, path, written, answer, settle_mono=0.0):
    return attribution.Question(key=key, path=str(path), also=(), observed_at=written, read_at=written,
                                settle_at=written + 1.5, first=answer, settle_mono=settle_mono)


def freeze(rig, key, path, answer, **kwargs):
    event = {"incident_id": key, "file_path": str(path)}
    rig.policy.on_first_answer(monitor_app.attributor, event, answer, str(path), (str(rig.watch),),
                               parked=True, incident_id=key, background=True, **kwargs)
    return event


def certain_for(victim, written):
    answer = attribution.Attribution(pid=victim.pid, image=victim.image, confidence=attribution.CERTAIN,
                                     reason="sole writer", candidates=(victim.pid,), written_at=written,
                                     source="fake-4663")
    assert answer.kill_authorised
    return answer


def probable_for(victim, reason="two writers"):
    return attribution.Attribution(pid=victim.pid, image=victim.image, confidence=attribution.PROBABLE,
                                   reason=reason, candidates=(victim.pid, 1))


# ======================================================== 1. a kill never waits for a freeze


def test_a_kill_is_dispatched_at_once_while_a_suspend_is_still_in_flight(rig):
    victim = rig.child()
    rig.stub.suspend_delay = 1.5  # Response is slow to answer the suspend
    path, written, answer = open_question(rig, "k1.docx", victim)
    freeze(rig, "inc_k1", path, answer)
    question = question_for("inc_k1", path, written, answer)

    started = time.perf_counter()
    action = pipeline.escalation_action(None, question, certain_for(victim, written))
    waited = time.perf_counter() - started

    assert waited < 0.5, f"the terminate went out {waited:.2f}s after the close: it waited for the freeze"
    (terminate,) = rig.stub.of("/response/terminate")
    assert terminate["process_id"] == victim.pid
    assert "lease_id" not in terminate, "no lease was known when the kill went out"
    assert action["termination"]["status"] == "terminated"
    assert not victim.alive()
    rig.settle()  # the suspend lands on a dead PID and is refused: nothing is left frozen
    assert victim.alive() is False


def test_a_kill_that_arrives_while_the_suspend_is_in_flight_records_that_it_went_without_a_lease(rig):
    victim = rig.child()
    rig.stub.suspend_delay = 0.8
    path, written, answer = open_question(rig, "k2.docx", victim)
    freeze(rig, "inc_k2", path, answer)
    action = pipeline.escalation_action(None, question_for("inc_k2", path, written, answer),
                                        certain_for(victim, written))
    lease = action["lease"]
    assert lease["outcome"] == "terminated" and lease["lease_id"] is None
    assert "in flight" in lease["reason"]


def test_a_close_that_is_not_a_kill_does_not_wait_and_the_suspend_thread_resumes_on_its_reply(rig, suspend_policy):
    victim = rig.child()
    rig.stub.suspend_delay = 0.8
    path, written, answer = open_question(rig, "n1.docx", victim)
    freeze(rig, "inc_n1", path, answer)

    started = time.perf_counter()
    lease = suspend_policy.on_close(question_for("inc_n1", path, written, answer), probable_for(victim))
    waited = time.perf_counter() - started

    assert waited < 0.5, f"the close waited {waited:.2f}s for the suspend"
    assert lease is not None and lease["outcome"] == "resume_deferred"
    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0), "the suspend thread never resumed"
    (resume,) = rig.stub.of("/response/resume")
    assert resume["lease_id"], "resumed by lease: the reply carried one"
    assert victim.is_running()
    assert rig.stub.of("/response/terminate") == []


def test_a_close_that_is_not_a_kill_resumes_by_pid_when_the_reply_is_lost(rig, suspend_policy):
    rig.stub.suspend_mode = "lost_reply"
    rig.stub.suspend_delay = 0.5
    victim = rig.child()
    path, written, answer = open_question(rig, "n2.docx", victim)
    freeze(rig, "inc_n2", path, answer)
    suspend_policy.on_close(question_for("inc_n2", path, written, answer), probable_for(victim))
    assert wait_for(lambda: rig.stub.of("/response/resume"), timeout=8.0)
    (resume,) = rig.stub.of("/response/resume")
    assert resume["process_id"] == victim.pid and "lease_id" not in resume
    assert victim.is_running()


def test_no_freeze_is_started_once_the_horizon_has_passed(rig):
    victim = rig.child()
    path, written, answer = open_question(rig, "h1.docx", victim)
    freeze(rig, "inc_h1", path, answer, deadline=monitor_app.attributor.clock() - 0.01)
    rig.settle()
    assert rig.stub.of("/response/suspend") == []
    assert rig.policy.counts["skipped_horizon_passed"] == 1
    assert victim.is_running()


def test_a_freeze_whose_horizon_is_still_ahead_is_started(rig):
    victim = rig.child()
    path, written, answer = open_question(rig, "h2.docx", victim)
    freeze(rig, "inc_h2", path, answer, deadline=monitor_app.attributor.clock() + 5.0)
    rig.settle()
    assert len(rig.stub.of("/response/suspend")) == 1


def test_the_sweepers_re_ask_passes_the_questions_horizon(rig):
    """`app._question_rechecked` hands the question's own deadline to the hook."""
    victim, other = rig.child(), rig.child()
    path, written, answer = open_question(rig, "h3.docx", victim)
    event = {"incident_id": "inc_h3", "file_path": str(path)}
    past = attribution.Question(key="inc_h3", path=str(path), also=(), observed_at=written, read_at=written,
                                settle_at=written + 1.5, first=answer, context=event,
                                settle_mono=monitor_app.attributor.clock() - 1.0)
    monitor_app._question_rechecked(past, answer)
    rig.settle()
    assert rig.stub.of("/response/suspend") == []

    event2 = {"incident_id": "inc_h4", "file_path": str(path)}
    path2, written2, answer2 = open_question(rig, "h4.docx", other)
    future = attribution.Question(key="inc_h4", path=str(path2), also=(), observed_at=written2, read_at=written2,
                                  settle_at=written2 + 1.5, first=answer2, context=event2,
                                  settle_mono=monitor_app.attributor.clock() + 5.0)
    monitor_app._question_rechecked(future, answer2)
    rig.settle()
    assert len(rig.stub.of("/response/suspend")) == 1


HOLD_STATES = ["held", "uncertain", "requesting", "refused", "terminating", "ended", "none"]


def test_terminate_is_sent_if_and_only_if_the_answer_is_kill_authorised_whatever_the_hold(rig, suspend_policy,
                                                                                         monkeypatch):
    """The kill decision is `answer.kill_authorised` and nothing else: not the hold's state."""
    victim = rig.child()
    sent = []
    monkeypatch.setattr(pipeline, "_post", lambda client, base, p, body, *a, **k: (
        sent.append((p, body)) or {"status": "terminated"}))
    n = 0
    for conf, pending, pid_mode, ncand, state in itertools.product(
            ["certain", "probable", "unknown"], [False, True], ["hold", "other", None], [1, 2], HOLD_STATES):
        n += 1
        key = f"inc_iff_{n}"
        pid = {"hold": victim.pid, "other": victim.pid + 7, None: None}[pid_mode]
        cands = (pid, *range(1, ncand)) if pid is not None else tuple(range(1, ncand + 1))
        ans = attribution.Attribution(pid=pid, image=victim.image, confidence=conf, reason="r", pending=pending,
                                      candidates=cands, written_at=time.time(), source="fake")
        if state != "none":
            hold = suspend_policy.Hold(pid=victim.pid, incident_id=key, created=0.0)
            hold.state = state
            hold.lease_id = "lease_X" if state != "requesting" else None
            rig.policy._by_incident[key] = hold
            rig.policy._holds[victim.pid] = hold
        question = question_for(key, "p", 0.0, ans)
        before = len(sent)
        pipeline.escalation_action(None, question, ans)
        new = sent[before:]
        assert bool(new) == bool(ans.kill_authorised), (conf, pending, pid_mode, ncand, state, new)
        assert all(body["process_id"] == ans.pid for _, body in new)
        rig.policy._holds.clear()
    assert n == 3 * 2 * 3 * 2 * len(HOLD_STATES)


# ============================== 2. no ledger block names a process it is not certain about


PID_REFUSAL = ("PID {pid} is now C:\\Users\\victim\\AppData\\evil.exe, while attribution named {image}: "
               "the PID was reused; refusing to suspend")


def refusing_with_a_process_in_the_text(monkeypatch):
    def refusing(self, p):
        return 409, {"code": "PID_REUSED", "message": PID_REFUSAL.format(pid=p["process_id"], image=p.get("image"))}

    monkeypatch.setattr(ResponseStub, "_suspend", refusing)


def only_words(suspension: dict) -> str:
    """Everything in the object that is free text or a code (timestamps cannot name a process)."""
    return json.dumps({k: v for k, v in suspension.items() if k not in ("suspended_at", "expires_at", "resumed_at")})


def test_a_refusal_text_naming_a_process_stays_out_of_the_ledger_block(rig, monkeypatch):
    refusing_with_a_process_in_the_text(monkeypatch)
    victim, other = rig.child(), rig.child()
    path = rig.write("l1.docx", victim)
    event = rig.notify(path)
    rig.late_record(path, other)  # a second writer: the question closes, not certain
    rig.close_everything()
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["attribution_confidence"] != "certain" and block["process_id"] is None
    assert block["suspension"]["code"] == "PID_REUSED"
    assert "detail" not in block["suspension"], block["suspension"]
    words = only_words(block["suspension"])
    assert str(victim.pid) not in re.findall(r"\d+", words) and "evil.exe" not in words
    assert "\\" not in words and "/" not in words
    # The free text is kept where it helps: on the in-memory event, not in the chain.
    assert "evil.exe" in event["suspension"]["detail"]


def test_the_answers_own_text_does_not_ride_into_the_ledger_through_the_reason(rig):
    """A second writer's answer says "2 processes wrote this path (pid, pid)"; that is evidence
    for the candidates field, not for a block whose attribution is not certain."""
    victim, other = rig.child(), rig.child()
    path = rig.write("l2.docx", victim)
    rig.notify(path)
    rig.late_record(path, other)
    rig.close_everything()
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["suspension"]["outcome"] == "resumed"
    words = only_words(block["suspension"])
    numbers = re.findall(r"\d+", words)
    assert str(victim.pid) not in numbers and str(other.pid) not in numbers, block["suspension"]
    assert "kill gate" in block["suspension"]["reason"]
    assert block["attribution_candidates"], "the evidence is still on the block, as candidates"


def test_the_ledger_copy_is_an_allow_list(suspend_policy):
    record = {
        "lease_id": "lease_1", "gate": "suspend_authorised", "outcome": "resumed", "suspended_at": "2026-10-06T15:56:58Z",
        "expires_at": "2026-10-06T15:57:01Z", "lease_seconds": 2.05, "already_held": False, "code": None,
        "action": "resume", "reason": "the kill gate is not satisfied at the horizon (probable)",
        "detail": "PID 4242 is C:\\x\\y.exe", "shared_with_incident": "inc_1",
        "process_image": "C:\\x\\y.exe", "process_id": 4242,
    }
    copy = suspend_policy.ledger_copy(record)
    assert "detail" not in copy and "process_image" not in copy and "process_id" not in copy
    assert copy["lease_id"] == "lease_1" and copy["outcome"] == "resumed"
    assert suspend_policy.ledger_copy(None) is None


def test_a_string_that_could_name_a_process_is_withheld_even_in_an_allowed_field(suspend_policy):
    copy = suspend_policy.ledger_copy({"outcome": "refused", "reason": "PID 4242 was reused", "code": r"C:\x"})
    assert "4242" not in json.dumps(copy) and "\\" not in json.dumps(copy)


@pytest.mark.parametrize("hostile", ["pid 4242 holds it", r"C:\Windows\x.exe", "/usr/bin/x", "process PID 7"])
def test_values_from_the_response_service_cannot_carry_a_process_into_the_chain(rig, monkeypatch, hostile):
    """lease ids, codes and times come from another service: shaped before they are recorded."""
    victim, other = rig.child(), rig.child()

    def odd(self, p):
        return 409, {"code": hostile, "message": hostile}

    monkeypatch.setattr(ResponseStub, "_suspend", odd)
    path = rig.write("l3.docx", victim)
    rig.notify(path)
    rig.late_record(path, other)
    rig.close_everything()
    (block,) = rig.stub.blocks("attribution_escalation")
    assert not ledger_coverage.unsupported_suspension(block), block["suspension"]
    assert hostile not in json.dumps(block["suspension"])


def clean_suspension(**overrides):
    suspension = {"lease_id": "lease_1", "gate": "suspend_authorised", "outcome": "resumed",
                  "suspended_at": "2026-10-06T15:56:58.9Z", "expires_at": "2026-10-06T15:57:01.0Z",
                  "lease_seconds": 2.05, "already_held": False, "code": None, "action": "resume",
                  "reason": "the kill gate is not satisfied at the horizon (probable)"}
    suspension.update(overrides)
    return suspension


def escalation(suspension) -> dict:
    return {"block_id": 9, "event_type": "attribution_escalation", "event_data": {
        "process_id": None, "attribution_confidence": "probable", "attribution_candidates": [4242, 5151],
        "lease_id": "lease_1", "suspension": suspension}}


def test_the_scan_accepts_a_clean_suspension_object():
    report = ledger_coverage.scan_writes([escalation(clean_suspension())])
    assert report["unsupported"] == 0 and report["events_examined"] == 1, report


@pytest.mark.parametrize(
    "overrides, why",
    [
        pytest.param({"detail": "anything"}, "detail", id="a_key_outside_the_allow_list"),
        pytest.param({"process_image": "x"}, "process_image", id="an_image_key"),
        pytest.param({"reason": "pid 4242 wrote it"}, "reason", id="the_word_pid"),
        pytest.param({"reason": "PID 4242"}, "reason", id="the_word_PID"),
        pytest.param({"reason": r"C:\Users\x\evil.exe"}, "reason", id="a_windows_path"),
        pytest.param({"reason": "/usr/bin/evil"}, "reason", id="a_posix_path"),
        pytest.param({"code": r"..\evil"}, "code", id="a_separator_in_a_code"),
    ],
)
def test_the_scan_rejects_a_suspension_object_that_could_name_a_process(overrides, why):
    report = ledger_coverage.scan_writes([escalation(clean_suspension(**overrides))])
    assert report["unsupported"] == 1, report
    assert why in report["detail"][0]["why"]


def test_a_code_that_merely_contains_pid_is_not_the_word_pid():
    """PID_REUSED is a code, not a process id."""
    report = ledger_coverage.scan_writes([escalation(clean_suspension(code="PID_REUSED", outcome="refused"))])
    assert report["unsupported"] == 0, report


def test_blocks_without_a_suspension_object_are_judged_as_before():
    clean = {"block_id": 1, "event_type": "attribution_escalation",
             "event_data": {"process_id": 4242, "attribution_confidence": "certain"}}
    named = {"block_id": 2, "event_type": "attribution_escalation",
             "event_data": {"process_id": 4242, "attribution_confidence": "probable"}}
    report = ledger_coverage.scan_writes([clean, named])
    assert [d["block_id"] for d in report["detail"]] == [2]


def test_a_real_policy_record_passes_the_scan_in_every_shape(suspend_policy):
    hold = suspend_policy.Hold(pid=4242, incident_id="inc_1", created=0.0)
    hold.lease_id, hold.suspended_at, hold.expires_at, hold.lease_seconds = "lease_7", "2026-10-06T10:00:00Z", None, 2.05
    for outcome in ("suspended", "resumed", "refused", "uncertain", "unreachable", "resume_failed",
                    "terminated", "lease_expired", "resume_deferred", "left_to_expire", "skipped"):
        record = hold.record(outcome, detail=r"PID 4242 is C:\evil.exe", reason="the kill gate is not satisfied")
        report = ledger_coverage.scan_writes([escalation(suspend_policy.ledger_copy(record))])
        assert report["unsupported"] == 0, (outcome, report)


# ====================================== 3. a stale hold does not silence freeze-first for ever


def test_a_resume_that_fails_after_the_lease_expired_ends_the_hold_and_a_later_incident_freezes_again(rig):
    fake = FakeClock()
    rig.policy._clock = fake
    victim, other = rig.child(), rig.child()
    path = rig.write("s1.docx", victim)
    first = rig.notify(path)
    assert first["suspension"]["outcome"] == "suspended"
    lease_id = first["suspension"]["lease_id"]

    rig.stub.suspend_mode = "unreachable"  # the resume will not get through
    fake.t += 10.0  # and by now the lease has long run out (2.05 s + margin)
    rig.late_record(path, other)  # the question closes: not a kill, a resume is due
    assert wait_for(lambda: rig.stub.blocks("attribution_escalation"), timeout=8.0)
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["suspension"]["outcome"] == "lease_expired", block["suspension"]
    assert victim.pid not in rig.policy._holds, "the hold must not stay `held` for ever"

    # What Response's own expiry does, and a new writer-incident afterwards:
    rig.stub.suspend_mode = "ok"
    rig.stub._resume({"lease_id": lease_id})
    assert victim.is_running()
    fake.t += 60.0  # past the cooldown
    again = rig.write("s1b.docx", victim)
    rig.notify(again)
    assert len(rig.stub.of("/response/suspend")) == 2, "the PID was never frozen again"
    assert victim.is_frozen()


def test_a_resume_that_fails_before_the_lease_expired_leaves_it_to_expire_and_stays_held(rig):
    """Not stale yet: Response's expiry has not had its say, so the hold is kept (release_all retries)."""
    fake = FakeClock()
    rig.policy._clock = fake
    victim, other = rig.child(), rig.child()
    path = rig.write("s2.docx", victim)
    rig.notify(path)
    rig.stub.suspend_mode = "unreachable"
    rig.late_record(path, other)
    assert wait_for(lambda: rig.stub.blocks("attribution_escalation"), timeout=8.0)
    (block,) = rig.stub.blocks("attribution_escalation")
    assert block["suspension"]["outcome"] == "resume_failed"
    assert rig.policy._holds[victim.pid].state == "held"


def test_a_held_hold_that_is_stale_no_longer_blocks_the_next_incident(rig):
    fake = FakeClock()
    rig.policy._clock = fake
    victim = rig.child()
    rig.notify(rig.write("s3a.docx", victim))
    assert len(rig.stub.of("/response/suspend")) == 1
    fake.t += 10.0  # the lease has run out; nobody ever closed the question
    rig.stub._resume({"lease_id": rig.policy._holds[victim.pid].lease_id})  # Response's expiry
    rig.notify(rig.write("s3b.docx", victim))
    assert len(rig.stub.of("/response/suspend")) == 1, "inside the cooldown that follows the lease"
    assert rig.policy.counts["skipped_cooldown"] >= 1
    fake.t += 60.0
    rig.notify(rig.write("s3c.docx", victim))
    assert len(rig.stub.of("/response/suspend")) == 2


# ===================================== 4. nothing is suspended after /monitor/stop returned


def test_a_suspend_does_not_start_after_monitor_stop_returned(rig):
    victim = rig.child()
    path = rig.write("p1.docx")  # the audit record is still in flight
    rig.notify(path)
    assert monitor_app.stop_monitoring(None).status_code == 200
    rig.late_record(path, victim)  # arrives after /monitor/stop returned
    time.sleep(0.6)
    assert rig.stub.of("/response/suspend") == [], "a suspend started after the Monitor stopped"
    assert victim.is_running()
    rig.close_everything()
    assert [t["process_id"] for t in rig.stub.of("/response/terminate")] == [victim.pid], (
        "the question still closes and the kill is the ordinary one")


def test_monitor_start_lifts_the_pause(rig, tmp_path):
    victim = rig.child()
    monitor_app.stop_monitoring(None)
    assert rig.policy.stats()["paused"] is True
    request = monitor_app.MonitorStartRequest(watch_path=str(rig.watch))
    try:
        assert monitor_app.start_monitoring(request).status_code == 200
        assert rig.policy.stats()["paused"] is False
        rig.notify(rig.write("p2.docx", victim))
        assert len(rig.stub.of("/response/suspend")) == 1
    finally:
        monitor_app.stop_monitoring(None)


def test_the_pause_covers_the_first_look_too(rig):
    victim = rig.child()
    rig.policy.pause()
    rig.notify(rig.write("p3.docx", victim))
    assert rig.stub.of("/response/suspend") == []
    rig.policy.unpause()


# ================================== 5. the lifespan releases even if the app leaves by an exception


def test_the_lifespan_releases_every_lease_even_if_the_app_exits_through_an_exception(rig):
    victim = rig.child()
    rig.notify(rig.write("x1.docx", victim))
    assert victim.is_frozen()

    async def crash_inside():
        context = monitor_app.lifespan(monitor_app.app)
        await context.__aenter__()
        await context.__aexit__(RuntimeError, RuntimeError("the app died"), None)

    asyncio.run(crash_inside())
    assert len(rig.stub.of("/response/resume")) == 1
    assert victim.is_running()


# ================================================ warm() respects the switch


def test_warm_builds_nothing_when_freeze_first_is_off(suspend_policy, monkeypatch):
    monkeypatch.setenv("MONITOR_SUSPEND_FIRST", "0")
    policy = suspend_policy.SuspendPolicy()
    policy.warm()
    time.sleep(0.8)
    assert policy._client is None


def test_warm_builds_the_client_when_it_is_on(suspend_policy, monkeypatch):
    monkeypatch.delenv("MONITOR_SUSPEND_FIRST", raising=False)
    policy = suspend_policy.SuspendPolicy()
    policy.warm()
    assert wait_for(lambda: policy._client is not None, timeout=10.0)
    policy._client.close()


def test_the_scans_allow_list_and_the_monitors_are_the_same_list(suspend_policy):
    assert ledger_coverage.SUSPENSION_FIELDS == suspend_policy.LEDGER_FIELDS
