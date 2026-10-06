"""Downstream fan-out for a suspicious file event - AS.

The Monitor is what notices an attack, so it is what drives the rest of the
chain: ML classification, ledger entry, then response. Each hop is best-effort
and independently reported - a ledger that is briefly down must not stop a
process from being killed, and a failed kill must still leave an audit trail.

Every ledger event carries `file_hash` in `event_data`. SI's recovery integrity
check reads that field back to decide whether a restored file matches what was
last seen, so it is not optional metadata.
"""

import logging
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

import httpx

import attribution
import suspend_policy

logger = logging.getLogger(__name__)

LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger:8003").rstrip("/")
ML_URL = os.getenv("ML_URL", "http://ml_engine:8002").rstrip("/")
RESPONSE_URL = os.getenv("RESPONSE_URL", "http://response:8004").rstrip("/")

# Short: this runs on the detection path, where the target is sub-100ms to
# decide and a couple of seconds to act.
DOWNSTREAM_TIMEOUT = float(os.getenv("DOWNSTREAM_TIMEOUT", "3.0"))

# Threat levels that justify killing a process.
ACTIONABLE_THREAT_LEVELS = {"high", "critical"}

# Ascending severity. Anything unrecognised ranks lowest.
THREAT_LEVEL_ORDER = ("low", "medium", "high", "critical")


def _rank(threat_level: str) -> int:
    try:
        return THREAT_LEVEL_ORDER.index(threat_level)
    except ValueError:
        return 0


def effective_threat_level(model_threat_level: str | None, suspicious: bool) -> str:
    """Combine the model's score with the Monitor's own verdict, taking the higher.

    The ML engine refines the Monitor's verdict; it does not overrule it. The
    behavioural classifier's operating point needs Shannon entropy of roughly
    7.995 before it calls something ransomware with confidence, and ciphertext
    under about 40KB cannot reach that through sampling noise alone. So a small
    file encrypted in place scored "low" here while the Monitor had already
    classified it `suspected_encryption` - and because the response gate read
    only the model's answer, nothing acted on it. Measured on this machine, that
    was every trial at 4KB, 8KB and 32KB.

    Treating the Monitor as a floor rather than a fallback keeps one detector
    from silently cancelling the other, and keeps the level coherent downstream:
    the Response service runs network isolation on `high`/`critical` only, so
    forwarding "low" for a file we are confident is encrypted would trigger a
    response that then declined to do most of its job.
    """
    monitor_threat_level = "high" if suspicious else "low"
    model_threat_level = model_threat_level or "low"
    return max(model_threat_level, monitor_threat_level, key=_rank)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def chained_pid(pid: int | None, confidence: str | None) -> int | None:
    """The PID a ledger block may name: a CERTAIN answer's, or none.

    Claim C-16 (scripts/ledger_coverage.py, docs/CORRECTIONS.md): an event in
    the chain names a process only when attribution resolved to CERTAIN. A
    PROBABLE answer's PIDs still go on the block, as `attribution_candidates` -
    every PID whose audited write fell in the window, which is the evidence -
    and the event on /monitor/events still names the one the answer picked.
    What the chain does not do is put that pick in `process_id`, the field that
    means "this process did it". The 2026-10-04 elevated run's chain did so in
    649 of its 703 blocks that named a process.
    """
    if pid and confidence == attribution.CERTAIN:
        return pid
    return None


class PipelineResult(dict):
    """Plain dict; named so logs and tests read clearly."""


def _post(client: httpx.Client, base_url: str, path: str, payload: dict) -> dict | None:
    try:
        response = client.post(f"{base_url}{path}", json=payload, timeout=DOWNSTREAM_TIMEOUT)
        if response.status_code >= 400:
            logger.warning("%s%s returned %s: %s", base_url, path, response.status_code, response.text[:200])
            return None
        return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("%s%s unreachable: %s", base_url, path, exc)
        return None


def log_to_ledger(client: httpx.Client, event_type: str, event_data: dict) -> dict | None:
    """Append one event. `event_data` must already contain file_hash when known."""
    return _post(client, LEDGER_URL, "/ledger/log", {"event_type": event_type, "event_data": event_data})


def log_baseline(client: httpx.Client, event: dict) -> dict | None:
    """Record what a file hashed to while it was still known-good.

    `file_baseline` is one of the three event types
    services/response/recovery/ledger_client.py will accept as a reference for
    an integrity check, and until this existed nothing in the running system
    wrote any of them. The Monitor reached the ledger only for suspicious
    events, so the newest hash on an attacked path was the attacker's - which
    made "does the restored file match the ledger" a test that passed only if
    recovery handed back the ciphertext. The recovery client refuses to trust
    that hash, correctly, and the result was a verification step that could
    never verify anything.

    Written once per path per monitor run, for a file the detector found benign
    the first time it saw it. That is the strongest claim available without a
    trusted installer manifest, and the claim is exactly what it says: this is
    what the file hashed to when this monitor first saw it and had no reason to
    think it had been touched.
    """
    return log_to_ledger(
        client,
        "file_baseline",
        {
            "file_path": event.get("file_path"),
            "file_hash": event.get("file_hash"),
            # The length of the bytes `file_hash` was taken over (F5): two
            # blocks on the VM recorded 0 beside a full 16,368-byte file's hash.
            "file_size": event.get("file_size"),
            # True when the file changed size while it was being read: the
            # hash is of what was there at the end of the read.
            "size_changed_during_read": event.get("size_changed_during_read"),
            "entropy": event.get("entropy"),
            "verdict": event.get("verdict"),
            "event_type": event.get("event_type"),
            "observed_at": event.get("timestamp") or utc_now(),
        },
    )


def log_governance_decision(client: httpx.Client, event: dict) -> dict | None:
    """Chain a suppression that *cancelled* an alert.

    P5.1 row M-16 and Table 9.8 row 7: an admitted suppression stops the event
    at `app.handle_event`'s fan-out gate, so the one decision an auditor most
    needs to see - the one that made a detection disappear - was the only one
    the chain never held. Coverage measured at 50.0% before this existed.

    This is not the pipeline. There is no prediction and no response, because
    the alert was cancelled and acting on it would defeat the operator's own
    rule. What is written is the decision and its two costs, so the chain shows
    that a detection existed, which rule removed it, and what that rule would
    have cost to forge against what the signal cost to avoid.
    """
    admissibility = event.get("admissibility")
    if not admissibility:
        return None
    return log_to_ledger(
        client,
        "suppression_decision",
        {
            "file_path": event.get("file_path"),
            "file_hash": event.get("file_hash"),
            "event_type": event.get("event_type"),
            "entropy": event.get("entropy"),
            # The verdict as the detector reached it, before the rule applied.
            # Without this the entry says a rule fired and not what it silenced.
            "verdict": event.get("verdict"),
            "reason": event.get("reason"),
            "signal": admissibility.get("signal"),
            "admissibility": admissibility,
            "outcome": admissibility.get("outcome"),
            # The two fields NOVELTY_PROOF_PLAN.md §9 row 10 requires and this
            # block did not have. `admissibility` already carries the mitigation
            # identifier, both capability levels and the reason; these say what
            # the validator concluded and under which policy it was read.
            "validation_state": event.get("validation_state"),
            "policy_version": event.get("policy_version"),
            "suppressed_by": event.get("suppressed_by"),
            "detection_latency_ms": event.get("detection_latency_ms"),
            "observed_at": event.get("timestamp") or utc_now(),
        },
    )


def predict(client: httpx.Client, features: dict) -> dict | None:
    return _post(client, ML_URL, "/predict", {"features": features})


def trigger_response(
    client: httpx.Client,
    incident_id: str,
    process_id: int | None,
    threat_level: str,
    admissibility: dict | None = None,
    attribution_confidence: str = attribution.UNKNOWN,
    attribution_reason: str | None = None,
    process_image: str | None = None,
    attribution_candidates: list | None = None,
) -> dict | None:
    """Ask the Response service to act on one incident.

    Termination is requested only when a PID was attributed **and** the
    attribution is `certain` - one process, one path, one window, from a
    kernel-level source. `probable` and `unknown` both fall through to
    `isolate_and_log`, which is what this call did for every filesystem event
    before attribution existed.

    The asymmetry is deliberate and it is the whole safety argument: failing to
    kill leaves an encryptor running for the seconds it takes an operator to
    act, and killing the wrong process can take down anything on the host. The
    first failure is recoverable and the second is not, so only the level that
    names exactly one candidate is allowed to ask for a kill.
    """
    authorised = bool(process_id) and attribution_confidence in attribution.KILL_AUTHORISING
    return _post(
        client,
        RESPONSE_URL,
        "/response/trigger",
        {
            "incident_id": incident_id,
            "process_id": process_id or 0,
            "threat_level": threat_level,
            "action_required": "terminate_process" if authorised else "isolate_and_log",
            # Why this incident did or did not ask for a kill. Without it the
            # ledger cannot tell "nothing was attributed" from "something was
            # attributed and the evidence was not strong enough", and those are
            # different failures with different fixes.
            "attribution_confidence": attribution_confidence,
            "attribution_reason": attribution_reason,
            "process_image": process_image,
            # The evidence behind a PROBABLE answer. The Response service puts
            # these, not `process_id`, on its block when it does not kill
            # (chained_pid, C-16).
            "attribution_candidates": list(attribution_candidates or []),
            # The governance record travels with the incident. An operator rule
            # that was consulted and outranked is why this response is firing at
            # all, and the Response service's own ledger entry should say so
            # rather than making an auditor join two chains on a timestamp.
            "admissibility": admissibility,
        },
    )


def request_termination(
    client: httpx.Client,
    incident_id: str,
    answer: "attribution.Attribution",
    lease_id: str | None = None,
) -> dict | None:
    """Ask the Response service to kill the process an escalation named.

    The gate is applied here again, at the caller, from the `Attribution`
    itself rather than from a confidence string: an answer that is pending,
    PROBABLE, UNKNOWN, or CERTAIN without a PID never reaches the Response
    service at all. `/response/terminate` rather than `/response/trigger`,
    because the incident already had its response - isolation ran when the first
    answer came back - and the only thing this adds is the kill. The Response
    service writes its own `response_action` block for it, with the same
    incident ID.

    `lease_id` is the freeze-first lease the process is held under
    (`suspend_policy`), when it was suspended first: the kill names it, so the
    Response service ends it "terminated" rather than resuming a dead process.
    Absent - nothing was suspended, or freeze-first is off - the request is
    exactly what it always was, key for key.
    """
    if not answer.kill_authorised:
        return None
    payload = {
        "process_id": answer.pid,
        "incident_id": incident_id,
        "reason": f"attribution escalated to certain after the delivery horizon: {answer.reason}",
        "force": True,
        # What authorised it, so the Response service's own block says so.
        # A kill asked for with neither is an operator's, and the C-16 scan
        # reports its block as naming a process without attribution.
        "attribution_confidence": answer.confidence,
        "attribution_source": answer.source,
    }
    if lease_id:
        payload["lease_id"] = lease_id
    return _post(client, RESPONSE_URL, "/response/terminate", payload)


# ------------------------------------------------- kills this Monitor already made
#
# R16 (FIXES.md, defect 22): one writer's burst closes many CERTAIN questions
# with its PID - 2-4 per file, F6 - and they reach the escalation thread
# together. The first kill worked; every later one still made the round trip to
# /response/terminate and was refused ("PID ... does not exist"), 0.30-0.38 s
# each on the VM, one at a time, while a fresh writer's kill waited behind them:
# 2.0-8.7 s from its write to its death against a 2.05 s budget.
#
# So the escalation thread remembers each kill the Response service confirmed,
# by PID *and* the process's start time and image - never by PID alone, because
# Windows reuses PIDs - and a later answer about a write by that same process is
# closed as `terminated_earlier` without a request, once the PID is shown to be
# gone or to belong to a process that started after the write. Anything else -
# a PID never killed, a reused PID's own write, a PID that cannot be probed -
# asks the Response service exactly as before, with one exception (defect 22
# review follow-ups): a PID whose current owner provably started after the write
# is never asked to be killed (`pid_reused_before_kill`), whether or not the
# kill memory still remembers anything about it.

#: How many confirmed kills the escalation thread remembers, and for how long.
MAX_TERMINATIONS = int(os.getenv("MONITOR_MAX_TERMINATIONS", "1024"))
TERMINATION_MEMORY_S = float(os.getenv("MONITOR_TERMINATION_MEMORY_S", "600"))
#: How many unconfirmed terminates (refused, timed out, unreachable) of one
#: process cover a write made before them (defect 22, R-RACE (b)): the first
#: attempt and one retry. A question about such a write is then closed as
#: `termination_unconfirmed_earlier` instead of paying another full timeout.
UNCONFIRMED_ATTEMPTS = max(1, int(os.getenv("MONITOR_UNCONFIRMED_ATTEMPTS", "2")))


@dataclass(frozen=True)
class Termination:
    """One kill this Monitor asked for and the Response service confirmed."""

    pid: int
    #: The killed process's start time (system clock), probed just before the
    #: request; None when it could not be shown to be the writer's.
    created_at: float | None
    image: str | None
    incident_id: str
    #: When the request went out (system clock) and when it was remembered
    #: (monotonic, for the age bound).
    dispatched_at: float
    remembered_mono: float
    #: When the request went out on the horizon clock (`time.perf_counter`, the
    #: clock `Question.horizon_from` is stamped with); None if not recorded.
    dispatched_mono: float | None = None

    def wrote(self, answer: "attribution.Attribution", read_mono: float | None = None) -> bool:
        """Was `answer`'s write made by this process, the one already killed?

        It started no later than the write, has the same image, and the write
        came before the kill was asked for. A process that held the PID before
        this one died before this one started, so it could not have been
        verified alive after the write; one that holds it after started after
        the kill, so its writes come after the kill too. The start time and the
        write are compared on the system clock, with the identity check's
        tolerance.

        "Before the kill" is not taken from the system clock alone: it can be
        stepped (VirtualBox time sync), and a step just as the kill went out
        once made a later process that exited by itself look like this kill's.
        When the question's read time is known on the horizon clock
        (`read_mono`, `Question.horizon_from`), the bytes must also have been
        read - and the write, which lands no later than the read plus the
        tolerance, made - before the request went out on that monotonic clock.
        Both clocks must agree; either one saying otherwise means "not shown".
        """
        if self.created_at is None or answer.written_at is None:
            return False
        if not attribution.same_image(self.image, answer.image):
            return False
        tolerance = attribution.CLOCK_TOLERANCE_MS / 1000.0
        if not self.created_at <= answer.written_at + tolerance < self.dispatched_at:
            return False
        if read_mono and self.dispatched_mono is not None:
            return read_mono + tolerance < self.dispatched_mono
        return True

    def as_record(self) -> dict:
        """What the escalation block says about the earlier kill."""
        return {
            "incident_id": self.incident_id,
            "response_dispatched_at": attribution.iso_utc(self.dispatched_at),
            "process_started_at": attribution.iso_utc(self.created_at),
        }


class TerminationRegistry:
    """Confirmed kills, bounded in number and age. Thread-safe.

    It also keeps, apart, the terminates that were asked for and *not*
    confirmed (`remember_unconfirmed`): the last `UNCONFIRMED_ATTEMPTS` per
    process, under the same count and age bounds. They are never treated as
    kills - `find`, `entries` and `len` see confirmed kills only.
    """

    def __init__(
        self,
        max_entries: int = MAX_TERMINATIONS,
        memory_s: float = TERMINATION_MEMORY_S,
        clock: Callable[[], float] = time.monotonic,
        unconfirmed_attempts: int = UNCONFIRMED_ATTEMPTS,
    ) -> None:
        self.max_entries = int(max_entries)
        self.memory_s = float(memory_s)
        self.clock = clock
        self.unconfirmed_attempts = max(1, int(unconfirmed_attempts))
        self._items: "OrderedDict[tuple[int, float | None], Termination]" = OrderedDict()
        self._unconfirmed: "OrderedDict[tuple[int, float | None], deque[Termination]]" = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        while self._items:
            oldest = next(iter(self._items.values()))
            if len(self._items) <= self.max_entries and now - oldest.remembered_mono <= self.memory_s:
                break
            self._items.popitem(last=False)
        while self._unconfirmed:
            newest_of_oldest = next(iter(self._unconfirmed.values()))[-1]
            if (len(self._unconfirmed) <= self.max_entries
                    and now - newest_of_oldest.remembered_mono <= self.memory_s):
                break
            self._unconfirmed.popitem(last=False)

    def remember_unconfirmed(
        self,
        pid: int,
        created_at: float,
        image: str | None,
        incident_id: str,
        dispatched_at: float,
        dispatched_mono: float | None = None,
    ) -> Termination:
        """A terminate of this process that was refused, timed out or unreachable."""
        now = self.clock()
        entry = Termination(int(pid), created_at, image, incident_id, dispatched_at, now, dispatched_mono)
        with self._lock:
            key = (entry.pid, created_at)
            attempts = self._unconfirmed.pop(key, None) or deque(maxlen=self.unconfirmed_attempts)
            attempts.append(entry)
            self._unconfirmed[key] = attempts
            self._expire(now)
        return entry

    def unconfirmed(self, pid: int, created_at: float | None = None) -> list[Termination]:
        """Remembered unconfirmed terminates of one process (or of every process
        on `pid` when `created_at` is None), newest first within each process."""
        with self._lock:
            self._expire(self.clock())
            if created_at is not None:
                return list(reversed(self._unconfirmed.get((int(pid), created_at), ())))
            return [e for (p, _), attempts in self._unconfirmed.items() if p == int(pid)
                    for e in reversed(attempts)]

    def remember(
        self,
        pid: int,
        created_at: float | None,
        image: str | None,
        incident_id: str,
        dispatched_at: float,
        dispatched_mono: float | None = None,
    ) -> Termination:
        now = self.clock()
        entry = Termination(int(pid), created_at, image, incident_id, dispatched_at, now, dispatched_mono)
        with self._lock:
            key = (entry.pid, created_at)
            self._items.pop(key, None)
            self._items[key] = entry
            self._expire(now)
        return entry

    def entries(self, pid: int) -> list[Termination]:
        """This PID's remembered kills, newest first."""
        with self._lock:
            self._expire(self.clock())
            return [e for e in reversed(self._items.values()) if e.pid == int(pid)]

    def find(
        self, pid: int, *, created_at: float | None = None, incident_id: str | None = None
    ) -> Termination | None:
        """The newest remembered kill of `pid`, or None.

        Narrowed to one process with `created_at` (its start time, as
        `ProcessFacts.created_at` gives it) and to one incident with
        `incident_id`. This is the question other code asks - "has this
        process already been killed, and for which incident?" - rather than
        keeping a second record of its own.
        """
        for entry in self.entries(pid):
            if created_at is not None and entry.created_at != created_at:
                continue
            if incident_id is not None and entry.incident_id != incident_id:
                continue
            return entry
        return None

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._unconfirmed.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


TERMINATIONS = TerminationRegistry()

# Only the threads bound here - the Monitor's escalation kill workers
# (app._Escalator) - consult and fill TERMINATIONS. Anything else that calls
# `escalate` or `escalation_action`, such as the safety-invariant tests, asks
# the Response service every time, as it always did.
_ESCALATION_THREAD = threading.local()


def bind_escalation_thread(probe: "Callable[[int], attribution.ProcessFacts | None]") -> None:
    """Let the calling thread skip kills already made, probing PIDs with `probe`."""
    _ESCALATION_THREAD.probe = probe


def _probe(probe, pid: int) -> "attribution.ProcessFacts | None | bool":
    """The probe's answer, or False when the PID could not be inspected."""
    try:
        return probe(pid)
    except Exception:  # ProbeUnavailable, or anything else: unproven
        return False


def _killed_earlier(
    answer: "attribution.Attribution", probe, read_mono: float | None = None
) -> Termination | None:
    """The earlier kill that already covers this answer, if there is one.

    Only when the answer's write was by the process already killed (on both
    clocks when `read_mono` is known, `Termination.wrote`), and the PID is now
    gone or held by a process that started after the write and so cannot have
    made it. If the probe fails, or the killed process is somehow still there,
    the request goes out as before.
    """
    tolerance = attribution.CLOCK_TOLERANCE_MS / 1000.0
    for entry in TERMINATIONS.entries(answer.pid):
        if not entry.wrote(answer, read_mono):
            continue
        now = _probe(probe, answer.pid)
        if now is None:
            return entry
        if (
            now
            and now.created_at is not None
            and now.created_at != entry.created_at
            and now.created_at > answer.written_at + tolerance
        ):
            return entry
        return None
    return None


def _started_after_write(facts, answer: "attribution.Attribution") -> bool:
    """Does the PID's current owner provably post-date the write?

    `Attributor.verify`'s start-time rule, unchanged: created later than the
    write plus the clock tolerance, so it cannot have made it - the writer
    exited and its PID was reused. Anything unreadable (probe failed, PID gone,
    no start time, no write time) is not proof.
    """
    if not facts or facts.created_at is None or answer.written_at is None:
        return False
    tolerance = attribution.CLOCK_TOLERANCE_MS / 1000.0
    return facts.created_at > answer.written_at + tolerance


def _writer_started_at(answer: "attribution.Attribution", facts) -> float | None:
    """The start time of the process about to be killed, if it can be the writer."""
    if not facts or facts.created_at is None or _started_after_write(facts, answer):
        return None
    return facts.created_at


def _unconfirmed_earlier(
    answer: "attribution.Attribution", facts, read_mono: float | None = None
) -> list[Termination]:
    """The unconfirmed terminates that already cover this answer, newest first, or [].

    R-RACE (b): a terminate that times out or finds the Response service
    unreachable was not remembered, so each later question about the same
    process paid the full timeout again (3 s each live), one after another.

    Covered means: at least `UNCONFIRMED_ATTEMPTS` terminates of one process
    were asked for after this answer's write and none was confirmed. The
    process is the one the probe sees now (same PID *and* start time), or, if
    the PID is gone, any process on it; and each attempt must be about this
    write (`Termination.wrote`: same image, started by the write, the write
    before the request on both clocks). A write made after them, a different
    live process on the PID, or a probe that failed all ask the Response
    service as before.
    """
    if facts is False:
        return []
    if facts is None:
        attempts = TERMINATIONS.unconfirmed(answer.pid)
    else:
        started_at = _writer_started_at(answer, facts)
        if started_at is None:
            return []
        attempts = TERMINATIONS.unconfirmed(answer.pid, started_at)
    covering: dict[float | None, list[Termination]] = {}
    for entry in attempts:
        if entry.wrote(answer, read_mono):
            covering.setdefault(entry.created_at, []).append(entry)
    for entries in covering.values():
        if len(entries) >= TERMINATIONS.unconfirmed_attempts:
            return entries
    return []


def escalate(
    client: httpx.Client,
    event: dict,
    question: "attribution.Question",
    answer: "attribution.Attribution",
    outcome: str,
) -> dict:
    """Close an attribution question that was left open, on the chain.

    Written for every question the Monitor kept open, whether or not it ended
    in a kill: "the horizon closed and no record arrived", "two writers turned
    up" and "the writer had already exited" are all answers an auditor needs,
    and without this block they would be indistinguishable from a question
    nobody asked. It is a *new* block, joined to the incident by `incident_id`;
    the `file_event` and `response_action` blocks written when the first answer
    came back are never touched, because they are inside the hash chain.

    The two halves, `escalation_action` and `record_escalation`, are also
    called apart: the Monitor takes the action the moment a question closes,
    and writes the block only once the incident's own blocks are in the chain
    (app._Escalator).
    """
    action = escalation_action(client, question, answer)
    return record_escalation(client, event, question, answer, outcome, action)


def escalation_action(
    client: httpx.Client,
    question: "attribution.Question",
    answer: "attribution.Attribution",
) -> dict:
    """The action a closed question authorises, taken now: a kill, or nothing.

    Freeze-first first (`suspend_policy.on_close`): if this question's writer
    was suspended, the lease is converted to the kill the unchanged gate
    authorises or the process is resumed. It never decides the kill - the
    action below does, from `answer.kill_authorised` alone - and with nothing
    suspended, or freeze-first off, it returns None and this is exactly the
    function it was. The action carries what happened to the lease as `lease`.

    The rest of this docstring is about the kill itself.

    On the escalation thread, a kill this Monitor has already made for the same
    process is not asked for again (`_killed_earlier`); the action then carries
    `terminated_earlier`, the earlier kill's incident and time.

    Also on the escalation thread, the PID is probed just before the request.
    If its current owner provably started after the write (`verify`'s
    start-time rule, `_started_after_write`), the writer has exited and Windows
    has reused the number - between the close and the dispatch, or after the
    kill memory forgot an earlier kill. The Response service kills by PID
    alone, so the request would kill that new, innocent owner: it is not sent,
    and the action carries `pid_reused_before_kill`. A probe that fails, a PID
    that is gone, or a start time that cannot be read is not proof, and the
    request goes out exactly as before.

    Also on the escalation thread, a request that is not confirmed is
    remembered (never as a kill). Once `UNCONFIRMED_ATTEMPTS` of them about this
    write by this process have gone unconfirmed, a further question about it is
    not asked again: the action carries `termination_unconfirmed_earlier`
    (`_unconfirmed_earlier`). A later write by the process is asked for anew.
    """
    lease = suspend_policy.on_close(question, answer)
    lease_id = lease.get("lease_id") if lease and lease.get("action") == "terminate" else None
    action = _take_action(client, question, answer, lease_id)
    if lease is not None:
        action["lease"] = _lease_after(lease, action)
    return action


def _lease_after(lease: dict, action: dict) -> dict:
    """The lease's record once the kill it was converted to has been tried."""
    if lease.get("action") != "terminate":
        return lease
    termination = action.get("termination")
    if termination is not None and termination.get("status") == "terminated":
        return {**lease, "outcome": "terminated",
                "reason": "killed at the horizon: the kill gate was satisfied; the kill carried the lease"}
    if action.get("response_dispatched_at") is None:
        # The kill was not sent (terminated earlier, PID reused, retry budget
        # spent). A frozen process cannot have lost its PID, so this is a
        # process that is already gone; the lease ends on its own expiry.
        return {**lease, "outcome": "terminate_not_sent",
                "reason": "the kill was authorised and not sent (see the action); the lease ends on its expiry"}
    return {**lease, "outcome": "terminate_not_confirmed",
            "reason": "the kill was authorised and not confirmed; the lease ends on its own expiry"}


def _take_action(
    client: httpx.Client,
    question: "attribution.Question",
    answer: "attribution.Attribution",
    lease_id: str | None,
) -> dict:
    """`escalation_action`'s kill, with the lease it is to release, if any."""
    termination = None
    dispatched_at = None
    if answer.kill_authorised:
        probe = getattr(_ESCALATION_THREAD, "probe", None)
        started_at = None
        if probe is not None:
            earlier = _killed_earlier(answer, probe, getattr(question, "horizon_from", None))
            if earlier is not None:
                return {"termination": None, "response_dispatched_at": None,
                        "terminated_earlier": earlier.as_record()}
            facts = _probe(probe, answer.pid)
            if _started_after_write(facts, answer):
                return {"termination": None, "response_dispatched_at": None,
                        "pid_reused_before_kill": {
                            "written_at": attribution.iso_utc(answer.written_at),
                            "process_started_at": attribution.iso_utc(facts.created_at),
                            "process_image": facts.image,
                        }}
            started_at = _writer_started_at(answer, facts)
            unconfirmed = _unconfirmed_earlier(answer, facts, getattr(question, "horizon_from", None))
            if unconfirmed:
                return {"termination": None, "response_dispatched_at": None,
                        "termination_unconfirmed_earlier": {**unconfirmed[0].as_record(),
                                                            "attempts": len(unconfirmed)}}
        dispatched_epoch = time.time()
        dispatched_mono = time.perf_counter()
        dispatched_at = utc_now()
        termination = request_termination(client, question.key, answer, lease_id=lease_id)
        if probe is not None:
            if termination is not None and termination.get("status") == "terminated":
                TERMINATIONS.remember(answer.pid, started_at, answer.image, question.key, dispatched_epoch,
                                      dispatched_mono)
            elif started_at is not None:
                # Refused, timed out or unreachable: never a kill, but remembered so
                # that the process's later questions do not each pay it again.
                TERMINATIONS.remember_unconfirmed(answer.pid, started_at, answer.image, question.key,
                                                  dispatched_epoch, dispatched_mono)
    return {"termination": termination, "response_dispatched_at": dispatched_at}


def escalation_result(answer: "attribution.Attribution", action: dict) -> str:
    if not answer.kill_authorised:
        return "not_escalated"
    if action.get("terminated_earlier"):
        # This process was already killed, at this Monitor's request, for an
        # earlier question; nothing was asked of the Response service again.
        return "terminated_earlier"
    if action.get("pid_reused_before_kill"):
        # The writer was gone and its PID already belonged to a process that
        # started after the write; no kill was asked for, so nothing innocent
        # was killed and the writer was not either.
        return "pid_reused_before_kill"
    if action.get("termination_unconfirmed_earlier"):
        # This process's kill was already asked for, after this write, and not
        # confirmed (refused, timed out or unreachable) as many times as the
        # retry budget allows; nothing was asked again for this question. Not a
        # kill: the process may still be running.
        return "termination_unconfirmed_earlier"
    if action.get("termination") is None:
        # 409 from the guard, or unreachable. The Response service's own block
        # carries the refusal reason when it was reachable.
        return "termination_refused_or_unreachable"
    return "terminated"


def record_escalation(
    client: httpx.Client,
    event: dict,
    question: "attribution.Question",
    answer: "attribution.Attribution",
    outcome: str,
    action: dict,
) -> dict:
    """The `attribution_escalation` block for a question whose action was taken."""
    termination = action.get("termination")
    dispatched_at = action.get("response_dispatched_at")
    result = escalation_result(answer, action)

    record = {
        "incident_id": question.key,
        "event_id": event.get("event_id"),
        "file_path": event.get("file_path"),
        "renamed_from": event.get("renamed_from"),
        "file_hash": event.get("file_hash"),
        "observed_at": attribution.iso_utc(question.observed_at),
        "horizon_closed_at": attribution.iso_utc(question.settle_at),
        "initial_attribution_confidence": question.first.confidence,
        "initial_attribution_reason": question.first.reason,
        "outcome": outcome,
        "result": result,
        "action_requested": "terminate_process" if answer.kill_authorised else None,
        # Only a CERTAIN answer's PID (chained_pid). A PROBABLE one's - two
        # writers, or a writer that exited - is in attribution_candidates.
        "process_id": chained_pid(answer.pid, answer.confidence),
        "process_image": answer.image,
        "attribution_confidence": answer.confidence,
        "attribution_reason": answer.reason,
        "attribution_source": answer.source,
        "attribution_candidates": list(answer.candidates),
        # The matched 4663's own times: when the write happened by the event
        # log's clock, when it reached the Monitor, and the lag between them.
        # This is the measurement defect 1 turned on, recorded per incident.
        "audit_record": answer.audit_record(),
        "response_dispatched_at": dispatched_at,
        "termination": termination,
        # The further notifications for this file that joined the incident
        # while its question was open (app._join_open_incident, F6). Their
        # writes are inside this answer's window and horizon - which is why
        # `horizon_closed_at` can sit up to MONITOR_COALESCE_MS later than
        # `observed_at` plus the horizon - and they have no blocks of their own.
        "coalesced_event_ids": list(event.get("coalesced_event_ids") or []),
        "timestamp": utc_now(),
    }
    if action.get("terminated_earlier"):
        # Which incident's kill this was: the join an auditor needs to find the
        # Response service's own `response_action` block for it.
        record["terminated_earlier"] = action["terminated_earlier"]
    if action.get("pid_reused_before_kill"):
        # Why the authorised kill was not sent: the write's time against the
        # start time of the process that held the PID at dispatch.
        record["pid_reused_before_kill"] = action["pid_reused_before_kill"]
    if action.get("termination_unconfirmed_earlier"):
        # The latest unconfirmed attempt (its incident and time) and how many
        # there were: where an auditor finds the refusals or the silence.
        record["termination_unconfirmed_earlier"] = action["termination_unconfirmed_earlier"]
    if action.get("lease"):
        # Freeze-first: the lease this incident's writer was held under, when
        # it was suspended at all - when, how it ended (terminated, resumed,
        # refused...) and why. No process id: the Response service's own
        # `process_suspended` / `process_resumed` blocks name it, with the gate
        # (C-16, scripts/ledger_coverage.py). Absent when nothing was asked.
        record["lease_id"] = action["lease"].get("lease_id")
        record["suspension"] = action["lease"]
    block = log_to_ledger(client, "attribution_escalation", record)
    return {"record": record, "block": block, "termination": termination, "result": result}


def run(event: dict, features: dict, verdict: dict, client: httpx.Client | None = None) -> PipelineResult:
    """ML -> ledger -> response for one detected event.

    Returns what each hop did so `/monitor/events` can show the chain and the
    integration test can assert on it.
    """
    owns_client = client is None
    client = client or httpx.Client(timeout=DOWNSTREAM_TIMEOUT)
    result = PipelineResult(
        {
            "prediction": None,
            "ledger_block": None,
            "response": None,
            "stages": [],
            "incident_id": None,
            "response_dispatched_at": None,
        }
    )

    try:
        file_hash = event.get("file_hash")

        prediction = predict(client, features)
        if prediction:
            result["prediction"] = prediction
            result["stages"].append("ml_predicted")

        model_threat_level = (prediction or {}).get("threat_level")
        threat_level = effective_threat_level(model_threat_level, verdict["suspicious"])
        label = (prediction or {}).get("prediction", "ransomware" if verdict["suspicious"] else "benign")

        # file_hash is the field SI's recovery integrity check depends on.
        event_data = {
            "file_path": event.get("file_path"),
            # Joins this block to the incident's response and escalation blocks.
            # The incident ID is now given at detection, so it no longer embeds
            # this block's ID; it is carried here instead.
            "event_id": event.get("event_id"),
            "incident_id": event.get("incident_id"),
            # The old name when this event is a rename, so a rewrite-then-rename
            # can be followed from the chain alone: the write happened under
            # `renamed_from`, the ciphertext sits at `file_path`.
            "renamed_from": event.get("renamed_from"),
            "file_hash": file_hash,
            "event_type": event.get("event_type"),
            "entropy": verdict.get("entropy"),
            # Differential entropy - the rise that made this suspicious, when a
            # rise is what did. Null for a file seen only once.
            "entropy_delta": verdict.get("entropy_delta"),
            "verdict": verdict.get("verdict"),
            "reason": verdict.get("reason"),
            # Which detection fired, and whether any operator rule tried to
            # cancel it. An outranked suppression is recorded here with both
            # costs, so the chain shows a rule that was consulted and lost
            # rather than leaving the operator to wonder why theirs did nothing.
            "signal": verdict.get("signal"),
            "admissibility": event.get("admissibility"),
            "container_format": verdict.get("container_format"),
            "container_valid": verdict.get("container_valid"),
            # An *attenuated* decision is chained here rather than as a
            # `suppression_decision`, because the alert stood and the event went
            # through the pipeline. TC-23 asks for the same five fields on it as
            # on a cancelled one, so both blocks carry them.
            "validation_state": verdict.get("validation_state"),
            "policy_version": verdict.get("policy"),
            "detection_latency_ms": event.get("detection_latency_ms"),
            # Only a CERTAIN answer's PID; a PROBABLE answer's are the
            # candidates below (chained_pid, C-16).
            "process_id": chained_pid(event.get("process_id"), event.get("attribution_confidence")),
            "attribution_candidates": list(event.get("attribution_candidates") or []),
            # Attribution travels into the chain with the event it explains. A
            # PID in the ledger with no confidence beside it cannot be audited
            # later: the reader cannot tell whether a kill was declined because
            # nothing was found or because what was found was not good enough.
            "process_image": event.get("process_image"),
            "attribution_confidence": event.get("attribution_confidence"),
            "attribution_reason": event.get("attribution_reason"),
            "attribution_source": event.get("attribution_source"),
            # True when this answer was taken before the audit channel could
            # have delivered everything, and the question was kept open. The
            # closing answer is a separate `attribution_escalation` block with
            # this incident's ID.
            "attribution_pending": event.get("attribution_pending", False),
            "prediction": label,
            "confidence": (prediction or {}).get("confidence"),
            "threat_level": threat_level,
            # What the model said before the Monitor's verdict was applied as a
            # floor. Recorded so an escalated entry ("prediction": "benign",
            # "threat_level": "high") reads as a deliberate override with both
            # inputs visible, rather than as two fields contradicting each other.
            "model_threat_level": model_threat_level,
        }

        block = log_to_ledger(client, "file_event", event_data)
        if block:
            result["ledger_block"] = block
            result["stages"].append("ledger_logged")

        if threat_level in ACTIONABLE_THREAT_LEVELS:
            # The Monitor names the incident when it detects it (app._correlate),
            # so a kill that comes before this point can carry it. A caller that
            # did not gets the old name, built from the file_event block.
            incident_id = event.get("incident_id") or (
                f"inc_{(block or {}).get('block_id', 'na')}_{event.get('event_id', 'na')}"
            )
            result["incident_id"] = incident_id
            # When the response was *asked for* - the end of everything the
            # Monitor controls. With `observed_at` on the event, the gap between
            # the two is the whole queue-and-fan-out delay that
            # `detection_latency_ms` deliberately does not include.
            result["response_dispatched_at"] = utc_now()
            response = trigger_response(
                client,
                incident_id,
                event.get("process_id"),
                threat_level,
                admissibility=event.get("admissibility"),
                attribution_confidence=event.get("attribution_confidence", attribution.UNKNOWN),
                attribution_reason=event.get("attribution_reason"),
                process_image=event.get("process_image"),
                attribution_candidates=event.get("attribution_candidates"),
            )
            if response:
                result["response"] = response
                result["stages"].append("response_triggered")
                log_to_ledger(
                    client,
                    "response_action",
                    {
                        "file_path": event.get("file_path"),
                        "file_hash": file_hash,
                        "incident_id": incident_id,
                        "threat_level": threat_level,
                        "actions_taken": response.get("actions_taken", []),
                        "admissibility": event.get("admissibility"),
                        # The third block that can hold an adjudication, and so
                        # the third that TC-23 reads. An attenuated decision is
                        # chained here as well as on the `file_event`; a record
                        # complete on one and truncated on the other is not a
                        # complete record.
                        "validation_state": verdict.get("validation_state"),
                        "policy_version": verdict.get("policy"),
                        "timestamp": utc_now(),
                    },
                )
        return result
    finally:
        if owns_client:
            client.close()
