"""Freeze-first - the Monitor side of defect 26 (F2b): suspend a sole writer early, then kill or resume.

THE IDEA. The Monitor cannot kill on a first answer: the audit record for the
first write arrives 116-1,269 ms after it (median 888-985 ms on the VM), a
second writer's can arrive later still, and a kill cannot be taken back. But it
can *freeze* on one, because a freeze can be: as soon as a kernel-grade answer
names exactly one writer so far, the Response service is asked to suspend that
process under a lease, and the question stays open exactly as before. At the
delivery horizon one of two things happens, and both are decided by the
unchanged kill gate:

  * `Attribution.kill_authorised` is true -> the frozen process is killed, and
    the terminate carries the lease id so the lease is released with the kill;
  * anything else (a second writer turned up, the writer exited, the identity
    no longer holds, no record) -> the process is RESUMED, and the escalation
    block says why.

A second writer that appears during the lease closes the question early as
ambiguous (`PendingAttribution.sweep`), which is the same "anything else": the
process is resumed and never killed.

WHAT THIS CAN AND CANNOT DO. It reduces damage for attackers still running when
the first audit record arrives. On the VM the simulator families that were not
killed had already finished and exited before the horizon, and the 4663 for a
first write arrives ~0.4-1 s after it, so there was nothing left to freeze. The
code cannot make the fastest attackers stoppable. Nothing here has run against
a live Security-log subscription (that needs elevation); every test drives a
real process through a stubbed Response service and a recorded audit answer.

THE RULES IT KEEPS.
  * Suspension is the only action allowed on the weaker gate
    (`Attribution.suspend_authorised`); a kill is never asked for below
    `kill_authorised`, and this module never asks for one itself - it only
    tells `pipeline.escalation_action` whether the lease that exists should be
    named on the kill that gate already authorised.
  * Every suspension is undoable and is certain to be undone: the lease expires
    on the Response side whatever happens to this process (`SUSPEND_LEASE_S`),
    `/monitor/stop` and the lifespan shutdown release every lease held, and
    `atexit` does as a last resort.
  * C-16: this module writes no ledger block that names a process. The
    `process_suspended` / `process_resumed` blocks are the Response service's;
    the Monitor's `attribution_escalation` block gains lease fields and no PID.
  * Anything that goes wrong here - Response unreachable, a 409, a bug - is
    logged and ignored. Detection and the ordinary kill path never depend on
    this module and are unchanged when it does nothing.

Two hooks into the rest of the Monitor, and no more: `on_first_answer`, called
from `app._correlate` right after the first verified answer, and `on_close`,
called at the top of `pipeline.escalation_action`. `MONITOR_SUSPEND_FIRST=0`
turns both into no-ops and the Monitor behaves exactly as it did without them.
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
import time
from collections import OrderedDict, Counter
from dataclasses import dataclass, field
from typing import Iterable

import httpx

import attribution

logger = logging.getLogger("monitor.suspend")

#: The gate name sent to the Response service and recorded by it on every block
#: that names the PID. The C-16 scan accepts a `process_suspended` /
#: `process_resumed` block naming a PID only with exactly this value.
GATE = "suspend_authorised"

#: `MONITOR_SUSPEND_FIRST`: on unless set to 0 / false / off / no.
ENV_SWITCH = "MONITOR_SUSPEND_FIRST"

#: Slack for the kill to be dispatched after the horizon closes: the sweeper's
#: own lag (`PendingAttribution.max_close_lag_ms`), the intake hop, and the
#: terminate request itself. The lease has to outlive all of it, or the
#: process would resume a moment before it was killed.
KILL_DISPATCH_MARGIN_MS = float(os.getenv("MONITOR_KILL_DISPATCH_MARGIN_MS", "500"))

#: How long a lease is asked for: the horizon, the clock tolerance the horizon
#: is closed with, and the dispatch margin - the longest a question can stay
#: open, counted from the moment of the suspension and so an over-estimate of
#: what is left. 2.05 s by default; the Response service caps a lease at
#: RESPONSE_LEASE_MAX_SECONDS (10). Measured from the suspend, not the write,
#: because that is what the lease is.
SUSPEND_LEASE_S = float(os.getenv(
    "MONITOR_SUSPEND_LEASE_S",
    str((attribution.HORIZON_MS + attribution.CLOCK_TOLERANCE_MS + KILL_DISPATCH_MARGIN_MS) / 1000.0),
))

#: The suspend request is made on a thread of its own (never on a correlation
#: lane or the sweeper), so what a slow Response costs is only the time before
#: the freeze. Short anyway, because the process keeps writing until it lands:
#: a warm Response answers in milliseconds, and a cold one took longer than
#: 0.5 s for its first suspend when measured against the real service.
#: A timeout is not a refusal - the request may have been carried out - and is
#: handled as such (`uncertain`).
SUSPEND_TIMEOUT_S = float(os.getenv("MONITOR_SUSPEND_TIMEOUT_S", "1.0"))
#: One resume. Longer than a suspend: this is the call that undoes a freeze.
RESUME_TIMEOUT_S = float(os.getenv("MONITOR_RESUME_TIMEOUT_S", "1.0"))
#: The whole of `release_all` (`/monitor/stop`, shutdown): best effort, short,
#: because Response's lease expiry is the backstop and a stop must not hang.
RELEASE_TIMEOUT_S = float(os.getenv("MONITOR_SUSPEND_RELEASE_TIMEOUT_S", "2.0"))

#: After a process is resumed without being killed (or a suspend of it was
#: refused), it is not frozen again for this long. A benign process that keeps
#: writing files the detector flags would otherwise be frozen for a horizon per
#: file. It only ever removes a suspension; it never adds an action.
COOLDOWN_S = float(os.getenv("MONITOR_SUSPEND_COOLDOWN_S", "30"))
#: After Response is unreachable, or refuses for a reason that is not about one
#: process (Docker's PID namespace, a bad URDS_MONITOR_PID, shutting down), no
#: further suspend is asked for this long: every file would cost a lane the same
#: failed round trip.
BACKOFF_S = float(os.getenv("MONITOR_SUSPEND_BACKOFF_S", "5"))
GLOBAL_REFUSALS = frozenset({"PID_NAMESPACE_ISOLATED", "MONITOR_PID_INVALID", "SHUTTING_DOWN",
                             "WATCHDOG_UNAVAILABLE"})

#: Holds remembered (active ones and recently ended ones, which later questions
#: of the same writer still report). Bounded like every per-event structure here.
MAX_HOLDS = int(os.getenv("MONITOR_SUSPEND_MAX_HOLDS", "1024"))


#: A hold in one of these states may have a process frozen under it.
ACTIVE = ("requesting", "held", "uncertain")
#: ... and once its request has been answered, one of these may still need undoing.
RELEASABLE = ("held", "uncertain", "terminating")


def enabled() -> bool:
    """Is freeze-first on? Read at every call, so an operator's change takes effect."""
    return os.getenv(ENV_SWITCH, "1").strip().lower() not in {"0", "false", "off", "no"}


def _response_url() -> str:
    import pipeline  # noqa: PLC0415 - the one place RESPONSE_URL is configured; pipeline imports this module

    return pipeline.RESPONSE_URL


@dataclass
class Hold:
    """One suspension this Monitor asked for: one per PID, shared by that writer's incidents."""

    pid: int
    incident_id: str
    created: float
    #: Held while the suspend request is in flight, so a close that arrives for
    #: this PID meanwhile waits for it rather than missing the lease.
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    #: requesting | held | uncertain | refused | terminating | ended.
    #: `uncertain`: the request timed out, so the lease may or may not exist;
    #: it is undone by PID, which the Response service accepts.
    state: str = "requesting"
    lease_id: str | None = None
    #: False when Response said `already_held`: someone else's lease (an operator's,
    #: or one a previous Monitor took). It is not this Monitor's to resume.
    owned: bool = True
    suspended_at: str | None = None
    expires_at: str | None = None
    lease_seconds: float | None = None
    code: str | None = None
    detail: str | None = None
    failure: str | None = None
    #: What became of it, once decided: the first question to close decides, and
    #: the writer's other questions report the same.
    disposition: dict | None = None
    decided_by: str | None = None
    ended: float | None = None

    def record(self, outcome: str, **extra) -> dict:
        """The lease's part of the escalation block. Names no process: C-16."""
        out = {
            "lease_id": self.lease_id,
            "gate": GATE,
            "outcome": outcome,
            "suspended_at": self.suspended_at,
            "expires_at": self.expires_at,
            "lease_seconds": self.lease_seconds,
            "already_held": not self.owned,
            "code": self.code,
        }
        out.update(extra)
        return out


class SuspendPolicy:
    """Decides, per writer, whether to freeze, and what to do with the freeze at the horizon."""

    def __init__(self, client: httpx.Client | None = None, clock=time.monotonic) -> None:
        self._client = client
        self._client_lock = threading.Lock()
        self._clock = clock
        self._lock = threading.RLock()
        self._holds: "OrderedDict[int, Hold]" = OrderedDict()
        self._by_incident: "OrderedDict[str, Hold]" = OrderedDict()
        self._cooldown: dict[int, float] = {}
        #: (incident, pid) pairs already looked at. A question is re-asked on
        #: every recorded write, so the same answer reaches this hook many
        #: times; it is judged once.
        self._handled: "OrderedDict[tuple[str, int], bool]" = OrderedDict()
        self._backoff_until = 0.0
        self._closing = False
        self.counts: Counter = Counter()

    # -- the Response client ---------------------------------------------

    def _http(self) -> httpx.Client:
        with self._client_lock:
            if self._client is None:
                self._client = httpx.Client(timeout=SUSPEND_TIMEOUT_S)
            return self._client

    def warm(self) -> None:
        """Build the HTTP client off the request path.

        Constructing one builds an SSL context and the CA bundle: 311-1545 ms on
        the loaded 4-vCPU VM (FIXES.md defect 22). The first suspend is the one
        that matters most, and must not pay for it. Called when the watch starts.
        """
        if self._client is None:
            threading.Thread(target=self._http, name="monitor-suspend-warm", daemon=True).start()

    def _call(self, path: str, payload: dict, timeout: float) -> tuple[int, dict]:
        """One request to the Response service: (status, body). Raises httpx.HTTPError / ValueError.

        The terminate call's conventions (pipeline._post): a bounded timeout, and
        a transport error or an unreadable body is the caller's to treat as
        "unreachable". Unlike `_post` the status is kept: a 409's code is the
        reason, and it goes in the record.
        """
        response = self._http().post(f"{_response_url()}{path}", json=payload, timeout=timeout)
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body if isinstance(body, dict) else {}

    # -- the first answer -------------------------------------------------

    def on_first_answer(
        self,
        attributor,
        event: dict,
        first,
        path: str,
        roots: Iterable[str],
        *,
        parked: bool,
        lock=None,
        incident_id: str | None = None,
        background: bool = False,
    ) -> dict | None:
        """Freeze the writer `first` names, if `suspend_authorised` and not already frozen.

        Called when an answer first names a writer: by `app._correlate` on the
        first look, and by the pending sweeper when a re-ask of an open
        question does - on the VM the audit record usually arrives after the
        first look, so the second is the usual one. The same answer reaching
        here again is judged once (`_handled`).

        `parked`: a question is open for this answer, so something will close
        it. Without one nothing would end the freeze but the lease's expiry, so
        nothing is suspended. `incident_id` defaults to the event's.
        `background`: the caller is the sweeper, which must go on closing
        questions on time; the request is made on a thread of its own (the
        lease is still registered before this returns, so a close that comes
        meanwhile waits for it). Returns the record put on the event
        (`event["suspension"]`), or None when no request was made - which is
        every case with the switch off, and leaves the event exactly as it was.
        """
        try:
            return self._first_answer(attributor, event, first, path, roots, parked, lock,
                                      incident_id, background)
        except Exception:  # nothing here may break correlation
            logger.exception("freeze-first failed for %s; carrying on without it", path)
            return None

    def _first_answer(self, attributor, event, first, path, roots, parked, lock, incident_id,
                      background) -> dict | None:
        if not enabled() or self._closing or not parked or first.pid is None:
            return None
        incident = incident_id or event.get("incident_id")
        if not incident:
            return None
        pid = int(first.pid)
        now = self._clock()
        if (incident, pid) in self._handled:
            return None

        with self._lock:
            hold = self._holds.get(pid)
            if hold is not None and hold.state in ACTIVE:
                self.counts["pid_already_held"] += 1
                self._link(incident, hold)
                self._remember(incident, pid)
            else:
                hold = None
                if self._cooldown.get(pid, 0.0) > now:
                    self.counts["skipped_cooldown"] += 1
                    return None
                if now < self._backoff_until:
                    self.counts["skipped_backoff"] += 1
                    return None
        if hold is not None:
            # One suspend per PID per lease, never one per file: this incident
            # joins the lease that exists.
            return self._join(hold, incident, event, lock, background)

        assessed, outcome = attributor.assess_suspend(first, path, roots)
        with self._lock:
            self._remember(incident, pid)
        if not assessed.suspend_authorised:
            self.counts[f"skipped_{outcome}"] += 1
            logger.debug("freeze-first: not suspending %s (%s): %s", pid, outcome, assessed.suspend_blockers())
            return None

        with self._lock:
            hold = self._holds.get(pid)
            if hold is not None and hold.state in ACTIVE:
                mine = False  # another lane got there between the check and now
            else:
                mine = True
                hold = Hold(pid=pid, incident_id=incident, created=now)
                hold.lock.acquire()
                self._holds[pid] = hold
                self._prune(now)
            self._link(incident, hold)
        if not mine:
            return self._join(hold, incident, event, lock, background)

        if background:
            threading.Thread(
                target=self._suspend_and_annotate, args=(hold, assessed, incident, event, lock),
                name="monitor-suspend", daemon=True,
            ).start()
            return None
        return self._suspend_and_annotate(hold, assessed, incident, event, lock)

    def _suspend_and_annotate(self, hold: Hold, answer, incident: str, event: dict, lock) -> dict | None:
        """Make the one request and put its record on the event. Releases the hold lock the caller took.

        The record is on the event before the lock is released, so whoever
        waits for the hold (a close, a test) finds it there.
        """
        try:
            try:
                record = self._suspend(hold, answer, incident)
            except Exception:  # the hold must not stay locked, whatever happened
                logger.exception("freeze-first: suspending for %s failed", incident)
                record = self._uncertain(hold, "unexpected error while suspending")
            self._annotate(event, record, lock)
            return record
        finally:
            hold.lock.release()

    def _join(self, hold: Hold, incident: str, event: dict, lock, background: bool) -> dict | None:
        """This incident's writer is already frozen (or refused): say so on the event."""
        if background:
            # Never wait on a request in flight from the sweeper: the escalation
            # block carries the full lease record when the question closes.
            record = hold.record("uncertain" if hold.state == "uncertain" else "suspended",
                                 shared_with_incident=hold.incident_id)
        else:
            with hold.lock:
                record = self._shared(hold, incident)
        self._annotate(event, record, lock)
        return record

    def _remember(self, incident: str, pid: int) -> None:
        """Note that this answer was judged. Under the lock."""
        self._handled[(incident, pid)] = True
        while len(self._handled) > MAX_HOLDS:
            self._handled.popitem(last=False)

    def _suspend(self, hold: Hold, answer, incident: str) -> dict:
        """The one suspend request for this PID. The hold lock is held by the caller."""
        payload = {
            "process_id": hold.pid,
            "incident_id": incident,
            "lease_seconds": SUSPEND_LEASE_S,
            "reason": f"freeze-first: sole writer so far of an incident, pending the delivery horizon; "
                      f"killed at the horizon only if the kill gate is then satisfied, else resumed",
            # What the Monitor knows, as the Response service records it: the
            # caller's claim, never Response's verdict (leases.gate_record).
            "attribution_confidence": answer.confidence,
            "attribution_source": answer.source,
            "attribution_reason": answer.reason,
            "gate": GATE,
            "image": answer.image,
            # The creation time of the process the probe just identified: the
            # Response service refuses a PID whose live process is newer.
            "started_at": answer.process_started_at,
        }
        payload = {key: value for key, value in payload.items() if value is not None}
        self.counts["requested"] += 1
        stamp = attribution.iso_utc(time.time())
        try:
            status, body = self._call("/response/suspend", payload, SUSPEND_TIMEOUT_S)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # Never reached the service: nothing was suspended.
            return self._failed(hold, "unreachable", None, f"{type(exc).__name__}: {exc}", backoff=True)
        except (httpx.HTTPError, ValueError) as exc:
            # The request went out and no usable answer came back (a read
            # timeout, a dropped connection): the process may be frozen under a
            # lease nobody told us about. Not a refusal; undone by PID.
            return self._uncertain(hold, f"{type(exc).__name__}: {exc}")

        if status >= 400:
            code = body.get("code") or (body.get("error") or {}).get("code") or f"HTTP_{status}"
            detail = body.get("message") or (body.get("error") or {}).get("message") or ""
            return self._failed(hold, "refused", str(code), str(detail),
                                backoff=str(code) in GLOBAL_REFUSALS or status >= 500)

        lease_id = body.get("lease_id")
        if not lease_id or body.get("suspended") is False:
            return self._failed(hold, "refused", "UNEXPECTED_RESPONSE", f"no lease in the reply: {body!r}"[:200],
                                backoff=True)
        with self._lock:
            hold.lease_id = str(lease_id)
            hold.owned = not body.get("already_held")
            hold.suspended_at = stamp
            hold.expires_at = body.get("expires_at")
            hold.lease_seconds = body.get("lease_seconds", SUSPEND_LEASE_S)
            hold.state = "held"
        self.counts["suspended" if hold.owned else "already_held_elsewhere"] += 1
        logger.info("freeze-first: pid %s suspended under lease %s%s", hold.pid, lease_id,
                    "" if hold.owned else " (already held by someone else; not ours to resume)")
        return hold.record("suspended")

    def _uncertain(self, hold: Hold, detail: str) -> dict:
        """The suspend request got no answer: assume the process may be frozen, and say so."""
        now = self._clock()
        with self._lock:
            hold.state = "uncertain"
            hold.detail = detail
            hold.suspended_at = None
            self._backoff_until = now + BACKOFF_S
        self.counts["suspend_uncertain"] += 1
        logger.warning("freeze-first: no answer to the suspend of pid %s (%s); treating it as possibly frozen "
                       "and resuming it by PID when its question closes; the lease expires on its own in at "
                       "most %.1fs", hold.pid, detail, SUSPEND_LEASE_S)
        return hold.record("uncertain", detail=detail)

    def _failed(self, hold: Hold, kind: str, code: str | None, detail: str, backoff: bool) -> dict:
        """The suspend did not happen. Logged, remembered, and nothing else changes."""
        now = self._clock()
        with self._lock:
            hold.state = "refused"
            hold.failure = kind
            hold.code = code
            hold.detail = detail
            hold.ended = now
            if self._holds.get(hold.pid) is hold:
                del self._holds[hold.pid]
            if backoff:
                self._backoff_until = now + BACKOFF_S
            elif kind == "refused":
                self._cooldown[hold.pid] = now + COOLDOWN_S
        self.counts[f"suspend_{kind}"] += 1
        logger.warning("freeze-first: suspend of pid %s %s (%s%s); detection and the kill path are unaffected",
                       hold.pid, kind, code or "no response", f": {detail}" if detail else "")
        return hold.record(kind, detail=detail)

    def _shared(self, hold: Hold, incident: str) -> dict:
        """What a further incident of a writer that is already frozen records."""
        if hold.state == "refused":
            return hold.record(hold.failure or "refused", detail=hold.detail, shared_with_incident=hold.incident_id)
        if hold.state == "uncertain":
            return hold.record("uncertain", detail=hold.detail, shared_with_incident=hold.incident_id)
        return hold.record("suspended", shared_with_incident=hold.incident_id)

    def _link(self, incident: str, hold: Hold) -> None:
        self._by_incident[incident] = hold
        while len(self._by_incident) > MAX_HOLDS:
            self._by_incident.popitem(last=False)

    def _prune(self, now: float) -> None:
        """Forget holds that ended long enough ago that nothing can still ask. Under the lock."""
        horizon = max(2 * SUSPEND_LEASE_S, 30.0)
        for pid, hold in list(self._holds.items()):
            if hold.state in ("terminating", "ended") and hold.ended is not None and now - hold.ended > horizon:
                del self._holds[pid]
        while len(self._holds) > MAX_HOLDS:
            self._holds.popitem(last=False)
        for pid, until in list(self._cooldown.items()):
            if until <= now:
                del self._cooldown[pid]

    @staticmethod
    def _annotate(event: dict, record: dict, lock) -> None:
        if lock is not None:
            with lock:
                event["suspension"] = record
        else:
            event["suspension"] = record

    # -- the horizon --------------------------------------------------------

    def on_close(self, question, answer) -> dict | None:
        """The question closed: convert the freeze to the kill, or undo it.

        Returns None when this question holds no lease (the usual case, and
        every case with the switch off). Otherwise the lease's record for the
        escalation block, with `action`:

          * "terminate" - `answer.kill_authorised` and it names the frozen
            process: the caller sends the kill WITH `lease_id`, and Response
            releases the lease with it;
          * "resume"    - anything else: the process has been resumed here
            (idempotent on the Response side) and `reason` says why;
          * None        - nothing for the caller to do: the writer's lease was
            already decided by another of its questions, was never taken, or is
            someone else's.

        Never kills, and never asks for a kill: the only way a kill follows is
        the caller's own `kill_authorised` check, which this does not touch.
        """
        try:
            return self._close(question, answer)
        except Exception:  # the kill path must not depend on this
            logger.exception("freeze-first: closing %s failed; the lease will expire on its own",
                             getattr(question, "key", "?"))
            return None

    def _close(self, question, answer) -> dict | None:
        with self._lock:
            hold = self._by_incident.pop(question.key, None)
        if hold is None:
            return None
        if not hold.lock.acquire(timeout=SUSPEND_TIMEOUT_S + RESUME_TIMEOUT_S + 1.0):
            logger.warning("freeze-first: a suspend request for %s is still in flight; its lease will expire",
                           question.key)
            return None
        try:
            if hold.state == "refused":
                return hold.record(hold.failure or "refused", detail=hold.detail, action=None)
            if hold.disposition is not None:
                return {**hold.disposition, "action": None, "decided_by_incident": hold.decided_by}

            kill = bool(answer.kill_authorised and answer.pid == hold.pid)
            if kill:
                record = hold.record(
                    "terminate_requested", action="terminate",
                    reason="the kill gate is satisfied at the horizon: the kill goes out carrying the lease",
                )
                with self._lock:
                    hold.state = "terminating"
                    hold.ended = self._clock()
            elif not hold.owned:
                record = hold.record(
                    "left_to_expire", action=None,
                    reason="the lease was already held by someone else; it is not this Monitor's to resume "
                           "and ends on its own expiry",
                )
                with self._lock:
                    hold.state = "ended"
                    hold.ended = self._clock()
            else:
                record = self._resume(hold, self._why_not_killed(answer, hold), question.key)
            hold.disposition = record
            hold.decided_by = question.key
            return record
        finally:
            hold.lock.release()

    @staticmethod
    def _why_not_killed(answer, hold: Hold) -> str:
        if answer.kill_authorised and answer.pid != hold.pid:
            return ("the kill gate is not satisfied for the frozen process: the closing answer names a "
                    "different process")
        pending = ", still pending" if answer.pending else ""
        return (f"the kill gate is not satisfied at the horizon ({answer.confidence}{pending}): "
                f"{answer.reason}")

    def _resume(self, hold: Hold, reason: str, incident: str) -> dict:
        """Undo the freeze. Idempotent: resuming a released lease is a 200 that says it was not held.

        On a failure the hold stays `held`: `release_all` tries again, and
        failing that the Response service's expiry ends the lease.
        """
        payload = {"incident_id": incident, "reason": reason}
        # By lease when there is one; by PID when the suspend's answer was lost.
        payload.update({"lease_id": hold.lease_id} if hold.lease_id else {"process_id": hold.pid})
        resumed_at = attribution.iso_utc(time.time())
        try:
            status, body = self._call("/response/resume", payload, RESUME_TIMEOUT_S)
        except (httpx.HTTPError, ValueError) as exc:
            self.counts["resume_failed"] += 1
            logger.warning("freeze-first: resuming lease %s failed (%s: %s); it expires at %s",
                           hold.lease_id, type(exc).__name__, exc, hold.expires_at)
            return hold.record("resume_failed", action="resume", reason=reason,
                               detail=f"{type(exc).__name__}: {exc}; the lease expires on its own")
        if status >= 400:
            self.counts["resume_failed"] += 1
            logger.warning("freeze-first: resuming lease %s was refused (HTTP %s); it expires at %s",
                           hold.lease_id, status, hold.expires_at)
            return hold.record("resume_failed", action="resume", reason=reason,
                               detail=f"HTTP {status}; the lease expires on its own")
        with self._lock:
            hold.state = "ended"
            hold.ended = self._clock()
            if self._holds.get(hold.pid) is hold:
                del self._holds[hold.pid]
            self._cooldown[hold.pid] = self._clock() + COOLDOWN_S
        if body.get("resumed") is False:
            self.counts["resume_not_needed"] += 1
            return hold.record("resume_not_needed", action="resume", reason=reason, resumed_at=resumed_at,
                               detail=f"the lease had already ended ({body.get('state')})")
        self.counts["resumed"] += 1
        logger.info("freeze-first: lease %s resumed: %s", hold.lease_id, reason)
        return hold.record("resumed", action="resume", reason=reason, resumed_at=resumed_at)

    # -- stop, shutdown, exit -------------------------------------------------

    def release_all(self, reason: str, timeout: float | None = None) -> dict:
        """Resume every lease this Monitor holds. Best effort, short, idempotent.

        `/monitor/stop`, the lifespan shutdown and `atexit` call it. Anything it
        cannot reach is still ended by the Response service's lease expiry (and
        by its own watchdog if Response itself died), which is why this is
        allowed to be short. Questions still open when it runs close later, find
        their hold already ended, and kill - if the gate says so - without a lease.
        """
        budget = RELEASE_TIMEOUT_S if timeout is None else timeout
        deadline = self._clock() + budget
        with self._lock:
            # A request still in flight is included: taking its lock waits for
            # it, and the state is read again once it is held.
            held = [h for h in self._holds.values() if h.state in ("requesting",) + RELEASABLE]
        released, failed, skipped = 0, 0, 0
        for hold in held:
            remaining = deadline - self._clock()
            if remaining <= 0:
                failed += 1
                continue
            if not hold.lock.acquire(timeout=min(remaining, SUSPEND_TIMEOUT_S + 0.5)):
                failed += 1
                continue
            try:
                if hold.state not in RELEASABLE or not (hold.lease_id or hold.state == "uncertain"):
                    continue  # refused or already ended: nothing is frozen under it
                if not hold.owned:
                    skipped += 1
                    continue
                call_timeout = max(0.05, min(RESUME_TIMEOUT_S, deadline - self._clock()))
                payload = {"incident_id": hold.incident_id,
                           "reason": f"{reason}: the Monitor is stopping and releases every lease it holds"}
                payload.update({"lease_id": hold.lease_id} if hold.lease_id else {"process_id": hold.pid})
                try:
                    status, body = self._call("/response/resume", payload, call_timeout)
                except (httpx.HTTPError, ValueError) as exc:
                    failed += 1
                    logger.warning("freeze-first: releasing lease %s failed (%s); it expires at %s",
                                   hold.lease_id, exc, hold.expires_at)
                    continue
                if status >= 400:
                    failed += 1
                    continue
                released += 1
                with self._lock:
                    hold.state = "ended"
                    hold.ended = self._clock()
                    if self._holds.get(hold.pid) is hold:
                        del self._holds[hold.pid]
                if hold.disposition is None or hold.disposition.get("action") == "terminate":
                    hold.disposition = hold.record(
                        "resumed", action=None, resumed_at=attribution.iso_utc(time.time()),
                        reason=f"released at {reason}",
                    )
                    hold.decided_by = hold.incident_id
            finally:
                hold.lock.release()
        if held:
            self.counts["released_on_stop"] += released
            logger.info("freeze-first: %s released %d lease(s), %d failed, %d not ours", reason, released, failed,
                        skipped)
        return {"released": released, "failed": failed, "not_ours": skipped}

    def shutdown(self) -> dict:
        """The Monitor is going away: refuse further suspends and release what is held."""
        self._closing = True
        return self.release_all("monitor_shutdown")

    # -- reporting ----------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            held = [h for h in self._holds.values() if h.state in ACTIVE]
            return {
                "enabled": enabled(),
                "lease_seconds": SUSPEND_LEASE_S,
                "held": len(held),
                "lease_ids": [h.lease_id for h in held if h.lease_id],
                "counts": dict(self.counts),
                "backing_off": self._clock() < self._backoff_until,
            }


#: The process-wide instance, as `attribution.attributor` is. Tests replace it.
POLICY = SuspendPolicy()


def on_first_answer(*args, **kwargs) -> dict | None:
    return POLICY.on_first_answer(*args, **kwargs)


def on_close(question, answer) -> dict | None:
    return POLICY.on_close(question, answer)


def release_all(reason: str, timeout: float | None = None) -> dict:
    return POLICY.release_all(reason, timeout)


def shutdown() -> dict:
    return POLICY.shutdown()


def warm() -> None:
    POLICY.warm()


def stats() -> dict:
    return POLICY.stats()


def _release_at_exit() -> None:
    """The last resort for a clean interpreter exit: nothing stays frozen because this exited."""
    try:
        if POLICY.stats()["held"]:
            POLICY.release_all("monitor_exit", timeout=1.0)
    except Exception:  # an exit handler must not raise
        pass


atexit.register(_release_at_exit)
