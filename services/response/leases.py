"""Suspensions the Response service holds, and the clock that ends them.

A suspension is the cheap half of suspend-before-kill: a wrongly suspended
process resumes and loses a second, a wrongly killed one loses its work. That
asymmetry only holds while every suspension is certain to end. So a suspension
here is never a bare `psutil.Process.suspend()`: it is a **lease**, and a lease
ends in exactly one of four ways, each of which leaves the process running or
gone, never frozen:

    resumed     the caller asked (`/response/resume`), or the lease expired
                (the reaper), or the Response service shut down (lifespan, and
                `atexit` as a backstop)
    terminated  `/response/terminate` killed it; there is nothing to resume
    gone        the process exited while it was held

and, should this process die without running any of that, the out-of-process
watchdog (`lease_watchdog.py`) resumes whatever was still held.

**One lease per PID.** `NtSuspendProcess` nests: a process suspended twice
needs two resumes, and the single resume on the release path would leave it
frozen for good. `fix/evidence-integrity` found exactly that in `5cacb70` (six
suspends for six files). A second suspend of a held PID is therefore a no-op
that returns the existing lease (`already_held`), never a second suspend.

Time is a monotonic clock, injectable, because the test VM's wall clock is
slewed: `expires_at` is reported in wall-clock UTC for people, but expiry is
decided on `clock()`. Nothing in this module knows how to suspend a process;
`vet`, `suspend` and `resume` are handed in, so the table is testable without
one and `actions.py` keeps every guard in one place.
"""

from __future__ import annotations

import logging
import math
import os
import queue
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

logger = logging.getLogger(__name__)

#: The longest lease a caller can ask for. The Monitor asks for about the
#: attribution horizon (1.5 s) plus a margin; this bounds what anyone else can
#: hold, so an abandoned lease costs at most this long.
LEASE_MAX_SECONDS = float(os.getenv("RESPONSE_LEASE_MAX_SECONDS", "10"))

#: How often the reaper looks for expired leases. A lease ends at most this
#: much after its deadline.
REAP_INTERVAL_SECONDS = float(os.getenv("RESPONSE_LEASE_REAP_INTERVAL", "0.1"))

#: Ended leases remembered, so a resume of one already released answers
#: `resumed: false` with what ended it rather than "never heard of it".
HISTORY_LIMIT = 1024

HELD = "held"
RESUMED = "resumed"
TERMINATED = "terminated"
GONE = "gone"


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


#: What a block records when the request carried no gate. The Response service
#: does not evaluate a gate of its own and must not write one it did not
#: evaluate (review finding R8c: it used to stamp "suspend_authorised" on every
#: block, a gate that was never built).
NO_GATE_REASON = "no gate supplied (operator request)"


def gate_record(gate: str | None) -> dict:
    """How a block records the gate: the caller's claim, never Response's verdict."""
    if gate:
        reason = (f"claimed by the caller ({gate!r}); the Response service cannot "
                  "verify it and did not evaluate any gate")
    else:
        reason = NO_GATE_REASON
    return {
        # The attribution fields beside this are the caller's too.
        "attribution_supplied_by": "caller",
        "gate": gate or None,
        "gate_verified": False,
        "gate_reason": reason,
    }


class LeaseError(RuntimeError):
    """A lease could not be granted, with a code for the refusal."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Lease:
    lease_id: str
    process_id: int
    incident_id: str
    reason: str
    attribution_confidence: str | None
    attribution_source: str | None
    attribution_reason: str | None
    image: str | None
    started_at: float | None
    lease_seconds: float
    lease_seconds_requested: float
    granted_at: str
    expires_at: str
    deadline: float
    granted_mono: float
    state: str = HELD
    #: The gate the caller says allowed this suspension, verbatim, or None.
    gate: str | None = None
    ended_by: str | None = None
    ended_reason: str | None = None
    ended_at: str | None = None
    held_ms: float | None = None
    #: The psutil.Process the suspension was made through. Kept so that resume
    #: goes through the same object, whose identity check (psutil refuses to
    #: signal a PID that has been reused) protects whatever holds the number
    #: later.
    handle: Any = field(default=None, repr=False, compare=False)

    def summary(self) -> dict:
        """The contract's shape for `GET /response/leases`."""
        return {
            "lease_id": self.lease_id,
            "process_id": self.process_id,
            "incident_id": self.incident_id,
            "expires_at": self.expires_at,
            "state": self.state,
        }

    def gate_fields(self) -> dict:
        """What the caller said allowed this suspension. Every block naming the
        PID carries it, recorded as the caller's claim (`gate_verified: false`)."""
        return {
            "attribution_confidence": self.attribution_confidence,
            "attribution_source": self.attribution_source,
            "attribution_reason": self.attribution_reason,
            **gate_record(self.gate),
        }


class LeaseTable:
    """Every suspension this process holds. Thread-safe."""

    def __init__(
        self,
        *,
        resume: Callable[[Any], bool],
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        max_seconds: float = LEASE_MAX_SECONDS,
        watchdog: Any = None,
        on_end: Callable[[Lease], None] | None = None,
    ) -> None:
        self._resume = resume
        self._clock = clock
        self._wall = wall
        self.max_seconds = max_seconds
        self.watchdog = watchdog
        self.on_end = on_end
        self._lock = threading.RLock()
        self._held: dict[int, Lease] = {}
        self._by_id: dict[str, Lease] = {}
        self._history: OrderedDict[str, Lease] = OrderedDict()
        self._reaper: threading.Thread | None = None
        self._stop = threading.Event()
        #: Set from shutdown on: no new suspensions, because nothing would end them.
        self._closed = False
        #: Ended leases waiting to be recorded. `on_end` (a ledger write, up to
        #: LEDGER_TIMEOUT each) runs on its own thread once the table is
        #: started, so expiry never waits behind it (review finding R-RACE 5).
        self._notes: queue.Queue = queue.Queue()
        self._recorder: threading.Thread | None = None

    # ---------------------------------------------------------------- granting

    def acquire(
        self,
        process_id: int,
        *,
        incident_id: str,
        lease_seconds: float,
        reason: str,
        vet: Callable[[], Any],
        suspend: Callable[[Any], None],
        attribution_confidence: str | None = None,
        attribution_source: str | None = None,
        attribution_reason: str | None = None,
        gate: str | None = None,
    ) -> tuple[Lease, bool]:
        """Suspend `process_id` under a new lease, or return the one it is under.

        `vet()` runs every guard and returns the process handle (raising to
        refuse); `suspend(handle)` freezes it. The watchdog is told about the
        lease *before* the suspend, so there is no moment at which this process
        could die holding a suspension nobody else knows about.

        Refused (LeaseError): a lease that is not a finite positive number of
        seconds (`INVALID_LEASE`); any suspend once shutdown has begun
        (`SHUTTING_DOWN`); a held PID whose state cannot be proven
        (`LEASE_STATE_UNCERTAIN`); a watchdog that will not start.
        """
        pid = int(process_id)
        try:
            requested = float(lease_seconds)
        except (TypeError, ValueError):
            requested = float("nan")
        if not math.isfinite(requested) or requested <= 0:
            raise LeaseError("INVALID_LEASE", f"lease_seconds must be a finite number above 0, not {lease_seconds!r}")
        if self._closed:
            raise LeaseError("SHUTTING_DOWN", "the Response service is shutting down; refusing to suspend "
                             "anything nothing would resume")
        # A watchdog respawn can take seconds. It happens here, outside the
        # table lock, so no expiry, resume or terminate waits for it.
        if self.watchdog is not None:
            self.watchdog.start()
        ended: list[Lease] = []
        try:
            with self._lock:
                if self._closed:
                    raise LeaseError("SHUTTING_DOWN", "the Response service is shutting down; refusing to "
                                     "suspend anything nothing would resume")
                existing = self._held.get(pid)
                if existing is not None and self._still_alive(existing):
                    return existing, True

                handle = vet()
                if existing is not None:
                    # The held handle says its process is gone. Before believing
                    # it, look at the live process: if it is the one we hold
                    # (same start time), it is still suspended under this lease,
                    # and suspending it again would nest a second suspend that
                    # one resume does not undo (review finding R7b).
                    _, live_start = _identity(handle)
                    if live_start is None or existing.started_at is None:
                        raise LeaseError(
                            "LEASE_STATE_UNCERTAIN",
                            f"pid {pid} is held under {existing.lease_id}, the held handle reports it gone, "
                            "and the start time needed to tell whether it is the same process cannot be "
                            "read; refusing rather than risk suspending it twice",
                        )
                    if abs(live_start - existing.started_at) < 1e-6:
                        existing.handle = handle
                        return existing, True
                    # A different process holds the number now. Close the old
                    # lease out (nothing to resume) and start fresh.
                    self._end(existing, GONE, by="acquire",
                              reason="the process exited while the lease was held")
                    ended.append(existing)

                seconds = min(requested, self.max_seconds)
                now_mono = self._clock()
                now_wall = self._wall()
                image, started_at = _identity(handle)
                lease = Lease(
                    lease_id=f"lease_{uuid4().hex[:16]}",
                    process_id=pid,
                    incident_id=incident_id,
                    reason=reason,
                    attribution_confidence=attribution_confidence,
                    attribution_source=attribution_source,
                    attribution_reason=attribution_reason,
                    image=image,
                    started_at=started_at,
                    lease_seconds=round(seconds, 3),
                    lease_seconds_requested=requested,
                    granted_at=iso_utc(now_wall),
                    expires_at=iso_utc(now_wall + seconds),
                    deadline=now_mono + seconds,
                    granted_mono=now_mono,
                    gate=gate or None,
                    handle=handle,
                )

                if self.watchdog is not None:
                    self.watchdog.hold(lease.lease_id, pid, started_at, image, seconds)
                try:
                    suspend(handle)
                except BaseException:
                    if self.watchdog is not None:
                        self.watchdog.drop(lease.lease_id)
                    raise

                self._held[pid] = lease
                self._by_id[lease.lease_id] = lease
                return lease, False
        finally:
            self._notify(ended)

    # ---------------------------------------------------------------- ending

    def release(
        self,
        *,
        lease_id: str | None = None,
        process_id: int | None = None,
        reason: str,
        by: str = "caller",
        notify: bool = False,
    ) -> tuple[Lease | None, bool, bool]:
        """End a held lease by resuming it.

        Returns (the lease if known, whether the process was resumed, whether
        this call ended the lease). A held lease whose process has gone ends
        `gone` with `resumed` False.

        Idempotent: a lease already ended, or a PID this table does not hold,
        returns (lease or None, False, False) and touches nothing. In
        particular it never resumes a process it did not suspend - that might
        be a debugger's.
        """
        ended: list[Lease] = []
        try:
            with self._lock:
                lease = self._find_held(lease_id, process_id)
                if lease is None:
                    known = (self._by_id.get(lease_id) or self._history.get(lease_id)) if lease_id else None
                    return known, False, False
                resumed = self._resume_lease(lease, by=by, reason=reason)
                if notify:
                    ended.append(lease)
                return lease, resumed, True
        finally:
            self._notify(ended)

    def end_for_terminate(self, process_id: int) -> Lease | None:
        """The held process was killed: close its lease without resuming."""
        with self._lock:
            lease = self._held.get(int(process_id))
            if lease is None:
                return None
            self._end(lease, TERMINATED, by="terminate", reason="the process was terminated")
            return lease

    def reap(self) -> list[Lease]:
        """Resume every lease whose deadline has passed. The backstop for a
        caller that never comes back - a crashed Monitor included."""
        ended: list[Lease] = []
        try:
            with self._lock:
                now = self._clock()
                for lease in [l for l in self._held.values() if l.deadline <= now]:
                    if self._try_resume(lease, by="lease_expiry", reason="lease_expired"):
                        ended.append(lease)
            return ended
        finally:
            self._notify(ended)

    def resume_all(self, reason: str, by: str) -> list[Lease]:
        """Nothing stays frozen because this service stopped."""
        ended: list[Lease] = []
        try:
            with self._lock:
                for lease in list(self._held.values()):
                    if self._try_resume(lease, by=by, reason=reason):
                        ended.append(lease)
            return ended
        finally:
            self._notify(ended)

    def _try_resume(self, lease: Lease, *, by: str, reason: str) -> bool:
        """One lease's failure must not stop the others being resumed."""
        try:
            self._resume_lease(lease, by=by, reason=reason)
            return True
        except Exception:
            return False

    # ---------------------------------------------------------------- reading

    def get(self, lease_id: str) -> Lease | None:
        with self._lock:
            return self._by_id.get(lease_id) or self._history.get(lease_id)

    def held_for(self, process_id: int) -> Lease | None:
        with self._lock:
            return self._held.get(int(process_id))

    def held(self) -> list[Lease]:
        with self._lock:
            return list(self._held.values())

    def list(self) -> list[dict]:
        """Held leases first, then the most recently ended."""
        with self._lock:
            held = [l.summary() for l in self._held.values()]
            ended = [l.summary() for l in reversed(self._history.values())]
        return held + ended

    def protected_pids(self) -> set[int]:
        """Processes that must never be suspended because they end suspensions."""
        if self.watchdog is None:
            return set()
        return set(self.watchdog.pids())

    # ---------------------------------------------------------------- lifecycle

    def start(self, interval: float = REAP_INTERVAL_SECONDS) -> None:
        """Start the reaper, and the watchdog so the first suspend does not wait for it."""
        self._closed = False
        if self._recorder is None or not self._recorder.is_alive():
            self._recorder = threading.Thread(target=self._record_loop, name="lease-recorder", daemon=True)
            self._recorder.start()
        if self.watchdog is not None:
            try:
                self.watchdog.start()
            except LeaseError as exc:
                # Not fatal to the service: suspends are refused while it is
                # down (acquire asks again), terminate and recovery still work.
                logger.error("lease watchdog unavailable at startup: %s", exc)
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._stop.clear()
        self._reaper = threading.Thread(target=self._reap_loop, args=(interval,),
                                        name="lease-reaper", daemon=True)
        self._reaper.start()

    def shutdown(self, reason: str, by: str) -> list[Lease]:
        """Refuse new suspensions, resume every held one, then stop.

        Closed first, under the lock, so a suspend racing the shutdown either
        lands before it (and is resumed here) or is refused.
        """
        with self._lock:
            self._closed = True
        ended = self.resume_all(reason=reason, by=by)
        self.stop()
        return ended

    def stop(self) -> None:
        with self._lock:
            self._closed = True
        self._stop.set()
        reaper, self._reaper = self._reaper, None
        if reaper is not None:
            reaper.join(timeout=2)
        recorder, self._recorder = self._recorder, None
        if recorder is not None:
            # Drain: every ended lease is recorded before the service exits.
            # Bounded by the ledger client's own timeout per block.
            self._notes.put(None)
            recorder.join(timeout=30)
        if self.watchdog is not None:
            self.watchdog.close()

    def drain(self, timeout: float = 5.0) -> bool:
        """Wait until every ended lease queued so far has been recorded."""
        recorder = self._recorder
        if recorder is None or not recorder.is_alive():
            return True
        marker = threading.Event()
        self._notes.put(marker)
        return marker.wait(timeout)

    def _record_loop(self) -> None:
        while True:
            item = self._notes.get()
            if item is None:
                return
            if isinstance(item, threading.Event):
                item.set()
                continue
            self._call_on_end(item)

    def _reap_loop(self, interval: float) -> None:
        while not self._stop.wait(interval):
            try:
                self.reap()
            except Exception:  # the reaper must outlive any one bad lease
                logger.exception("lease reaper pass failed")

    # ---------------------------------------------------------------- internals

    def _find_held(self, lease_id: str | None, process_id: int | None) -> Lease | None:
        if lease_id:
            lease = self._by_id.get(lease_id)
            return lease if lease is not None and lease.state == HELD else None
        if process_id is not None:
            return self._held.get(int(process_id))
        return None

    def _resume_lease(self, lease: Lease, *, by: str, reason: str) -> bool:
        try:
            resumed = bool(self._resume(lease.handle))
        except Exception as exc:
            # Keep it held: the reaper tries again, and so would shutdown and
            # the watchdog. Dropping it here would forget a frozen process.
            logger.error("resume of pid %s (lease %s) failed: %s", lease.process_id, lease.lease_id, exc)
            raise
        self._end(lease, RESUMED if resumed else GONE, by=by, reason=reason)
        return resumed

    def _end(self, lease: Lease, state: str, *, by: str, reason: str) -> None:
        lease.state = state
        lease.ended_by = by
        lease.ended_reason = reason
        lease.ended_at = iso_utc(self._wall())
        lease.held_ms = round((self._clock() - lease.granted_mono) * 1000.0, 1)
        if self._held.get(lease.process_id) is lease:
            del self._held[lease.process_id]
        self._by_id.pop(lease.lease_id, None)
        self._history[lease.lease_id] = lease
        while len(self._history) > HISTORY_LIMIT:
            self._history.popitem(last=False)
        if self.watchdog is not None:
            self.watchdog.drop(lease.lease_id)

    def _still_alive(self, lease: Lease) -> bool:
        is_running = getattr(lease.handle, "is_running", None)
        if is_running is None:
            return True
        try:
            return bool(is_running())
        except Exception:
            return False

    def _notify(self, leases: list[Lease]) -> None:
        if not leases or self.on_end is None:
            return
        recorder = self._recorder
        for lease in leases:
            if recorder is not None and recorder.is_alive():
                self._notes.put(lease)  # recorded on the recorder thread, not the reaper's
            else:
                self._call_on_end(lease)

    def _call_on_end(self, lease: Lease) -> None:
        try:
            self.on_end(lease)
        except Exception:
            logger.exception("recording the end of lease %s failed", lease.lease_id)


def _identity(handle: Any) -> tuple[str | None, float | None]:
    """The image and start time of the process behind `handle`, where readable."""
    image = started_at = None
    try:
        image = handle.exe() or None
    except Exception:
        pass
    try:
        started_at = float(handle.create_time())
    except Exception:
        pass
    return image, started_at
