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
import os
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
        """What allowed this suspension; every block naming the PID carries it (C-16)."""
        return {
            "attribution_confidence": self.attribution_confidence,
            "attribution_source": self.attribution_source,
            "attribution_reason": self.attribution_reason,
            "gate": "suspend_authorised",
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
    ) -> tuple[Lease, bool]:
        """Suspend `process_id` under a new lease, or return the one it is under.

        `vet()` runs every guard and returns the process handle (raising to
        refuse); `suspend(handle)` freezes it. The watchdog is told about the
        lease *before* the suspend, so there is no moment at which this process
        could die holding a suspension nobody else knows about.
        """
        pid = int(process_id)
        ended: list[Lease] = []
        try:
            with self._lock:
                existing = self._held.get(pid)
                if existing is not None:
                    if self._still_alive(existing):
                        return existing, True
                    # Killed by someone else while held; the number may since
                    # belong to another process. Close it out and start fresh.
                    self._end(existing, GONE, by="acquire",
                              reason="the process exited while the lease was held")
                    ended.append(existing)

                handle = vet()
                requested = float(lease_seconds)
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

    def stop(self) -> None:
        self._stop.set()
        reaper, self._reaper = self._reaper, None
        if reaper is not None:
            reaper.join(timeout=2)
        if self.watchdog is not None:
            self.watchdog.close()

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
        for lease in leases:
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
