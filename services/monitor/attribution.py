"""Which process wrote this file, and how sure are we.

Watchdog reports *what* changed and never *who* changed it. Until this module
existed, `handle_event` set `process_id` to `None` for every filesystem
detection and the pipeline downgraded the response from `terminate_process` to
`isolate_and_log`, because asking the Response service to kill a PID nobody had
attributed would have named an unrelated process.

This answers the second question, or says honestly that it cannot.

THE SHAPE OF THE ANSWER

`resolve()` returns an `Attribution`, never a bare PID. A bare PID cannot
express the difference between "one process wrote this path and nothing else
touched it" and "three processes did, here is the most recent one", and those
two have to reach different decisions: killing the wrong process is worse than
killing nothing. So the answer carries a confidence, and only `CERTAIN`
authorises termination. `PROBABLE` and `UNKNOWN` both degrade to the
isolate-and-log behaviour that was there before, which makes this module
strictly additive - it can add kills the evidence supports and cannot turn a
guess into a dead process.

WHERE THE EVIDENCE COMES FROM

Windows will not tell an unprivileged process who wrote a file. Every route to
that fact is privileged, and the cheap-looking one does not work at all:
enumerating handles with `psutil.open_files()` was measured on the development
host at **25.2 seconds for a single lookup, returning no match** - against a 2
second response budget. It is not implemented here and should not be.

What is implemented is a pluggable source feeding one bounded, time-windowed
log of writes:

  * `SecurityLogSource` - Windows Security channel, Event ID 4663, which
    carries `ObjectName`, `ProcessId` and `ProcessName` for every audited
    access. Needs the File System audit subcategory enabled and a SACL on the
    watched directory; `scripts/setup_attribution_audit.ps1` does both. Needs
    Administrator, which is the OS boundary rather than a limitation here.
  * `NullSource` - everywhere else, including Linux CI. Reports unavailable,
    every lookup returns `UNKNOWN`, and the pipeline behaves exactly as it did
    before this module existed.

An ETW `Microsoft-Windows-Kernel-File` source would be the higher-fidelity
version of the same interface. It is deliberately not written here: it needs a
consumer this project does not have, and the interface below is what makes
swapping it in later a one-class change rather than a pipeline change.

THE RACE, AND WHY NOTHING IS CERTAIN UNTIL THE DELIVERY HORIZON HAS CLOSED

The audit record and the watchdog event describe the same write and arrive by
different paths, and they do not arrive together. The Windows 11 integration
VM measured the Security channel delivering 4663 to an `EvtSubscribe` push
subscription **390 ms to 1032 ms after the write, median 1000 ms** (35 writes;
reports/evidence/diag_4663_lag.txt has the fixed-cadence ten). The
fix/evidence-integrity branch measured the same channel on another host at four
write rates and found the same ceiling (~1010 ms) independent of rate: a flush
timer, not a queue.

This module used to stamp each record with the moment it was *delivered* and
look back 750 ms from the moment of the *lookup*, after waiting at most 250 ms.
Against that channel, three things followed, all of them seen on the VM:

  1. A fresh write was never attributed. Its record was still ~1 s away when
     the 250 ms wait gave up: 0 of 35.
  2. What *was* attributed was the previous write. A record delivered now is,
     by the measurement, the record of a write about a second ago; if the same
     path was written a second earlier, that record sat inside the 750 ms
     window when the new event was looked up, and it was the only writer there,
     so it read as CERTAIN. The reboot run's one kill (quarterly_report_01, pid
     6816, "waited 0.0 ms") was exactly this: the simulator's own *creation*
     write, answering for its encryption write 1.5 s later. Right PID, by luck
     - it would have named any process that happened to write the file a second
     before the attacker did.
  3. A single record seen early is only part of the evidence. Records for two
     writes a few milliseconds apart can land in different flushes, so an
     answer taken before the second flush says "one writer" about a path that
     had two.

So now:

  * Records are stamped with the event's own `System/TimeCreated/@SystemTime`
    and compared with the file event's observation time **on the same clock**
    (the Windows system clock, UTC). Delivery lag no longer moves a record in
    or out of the window; see `WriteLog.lookup` for the window arithmetic and
    `CLOCK_TOLERANCE_MS` for the slack.
  * An answer from a source that delivers late is not final until every record
    that could still matter has had `HORIZON_MS` to arrive. Before that, one
    writer is `PROBABLE` and flagged `pending`; two writers are `PROBABLE` and
    final (more records can only add writers). Only after the horizon closes
    can one writer become `CERTAIN`.
  * The Monitor therefore responds in two steps. The first answer drives the
    non-destructive response immediately. The question stays open in
    `PendingAttribution`; when the horizon closes with exactly one kernel-grade
    writer, whose PID still names the same process (`Attributor.verify`), the
    answer escalates to `CERTAIN` and the kill is requested as a separate,
    later action, recorded in its own ledger block joined by incident ID.

That wait is response-budget work, not detection work. `detection_latency_ms`
is recorded before any of it, so Table 5.9's <100 ms detection target stays a
measurement of detection and does not silently become a measurement of the
Security log's delivery lag.
"""

from __future__ import annotations

import logging
import ntpath
import os
import posixpath
import re
import threading
import time
import xml.etree.ElementTree as ET
from calendar import timegm
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- confidence

CERTAIN = "certain"
PROBABLE = "probable"
UNKNOWN = "unknown"

#: Only this one authorises a kill. Kept as a set so a future source that
#: warrants its own level does not have to touch the call sites.
KILL_AUTHORISING = frozenset({CERTAIN})

# ------------------------------------------------------------------- tunables
#
# Every default below is justified against the one measurement that matters
# here: 4663 delivery to a push subscription on the Windows 11 integration VM,
# 35 writes, min 390 ms, median 1000 ms, max 1032 ms.

#: How far *before* the file event an audited write still counts as explaining
#: it, compared on the event clock (TimeCreated against the observation time).
#:
#: 750, the value this shipped with, but for a different reason. It used to
#: have to absorb the delivery lag, and at 750 ms it could not - that is
#: defect 1. With event-time stamps the lag is the horizon's problem (below),
#: and what is left for the window is the gap between the audited write and
#: watchdog reporting it, plus any time a writer holds its handle open while it
#: writes. That gap was not measured on its own on the VM. What *was* measured
#: bounds it from above: the previous write's record, about a second earlier,
#: is exactly what got taken as evidence in the reboot run, and a window under a
#: second leaves it out. 750 keeps the old value, under that bound.
WINDOW_MS = float(os.getenv("ATTRIBUTION_WINDOW_MS", "750"))

#: How far back *any other* writer to the same path makes the answer ambiguous.
#:
#: 3000, ported from fix/evidence-integrity, where it was the correlation
#: window the agent calibrated and ran its acceptance with. There it had to
#: cover the delivery ceiling; here it only ever *removes* confidence: it is
#: consulted for competing writers, never for a match. A write by B 2 s before A
#: overwrote the file makes the answer PROBABLE rather than CERTAIN-for-A, which
#: costs one kill that would probably have been right and cannot cost one that
#: would have been wrong. It also covers the case the explanation window cannot
#: see: an attacker that opened its handle (and was audited) long before it
#: wrote, while an innocent process wrote the same file just before the event.
COMPETITION_MS = float(os.getenv("ATTRIBUTION_COMPETITION_MS", "3000"))

#: How long the first look waits for a record, measured from when the event
#: was *observed* (not from when the lookup starts).
#:
#: 0, down from 250. No record in 35 arrived sooner than 390 ms, so any grace
#: under that caught nothing and delayed the non-destructive response by
#: exactly its own length - and a grace long enough to catch the median would
#: hold the first response for a second. The first answer can no longer
#: authorise a kill anyway (the horizon has to close first), so there is
#: nothing to wait *for*: take the first answer immediately, respond to it, and
#: keep the question open.
GRACE_MS = float(os.getenv("ATTRIBUTION_GRACE_MS", "0"))

#: How long after a write its audit record may still arrive.
#:
#: 1500: the measured maximum was 1032 ms, and this is that plus ~45%, while
#: still leaving the escalated kill inside the 2 s response budget. The kill
#: happens at observation + tolerance + horizon (~1.56 s), then one HTTP call and
#: `TerminateProcess`; TC-07's 91 ms termination fits in what is left. A record
#: that arrives later than this is not an answer, however unambiguous it looks.
HORIZON_MS = float(os.getenv("ATTRIBUTION_HORIZON_MS", "1500"))

#: Slack between the two timestamps that are compared.
#:
#: Both are the Windows system clock, but read at different precision. On the
#: Windows test host's interpreter (Python 3.12.10) `time.time()` is
#: `GetSystemTimeAsFileTime`, reported by `time.get_clock_info('time')` with a
#: 15.625 ms resolution, while TimeCreated is written at 100 ns. So an
#: observation can read up to one tick early against a precise record. 50 ms is
#: two ticks and margin.
#: (Python 3.13 moves `time.time()` to the precise clock; the default can shrink
#: then, and does not need to.)
CLOCK_TOLERANCE_MS = float(os.getenv("ATTRIBUTION_CLOCK_TOLERANCE_MS", "50"))

#: Poll interval of the legacy (unanchored) grace loop. The loop now also wakes
#: on every recorded write, so this is only a backstop.
POLL_MS = float(os.getenv("ATTRIBUTION_POLL_MS", "10"))

#: How often `PendingAttribution` re-checks its open questions when nothing
#: else wakes it. It also wakes on every recorded write and at the earliest
#: horizon, so this is a backstop, not the latency.
SWEEP_MS = float(os.getenv("ATTRIBUTION_SWEEP_MS", "100"))

#: Open questions held at once. Past this the oldest is closed unanswered (and
#: says so in the ledger) rather than silently forgotten.
MAX_PENDING = int(os.getenv("ATTRIBUTION_MAX_PENDING", "4096"))

#: Bounded, because this is fed by every audited write on the volume. At the
#: default it is a few MB and it is the reason this module cannot become the
#: `_SEEN_FILES` leak recorded as S-7 in the security audit.
#:
#: 16384, up from 4096, ported from fix/evidence-integrity for the same reason:
#: a record now has to survive horizon + competition window (~4.5 s) rather
#: than 750 ms. An eviction inside that span can no longer go unnoticed either:
#: `WriteLog` tracks what it evicted, and an answer that an evicted record could
#: have contradicted cannot be CERTAIN.
MAX_ENTRIES = int(os.getenv("ATTRIBUTION_MAX_ENTRIES", "16384"))

#: 4663 reports the access that was checked. WriteData (0x2) and AppendData
#: (0x4) are the two that mean "this process put bytes in the file".
ACCESS_WRITE_DATA = 0x2
ACCESS_APPEND_DATA = 0x4
WRITE_MASK = ACCESS_WRITE_DATA | ACCESS_APPEND_DATA


def _normalise(path: str) -> str:
    """One spelling per file, so a lookup and a record agree.

    `normcase` alone is not enough: the audit record and watchdog can disagree
    on relative-vs-absolute and on short-vs-long form, and on Windows
    `normcase` also folds case and slashes, which is what makes the comparison
    work at all.
    """
    try:
        return os.path.normcase(os.path.abspath(path))
    except (ValueError, OSError):
        return os.path.normcase(path)


def _settle_span_s(horizon_ms: float) -> float:
    """How long after the read an answer from a source with this horizon is final.

    Clock tolerance plus the horizon for a source that delivers late; nothing
    for one that delivers as it happens.
    """
    if horizon_ms <= 0:
        return 0.0
    return (CLOCK_TOLERANCE_MS + horizon_ms) / 1000.0


def iso_utc(epoch: float | None) -> str | None:
    """An epoch-seconds instant as the ISO-8601 `Z` form the other services use."""
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------ the answer


@dataclass(frozen=True)
class Attribution:
    """Who wrote the file, and how much the evidence supports saying so."""

    pid: int | None
    image: str | None
    confidence: str
    reason: str
    source: str = "none"
    candidates: tuple[int, ...] = ()
    waited_ms: float = 0.0
    #: True while the evidence can still change: records for this event may
    #: still be in flight. A pending answer is never CERTAIN.
    pending: bool = False
    #: When a pending answer becomes final (epoch seconds, system clock).
    settle_at: float | None = None
    #: The matched record's own TimeCreated, and when it reached the log.
    written_at: float | None = None
    delivered_at: float | None = None
    #: How far past its deadline the wait actually returned. Counted from the
    #: deadline, or from when the wait began if the deadline had already passed
    #: by then - time spent queued before that is `queue_wait_ms`, not this. The
    #: VM's reboot run saw a 250 ms grace come back after 766 ms with no way to
    #: tell why (monitor/dispatch.py); this is the number that would have said so.
    wait_overrun_ms: float = 0.0

    @property
    def kill_authorised(self) -> bool:
        """The single question the pipeline asks. Fail-closed by construction."""
        return self.confidence in KILL_AUTHORISING and self.pid is not None and not self.pending

    def as_event_fields(self) -> dict:
        """The shape that travels on the event, and so into the ledger.

        Recorded in full even when nothing was attributed, because "no process
        was identified" and "this field was never populated" have to be
        distinguishable to an auditor reading the chain later.
        """
        return {
            "process_id": self.pid,
            "process_image": self.image,
            "attribution_confidence": self.confidence,
            "attribution_reason": self.reason,
            "attribution_source": self.source,
            "attribution_candidates": list(self.candidates),
            "attribution_waited_ms": round(self.waited_ms, 3),
            "attribution_wait_overrun_ms": round(self.wait_overrun_ms, 3),
            # Whether the question was left open. A pending first answer is
            # followed, one horizon later, by an `attribution_escalation` block
            # with the same incident ID.
            "attribution_pending": self.pending,
        }

    def audit_record(self) -> dict | None:
        """The matched record's own facts, for the escalation block."""
        if self.written_at is None:
            return None
        lag = None
        if self.delivered_at is not None:
            lag = round((self.delivered_at - self.written_at) * 1000.0, 1)
        return {
            "written_at": iso_utc(self.written_at),
            "delivered_at": iso_utc(self.delivered_at),
            "delivery_lag_ms": lag,
        }


def _unattributed(reason: str, source: str = "none", waited_ms: float = 0.0) -> Attribution:
    return Attribution(
        pid=None,
        image=None,
        confidence=UNKNOWN,
        reason=reason,
        source=source,
        waited_ms=waited_ms,
    )


# -------------------------------------------------------------- the write log


@dataclass(frozen=True)
class Write:
    path: str
    pid: int
    image: str | None
    #: `time.monotonic()` when the log received the record, or the stamp the
    #: caller passed. The legacy lookup compares on this clock.
    at: float
    #: When the write happened, on the system clock (epoch seconds): the
    #: record's own TimeCreated when the source supplies one, otherwise `at`
    #: carried onto the system clock. The anchored lookup compares on this.
    written_at: float = 0.0
    #: When the log received the record, on the system clock. For the record
    #: only - the delivery lag an auditor reads in the escalation block.
    delivered_at: float = 0.0
    #: When the log received the record, on the horizon clock (monotonic).
    #: "Did it arrive before the horizon closed" is decided on this, never on
    #: the system clock, which can step or run slow under load.
    delivered_mono: float = 0.0


class WriteLog:
    """A bounded, time-windowed record of who wrote what.

    Append is hot - every audited write on the volume reaches it - and lookup
    is cold, because only a suspicious event asks. So append is O(1) onto a
    `deque` with a `maxlen`, plus a per-path index kept in step with it, and a
    lookup scans only the records for the paths it asks about. The index is
    what makes re-asking every open question on every recorded write cheap
    enough for `PendingAttribution` to do it.
    """

    def __init__(
        self,
        window_ms: float = WINDOW_MS,
        maxlen: int = MAX_ENTRIES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.window_ms = window_ms
        #: The horizon clock that stamps `delivered_mono`: monotonic, and the
        #: same clock `Attributor.clock` reads. Injectable for the same reason.
        self.clock = clock if clock is not None else time.perf_counter
        self._writes: deque[Write] = deque(maxlen=maxlen)
        self._by_path: dict[str, deque[Write]] = {}
        self._lock = threading.Lock()
        self._arrived = threading.Condition(self._lock)
        self._excluded: set[int] = set()
        self._listeners: list[Callable[[], None]] = []
        #: The newest `written_at` of any record pushed out by `maxlen`. An
        #: answer whose competition window reaches back past this cannot rule
        #: out a second writer, because the evidence for one may be gone.
        self._evicted_through = float("-inf")
        self._sequence = 0
        self.recorded = 0
        self.evicted = 0
        self.dropped_non_write = 0
        self.dropped_untimed = 0

    # -- exclusions ------------------------------------------------------

    def exclude(self, pids: Iterable[int]) -> None:
        """PIDs that must never be attributed - this process and its parents.

        The Monitor writes into the watched tree during its own tests, and a
        detector that can name itself as the attacker is a detector that can
        kill itself.
        """
        with self._lock:
            self._excluded.update(int(p) for p in pids)

    @property
    def excluded(self) -> frozenset[int]:
        with self._lock:
            return frozenset(self._excluded)

    # -- write side ------------------------------------------------------

    def record(
        self,
        path: str,
        pid: int,
        image: str | None = None,
        at: float | None = None,
        written_at: float | None = None,
    ) -> None:
        mono = time.monotonic()
        wall = time.time()
        delivered_mono = self.clock()
        stamp = mono if at is None else at
        if written_at is None:
            # No event time from the source: the write happened at `stamp`, on
            # the monotonic clock, which is how every caller before event-time
            # stamping described it.
            written_at = wall - (mono - stamp)
        entry = Write(
            path=_normalise(path),
            pid=int(pid),
            image=image,
            at=stamp,
            written_at=float(written_at),
            delivered_at=wall,
            delivered_mono=delivered_mono,
        )
        with self._arrived:
            if self._writes.maxlen is not None and len(self._writes) == self._writes.maxlen:
                oldest = self._writes[0]
                bucket = self._by_path.get(oldest.path)
                if bucket:
                    bucket.popleft()
                    if not bucket:
                        del self._by_path[oldest.path]
                self._evicted_through = max(self._evicted_through, oldest.written_at)
                self.evicted += 1
            self._writes.append(entry)
            self._by_path.setdefault(entry.path, deque()).append(entry)
            self.recorded += 1
            self._sequence += 1
            self._arrived.notify_all()
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener()
            except Exception:  # a listener must never break the source callback
                logger.debug("attribution: write-log listener failed", exc_info=True)

    def add_listener(self, callback: Callable[[], None]) -> None:
        """Called (outside the lock) after every recorded write."""
        with self._lock:
            self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[], None]) -> None:
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._sequence

    def wait_for_new(self, since: int, timeout: float) -> bool:
        """Block until a write is recorded after `since`, or `timeout` seconds.

        A condition-variable wait, not a sleep: a record that arrives mid-wait
        is seen at once rather than at the next poll, and a wait that cannot be
        scheduled on time wakes into a lookup rather than into another sleep.
        """
        if timeout <= 0:
            return False
        with self._arrived:
            return self._arrived.wait_for(lambda: self._sequence != since, timeout=timeout)

    # -- read side -------------------------------------------------------

    def lookup(
        self,
        path: str,
        window_ms: float | None = None,
        now: float | None = None,
        source: str = "none",
        kernel_grade: bool = False,
        *,
        observed_at: float | None = None,
        read_at: float | None = None,
        also: Iterable[str] = (),
        competition_ms: float | None = None,
        horizon_ms: float = 0.0,
        horizon_from: float | None = None,
        clock_now: float | None = None,
    ) -> Attribution:
        """Who wrote `path`, on the evidence recorded so far.

        Two modes, chosen by `observed_at`.

        **Anchored** (`observed_at` given, epoch seconds on the system clock -
        what the Monitor passes). A record explains the event if it was written
        in `[observed_at - window, read_at + tolerance]`: up to `window` before
        watchdog reported the change, and up to the moment the detector
        finished reading the bytes it judged, because a write that landed after
        the notification but before the read produced some of those bytes.
        Any *other* PID that wrote the path in `[observed_at - competition,
        read_at + tolerance]` makes the answer PROBABLE. `also` adds paths whose
        records count as this file's - a rename's source. A single writer from
        a kernel-grade source is CERTAIN only once the horizon has closed:
        `horizon_ms` (plus the tolerance) after `horizon_from`, the moment the
        bytes were read *on this log's monotonic clock*. Before that it is
        PROBABLE and `pending`, and a record delivered after it closed is not a
        match.

        Two clocks, on purpose. TimeCreated is a system-clock instant, so the
        matching is done on the system clock. The horizon is an interval, and
        the system clock is not an interval timer: `time.get_clock_info` calls
        it adjustable, and it advances in 15.625 ms steps on the test host.
        Timed on it, one full-suite run on that host counted a record delivered
        1.6 s after the write (by the performance counter) as inside a 1.55 s
        horizon. Without `horizon_from` the horizon runs from this lookup,
        which can only make an answer later, never earlier.

        **Legacy** (no `observed_at`). The rule this module shipped with,
        unchanged: records received within `window` of `now`, on the monotonic
        clock. Kept because it is a published interface and TC-26 pins it; the
        Monitor no longer asks this way, because it answers with the previous
        writer whenever the channel delivers late (module docstring).
        """
        if observed_at is None:
            return self._lookup_legacy(path, window_ms, now, source, kernel_grade)
        return self._lookup_anchored(
            path,
            also=also,
            observed_at=observed_at,
            read_at=read_at,
            window_ms=window_ms,
            competition_ms=competition_ms,
            horizon_ms=horizon_ms,
            horizon_from=horizon_from,
            clock_now=clock_now,
            source=source,
            kernel_grade=kernel_grade,
        )

    def _lookup_legacy(
        self,
        path: str,
        window_ms: float | None,
        now: float | None,
        source: str,
        kernel_grade: bool,
    ) -> Attribution:
        target = _normalise(path)
        window = self.window_ms if window_ms is None else window_ms
        moment = time.monotonic() if now is None else now
        cutoff = moment - (window / 1000.0)

        with self._lock:
            hits = [
                w
                for w in self._by_path.get(target, ())
                if w.at >= cutoff and w.pid not in self._excluded
            ]

        if not hits:
            return _unattributed(
                f"no audited write to this path by another process in the last {window:.0f}ms",
                source=source,
            )

        hits.sort(key=lambda w: w.at)
        distinct = []
        for w in hits:
            if w.pid not in distinct:
                distinct.append(w.pid)
        newest = hits[-1]

        if len(distinct) == 1:
            if kernel_grade:
                return Attribution(
                    pid=newest.pid,
                    image=newest.image,
                    confidence=CERTAIN,
                    reason=(
                        f"exactly one process wrote this path in the last {window:.0f}ms, "
                        f"from {source}"
                    ),
                    source=source,
                    candidates=(newest.pid,),
                )
            # A source that cannot see the kernel's view of the write is
            # inferring, and an inference does not authorise a kill however
            # unambiguous it looks.
            return Attribution(
                pid=newest.pid,
                image=newest.image,
                confidence=PROBABLE,
                reason=f"one candidate, but {source} is not a kernel-level source",
                source=source,
                candidates=(newest.pid,),
            )

        return Attribution(
            pid=newest.pid,
            image=newest.image,
            confidence=PROBABLE,
            reason=(
                f"{len(distinct)} processes wrote this path in the last {window:.0f}ms "
                f"({', '.join(str(p) for p in distinct)}); reporting the most recent"
            ),
            source=source,
            candidates=tuple(distinct),
        )

    def _lookup_anchored(
        self,
        path: str,
        *,
        also: Iterable[str],
        observed_at: float,
        read_at: float | None,
        window_ms: float | None,
        competition_ms: float | None,
        horizon_ms: float,
        horizon_from: float | None,
        clock_now: float | None,
        source: str,
        kernel_grade: bool,
    ) -> Attribution:
        targets: list[str] = []
        for candidate in (path, *also):
            if candidate:
                key = _normalise(candidate)
                if key not in targets:
                    targets.append(key)

        window = self.window_ms if window_ms is None else window_ms
        competition = max(window, COMPETITION_MS if competition_ms is None else competition_ms)
        tolerance_s = CLOCK_TOLERANCE_MS / 1000.0
        read = observed_at if read_at is None else max(observed_at, read_at)
        lo_match = observed_at - window / 1000.0
        lo_compete = observed_at - competition / 1000.0
        hi = read + tolerance_s
        horizon = max(0.0, horizon_ms)
        # The last write that can still match was stamped up to `tolerance`
        # after the read, and a late source may take `horizon` to deliver it. A
        # source with no delivery lag has already delivered everything that
        # happened before the read, so for it there is nothing to wait for.
        span_s = _settle_span_s(horizon)
        # For the record: when the horizon closes, on the system clock.
        settle_at = read + span_s
        # For the decision: the same close, on the monotonic horizon clock.
        moment = self.clock() if clock_now is None else clock_now
        start = moment if horizon_from is None else horizon_from
        settle_mono = start + span_s
        still_arriving = moment < settle_mono

        with self._lock:
            relevant = [
                w
                for key in targets
                for w in self._by_path.get(key, ())
                if lo_compete <= w.written_at <= hi and w.pid not in self._excluded
            ]
            overflowed = self._evicted_through >= lo_compete

        # A record delivered after the horizon closed is not an answer, however
        # unambiguous it looks - the question was due at the horizon, and
        # whether a late sweep happens to see the record must not decide it. It
        # still counts as a *competing* writer, because that can only lower
        # confidence: the asymmetry is the whole safety argument.
        matches = [
            w
            for w in relevant
            if w.written_at >= lo_match and (horizon <= 0 or w.delivered_mono <= settle_mono)
        ]
        if not matches:
            if still_arriving and horizon > 0:
                reason = (
                    f"no audited write to this path in the {window:.0f}ms before the event yet; "
                    f"{source} delivers up to {horizon:.0f}ms late, so the question stays open "
                    f"for another {max(0.0, settle_mono - moment) * 1000.0:.0f}ms"
                )
            else:
                reason = (
                    f"no audited write to this path by another process in the {window:.0f}ms "
                    f"before the event"
                    + (f", and none arrived within the {horizon:.0f}ms delivery horizon" if horizon > 0 else "")
                )
            return Attribution(
                pid=None,
                image=None,
                confidence=UNKNOWN,
                reason=reason,
                source=source,
                pending=still_arriving and horizon > 0,
                settle_at=settle_at,
            )

        relevant.sort(key=lambda w: w.written_at)
        distinct: list[int] = []
        for w in relevant:
            if w.pid not in distinct:
                distinct.append(w.pid)
        newest = max(matches, key=lambda w: w.written_at)
        evidence = dict(
            source=source,
            written_at=newest.written_at,
            delivered_at=newest.delivered_at,
            settle_at=settle_at,
        )

        if len(distinct) > 1:
            # Final, not pending: records still in flight can add writers to
            # this list and can never take one away.
            return Attribution(
                pid=newest.pid,
                image=newest.image,
                confidence=PROBABLE,
                reason=(
                    f"{len(distinct)} processes wrote this path within {competition:.0f}ms "
                    f"before the event ({', '.join(str(p) for p in distinct)}); "
                    f"reporting the most recent"
                ),
                candidates=tuple(distinct),
                **evidence,
            )

        if not kernel_grade:
            return Attribution(
                pid=newest.pid,
                image=newest.image,
                confidence=PROBABLE,
                reason=f"one candidate, but {source} is not a kernel-level source",
                candidates=(newest.pid,),
                **evidence,
            )

        if overflowed:
            return Attribution(
                pid=newest.pid,
                image=newest.image,
                confidence=PROBABLE,
                reason=(
                    f"one candidate, but the write log evicted records inside the "
                    f"{competition:.0f}ms competition window ({self.evicted} evicted so far), "
                    f"so a second writer cannot be ruled out"
                ),
                candidates=(newest.pid,),
                **evidence,
            )

        if still_arriving:
            return Attribution(
                pid=newest.pid,
                image=newest.image,
                confidence=PROBABLE,
                reason=(
                    f"one writer so far (pid {newest.pid}); {source} delivers up to "
                    f"{horizon:.0f}ms late, so this is final in "
                    f"{max(0.0, settle_mono - moment) * 1000.0:.0f}ms and not before"
                ),
                candidates=(newest.pid,),
                pending=True,
                **evidence,
            )

        return Attribution(
            pid=newest.pid,
            image=newest.image,
            confidence=CERTAIN,
            reason=(
                f"exactly one process wrote this path in the {window:.0f}ms before the event, "
                f"and no other within {competition:.0f}ms, from {source}"
                + (f"; the {horizon:.0f}ms delivery horizon has closed" if horizon > 0 else "")
            ),
            candidates=(newest.pid,),
            **evidence,
        )

    # -- housekeeping ----------------------------------------------------

    def clear(self) -> None:
        with self._lock:
            self._writes.clear()
            self._by_path.clear()
            self._evicted_through = float("-inf")
            self.recorded = 0
            self.evicted = 0
            self.dropped_non_write = 0
            self.dropped_untimed = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._writes)


# ----------------------------------------------------------------- 4663 parse

_EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
_SYSTEM_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]00:?00)?$"
)


def _as_int(raw: str | None) -> int | None:
    """4663 writes PIDs and masks as hex strings like `0x1a2c`."""
    if not raw:
        return None
    raw = raw.strip()
    try:
        return int(raw, 16) if _HEX.match(raw) else int(raw)
    except ValueError:
        return None


def parse_system_time(raw: str | None) -> float | None:
    """`System/TimeCreated/@SystemTime` to epoch seconds (UTC).

    The event log renders it as `2026-09-23T06:08:18.7812345Z` - seven
    fractional digits, sometimes nine, which `datetime.fromisoformat` does not
    accept on every Python this project supports - so it is parsed by hand.
    Anything that is not UTC is refused rather than guessed at: the comparison
    it feeds is only meaningful on one clock.
    """
    if not raw:
        return None
    match = _SYSTEM_TIME.match(raw.strip())
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, _zone = match.groups()
    try:
        whole = timegm((int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    return whole + (float(f"0.{fraction}") if fraction else 0.0)


def parse_4663(xml: str) -> dict | None:
    """One rendered 4663 event into `{path, pid, image, access_mask, time_created}`.

    Returns `None` for anything that is not an audited *write* by a real
    process - a read, a directory, or an event whose fields did not render.
    Split out from the subscription so the parsing is testable off Windows,
    which is where CI runs.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None

    data = {}
    for node in root.findall(".//e:EventData/e:Data", _EVENT_NS):
        name = node.get("Name")
        if name:
            data[name] = node.text

    mask = _as_int(data.get("AccessMask"))
    if mask is None or not mask & WRITE_MASK:
        return None

    pid = _as_int(data.get("ProcessId"))
    path = data.get("ObjectName")
    if pid is None or pid <= 0 or not path:
        return None

    # `ObjectType` is `File` for both files and directories; a directory write
    # is a rename or a create inside it, not bytes into the file we are asking
    # about, and attributing one to the other would be wrong in the direction
    # that gets something killed.
    if (data.get("ObjectType") or "File") != "File":
        return None

    created = root.find("./e:System/e:TimeCreated", _EVENT_NS)
    return {
        "path": path,
        "pid": pid,
        "image": data.get("ProcessName"),
        "access_mask": mask,
        # When the access happened, on the system clock. None only for a
        # record whose System block did not render, which the subscription
        # refuses to record - see SecurityLogSource._on_event.
        "time_created": parse_system_time(created.get("SystemTime") if created is not None else None),
    }


# --------------------------------------------------------------- the sources


class AttributionSource:
    """Where writes come from. Subclasses fill in `start`."""

    name = "none"
    #: True only for a source that sees the kernel's own view of the write.
    #: This is what separates CERTAIN from PROBABLE, so it is not a label.
    kernel_grade = False
    #: How late this source can deliver a record after the write it describes.
    #: 0 means "as it happens", and an answer from such a source is final the
    #: moment it is taken. Anything else holds CERTAIN back until the horizon
    #: has closed, because until then a second writer may still be in flight.
    delivery_horizon_ms = 0.0

    def __init__(self, log: WriteLog) -> None:
        self.log = log
        self.available = False
        self.error: str | None = None

    def start(self) -> bool:
        return False

    def stop(self) -> None:
        return None

    def status(self) -> dict:
        return {
            "source": self.name,
            "available": self.available,
            "kernel_grade": self.kernel_grade,
            "delivery_horizon_ms": self.delivery_horizon_ms,
            "error": self.error,
            "writes_recorded": self.log.recorded,
            "writes_buffered": len(self.log),
            "writes_evicted": self.log.evicted,
            "writes_dropped_untimed": self.log.dropped_untimed,
        }


class NullSource(AttributionSource):
    """No attribution available. Every lookup returns UNKNOWN.

    This is the state on Linux, on a Windows host without the audit policy,
    and on any host where the Monitor is not elevated - which is to say it is
    the state the project was in before this module, preserved exactly.
    """

    name = "none"

    def __init__(self, log: WriteLog, reason: str = "no attribution source configured") -> None:
        super().__init__(log)
        self.error = reason

    def start(self) -> bool:
        self.available = False
        return False


class SecurityLogSource(AttributionSource):
    """Windows Security channel, Event ID 4663.

    Requires `auditpol /set /subcategory:"File System" /success:enable` and a
    SACL on the watched tree, both of which need Administrator, and both of
    which `scripts/setup_attribution_audit.ps1` performs and verifies.
    """

    name = "windows-security-4663"
    kernel_grade = True
    #: Measured, not assumed: see HORIZON_MS.
    delivery_horizon_ms = HORIZON_MS

    CHANNEL = "Security"
    QUERY = "*[System[(EventID=4663)]]"

    def __init__(self, log: WriteLog) -> None:
        super().__init__(log)
        self._handle = None
        self._evtlog = None

    def start(self) -> bool:
        if os.name != "nt":
            self.error = f"Security-channel attribution is Windows-only; this host is {os.name!r}"
            self.available = False
            return False

        try:
            import win32evtlog  # noqa: PLC0415 - optional, Windows-only
        except ImportError as exc:
            self.error = f"pywin32 is not installed: {exc}"
            self.available = False
            return False

        self._evtlog = win32evtlog
        try:
            self._handle = win32evtlog.EvtSubscribe(
                self.CHANNEL,
                win32evtlog.EvtSubscribeToFutureEvents,
                None,
                self._on_event,
                None,
                self.QUERY,
            )
        except Exception as exc:  # pywin32 raises its own error type
            # Error 5 here means the process is not elevated, which is the
            # normal case rather than a bug. It is reported as the reason
            # attribution is unavailable, not swallowed.
            self.error = f"could not subscribe to the {self.CHANNEL} channel: {exc}"
            self.available = False
            return False

        self.available = True
        self.error = None
        logger.info("attribution: subscribed to %s 4663", self.CHANNEL)
        return True

    def _on_event(self, action, context, event) -> int:
        """Called on a Windows thread. Must never raise into the subscription."""
        try:
            if action != self._evtlog.EvtSubscribeActionDeliver:
                return 0
            xml = self._evtlog.EvtRender(event, self._evtlog.EvtRenderEventXml)
            self.accept(parse_4663(xml))
        except Exception:  # a callback that raises tears down the subscription
            logger.debug("attribution: 4663 callback failed", exc_info=True)
        return 0

    def accept(self, parsed: dict | None) -> None:
        """Record one parsed 4663. Split out so it is testable off Windows."""
        if parsed is None:
            self.log.dropped_non_write += 1
            return
        if parsed.get("time_created") is None:
            # A record this source delivers up to a second late, with no event
            # time on it, cannot be placed against the file event it might
            # explain - and stamping it with its arrival is exactly how the
            # previous writer used to answer for the next one. Counted and
            # dropped. A 4663 whose System block renders never takes this path.
            self.log.dropped_untimed += 1
            return
        self.log.record(parsed["path"], parsed["pid"], parsed["image"], written_at=parsed["time_created"])

    def stop(self) -> None:
        self._handle = None
        self.available = False


# ---------------------------------------------------------- process identity


class ProbeUnavailable(RuntimeError):
    """The process could not be inspected at all, so its identity is unproven."""


@dataclass(frozen=True)
class ProcessFacts:
    """What a live PID is now. `None` fields could not be read."""

    pid: int
    image: str | None
    created_at: float | None


def probe_process(pid: int) -> ProcessFacts | None:
    """The live process behind `pid`, or None if there is none.

    psutil, because it reads the image path and the creation time through the
    same documented calls on every platform (`QueryFullProcessImageNameW` and
    `GetProcessTimes` on Windows). A host without it cannot verify a PID's
    identity, and `Attributor.verify` refuses to escalate on one.
    """
    try:
        import psutil  # noqa: PLC0415 - declared in requirements.txt; optional for import
    except ImportError as exc:
        raise ProbeUnavailable(f"psutil is not installed ({exc})") from exc

    try:
        process = psutil.Process(int(pid))
    except psutil.NoSuchProcess:
        return None
    except psutil.Error as exc:
        raise ProbeUnavailable(f"pid {pid} could not be opened: {exc}") from exc

    try:
        image = process.exe() or None
    except psutil.NoSuchProcess:
        return None
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        image = None

    try:
        created_at = float(process.create_time())
    except psutil.NoSuchProcess:
        return None
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        created_at = None

    return ProcessFacts(pid=int(pid), image=image, created_at=created_at)


def _image_key(image: str) -> str:
    """Compare two image paths the way the filesystem that holds them would.

    Windows paths - which is what 4663 reports - are compared with `ntpath`
    whatever host this runs on, so the check means the same thing in CI as on
    the machine that produced the record. The `\\\\?\\` prefix is dropped
    because it changes how a path is parsed, not which file it names.
    """
    text = image.strip()
    if text.startswith("\\\\?\\"):
        text = text[4:]
    if "\\" in text or re.match(r"^[A-Za-z]:", text):
        return ntpath.normcase(ntpath.normpath(text))
    return posixpath.normpath(text)


def same_image(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return _image_key(left) == _image_key(right)


# ------------------------------------------------------------- open questions


@dataclass
class Question:
    """One event whose first answer could still change."""

    key: str
    path: str
    also: tuple[str, ...]
    observed_at: float
    read_at: float
    #: When the horizon closes on the system clock - what the ledger says.
    settle_at: float
    first: Attribution
    context: Any = None
    #: The read time and the horizon's close on the monotonic horizon clock -
    #: what the sweeper actually waits for.
    horizon_from: float = 0.0
    settle_mono: float = 0.0
    opened_at: float = field(default_factory=time.time)
    checks: int = 0


# ---------------------------------------------------------------- the facade


class Attributor:
    """The object `app.py` talks to. One per process."""

    def __init__(
        self,
        log: WriteLog | None = None,
        source: AttributionSource | None = None,
        probe: Callable[[int], ProcessFacts | None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.log = log if log is not None else WriteLog()
        self.source = source if source is not None else NullSource(self.log)
        self.probe = probe if probe is not None else probe_process
        #: The horizon clock: what "has the horizon closed yet" is asked of.
        #: Monotonic by default, and the same one the write log stamps
        #: deliveries with. Injectable so the decision logic can be tested
        #: without sleeping through it.
        self.clock = clock if clock is not None else self.log.clock
        self.log.exclude(_self_and_ancestors())

    # -- lifecycle -------------------------------------------------------

    def start(self, source: AttributionSource | None = None) -> bool:
        if source is not None:
            self.source = source
        return self.source.start()

    def stop(self) -> None:
        self.source.stop()

    @property
    def available(self) -> bool:
        return self.source.available

    @property
    def horizon_ms(self) -> float:
        return float(getattr(self.source, "delivery_horizon_ms", 0.0) or 0.0)

    def status(self) -> dict:
        return {
            **self.source.status(),
            "window_ms": self.log.window_ms,
            "competition_ms": max(self.log.window_ms, COMPETITION_MS),
            "grace_ms": GRACE_MS,
            "horizon_ms": self.horizon_ms,
            "clock_tolerance_ms": CLOCK_TOLERANCE_MS,
            "max_entries": self.log._writes.maxlen,
            "excluded_pids": sorted(self.log.excluded),
        }

    # -- the question ----------------------------------------------------

    def _look(
        self,
        path: str,
        window_ms: float | None = None,
        observed_at: float | None = None,
        read_at: float | None = None,
        also: Iterable[str] = (),
        horizon_from: float | None = None,
    ) -> Attribution:
        return self.log.lookup(
            path,
            window_ms=window_ms,
            source=self.source.name,
            kernel_grade=self.source.kernel_grade,
            observed_at=observed_at,
            read_at=read_at,
            also=also,
            horizon_ms=self.horizon_ms,
            horizon_from=horizon_from,
            clock_now=self.clock() if observed_at is not None else None,
        )

    def resolve(
        self,
        path: str,
        grace_ms: float | None = None,
        window_ms: float | None = None,
        *,
        observed_at: float | None = None,
        read_at: float | None = None,
        deadline: float | None = None,
        also: Iterable[str] = (),
        horizon_from: float | None = None,
    ) -> Attribution:
        """Who wrote `path`, waiting briefly for a record that is still in flight.

        Callers run this *after* recording detection latency. See the module
        docstring for why.

        `observed_at` (epoch seconds) anchors the lookup to when the event was
        observed and switches it to event-time matching - see `WriteLog.lookup`,
        which also says what `horizon_from` is and why it is on another clock.
        `deadline` is a `time.perf_counter()` instant; when given it replaces
        `grace_ms`, so a caller that queued the event can charge the queueing to
        the grace instead of paying the grace again on top of it.

        Returns as soon as anything is found. Found-but-pending is not a reason
        to keep waiting: that answer drives the non-destructive response, and
        `PendingAttribution` keeps the question open.
        """
        if not self.source.available:
            return _unattributed(
                self.source.error or "no attribution source is available",
                source=self.source.name,
            )

        grace = GRACE_MS if grace_ms is None else grace_ms
        started = time.perf_counter()
        until = started + (grace / 1000.0) if deadline is None else deadline

        while True:
            seen = self.log.sequence
            answer = self._look(path, window_ms, observed_at, read_at, also, horizon_from)
            now = time.perf_counter()

            # A PROBABLE answer is already evidence; waiting longer can only add
            # more writers to the same path and make it less certain, not more.
            if answer.confidence != UNKNOWN or now >= until:
                overrun_ms = max(0.0, now - max(until, started)) * 1000.0 if now >= until else 0.0
                return replace(
                    answer,
                    waited_ms=max(0.0, (now - started) * 1000.0),
                    wait_overrun_ms=overrun_ms,
                )
            self.log.wait_for_new(seen, min(until - now, POLL_MS / 1000.0))

    def should_park(self, answer: Attribution) -> bool:
        """Whether an answer is worth re-asking once the horizon closes.

        Only a live, kernel-grade source can ever produce CERTAIN, and only a
        pending answer can still change.
        """
        return (
            answer.pending
            and self.source.available
            and self.source.kernel_grade
            and self.horizon_ms > 0
        )

    def question(
        self,
        key: str,
        path: str,
        observed_at: float,
        read_at: float,
        first: Attribution,
        also: Iterable[str] = (),
        context: Any = None,
        horizon_from: float | None = None,
    ) -> Question:
        read = max(observed_at, read_at)
        start = self.clock() if horizon_from is None else horizon_from
        span_s = _settle_span_s(self.horizon_ms)
        return Question(
            key=key,
            path=path,
            also=tuple(p for p in also if p),
            observed_at=observed_at,
            read_at=read,
            settle_at=read + span_s,
            first=first,
            context=context,
            horizon_from=start,
            settle_mono=start + span_s,
        )

    def recheck(self, question: Question) -> Attribution:
        """The current answer to an open question, without waiting."""
        question.checks += 1
        return self._look(
            question.path,
            observed_at=question.observed_at,
            read_at=question.read_at,
            also=question.also,
            horizon_from=question.horizon_from,
        )

    def verify(self, answer: Attribution) -> tuple[Attribution, str]:
        """Is the PID a CERTAIN answer names still the process that wrote?

        A kernel-grade record names the PID that wrote *at the time of the
        write*. By the time the horizon has closed that process may have
        exited - one `openssl` per file lives about 65 ms on the
        fix/evidence-integrity host - and Windows recycles PIDs, so the number
        can now belong to something else. Killing by number without checking
        would then kill whatever holds it.

        Three facts are checked, and any one failing is enough to refuse:

          * the PID still exists;
          * its image path is the image the audit record named;
          * it was created no later than the write (plus the clock tolerance) -
            a process that did not exist yet cannot have written.

        If neither the image nor the creation time can be read, identity is
        unproven and the answer is not escalated either. Returns the answer
        (downgraded where it fails) and a short outcome code for the ledger.
        """
        if not answer.kill_authorised:
            return answer, "not_certain"

        pid = int(answer.pid)
        wrote_as = answer.image or "an unnamed image"
        try:
            facts = self.probe(pid)
        except ProbeUnavailable as exc:
            return (
                replace(
                    answer,
                    confidence=PROBABLE,
                    reason=f"{answer.reason}; but pid {pid} could not be inspected to confirm it is "
                    f"still the writer ({exc}), so nothing is acted on",
                ),
                "identity_unverifiable",
            )

        if facts is None:
            return (
                replace(
                    answer,
                    confidence=PROBABLE,
                    reason=f"{answer.reason}; but pid {pid} ({wrote_as}) has exited, so there is "
                    f"nothing left to act on",
                ),
                "process_exited",
            )

        tolerance_s = CLOCK_TOLERANCE_MS / 1000.0
        # A start time proves something only against the write's own time; an
        # answer without one (a legacy, unanchored lookup) cannot use it.
        time_checked = facts.created_at is not None and answer.written_at is not None
        if time_checked and facts.created_at > answer.written_at + tolerance_s:
            late_ms = (facts.created_at - answer.written_at) * 1000.0
            return (
                replace(
                    answer,
                    pid=None,
                    image=None,
                    confidence=UNKNOWN,
                    reason=f"{answer.reason}; but pid {pid} now belongs to a process created "
                    f"{late_ms:.0f}ms after the write ({facts.image or 'image unreadable'}): the "
                    f"PID was reused, and the process that wrote is gone",
                ),
                "pid_reused",
            )

        if facts.image and answer.image and not same_image(facts.image, answer.image):
            return (
                replace(
                    answer,
                    pid=None,
                    image=None,
                    confidence=UNKNOWN,
                    reason=f"{answer.reason}; but pid {pid} is now {facts.image}, while the "
                    f"write was by {answer.image}: the PID was reused, and the process that "
                    f"wrote is gone",
                ),
                "pid_reused",
            )

        image_proven = bool(facts.image and answer.image)
        if not image_proven and not time_checked:
            return (
                replace(
                    answer,
                    confidence=PROBABLE,
                    reason=f"{answer.reason}; but neither the image nor the start time of pid "
                    f"{pid} could be checked against the write, so it cannot be shown to be "
                    f"the writer",
                ),
                "identity_unverifiable",
            )

        proven_by = "image and start time" if image_proven and time_checked else (
            "image" if image_proven else "start time"
        )
        return (
            replace(answer, reason=f"{answer.reason}; pid {pid} verified as the writer by {proven_by}"),
            "verified",
        )

    def final(self, question: Question) -> tuple[Attribution, str]:
        """The closing answer to an open question, identity-checked.

        Called once `question.settle_mono` has passed, so a pending answer here
        should not happen; if it does, it is treated as not final.
        """
        answer = self.recheck(question)
        if answer.pending:
            return answer, "not_settled"
        if answer.confidence == CERTAIN:
            return self.verify(answer)
        if answer.confidence == PROBABLE and len(answer.candidates) > 1:
            return answer, "ambiguous"
        if answer.confidence == UNKNOWN:
            return answer, "no_record"
        return answer, "not_certain"


class PendingAttribution:
    """Questions that were answered too early to be final, kept open.

    Ported from fix/evidence-integrity's `agent/pending.py`: look without
    waiting, respond to what is known, and look again when the record lands.
    What changes here is *when* an answer is allowed to close as CERTAIN - not
    when a single record arrives, but when the delivery horizon has closed with
    still only one writer - because on the measured channel the first record
    to arrive is not necessarily the only one coming.

    One thread. It wakes on every recorded write (a lookup is a dictionary hit
    and a short scan, so re-asking costs microseconds), at the earliest
    horizon, and every `SWEEP_MS` as a backstop. A question closes early only
    when it is already final - two writers - and otherwise closes at its
    horizon. Every question closes exactly once, through `on_closed(question,
    answer, outcome)`, including the ones still open when this stops: an open
    question that silently vanished would be indistinguishable from one that
    was answered and not acted on.
    """

    def __init__(
        self,
        attributor: Attributor,
        on_closed: Callable[[Question, Attribution, str], None],
        sweep_ms: float = SWEEP_MS,
        max_pending: int = MAX_PENDING,
    ) -> None:
        self.attributor = attributor
        self._on_closed = on_closed
        self.sweep_ms = float(sweep_ms)
        self.max_pending = int(max_pending)

        self._items: deque[Question] = deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopping = False

        self.opened = 0
        self.dropped = 0
        self.failed = 0
        self.closed: dict[str, int] = {}
        self.max_close_lag_ms = 0.0

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping = False
        self.attributor.log.add_listener(self._wake.set)
        self._thread = threading.Thread(target=self._run, name="monitor-attribution-pending", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> dict:
        self._stopping = True
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self.attributor.log.remove_listener(self._wake.set)
        with self._lock:
            left = list(self._items)
            self._items.clear()
        for question in left:
            self._close(
                question,
                replace(
                    question.first,
                    confidence=question.first.confidence if question.first.confidence != CERTAIN else PROBABLE,
                    pending=False,
                    reason=f"{question.first.reason}; closed unanswered because attribution stopped "
                    f"before the delivery horizon",
                ),
                "stopped",
            )
        return self.stats()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- the two ends ----------------------------------------------------

    def add(self, question: Question) -> bool:
        """Open a question. False if an older one had to be closed to make room."""
        discarded = None
        with self._lock:
            if len(self._items) >= self.max_pending:
                discarded = self._items.popleft()
                self.dropped += 1
            self._items.append(question)
            self.opened += 1
        if discarded is not None:
            self._close(
                discarded,
                replace(
                    discarded.first,
                    confidence=discarded.first.confidence if discarded.first.confidence != CERTAIN else PROBABLE,
                    pending=False,
                    reason=f"{discarded.first.reason}; closed unanswered because "
                    f"{self.max_pending} questions were already open",
                ),
                "dropped",
            )
        self._wake.set()
        return discarded is None

    def _run(self) -> None:
        while not self._stopping:
            self._wake.wait(timeout=self._next_timeout())
            self._wake.clear()
            if self._stopping:
                return
            try:
                self.sweep()
            except Exception:  # the sweep must never die
                self.failed += 1
                logger.exception("attribution: pending sweep failed")

    def _next_timeout(self) -> float:
        cap = self.sweep_ms / 1000.0
        with self._lock:
            if not self._items:
                return cap
            earliest = min(q.settle_mono for q in self._items)
        return max(0.0, min(cap, earliest - self.attributor.clock()))

    def sweep(self, now: float | None = None) -> int:
        """Re-ask every open question once. Returns how many closed."""
        moment = self.attributor.clock() if now is None else now
        with self._lock:
            candidates = list(self._items)
        if not candidates:
            return 0

        done: list[tuple[Question, Attribution, str]] = []
        for question in candidates:
            try:
                if moment >= question.settle_mono:
                    answer, outcome = self.attributor.final(question)
                    if outcome == "not_settled":
                        continue
                    done.append((question, answer, outcome))
                    continue
                current = self.attributor.recheck(question)
                if not current.pending and current.confidence == PROBABLE and len(current.candidates) > 1:
                    done.append((question, current, "ambiguous"))
            except Exception:
                self.failed += 1
                logger.debug("attribution: re-check failed for %s", question.path, exc_info=True)

        if not done:
            return 0
        finished = {id(q) for q, _, _ in done}
        with self._lock:
            self._items = deque(q for q in self._items if id(q) not in finished)
        for question, answer, outcome in done:
            self._close(question, answer, outcome, moment)
        return len(done)

    def _close(self, question: Question, answer: Attribution, outcome: str, now: float | None = None) -> None:
        moment = self.attributor.clock() if now is None else now
        lag_ms = max(0.0, (moment - question.settle_mono) * 1000.0)
        if lag_ms > self.max_close_lag_ms and outcome not in {"stopped", "dropped", "ambiguous"}:
            self.max_close_lag_ms = lag_ms
        self.closed[outcome] = self.closed.get(outcome, 0) + 1
        try:
            self._on_closed(question, answer, outcome)
        except Exception:
            self.failed += 1
            logger.exception("attribution: closing the question for %s failed", question.path)

    # -- reporting -------------------------------------------------------

    def depth(self) -> int:
        with self._lock:
            return len(self._items)

    def stats(self) -> dict:
        return {
            "running": self.running,
            "open": self.depth(),
            "opened": self.opened,
            "closed": dict(self.closed),
            "dropped": self.dropped,
            "failed": self.failed,
            "max_pending": self.max_pending,
            "sweep_ms": self.sweep_ms,
            # How far past its horizon the slowest question closed. The kill
            # budget is observation + tolerance + horizon + this + one HTTP
            # call, so this is the number to watch against the 2 s target.
            "max_close_lag_ms": round(self.max_close_lag_ms, 1),
        }


def _self_and_ancestors() -> set[int]:
    """This process and everything it descends from.

    Mirrors the Response service's own guard. The Monitor writes into the
    watched tree during its tests, and a detector that can attribute a write to
    itself is one hop from asking for its own termination.
    """
    pids = {os.getpid()}
    try:
        pids.add(os.getppid())
    except (AttributeError, OSError):
        pass
    try:
        import psutil  # noqa: PLC0415 - declared in requirements.txt; optional for import

        pids.update(parent.pid for parent in psutil.Process().parents())
    except Exception:
        # Without psutil (a pre-escalation install) the immediate parent is
        # still excluded, which covers the shell that started the Monitor.
        pass
    return pids


def build_source(log: WriteLog) -> AttributionSource:
    """The best source this host can actually provide.

    Selection is by capability, not by configuration: a host that cannot
    subscribe gets `NullSource` with the refusal reason attached, so
    `/monitor/attribution` explains *why* nothing is attributed rather than
    just reporting that nothing is.
    """
    mode = os.getenv("ATTRIBUTION_SOURCE", "auto").strip().lower()

    if mode in {"off", "none", "disabled"}:
        return NullSource(log, "attribution disabled by ATTRIBUTION_SOURCE")

    if mode in {"auto", "security", "4663"}:
        if os.name == "nt":
            candidate = SecurityLogSource(log)
            if candidate.start():
                return candidate
            if mode != "auto":
                return candidate  # explicitly asked for; keep its error visible
            return NullSource(log, candidate.error or "Security channel unavailable")
        if mode != "auto":
            return NullSource(log, f"ATTRIBUTION_SOURCE={mode!r} is Windows-only")
        return NullSource(log, f"no attribution source for platform {os.name!r}")

    return NullSource(log, f"unknown ATTRIBUTION_SOURCE {mode!r}")


#: The process-wide instance. `app.py` starts it at startup and asks it per
#: suspicious event; tests build their own rather than reaching for this one.
attributor = Attributor()
