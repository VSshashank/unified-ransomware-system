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

THE RACE, AND WHY `resolve()` MAY WAIT

The audit record and the watchdog event describe the same write and arrive by
different paths. The audit record is usually first - the access check happens
before the write completes - but Security-channel delivery is not instant. So
`resolve()` looks once, and if the source is live and has nothing yet, polls
for a bounded grace period.

That wait is response-budget work, not detection work. The caller in `app.py`
runs it *after* `detection_latency_ms` is recorded, so Table 5.9's <100 ms
detection target stays a measurement of detection and does not silently become
a measurement of the Security log's delivery lag.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- confidence

CERTAIN = "certain"
PROBABLE = "probable"
UNKNOWN = "unknown"

#: Only this one authorises a kill. Kept as a set so a future source that
#: warrants its own level does not have to touch the call sites.
KILL_AUTHORISING = frozenset({CERTAIN})

# ------------------------------------------------------------------- tunables

#: How far back a write counts as explaining this event. Long enough to cover
#: audit delivery lag and the watchdog debounce, short enough that an unrelated
#: earlier writer to the same path is not swept in.
#:
#: 3000, not the 750 this shipped with. `scripts/measure_attribution_lag.py`
#: measured delivery on this channel at four write rates and found the lag
#: bounded at ~1010 ms and *independent of rate* - a flush timer, not queueing.
#: A write landing just before a flush is visible in ~12 ms; one landing just
#: after waits out the interval. 750 ms is therefore below the delivery floor
#: of the mechanism this reads: under a burst, where every write falls inside
#: one flush interval, it matched 0 of 120 records. At 3000 it matched 245 of
#: 245 across every rate tested, with roughly 3x margin on the ceiling.
#:
#: Widening this does not make attribution easier to obtain. `lookup` returns
#: CERTAIN only when exactly one process wrote the path inside the window, so a
#: longer window admits *more* candidate writers and yields PROBABLE where a
#: shorter one would have said CERTAIN on partial evidence. The cost is paid in
#: the safe direction. See reports/attribution_delivery_lag.json.
WINDOW_MS = float(os.getenv("ATTRIBUTION_WINDOW_MS", "3000"))

#: How long `resolve()` will wait for a record that has not arrived yet.
#:
#: This is a *blocking* wait, and the same measurement says it catches a
#: minority of records at any rate and none at all under burst. It is kept for
#: the Monitor's own HTTP path, where one event is adjudicated per request and
#: blocking briefly is harmless. The agent passes `grace_ms=0` and re-checks
#: instead - see `agent/pending.py` - because a detector that blocks a thread
#: for a second per unattributed write cannot keep up with an encryptor.
GRACE_MS = float(os.getenv("ATTRIBUTION_GRACE_MS", "250"))

#: Poll interval inside that grace period.
POLL_MS = float(os.getenv("ATTRIBUTION_POLL_MS", "10"))

#: Bounded, because this is fed by every audited write on the volume. At the
#: default it is a couple of MB and it is the reason this module cannot become
#: the `_SEEN_FILES` leak recorded as S-7 in the security audit.
#:
#: Raised with WINDOW_MS and for the same reason: four times the window holds
#: four times the in-window records, and an entry evicted while still inside
#: the window is an attribution silently lost.
MAX_ENTRIES = int(os.getenv("ATTRIBUTION_MAX_ENTRIES", "16384"))

#: 4663 reports the access that was checked. WriteData (0x2) and AppendData
#: (0x4) are the two that mean "this process put bytes in the file".
ACCESS_WRITE_DATA = 0x2
ACCESS_APPEND_DATA = 0x4
WRITE_MASK = ACCESS_WRITE_DATA | ACCESS_APPEND_DATA

#: DELETE (0x10000), and it is not an afterthought.
#:
#: Two of the commonest ransomware shapes never write over the original file at
#: all. `7z a -sdel` and `tar --remove-files` archive it and unlink it; a loop
#: around `openssl enc -in X -out X.enc` writes a *new* path and unlinks the
#: old one. In both, the bytes-written record names a process that has usually
#: already exited - one `openssl` per file lives about 65 ms on the measured
#: host, against roughly 1000 ms of audit delivery lag - while the process
#: doing the *deleting* is the long-lived one that is actually running the
#: campaign.
#:
#: Without this bit the agent watched forty documents disappear and could not
#: say who removed them. Auditing it costs one more access right on the SACL
#: and a modest rise in log volume, because deletes are rare next to writes.
ACCESS_DELETE = 0x10000

#: What counts as touching a file destructively, and therefore as something
#: attribution will answer about.
ACTIONABLE_MASK = WRITE_MASK | ACCESS_DELETE


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

    @property
    def kill_authorised(self) -> bool:
        """The single question the pipeline asks. Fail-closed by construction."""
        return self.confidence in KILL_AUTHORISING and self.pid is not None

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
    at: float
    #: "write" or "delete". Both are destructive touches by a named process and
    #: both answer "who did this to my file"; the word is kept so an incident
    #: record can say which one happened.
    kind: str = "write"


class WriteLog:
    """A bounded, time-windowed record of who wrote what.

    Append is hot - every audited write on the volume reaches it - and lookup
    is cold, because only a suspicious event asks. So append is O(1) onto a
    `deque` with a `maxlen`, and lookup is a linear scan of at most
    `MAX_ENTRIES`. At the default that scan is tens of microseconds and it
    keeps the eviction policy to one line instead of a second index that can
    disagree with the first.
    """

    def __init__(self, window_ms: float = WINDOW_MS, maxlen: int = MAX_ENTRIES) -> None:
        self.window_ms = window_ms
        self._writes: deque[Write] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._excluded: set[int] = set()
        self.recorded = 0
        self.dropped_non_write = 0

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

    def record(self, path: str, pid: int, image: str | None = None,
               at: float | None = None, kind: str = "write") -> None:
        entry = Write(
            path=_normalise(path),
            pid=int(pid),
            image=image,
            at=time.monotonic() if at is None else at,
            kind=kind,
        )
        with self._lock:
            self._writes.append(entry)
            self.recorded += 1

    # -- read side -------------------------------------------------------

    def lookup(
        self,
        path: str,
        window_ms: float | None = None,
        now: float | None = None,
        source: str = "none",
        kernel_grade: bool = False,
    ) -> Attribution:
        target = _normalise(path)
        window = self.window_ms if window_ms is None else window_ms
        moment = time.monotonic() if now is None else now
        cutoff = moment - (window / 1000.0)

        with self._lock:
            hits = [
                w
                for w in self._writes
                if w.path == target and w.at >= cutoff and w.pid not in self._excluded
            ]

        if not hits:
            return _unattributed(
                f"no audited write or delete on this path by another process "
                f"in the last {window:.0f}ms",
                source=source,
            )

        hits.sort(key=lambda w: w.at)
        distinct = []
        for w in hits:
            if w.pid not in distinct:
                distinct.append(w.pid)
        newest = hits[-1]
        did = "deleted" if newest.kind == "delete" else "wrote"

        if len(distinct) == 1:
            if kernel_grade:
                return Attribution(
                    pid=newest.pid,
                    image=newest.image,
                    confidence=CERTAIN,
                    reason=(
                        f"exactly one process {did} this path in the last "
                        f"{window:.0f}ms, from {source}"
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
                f"{len(distinct)} processes wrote or deleted this path in the last "
                f"{window:.0f}ms ({', '.join(str(p) for p in distinct)}); "
                f"reporting the most recent"
            ),
            source=source,
            candidates=tuple(distinct),
        )

    # -- housekeeping ----------------------------------------------------

    def clear(self) -> None:
        with self._lock:
            self._writes.clear()
            self.recorded = 0
            self.dropped_non_write = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._writes)


# ----------------------------------------------------------------- 4663 parse

_EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")


def _as_int(raw: str | None) -> int | None:
    """4663 writes PIDs and masks as hex strings like `0x1a2c`."""
    if not raw:
        return None
    raw = raw.strip()
    try:
        return int(raw, 16) if _HEX.match(raw) else int(raw)
    except ValueError:
        return None


def parse_4663(xml: str) -> dict | None:
    """One rendered 4663 event into `{path, pid, image, access_mask}`.

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
    if mask is None or not mask & ACTIONABLE_MASK:
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

    return {
        "path": path,
        "pid": pid,
        "image": data.get("ProcessName"),
        "access_mask": mask,
        # Which kind of destruction this was. Both are attributable and both
        # are recorded; the distinction is kept because "who deleted my decoy"
        # and "who overwrote it" are different sentences in an incident record.
        "kind": "write" if mask & WRITE_MASK else "delete",
    }


# --------------------------------------------------------------- the sources


class AttributionSource:
    """Where writes come from. Subclasses fill in `start`."""

    name = "none"
    #: True only for a source that sees the kernel's own view of the write.
    #: This is what separates CERTAIN from PROBABLE, so it is not a label.
    kernel_grade = False

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
            "error": self.error,
            "writes_recorded": self.log.recorded,
            "writes_buffered": len(self.log),
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
            parsed = parse_4663(xml)
            if parsed is None:
                self.log.dropped_non_write += 1
                return 0
            self.log.record(parsed["path"], parsed["pid"], parsed["image"],
                            kind=parsed["kind"])
        except Exception:  # a callback that raises tears down the subscription
            logger.debug("attribution: 4663 callback failed", exc_info=True)
        return 0

    def stop(self) -> None:
        self._handle = None
        self.available = False


# ---------------------------------------------------------------- the facade


class Attributor:
    """The object `app.py` talks to. One per process."""

    def __init__(self, log: WriteLog | None = None, source: AttributionSource | None = None) -> None:
        self.log = log if log is not None else WriteLog()
        self.source = source if source is not None else NullSource(self.log)
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

    def status(self) -> dict:
        return {
            **self.source.status(),
            "window_ms": self.log.window_ms,
            "grace_ms": GRACE_MS,
            "max_entries": self.log._writes.maxlen,
            "excluded_pids": sorted(self.log.excluded),
        }

    # -- the question ----------------------------------------------------

    def resolve(
        self,
        path: str,
        grace_ms: float | None = None,
        window_ms: float | None = None,
    ) -> Attribution:
        """Who wrote `path`, waiting briefly for a record that is still in flight.

        Callers run this *after* recording detection latency. See the module
        docstring for why.
        """
        if not self.source.available:
            return _unattributed(
                self.source.error or "no attribution source is available",
                source=self.source.name,
            )

        grace = GRACE_MS if grace_ms is None else grace_ms
        started = time.monotonic()
        deadline = started + (grace / 1000.0)
        poll = POLL_MS / 1000.0

        while True:
            answer = self.log.lookup(
                path,
                window_ms=window_ms,
                source=self.source.name,
                kernel_grade=self.source.kernel_grade,
            )
            waited_ms = (time.monotonic() - started) * 1000.0

            # A PROBABLE answer is already evidence; waiting longer can only add
            # more writers to the same path and make it less certain, not more.
            if answer.confidence != UNKNOWN or time.monotonic() >= deadline:
                return Attribution(
                    pid=answer.pid,
                    image=answer.image,
                    confidence=answer.confidence,
                    reason=answer.reason,
                    source=answer.source,
                    candidates=answer.candidates,
                    waited_ms=waited_ms,
                )
            time.sleep(poll)


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
        import psutil  # noqa: PLC0415 - optional; the Monitor does not ship it

        pids.update(parent.pid for parent in psutil.Process().parents())
    except Exception:
        # psutil is a test-only dependency of this service. Without it the
        # immediate parent is still excluded, which covers the shell that
        # started the Monitor.
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
