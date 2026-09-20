"""Events that deserve a response but cannot yet name a process.

`scripts/measure_attribution_lag.py` measured what the Security channel
actually does on this host, at four write rates:

    idle       5 writes/s   median  601 ms   max 1007 ms
    busy      20 writes/s   median  512 ms   max 1013 ms
    fast     100 writes/s   median  655 ms   max 1010 ms
    burst   uncapped        median  949 ms   max 1009 ms

The lag is bounded near one second and it does not depend on the rate, which
is the signature of a **flush timer**. A write landing just before a flush is
visible in about twelve milliseconds; one landing just after waits out the
interval. Nothing about the agent changes that: it is how the channel delivers.

Two things follow, and together they are the Phase 3 defect.

First, the 250 ms blocking grace inside `Attributor.resolve` catches a minority
of records at any rate and **none at all under burst**. Paying it on the
detection path bought almost nothing and cost a quarter of a second per event.

Second - and this is the one that made the first acceptance read as a total
failure - a 750 ms correlation window is *below the delivery ceiling of the
source*. Under a burst every write falls inside a single flush interval, so by
the time any record is visible every event it could explain has already aged
out. The window has since been calibrated to the measurement.

So the shape here is: **look without waiting, and look again when the record
lands.** An event that cannot name its writer is parked, and a single thread
re-asks every 25 ms. A lookup is a lock and a scan of a bounded deque, so a
re-ask costs microseconds - the thing that was expensive was the *sleeping*,
not the asking. An event resolves the moment its record arrives, which for the
common case is far sooner than any fixed delay would have been, and the lanes
stay free to keep up with the attack.

Nothing here decides anything. It re-asks a question and hands the answer back
to the same responder that would have handled the event inline, with the same
gates, the same `CERTAIN` requirement and the same refusal to guess a PID. An
event that never attributes is still responded to - as `isolate_and_log`, with
the reason recorded - so a parked event is never an event quietly dropped.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("urds-agent.pending")

#: How often the parked events are re-asked. Well under the ~12 ms best case
#: seen in the measurement, so an early-delivered record is acted on almost as
#: fast as it would have been inline.
POLL_MS = 25.0

#: Parked events held at once. Past this the oldest is discarded, for the same
#: reason the dispatcher discards its oldest: the oldest is the one whose
#: window is closest to expiring, so it is the one least likely to resolve.
MAX_PENDING = 4096


@dataclass
class Parked:
    """One event waiting for its writer to be named."""

    event: dict
    path: str
    kind: str
    queued_at: float
    canary_path: bool
    expires_at: float
    attempts: int = 0
    resolved_after_ms: float | None = field(default=None)


class PendingAttribution:
    """Re-asks who wrote a path until the answer arrives or the window shuts."""

    def __init__(self, resolve, respond, window_ms: float,
                 poll_ms: float = POLL_MS, max_pending: int = MAX_PENDING) -> None:
        #: resolve(path, event_at) -> dict of attribution fields, without
        #: waiting. `event_at` is when the parked event was queued, and it is
        #: the queued moment on every re-ask rather than the moment of the
        #: re-ask: the lookup rejects audit records that predate the event, and
        #: stamping the question with `now` would reject the record the sweep
        #: exists to wait for.
        self._resolve = resolve
        #: respond(parked, attributed: bool) -> None. The single place an
        #: event is acted on, whether it named a process or ran out of window.
        self._respond = respond
        self.window_ms = float(window_ms)
        self.poll_ms = float(poll_ms)
        self.max_pending = int(max_pending)

        self._items: deque[Parked] = deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopping = False

        self.parked = 0
        self.resolved = 0
        self.expired = 0
        self.dropped = 0
        self.failed = 0
        self._resolved_lags: deque[float] = deque(maxlen=512)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping = False
        self._thread = threading.Thread(
            target=self._run, name="urds-pending", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> dict:
        self._stopping = True
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        # Whatever is still parked never named anybody. Responding to it on the
        # way out is what keeps "the agent stopped" from being indistinguishable
        # from "the agent decided these were fine".
        self._flush_remaining()
        return self.stats()

    # -- the two ends ------------------------------------------------------

    def add(self, event: dict, path: str, kind: str, queued_at: float,
            canary_path: bool) -> bool:
        """Park an event. False if an older one had to be discarded first."""
        parked = Parked(
            event=event, path=path, kind=kind, queued_at=queued_at,
            canary_path=canary_path,
            expires_at=queued_at + (self.window_ms / 1000.0),
        )
        discarded = None
        with self._lock:
            dropped = False
            if len(self._items) >= self.max_pending:
                discarded = self._items.popleft()
                self.dropped += 1
                dropped = True
            self._items.append(parked)
            self.parked += 1
        if discarded is not None:
            self._safe_respond(discarded, attributed=False)
        self._wake.set()
        return not dropped

    def _run(self) -> None:
        while not self._stopping:
            self._wake.wait(timeout=self.poll_ms / 1000.0)
            self._wake.clear()
            if self._stopping:
                return
            try:
                self._sweep()
            except Exception:  # noqa: BLE001 - the sweep must never die
                logger.exception("pending sweep failed")

    def _sweep(self) -> None:
        now = time.monotonic()
        with self._lock:
            if not self._items:
                return
            candidates = list(self._items)

        done: list[tuple[Parked, bool]] = []
        for parked in candidates:
            parked.attempts += 1
            fields = None
            try:
                fields = self._resolve(parked.path, parked.queued_at)
            except Exception:  # noqa: BLE001
                self.failed += 1
                logger.debug("re-resolve failed for %s", parked.path,
                             exc_info=True)

            if fields is not None:
                parked.event.update(fields)
                if fields.get("attribution_confidence") == "certain":
                    parked.resolved_after_ms = (now - parked.queued_at) * 1000.0
                    self._resolved_lags.append(parked.resolved_after_ms)
                    self.resolved += 1
                    done.append((parked, True))
                    continue

            if now >= parked.expires_at:
                self.expired += 1
                done.append((parked, False))

        if not done:
            return
        finished = {id(parked) for parked, _ in done}
        with self._lock:
            self._items = deque(item for item in self._items
                                if id(item) not in finished)
        for parked, attributed in done:
            self._safe_respond(parked, attributed)

    def _flush_remaining(self) -> None:
        with self._lock:
            left = list(self._items)
            self._items.clear()
        for parked in left:
            self.expired += 1
            self._safe_respond(parked, attributed=False)

    def _safe_respond(self, parked: Parked, attributed: bool) -> None:
        try:
            self._respond(parked, attributed)
        except Exception:  # noqa: BLE001
            self.failed += 1
            logger.exception("responding to a parked event failed: %s",
                             parked.path)

    # -- reporting ---------------------------------------------------------

    def depth(self) -> int:
        with self._lock:
            return len(self._items)

    def stats(self) -> dict:
        lags = sorted(self._resolved_lags)
        return {
            "window_ms": self.window_ms,
            "poll_ms": self.poll_ms,
            "max_pending": self.max_pending,
            "parked": self.parked,
            "resolved_by_re_asking": self.resolved,
            "expired_without_a_writer": self.expired,
            "dropped": self.dropped,
            "failed": self.failed,
            "depth": self.depth(),
            "resolve_lag_ms_median": (round(lags[len(lags) // 2], 1)
                                      if lags else None),
            "resolve_lag_ms_max": round(lags[-1], 1) if lags else None,
        }
