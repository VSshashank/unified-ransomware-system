"""How fast a process is working, and whether that looks like encryption.

The motivating result is in the write-up and is not a small one. On the Phase 5
corpus all four repair arms collapse to 90/90 on the *unvalidated* stratum
while the validated stratum goes 95 -> 0: content-only inspection cannot
adjudicate a container it has no structural validator for, at any threshold,
because a benign `.xz` and ciphertext under a forged header are the same bytes
to an entropy test. The project has validators for 6 of 17 formats, so the
headline "100.0 pp" negative result is a validator-coverage artefact rather
than a law.

What that result implies is an axis orthogonal to content: *who* wrote these
bytes, and *how fast*. Attribution answers the first. This answers the second.

Four signals, kept per PID over a sliding window:

  path_rate         distinct paths written per second
  directory_fanout  distinct directories touched
  extension_churn   writes landing on a different extension than the path had
  entropy_delta     this reading against the entropy the ledger recorded for
                    the same path while it was still known-good

The last one is the cheap one and the one the per-file design throws away. A
file that was 4.2 bits/byte yesterday and is 7.99 today has not become a better
compressed archive. `file_baseline` events already carry `entropy`, so the
reference value costs a ledger read and nothing else.

None of these is a detector on its own, and none of them is used as one: they
are corroboration for a decision to *kill*, which `agent.responder` requires
two independent instances of. A suspension needs none of them.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Write:
    at: float
    path: str
    directory: str
    extension: str
    entropy: float | None = None
    baseline_entropy: float | None = None
    #: Decided at record time, not at read time. Both are derived from state
    #: this same write then updates, so asking afterwards would compare the
    #: write against itself and never fire.
    churned: bool = False

    @property
    def entropy_delta(self) -> float | None:
        if self.entropy is None or self.baseline_entropy is None:
            return None
        return self.entropy - self.baseline_entropy


@dataclass
class Signals:
    """What fired, and the numbers behind it."""

    pid: int
    window_s: float
    writes: int = 0
    distinct_paths: int = 0
    path_rate: float = 0.0
    directory_fanout: int = 0
    extension_churn: int = 0
    max_entropy_delta: float | None = None
    fired: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "window_s": self.window_s,
            "writes": self.writes,
            "distinct_paths": self.distinct_paths,
            "path_rate_per_s": round(self.path_rate, 3),
            "directory_fanout": self.directory_fanout,
            "extension_churn": self.extension_churn,
            "max_entropy_delta": (round(self.max_entropy_delta, 3)
                                  if self.max_entropy_delta is not None else None),
            "fired": list(self.fired),
        }


#: A rise this far above the ledger's known-good reading for the same path.
#: 2.0 bits/byte is the Monitor's own ENTROPY_RISE_THRESHOLD default, reused
#: rather than invented so the two layers do not disagree about what a rise is.
ENTROPY_DELTA_THRESHOLD = float(os.getenv("ENTROPY_RISE_THRESHOLD", "2.0"))

#: Writes landing on a changed extension before churn counts as a signal. One
#: rename is a save; a run of them is a campaign.
EXTENSION_CHURN_THRESHOLD = 3

#: The shortest span a rate may be computed over, in seconds. See `signals`.
MIN_RATE_SPAN_S = 0.25

#: The rate term additionally needs this many distinct paths before it fires.
#: Without a floor, a fast burst of three files - a document, its index and its
#: temp file, which ordinary applications write in one go - is a "rate" of
#: hundreds per second, and path_velocity becomes a signal about application
#: behaviour rather than about a campaign.
MIN_PATHS_FOR_RATE = 6


class VelocityTracker:
    """Per-PID sliding window over recent writes."""

    def __init__(self, window_s: float = 10.0, path_threshold: int = 12,
                 fanout_threshold: int = 3, max_pids: int = 512) -> None:
        self.window_s = float(window_s)
        self.path_threshold = int(path_threshold)
        self.fanout_threshold = int(fanout_threshold)
        self.max_pids = int(max_pids)
        self._writes: dict[int, deque[Write]] = {}
        #: stem (path without its final extension) -> the extension last seen
        #: on it. Catches replacement: report.docx -> report.locked.
        self._known_extension: dict[str, str] = {}
        #: every path seen. Catches appending, which is what real families
        #: actually do: report.docx -> report.docx.locked.
        self._seen_paths: set[str] = set()
        self._lock = threading.Lock()

    # -- recording ---------------------------------------------------------

    def record(self, pid: int | None, path: str, entropy: float | None = None,
               baseline_entropy: float | None = None, at: float | None = None) -> None:
        """Note one write. An unattributed write is not attributed to anyone.

        `pid is None` is dropped rather than bucketed under a sentinel: a
        shared "unknown" bucket would pool every unattributed write on the
        host into one apparent process and manufacture a velocity signal out
        of ordinary activity.
        """
        if pid is None:
            return
        moment = time.monotonic() if at is None else at
        directory = os.path.dirname(path)
        extension = os.path.splitext(path)[1].lower()

        lowered = path.lower()
        stem = os.path.splitext(path)[0].lower()

        with self._lock:
            # Decide churn against the state as it was *before* this write.
            #
            # Two shapes, because families use both. Appending is the common
            # one - report.docx -> report.docx.locked - and shows up as the
            # new path's stem being a path already written. Replacement -
            # report.docx -> report.locked - shows up as a known stem
            # acquiring a different extension.
            appended = stem in self._seen_paths
            replaced = (self._known_extension.get(stem) not in (None, extension))
            churned = bool(appended or replaced)

            if pid not in self._writes and len(self._writes) >= self.max_pids:
                self._evict_locked(moment)
            bucket = self._writes.setdefault(pid, deque())
            bucket.append(Write(moment, path, directory, extension,
                                entropy, baseline_entropy, churned))
            self._trim_locked(bucket, moment)

            self._seen_paths.add(lowered)
            self._known_extension[stem] = extension
            if len(self._seen_paths) > 20000:
                self._seen_paths.clear()
                self._known_extension.clear()

    def _trim_locked(self, bucket: deque, now: float) -> None:
        cutoff = now - self.window_s
        while bucket and bucket[0].at < cutoff:
            bucket.popleft()

    def _evict_locked(self, now: float) -> None:
        """Drop PIDs with nothing left in the window."""
        for pid in [p for p, b in self._writes.items()
                    if not b or b[-1].at < now - self.window_s]:
            self._writes.pop(pid, None)
        if len(self._writes) >= self.max_pids:
            oldest = min(self._writes, key=lambda p: self._writes[p][-1].at)
            self._writes.pop(oldest, None)

    # -- reading -----------------------------------------------------------

    def signals(self, pid: int | None, now: float | None = None) -> Signals:
        if pid is None:
            return Signals(pid=-1, window_s=self.window_s)
        moment = time.monotonic() if now is None else now

        with self._lock:
            bucket = self._writes.get(int(pid))
            recent = [w for w in bucket if w.at >= moment - self.window_s] if bucket else []

        result = Signals(pid=int(pid), window_s=self.window_s, writes=len(recent))
        if not recent:
            return result

        paths = {w.path for w in recent}
        result.distinct_paths = len(paths)
        # Rate over the span actually observed, not over the nominal window: a
        # burst of 20 files in 0.4s is 50/s, and dividing by 10 would report 2.
        #
        # The span is floored at MIN_RATE_SPAN_S because dividing by a
        # sub-millisecond observation extrapolates three files saved together -
        # a document, its index and its temp file, which ordinary applications
        # write in one go - into thousands per second. A rate computed from
        # almost no elapsed time is arithmetic, not evidence.
        span = max(recent[-1].at - recent[0].at, MIN_RATE_SPAN_S)
        result.path_rate = len(paths) / span if len(recent) > 1 else 0.0
        result.directory_fanout = len({w.directory for w in recent})
        result.extension_churn = sum(1 for w in recent if w.churned)
        deltas = [w.entropy_delta for w in recent if w.entropy_delta is not None]
        result.max_entropy_delta = max(deltas) if deltas else None

        fired = []
        if (result.distinct_paths >= self.path_threshold
                or (result.path_rate >= self.path_threshold
                    and result.distinct_paths >= MIN_PATHS_FOR_RATE)):
            fired.append("path_velocity")
        if result.directory_fanout >= self.fanout_threshold:
            fired.append("directory_fanout")
        if result.extension_churn >= EXTENSION_CHURN_THRESHOLD:
            fired.append("extension_churn")
        if result.max_entropy_delta is not None and \
                result.max_entropy_delta >= ENTROPY_DELTA_THRESHOLD:
            fired.append("entropy_delta")
        result.fired = tuple(fired)
        return result

    def forget(self, pid: int) -> None:
        with self._lock:
            self._writes.pop(int(pid), None)

    def tracked_pids(self) -> list[int]:
        with self._lock:
            return sorted(self._writes)
