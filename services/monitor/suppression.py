"""False-positive suppression: whitelist and training mode - AS.

Table 5.7 lists four mitigations for "High false positive rate". Two were built
(differential entropy analysis, magic byte verification) and two were not:

    Training mode for learning legitimate patterns
    Whitelist mechanism

This module is those two. Both answer the same question - "is this alert one an
operator has already decided they do not want?" - and both have the same danger,
which is that a suppression mechanism is indistinguishable from a hole in the
detector unless it is bounded. So every rule here is bounded in the same way:

    A suppression may never survive evidence that is more expensive to fake than
    the suppression itself is.

Where that decision is made
---------------------------
Not here. `match()` answers only "does this rule describe this file" - is the
path in the list, was this extension learned in this directory, does the content
hash to an approved value. Whether a matching rule is then allowed to *cancel*
the alert is decided in services/monitor/admissibility.py, from the cost of
forging the rule against the cost of avoiding the detection that fired.

That split is deliberate and it replaced two hand-written rules that lived here:
a path rule used to return None when the verdict carried an entropy rise, and a
training-mode ceiling used to do the same. Both were right, and both were
special cases someone had to think of one at a time - which is why the two
equivalent cases nobody thought of (a ceiling cancelling a forged container, a
ceiling cancelling intermittent encryption) were open until the general rule was
written down. Keeping one decision point also means an outranked suppression is
recorded on the event rather than silently dropped, so an operator can see that
the rule they wrote was consulted and lost.

What is still decided here, because it is about matching rather than ranking:

  * A content hash is exact. If the bytes hash to an approved value the file
    *is* the approved file, and there is nothing to adjudicate.
  * A ransom extension was never learned, so no training baseline describes it.
  * A file whose declared container is structurally forged is not the file any
    baseline learned either, whatever its extension says.

Publisher-based whitelisting is deliberately absent. It needs Authenticode
verification, which is Windows-only and cannot run in the Linux container the
Monitor ships in, and 8.5 of the reference document places "a more robust
whitelist mechanism using digital signature verification" in future work.
"""

from __future__ import annotations

import json
import os
import threading
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import PurePath
from time import time

# Verdicts that mean "this file's content was replaced, not edited". Retained
# because the ledger and the write-up both name it; the ranking that used to be
# built on it now lives in admissibility.py.
REPLACEMENT_EVIDENCE = frozenset({"suspected_encryption", "suspicious_extension"})

# How long a file must have been under observation before its entropy is allowed
# to raise a learned ceiling.
#
# This is the fix for a defect the module's own docstring promised was not
# possible. `observe` refused an event carrying a differential-entropy rise, but
# a *created* file has no baseline, so `entropy_delta` is None and there is no
# rise to refuse - which meant anyone who could write a file into the watched
# tree during a training window could write one at 7.99 bits/byte and lift the
# ceiling for that extension to 7.99. Measured: real encryption at 7.98
# suppressed after a single poison write. The mechanism advertised as unable to
# "teach the detector to ignore that workload being encrypted" did exactly that.
#
# A dwell requirement prices it. A reading only becomes a ceiling once its path
# has been under observation for this long, so a file written to move the
# ceiling and then used has to survive the window rather than being created for
# the purpose. It does not make poisoning impossible - an attacker patient
# enough to write early and wait still succeeds - and that residual is why the
# ceiling is also keyed by structural class below, and why admissibility.py
# prices a training-mode ceiling LOW and refuses to let it cancel anything that
# costs more than that to avoid.
TRAINING_DWELL_SECONDS = float(os.getenv("TRAINING_DWELL_SECONDS", "30"))

# Candidate readings kept per (extension, structure) key while learning. Bounded
# like everything else that grows per-path; the highest readings are the ones
# that can become a ceiling, so those are the ones retained.
MAX_CANDIDATE_PATHS = int(os.getenv("TRAINING_MAX_CANDIDATES", "64"))


def _normalise(path: str) -> str:
    """Compare paths the way the platform does, with one separator convention."""
    return PurePath(os.path.normcase(path)).as_posix()


class Whitelist:
    """Paths and content hashes an operator has approved.

    Configurable from a JSON file (`WHITELIST_PATH`) and at runtime through
    `/monitor/whitelist`. Both write the same structure:

        {"paths": ["/watch/backups/*.zip"], "hashes": ["ab12..."]}
    """

    def __init__(self, paths: list[str] | None = None, hashes: list[str] | None = None):
        self._paths = list(paths or [])
        self._hashes = {h.lower() for h in (hashes or [])}
        self._lock = threading.Lock()

    # -------------------------------------------------------------- loading

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "Whitelist":
        try:
            with open(path, "r", encoding="utf-8") as handle:
                config = json.load(handle)
        except (OSError, ValueError):
            # A missing or unparseable whitelist must not stop the Monitor from
            # starting, and must not silently become a permissive one either -
            # an empty whitelist suppresses nothing.
            return cls()
        return cls(paths=config.get("paths"), hashes=config.get("hashes"))

    def to_dict(self) -> dict:
        with self._lock:
            return {"paths": list(self._paths), "hashes": sorted(self._hashes)}

    def replace(self, paths: list[str] | None, hashes: list[str] | None) -> None:
        with self._lock:
            self._paths = list(paths or [])
            self._hashes = {h.lower() for h in (hashes or [])}

    def __len__(self) -> int:
        with self._lock:
            return len(self._paths) + len(self._hashes)

    # ------------------------------------------------------------- matching

    def match(self, file_path: str, file_hash: str | None, verdict: dict) -> dict | None:
        """The rule that describes this event, or None.

        Returns the matching rule rather than a bare bool so the suppression can
        be recorded on the event and audited later. An alert that vanishes
        without saying which rule removed it is not a mitigation, it is a bug
        that has not been noticed yet.

        Whether the rule is strong enough to cancel the alert is not decided
        here - see admissibility.adjudicate. `verdict` is still taken because a
        hash rule needs to be reported ahead of a path rule regardless.
        """
        with self._lock:
            paths = list(self._paths)
            hashes = set(self._hashes)

        if file_hash and file_hash.lower() in hashes:
            # Content-exact, and reported first: the bytes are an approved file's
            # bytes, so there is nothing weaker that should shadow it.
            return {"rule": "hash", "value": file_hash.lower()}

        target = _normalise(file_path)
        for pattern in paths:
            if fnmatch(target, _normalise(pattern)) or fnmatch(
                os.path.basename(target), os.path.basename(_normalise(pattern))
            ):
                return {"rule": "path", "value": pattern}

        return None


def _rose(verdict: dict) -> bool:
    """True when differential entropy says this file's content was replaced."""
    delta = verdict.get("entropy_delta")
    return delta is not None and delta > 0


def _structure_of(verdict: dict) -> str:
    """The structural class a learned ceiling is keyed by.

    An extension is a claim about a file; the structure is what the file
    actually is. Keeping them apart means a ceiling learned from real ZIP
    archives named `.docx` cannot be spent on a `.docx` that is raw ciphertext,
    and vice versa - which is the difference between learning "this workload
    produces high-entropy archives" and learning "ignore anything called .docx".
    """
    container = verdict.get("container_format")
    if not container:
        return "plain"
    if verdict.get("container_valid") is False:
        return "forged"
    return f"container:{container}"


class TrainingMode:
    """Learn what normal looks like on this machine, then stop alerting on it.

    Table 5.7: *"Training mode for learning legitimate patterns."* The baseline
    is deliberately coarse - which directories see writes, which extensions
    appear in them, what structure those files have, and how random they got.
    Anything finer would need a per-file model, and the point of this mechanism
    is to be auditable by a human who has to decide whether to trust it.

    What is recorded, per (extension, structural class):

      * the directories it was seen in
      * the highest entropy any file of that shape reached, once that file had
        been under observation for `dwell_seconds`

    Suppression then requires *all* of:

      * training finished and this shape was learned
      * the file is in a directory that shape was learned in
      * its entropy does not exceed the highest learned for that shape
      * no known ransomware extension
      * its declared container, if it has one, is not structurally forged

    The entropy ceiling is what keeps this from becoming a hole. A `.docx` whose
    baseline reached 6.1 bits/byte will not suppress the same `.docx` at 7.99
    after an encryptor has been through it, because 7.99 is above anything the
    baseline observed.

    Three things stop the ceiling itself from being the hole - the failure this
    class shipped with, where one created file at 7.99 raised it to 7.99:

      * a reading only counts once its path has dwelled (TRAINING_DWELL_SECONDS)
      * a forged container never contributes and is never suppressed
      * the ceiling is keyed by structural class, so poisoning with a real
        archive buys a ceiling that only covers real archives

    None of the three makes poisoning impossible, and the fourth bound is the
    one that makes the residual survivable: admissibility.py prices a
    training-mode ceiling LOW, so whatever it is poisoned to, it can only ever
    cancel a static-entropy verdict on a file with no measurement history. It
    cannot cancel an entropy rise, a forged container, or intermittent
    encryption.
    """

    IDLE = "idle"
    LEARNING = "learning"
    ACTIVE = "active"

    def __init__(self, dwell_seconds: float = TRAINING_DWELL_SECONDS) -> None:
        self._state = self.IDLE
        self._deadline: float | None = None
        self._started_at: float | None = None
        self._dwell = dwell_seconds
        self._directories: dict[tuple[str, str], set[str]] = defaultdict(set)
        # (extension, structure) -> {path: (highest entropy seen, first seen at)}
        self._candidates: dict[tuple[str, str], dict[str, tuple[float, float]]] = defaultdict(dict)
        self._ceilings: dict[tuple[str, str], float] = {}
        self._observed = 0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- state

    def start(self, duration_seconds: float) -> dict:
        with self._lock:
            self._state = self.LEARNING
            self._started_at = time()
            self._deadline = self._started_at + duration_seconds
            self._directories.clear()
            self._candidates.clear()
            self._ceilings = {}
            self._observed = 0
        return self.status()

    def finish(self) -> dict:
        """End learning. Becomes active only if something was actually learned.

        A baseline of nothing would suppress nothing, so this is not a failure
        mode so much as a state worth reporting honestly: a training window that
        saw no events has not learned that everything is suspicious, it has
        learned nothing. A window whose every candidate was too fresh to have
        dwelled is the same state, and reports the same way.
        """
        with self._lock:
            self._promote()
        return self.status()

    def reset(self) -> dict:
        with self._lock:
            self._state = self.IDLE
            self._deadline = None
            self._started_at = None
            self._directories.clear()
            self._candidates.clear()
            self._ceilings = {}
            self._observed = 0
        return self.status()

    def _promote(self) -> None:
        """Freeze the candidates that have dwelled into ceilings. Lock held."""
        self._ceilings = self._eligible_ceilings()
        self._state = self.ACTIVE if self._ceilings else self.IDLE
        self._deadline = None

    def _eligible_ceilings(self) -> dict[tuple[str, str], float]:
        """The ceiling each shape would get right now. Lock held."""
        now = time()
        ceilings: dict[tuple[str, str], float] = {}
        for key, candidates in self._candidates.items():
            dwelled = [
                entropy
                for entropy, first_seen in candidates.values()
                if now - first_seen >= self._dwell
            ]
            if dwelled:
                ceilings[key] = max(dwelled)
        return ceilings

    def _expire_if_due(self) -> None:
        if self._state == self.LEARNING and self._deadline and time() >= self._deadline:
            self._promote()

    @property
    def state(self) -> str:
        with self._lock:
            self._expire_if_due()
            return self._state

    def status(self) -> dict:
        with self._lock:
            self._expire_if_due()
            # While learning, report what the baseline would be if it froze now.
            # A ceiling that only appears at `finish` would leave an operator
            # watching a training window with nothing to look at.
            ceilings = self._ceilings if self._state == self.ACTIVE else self._eligible_ceilings()
            return {
                "state": self._state,
                "observed_events": self._observed,
                "learned_extensions": self._learned_view(ceilings),
                "dwell_seconds": self._dwell,
                "seconds_remaining": (
                    max(0, round(self._deadline - time(), 1)) if self._deadline else None
                ),
            }

    def _learned_view(self, ceilings: dict[tuple[str, str], float]) -> dict:
        """Ceilings grouped for reporting. Lock held.

        Keyed by extension, because that is what an operator asks about and what
        the API has always returned. `profiles` is where the structural split is
        visible - one extension can hold a ceiling for real archives and a
        different, lower one for files with no container at all.
        """
        view: dict[str, dict] = {}
        for (extension, structure), ceiling in sorted(ceilings.items()):
            directories = sorted(self._directories.get((extension, structure), ()))
            entry = view.setdefault(
                extension, {"entropy_ceiling": 0.0, "directories": [], "profiles": []}
            )
            entry["entropy_ceiling"] = max(entry["entropy_ceiling"], round(ceiling, 2))
            entry["directories"] = sorted(set(entry["directories"]) | set(directories))
            entry["profiles"].append(
                {
                    "structure": structure,
                    "entropy_ceiling": round(ceiling, 2),
                    "directories": directories,
                }
            )
        return view

    # -------------------------------------------------------------- learning

    def observe(self, file_path: str, entropy: float | None, verdict: dict) -> bool:
        """Fold one event into the baseline. True when it was recorded.

        Events carrying replacement evidence are refused. If an encryptor is
        already running when training starts, the alternative is a baseline that
        has learned the attack as normal - which is the one way this feature
        could do real harm. A file whose declared container is forged is refused
        for the same reason: whatever it is, it is not an example of the format
        it claims, so it is not an example of anything.

        Recording is not the same as raising a ceiling. A reading becomes a
        ceiling only once its path has been under observation for
        `dwell_seconds`; see `_eligible_ceilings`.
        """
        if self.state != self.LEARNING or entropy is None:
            return False
        if verdict.get("ransom_extension") or _rose(verdict):
            return False
        if verdict.get("container_valid") is False:
            return False

        directory, extension = _split(file_path)
        key = (extension, _structure_of(verdict))
        now = time()

        with self._lock:
            self._directories[key].add(directory)
            candidates = self._candidates[key]
            previous = candidates.get(file_path)
            if previous is None:
                candidates[file_path] = (entropy, now)
                self._trim(candidates)
            elif entropy > previous[0]:
                # Keep the path's own first sighting: the dwell is a property of
                # how long the file has been watched, not of when it peaked.
                candidates[file_path] = (entropy, previous[1])
            self._observed += 1
        return True

    @staticmethod
    def _trim(candidates: dict[str, tuple[float, float]]) -> None:
        """Bound the candidate set per shape. Lock held.

        The highest readings are the only ones that can become a ceiling, so
        those are the ones kept. Without this a training window over a busy tree
        grows an entry per file for the length of the window.
        """
        while len(candidates) > MAX_CANDIDATE_PATHS:
            lowest = min(candidates, key=lambda path: candidates[path][0])
            del candidates[lowest]

    # ----------------------------------------------------------- suppression

    def match(self, file_path: str, entropy: float | None, verdict: dict) -> dict | None:
        """The learned pattern that describes this file, or None.

        Whether it is allowed to cancel the alert is admissibility.adjudicate's
        decision, not this one.
        """
        if self.state != self.ACTIVE or entropy is None:
            return None
        if verdict.get("ransom_extension"):
            return None
        if verdict.get("container_valid") is False:
            return None

        directory, extension = _split(file_path)
        key = (extension, _structure_of(verdict))
        with self._lock:
            ceiling = self._ceilings.get(key)
            directories = set(self._directories.get(key, ()))

        if ceiling is None or directory not in directories:
            return None
        if entropy > ceiling:
            return None

        return {
            "rule": "training_mode",
            "value": (
                f"{extension} ({key[1]}) in {directory} at or below "
                f"{round(ceiling, 2)} bits/byte"
            ),
        }


def _split(file_path: str) -> tuple[str, str]:
    normalised = _normalise(file_path)
    directory = os.path.dirname(normalised)
    extension = os.path.splitext(normalised)[1].lower() or "<none>"
    return directory, extension
