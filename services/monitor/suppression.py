"""False-positive suppression: whitelist and training mode - AS.

Table 5.7 lists four mitigations for "High false positive rate". Two were built
(differential entropy analysis, magic byte verification) and two were not:

    Training mode for learning legitimate patterns
    Whitelist mechanism

This module is those two. Both answer the same question - "is this alert one an
operator has already decided they do not want?" - and both have the same danger,
which is that a suppression mechanism is indistinguishable from a hole in the
detector unless it is bounded. So every rule here is bounded in the same way:

    A suppression may never survive evidence that the file was replaced.

Differential entropy analysis measures exactly that. A path rule saying "never
alert on D:\\Backups\\*" is an operator's statement about a *location*, and
ransomware writing into that location is precisely the case the operator did not
intend to authorise. So a whitelisted path stops suppressing the moment the
entropy on it rises the way replacement makes it rise. A content hash is
different: if the bytes hash to a value already approved, the file *is* the
approved file, and no rise is possible without changing the hash. Hash rules
therefore hold where path rules give way.

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

# Verdicts that mean "this file's content was replaced, not edited". A path or
# extension rule does not override these; see the module docstring.
REPLACEMENT_EVIDENCE = frozenset({"suspected_encryption", "suspicious_extension"})


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
        """The rule that suppresses this event, or None.

        Returns the matching rule rather than a bare bool so the suppression can
        be recorded on the event and audited later. An alert that vanishes
        without saying which rule removed it is not a mitigation, it is a bug
        that has not been noticed yet.
        """
        with self._lock:
            paths = list(self._paths)
            hashes = set(self._hashes)

        if file_hash and file_hash.lower() in hashes:
            # Content-exact. The bytes are an approved file's bytes, so there is
            # nothing for replacement evidence to contradict.
            return {"rule": "hash", "value": file_hash.lower()}

        replaced = verdict.get("verdict") in REPLACEMENT_EVIDENCE and _rose(verdict)

        target = _normalise(file_path)
        for pattern in paths:
            if fnmatch(target, _normalise(pattern)) or fnmatch(
                os.path.basename(target), os.path.basename(_normalise(pattern))
            ):
                if replaced:
                    # The operator approved the location, not an encryptor
                    # writing into it.
                    return None
                return {"rule": "path", "value": pattern}

        return None


def _rose(verdict: dict) -> bool:
    """True when differential entropy says this file's content was replaced."""
    delta = verdict.get("entropy_delta")
    return delta is not None and delta > 0


class TrainingMode:
    """Learn what normal looks like on this machine, then stop alerting on it.

    Table 5.7: *"Training mode for learning legitimate patterns."* The baseline
    is deliberately coarse - which directories see writes, which extensions
    appear in them, and how random those files got. Anything finer would need a
    per-file model, and the point of this mechanism is to be auditable by a
    human who has to decide whether to trust it.

    What is recorded, per extension:

      * the directories it was seen in
      * the highest entropy any file with that extension reached

    Suppression then requires *all* of:

      * training finished and this extension was learned
      * the file is in a directory that extension was learned in
      * its entropy does not exceed the highest learned for that extension
      * no known ransomware extension
      * no differential-entropy rise

    The entropy ceiling is what keeps this from becoming a hole. A `.docx` that
    the baseline saw reach 6.1 bits/byte will not suppress the same `.docx` at
    7.99 after an encryptor has been through it, because 7.99 is above anything
    the baseline observed. Learning a workload therefore cannot teach the
    detector to ignore that workload being encrypted.
    """

    IDLE = "idle"
    LEARNING = "learning"
    ACTIVE = "active"

    def __init__(self) -> None:
        self._state = self.IDLE
        self._deadline: float | None = None
        self._started_at: float | None = None
        self._directories: dict[str, set[str]] = defaultdict(set)
        self._entropy_ceiling: dict[str, float] = {}
        self._observed = 0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- state

    def start(self, duration_seconds: float) -> dict:
        with self._lock:
            self._state = self.LEARNING
            self._started_at = time()
            self._deadline = self._started_at + duration_seconds
            self._directories.clear()
            self._entropy_ceiling.clear()
            self._observed = 0
        return self.status()

    def finish(self) -> dict:
        """End learning. Becomes active only if something was actually learned.

        A baseline of nothing would suppress nothing, so this is not a failure
        mode so much as a state worth reporting honestly: a training window that
        saw no events has not learned that everything is suspicious, it has
        learned nothing.
        """
        with self._lock:
            self._state = self.ACTIVE if self._entropy_ceiling else self.IDLE
            self._deadline = None
        return self.status()

    def reset(self) -> dict:
        with self._lock:
            self._state = self.IDLE
            self._deadline = None
            self._started_at = None
            self._directories.clear()
            self._entropy_ceiling.clear()
            self._observed = 0
        return self.status()

    def _expire_if_due(self) -> None:
        if self._state == self.LEARNING and self._deadline and time() >= self._deadline:
            self._state = self.ACTIVE if self._entropy_ceiling else self.IDLE
            self._deadline = None

    @property
    def state(self) -> str:
        with self._lock:
            self._expire_if_due()
            return self._state

    def status(self) -> dict:
        with self._lock:
            self._expire_if_due()
            return {
                "state": self._state,
                "observed_events": self._observed,
                "learned_extensions": {
                    extension: {
                        "entropy_ceiling": round(ceiling, 2),
                        "directories": sorted(self._directories[extension]),
                    }
                    for extension, ceiling in sorted(self._entropy_ceiling.items())
                },
                "seconds_remaining": (
                    max(0, round(self._deadline - time(), 1)) if self._deadline else None
                ),
            }

    # -------------------------------------------------------------- learning

    def observe(self, file_path: str, entropy: float | None, verdict: dict) -> bool:
        """Fold one event into the baseline. True when it was recorded.

        Events carrying replacement evidence are refused. If an encryptor is
        already running when training starts, the alternative is a baseline that
        has learned the attack as normal - which is the one way this feature
        could do real harm.
        """
        if self.state != self.LEARNING or entropy is None:
            return False
        if verdict.get("ransom_extension") or _rose(verdict):
            return False

        directory, extension = _split(file_path)
        with self._lock:
            self._directories[extension].add(directory)
            current = self._entropy_ceiling.get(extension)
            if current is None or entropy > current:
                self._entropy_ceiling[extension] = entropy
            self._observed += 1
        return True

    # ----------------------------------------------------------- suppression

    def match(self, file_path: str, entropy: float | None, verdict: dict) -> dict | None:
        if self.state != self.ACTIVE or entropy is None:
            return None
        if verdict.get("ransom_extension") or _rose(verdict):
            return None

        directory, extension = _split(file_path)
        with self._lock:
            ceiling = self._entropy_ceiling.get(extension)
            directories = set(self._directories.get(extension, ()))

        if ceiling is None or directory not in directories:
            return None
        if entropy > ceiling:
            return None

        return {
            "rule": "training_mode",
            "value": f"{extension} in {directory} at or below {round(ceiling, 2)} bits/byte",
        }


def _split(file_path: str) -> tuple[str, str]:
    normalised = _normalise(file_path)
    directory = os.path.dirname(normalised)
    extension = os.path.splitext(normalised)[1].lower() or "<none>"
    return directory, extension
