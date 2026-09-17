"""Watch for the commands that destroy the ability to recover.

Real families do this first, and they do it before the encryption rather than
after it, because a victim with shadow copies is a victim who does not pay. The
sequence is well known and barely varies:

    vssadmin delete shadows /all /quiet
    wmic shadowcopy delete
    wbadmin delete catalog -quiet
    bcdedit /set {default} recoveryenabled No
    cipher /w:C

None of these is a detection problem. There is no threshold to tune and no
false-positive rate to trade against: an ordinary desktop does not delete its
own shadow copies, and an administrator who genuinely means to will not mind
being asked. So a match suspends on sight, and the allowlist that could excuse
it is explicit and empty.

The process that runs `vssadmin` is usually a short-lived child of the thing
that matters, so the parent is recorded and suspended too where it can be
attributed. Suspending only the child stops the deletion and leaves the
encryptor running.

**What this does not do.** It sees process *creation*, not process *intent*.
The primary source is a WMI `__InstanceCreationEvent` subscription, which WMI
services by comparing snapshots on an interval, so a process that starts and
exits entirely inside that interval is not reported at all. The interval is set
to 50 ms, which is short relative to the work these commands actually do - a
real `vssadmin delete shadows` spends far longer than that enumerating and
deleting - but it is not zero, and closing it properly needs ETW or a
minifilter. That limitation is in docs/LIMITATIONS.md rather than only here.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class Pattern:
    """One destructive command, as an ordered set of required fragments."""

    name: str
    image: str
    fragments: tuple[str, ...]
    why: str

    def matches(self, image: str | None, command_line: str | None) -> bool:
        """Every fragment present, in order, in the normalised command line.

        Ordered subsequence rather than a single substring, so that argument
        order and the switches between them do not matter:
        `vssadmin delete shadows /all /quiet` and
        `vssadmin  /quiet delete  shadows` both match, and `vssadmin list
        shadows` does not.
        """
        haystack = normalise(command_line)
        if not haystack:
            return False
        # The image has to be right too, and it is checked against the image
        # name or the *executable token* - never against the whole command
        # line. Matching the whole line means
        #     python -c "print('vssadmin delete shadows')"
        # is read as an attempt to delete shadow copies, because every fragment
        # really is in there. Suspending a process for printing a string is
        # exactly the kind of false positive a guard that acts without a
        # threshold cannot afford.
        if (self.image not in normalise(image)
                and self.image not in executable_of(command_line)):
            return False
        cursor = 0
        for fragment in self.fragments:
            found = haystack.find(fragment, cursor)
            if found < 0:
                return False
            cursor = found + len(fragment)
        return True


def normalise(value: str | None) -> str:
    if not value:
        return ""
    return _WHITESPACE.sub(" ", str(value).strip().lower())


def executable_of(command_line: str | None) -> str:
    """The program a command line runs, without its arguments.

    Handles the quoted form. An executable under a path containing a space is
    quoted, so it is one token, and splitting the line on whitespace would
    return only the fragment up to that space and never match an image name.
    """
    text = normalise(command_line)
    if not text:
        return ""
    if text.startswith('"'):
        closing = text.find('"', 1)
        return text[1:closing] if closing > 0 else text[1:]
    return text.split(" ", 1)[0]


#: The five from the brief, plus nothing. Each one names what it protects, so
#: an operator reading an alert knows what was about to be lost.
PATTERNS: tuple[Pattern, ...] = (
    Pattern("vssadmin_delete_shadows", "vssadmin",
            ("delete", "shadows"),
            "deletes Volume Shadow Copies, which is what VSS-backed restore "
            "recovers from"),
    Pattern("wmic_shadowcopy_delete", "wmic",
            ("shadowcopy", "delete"),
            "deletes shadow copies through WMI rather than vssadmin, which "
            "evades a guard that only watches vssadmin"),
    Pattern("wbadmin_delete_catalog", "wbadmin",
            ("delete", "catalog"),
            "destroys the Windows Backup catalogue, so backups that still "
            "exist can no longer be found"),
    Pattern("bcdedit_disable_recovery", "bcdedit",
            ("recoveryenabled", "no"),
            "turns off the Windows Recovery Environment, removing the "
            "offline repair path"),
    Pattern("cipher_wipe_free_space", "cipher",
            ("/w",),
            "overwrites free space, destroying the remnants of files that "
            "undelete tools could otherwise recover"),
)


@dataclass
class Sighting:
    pattern: str
    pid: int | None
    parent_pid: int | None
    image: str | None
    command_line: str | None
    why: str
    at: str = field(default_factory=lambda: datetime.now(timezone.utc)
                    .isoformat().replace("+00:00", "Z"))
    action: str = "pending"
    parent_action: str = "none"

    def as_dict(self) -> dict:
        return {
            "pattern": self.pattern, "process_id": self.pid,
            "parent_process_id": self.parent_pid, "image": self.image,
            "command_line": self.command_line, "why": self.why,
            "at": self.at, "action": self.action,
            "parent_action": self.parent_action,
        }


def classify(image: str | None, command_line: str | None) -> Pattern | None:
    """Which destructive command is this, if any. Pure, and the testable part."""
    for pattern in PATTERNS:
        if pattern.matches(image, command_line):
            return pattern
    return None


class ShadowCopyGuard:
    """Matches process creations against PATTERNS and suspends on sight."""

    def __init__(self, config, responder=None, ledger=None) -> None:
        self.config = config
        self.responder = responder
        self.ledger = ledger
        self.sightings: list[Sighting] = []
        self._lock = threading.Lock()

    def allowlisted(self, image: str | None) -> bool:
        if not image:
            return False
        return image.lower() in {e.lower() for e in self.config.allowlist_images}

    def on_process(self, pid: int | None, image: str | None,
                   command_line: str | None, parent_pid: int | None = None) -> Sighting | None:
        """One process creation. Returns a Sighting when it was one of ours."""
        pattern = classify(image, command_line)
        if pattern is None:
            return None

        sighting = Sighting(
            pattern=pattern.name, pid=pid, parent_pid=parent_pid,
            image=image, command_line=command_line, why=pattern.why,
        )

        if self.allowlisted(image):
            sighting.action = "allowlisted"
            logger.warning("%s from an allowlisted image (%s); not suspending",
                           pattern.name, image)
        elif self.responder is None or pid is None:
            sighting.action = "logged_only"
        else:
            sighting.action = self._suspend(pid, f"{pattern.name}: {pattern.why}")
            # The thing that ran vssadmin is what matters. Suspending only the
            # child stops this deletion and leaves the encryptor running.
            if parent_pid:
                sighting.parent_action = self._suspend(
                    parent_pid,
                    f"parent of {pattern.name}; the command is a symptom and "
                    f"this is what issued it")

        with self._lock:
            self.sightings.append(sighting)
        logger.warning("shadow-copy guard: %s pid=%s parent=%s action=%s cmd=%r",
                       pattern.name, pid, parent_pid, sighting.action,
                       (command_line or "")[:160])
        if self.ledger is not None:
            self.ledger.try_log_event("recovery_destruction_attempt", sighting.as_dict())
        return sighting

    def _suspend(self, pid: int, reason: str) -> str:
        import psutil

        try:
            self.responder.guard_pid(int(pid))
        except Exception as exc:  # noqa: BLE001 - the guard's own refusals
            return f"refused: {exc}"
        try:
            psutil.Process(int(pid)).suspend()
        except psutil.NoSuchProcess:
            return "gone"
        except psutil.AccessDenied as exc:
            return f"access_denied: {exc}"
        self.responder.note_suspended(int(pid), reason)
        return "suspended"

    def recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return [s.as_dict() for s in self.sightings[-limit:]]


# ------------------------------------------------------------------ sources

class ProcessSource:
    """Where process creations come from. Subclasses fill in `start`."""

    name = "none"

    def __init__(self, guard: ShadowCopyGuard) -> None:
        self.guard = guard
        self.available = False
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        return False

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def status(self) -> dict:
        return {"source": self.name, "available": self.available,
                "error": self.error}


class WmiProcessSource(ProcessSource):
    """WMI `__InstanceCreationEvent`, which carries the command line."""

    name = "wmi-instance-creation"
    #: WMI services this by comparing snapshots on this interval, in seconds.
    #: A process that starts and exits entirely within it is never reported.
    POLL_WITHIN = 0.05

    def start(self) -> bool:
        try:
            import pythoncom  # noqa: F401
            import win32com.client  # noqa: F401
        except ImportError as exc:
            self.error = f"pywin32 is not available: {exc}"
            return False
        self._thread = threading.Thread(target=self._run, name="urds-procmon",
                                        daemon=True)
        self._thread.start()
        # Give the subscription a moment to fail loudly if it is going to.
        time.sleep(0.5)
        return self.available

    def _run(self) -> None:
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        try:
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent "
                f"WITHIN {self.POLL_WITHIN} "
                "WHERE TargetInstance ISA 'Win32_Process'")
            self.available = True
            logger.info("shadow-copy guard: subscribed to Win32_Process creation")
        except Exception as exc:  # noqa: BLE001
            self.error = f"could not subscribe to process creation: {exc}"
            logger.warning("shadow-copy guard unavailable: %s", self.error)
            pythoncom.CoUninitialize()
            return

        while not self._stop.is_set():
            try:
                event = watcher.NextEvent(500)
            except Exception:  # noqa: BLE001 - a timeout is the common case
                continue
            try:
                target = event.TargetInstance
                self.guard.on_process(
                    pid=int(target.ProcessId) if target.ProcessId else None,
                    image=str(target.Name or ""),
                    command_line=str(target.CommandLine or ""),
                    parent_pid=int(target.ParentProcessId) if target.ParentProcessId else None,
                )
            except Exception:  # noqa: BLE001 - one bad event must not stop the guard
                logger.exception("shadow-copy guard failed on an event")
        pythoncom.CoUninitialize()


class NullProcessSource(ProcessSource):
    """No process-creation source. The guard sees nothing and says so."""

    name = "none"

    def __init__(self, guard: ShadowCopyGuard, reason: str) -> None:
        super().__init__(guard)
        self.error = reason

    def start(self) -> bool:
        logger.warning("shadow-copy guard is not running: %s", self.error)
        return False


def build_source(guard: ShadowCopyGuard) -> ProcessSource:
    """The best source this host can provide, chosen by capability."""
    import platform

    if platform.system() != "Windows":
        return NullProcessSource(
            guard, "process-creation watching is implemented for Windows only")
    source = WmiProcessSource(guard)
    if source.start():
        return source
    return NullProcessSource(
        guard, source.error or "WMI process-creation subscription failed")
