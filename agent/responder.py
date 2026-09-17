"""What the agent does about a process, and the order it does it in.

Suspend before you kill. A wrongly suspended build resumes in 200 ms; a wrongly
killed one does not. `psutil.Process(pid).suspend()` stops the process
scheduling immediately, which stops the encryption immediately, and it leaves
every recovery option open - including doing nothing, which is the right answer
more often than a detector likes to admit.

Two gates stand in front of every action, and neither is advisory:

* **The path must be inside a protected root.** The blast radius is the
  configuration file; see `agent.config`.
* **Only `CERTAIN` attribution authorises acting on a PID.** `PROBABLE` and
  `UNKNOWN` record what was seen and touch nothing. A guessed PID written into
  a hash chain is the defect docs/CORRECTIONS.md exists about, and a guessed
  PID passed to `suspend()` is worse, because it is a guess with an effect.

`guard()` and `_guard_image_path()` in `services/response/actions.py` are the
third gate and are reused rather than reimplemented: they refuse this process,
its ancestors, and anything whose executable lives under `%SystemRoot%`,
`/usr/sbin`, `/sbin` or `/usr/lib/systemd`.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

import psutil

from agent import imports

_actions = imports.load("actions")
_attribution = imports.load("attribution")

CERTAIN = _attribution.CERTAIN
KILL_AUTHORISING = _attribution.KILL_AUTHORISING
guard = _actions.guard
terminate_process = _actions.terminate_process
TerminationError = _actions.TerminationError

logger = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Outcome:
    """What the agent did about one incident, and why."""

    incident_id: str
    action: str
    process_id: int | None = None
    process_image: str | None = None
    attribution_confidence: str = "unknown"
    attribution_reason: str | None = None
    reason: str = ""
    suspended: bool = False
    elapsed_ms: float = 0.0
    evidence: dict = field(default_factory=dict)
    at: str = field(default_factory=utc_now)

    def as_event(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "action": self.action,
            "process_id": self.process_id,
            "process_image": self.process_image,
            "attribution_confidence": self.attribution_confidence,
            "attribution_reason": self.attribution_reason,
            "outcome": self.reason,
            "suspended": self.suspended,
            "response_time_ms": round(self.elapsed_ms, 3),
            "evidence": self.evidence,
            "timestamp": self.at,
        }


class Responder:
    """Suspend-first response, gated on attribution and on the protected paths."""

    def __init__(self, config, ledger=None) -> None:
        self.config = config
        self.ledger = ledger
        self._lock = threading.Lock()
        #: incident_id -> Outcome, so the pipeline's own ledger record reports
        #: the action that actually happened rather than asking for a second.
        self.outcomes: dict[str, Outcome] = {}
        self.suspended: dict[int, str] = {}

    # -- the decision ------------------------------------------------------

    def respond(self, event: dict) -> Outcome:
        """Act on one suspicious event. Returns what was done and why."""
        started = perf_counter()
        incident = event.get("incident_id") or f"inc_{event.get('event_id', 'unknown')}"
        pid = event.get("process_id")
        confidence = event.get("attribution_confidence", "unknown")
        image = event.get("process_image")
        path = event.get("file_path") or ""

        def finish(action: str, reason: str, suspended: bool = False, **evidence) -> Outcome:
            outcome = Outcome(
                incident_id=incident,
                action=action,
                process_id=pid if suspended or action == "terminated" else (pid if pid else None),
                process_image=image,
                attribution_confidence=confidence,
                attribution_reason=event.get("attribution_reason"),
                reason=reason,
                suspended=suspended,
                elapsed_ms=(perf_counter() - started) * 1000,
                evidence=dict(evidence),
            )
            with self._lock:
                self.outcomes[incident] = outcome
            return outcome

        if not self.config.protects(path):
            return finish(
                "ignored",
                f"{path} is not inside a protected root; the agent does not act "
                f"outside its configured blast radius",
                protected_roots=[str(p) for p in self.config.protected_paths],
            )

        if confidence not in KILL_AUTHORISING or not pid:
            return finish(
                "isolate_and_log",
                f"attribution resolved to {confidence!r}, which does not "
                f"authorise acting on a process. Nothing was suspended and no "
                f"PID was guessed.",
            )

        try:
            guard(int(pid))
        except Exception as exc:  # the service's own refusals, re-reported
            return finish(
                "refused",
                f"the response guard refused pid {pid}: {exc}",
            )

        try:
            process = psutil.Process(int(pid))
            image = image or process.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return finish("gone", f"pid {pid} could not be opened: {exc}")

        # Suspend once, and only once.
        #
        # An encryptor writes many files, so one process produces many events,
        # and the first run of this code suspended the same PID six times for
        # six files. On Windows that is not idempotent: NtSuspendProcess
        # increments a suspend count, so a process suspended six times needs
        # six resumes, and the single resume on the near-miss path or at
        # shutdown would have left it frozen for good. The cheap half of
        # "suspend before you kill" stops being cheap the moment it cannot be
        # undone.
        with self._lock:
            already = int(pid) in self.suspended
        if already:
            return finish(
                "already_suspended",
                f"pid {pid} was already suspended by this agent; not suspending "
                f"again, because suspend counts nest on Windows and this one "
                f"has to remain reversible",
                suspended=True,
                image=image,
            )

        try:
            process.suspend()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return finish("suspend_failed", f"pid {pid} could not be suspended: {exc}")

        with self._lock:
            self.suspended[int(pid)] = image or ""

        logger.warning("suspended pid %s (%s) for %s", pid, image, path)
        return finish(
            "suspended",
            f"pid {pid} suspended on a certain attribution for {path}",
            suspended=True,
            image=image,
        )

    # -- the two ways a suspension ends ------------------------------------

    def resume(self, pid: int, why: str) -> dict:
        """Undo a suspension. The cheap half of the asymmetry."""
        try:
            psutil.Process(int(pid)).resume()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return {"resumed": False, "process_id": pid, "error": str(exc), "why": why}
        with self._lock:
            self.suspended.pop(int(pid), None)
        logger.info("resumed pid %s: %s", pid, why)
        return {"resumed": True, "process_id": pid, "why": why}

    def kill(self, pid: int, why: str) -> dict:
        """Terminate, through the Response service's own guarded path."""
        try:
            result = terminate_process(int(pid), force=True)
        except TerminationError as exc:
            return {"terminated": False, "process_id": pid, "error": str(exc), "why": why}
        with self._lock:
            self.suspended.pop(int(pid), None)
        logger.warning("terminated pid %s: %s", pid, why)
        return {**result, "terminated": True, "why": why}

    def resume_all(self, why: str = "agent shutting down") -> list[dict]:
        """Nothing stays frozen because the agent stopped."""
        with self._lock:
            pids = list(self.suspended)
        return [self.resume(pid, why) for pid in pids]

    # -- what the pipeline's ledger record should say ----------------------

    def recorded(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            outcome = self.outcomes.get(incident_id)
        return outcome.as_event() if outcome else None
