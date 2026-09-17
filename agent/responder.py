"""What the agent does about a process, and the order it does it in.

    suspend  ->  snapshot  ->  gather evidence  ->  kill, or resume

Suspend before you kill. A wrongly suspended build resumes in 200 ms; a wrongly
killed one does not. `psutil.Process(pid).suspend()` stops the process
scheduling immediately, which stops the encryption immediately, and it leaves
every option open - including doing nothing, which is the right answer more
often than a detector likes to admit.

Three gates stand in front of a suspension and none is advisory:

* **The path is inside a protected root.** The blast radius is the config file.
* **Attribution is CERTAIN.** `PROBABLE` and `UNKNOWN` record what was seen and
  touch nothing. A guessed PID in a hash chain is the defect
  docs/CORRECTIONS.md is about; a guessed PID passed to `suspend()` is worse,
  because it is a guess with an effect.
* **`guard()` in services/response/actions.py agrees**, which refuses this
  process, its ancestors, and anything whose executable lives under
  `%SystemRoot%`, `/usr/sbin`, `/sbin` or `/usr/lib/systemd`.

A **kill** needs more than a suspension does: two independent corroborating
signals, from `agent.velocity`, `agent.canary` and `agent.procmon`. The per-file
entropy verdict deliberately does not count toward that two. It is the entry
condition - it is what produced the suspension - and a signal cannot corroborate
itself. Without two, the process is **resumed** and the near-miss is logged with
everything that caused it, because a near-miss nobody can read is how thresholds
get quietly loosened later.

The slow half of the ladder runs on its own thread. Suspension is milliseconds
and belongs on the detection path; a VSS snapshot is seconds and does not, and
holding the watchdog thread for it would stall every other event on the host.
It is safe to take slowly precisely because the target is frozen while it runs.
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

#: Independent signals required before a suspension escalates to a kill.
#: Two, and the entry verdict is not one of them.
KILL_REQUIRES = 2

#: At least one of the two must come from this set, and that is not a tuning
#: knob - it is the difference between a detector and a nuisance.
#:
#: `path_velocity` and `directory_fanout` say a process is writing quickly and
#: broadly. So does `git clone`, so does a compiler, so does an installer, and
#: so does a backup. A measured run of `git clone` into a protected folder
#: produced hundreds of `suspected_encryption` verdicts - git objects are
#: zlib-compressed and therefore high-entropy - and fired both behavioural
#: signals at once. Under a rule of "any two signals" that clone would have
#: been killed, and the only reason the run did not show it is that the agent
#: had fallen far enough behind on the backlog that attribution had already
#: gone stale. A false positive that survives on a race is not a passing test.
#:
#: What actually distinguishes encryption is not speed. It is destroying
#: content that was known to be good (`entropy_delta`, measured against the
#: ledger's own baseline), touching something that nothing has any reason to
#: touch (`canary`), or destroying the means of recovery
#: (`recovery_destruction`). Velocity corroborates those. It does not replace
#: them.
DISCRIMINATING_SIGNALS = frozenset({
    "canary", "entropy_delta", "recovery_destruction",
})

#: How long the escalation waits for a snapshot before deciding without one.
#: A snapshot that has not returned in this long is not going to change the
#: decision, and the target stays frozen either way.
SNAPSHOT_TIMEOUT_S = 45.0


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
    """The ladder, plus the record of everything it decided."""

    def __init__(self, config, ledger=None, velocity=None, canaries=None,
                 vss=None, escalate: bool = True) -> None:
        self.config = config
        self.ledger = ledger
        self.velocity = velocity
        self.canaries = canaries
        self.vss = vss
        #: Off in tests that only exercise the gates, so no background thread
        #: outlives the assertion it was started by.
        self.escalate_enabled = escalate

        self._lock = threading.Lock()
        self.outcomes: dict[str, Outcome] = {}
        self.suspended: dict[int, str] = {}
        self.near_misses: list[dict] = []
        self.escalations: list[dict] = []
        self._escalating: set[int] = set()

    # -- shared with the shadow-copy guard ---------------------------------

    def guard_pid(self, pid: int) -> None:
        """The Response service's own refusals, raised for the caller."""
        guard(int(pid))

    def note_suspended(self, pid: int, why: str) -> None:
        """Record a suspension taken by something other than `respond`."""
        with self._lock:
            self.suspended[int(pid)] = why

    def is_suspended(self, pid: int) -> bool:
        with self._lock:
            return int(pid) in self.suspended

    # -- the fast half -----------------------------------------------------

    def respond(self, event: dict) -> Outcome:
        """Act on one suspicious event. Returns as soon as the target is frozen."""
        started = perf_counter()
        incident = event.get("incident_id") or f"inc_{event.get('event_id', 'unknown')}"
        pid = event.get("process_id")
        confidence = event.get("attribution_confidence", "unknown")
        image = event.get("process_image")
        path = event.get("file_path") or ""
        canary_hit = bool(event.get("canary_hit"))

        def finish(action: str, reason: str, suspended: bool = False,
                   **evidence) -> Outcome:
            outcome = Outcome(
                incident_id=incident,
                action=action,
                process_id=pid,
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
                f"PID was guessed."
                + (" A canary was touched, and it still did not authorise "
                   "acting: the tripwire says something walked the directory, "
                   "not which process did." if canary_hit else ""),
                canary_hit=canary_hit,
            )

        try:
            guard(int(pid))
        except Exception as exc:  # the service's own refusals, re-reported
            return finish("refused", f"the response guard refused pid {pid}: {exc}")

        try:
            process = psutil.Process(int(pid))
            image = image or process.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return finish("gone", f"pid {pid} could not be opened: {exc}")

        # Suspend once, and only once. NtSuspendProcess nests on Windows, so a
        # process suspended six times for six files needs six resumes, and the
        # single resume on the near-miss path would leave it frozen for good.
        # The cheap half of "suspend before you kill" stops being cheap the
        # moment it cannot be undone.
        with self._lock:
            already = int(pid) in self.suspended
        if already:
            self._schedule_escalation(int(pid), incident, image, event)
            return finish(
                "already_suspended",
                f"pid {pid} was already suspended by this agent; not suspending "
                f"again, because suspend counts nest on Windows and this one "
                f"has to remain reversible",
                suspended=True, image=image,
            )

        try:
            process.suspend()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return finish("suspend_failed", f"pid {pid} could not be suspended: {exc}")

        with self._lock:
            self.suspended[int(pid)] = image or ""

        logger.warning("suspended pid %s (%s) for %s%s", pid, image, path,
                       " [canary]" if canary_hit else "")
        outcome = finish(
            "suspended",
            f"pid {pid} suspended on a certain attribution for {path}"
            + (" after touching a canary" if canary_hit else ""),
            suspended=True, image=image, canary_hit=canary_hit,
        )
        self._schedule_escalation(int(pid), incident, image, event)
        return outcome

    # -- the slow half -----------------------------------------------------

    def _schedule_escalation(self, pid: int, incident: str, image: str | None,
                             event: dict) -> None:
        if not self.escalate_enabled:
            return
        with self._lock:
            if pid in self._escalating:
                return
            self._escalating.add(pid)
        threading.Thread(
            target=self._escalate, args=(pid, incident, image, event),
            name=f"urds-escalate-{pid}", daemon=True).start()

    def _escalate(self, pid: int, incident: str, image: str | None,
                  event: dict) -> dict:
        """Snapshot, gather evidence, then kill or resume. Target is frozen."""
        record: dict[str, Any] = {
            "incident_id": incident, "process_id": pid, "process_image": image,
            "started_at": utc_now(),
        }
        try:
            record["snapshot"] = self._snapshot()
            record["evidence"] = evidence = self._evidence(pid, image, event)
            corroborating = list(evidence["corroborating_signals"])
            discriminating = sorted(set(corroborating) & DISCRIMINATING_SIGNALS)
            record["corroborating_signals"] = corroborating
            record["discriminating_signals"] = discriminating
            record["kill_requires"] = KILL_REQUIRES
            record["kill_requires_discriminating"] = sorted(DISCRIMINATING_SIGNALS)

            enough = len(corroborating) >= KILL_REQUIRES
            if enough and discriminating:
                record["decision"] = "kill"
                record["result"] = self.kill(
                    pid, f"{len(corroborating)} independent signals agreed "
                         f"({', '.join(corroborating)}), including "
                         f"{', '.join(discriminating)}")
            elif enough:
                record["decision"] = "resume"
                record["result"] = self.resume(
                    pid,
                    f"near miss: {len(corroborating)} signals "
                    f"({', '.join(corroborating)}) but none of them "
                    f"discriminating. Writing quickly and broadly is what a "
                    f"clone, a compiler and an installer also do; a kill needs "
                    f"evidence that known-good content was destroyed, that a "
                    f"decoy was touched, or that recovery was attacked.")
                with self._lock:
                    self.near_misses.append(record)
                    if len(self.near_misses) > 500:
                        del self.near_misses[:250]
            else:
                record["decision"] = "resume"
                record["result"] = self.resume(
                    pid,
                    f"near miss: only {len(corroborating)} independent signal(s) "
                    f"({', '.join(corroborating) or 'none'}) and a kill needs "
                    f"{KILL_REQUIRES}. The entropy verdict that caused the "
                    f"suspension is not counted, because a signal cannot "
                    f"corroborate itself.")
                with self._lock:
                    self.near_misses.append(record)
                    if len(self.near_misses) > 500:
                        del self.near_misses[:250]
        except Exception as exc:  # noqa: BLE001
            # An escalation that raises must not leave a process frozen with
            # nobody coming back for it.
            logger.exception("escalation failed for pid %s", pid)
            record["decision"] = "resume_on_error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            record["result"] = self.resume(pid, f"escalation failed: {exc}")
        finally:
            with self._lock:
                self._escalating.discard(pid)
            record["finished_at"] = utc_now()
            with self._lock:
                self.escalations.append(record)
                if len(self.escalations) > 500:
                    del self.escalations[:250]
            if self.ledger is not None:
                self.ledger.try_log_event("response_escalation", record)
            logger.warning("escalation for pid %s: %s (%s)", pid,
                           record.get("decision"),
                           ", ".join(record.get("corroborating_signals") or []) or "no corroboration")
        return record

    def _snapshot(self) -> dict:
        """A shadow copy taken while the suspect is frozen."""
        if self.vss is None:
            return {"taken": False, "reason": "no VSS manager configured"}
        started = perf_counter()
        try:
            volume = str(self.config.protected_paths[0].anchor or "C:\\")
            shadow_id = self.vss.create_snapshot(volume)
        except Exception as exc:  # noqa: BLE001 - every VSS failure is reported
            return {"taken": False, "reason": f"{type(exc).__name__}: {exc}",
                    "elapsed_s": round(perf_counter() - started, 3)}
        return {"taken": True, "snapshot_id": shadow_id,
                "elapsed_s": round(perf_counter() - started, 3)}

    def _evidence(self, pid: int, image: str | None, event: dict) -> dict:
        """Everything known about this process, and which signals corroborate.

        The per-file verdict that produced the suspension is recorded and is
        deliberately absent from `corroborating_signals`.
        """
        found: list[str] = []
        evidence: dict[str, Any] = {
            "image_path": image,
            "entry_verdict": event.get("verdict"),
            "entry_signal": event.get("signal"),
            "entry_entropy": event.get("entropy"),
            "note_on_the_entry_verdict":
                "not counted as corroboration: it is what caused the "
                "suspension, and a signal cannot corroborate itself",
        }

        try:
            process = psutil.Process(pid)
            with process.oneshot():
                evidence["cmdline"] = " ".join(process.cmdline() or [])[:400]
                evidence["username"] = process.username()
                parent = process.parent()
                evidence["parent_pid"] = parent.pid if parent else None
                evidence["parent_image"] = parent.exe() if parent else None
        except (psutil.Error, OSError) as exc:
            evidence["process_detail_error"] = str(exc)

        if self.velocity is not None:
            signals = self.velocity.signals(pid)
            evidence["velocity"] = signals.as_dict()
            found.extend(signals.fired)

        if self.canaries is not None:
            hits = self.canaries.hits(pid)
            evidence["canary_hits"] = hits
            if hits:
                found.append("canary")

        shadow = event.get("shadow_copy_attempt")
        if shadow:
            evidence["shadow_copy_attempt"] = shadow
            found.append("recovery_destruction")

        evidence["corroborating_signals"] = sorted(set(found))
        return evidence

    # -- the two ways a suspension ends ------------------------------------

    def resume(self, pid: int, why: str) -> dict:
        """Undo a suspension. The cheap half of the asymmetry.

        Loops, because Windows suspend counts nest and a process suspended by
        something other than this agent may need more than one.
        """
        attempts = 0
        try:
            process = psutil.Process(int(pid))
            for attempts in range(1, 11):
                process.resume()
                if process.status() != psutil.STATUS_STOPPED:
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            with self._lock:
                self.suspended.pop(int(pid), None)
            return {"resumed": False, "process_id": pid, "error": str(exc), "why": why}
        with self._lock:
            self.suspended.pop(int(pid), None)
        logger.info("resumed pid %s after %d call(s): %s", pid, attempts, why)
        return {"resumed": True, "process_id": pid, "resume_calls": attempts,
                "why": why}

    def kill(self, pid: int, why: str) -> dict:
        """Terminate, through the Response service's own guarded path."""
        try:
            result = terminate_process(int(pid), force=True)
        except TerminationError as exc:
            return {"terminated": False, "process_id": pid, "error": str(exc),
                    "why": why}
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

    def summary(self) -> dict:
        with self._lock:
            return {
                "suspended_now": dict(self.suspended),
                "escalations": len(self.escalations),
                "near_misses": len(self.near_misses),
                "kill_requires": KILL_REQUIRES,
            }
