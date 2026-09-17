"""The protection path, assembled and running in one process on the host.

    watchdog event
      -> app.handle_event      the Monitor's measured detector, unchanged
      -> Responder.respond     synchronous, in-process, on host PIDs
      -> pipeline fan-out      background thread, transport swapped to SQLite

The response is taken **synchronously on the detection path**, before the
fan-out is queued. The pipeline's worker is a background thread and a
suspension that waits behind a queue is not a response inside 100 ms. By the
time the fan-out writes its record, the decision has already been made and the
record reports it rather than requesting a second action.

Nothing here reimplements detection. `app.handle_event` is the function the
thesis measures latency over, and it already runs entropy history, container
validation, admissibility, suppression and attribution in the right order.
"""

from __future__ import annotations

import logging
import os
import platform
import threading
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler

from agent import config as agent_config
from agent import imports, procmon, transport
from agent.canary import CanaryField
from agent.ledger import DirectLedger
from agent.responder import Responder
from agent.velocity import VelocityTracker

logger = logging.getLogger("urds-agent")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _Handler(FileSystemEventHandler):
    """Mirrors `app.MonitorHandler`, with the response hop added after it."""

    def __init__(self, agent: "Agent") -> None:
        self.agent = agent

    def on_created(self, event):
        if not event.is_directory:
            self.agent.on_file_event(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.agent.on_file_event(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            self.agent.on_file_event(event.dest_path, "renamed")

    def on_deleted(self, event):
        if not event.is_directory:
            self.agent.on_file_event(event.src_path, "deleted")


class Agent:
    """Everything the service runs, with a start/stop the service can drive."""

    def __init__(self, config=None) -> None:
        self.config = config or agent_config.load()
        self.monitor_app = imports.load("app")
        self.pipeline = imports.load("pipeline")
        self.attribution = imports.load("attribution")

        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.snapshot_root.mkdir(parents=True, exist_ok=True)

        self.ledger = DirectLedger(self.config.ledger_db)
        self.velocity = VelocityTracker(
            window_s=self.config.velocity_window_s,
            path_threshold=self.config.velocity_path_threshold,
            fanout_threshold=self.config.velocity_fanout_threshold,
        )
        self.canaries = CanaryField(self.config)
        self.vss = self._build_vss()
        self.responder = Responder(
            self.config, ledger=self.ledger, velocity=self.velocity,
            canaries=self.canaries, vss=self.vss)
        self.guard = procmon.ShadowCopyGuard(
            self.config, responder=self.responder, ledger=self.ledger)
        self.process_source: procmon.ProcessSource | None = None
        self.transport = transport.InProcessTransport(self.ledger, self.responder)

        #: path -> the entropy the ledger holds for it while it was known-good.
        #: Cached because the alternative is a SQLite read on the hot path for
        #: every filesystem event on the machine.
        self._baseline_entropy: dict[str, float | None] = {}

        self._original_post = None
        self._observers: list = []
        self._lock = threading.Lock()
        self._running = False
        self.events_seen = 0
        self.responses = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> dict:
        if self._running:
            return self.status()

        self._original_post = transport.install(self.pipeline, self.transport)

        # The fan-out stays enabled so that the Monitor's own rules about what
        # reaches the ledger keep running. What changed is where the writes go.
        self.monitor_app.PIPELINE_ENABLED = True
        self.monitor_app._ensure_worker()

        attribution_started = self._start_attribution()

        # Seeded before the observers start, so the agent's own twenty writes
        # do not arrive as twenty filesystem events to judge.
        self.canaries.load()
        canaries = self.canaries.seed()

        self.process_source = procmon.build_source(self.guard)
        self.process_source.start()
        guard_status = self.process_source.status()
        if not self.process_source.available:
            logger.warning(
                "shadow-copy guard is not watching process creation (%s). "
                "vssadmin delete shadows and its relatives will not be seen.",
                guard_status.get("error"))

        watched = []
        for root in self.config.protected_paths:
            root.mkdir(parents=True, exist_ok=True)
            observer, backend, why = self.monitor_app.build_observer(str(root))
            observer.schedule(_Handler(self), str(root), recursive=True)
            observer.start()
            self._observers.append(observer)
            watched.append({"path": str(root), "backend": backend, "why": why})
            logger.info("watching %s (%s: %s)", root, backend, why)

        self._running = True
        started = {
            "agent": "urds-agent",
            "host": platform.node(),
            "platform": f"{platform.system()} {platform.version()}",
            "elevated": is_elevated(),
            "pid": os.getpid(),
            "watching": watched,
            "attribution": attribution_started,
            "canaries": {"seeded": len(canaries["created"]),
                         "already_present": len(canaries["existing"]),
                         "total": canaries["total"]},
            "shadow_copy_guard": guard_status,
            "ledger_db": str(self.config.ledger_db),
            "config_source": str(self.config.source) if self.config.source else None,
            "timestamp": utc_now(),
        }
        self.ledger.try_log_event("agent_started", started)
        return started

    def stop(self) -> dict:
        if not self._running:
            return {"stopped": False, "reason": "not running"}

        for observer in self._observers:
            try:
                observer.stop()
            except Exception:  # noqa: BLE001
                logger.exception("observer failed to stop")
        for observer in self._observers:
            try:
                observer.join(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        self._observers.clear()

        if self.process_source is not None:
            try:
                self.process_source.stop()
            except Exception:  # noqa: BLE001
                logger.exception("process source failed to stop")
            self.process_source = None

        # Nothing stays frozen because the agent stopped. A suspended process
        # whose supervisor has exited is a process nobody will ever resume.
        resumed = self.responder.resume_all("urds-agent stopping")

        if self._original_post is not None:
            transport.restore(self.pipeline, self._original_post)
            self._original_post = None

        record = {
            "events_seen": self.events_seen,
            "responses": self.responses,
            "resumed_on_shutdown": resumed,
            "timestamp": utc_now(),
        }
        self.ledger.try_log_event("agent_stopped", record)
        self.ledger.close()
        self._running = False
        return {"stopped": True, **record}

    # -- the hot path ------------------------------------------------------

    def on_file_event(self, path: str, kind: str) -> dict | None:
        """One filesystem event, from detection through to the response."""
        try:
            event = self.monitor_app.handle_event(path, kind)
        except Exception:  # noqa: BLE001 - one bad file must not stop the agent
            logger.exception("detection failed for %s", path)
            return None
        if event is None:
            return None

        with self._lock:
            self.events_seen += 1

        canary_hit = self._check_canary(event, path, kind)

        # Velocity is fed by every write, not only suspicious ones. An
        # encryptor's first few files may each look individually unremarkable;
        # what makes them evidence is that one process produced all of them.
        self.velocity.record(
            event.get("process_id"), path,
            entropy=event.get("entropy"),
            baseline_entropy=self._baseline_for(path),
        )

        if not event.get("suspicious") and not canary_hit:
            return event

        outcome = self.responder.respond(event)
        with self._lock:
            self.responses += 1
        event["response"] = outcome.as_event()

        logger.warning("%s: %s -> %s (%s)", path, event.get("verdict"),
                       outcome.action, outcome.reason)
        return event

    def _check_canary(self, event: dict, path: str, kind: str) -> bool:
        """Did this touch a decoy, and if so, who did it?

        Attribution normally runs only for an event the detector already found
        suspicious, which is the right economy for ordinary files. It is the
        wrong one here: a canary rewritten with low-entropy junk produces no
        entropy verdict at all, so without asking explicitly the tripwire would
        fire with no PID attached and nothing could be done about it. The whole
        value of a canary is that it needs no threshold, and that is worth one
        attribution lookup on the rare event that touches one.
        """
        if kind == "deleted" or not self.canaries.is_canary(path):
            return False

        if event.get("attribution_confidence") != self.attribution.CERTAIN:
            try:
                event.update(
                    self.monitor_app.attributor.resolve(path).as_event_fields())
            except Exception:  # noqa: BLE001
                logger.exception("canary attribution failed for %s", path)

        hit = self.canaries.touched(path, event.get("process_id"),
                                    event.get("process_image"))
        if hit is None:
            return False
        event["canary_hit"] = True
        event["canary_detail"] = hit.as_dict()
        return True

    def _baseline_for(self, path: str) -> float | None:
        """The entropy the ledger recorded for this path while it was good.

        This is the signal the per-file design throws away, and it is free: the
        `file_baseline` events the pipeline already writes carry `entropy`. A
        file that read 4.2 bits/byte when first seen and reads 7.99 now has not
        become a better compressed archive.

        Cached, including misses, because the alternative is a SQLite query on
        the hot path for every filesystem event on the machine.
        """
        key = path.lower()
        if key in self._baseline_entropy:
            return self._baseline_entropy[key]

        value = None
        try:
            found = self.ledger.chain.get_blocks(
                file_path=path, newest_first=True, limit=20)
            for block in found.get("blocks", []):
                if block.get("event_type") != "file_baseline":
                    continue
                candidate = (block.get("event_data") or {}).get("entropy")
                if isinstance(candidate, (int, float)):
                    value = float(candidate)
                    break
        except Exception:  # noqa: BLE001 - a missing baseline is not an error
            value = None

        if len(self._baseline_entropy) > 10000:
            self._baseline_entropy.clear()
        self._baseline_entropy[key] = value
        return value

    # -- reporting ---------------------------------------------------------

    def _build_vss(self):
        """A VSS manager pointed at this agent's ledger, or None where VSS is not.

        Constructed with the direct ledger so that `snapshot_created` events -
        which recovery later accepts as an integrity reference - land in the
        same chain as everything else rather than being posted over HTTP to a
        service that may not be running.
        """
        try:
            vss_module = imports.load("recovery.vss_manager")
            manager = vss_module.VSSManager(
                ledger_client=self.ledger,
                default_volume=str(self.config.protected_paths[0].anchor or "C:\\"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("VSS unavailable, snapshots will not be taken: %s", exc)
            return None
        status = manager.platform_status()
        if not status.get("supported"):
            logger.warning("VSS reports unsupported on this host: %s", status)
        return manager

    def _start_attribution(self) -> dict:
        attributor = self.monitor_app.attributor
        if not attributor.available:
            attributor.start(self.attribution.build_source(attributor.log))
        status = attributor.status()
        if attributor.available:
            logger.info("attribution active via %s", attributor.source.name)
        else:
            logger.warning(
                "attribution unavailable (%s). Nothing will be suspended: "
                "without a kernel-grade source no attribution reaches CERTAIN, "
                "and the agent does not guess a PID.",
                attributor.source.error)
        return status

    def status(self) -> dict:
        attributor = self.monitor_app.attributor
        return {
            "running": self._running,
            "pid": os.getpid(),
            "elevated": is_elevated(),
            "watching": [str(p) for p in self.config.protected_paths],
            "observers_alive": [o.is_alive() for o in self._observers],
            "events_seen": self.events_seen,
            "responses": self.responses,
            "responder": self.responder.summary(),
            "canaries": len(self.canaries.paths()),
            "canary_hits": self.canaries.hit_count(),
            "shadow_copy_guard": (self.process_source.status()
                                  if self.process_source else
                                  {"source": "none", "available": False,
                                   "error": "agent is not running"}),
            "recovery_destruction_attempts": self.guard.recent(10),
            "velocity_tracked_pids": len(self.velocity.tracked_pids()),
            "attribution": attributor.status(),
            "ledger_blocks": self.ledger.block_count(),
            "ledger_db": str(self.config.ledger_db),
            "timestamp": utc_now(),
        }


def is_elevated() -> bool:
    """Administrator on Windows, root elsewhere. Reported, never assumed."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
