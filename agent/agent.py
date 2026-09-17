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
from agent import imports, transport
from agent.ledger import DirectLedger
from agent.responder import Responder

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
        self.responder = Responder(self.config, self.ledger)
        self.transport = transport.InProcessTransport(self.ledger, self.responder)

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

        if not event.get("suspicious"):
            return event

        outcome = self.responder.respond(event)
        with self._lock:
            self.responses += 1
        event["response"] = outcome.as_event()

        logger.warning("%s: %s -> %s (%s)", path, event.get("verdict"),
                       outcome.action, outcome.reason)
        return event

    # -- reporting ---------------------------------------------------------

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
            "suspended": dict(self.responder.suspended),
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
