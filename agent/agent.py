"""The protection path, assembled and running in one process on the host.

    watchdog event
      -> Dispatcher.submit     append and return, on the watchdog's thread
      -> app.handle_event      the Monitor's measured detector, unchanged
      -> who wrote it?         asked once, never waited for
           named    -> Responder.respond, on the lane
           not yet  -> PendingAttribution, re-asked every 25 ms
      -> pipeline fan-out      background thread, transport swapped to SQLite

The response is taken **on the detection path**, before the fan-out is queued.
The pipeline's worker is a background thread and a suspension that waits behind
a queue is not a response. By the time the fan-out writes its record, the
decision has already been made and the record reports it rather than requesting
a second action.

Two modules carry the Phase 3 fix and the measurements behind it.
`agent/dispatch.py` took the work off the watchdog's single thread;
`agent/pending.py` took the *waiting* out of the work, after measuring that the
Security channel delivers its audit records on a one-second flush timer - so a
blocking grace catches a minority of them at any write rate and none at all
under a burst. Nothing on this path waits for attribution. It asks, and asks
again when the answer has had time to arrive.

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
from agent import dispatch, imports, pending, procmon, transport
from agent.canary import CanaryField
from agent.ledger import DirectLedger
from agent.responder import Responder
from agent.velocity import VelocityTracker

logger = logging.getLogger("urds-agent")

#: Paths the baseline cache will hold before it is emptied. Also the cap on
#: the single query that fills it at startup.
MAX_BASELINES = int(os.getenv("URDS_MAX_BASELINES", "20000"))

#: Distinct (path, pid, action) decisions remembered before the set is emptied,
#: so that a long run cannot grow it without bound. Emptying it can only cause
#: a decision to be chained a second time, never to be dropped.
MAX_CHAINED_DECISIONS = int(os.getenv("URDS_MAX_CHAINED_DECISIONS", "4096"))


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
        self.transport = transport.InProcessTransport(
            self.ledger, self.responder, on_block=self._note_block)
        self.dispatcher = dispatch.Dispatcher(
            self._process,
            lanes=self.config.dispatch_lanes,
            queue_max=self.config.dispatch_queue_max,
        )
        self.pending = pending.PendingAttribution(
            resolve=self._attribution_fields,
            respond=self._respond_to_parked,
            window_ms=self._attribution_window_ms(),
        )

        #: path -> the entropy the ledger holds for it while it was known-good.
        #: Filled once at startup and kept current from the agent's own writes.
        #: See `_warm_baselines` for what it replaced and why that mattered.
        self._baseline_entropy: dict[str, float] = {}

        self._original_post = None
        self._observers: list = []
        self._lock = threading.Lock()
        self._running = False
        self.events_seen = 0
        self.responses = 0
        #: (path, pid, action) triples already written to the chain by
        #: `_chain_unsuspicious_decision`. See it for why this is deduplicated.
        self._chained_decisions: set[tuple] = set()

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

        # Before the observers, because this is the one chain read the agent
        # makes and it must not happen while events are queueing behind it.
        baselines = self._warm_baselines()

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

        # Started before the observers, so that the first event the watchdog
        # delivers has a lane to go to rather than a queue nobody is reading.
        self.dispatcher.start()
        self.pending.start()

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
            "dispatch": {"lanes": self.dispatcher.lane_count,
                         "queue_max_per_lane": self.dispatcher.queue_max},
            "baselines_loaded": baselines,
            "attribution_window_ms": self._attribution_window_ms(),
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

        # Observers first, then the lanes: no new events can arrive now, so
        # draining finishes the ones already in hand instead of discarding
        # them. A response half-taken at shutdown is the worst of both.
        drained = self.dispatcher.drain(timeout=10.0)
        dispatch_stats = self.dispatcher.stop(timeout=5.0)
        if not drained:
            logger.warning("dispatch did not drain within 10s; %d events left",
                           dispatch_stats["depth"])

        # After the lanes, because a lane can still be parking events. Stopping
        # responds to whatever is left as unattributed rather than discarding
        # it: "the agent stopped" must not read the same as "the agent looked
        # at these and decided they were fine".
        pending_stats = self.pending.stop(timeout=5.0)

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
            # In the chain, not only in a log file. An agent that dropped
            # writes during a run must say so somewhere an auditor reads.
            "dispatch": {k: v for k, v in dispatch_stats.items()
                         if k != "per_lane"},
            "dispatch_drained_cleanly": drained,
            "pending_attribution": pending_stats,
            "resumed_on_shutdown": resumed,
            "timestamp": utc_now(),
        }
        self.ledger.try_log_event("agent_stopped", record)
        self.ledger.close()
        self._running = False
        return {"stopped": True, **record}

    # -- the hot path ------------------------------------------------------

    def on_file_event(self, path: str, kind: str) -> bool:
        """Called on a watchdog thread. Hands the event to a lane and returns.

        Nothing is decided here, with one exception: whether this path is a
        decoy, which is a dict lookup and decides only *where in the queue*
        the event goes, never what happens to it. A canary event that waits
        behind two hundred ordinary writes is a tripwire wired through a
        backlog, and the whole point of the decoy is that it is the one signal
        needing no threshold and no delay.

        Everything else used to happen here - detection, the attribution wait
        and the response inline, a quarter of a second of the watchdog's only
        thread for every write nobody could be named for. See
        `agent/dispatch.py` for what that cost measured.
        """
        return self.dispatcher.submit(path, kind,
                                      priority=self.canaries.is_canary(path))

    def _attribution_window_ms(self) -> float:
        """How far back a lookup will still match an audited write."""
        try:
            return float(self.monitor_app.attributor.log.window_ms)
        except Exception:  # noqa: BLE001
            return float(self.config.attribution_timeout_ms)

    def _attribution_fields(self, path: str, event_at: float | None = None) -> dict:
        """Who wrote this path, asked once and without waiting.

        `grace_ms=0` always. The blocking grace was measured on this host and
        catches a minority of records at any rate and none at all under burst;
        `agent/pending.py` carries the numbers. What replaces it is asking
        again, which costs a lock and a bounded scan.

        `event_at` is when the event being judged was queued. Without it the
        lookup will answer with the path's previous writer while the current
        one's audit record is still in flight - see `WriteLog.lookup`. Every
        call site here passes it.
        """
        return (self.monitor_app.attributor
                .resolve(path, grace_ms=0.0, event_at=event_at)
                .as_event_fields())

    def _process(self, queued: "dispatch.Event") -> dict | None:
        """One filesystem event, from detection to a response or a parking slot.

        This function never waits for anything. It classifies, asks who wrote
        the file, and then either acts - if the answer is `CERTAIN` - or parks
        the event for `pending` to re-ask. The lane is free either way.
        """
        path, kind = queued.path, queued.kind
        try:
            event = self.monitor_app.handle_event(
                path, kind, attribution_grace_ms=0.0,
                event_at=queued.queued_at)
        except Exception:  # noqa: BLE001 - one bad file must not stop the agent
            logger.exception("detection failed for %s", path)
            return None
        if event is None:
            return None

        with self._lock:
            self.events_seen += 1
        event["dispatch_lag_ms"] = round(queued.age_ms(), 3)

        # A canary rewritten with low-entropy junk produces no entropy verdict
        # at all, so the detector never asks who wrote it. The whole value of a
        # decoy is that it needs no threshold, and that is worth one lookup on
        # the rare event that touches one.
        #
        # Deletions count. They used to be skipped here, on the reasoning that
        # a file that is gone cannot be hash-compared - which is true and beside
        # the point. A decoy that has been deleted is the least ambiguous
        # tripwire in the system, and skipping it meant an attack that archives
        # and unlinks rather than overwriting walked through the whole field
        # without setting anything off.
        canary_path = self.canaries.is_canary(path)
        if canary_path and event.get("attribution_confidence") != self.attribution.CERTAIN:
            try:
                event.update(self._attribution_fields(path, queued.queued_at))
            except Exception:  # noqa: BLE001
                logger.exception("canary attribution failed for %s", path)

        if not event.get("suspicious") and not canary_path:
            # Not actionable, so there is nothing to wait for. Velocity still
            # takes it if somebody is named: an encryptor's first few files may
            # each look unremarkable, and what makes them evidence is that one
            # process produced all of them.
            self.velocity.record(
                event.get("process_id"), path,
                entropy=event.get("entropy"),
                baseline_entropy=self._baseline_for(path),
            )
            return event

        if event.get("attribution_confidence") == self.attribution.CERTAIN:
            self._act(event, path, canary_path, queued.queued_at)
            return event

        # Actionable, but nobody is named yet - which at these delivery
        # latencies is the common case, not the exception. Park it rather than
        # holding the lane, and rather than deciding on evidence that has not
        # arrived. `pending` responds either way: when the writer is named, or
        # when the window shuts and the answer is honestly `unknown`.
        self.pending.add(event, path, kind, queued.queued_at, canary_path)
        return event

    def _respond_to_parked(self, parked: "pending.Parked", attributed: bool) -> None:
        """The other way into `_act`: a parked event whose writer arrived."""
        if attributed:
            logger.info("attribution arrived %.0f ms after the write for %s",
                        parked.resolved_after_ms or 0.0, parked.path)
        self._act(parked.event, parked.path, parked.canary_path,
                  parked.queued_at)

    def _act(self, event: dict, path: str, canary_path: bool,
             queued_at: float) -> None:
        """Velocity, the decoy record, and the response. Once per event.

        Reached either straight from a lane when the writer was already known,
        or from `pending` when the audit record caught up. Both go through here
        so that an event cannot be responded to twice, and so that a decoy's
        hit is recorded with the PID that was finally established rather than
        with the `None` that was true a second earlier.
        """
        self.velocity.record(
            event.get("process_id"), path,
            entropy=event.get("entropy"),
            baseline_entropy=self._baseline_for(path),
            # The write happened when it was queued, not when it was resolved.
            # Stamping it now would make a slow attribution look like a slow
            # attacker and flatten the rate the signals are measuring.
            at=queued_at,
        )

        if canary_path:
            hit = self.canaries.touched(path, event.get("process_id"),
                                        event.get("process_image"))
            if hit is not None:
                event["canary_hit"] = True
                event["canary_detail"] = hit.as_dict()

        outcome = self.responder.respond(event)
        with self._lock:
            self.responses += 1
        event["response"] = outcome.as_event()

        logger.warning("%s: %s -> %s (%s)", path, event.get("verdict"),
                       outcome.action, outcome.reason)

        self._chain_unsuspicious_decision(event, path, outcome)

    def _chain_unsuspicious_decision(self, event: dict, path: str,
                                     outcome) -> None:
        """Put a decision in the chain that the Monitor's pipeline will not.

        `app.handle_event` fans out to the ledger only for events it found
        suspicious, and a deletion returns before the fan-out entirely. That is
        right for the Monitor - a file being removed is not an entropy verdict -
        and wrong for the agent, because the agent *responds* to those events.
        Measured, Phase 5: 7-Zip archived the protected root with `-sdel`,
        deleted all twenty decoys, and the agent saw every one of them, named
        `7z.exe` correctly 2772 ms later, and recorded `isolate_and_log` and
        then `refused (PID 5844 does not exist)`. None of it reached the hash
        chain. The whole attack existed only in a plain text log file that
        anything running as the user can rewrite, while the chain showed
        nothing had happened.

        So: one block per *distinct decision*, keyed on the path, the process
        finally named, and the action taken. Distinct, not per event, because
        one decoy deletion arrives from the watchdog dozens of times - that run
        logged forty-two lines for a single file - and a chain that grows by
        forty-two blocks per touched file can be flooded into uselessness by an
        attacker who simply rewrites one decoy in a loop. A second, *different*
        decision about the same path still gets its own block, which is the
        case that matters: `unknown -> isolate_and_log` followed by
        `certain -> suspended` is two facts, not one repeated.
        """
        if event.get("suspicious"):
            return  # the pipeline carries this one, and two blocks is worse
        key = (str(path).lower(), event.get("process_id"), outcome.action)
        with self._lock:
            if key in self._chained_decisions:
                return
            self._chained_decisions.add(key)
            if len(self._chained_decisions) > MAX_CHAINED_DECISIONS:
                self._chained_decisions.clear()
        self.ledger.try_log_event("file_event", {
            "file_path": path,
            "file_hash": event.get("file_hash"),
            "event_type": event.get("event_type"),
            "entropy": event.get("entropy"),
            "verdict": event.get("verdict"),
            "reason": event.get("reason"),
            "signal": event.get("signal"),
            "detection_latency_ms": event.get("detection_latency_ms"),
            "process_id": event.get("process_id"),
            "process_image": event.get("process_image"),
            "attribution_confidence": event.get("attribution_confidence"),
            "attribution_reason": event.get("attribution_reason"),
            "attribution_source": event.get("attribution_source"),
            "canary_hit": event.get("canary_hit", False),
            "canary_detail": event.get("canary_detail"),
            "response": event.get("response"),
            # Why this block exists at all, on the block, so a reader does not
            # have to know this function to know it is not a pipeline record.
            "chained_by": "agent: responded to an event the pipeline does not "
                          "carry",
        })

    def _baseline_for(self, path: str) -> float | None:
        """The entropy the ledger recorded for this path while it was good.

        This is the signal the per-file design throws away, and it is free: the
        `file_baseline` events the pipeline already writes carry `entropy`. A
        file that read 4.2 bits/byte when first seen and reads 7.99 now has not
        become a better compressed archive.

        A dict lookup, and nothing else. It used to be a lookup backed by a
        query, and the query was the single most expensive thing on the
        protection path - see `_warm_baselines`.
        """
        return self._baseline_entropy.get(path.lower())

    def _note_block(self, event_type: str, event_data: dict) -> None:
        """Keep the baseline cache current from the agent's own ledger writes.

        Called by the transport after a block commits, on the pipeline's
        worker thread. The agent is the process writing these baselines, so
        reading them back out of the chain to learn what it just put in was
        always the long way round.
        """
        if event_type != "file_baseline":
            return
        entropy = (event_data or {}).get("entropy")
        path = (event_data or {}).get("file_path")
        if not path or not isinstance(entropy, (int, float)):
            return
        if len(self._baseline_entropy) > MAX_BASELINES:
            # Dropping the lot loses the signal for every path until each is
            # baselined again, which is the safe direction: a missing baseline
            # makes the detector rely on absolute entropy, and a stale one
            # would have it compare against a reading from a different file.
            self._baseline_entropy.clear()
            logger.info("baseline cache exceeded %d paths and was cleared",
                        MAX_BASELINES)
        self._baseline_entropy[str(path).lower()] = float(entropy)

    def _warm_baselines(self) -> int:
        """Load every baseline the chain holds, in one indexed query.

        What this replaced: `_baseline_for` used to call `get_blocks(
        file_path=...)` on a cache miss, and every path the agent has not seen
        before is a miss. That query has no index it can use - `file_path`
        lives inside the `event_data` JSON blob, so the filter is a LIKE with
        a leading wildcard - and it runs twice, once to COUNT and once to
        SELECT. It is a full scan of the chain, it gets slower as the chain
        grows, and it ran on a lane, on one SQLite connection shared with the
        fan-out thread writing the next block.

        Measured at 3300 blocks: 4.4 ms, against 2.5 ms for the whole of
        detection. Five hundred documents is five hundred of them, and the
        arm that created that corpus recorded a dispatch lag of 12.8 s -
        which is the agent still draining the backlog when the attack started.

        This is one query on `event_type`, which *is* indexed, and after it
        the protection path never reads the chain at all.
        """
        try:
            found = self.ledger.chain.get_blocks(
                event_type="file_baseline", newest_first=True,
                limit=MAX_BASELINES)
        except Exception as exc:  # noqa: BLE001 - starting without them is fine
            logger.warning("could not warm the baseline cache: %s", exc)
            return 0

        loaded = 0
        # Newest first, so the first reading seen for a path is the most
        # recent one and later (older) blocks must not overwrite it.
        for block in found.get("blocks", []):
            data = block.get("event_data") or {}
            path, entropy = data.get("file_path"), data.get("entropy")
            if not path or not isinstance(entropy, (int, float)):
                continue
            key = str(path).lower()
            if key not in self._baseline_entropy:
                self._baseline_entropy[key] = float(entropy)
                loaded += 1
        return loaded

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
            "dispatch": self.dispatcher.stats(),
            "pending_attribution": self.pending.stats(),
            "attribution_window_ms": self._attribution_window_ms(),
            "responder": self.responder.summary(),
            "canaries": len(self.canaries.paths()),
            "canary_hits": self.canaries.hit_count(),
            "baselines_cached": len(self._baseline_entropy),
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
