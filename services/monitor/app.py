"""URDS Monitor service (port 8001) - AS.

    POST /monitor/start   begin watching a path
    POST /monitor/stop    stop watching
    GET  /monitor/status  monitor id, files seen, events captured
    GET  /monitor/events  recent events, newest first
    POST /features        feature extraction for one file (used by /analyze)
    GET  /health          liveness for docker-compose and the gateway

Watchdog delivers filesystem events on its own thread. Classification happens
inline there - it is a couple of reads and a counter, and the detection-latency
target is measured from the moment the event arrives to the moment the verdict
exists. The downstream fan-out (ML, ledger, response) is handed to a worker
thread so a slow ledger cannot stall the watcher.
"""

import logging
import os
import queue
import threading
from collections import deque
from fnmatch import fnmatch
from datetime import datetime, timezone
from time import perf_counter, time
from uuid import uuid4

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

import pipeline
from admissibility import adjudicate
from containers import compression_evidence, inner_content_evidence, validate_container
from detection import (
    CONTAINER_POLICY_INNER,
    DEFAULT_CONTAINER_POLICY,
    DEFAULT_ENTROPY_THRESHOLD,
    EntropyHistory,
    classify,
    get_magic_bytes,
    identify_container,
    looks_unreadable,
    measure,
    read_magic,
    sample_file,
    sha256_file,
)
from pe_features import suspicious_api_names
from pe_features import extract_pe_features as _extract_pe_features
from suppression import TrainingMode, Whitelist


def pe_imports_count(path: str) -> int:
    """Imported-function count for a PE, 0 for anything else."""
    return _extract_pe_features(path).get("pe_imports_count", 0)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("monitor")

app = FastAPI(title="URDS Monitor", version="1.0.0")

ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", DEFAULT_ENTROPY_THRESHOLD))


def _inner_content(head: bytes, tail: bytes, container: str | None, size: int) -> dict | None:
    """The inner-content reading, taken only by the policy that consults it.

    It costs a bounded inflate of up to 64KB. Every other policy ignores the
    result, so taking it unconditionally would put that cost on the sub-100ms
    detection path for a value nobody reads.
    """
    if DEFAULT_CONTAINER_POLICY != CONTAINER_POLICY_INNER:
        return None
    return inner_content_evidence(head, tail, container, size)
# Off in unit tests and anywhere the downstream services are not running.
PIPELINE_ENABLED = os.getenv("PIPELINE_ENABLED", "true").lower() not in {"false", "0", "no"}
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "500"))

# auto | native | polling. `native` is inotify on Linux and ReadDirectoryChangesW
# on Windows; `polling` stats the tree on an interval instead.
OBSERVER_MODE = os.getenv("MONITOR_OBSERVER", "auto").lower()
POLLING_INTERVAL_SECONDS = float(os.getenv("MONITOR_POLLING_INTERVAL", "1.0"))

# Filesystems that carry no change notifications into this container. A bind
# mount from a Windows host is the one that matters here: Docker Desktop passes
# D:\ through to the Linux VM as virtiofs/9p, and inotify watches on it are
# accepted and then never fire. Verified on Windows 11 build 26200 - a host-side
# write produced zero events while the identical write made inside the container
# produced ten. Silence is indistinguishable from "nothing happened", so the
# detector reported healthy and saw nothing at all.
NON_INOTIFY_FILESYSTEMS = frozenset(
    {"9p", "virtiofs", "drvfs", "fuse.grpcfs", "osxfs", "cifs", "smb3", "smbfs", "nfs", "nfs4", "vboxsf"}
)

STARTED_AT = time()

# Bounded on purpose: the old list grew without limit for the lifetime of the
# process, which is a slow leak on a busy watch path.
EVENTS: deque = deque(maxlen=MAX_EVENTS)
_SEEN_FILES: set[str] = set()
_LOCK = threading.Lock()

# Differential entropy analysis (spec 1.4): entropy per path over time, so a
# file that *became* random can be told from one that always was. Takes its own
# lock; the watchdog threads share it.
ENTROPY_HISTORY = EntropyHistory()

# Table 5.7's two remaining false-positive mitigations. Both suppress alerts, so
# both are bounded by the same rule: neither overrides evidence that a file's
# content was replaced. See services/monitor/suppression.py.
WHITELIST_PATH = os.getenv("WHITELIST_PATH", "")
WHITELIST = Whitelist.from_file(WHITELIST_PATH) if WHITELIST_PATH else Whitelist()
TRAINING_MODE = TrainingMode()

# Recovery's integrity check compares a restored file against the last hash the
# ledger holds for it in a *good* state. Nothing wrote one: the pipeline fans out
# to the ledger only for suspicious events, so the only hash on an attacked path
# was the ciphertext's, and services/response/recovery/ledger_client.py had to
# refuse to trust it. Correct, and it left the feature inert - every real
# recovery reported "integrity could not be verified".
#
# So the first time a file is seen and found benign, its hash is recorded as
# `file_baseline`. One write per path per monitor run, off the detection path,
# and it is what a later recovery verifies against. Deviation V-5 in the
# write-up is the extra ledger traffic this costs, so it stays switchable.
BASELINE_LOGGING_ENABLED = os.getenv("BASELINE_LOGGING_ENABLED", "true").lower() not in {
    "false",
    "0",
    "no",
}

_observer: Observer | None = None
_monitor_id: str | None = None
_watch_path: str | None = None
_file_patterns: list[str] = []

_work: queue.Queue = queue.Queue()
_worker: threading.Thread | None = None

_observer_backend: str = "none"
_observer_reason: str = ""


def filesystem_for(path: str) -> str:
    """Filesystem type backing `path`, per /proc/mounts. Empty when unknown.

    Longest matching mountpoint wins, so /watch inside /  resolves to the bind
    mount rather than the root filesystem.
    """
    try:
        with open("/proc/mounts", "r") as handle:
            mounts = [line.split() for line in handle]
    except OSError:
        return ""  # not Linux, or no /proc - fall through to the native backend

    target = os.path.realpath(path)
    best_type = ""
    best_len = -1
    for fields in mounts:
        if len(fields) < 3:
            continue
        mountpoint, fstype = fields[1], fields[2]
        if target == mountpoint or target.startswith(mountpoint.rstrip("/") + "/"):
            if len(mountpoint) > best_len:
                best_type, best_len = fstype, len(mountpoint)
    return best_type


def build_observer(path: str):
    """Pick a watchdog backend for `path`, and record why it was picked.

    Polling costs a directory stat per interval, so it is not the default. It is
    selected only where the native backend cannot work, because there the native
    backend fails *silently* - watches are accepted and no event ever arrives.
    """
    if OBSERVER_MODE == "polling":
        return PollingObserver(timeout=POLLING_INTERVAL_SECONDS), "polling", "MONITOR_OBSERVER=polling"
    if OBSERVER_MODE == "native":
        return Observer(), "native", "MONITOR_OBSERVER=native"

    fstype = filesystem_for(path)
    if fstype in NON_INOTIFY_FILESYSTEMS:
        return (
            PollingObserver(timeout=POLLING_INTERVAL_SECONDS),
            "polling",
            f"{path} is on '{fstype}', which delivers no inotify events to this container",
        )
    return Observer(), "native", f"{path} is on '{fstype or 'unknown'}'"


class MonitorStartRequest(BaseModel):
    watch_path: str
    recursive: bool = True
    file_patterns: list[str] = Field(default_factory=list)


def matches_patterns(path: str, patterns: list[str]) -> bool:
    """True when `path` is one the caller asked to watch.

    An empty pattern list means everything, which is both the default and what
    every existing caller relies on.

    Patterns are matched against the file name (`*.pdf`, the shape Listing 3.1
    uses) and against the whole path, so a caller who writes a directory-bearing
    pattern gets what they meant rather than silence. `fnmatch` rather than
    `fnmatchcase`: it normalises case per platform, so `*.PDF` matches `a.pdf`
    on Windows, where the filesystem itself does not distinguish them.
    """
    if not patterns:
        return True
    name = os.path.basename(path)
    return any(fnmatch(name, pattern) or fnmatch(path, pattern) for pattern in patterns)


class MonitorStopRequest(BaseModel):
    # Optional, though Listing 3.3 shows it sent. Only one monitor runs per
    # process, so an omitted id still means "stop what is running" - which is
    # what every existing caller does. When it *is* sent it is checked, because
    # accepting an identifier and ignoring it is how a caller ends up believing
    # it stopped one monitor while another kept running.
    monitor_id: str | None = None


class FeatureRequest(BaseModel):
    path: str


class WhitelistRequest(BaseModel):
    paths: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class TrainingModeRequest(BaseModel):
    # "learn normal activity for a while, then use it" - the window is the whole
    # configuration. Expires on its own so a forgotten training mode does not
    # become a permanently degraded detector.
    duration_seconds: float = Field(default=300.0, gt=0, le=86_400)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_error(code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "timestamp": utc_now(),
            "request_id": f"req_{uuid4().hex[:12]}",
        },
        "details": details or {},
    }


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content=build_error("BAD_REQUEST", "Request validation failed", {"errors": exc.errors()}),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 500: "INTERNAL_SERVER_ERROR"}.get(
        exc.status_code, "REQUEST_FAILED"
    )
    return JSONResponse(status_code=exc.status_code, content=build_error(code, str(exc.detail)))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=build_error("MONITOR_ERROR", "Unexpected monitor error", {"error": str(exc)}),
    )


# ------------------------------------------------------------------- extraction


def extract_features(path: str) -> dict:
    """Feature vector for one file. Every value is measured, none are invented."""
    magic = read_magic(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    # read_magic already waited out the lock budget. If it came back empty on a
    # file with bytes in it, the remaining reads would each wait the same budget
    # to reach the same empty result, so they are told not to.
    readable = not looks_unreadable(magic, size)
    head, tail = sample_file(path, size, retry=readable)
    entropy, statistics = measure(head)
    container_valid = validate_container(head, tail, identify_container(magic), size)
    compression = compression_evidence(head, tail, identify_container(magic), size)
    inner = _inner_content(head, tail, identify_container(magic), size)

    verdict = classify(
        path,
        entropy,
        magic,
        ENTROPY_THRESHOLD,
        readable=readable,
        container_valid=container_valid,
        statistics=statistics,
        compression=compression,
        inner_content=inner,
    )
    return {
        "shannon_entropy": entropy,
        "file_size": size,
        "magic_bytes": magic[:4].hex().upper() if magic else "UNKNOWN",
        "container_format": verdict["container_format"],
        # Tri-state, and it is reported as one. True the structure holds, false
        # the header is forged, null no validator for this format or the file is
        # still being written. Collapsing null into false would tell a consumer
        # that every .rar is a forgery.
        "container_valid": container_valid,
        "ransom_extension": verdict["ransom_extension"],
        "suspicious": verdict["suspicious"],
        "verdict": verdict["verdict"],
        "signal": verdict["signal"],
        # Normalised 0-1 view of entropy; the dashboard reads this as "how
        # encrypted-looking is it".
        "modification_rate": round(min(1.0, entropy / 8.0), 2),
        # Measured, not estimated - the ML engine's behavioural model takes
        # these directly rather than deriving them from entropy. The same keys
        # `handle_event` puts on an event, from the same function, because a
        # consumer that got different columns depending on which endpoint it
        # came in by would be scoring two different models.
        **statistics,
        # spec 3.4.2 lists both of these in the FeatureSet, and gateway.yaml
        # marks them required, but nothing produced them until the PE parser
        # existed. Real values for a PE; 0 and [] for everything else, which is
        # the honest answer for a .docx rather than a fabricated count.
        "pe_imports_count": pe_imports_count(path),
        "api_calls": suspicious_api_names(path),
    }


def handle_event(path: str, event_type: str) -> dict | None:
    """Classify one filesystem event and record it.

    Detection latency is measured over exactly this function: from the event
    arriving to a verdict existing. Target is under 100ms.
    """
    started = perf_counter()

    # The caller asked for a subset of files. Applied here rather than at the
    # watchdog layer so it covers deletions and renames too, and so the filtered
    # file never reaches the event buffer or the counters.
    if not matches_patterns(path, _file_patterns):
        return None

    if event_type == "deleted":
        # Readings describe content that no longer exists. Keeping them would
        # also let a new file at the same path inherit a baseline it never had.
        ENTROPY_HISTORY.forget(path)
        event = {
            "event_id": f"evt_{uuid4().hex[:10]}",
            "file_path": path,
            "event_type": "deleted",
            "entropy": 0.0,
            "file_size": 0,
            "magic_bytes": "UNKNOWN",
            "file_hash": None,
            "suspicious": False,
            "verdict": "deleted",
            "reason": "file removed",
            "timestamp": utc_now(),
            "process_id": os.getpid(),
            "user": "system",
        }
        event["detection_latency_ms"] = round((perf_counter() - started) * 1000, 3)
        _record(event)
        return event

    if not os.path.isfile(path):
        return None

    magic = read_magic(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        return None

    # read_magic already waited out the lock budget; see extract_features.
    readable = not looks_unreadable(magic, size)
    # One read, every measurement. Entropy, the byte statistics and the block
    # profile all score exactly the same prefix, and the statistics are inputs
    # to the behavioural model - a consumer that has to estimate them from
    # entropy instead gets the ZIP-versus-ciphertext distinction wrong, which is
    # what the dashboard banner was doing. `sample_file` adds a bounded tail
    # read for the structural check, and only for files larger than the leading
    # sample; smaller ones are already entirely in hand.
    head, tail = sample_file(path, size, retry=readable)
    entropy, statistics = measure(head)
    # Structural validation: does the file have the format its header declares?
    # Tri-state - None means no validator, or a file still being written, and
    # keeps the behaviour that existed before this check.
    container_valid = validate_container(head, tail, identify_container(magic), size)
    # Did the container actually compress what it carries? Read from the same two
    # samples the validator just used, and consumed only by the `+ratio` policy -
    # under `legacy` it is measured and ignored, which is what lets the Phase 6
    # experiment attribute a flip to the clause that caused it.
    compression = compression_evidence(head, tail, identify_container(magic), size)
    # One level in: what does the container carry? Only the `+inner` policy asks,
    # and only that policy pays the bounded inflate it costs.
    inner = _inner_content(head, tail, identify_container(magic), size)
    # Differential entropy: how far this reading sits above the lowest one ever
    # taken on this path. None the first time a file is seen.
    entropy_delta = ENTROPY_HISTORY.observe(path, entropy, size) if readable else None

    verdict = classify(
        path,
        entropy,
        magic,
        ENTROPY_THRESHOLD,
        readable=readable,
        entropy_delta=entropy_delta,
        container_valid=container_valid,
        statistics=statistics,
        compression=compression,
        inner_content=inner,
    )
    # Hashing a file we could not read only pays the retry cost again to reach
    # the same None, and it is on the sub-100ms detection path.
    file_hash = sha256_file(path) if readable else None

    # Table 5.7's suppression mitigations. Applied after classification, never
    # before it: the verdict and its reason are what get recorded either way, so
    # a suppressed event is still fully auditable and still counted. What
    # suppression changes is whether the pipeline fans out and whether the event
    # reads as suspicious - not whether it was seen.
    #
    # `match` finds the rule that describes the file; `adjudicate` decides
    # whether that rule is expensive enough to fake to be allowed to cancel this
    # particular detection. A rule that is outranked is *attenuated*, not
    # discarded - it stays on the event with both costs, so an operator can see
    # their rule was consulted and lost.
    TRAINING_MODE.observe(path, verdict["entropy"], verdict)
    decision = None
    if verdict["suspicious"]:
        decision = adjudicate(
            verdict,
            WHITELIST.match(path, file_hash, verdict)
            or TRAINING_MODE.match(path, verdict["entropy"], verdict),
        )
    # `suppressed_by` keeps its original shape - the rule that removed the alert,
    # or null. The full adjudication, including the rules that were outranked,
    # goes in its own field so the older one does not change meaning.
    suppression = (
        {"rule": decision["rule"], "value": decision["value"]}
        if decision and decision["admitted"]
        else None
    )

    event = {
        "event_id": f"evt_{uuid4().hex[:10]}",
        "file_path": path,
        "event_type": event_type,
        # verdict's entropy, not the raw one: it is None for a file we could not
        # read, where the raw value is a 0.0 that was never measured. The ledger
        # already records the verdict's value, so taking the raw one here made
        # /monitor/events and the ledger disagree about the same event.
        "entropy": verdict["entropy"],
        "file_size": size,
        "magic_bytes": magic[:4].hex().upper() if magic else "UNKNOWN",
        "file_hash": file_hash,
        # The verdict's own answer is preserved in `verdict`/`reason` even when a
        # rule suppresses it, so the record shows what the detector concluded and
        # what an operator had previously decided about it - not one overwriting
        # the other.
        "suspicious": verdict["suspicious"] and suppression is None,
        "verdict": verdict["verdict"],
        "reason": verdict["reason"],
        # Which of the four detections fired. `verdict` says what was concluded;
        # this says what concluded it, and it is what admissibility ranks
        # against - the three rules that collapse to "suspected_encryption"
        # differ by an order of magnitude in what it costs to evade them.
        "signal": verdict["signal"],
        "suppressed_by": suppression,
        # The whole adjudication, present whenever any rule matched - including
        # one that was outranked and left the alert standing. A suppression that
        # disappears without a record is indistinguishable from a detector that
        # never fired.
        "admissibility": decision,
        "container_format": verdict["container_format"],
        "container_valid": container_valid,
        # Both of the model's top two features are decided here. Carrying them
        # on the event means a consumer scoring it later - the dashboard does -
        # reads the values that were actually measured instead of guessing them
        # back from the file path.
        "ransom_extension": verdict["ransom_extension"],
        "entropy_delta": entropy_delta,
        **statistics,
        "timestamp": utc_now(),
        # watchdog reports *what* changed, never *who* changed it - attribution
        # needs eBPF/fanotify (Linux) or ETW (Windows), which is Phase 5 work.
        # Reporting the monitor's own PID here would be worse than admitting the
        # gap: the response service runs in a different PID namespace, so that
        # number would name an unrelated process for it to kill.
        "process_id": None,
        "user": "system",
    }
    event["detection_latency_ms"] = round((perf_counter() - started) * 1000, 3)

    first_sighting = _record(event)

    if verdict["suspicious"] and suppression is None and PIPELINE_ENABLED:
        features = {
            "shannon_entropy": entropy,
            "file_size": size,
            "magic_bytes": event["magic_bytes"],
            "modification_rate": round(min(1.0, entropy / 8.0), 2),
            "container_format": verdict["container_format"],
            "container_valid": container_valid,
            "ransom_extension": verdict["ransom_extension"],
            **statistics,
        }
        _work.put(("detection", event, features, verdict))
    elif BASELINE_LOGGING_ENABLED and PIPELINE_ENABLED and first_sighting and file_hash and not verdict["suspicious"]:
        # The first time this path is seen and found benign, record what it
        # hashed to. This is the reference value recovery verifies a restored
        # file against; without it the integrity check has nothing trustworthy
        # to compare to and honestly reports that it could not verify.
        #
        # Queued, never inline: the fan-out is an HTTP call to another container
        # and this function is what the sub-100ms detection budget is measured
        # over. The `first_sighting` test bounds it to one write per path per
        # monitor run, and the raw verdict is used rather than the suppressed
        # one so a file an operator has whitelisted into silence still cannot
        # contribute a baseline if the detector thought it was encrypted.
        _work.put(("baseline", event))

    return event


def _record(event: dict) -> bool:
    """Buffer the event. True when this path had not been seen before.

    The answer is taken under the same lock that records it, because the
    "first sighting" test drives a ledger write and two watchdog threads
    reaching that test for the same new path would otherwise both pass it.
    """
    with _LOCK:
        EVENTS.append(event)
        first = event["file_path"] not in _SEEN_FILES
        _SEEN_FILES.add(event["file_path"])
    return first


def _drain() -> None:
    client = httpx.Client(timeout=pipeline.DOWNSTREAM_TIMEOUT)
    try:
        while True:
            item = _work.get()
            if item is None:
                return
            kind, payload = item[0], item[1:]
            try:
                if kind == "baseline":
                    _run_baseline(client, *payload)
                else:
                    _run_detection(client, *payload)
            except Exception:  # a bad event must not kill the worker
                logger.exception("%s work failed for %s", kind, payload[0].get("file_path"))
            finally:
                _work.task_done()
    finally:
        client.close()


def _run_detection(client: httpx.Client, event: dict, features: dict, verdict: dict) -> None:
    outcome = pipeline.run(event, features, verdict, client=client)
    with _LOCK:
        event["pipeline"] = {"stages": outcome["stages"]}
        if outcome["ledger_block"]:
            event["block_id"] = outcome["ledger_block"].get("block_id")
        if outcome["prediction"]:
            event["prediction"] = outcome["prediction"].get("prediction")
            event["threat_level"] = outcome["prediction"].get("threat_level")


def _run_baseline(client: httpx.Client, event: dict) -> None:
    block = pipeline.log_baseline(client, event)
    if block:
        with _LOCK:
            event["baseline_block_id"] = block.get("block_id")


def _ensure_worker() -> None:
    global _worker
    if _worker is None or not _worker.is_alive():
        _worker = threading.Thread(target=_drain, name="monitor-pipeline", daemon=True)
        _worker.start()


class MonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            handle_event(event.dest_path, "renamed")

    def on_deleted(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "deleted")


# -------------------------------------------------------------------- endpoints


@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "service": "monitor",
        "monitoring": _observer is not None and _observer.is_alive(),
        "entropy_threshold": ENTROPY_THRESHOLD,
    }


@app.post("/monitor/start")
def start_monitoring(payload: MonitorStartRequest) -> JSONResponse:
    global _observer, _monitor_id, _watch_path, STARTED_AT, _observer_backend, _observer_reason
    global _file_patterns

    if not os.path.isdir(payload.watch_path):
        return JSONResponse(
            status_code=400,
            content=build_error(
                "INVALID_WATCH_PATH",
                f"{payload.watch_path} is not a directory",
                {"watch_path": payload.watch_path},
            ),
        )

    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)

    _ensure_worker()

    _observer, _observer_backend, _observer_reason = build_observer(payload.watch_path)
    _observer.schedule(MonitorHandler(), payload.watch_path, recursive=payload.recursive)
    _observer.start()
    logger.info("watching %s with the %s backend: %s", payload.watch_path, _observer_backend, _observer_reason)

    _monitor_id = f"mon_{uuid4().hex[:6]}"
    _watch_path = payload.watch_path
    _file_patterns = list(payload.file_patterns)
    STARTED_AT = time()

    logger.info("monitoring %s (recursive=%s) as %s", _watch_path, payload.recursive, _monitor_id)
    return JSONResponse(
        content={
            "status": "monitoring",
            "monitor_id": _monitor_id,
            "watch_path": _watch_path,
            "recursive": payload.recursive,
            "file_patterns": payload.file_patterns,
            "start_time": utc_now(),
        }
    )


@app.post("/monitor/stop")
def stop_monitoring(payload: MonitorStopRequest | None = None) -> JSONResponse:
    global _observer, _monitor_id, _file_patterns

    requested = payload.monitor_id if payload else None
    if requested is not None and requested != _monitor_id:
        return JSONResponse(
            status_code=404,
            content=build_error(
                "UNKNOWN_MONITOR_ID",
                f"{requested} is not the monitor that is running",
                {"requested": requested, "running": _monitor_id},
            ),
        )

    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None

    stopped = _monitor_id
    _monitor_id = None
    _file_patterns = []
    return JSONResponse(
        content={"status": "stopped", "monitor_id": stopped, "stop_time": utc_now()}
    )


@app.get("/monitor/status")
def monitor_status() -> dict:
    with _LOCK:
        files_monitored = len(_SEEN_FILES)
        events_captured = len(EVENTS)
    running = _observer is not None and _observer.is_alive()
    return {
        "status": "active" if running else "stopped",
        "monitor_id": _monitor_id,
        "watch_path": _watch_path,
        # Echoed so a caller can see the filter that is actually in force. An
        # empty list means every file is processed.
        "file_patterns": _file_patterns,
        "files_monitored": files_monitored,
        "events_captured": events_captured,
        "uptime_seconds": int(time() - STARTED_AT),
        # Which backend is watching, and why. A native watch on a mount that
        # carries no notifications looks identical to a quiet filesystem from
        # the outside, so the choice is reported rather than left to be guessed.
        "observer_backend": _observer_backend,
        "observer_reason": _observer_reason,
        # Both false-positive suppressions are reported here, because an alert
        # that never fires because of one of them looks exactly like an alert
        # that never fired at all.
        "whitelist_entries": len(WHITELIST),
        "training_mode": TRAINING_MODE.status()["state"],
    }


@app.get("/monitor/events")
def monitor_events(limit: int = 20) -> dict:
    with _LOCK:
        events = list(EVENTS)[-limit:]
    return {"events": list(reversed(events)), "total": len(events)}


@app.get("/monitor/whitelist")
def get_whitelist() -> dict:
    return {"whitelist": WHITELIST.to_dict(), "entries": len(WHITELIST)}


@app.put("/monitor/whitelist")
def put_whitelist(payload: WhitelistRequest) -> JSONResponse:
    """Replace the whitelist wholesale.

    Replace rather than append: a mitigation an operator cannot fully see the
    current state of is one they cannot reason about, and PUT makes the request
    body the whole truth.
    """
    WHITELIST.replace(payload.paths, payload.hashes)
    logger.info("whitelist replaced: %d entries", len(WHITELIST))
    return JSONResponse(content={"whitelist": WHITELIST.to_dict(), "entries": len(WHITELIST)})


@app.get("/monitor/training-mode")
def get_training_mode() -> dict:
    return TRAINING_MODE.status()


@app.post("/monitor/training-mode/start")
def start_training_mode(payload: TrainingModeRequest | None = None) -> JSONResponse:
    duration = payload.duration_seconds if payload else 300.0
    status = TRAINING_MODE.start(duration)
    logger.info("training mode learning for %.0fs", duration)
    return JSONResponse(content=status)


@app.post("/monitor/training-mode/finish")
def finish_training_mode() -> JSONResponse:
    status = TRAINING_MODE.finish()
    logger.info("training mode -> %s (%d events observed)", status["state"], status["observed_events"])
    return JSONResponse(content=status)


@app.post("/monitor/training-mode/reset")
def reset_training_mode() -> JSONResponse:
    return JSONResponse(content=TRAINING_MODE.reset())


@app.post("/features")
def features_endpoint(payload: FeatureRequest) -> JSONResponse:
    if not os.path.isfile(payload.path):
        return JSONResponse(
            status_code=404,
            content=build_error("FILE_NOT_FOUND", f"{payload.path} does not exist", {"path": payload.path}),
        )
    return JSONResponse(content=extract_features(payload.path))
