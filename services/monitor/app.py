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

import pipeline
from detection import (
    DEFAULT_ENTROPY_THRESHOLD,
    calculate_entropy,
    classify,
    get_magic_bytes,
    read_magic,
    sha256_file,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("monitor")

app = FastAPI(title="URDS Monitor", version="1.0.0")

ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", DEFAULT_ENTROPY_THRESHOLD))
# Off in unit tests and anywhere the downstream services are not running.
PIPELINE_ENABLED = os.getenv("PIPELINE_ENABLED", "true").lower() not in {"false", "0", "no"}
MAX_EVENTS = int(os.getenv("MAX_EVENTS", "500"))

STARTED_AT = time()

# Bounded on purpose: the old list grew without limit for the lifetime of the
# process, which is a slow leak on a busy watch path.
EVENTS: deque = deque(maxlen=MAX_EVENTS)
_SEEN_FILES: set[str] = set()
_LOCK = threading.Lock()

_observer: Observer | None = None
_monitor_id: str | None = None
_watch_path: str | None = None

_work: queue.Queue = queue.Queue()
_worker: threading.Thread | None = None


class MonitorStartRequest(BaseModel):
    watch_path: str
    recursive: bool = True
    file_patterns: list[str] = Field(default_factory=list)


class FeatureRequest(BaseModel):
    path: str


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
    entropy = calculate_entropy(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    verdict = classify(path, entropy, magic, ENTROPY_THRESHOLD)
    return {
        "shannon_entropy": entropy,
        "file_size": size,
        "magic_bytes": magic[:4].hex().upper() if magic else "UNKNOWN",
        "container_format": verdict["container_format"],
        "ransom_extension": verdict["ransom_extension"],
        "suspicious": verdict["suspicious"],
        "verdict": verdict["verdict"],
        # Normalised 0-1 view of entropy; the ML stub and the dashboard both
        # read this as "how encrypted-looking is it".
        "modification_rate": round(min(1.0, entropy / 8.0), 2),
    }


def handle_event(path: str, event_type: str) -> dict | None:
    """Classify one filesystem event and record it.

    Detection latency is measured over exactly this function: from the event
    arriving to a verdict existing. Target is under 100ms.
    """
    started = perf_counter()

    if event_type == "deleted":
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
    entropy = calculate_entropy(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        return None

    verdict = classify(path, entropy, magic, ENTROPY_THRESHOLD)
    file_hash = sha256_file(path)

    event = {
        "event_id": f"evt_{uuid4().hex[:10]}",
        "file_path": path,
        "event_type": event_type,
        "entropy": entropy,
        "file_size": size,
        "magic_bytes": magic[:4].hex().upper() if magic else "UNKNOWN",
        "file_hash": file_hash,
        "suspicious": verdict["suspicious"],
        "verdict": verdict["verdict"],
        "reason": verdict["reason"],
        "container_format": verdict["container_format"],
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

    _record(event)

    if verdict["suspicious"] and PIPELINE_ENABLED:
        features = {
            "shannon_entropy": entropy,
            "file_size": size,
            "magic_bytes": event["magic_bytes"],
            "modification_rate": round(min(1.0, entropy / 8.0), 2),
            "container_format": verdict["container_format"],
            "ransom_extension": verdict["ransom_extension"],
        }
        _work.put((event, features, verdict))

    return event


def _record(event: dict) -> None:
    with _LOCK:
        EVENTS.append(event)
        _SEEN_FILES.add(event["file_path"])


def _drain() -> None:
    client = httpx.Client(timeout=pipeline.DOWNSTREAM_TIMEOUT)
    try:
        while True:
            item = _work.get()
            if item is None:
                return
            event, features, verdict = item
            try:
                outcome = pipeline.run(event, features, verdict, client=client)
                with _LOCK:
                    event["pipeline"] = {"stages": outcome["stages"]}
                    if outcome["ledger_block"]:
                        event["block_id"] = outcome["ledger_block"].get("block_id")
                    if outcome["prediction"]:
                        event["prediction"] = outcome["prediction"].get("prediction")
                        event["threat_level"] = outcome["prediction"].get("threat_level")
            except Exception:  # a bad event must not kill the worker
                logger.exception("pipeline failed for %s", event.get("file_path"))
            finally:
                _work.task_done()
    finally:
        client.close()


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
    global _observer, _monitor_id, _watch_path, STARTED_AT

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

    _observer = Observer()
    _observer.schedule(MonitorHandler(), payload.watch_path, recursive=payload.recursive)
    _observer.start()

    _monitor_id = f"mon_{uuid4().hex[:6]}"
    _watch_path = payload.watch_path
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
def stop_monitoring() -> dict:
    global _observer, _monitor_id

    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None

    stopped = _monitor_id
    _monitor_id = None
    return {"status": "stopped", "monitor_id": stopped, "stop_time": utc_now()}


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
        "files_monitored": files_monitored,
        "events_captured": events_captured,
        "uptime_seconds": int(time() - STARTED_AT),
    }


@app.get("/monitor/events")
def monitor_events(limit: int = 20) -> dict:
    with _LOCK:
        events = list(EVENTS)[-limit:]
    return {"events": list(reversed(events)), "total": len(events)}


@app.post("/features")
def features_endpoint(payload: FeatureRequest) -> JSONResponse:
    if not os.path.isfile(payload.path):
        return JSONResponse(
            status_code=404,
            content=build_error("FILE_NOT_FOUND", f"{payload.path} does not exist", {"path": payload.path}),
        )
    return JSONResponse(content=extract_features(payload.path))
