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
exists. Correlation (which process wrote it) runs on path-sharded lanes, not on
that thread: waiting for an audit record there serialised a 20-file burst into
one grace period per file (dispatch.py). The downstream fan-out (ML, ledger,
response) is handed to a worker thread so a slow ledger cannot stall the
watcher.
"""

import logging
import os
import queue
import threading
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
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

import attribution
import dispatch
import pipeline
import suspend_policy
from admissibility import adjudicate
from attribution import attributor, build_source
from containers import (
    compression_evidence,
    container_status,
    inner_content_evidence,
    tristate,
)
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
    hash_file,
)
from pe_features import suspicious_api_names
from pe_features import extract_pe_features as _extract_pe_features
from suppression import TrainingMode, Whitelist


def pe_imports_count(path: str) -> int:
    """Imported-function count for a PE, 0 for anything else."""
    return _extract_pe_features(path).get("pe_imports_count", 0)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("monitor")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Nothing stays frozen because the Monitor stopped (freeze-first, `suspend_policy`).

    The Response service's lease expiry is the backstop for a crash; this is
    the orderly half, and it also refuses any further suspend.
    """
    try:
        yield
    finally:
        # Also when the app leaves through an exception: nothing stays frozen.
        suspend_policy.shutdown()


app = FastAPI(title="URDS Monitor", version="1.0.0", lifespan=lifespan)

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

# Attribution questions left open by a first answer that came back too early to
# be final (attribution.py, "THE RACE"), by event ID: the question, and whether
# the incident's own blocks - the pipeline's file_event and response_action -
# are in the chain yet. The question is opened when the event is detected
# (`_correlate`), not after the pipeline: F2 in the 2026-10-04 VM report
# measured a first write's kill 6.92 s after it, because its question waited
# behind a 20-write burst in `_work`. Bounded like every other per-event
# structure in this service.
MAX_ANCHORS = int(os.getenv("ATTRIBUTION_MAX_ANCHORS", "4096"))
_ANCHORS: "OrderedDict[str, dict]" = OrderedDict()
_ANCHORS_LOCK = threading.Lock()
_pending: attribution.PendingAttribution | None = None
_PENDING_LOCK = threading.Lock()
# Escalations get their own worker rather than a place in `_work`. `_work` is
# the ML -> ledger -> response fan-out for every detection, and during a burst
# it runs behind; a kill that is due at the horizon cannot wait its turn behind
# twenty ML calls without missing the 2 s budget.
_escalations: queue.Queue = queue.Queue()
_escalator: threading.Thread | None = None
# Started from the request thread (with the worker) and, as a backstop, from
# the pending thread when a question closes; one lock so they cannot both
# start one.
_ESCALATOR_LOCK = threading.Lock()
# How many terminates may be in flight at once, each for a different PID
# (`_KillLanes`; one PID never has two). The default is 16: with 20 different
# writers a one-at-a-time Monitor made the 20th kill wait behind 19 others
# (FIXES.md defect 22, review follow-ups (R-RACE) and the pool made default
# there). MONITOR_KILL_WORKERS=1 keeps them one at a time, as before. Read
# when the escalation thread starts.
KILL_WORKERS = max(1, int(os.getenv("MONITOR_KILL_WORKERS", "16")))
# Escalation blocks owed (action taken, block not yet written) before a kill
# worker waits for the ledger writer: only reached if the ledger is down.
MAX_OWED_BLOCKS = max(1, int(os.getenv("MONITOR_MAX_OWED_BLOCKS", "4096")))

# One incident per file, not per notification - F6, FIXES.md defect 25.
# Windows reports one write as one to three notifications (`created`, then one
# or two `modified`) a few milliseconds apart, and each suspicious one opened
# its own incident: its own question, `file_event`, `response_action`,
# escalation and terminate request. The 2026-10-05 elevated run's ledger held
# 530 `file_event` blocks for 275 suspicious files. While an incident's
# question is open, a further suspicious `modified` notification for the same
# path that read the same bytes now joins it instead (`_join_open_incident`).
# It is still recorded on /monitor/events, and its write is still waited for
# over its own full delivery horizon: joining moves the question's window and
# horizon to cover it, which can only add writers to the answer, never remove
# one.
#
# The window is bounded from the incident's first read: in that run 239 of 243
# follow-up `modified` notifications came within 100 ms of the one before
# (median 11 ms), and the bound is also the most a join can delay a kill.
COALESCE_MS = float(os.getenv("MONITOR_COALESCE_MS", "100"))
# Open incidents by path (normcase'd, as attribution compares paths), and per
# path the sequence number of the last notification that can mean "a new file
# is here": created, deleted, or either end of a rename. A notification joins
# only an incident opened since the last of those, so a new file is never
# folded into an older incident. Both bounded like `_ANCHORS`.
_OPEN_INCIDENTS: "OrderedDict[str, dict]" = OrderedDict()
_INCIDENTS_BY_QUESTION: "OrderedDict[str, dict]" = OrderedDict()
_FILE_EPOCHS: "OrderedDict[str, int]" = OrderedDict()
_EPOCH_SEQ = 0
_INCIDENTS_LOCK = threading.Lock()

# Correlation - the first attribution look and the hand-off to `_work` - runs
# on these, sharded by path, not on the watchdog observer thread. Started with
# the watch and drained when it stops. See dispatch.py for what this cost when
# it ran inline, measured, and for what "a full lane" does instead of dropping.
_lanes = dispatch.CorrelationLanes()

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


def normalise_path(path: str) -> str:
    """The one spelling of a path this service stores - defect 4.

    `os.path.normpath` of the absolute path: the platform's own separator, no
    `.` or `..`, no doubled or trailing separator. The Windows integration VM
    stored `C:/URDS-main/watched_files\\tc01\\file.docx` - the watch path had been
    posted with forward slashes and watchdog joins with backslashes - and the
    ledger's lookup matched that spelling only, so recovery asked about the
    spelling anyone would type and verified nothing. Applied to the watch path
    in `start_monitoring` and to every path in `handle_event`, so the events,
    the chain and `/monitor/status` all carry the same form.

    Case policy on Windows: case is kept as given - the operator's spelling of
    the watch path, the filesystem's for the names below it - and never folded
    here. The stored path is evidence an operator reads beside Explorer, and a
    directory can be made case-sensitive (fsutil setCaseSensitiveInfo, which
    WSL uses), where folding would merge two real files into one name.
    Comparing two spellings is the reader's job, and it is done
    case-insensitively for Windows paths: services/ledger/path_keys.py.

    Not `realpath`: that resolves junctions, symlinks and subst drives, and
    would record a path the operator never gave.
    """
    return os.path.normpath(os.path.abspath(path))


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


def _size_then_magic(path: str) -> tuple[int | None, bytes]:
    """The file's size and leading bytes, in the order that cannot invent a lock.

    `looks_unreadable(magic, size)` reads "bytes exist and we got none" as a
    lock. The leading bytes used to be read first and the size second, so a
    write landing between the two - a file created and filled, which is what
    watchdog's `created` fires on - gave an empty read of the empty file and the
    full size of the written one: "unreadable", with nothing locked. Measured on
    the Windows test VM, 2026-10-04: `test_tc01` failed in the final full pass
    on exactly that, the event that saw all 32,768 bytes reporting entropy None.
    An unreadable reading is never suspicious and nothing re-reads it, so
    without a later notification the content is never scored.

    So the size comes first: a file that grows between the looks is read as
    what it now holds. And an empty read of a file that had bytes is checked
    against the size once more before it counts as a lock - a file truncated in
    between (an overwrite's first step) is empty, not locked. A real lock still
    reads as one: bytes on disk before and after, none obtainable.
    (tests/test_unreadable_is_a_lock_not_a_race.py)
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, b""
    magic = read_magic(path)
    if not magic and size > 0:
        try:
            size = os.path.getsize(path)
        except OSError:
            return None, b""
    return size, magic


def _size_after_read(path: str, size_before: int) -> tuple[int, bool]:
    """The size once the content has been read, and whether it moved.

    F5 of the 2026-10-04 VM test (FIXES.md defect 18): a file that grew
    between the size and the read was recorded with the size from before -
    events with `size=0` and entropy 5.86, `file_baseline` blocks with
    `file_size: 0` beside the full file's hash. A number taken before the
    bytes it is recorded beside describes neither. Where a hash is taken the
    size is the length of the bytes hashed (`detection.hash_file`); where only
    a sample is read, it is the size after the read, and the change is said.
    """
    try:
        after = os.path.getsize(path)
    except OSError:
        return size_before, False
    return after, after != size_before


def extract_features(path: str) -> dict:
    """Feature vector for one file. Every value is measured, none are invented."""
    size, magic = _size_then_magic(path)
    if size is None:
        size = 0

    # read_magic already waited out the lock budget. If it came back empty on a
    # file with bytes in it, the remaining reads would each wait the same budget
    # to reach the same empty result, so they are told not to.
    readable = not looks_unreadable(magic, size)
    head, tail = sample_file(path, size, retry=readable)
    entropy, statistics = measure(head)
    validation_state = container_status(head, tail, identify_container(magic), size)
    container_valid = tristate(validation_state)
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
        container_status=validation_state,
    )
    # Only a sample was read here, so there is no hashed length to use: the
    # size after the read, and whether it moved (_size_after_read, F5).
    recorded_size, size_changed = _size_after_read(path, size)
    return {
        "shannon_entropy": entropy,
        "file_size": recorded_size,
        "size_changed_during_read": size_changed,
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


def handle_event(
    path: str,
    event_type: str,
    renamed_from: str | None = None,
    lanes: dispatch.CorrelationLanes | None = None,
) -> dict | None:
    """Classify one filesystem event and record it.

    Detection latency is measured over exactly the classification part of this
    function: from the event arriving to a verdict existing. Target is under
    100ms. It excludes, by design, every queue the event passes through - the
    time watchdog held it before calling here, the correlation lane, and the
    pipeline queue - and the attribution wait. Those are reported beside it:
    `observed_at` (when watchdog handed the event over), `queue_wait_ms` (how
    long it waited for a correlation lane) and `response_dispatched_at` (when
    the pipeline asked the Response service to act). The VM's 20-file burst
    reported 2-17 ms here while its last event was stamped 4.77 s after its
    write; the new fields are what show that kind of gap.

    `lanes`: when given (the watchdog handler passes the running ones),
    correlation for a suspicious event is queued on the lane that owns `path`
    and this returns without waiting for it. When not given - a direct call, as
    every test makes - correlation runs here before returning, so the returned
    event is complete.

    `renamed_from` is the old name when the event is a rename. The event is
    about the file at `path` - that is what is classified, recorded and
    reported as `file_path` - but the bytes that made it suspicious were very
    likely written under the old name, and that is where the audit record is.
    """
    started = perf_counter()
    # When watchdog handed this event over, on the system clock. Attribution
    # compares audit records against *this* - their own TimeCreated against the
    # moment the change was reported - and not against whenever it gets round to
    # looking. See attribution.WriteLog.lookup.
    observed_at = time()

    # One spelling for everything downstream (normalise_path). Watchdog's own
    # paths are already in it once the watch path is; a direct caller's may not be.
    path = normalise_path(path)
    if renamed_from:
        renamed_from = normalise_path(renamed_from)

    # The caller asked for a subset of files. Applied here rather than at the
    # watchdog layer so it covers deletions and renames too, and so the filtered
    # file never reaches the event buffer or the counters.
    if not matches_patterns(path, _file_patterns):
        return None

    # Taken here, on the watchdog thread, so it follows notification order.
    if event_type in ("created", "deleted", "renamed"):
        _new_file_at(path, renamed_from)
    epoch = _file_epoch(path)

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
            "observed_at": attribution.iso_utc(observed_at),
            # None, not os.getpid(). This used to stamp the *Monitor's own* PID
            # on every deletion it observed, with no confidence beside it - a
            # wrong answer in the shape of a right one, in the field whose whole
            # job is naming who did it. Ported from fix/evidence-integrity,
            # which found it the same way. Deletions are not attributed (a
            # delete is not a WriteData/AppendData access); the honest value is
            # that nobody has been named.
            "process_id": None,
            "process_image": None,
            "attribution_confidence": attribution.UNKNOWN,
            "attribution_reason": "not attempted: deletions are not attributed",
            "attribution_source": attributor.source.name,
            "user": "system",
        }
        event["detection_latency_ms"] = round((perf_counter() - started) * 1000, 3)
        _record(event)
        return event

    if not os.path.isfile(path):
        return None

    size, magic = _size_then_magic(path)
    if size is None:
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
    # Taken once by name - VALID / FORGED / INCOMPLETE / UNVALIDATED /
    # UNREADABLE - and projected to the tri-state the detector consumes. The
    # name is what goes in the ledger: the tri-state's None cannot tell "this
    # format has no validator" from "the validator ran and could not finish",
    # and that is the distinction an auditor needs after the fact.
    validation_state = container_status(head, tail, identify_container(magic), size)
    container_valid = tristate(validation_state)
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
        container_status=validation_state,
    )
    # Hashing a file we could not read only pays the retry cost again to reach
    # the same None, and it is on the sub-100ms detection path.
    file_hash, hashed_bytes = hash_file(path) if readable else (None, None)
    # The size recorded is the size of the content recorded beside it: the
    # hashed length where there is a hash, else the size after the read, and
    # either way whether it moved since the first look (F5, _size_after_read).
    if hashed_bytes is not None:
        recorded_size, size_changed = hashed_bytes, hashed_bytes != size
    else:
        recorded_size, size_changed = _size_after_read(path, size)
    # The last byte the verdict rests on has now been read. A write that landed
    # between the notification and this read produced some of what was judged,
    # so attribution's window runs up to here, not only up to `observed_at`.
    # Stamped twice: the system clock to compare with TimeCreated, and the
    # monotonic clock to time the delivery horizon from (attribution.WriteLog.lookup).
    read_at = time()
    read_mono = perf_counter()

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
        # The old name, for a rename; None otherwise. Carried because a
        # "rewrite, then rename to *.locked" attack is recorded under the new
        # name while its write happened under the old one, and an auditor
        # reading the chain needs both to follow it.
        "renamed_from": renamed_from,
        # verdict's entropy, not the raw one: it is None for a file we could not
        # read, where the raw value is a 0.0 that was never measured. The ledger
        # already records the verdict's value, so taking the raw one here made
        # /monitor/events and the ledger disagree about the same event.
        "entropy": verdict["entropy"],
        # The size of the content the hash below describes (F5).
        "file_size": recorded_size,
        "size_changed_during_read": size_changed,
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
        # NOVELTY_PROOF_PLAN.md §9 row 10 and TC-23: the record has to carry the
        # validation state and the policy version, not just the tri-state and
        # the outcome. Without the first, "no validator exists for this format"
        # and "the validator could not finish" are the same null. Without the
        # second, a decision cannot be re-derived, because the rule that made it
        # is an environment variable that is not written down anywhere.
        "validation_state": verdict["validation_state"],
        "policy_version": verdict["policy"],
        # Both of the model's top two features are decided here. Carrying them
        # on the event means a consumer scoring it later - the dashboard does -
        # reads the values that were actually measured instead of guessing them
        # back from the file path.
        "ransom_extension": verdict["ransom_extension"],
        "entropy_delta": entropy_delta,
        **statistics,
        "timestamp": utc_now(),
        # When watchdog handed this event over. `timestamp` is when the verdict
        # was recorded; the gap between the two is watchdog's own delivery, and
        # `detection_latency_ms` covers neither.
        "observed_at": attribution.iso_utc(observed_at),
        # How long correlation waited for its lane; None when there was nothing
        # to correlate (the event is not suspicious). 0.0 when it ran inline.
        "queue_wait_ms": None,
        # When the pipeline sent this incident's first response request; None
        # until it has (and for events that never need one).
        "response_dispatched_at": None,
        # watchdog reports *what* changed, never *who* changed it. The answer
        # comes from `attribution`, and it is filled in below rather than here
        # because resolving it may wait for an audit record still in flight.
        # An event that is not suspicious never asks, so the common path costs
        # nothing. Where no source is available these stay as they are and the
        # pipeline behaves exactly as it did before attribution existed.
        "process_id": None,
        "process_image": None,
        "attribution_confidence": attribution.UNKNOWN,
        "attribution_reason": "not attempted: event is not suspicious",
        "attribution_source": attributor.source.name,
        "user": "system",
    }
    event["detection_latency_ms"] = round((perf_counter() - started) * 1000, 3)

    # Correlation runs *after* the latency measurement, deliberately, and off
    # this thread when the caller gave it lanes. See `_correlate`.
    job = None
    if event["suspicious"]:
        features = {
            "shannon_entropy": entropy,
            "file_size": recorded_size,
            "magic_bytes": event["magic_bytes"],
            "modification_rate": round(min(1.0, entropy / 8.0), 2),
            "container_format": verdict["container_format"],
            "container_valid": container_valid,
            "ransom_extension": verdict["ransom_extension"],
            **statistics,
        }
        event.update(
            attribution_reason="pending: queued for correlation",
            attribution_pending=True,
        )

        def job(queue_wait_ms: float) -> None:
            _correlate(
                event, features, verdict, path, renamed_from,
                observed_at, read_at, read_mono, started, queue_wait_ms,
                epoch=epoch,
            )

    first_sighting = _record(event)

    if job is not None:
        if lanes is not None:
            lanes.submit(path, job)
        else:
            job(0.0)

    if BASELINE_LOGGING_ENABLED and PIPELINE_ENABLED and first_sighting and file_hash and not verdict["suspicious"]:
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

    if (
        PIPELINE_ENABLED
        and decision is not None
        and decision.get("admitted")
        and verdict["suspicious"]
    ):
        # The cancelled branch. `suppression is not None` above, so the event
        # never enters the pipeline and never reaches the chain - which is
        # exactly the audit gap P5.1 recorded as M-16 and Table 9.8 row 7
        # measured at 50%. The decision is chained on its own path: no
        # prediction, no response, because the alert was cancelled and acting on
        # it would defeat the operator's rule. What is preserved is the record
        # that a detection existed and which rule removed it.
        _work.put(("governance", event))

    return event


def _correlate(
    event: dict,
    features: dict,
    verdict: dict,
    path: str,
    renamed_from: str | None,
    observed_at: float,
    read_at: float,
    read_mono: float,
    started: float,
    queue_wait_ms: float,
    epoch: int = 0,
) -> None:
    """The first attribution look for one suspicious event, then the hand-off.

    Runs on the lane that owns the event's path (or inline, for a direct call).
    Attribution is response-budget work: waiting for the Security channel to
    deliver a 4663 is not detection, and charging it to Table 5.9's <100ms
    detection target would turn that target into a measurement of the event
    log's delivery lag.

    This is the *first* answer. Against a channel that delivers ~1 s late it is
    almost always pending: it drives the non-destructive response now, and the
    question stays open until the delivery horizon closes (`_open_question`).
    The grace is charged from when the event was *observed* - `started` is the
    observation on the performance counter - so an event that waited in its
    lane has already spent that much of it.

    A rename is looked up under both names. The VM's locker run - rewrite, then
    rename to *.locked - detected 20 of 20 and correlated 0 of 20, because the
    only audited write was on the old name and the lookup asked about the new
    one; the rename itself is not a WriteData/AppendData access, so there is no
    record for it and `parse_4663` is right to drop one. Asking about both also
    counts a writer of *either* name as a competitor, so a file renamed over one
    somebody else had just written is not CERTAIN.

    A further notification for a path whose incident's question is still open
    joins that incident and stops here (`_join_open_incident`, F6): no second
    question, no second set of blocks, no second response. `epoch` is the
    path's new-file sequence number when the notification arrived.
    """
    if _join_open_incident(event, path, renamed_from, epoch, observed_at, read_at, read_mono, queue_wait_ms):
        return
    also = (renamed_from,) if renamed_from else ()
    first = attributor.resolve(
        path,
        observed_at=observed_at,
        read_at=read_at,
        horizon_from=read_mono,
        deadline=started + attribution.GRACE_MS / 1000.0,
        also=also,
    )
    # A first answer that already authorises a kill (a source with no delivery
    # lag) is held to the same identity check as an escalation.
    first, _ = attributor.verify(first)
    with _LOCK:
        event.update(first.as_event_fields())
        event["queue_wait_ms"] = round(queue_wait_ms, 3)
        if PIPELINE_ENABLED:
            # Named now, so that a kill which comes before the pipeline has
            # reached this event still carries the incident it belongs to.
            event["incident_id"] = incident_id_for(event["event_id"])
    if PIPELINE_ENABLED:
        # The detection is queued before the question is opened, so the
        # escalation's ledger block - which goes through the same queue when
        # the question closes first - lands after this incident's own blocks.
        _work.put(("detection", event, features, verdict))
        parked = attributor.should_park(first)
        # Freeze-first: before the question is opened, so it cannot close
        # (and look for a lease) while the suspend is still being asked for -
        # the lease is registered before this returns, the request is made on
        # a thread of its own, and a close that comes meanwhile waits for it.
        suspend_policy.on_first_answer(
            attributor, event, first, path, (_watch_path,) if _watch_path else (), parked=parked, lock=_LOCK,
            background=True,
            # The question's horizon, on the horizon clock: no freeze starts after it.
            deadline=read_mono + attribution._settle_span_s(attributor.horizon_ms),
        )
        if parked:
            _open_question(event, path, observed_at, read_at, read_mono, first, also, epoch=epoch)


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
                elif kind == "governance":
                    _run_governance(client, *payload)
                elif kind == "escalation":
                    _run_escalation_record(client, *payload)
                else:
                    _run_detection(client, *payload)
            except Exception:  # a bad event must not kill the worker
                logger.exception("%s work failed for %s", kind, payload[0].get("file_path"))
            finally:
                _work.task_done()
    finally:
        client.close()


def _run_detection(client: httpx.Client, event: dict, features: dict, verdict: dict) -> None:
    try:
        outcome = pipeline.run(event, features, verdict, client=client)
        with _LOCK:
            event["pipeline"] = {"stages": outcome["stages"]}
            if outcome["ledger_block"]:
                event["block_id"] = outcome["ledger_block"].get("block_id")
            if outcome["prediction"]:
                event["prediction"] = outcome["prediction"].get("prediction")
                event["threat_level"] = outcome["prediction"].get("threat_level")
            if outcome.get("incident_id"):
                event["incident_id"] = outcome["incident_id"]
            if outcome.get("response_dispatched_at"):
                event["response_dispatched_at"] = outcome["response_dispatched_at"]
    finally:
        # The incident's own blocks are in the chain, or as far in as they are
        # going to get: an escalation closing from now on writes its block at
        # once rather than queueing it behind this one (`_Escalator`).
        _mark_in_chain(event.get("event_id"))


# ------------------------------------------------------- open attribution questions


def incident_id_for(event_id: str) -> str:
    """The incident a suspicious event opens, named at detection."""
    return "inc_" + event_id.removeprefix("evt_")


def _open_question(
    event: dict, path: str, observed_at: float, read_at: float, read_mono: float, first, also=(),
    epoch: int = 0,
) -> None:
    """Open the attribution question at detection, keyed by the incident.

    It used to be opened by the pipeline worker after ML, ledger and response
    had run for this event. The horizon clock already started at the read
    (`horizon_from=read_mono`), but a question that was not yet registered
    could not close, so behind a burst its kill waited for the whole backlog:
    6.92 s after the write on the VM (F2), 5.2 s twice before that.
    """
    question = attributor.question(
        key=event["incident_id"],
        path=path,
        observed_at=observed_at,
        read_at=read_at,
        first=first,
        also=also,
        context=event,
        horizon_from=read_mono,
    )
    with _ANCHORS_LOCK:
        _ANCHORS[event["event_id"]] = {"question": question, "in_chain": False}
        while len(_ANCHORS) > MAX_ANCHORS:
            _ANCHORS.popitem(last=False)
    # Registered before the question is added, so its close always finds it.
    incident = {
        "incident_id": event["incident_id"],
        "question": question,
        "event": event,
        "epoch": epoch,
        "read_mono": read_mono,
        "joined": [],
        "closed": False,
    }
    with _INCIDENTS_LOCK:
        # By path, for joining: the newest incident on a path is the joinable one.
        _OPEN_INCIDENTS[_path_key(path)] = incident
        _OPEN_INCIDENTS.move_to_end(_path_key(path))
        while len(_OPEN_INCIDENTS) > MAX_ANCHORS:
            _OPEN_INCIDENTS.popitem(last=False)
        # By question, for closing: an older incident on the same path still
        # hands its closing answer to the notifications that joined it.
        _INCIDENTS_BY_QUESTION[question.key] = incident
        while len(_INCIDENTS_BY_QUESTION) > MAX_ANCHORS:
            _INCIDENTS_BY_QUESTION.popitem(last=False)
    _ensure_pending().add(question)


def _path_key(path: str) -> str:
    """How two notifications are told to be about the same file: as attribution compares."""
    return os.path.normcase(path)


def _new_file_at(path: str, renamed_from: str | None = None) -> None:
    """A notification that can mean a different file is now at `path` (created,
    deleted, renamed): nothing seen after it joins an incident opened before it."""
    global _EPOCH_SEQ
    with _INCIDENTS_LOCK:
        for name in (path, renamed_from):
            if name:
                _EPOCH_SEQ += 1
                _FILE_EPOCHS[_path_key(name)] = _EPOCH_SEQ
                _FILE_EPOCHS.move_to_end(_path_key(name))
        while len(_FILE_EPOCHS) > 4 * MAX_ANCHORS:
            _FILE_EPOCHS.popitem(last=False)


def _file_epoch(path: str) -> int:
    with _INCIDENTS_LOCK:
        return _FILE_EPOCHS.get(_path_key(path), 0)


def _join_open_incident(
    event: dict,
    path: str,
    renamed_from: str | None,
    epoch: int,
    observed_at: float,
    read_at: float,
    read_mono: float,
    queue_wait_ms: float,
) -> bool:
    """Fold one notification into the open incident for its file, if there is one.

    Joins only when all of these hold, and otherwise the notification opens its
    own incident exactly as before:

      * it is a `modified` notification - a `created` or a rename is a new
        file at that name, and is never folded;
      * it read the same content the incident's first notification read (same
        hash): it re-reports that write. Different bytes are a further write,
        and get their own incident and their own `file_event` with their own
        hash, as before;
      * an incident for the same path has its question open (not closed), was
        opened since the last created/deleted/renamed notification for the
        path (`epoch`), and its first read was at most COALESCE_MS ago.

    Joining moves the question's read time and horizon to this notification's.
    The match window keeps its start, so the window now covers both reads, and
    the question closes one full horizon after the *later* read - a record for
    this notification's write, a second writer's included, arriving late but
    inside its horizon is still counted. The competition window is the union of
    both notifications' windows, so CERTAIN still means exactly one writer in
    all of it, and every write the question covers has had at least a full
    horizon to be reported (attribution, `_lookup_anchored`). The kill gate is
    not touched: it is the same `kill_authorised` on the closing answer.

    The horizon is moved before the read time. The pending sweep reads the read
    time before the horizon (`Attributor.recheck`), so a sweep running
    alongside sees either the old window or a longer horizon - never the wider
    window with the old horizon. A question cannot close at its horizon while
    it is joinable (COALESCE_MS is far shorter than the horizon); one closing
    early as `ambiguous` in the same instant ends with no kill whatever this
    notification adds.
    """
    if (
        not PIPELINE_ENABLED
        or renamed_from
        or event.get("event_type") != "modified"
        or not event.get("file_hash")
    ):
        return False
    with _INCIDENTS_LOCK:
        incident = _OPEN_INCIDENTS.get(_path_key(path))
        if (
            incident is None
            or incident["closed"]
            or incident["epoch"] != epoch
            or incident["event"].get("file_hash") != event["file_hash"]
            or (read_mono - incident["read_mono"]) * 1000.0 > COALESCE_MS
        ):
            return False
        question = incident["question"]
        if read_mono > question.horizon_from:
            span = question.settle_mono - question.horizon_from
            question.horizon_from = read_mono
            question.read_at = max(question.read_at, observed_at, read_at)
            question.settle_at = question.read_at + span
            question.settle_mono = read_mono + span
        incident["joined"].append(event)
        opener = incident["event"]
        incident_id = incident["incident_id"]
        joined_ids = [joined["event_id"] for joined in incident["joined"]]
    with _LOCK:
        opener["coalesced_event_ids"] = joined_ids
        event.update({
            key: opener.get(key)
            for key in ("process_id", "process_image", "attribution_confidence",
                        "attribution_candidates", "attribution_source", "attribution_pending")
        })
        event["attribution_reason"] = (
            f"joined incident {incident_id}, whose attribution question was open for this file "
            f"(opened by {opener['event_id']}); answered there"
        )
        event["incident_id"] = incident_id
        event["coalesced_into"] = incident_id
        event["queue_wait_ms"] = round(queue_wait_ms, 3)
    return True


def _close_incident(question, answer) -> None:
    """The question closed: nothing joins its incident any more, and every
    notification that joined it reports the closing answer."""
    with _INCIDENTS_LOCK:
        incident = _INCIDENTS_BY_QUESTION.get(question.key)
        if incident is None or incident["question"] is not question:
            return
        del _INCIDENTS_BY_QUESTION[question.key]
        incident["closed"] = True
        key = _path_key(question.path)
        if _OPEN_INCIDENTS.get(key) is incident:
            del _OPEN_INCIDENTS[key]
        joined = list(incident["joined"])
    if joined:
        fields = answer.as_event_fields()
        with _LOCK:
            for event in joined:
                event.update(fields)


def _mark_in_chain(event_id: str | None) -> None:
    with _ANCHORS_LOCK:
        anchor = _ANCHORS.get(event_id) if event_id else None
        if anchor is not None:
            anchor["in_chain"] = True


def _incident_in_chain(event: dict) -> bool:
    """Have this incident's own blocks been written (or never will be)?

    True for an event with no open question on record - a question evicted
    past MAX_ANCHORS, or one closed by a caller that never registered it -
    whose escalation block is then written at once, as before.
    """
    with _ANCHORS_LOCK:
        anchor = _ANCHORS.get(event.get("event_id")) if event.get("event_id") else None
        return anchor is None or anchor["in_chain"]


def _forget_question(event: dict) -> None:
    with _ANCHORS_LOCK:
        _ANCHORS.pop(event.get("event_id"), None)


def _ensure_pending() -> attribution.PendingAttribution:
    global _pending
    with _PENDING_LOCK:
        if _pending is None or _pending.attributor is not attributor:
            if _pending is not None:
                _pending.stop(timeout=1.0)
            _pending = attribution.PendingAttribution(
                attributor, _question_closed, on_recheck=_question_rechecked
            )
        if not _pending.running:
            _pending.start()
        return _pending


def _question_rechecked(question: attribution.Question, answer: attribution.Attribution) -> None:
    """The pending thread re-asked an open question and it now names a writer.

    The first look, at detection, usually names nobody - the audit record
    arrives 0.1-1.3 s after the write - so this is where freeze-first usually
    first sees a sole writer (`suspend_policy.on_first_answer`, the same hook
    `_correlate` calls). Runs on the pending thread, which must keep closing
    questions on time, so the suspend request is made on its own thread.
    """
    event = question.context if isinstance(question.context, dict) else None
    if event is None:
        return
    suspend_policy.on_first_answer(
        attributor, event, answer, question.path, (_watch_path,) if _watch_path else (),
        parked=True, lock=_LOCK, incident_id=question.key, background=True,
        deadline=question.settle_mono,
    )


def _question_closed(question: attribution.Question, answer: attribution.Attribution, outcome: str) -> None:
    """The pending thread's close callback: end the incident's joining, then escalate."""
    try:
        _close_incident(question, answer)
    finally:
        _on_question_closed(question, answer, outcome)


def _on_question_closed(question: attribution.Question, answer: attribution.Attribution, outcome: str) -> None:
    """Runs on the pending thread, so it only hands the work on."""
    _ensure_escalator()
    _escalations.put((question, answer, outcome))


class _KillLanes:
    """Closed questions that authorise a kill, one FIFO lane per PID.

    At most one question per PID is out at a time, so one process never has
    two terminates in flight and its later questions see what its earlier one
    found (`pipeline.TERMINATIONS`). Lanes with work are taken in turn: a
    fresh PID waits for at most the requests already in flight, not for every
    later question about a PID ahead of it. Keyed by PID alone, which is
    stricter than PID plus start time: the Response service kills by PID.
    Empty lanes are dropped, so this holds only what is queued.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._lanes: dict[int, deque] = {}
        self._ready: deque[int] = deque()
        self._busy: set[int] = set()
        self._closed = False

    def put(self, pid: int, item: tuple) -> None:
        with self._cond:
            lane = self._lanes.setdefault(pid, deque())
            if not lane and pid not in self._busy:
                self._ready.append(pid)
            lane.append(item)
            self._cond.notify()

    def take(self) -> tuple[int, tuple] | None:
        """The next PID's next question, or None once closed and nothing is ready."""
        with self._cond:
            while not self._ready:
                if self._closed:
                    return None
                self._cond.wait()
            pid = self._ready.popleft()
            self._busy.add(pid)
            return pid, self._lanes[pid].popleft()

    def done(self, pid: int) -> None:
        with self._cond:
            self._busy.discard(pid)
            if self._lanes.get(pid):
                self._ready.append(pid)
                self._cond.notify()
            else:
                self._lanes.pop(pid, None)

    def close(self) -> None:
        """Workers drain what is queued, then stop."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def __len__(self) -> int:
        with self._cond:
            return sum(len(lane) for lane in self._lanes.values())


class _Escalator(threading.Thread):
    """Take each closed question's action now; write its block as soon as it may go.

    The kill a CERTAIN answer authorises goes out the moment the question
    closes. Its `attribution_escalation` block has to follow the incident's
    first `response_action` block, which the pipeline worker writes; if that
    has not happened yet - a burst has `_work` running behind - the block is
    queued on `_work` behind it (it is FIFO, and the incident's detection was
    queued before its question opened), and only the block waits.

    A process this Monitor has already had killed is not asked about again
    (`pipeline.TERMINATIONS`, defect 22), and one whose kill went unconfirmed
    too often for a write is not asked again about that write (R-RACE (b)).

    Three kinds of thread, so that no kill waits on a ledger write (R-RACE (c),
    (d)) or on another PID's later questions:
    - this one (`monitor-escalation-intake`) only reads `_escalations` and
      routes: a question that authorises a kill to its PID's lane
      (`_KillLanes`), any other straight to the writer. It does no I/O;
    - `KILL_WORKERS` kill workers take the action (`pipeline.escalation_action`)
      and hand the result to the writer;
    - the writer (`monitor-escalation`) builds the one HTTP client they all
      share when the watch starts, and writes each block - or queues it on
      `_work` - in the order the actions finish. A question with no kill to
      take is closed there by `pipeline.escalate`, which then makes no request.
    A question is `task_done` only once its block is written or queued. The
    sentinel None stops it: every question already taken is acted on, every
    block owed is written, and all of its threads have exited before the
    sentinel is `task_done`.
    """

    def __init__(self, inbox: queue.Queue, workers: int) -> None:
        super().__init__(name="monitor-escalation-intake", daemon=True)
        self.inbox = inbox
        self.client: httpx.Client | None = None
        self.client_ready = threading.Event()
        self.lanes = _KillLanes()
        self.owed: queue.Queue = queue.Queue(maxsize=MAX_OWED_BLOCKS)
        self.writer = threading.Thread(target=self._write, name="monitor-escalation", daemon=True)
        self.workers = [
            threading.Thread(target=self._kill, name=f"monitor-escalation-kill-{n}", daemon=True)
            for n in range(max(1, int(workers)))
        ]

    def threads(self) -> list[threading.Thread]:
        return [self, self.writer, *self.workers]

    def run(self) -> None:
        self.writer.start()
        for worker in self.workers:
            worker.start()
        while True:
            item = self.inbox.get()
            if item is None:
                break
            self._route(item)
        # What was put before the sentinel was seen is still handled.
        while True:
            try:
                item = self.inbox.get_nowait()
            except queue.Empty:
                break
            if item is None:
                self.inbox.task_done()
            else:
                self._route(item)
        self.lanes.close()
        for worker in self.workers:
            worker.join()
        self.owed.put(None)
        self.writer.join()
        self.inbox.task_done()

    def _route(self, item: tuple) -> None:
        try:
            _, answer, _ = item
            if getattr(answer, "kill_authorised", False):
                self.lanes.put(int(answer.pid), item)
                return
        except Exception:  # a malformed item still gets closed, by the writer
            logger.exception("escalation could not be routed")
        self.owed.put(("escalate", item))

    def _kill(self) -> None:
        pipeline.bind_escalation_thread(_probe_for_escalation)
        self.client_ready.wait()
        while True:
            taken = self.lanes.take()
            if taken is None:
                return
            pid, item = taken
            # A worker that died would silently shrink the pool, and its question
            # would never be `task_done`. `_escalation_act` already contains its
            # own failures; this is for anything it did not foresee. The PID's
            # lane is always released, and the question is closed without a block
            # rather than left open.
            done = None
            try:
                done = _escalation_act(self.client, item)
            except Exception:
                logger.exception("kill worker: escalation failed unexpectedly")
            finally:
                self.lanes.done(pid)
            try:
                if done is None:
                    self.inbox.task_done()
                else:
                    self.owed.put(("record", done))
            except Exception:
                logger.exception("kill worker: could not hand a result on")

    def _write(self) -> None:
        try:
            self.client = httpx.Client(timeout=pipeline.DOWNSTREAM_TIMEOUT)
        finally:
            self.client_ready.set()
        try:
            while True:
                entry = self.owed.get()
                if entry is None:
                    return
                kind, payload = entry
                try:
                    if kind == "escalate":
                        _escalate_one(self.client, payload)
                    else:
                        _escalation_record(self.client, *payload)
                finally:
                    self.inbox.task_done()
        finally:
            if self.client is not None:
                self.client.close()


def _escalate_one(client: httpx.Client, item: tuple) -> None:
    """A question with no kill to take: its (empty) action, then its block if it can go now."""
    question, answer, outcome = item
    event = question.context if isinstance(question.context, dict) else {}
    try:
        if _incident_in_chain(event):
            closed = pipeline.escalate(client, event, question, answer, outcome)
            _show_closed(event, question, answer, outcome, closed["record"], closed["block"])
            _forget_question(event)
        else:
            done = _escalation_act(client, item)
            if done is not None:
                _work.put(("escalation", *done))
    except Exception:  # a bad escalation must not kill the worker
        logger.exception("escalation failed for %s", event.get("file_path"))


def _escalation_act(client: httpx.Client, item: tuple):
    """One closed question's action, taken now. None if it failed."""
    question, answer, outcome = item
    event = question.context if isinstance(question.context, dict) else {}
    try:
        action = pipeline.escalation_action(client, question, answer)
        _show_closed(event, question, answer, outcome,
                     {"result": pipeline.escalation_result(answer, action),
                      "response_dispatched_at": action["response_dispatched_at"],
                      "suspension": action.get("lease")}, None)
        return event, question, answer, outcome, action
    except Exception:  # a bad escalation must not kill the worker
        logger.exception("escalation failed for %s", event.get("file_path"))
        return None


def _escalation_record(client: httpx.Client, event: dict, question, answer, outcome: str, action: dict) -> None:
    """Its block: now if the incident's own blocks are in the chain, else behind them."""
    try:
        if _incident_in_chain(event):
            _run_escalation_record(client, event, question, answer, outcome, action)
        else:
            _work.put(("escalation", event, question, answer, outcome, action))
    except Exception:  # a bad block must not kill the worker
        logger.exception("escalation block failed for %s", event.get("file_path"))


def _probe_for_escalation(pid: int):
    """The current attributor's probe, looked up per call (it can be replaced)."""
    return attributor.probe(pid)


def _show_closed(event: dict, question, answer, outcome: str, record: dict, block: dict | None) -> None:
    """The event now carries the closing answer, and says what the first was.

    `/monitor/events` should show where the incident ended up, not where it
    started - as soon as the action is taken, with the block ID filled in when
    the block is written.
    """
    with _LOCK:
        event.update(answer.as_event_fields())
        event["attribution_escalation"] = {
            "outcome": outcome,
            "result": record["result"],
            "initial_attribution_confidence": question.first.confidence,
            "initial_attribution_reason": question.first.reason,
            "block_id": (block or {}).get("block_id"),
            "response_dispatched_at": record["response_dispatched_at"],
        }
        if record.get("suspension"):
            # Freeze-first: what became of the lease this incident's writer was held under.
            event["attribution_escalation"]["suspension"] = record["suspension"]


def _run_escalation_record(client: httpx.Client, event: dict, question, answer, outcome: str, action: dict) -> None:
    """On the pipeline worker, after the incident's own blocks: the block."""
    try:
        closed = pipeline.record_escalation(client, event, question, answer, outcome, action)
        _show_closed(event, question, answer, outcome, closed["record"], closed["block"])
    finally:
        _forget_question(event)


def _ensure_escalator() -> None:
    """Start the escalation thread if it is not running.

    `_ensure_worker` calls this when the watch starts. It used to be called
    only when the first question *closed*, and the thread's first act is to
    build its httpx.Client - an SSL context and the CA bundle - so the first
    kill of every Monitor run paid for that construction after the delivery
    horizon, on the one stretch of the path with a deadline. Traced in the end
    to end test (test_e_a_fresh_writer...): the question closed at +1580 ms and
    /response/terminate went out at +1767 ms, the 187 ms between them being
    that construction; an untraced run of the same test missed the 2 s budget
    at +2134 ms. On the same 4-vCPU host, loaded enough that the base commit's
    own latency benchmarks were failing, eight constructions took 311-1545 ms
    (median 735).

    Started with the watch, the client is built while nothing is due: an
    escalated kill cannot be due until one horizon after the first event. It
    is still built on the new thread rather than here, so /monitor/start does
    not wait for it - the gateway proxies that call with a 5 s timeout, and two
    constructions at the loaded figures above would take most of it. The call
    in `_on_question_closed` stays, as a backstop for a thread that died.
    """
    global _escalator
    with _ESCALATOR_LOCK:
        if _escalator is None or not _escalator.is_alive():
            _escalator = _Escalator(_escalations, KILL_WORKERS)
            _escalator.start()


def _run_governance(client: httpx.Client, event: dict) -> None:
    block = pipeline.log_governance_decision(client, event)
    if block:
        with _LOCK:
            event["governance_block_id"] = block.get("block_id")


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
    # With the worker, when the watch starts, rather than when the first
    # question closes - see _ensure_escalator for what that cost.
    _ensure_escalator()
    # The same reasoning for the freeze-first client: its construction must not
    # be paid by the first suspend, the one that matters most.
    suspend_policy.warm()


class MonitorHandler(FileSystemEventHandler):
    """Runs on watchdog's observer thread, so it hands correlation to the lanes."""

    def on_created(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "created", lanes=_lanes)

    def on_modified(self, event):
        if not event.is_directory:
            handle_event(event.src_path, "modified", lanes=_lanes)

    def on_moved(self, event):
        # Both names. The new one is what the event is about; the old one is
        # where a rewrite-then-rename attack's audited write is (_correlate).
        if not event.is_directory:
            handle_event(event.dest_path, "renamed", renamed_from=event.src_path, lanes=_lanes)

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

    # Normalised before anything uses it: watchdog builds every event path from
    # this prefix, so this is where one spelling for the whole run starts.
    watch_path = normalise_path(payload.watch_path)

    if not os.path.isdir(watch_path):
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
    _lanes.start()
    # A stop paused freeze-first (stop_monitoring); a start lifts it.
    suspend_policy.unpause()

    _observer, _observer_backend, _observer_reason = build_observer(watch_path)
    _observer.schedule(MonitorHandler(), watch_path, recursive=payload.recursive)
    _observer.start()
    logger.info("watching %s with the %s backend: %s", watch_path, _observer_backend, _observer_reason)

    _monitor_id = f"mon_{uuid4().hex[:6]}"
    _watch_path = watch_path
    _file_patterns = list(payload.file_patterns)
    STARTED_AT = time()

    # Attribution starts with the watch, not at import, so a test that imports
    # this module does not open a Security-channel subscription. Failure here
    # is not a failure to monitor: without a source every event is UNKNOWN and
    # the pipeline isolates instead of terminating, which is what it did
    # before. The reason is logged once and served from /monitor/attribution.
    if not attributor.available:
        attributor.start(build_source(attributor.log))
        if attributor.available:
            logger.info("attribution active via %s", attributor.source.name)
        else:
            logger.warning(
                "attribution unavailable (%s); responses will isolate rather than terminate",
                attributor.source.error,
            )

    logger.info("monitoring %s (recursive=%s) as %s", _watch_path, payload.recursive, _monitor_id)
    return JSONResponse(
        content={
            "status": "monitoring",
            "monitor_id": _monitor_id,
            "watch_path": _watch_path,
            "recursive": payload.recursive,
            "file_patterns": payload.file_patterns,
            "start_time": utc_now(),
            "attribution_available": attributor.available,
            "attribution_source": attributor.source.name,
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

    # First, so that nothing is frozen after this returns - the sweeper's re-ask of a
    # question still open included. `/monitor/start` lifts it.
    suspend_policy.pause()
    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None
    # After the observer, so nothing new arrives; finishing what is queued
    # means every detection already seen still gets its response.
    _lanes.stop(timeout=5)
    # Nothing stays frozen because this Monitor stopped: every lease it holds
    # is released now (best effort, short; the Response service's lease expiry
    # is the backstop). A question still open when this runs closes later and
    # kills, if the unchanged gate says so, without a lease.
    suspend_policy.release_all("monitor_stop")

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
        # Whether this Monitor can name the process behind an alert. Reported
        # here because an unattributed incident and an incident whose attacker
        # was identified and spared look identical from `/monitor/events`
        # otherwise.
        "attribution_available": attributor.available,
        "attribution_source": attributor.source.name,
        # The correlation lanes: how deep they got, how long jobs waited, and
        # how many ran inline because a lane was full. A burst that backs up
        # shows here rather than as silently late responses.
        "correlation": _lanes.stats(),
    }


@app.get("/monitor/attribution")
def monitor_attribution() -> dict:
    """What the attribution layer can and cannot currently do, and why.

    The failure modes here are all configuration - not elevated, audit policy
    off, no SACL on the watched tree - and every one of them looks from the
    outside like a quiet filesystem. This endpoint is what makes the difference
    legible without reading the Monitor's logs.
    """
    status = attributor.status()
    status["setup"] = (
        "powershell -ExecutionPolicy Bypass -File scripts/setup_attribution_audit.ps1 "
        "-WatchPath <dir>   (Administrator)"
    )
    # Questions kept open past the first answer, and how each one closed. An
    # incident isolated on a pending answer and never escalated shows up here as
    # a close outcome rather than as silence.
    status["pending"] = _pending.stats() if _pending is not None else {"running": False, "open": 0}
    # Freeze-first (suspend_policy): whether it is on, and what it has done.
    status["suspend_first"] = suspend_policy.stats()
    return status


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
