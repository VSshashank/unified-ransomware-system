"""URDS Response service (port 8004).

    POST /response/terminate  kill a process by PID (releases its lease, if any)
    POST /response/suspend    freeze a process under a lease (defect 26, F2b)
    POST /response/resume     end a lease and resume the process
    GET  /response/leases     held leases, then recently ended ones
    POST /response/isolate    apply (or plan) network isolation
    POST /response/trigger    orchestrate the reaction to one incident
    POST /response/recover    restore files from a snapshot  (SI, recovery/)
    GET  /health              liveness for docker-compose and the gateway

Terminate/isolate/trigger are AS's; everything under `recovery/` is SI's and is
mounted here unchanged.
"""

import atexit
import logging
import math
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

import leases as lease_module
from actions import (
    SuspendRefused,
    TerminationError,
    isolate_host,
    resume_process,
    suspend_process,
    terminate_process,
    vet_suspend,
)
from lease_watchdog import Watchdog

# SI: recovery module. Owns /response/recover and the VSS snapshot schedule.
from recovery.recovery import router as recovery_router
from recovery.vss_manager import VSSManager

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("response")

LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger:8003").rstrip("/")
LEDGER_TIMEOUT = float(os.getenv("LEDGER_TIMEOUT", "3.0"))

_vss_manager = VSSManager()

#: The out-of-process backstop that resumes held leases if this process dies
#: without running its shutdown. On by default; `RESPONSE_LEASE_WATCHDOG=0`
#: turns it off, and then a hard crash mid-lease can leave a process frozen
#: (logged at startup). While it is on but not running, suspends are refused.
WATCHDOG_ENABLED = os.getenv("RESPONSE_LEASE_WATCHDOG", "1").strip().lower() not in {"0", "false", "no", "off"}


def build_lease_table(**overrides) -> lease_module.LeaseTable:
    options = {
        "resume": resume_process,
        "watchdog": Watchdog() if WATCHDOG_ENABLED else None,
        "on_end": lambda lease: record_lease_end(lease),
    }
    options.update(overrides)
    return lease_module.LeaseTable(**options)


#: Every suspension this service holds. Replaced wholesale in tests.
LEASES = build_lease_table()


def _resume_everything_at_exit() -> None:
    """`atexit` backstop for a shutdown that skipped the lifespan hook."""
    try:
        LEASES.shutdown(reason="response_exit", by="atexit")
    except Exception:  # interpreter teardown; nothing left to report to
        pass


atexit.register(_resume_everything_at_exit)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Snapshot every 6 hours. On non-Windows hosts - including this Linux
    # container - this logs why it cannot run and returns False; startup
    # continues either way.
    _vss_manager.start_scheduler()
    # The ledger client is built now, off the request path, so the first kill's
    # block does not pay for it (see `_ledger_client`). On its own thread, so
    # startup does not wait for it either.
    threading.Thread(target=_ledger_client, name="response-ledger-client", daemon=True).start()
    table = LEASES
    table.start()
    if table.watchdog is None:
        logger.warning("lease watchdog disabled: a hard crash while a lease is held can leave that process suspended")
    try:
        yield
    finally:
        # Nothing stays frozen because this service stopped, and nothing new
        # is suspended once it has begun to stop.
        table.shutdown(reason="response_shutdown", by="shutdown")
        _vss_manager.stop_scheduler()


app = FastAPI(title="URDS Response", version="1.0.0", lifespan=lifespan)
app.include_router(recovery_router)


class TerminateRequest(BaseModel):
    process_id: int
    incident_id: str
    reason: str
    force: bool = True
    # What authorised the kill, when attribution did: the Monitor's escalation
    # sends `certain` and its source. Recorded on the block so the chain says
    # on what evidence a process was killed. A kill asked for without them -
    # an operator's, through the gateway, which does not forward them - is
    # recorded with none, and the C-16 scan reports that block as naming a
    # process without attribution (scripts/ledger_coverage.py).
    attribution_confidence: str | None = None
    attribution_source: str | None = None
    # The lease the process is held under, when it was suspended first. The
    # kill closes that lease (it ends "terminated", not resumed). Absent, any
    # lease held for this PID is closed anyway: the process is gone.
    lease_id: str | None = None


class SuspendRequest(BaseModel):
    process_id: int
    incident_id: str = Field(min_length=1)
    # About the attribution horizon plus a margin; capped at
    # RESPONSE_LEASE_MAX_SECONDS. The lease ends - and the process resumes -
    # when it runs out, whatever happened to the caller.
    # Finite: NaN and Infinity are a 400, not a 500 (review finding R8).
    lease_seconds: float = Field(gt=0, allow_inf_nan=False)
    reason: str
    # What the caller says the attribution was. Required, and recorded on
    # every block naming the PID - as the caller's claim, which this service
    # cannot check (`attribution_supplied_by: "caller"`).
    attribution_confidence: str = Field(min_length=1)
    attribution_source: str = Field(min_length=1)
    attribution_reason: str = Field(min_length=1)
    # The gate the caller says allowed the suspend (e.g. "suspend_authorised"
    # from a Monitor that evaluates one). Optional. Recorded verbatim with
    # `gate_verified: false`; absent, the block says `gate: null` and why. This
    # service evaluates no gate of its own and never writes one (review
    # finding R8c).
    gate: str | None = None
    # The identity attribution named. At least one must be checkable against
    # the live process, or the suspend is refused.
    image: str | None = None
    # The process's creation time (epoch seconds or ISO-8601). A live process
    # created after it is a reused PID.
    started_at: float | str | None = None


class ResumeRequest(BaseModel):
    lease_id: str | None = None
    process_id: int | None = None
    incident_id: str
    reason: str


class IsolateRequest(BaseModel):
    isolation_level: str = "full"
    duration_seconds: int = 300
    allow_localhost: bool = True


class TriggerRequest(BaseModel):
    incident_id: str
    process_id: int
    threat_level: str
    action_required: str
    # The Monitor's adjudication, carried through so the Response service's own
    # ledger entry records why the alert survived to reach it. Optional, so a
    # caller that predates the governance layer still validates.
    admissibility: dict | None = None
    # How the offending PID was arrived at. The Monitor has already applied the
    # kill gate before choosing `action_required`; these are recorded here so
    # the Response service's own ledger entry says on what evidence it killed,
    # rather than leaving an auditor to join two chains on a timestamp.
    # Optional, so a caller that predates attribution still validates.
    attribution_confidence: str | None = None
    attribution_reason: str | None = None
    process_image: str | None = None
    # Every PID whose audited write fell in the window: the evidence behind a
    # PROBABLE answer. Recorded instead of `process_id` when nothing is killed.
    attribution_candidates: list[int] | None = None


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
        content=build_error("BAD_REQUEST", "Request validation failed", {"errors": _json_safe(exc.errors())}),
    )


def _json_safe(value):
    """A validation error, made serialisable.

    `exc.errors()` echoes the input and can carry the exception itself: a NaN
    `lease_seconds` came back as a float JSON cannot hold, and the handler
    turned a 400 into a 500 (review finding R8). Non-finite floats and
    anything not JSON-native become strings.
    """
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 500: "INTERNAL_SERVER_ERROR"}.get(
        exc.status_code, "REQUEST_FAILED"
    )
    return JSONResponse(status_code=exc.status_code, content=build_error(code, str(exc.detail)))


# One client for every ledger write, built once. `log_action` used to call
# `httpx.post`, which builds a client - an SSL context and certifi's CA bundle -
# per call: 200 ms of the 252 ms the terminate handler took to refuse a dead PID
# on the VM, and the reason R16's refused escalations went out 0.30-0.38 s apart
# (FIXES.md, defect 22). httpx.Client is safe to share across FastAPI's worker
# threads.
_LEDGER_CLIENT: httpx.Client | None = None
_LEDGER_CLIENT_LOCK = threading.Lock()


def _ledger_client() -> httpx.Client:
    global _LEDGER_CLIENT
    with _LEDGER_CLIENT_LOCK:
        if _LEDGER_CLIENT is None:
            _LEDGER_CLIENT = httpx.Client(timeout=LEDGER_TIMEOUT)
        return _LEDGER_CLIENT


def log_action(event_type: str, event_data: dict) -> dict | None:
    """Best-effort ledger write. A response that happened must be recorded, but
    an unreachable ledger must not stop the next action from being taken."""
    try:
        response = _ledger_client().post(
            f"{LEDGER_URL}/ledger/log",
            json={"event_type": event_type, "event_data": event_data},
            timeout=LEDGER_TIMEOUT,
        )
        if response.status_code < 400:
            return response.json()
        logger.warning("ledger rejected %s: %s", event_type, response.text[:200])
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("ledger unreachable for %s: %s", event_type, exc)
    return None


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "response"}


@app.post("/response/terminate")
def terminate(payload: TerminateRequest) -> JSONResponse:
    try:
        result = terminate_process(payload.process_id, force=payload.force)
    except TerminationError as exc:
        # A refused kill leaves any lease alone: the process is still held and
        # still resumes when the lease runs out.
        log_action(
            "response_action",
            {
                "action": "terminate",
                "incident_id": payload.incident_id,
                "process_id": payload.process_id,
                "attribution_confidence": payload.attribution_confidence,
                "attribution_source": payload.attribution_source,
                "lease_id": payload.lease_id,
                "reason": payload.reason,
                "outcome": "refused",
                "detail": str(exc),
                "timestamp": utc_now(),
            },
        )
        return JSONResponse(
            status_code=409,
            content=build_error(
                "TERMINATION_REFUSED", str(exc), {"process_id": payload.process_id}
            ),
        )

    # The process is gone: close whatever lease held it, without resuming.
    ended = LEASES.end_for_terminate(payload.process_id)
    lease_note = None
    if payload.lease_id and (ended is None or ended.lease_id != payload.lease_id):
        known = LEASES.get(payload.lease_id)
        if known is None:
            lease_note = f"lease {payload.lease_id} is unknown to this service; no lease was released"
        elif known.process_id != payload.process_id:
            lease_note = (f"lease {payload.lease_id} is for pid {known.process_id}, not {payload.process_id}; "
                          "it was left as it is")
        else:
            lease_note = (f"lease {payload.lease_id} had already ended {known.state} "
                          f"({known.ended_by}: {known.ended_reason})")

    log_action(
        "response_action",
        {
            "action": "terminate",
            "incident_id": payload.incident_id,
            "process_id": payload.process_id,
            "attribution_confidence": payload.attribution_confidence,
            "attribution_source": payload.attribution_source,
            "lease_id": ended.lease_id if ended else payload.lease_id,
            "lease_released": ended is not None,
            "process_name": result["process_name"],
            "reason": payload.reason,
            "outcome": "terminated",
            "method": result["method"],
            "termination_time_ms": result["termination_time_ms"],
            "timestamp": result["timestamp"],
        },
    )
    body = {
        **result,
        "incident_id": payload.incident_id,
        "lease_id": ended.lease_id if ended else payload.lease_id,
        "lease_released": ended is not None,
    }
    if lease_note:
        body["lease_note"] = lease_note
    return JSONResponse(content=body)


# ------------------------------------------------------------- suspend / resume


def _suspended_block(payload: SuspendRequest, **fields) -> dict:
    """A `process_suspended` block. It names the PID, so it carries what the
    caller said allowed it - as the caller's claim, never as a verdict of this
    service's (`gate_verified: false`)."""
    return {
        "action": "suspend",
        "incident_id": payload.incident_id,
        "process_id": payload.process_id,
        "process_image": payload.image,
        "attribution_confidence": payload.attribution_confidence,
        "attribution_source": payload.attribution_source,
        "attribution_reason": payload.attribution_reason,
        **lease_module.gate_record(payload.gate),
        "reason": payload.reason,
        "lease_seconds_requested": payload.lease_seconds,
        **fields,
        "timestamp": utc_now(),
    }


def _resumed_block(lease, *, reason: str, requested_by: str, requested_incident_id: str | None = None) -> dict:
    """A `process_resumed` block, joined to the suspend and the terminate by lease and incident."""
    resumed = lease.state == lease_module.RESUMED
    return {
        "action": "resume",
        "lease_id": lease.lease_id,
        "incident_id": lease.incident_id,
        "requested_incident_id": requested_incident_id,
        "process_id": lease.process_id,
        "process_image": lease.image,
        **lease.gate_fields(),
        "resumed": resumed,
        "outcome": "resumed" if resumed else "process_gone",
        "requested_by": requested_by,
        "reason": reason,
        "held_ms": lease.held_ms,
        "timestamp": utc_now(),
    }


def record_lease_end(lease) -> None:
    """A lease ended without a caller asking: expiry, shutdown, or the process vanished."""
    if lease.state not in (lease_module.RESUMED, lease_module.GONE):
        return
    log_action(
        "process_resumed",
        _resumed_block(lease, reason=lease.ended_reason or "", requested_by=lease.ended_by or "unknown"),
    )


def _refusal(payload: SuspendRequest, code: str, message: str) -> JSONResponse:
    log_action(
        "process_suspended",
        _suspended_block(payload, outcome="refused", suspended=False, lease_id=None, code=code, detail=message),
    )
    envelope = build_error(code, message, {"process_id": payload.process_id})
    # The project's error envelope, with the contract's flat {code, message}
    # beside it, so a caller can read either.
    return JSONResponse(status_code=409, content={"code": code, "message": message, **envelope})


@app.post("/response/suspend")
def suspend(payload: SuspendRequest) -> JSONResponse:
    if payload.attribution_confidence.strip().lower() == "unknown":
        return _refusal(
            payload, "NOT_ATTRIBUTED",
            f"attribution is 'unknown': nothing named PID {payload.process_id}; refusing to suspend",
        )
    table = LEASES
    try:
        lease, already = table.acquire(
            payload.process_id,
            incident_id=payload.incident_id,
            lease_seconds=payload.lease_seconds,
            reason=payload.reason,
            attribution_confidence=payload.attribution_confidence,
            attribution_source=payload.attribution_source,
            attribution_reason=payload.attribution_reason,
            gate=payload.gate,
            vet=lambda: vet_suspend(payload.process_id, payload.image, payload.started_at,
                                    extra_protected=table.protected_pids()),
            suspend=suspend_process,
        )
    except (SuspendRefused, lease_module.LeaseError) as exc:
        return _refusal(payload, exc.code, str(exc))

    if not already:
        # A second suspend of a held PID suspends nothing and records nothing.
        log_action(
            "process_suspended",
            _suspended_block(
                payload,
                outcome="suspended",
                suspended=True,
                lease_id=lease.lease_id,
                process_image=lease.image or payload.image,
                process_started_at=lease.started_at,
                lease_seconds=lease.lease_seconds,
                expires_at=lease.expires_at,
            ),
        )
    return JSONResponse(
        content={
            "lease_id": lease.lease_id,
            "process_id": lease.process_id,
            "suspended": True,
            "expires_at": lease.expires_at,
            "already_held": already,
            "incident_id": lease.incident_id,
            "lease_seconds": lease.lease_seconds,
        }
    )


@app.post("/response/resume")
def resume(payload: ResumeRequest) -> JSONResponse:
    if not payload.lease_id and payload.process_id is None:
        return JSONResponse(
            status_code=400,
            content=build_error("BAD_REQUEST", "one of lease_id or process_id is required"),
        )
    try:
        lease, resumed, ended_now = LEASES.release(
            lease_id=payload.lease_id, process_id=payload.process_id, reason=payload.reason, by="caller"
        )
    except Exception as exc:  # the resume itself failed; the lease stays held and still expires
        return JSONResponse(
            status_code=409,
            content=build_error(
                "RESUME_FAILED", str(exc), {"lease_id": payload.lease_id, "process_id": payload.process_id}
            ),
        )

    if ended_now:
        log_action(
            "process_resumed",
            _resumed_block(lease, reason=payload.reason, requested_by="caller",
                           requested_incident_id=payload.incident_id),
        )

    body = {
        "lease_id": lease.lease_id if lease else payload.lease_id,
        "resumed": resumed,
        "reason": payload.reason,
        "process_id": lease.process_id if lease else payload.process_id,
        "state": lease.state if lease else "unknown",
    }
    if not resumed:
        if lease is None:
            body["detail"] = "no lease is held for this process or lease id; nothing was resumed"
        else:
            body["detail"] = f"the lease ended {lease.state} ({lease.ended_by}: {lease.ended_reason})"
    return JSONResponse(content=body)


@app.get("/response/leases")
def list_leases() -> JSONResponse:
    return JSONResponse(content=LEASES.list())


@app.post("/response/isolate")
def isolate(payload: IsolateRequest) -> JSONResponse:
    result = isolate_host(
        level=payload.isolation_level,
        duration_seconds=payload.duration_seconds,
        allow_localhost=payload.allow_localhost,
    )
    log_action(
        "response_action",
        {
            "action": "isolate",
            "isolation_level": payload.isolation_level,
            "outcome": result["status"],
            "enforced": result["enforced"],
            "backend": result["backend"],
            "reason": result["reason"],
            "timestamp": result["timestamp"],
        },
    )
    return JSONResponse(content=result)


@app.post("/response/trigger")
def trigger(payload: TriggerRequest) -> JSONResponse:
    """One incident in, the full reaction out.

    Actions are attempted in severity order and each records what actually
    happened - `actions_taken` only lists work that succeeded.
    """
    actions_taken: list[str] = []
    details: dict = {}
    kill_requested = payload.action_required == "terminate_process"

    if kill_requested:
        # Attempt it even for an implausible PID: the guard's refusal reason is
        # what makes the incident record explain why nothing was killed.
        try:
            details["terminate"] = terminate_process(payload.process_id, force=True)
            actions_taken.append("process_terminated")
        except TerminationError as exc:
            details["terminate"] = {"status": "refused", "reason": str(exc)}
    elif payload.process_id <= 1:
        details["terminate"] = {
            "status": "skipped",
            "reason": "no offending PID was attributed to this event; see /monitor/events",
        }

    if payload.threat_level in {"high", "critical"}:
        isolation = isolate_host(level="full", duration_seconds=300, allow_localhost=True)
        details["isolate"] = isolation
        actions_taken.append("network_isolated" if isolation["enforced"] else "network_isolation_planned")

    actions_taken.append("admin_notified")

    block = log_action(
        "response_action",
        {
            "action": "trigger",
            "incident_id": payload.incident_id,
            # The PID only when a kill was asked for: it is then the target, and
            # the block says what was done to it. Otherwise the caller's PID is
            # a candidate, not an identification, and goes in the candidates
            # (C-16, scripts/ledger_coverage.py). A process_id of 0 - "nobody
            # was attributed" - used to be recorded as the number 0.
            "process_id": payload.process_id if kill_requested else None,
            "attribution_candidates": (
                list(payload.attribution_candidates)
                if payload.attribution_candidates is not None
                else ([payload.process_id] if payload.process_id > 0 and not kill_requested else [])
            ),
            "process_image": payload.process_image,
            "attribution_confidence": payload.attribution_confidence,
            "attribution_reason": payload.attribution_reason,
            "threat_level": payload.threat_level,
            "action_required": payload.action_required,
            "actions_taken": actions_taken,
            "admissibility": payload.admissibility,
            "timestamp": utc_now(),
        },
    )

    return JSONResponse(
        content={
            "status": "success",
            "incident_id": payload.incident_id,
            "actions_taken": actions_taken,
            "details": details,
            "block_id": (block or {}).get("block_id"),
            "timestamp": utc_now(),
        }
    )
