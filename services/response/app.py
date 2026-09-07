"""URDS Response service (port 8004).

    POST /response/terminate  kill a process by PID
    POST /response/isolate    apply (or plan) network isolation
    POST /response/trigger    orchestrate the reaction to one incident
    POST /response/recover    restore files from a snapshot  (SI, recovery/)
    GET  /health              liveness for docker-compose and the gateway

Terminate/isolate/trigger are AS's; everything under `recovery/` is SI's and is
mounted here unchanged.
"""

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from actions import TerminationError, isolate_host, terminate_process

# SI: recovery module. Owns /response/recover and the VSS snapshot schedule.
from recovery.recovery import router as recovery_router
from recovery.vss_manager import VSSManager

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("response")

LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger:8003").rstrip("/")
LEDGER_TIMEOUT = float(os.getenv("LEDGER_TIMEOUT", "3.0"))

_vss_manager = VSSManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Snapshot every 6 hours. On non-Windows hosts - including this Linux
    # container - this logs why it cannot run and returns False; startup
    # continues either way.
    _vss_manager.start_scheduler()
    yield
    _vss_manager.stop_scheduler()


app = FastAPI(title="URDS Response", version="1.0.0", lifespan=lifespan)
app.include_router(recovery_router)


class TerminateRequest(BaseModel):
    process_id: int
    incident_id: str
    reason: str
    force: bool = True


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


def log_action(event_type: str, event_data: dict) -> dict | None:
    """Best-effort ledger write. A response that happened must be recorded, but
    an unreachable ledger must not stop the next action from being taken."""
    try:
        response = httpx.post(
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
        log_action(
            "response_action",
            {
                "action": "terminate",
                "incident_id": payload.incident_id,
                "process_id": payload.process_id,
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

    log_action(
        "response_action",
        {
            "action": "terminate",
            "incident_id": payload.incident_id,
            "process_id": payload.process_id,
            "process_name": result["process_name"],
            "reason": payload.reason,
            "outcome": "terminated",
            "method": result["method"],
            "termination_time_ms": result["termination_time_ms"],
            "timestamp": result["timestamp"],
        },
    )
    return JSONResponse(content={**result, "incident_id": payload.incident_id})


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

    if payload.action_required == "terminate_process":
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
            "process_id": payload.process_id,
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
