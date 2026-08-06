from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

# SI: recovery module. Owns /response/recover and the VSS snapshot schedule.
from recovery.recovery import router as recovery_router
from recovery.vss_manager import VSSManager


# PLACEHOLDER STUB: the real Response service owner should replace this file.
# It returns contract-shaped fake actions for SH integration testing only.
# SI note: /response/recover is no longer a stub - it is served by recovery/.
# terminate, isolate and trigger below are still placeholders and belong to AS.

_vss_manager = VSSManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Snapshot every 6 hours. On non-Windows hosts - including this Linux
    # container - this logs why it cannot run and returns False; startup
    # continues either way.
    _vss_manager.start_scheduler()
    yield
    _vss_manager.stop_scheduler()


app = FastAPI(title="URDS Response Stub", version="0.1.0", lifespan=lifespan)
app.include_router(recovery_router)


class TerminateRequest(BaseModel):
    process_id: int
    incident_id: str
    reason: str
    force: bool


class IsolateRequest(BaseModel):
    isolation_level: str
    duration_seconds: int
    allow_localhost: bool


class TriggerRequest(BaseModel):
    incident_id: str
    process_id: int
    threat_level: str
    action_required: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "response", "placeholder": True}


@app.post("/response/terminate")
def terminate(payload: TerminateRequest) -> dict:
    return {
        "status": "terminated",
        "process_id": payload.process_id,
        "timestamp": utc_now(),
        "exit_code": 1 if payload.force else 0,
    }


@app.post("/response/isolate")
def isolate(payload: IsolateRequest) -> dict:
    return {
        "status": "isolated",
        "isolation_level": payload.isolation_level,
        "duration_seconds": payload.duration_seconds,
        "timestamp": utc_now(),
    }


@app.post("/response/trigger")
def trigger(payload: TriggerRequest) -> dict:
    actions = ["admin_notified"]
    if payload.action_required == "terminate_process":
        actions.insert(0, "process_terminated")
    if payload.threat_level in {"high", "critical"}:
        actions.insert(1, "network_isolated")
    return {"status": "success", "actions_taken": actions, "timestamp": utc_now()}
