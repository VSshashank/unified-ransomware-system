from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel


# PLACEHOLDER STUB: the real Response service owner should replace this file.
# It returns contract-shaped fake actions for SH integration testing only.

app = FastAPI(title="URDS Response Stub", version="0.1.0")


class TerminateRequest(BaseModel):
    process_id: int
    incident_id: str
    reason: str
    force: bool


class IsolateRequest(BaseModel):
    isolation_level: str
    duration_seconds: int
    allow_localhost: bool


class RecoverRequest(BaseModel):
    snapshot_id: str
    files: list[str]
    verify_integrity: bool


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


@app.post("/response/recover")
def recover(payload: RecoverRequest) -> dict:
    return {
        "status": "success",
        "files_recovered": len(payload.files),
        "integrity_verified": payload.verify_integrity,
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
