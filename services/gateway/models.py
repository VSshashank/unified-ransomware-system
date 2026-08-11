from typing import Any

from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    # Defaults are the least-privileged role. They used to be admin/enterprise,
    # which made an empty POST to /auth/token a full-privilege token dispenser.
    # Anything above "free" now needs the bootstrap secret - see main.py.
    sub: str = "user_id_123"
    role: str = "free"
    tier: str = "free"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: str
    role: str = "free"
    tier: str | None = None
    exp: int
    iat: int


class ErrorEnvelope(BaseModel):
    code: str
    message: str
    timestamp: str
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorEnvelope
    details: dict[str, Any] = Field(default_factory=dict)


class MonitorStartRequest(BaseModel):
    watch_path: str
    recursive: bool = True
    file_patterns: list[str]


class AnalyzeRequest(BaseModel):
    file_path: str


class PredictRequest(BaseModel):
    features: dict[str, Any]


class LedgerLogRequest(BaseModel):
    event_type: str
    event_data: dict[str, Any]


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
