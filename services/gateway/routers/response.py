from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auth import get_current_user, require_role
from models import IsolateRequest, RecoverRequest, TerminateRequest, TriggerRequest
from rate_limit import enforce_rate_limit
from routers.proxy import RESPONSE_URL, proxy_request


# Admin only, at the router: every response action kills a process, cuts the
# network, or overwrites files on disk. Enterprise is deliberately not enough.
# Suspend and resume sit here too: freezing a process is an action on it.
router = APIRouter(
    prefix="/response",
    tags=["response"],
    dependencies=[Depends(get_current_user), Depends(require_role("admin")), Depends(enforce_rate_limit)],
)


class TerminateWithLeaseRequest(TerminateRequest):
    """`TerminateRequest`, plus the lease the process is held under (defect 26).

    Kept here rather than in models.py so the shared model is unchanged; the
    field is forwarded only when given, so an existing caller's body reaches
    the Response service exactly as before.
    """

    lease_id: str | None = None


class SuspendRequest(BaseModel):
    """Mirrors services/response/app.py `SuspendRequest`; see docs/openapi/gateway.yaml."""

    process_id: int
    incident_id: str = Field(min_length=1)
    lease_seconds: float = Field(gt=0)
    reason: str
    attribution_confidence: str = Field(min_length=1)
    attribution_source: str = Field(min_length=1)
    attribution_reason: str = Field(min_length=1)
    image: str | None = None
    started_at: float | str | None = None


class ResumeRequest(BaseModel):
    lease_id: str | None = None
    process_id: int | None = None
    incident_id: str
    reason: str


@router.post("/terminate")
async def terminate(payload: TerminateWithLeaseRequest, request: Request) -> JSONResponse:
    body = payload.model_dump()
    if body.get("lease_id") is None:
        body.pop("lease_id", None)
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/terminate", body)


@router.post("/suspend")
async def suspend(payload: SuspendRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/suspend", payload.model_dump())


@router.post("/resume")
async def resume(payload: ResumeRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/resume", payload.model_dump())


@router.get("/leases")
async def leases(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", RESPONSE_URL, "/response/leases")


@router.post("/isolate")
async def isolate(payload: IsolateRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/isolate", payload.model_dump())


@router.post("/recover")
async def recover(payload: RecoverRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/recover", payload.model_dump())


@router.post("/trigger")
async def trigger(payload: TriggerRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/trigger", payload.model_dump())
