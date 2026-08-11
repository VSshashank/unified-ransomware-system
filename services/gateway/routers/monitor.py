from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user, require_role
from models import MonitorStartRequest
from rate_limit import enforce_rate_limit
from routers.proxy import MONITOR_URL, proxy_request


# The router authenticates; the two write routes authorize on top of it. Reads
# (/status, /events) stay open to any authenticated role.
router = APIRouter(prefix="/monitor", tags=["monitor"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


@router.post("/start", dependencies=[Depends(require_role("admin", "enterprise"))])
async def start_monitoring(payload: MonitorStartRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", MONITOR_URL, "/monitor/start", payload.model_dump())


# Admin only: stopping the monitor blinds detection for the whole host, which is
# the same order of consequence as a response action.
@router.post("/stop", dependencies=[Depends(require_role("admin"))])
async def stop_monitoring(request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", MONITOR_URL, "/monitor/stop", {})


@router.get("/status")
async def monitor_status(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", MONITOR_URL, "/monitor/status")


@router.get("/events")
async def monitor_events(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", MONITOR_URL, "/monitor/events")
