from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user
from models import MonitorStartRequest
from rate_limit import enforce_rate_limit
from routers.proxy import MONITOR_URL, proxy_request


router = APIRouter(prefix="/monitor", tags=["monitor"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


@router.post("/start")
async def start_monitoring(payload: MonitorStartRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", MONITOR_URL, "/monitor/start", payload.model_dump())


@router.post("/stop")
async def stop_monitoring(request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", MONITOR_URL, "/monitor/stop", {})


@router.get("/status")
async def monitor_status(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", MONITOR_URL, "/monitor/status")


@router.get("/events")
async def monitor_events(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", MONITOR_URL, "/monitor/events")
