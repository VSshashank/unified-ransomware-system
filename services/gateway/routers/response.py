from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user
from models import IsolateRequest, RecoverRequest, TerminateRequest, TriggerRequest
from rate_limit import enforce_rate_limit
from routers.proxy import RESPONSE_URL, proxy_request


router = APIRouter(prefix="/response", tags=["response"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


@router.post("/terminate")
async def terminate(payload: TerminateRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/terminate", payload.model_dump())


@router.post("/isolate")
async def isolate(payload: IsolateRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/isolate", payload.model_dump())


@router.post("/recover")
async def recover(payload: RecoverRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/recover", payload.model_dump())


@router.post("/trigger")
async def trigger(payload: TriggerRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", RESPONSE_URL, "/response/trigger", payload.model_dump())
