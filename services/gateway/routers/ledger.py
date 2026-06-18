from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user
from models import LedgerLogRequest
from rate_limit import enforce_rate_limit
from routers.proxy import LEDGER_URL, proxy_request


router = APIRouter(prefix="/ledger", tags=["ledger"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


@router.post("/log")
async def log_event(payload: LedgerLogRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", LEDGER_URL, "/ledger/log", payload.model_dump())


@router.get("/entries")
async def ledger_entries(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", LEDGER_URL, "/ledger/entries")
